"""Ollama classifiers for #ops-noc mentions.

Exposes three classifiers: ``classify`` (four-way incident vs
change-with-CR vs change-no-CR vs fyi), ``classify_p3`` (P3-incident gate),
and ``classify_resolution`` (resolved vs unresolved for turnover).
All three share the same shape — one pure function, one Ollama call,
JSON verdict, deterministic fail-closed fallback on every error path
(HTTP error, timeout, malformed JSON, unknown verdict). No I/O other
than the Ollama HTTP request.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from enum import Enum

import requests

logger = logging.getLogger(__name__)

OLLAMA_TIMEOUT_SECONDS = 60
TEXT_CHAR_LIMIT = 2000

# Phase 4b'' (2026-04-27): two false-positive incident pages on posts that
# explicitly told NOC to stand down ("please disregard alerts for compute46",
# "please ignore the alert until Monday"). The prompt already covers this
# (example #6) but qwen-assistant overweights impact phrases ("alerts",
# "disk at 90%") and returns `incident` anyway. Deterministic post-rule:
# when no CR is attached and a clear disregard/ignore directive is present,
# override `incident` to `fyi`. Patterns chosen to fire only on imperative
# stand-down language, not on incidental "ignore" / "disregard" usage.
_FYI_OVERRIDE_PATTERNS = [
    re.compile(r"\bplease\s+disregard\b", re.IGNORECASE),
    re.compile(r"\bplease\s+ignore\b", re.IGNORECASE),
    re.compile(r"\bkindly\s+(?:disregard|ignore)\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(?:the\s+|these\s+|any\s+)?alerts?\b",
               re.IGNORECASE),
    re.compile(r"\bignore\s+(?:the\s+|these\s+|any\s+)?alerts?\b",
               re.IGNORECASE),
]

_P3_EXTERNAL_REPORT_RE = re.compile(
    r"\b(?:customer|reseller|client|partner|shopify)\b.*"
    r"\b(?:report(?:ing|ed|s)?|seeing|hit|experienc(?:e|ing|ed)|impacted?)\b",
    re.IGNORECASE | re.DOTALL,
)
_P3_LIVE_SYMPTOM_RE = re.compile(
    r"\b(?:time[- ]?outs?|timeouts?|errors?|failed|failing|down|unavailable|"
    r"degraded|latency|spike|non[- ]?200|5\d\d|impacted?)\b",
    re.IGNORECASE,
)


def _has_disregard_directive(text: str) -> bool:
    """True if text contains an imperative stand-down phrase."""
    return any(p.search(text) for p in _FYI_OVERRIDE_PATTERNS)


def _looks_like_external_customer_incident(text: str) -> bool:
    """Conservative fallback for LLM failures on external-impact reports."""
    return bool(
        text
        and _P3_EXTERNAL_REPORT_RE.search(text)
        and _P3_LIVE_SYMPTOM_RE.search(text)
        and not _has_disregard_directive(text)
    )


def _drain_ollama_stream(resp) -> str:
    """Consume Ollama's ``/api/chat`` NDJSON stream and reassemble the
    assistant's ``message.content`` across chunks.

    We issue requests with ``stream: true`` so the TCP connection stays
    non-idle during the model's thinking phase. Under the previous
    non-streaming mode, reasoning-mode models (qwen-assistant) hold the
    connection silent for the full thinking duration; an intermediate
    middlebox (~35s idle-reset) was closing those connections and
    surfacing as ``RequestException`` at the client, which drove the
    Phase 4b 19.5% fallback rate.

    Raises ``ValueError`` on any malformed chunk (caught upstream and
    routed through the classifier's fail-closed fallback).
    """
    parts: list[str] = []
    for raw in resp.iter_lines():
        if not raw:
            continue
        chunk = json.loads(raw)  # may raise ValueError; caller handles
        msg_content = chunk.get("message", {}).get("content", "")
        if msg_content:
            parts.append(msg_content)
        if chunk.get("done"):
            break
    return "".join(parts)


class Verdict(str, Enum):
    INCIDENT = "incident"
    CHANGE_WITH_CR = "change_with_cr"
    CHANGE_NO_CR = "change_no_cr"
    FYI = "fyi"


@dataclass(frozen=True)
class CRRef:
    """Minimal CR reference the classifier needs. Match jira_cr.CRData's
    `.key` and `.summary` fields — we accept either via duck-typing."""
    key: str
    summary: str


_PROMPT = """You classify #ops-noc mentions of @noc / @domains-sre into exactly one of:
- incident: user is reporting/describing a problem and asking for help
- change_with_cr: user is announcing a planned change and the CR is the one linked in THIS message
- change_no_cr: user is announcing a change but no CR link is in this message
- fyi: user is explicitly telling NOC/SRE NOT to act — a heads-up, a "please disregard", a monitoring announcement, or a "we're doing X, ignore alarms" notice

A CR link in the text is NOT automatically change_with_cr. If the CR is mentioned as historical context ("previous CR", "related CR", "CR that caused this"), the verdict is incident — the user's CURRENT problem is what matters, not a past change they reference.

**CR-attached precedence.** If `Linked CR` below is non-`none`, the bot has already confirmed a real CR is attached to THIS message. In that case the verdict is **change_with_cr** — even if the message says "please disregard" or "ignore alerts". A disregard notice WITH an attached CR is an announcement about a change, not an ambient FYI. Only choose `fyi` when `Linked CR` is `none`.

If the message explicitly tells NOC or SRE NOT to act (phrases like "please disregard", "ignore alerts", "just a heads up", "FYI", "we're doing X, ignore alarms") AND no CR is attached, choose fyi. Otherwise follow the incident / change ladder above.

Examples:
1. "@noc Could we get someone to look into HRS cert expiration? Previous CR for change: CR-40276. Cert expires tomorrow." -> incident
2. "@noc i will be patching and rebooting round 1 of the int.tucows.com domain controllers" (no CR) -> change_no_cr
3. "@noc CR-41799 starting now" with CR-41799 title "Patching round 1" -> change_with_cr
4. "@noc please disregard alerts for sml06b.bra2, working on CR-41381" with CR-41381 attached -> change_with_cr
5. "@noc Hey team - just a heads up that I've added and enabled new monitoring for TRS" -> fyi
6. "@noc please disregard alerts for compute74.bra2, working on INC-12345" (no CR) -> fyi

Message text:
<<TEXT>>

Linked CR (if any): <<CR_DISPLAY>>

Reply with JSON only: {"verdict": "incident"|"change_with_cr"|"change_no_cr"|"fyi", "reason": "<one short sentence>"}"""


def classify(text: str, cr_data, ollama_url: str, ollama_model: str) -> Verdict:
    """Return a Verdict. Never raises. Falls back to deterministic logic
    (CR present -> change_with_cr, else -> incident) on any error path."""
    cr_display = (
        f"{cr_data.key}: {cr_data.summary}" if cr_data is not None else "none"
    )
    # Use str.replace rather than .format() so stray '{' / '}' in Slack text
    # (JSON snippets, curl examples) can never break substitution — classify()
    # must never raise.
    prompt = (_PROMPT
              .replace("<<TEXT>>", text[:TEXT_CHAR_LIMIT])
              .replace("<<CR_DISPLAY>>", cr_display))
    payload = {
        "model": ollama_model,
        "format": "json",
        "stream": True,
        "messages": [
            {"role": "system",
             "content": "You are a strict JSON classifier. Output only the requested JSON."},
            {"role": "user", "content": prompt},
        ],
    }
    try:
        resp = requests.post(f"{ollama_url}/api/chat", json=payload,
                             timeout=OLLAMA_TIMEOUT_SECONDS, stream=True)
    except requests.RequestException as e:
        logger.warning("escalation_classifier: Ollama request failed: %s", e)
        return _fallback(cr_data, reason=f"request_error:{e}")

    if resp.status_code != 200:
        logger.warning("escalation_classifier: Ollama %d: %s",
                       resp.status_code, resp.text[:200])
        return _fallback(cr_data, reason=f"http_{resp.status_code}")

    try:
        content = _drain_ollama_stream(resp)
        parsed = json.loads(content)
    except (ValueError, json.JSONDecodeError, requests.RequestException) as e:
        logger.warning("escalation_classifier: malformed response (%s)", e)
        return _fallback(cr_data, reason=f"parse_error:{e}")

    raw = parsed.get("verdict")
    try:
        verdict = Verdict(raw)
    except ValueError:
        logger.warning("escalation_classifier: unknown verdict %r", raw)
        return _fallback(cr_data, reason=f"unknown_verdict:{raw}")

    # Defensive: model claimed a CR routing but we have no CR in hand.
    if verdict == Verdict.CHANGE_WITH_CR and cr_data is None:
        logger.warning("escalation_classifier: change_with_cr with no CR -> incident")
        return _fallback(cr_data, reason="change_with_cr_without_cr")

    # Defensive (Phase 4b'): model chose fyi but a CR is attached. Per the
    # 4-week shadow-eval, "disregard + CR attached" is the dominant fyi-FP
    # failure mode — the CR presence means this is an announcement about a
    # change, not an ambient heads-up. Route to change_with_cr instead.
    if verdict == Verdict.FYI and cr_data is not None:
        logger.info(
            "escalation_classifier: fyi with CR attached -> change_with_cr "
            "(cr=%s)", cr_data.key,
        )
        return Verdict.CHANGE_WITH_CR

    # Defensive (Phase 4b''): model chose incident but the text plainly
    # tells NOC to stand down and no CR is attached. qwen-assistant
    # overweights impact words near "please disregard" / "please ignore"
    # and ignores the directive. Route to fyi.
    if verdict == Verdict.INCIDENT and cr_data is None and \
            _has_disregard_directive(text):
        logger.info(
            "escalation_classifier: incident with explicit "
            "disregard/ignore directive and no CR -> fyi",
        )
        return Verdict.FYI

    logger.info("escalation_classifier: verdict=%s reason=%s",
                verdict.value, parsed.get("reason"))
    return verdict


def _fallback(cr_data, *, reason: str) -> Verdict:
    v = Verdict.CHANGE_WITH_CR if cr_data is not None else Verdict.INCIDENT
    logger.info("escalation_classifier: fallback reason=%s verdict=%s",
                reason, v.value)
    return v


class P3Verdict(str, Enum):
    INCIDENT = "incident"
    NOT_INCIDENT = "not_incident"


# Inverted prior from the four-way classifier. Most untagged posts in
# #ops-noc are peer chatter, questions, status updates, or thread echoes.
# Only flag `incident` when the post clearly announces an active,
# service-affecting problem requiring immediate attention.
#
# Negative / positive examples are mined from the 2026-04-22 smoke
# corpus (deploy/noc_escalation_bot/scripts/p3_smoke.py). Tune against
# the labeled corpus — acceptance gate is precision >= 90% AND recall
# >= 70% on >= 200 posts with >= 15 true-positives.
_P3_PROMPT = """Task: classify one UNTAGGED #ops-noc Slack post (no @noc / @domains-sre) as `incident` (needs escalation) or `not_incident` (doesn't).

Default answer: not_incident. Say `incident` ONLY when you would bet money the author wants on-call engineers paged right now.

HARD not_incident rules (check FIRST, before anything else):
- Contains a shell prompt like `$`, `#` followed by a command, OR looks like pasted command output (`df -h`, `ls`, `ps`, a filesystem table, `Filesystem`, `Used`, `Avail`, uptime output, pasted log lines) → not_incident.
- Reports a fix, a resolved state, or a current measurement: "brought it back up", "cleared", "fixed", "it's working now", "disk has N% free", "free space is now...", "resolved" → not_incident.
- Heads-up that an alert WILL fire or asking others to ignore alerts: "you will see an alert", "please ignore alerts", "I'll monitor", "no impact expected" → not_incident.
- Mentions deploy/patch/promo/upgrade/restart/rollout + a CR-#### link → not_incident (it's a change).
- A meta paging request with no symptoms: "please page <@user>" → not_incident.
- Pure thread-continuation reply (very short, answers a previous message): "yes", "no", "one sec", "looking", ":eyes:", "will check" → not_incident.

Then, say `incident` if ANY of these match:
- Names a service/system/host and asserts it's broken, down, erroring, unreachable, or degraded right now: "Wix error", "pingdom is broken?", "Production site not coming up", "prod is down", "errors on X".
- ":alert:" or "FYI for all" framing + a concrete service with live impact: ":alert: issues with vpn.ca and vpn.eu".
- Coordination for a live outage: "here is a bridge to discuss this outage", "we're on a call for the X issue".
- First-person user-impact report of a persistent problem: "Since <time> I have trouble with <service>", "I can't reach <service>".
- Live connectivity/network/service failure statement: "Network issues on AWS account X, can't reach the internet".
- Short ask for help that names live impact: "Anyone online — we have a Cluster A access issue".
- "Got an alert <link>" that is NOT pasted log output.

Otherwise → not_incident.

Reply with JSON only: {"verdict": "incident"|"not_incident", "reason": "<one short sentence>"}"""


def classify_p3(text: str, *, ollama_url: str, ollama_model: str) -> P3Verdict:
    """Classify an UNTAGGED #ops-noc post. Two-way: INCIDENT | NOT_INCIDENT.
    Never raises. Falls back to NOT_INCIDENT on every error path — a
    missed P3 prompt is status-quo, a false P3 prompt is new noise."""
    prompt = _P3_PROMPT.replace("<<TEXT>>", text[:TEXT_CHAR_LIMIT])
    payload = {
        "model": ollama_model,
        "format": "json",
        "stream": True,
        "messages": [
            {"role": "system",
             "content": "You are a strict JSON classifier. Output only the requested JSON."},
            {"role": "user", "content": prompt},
        ],
    }
    try:
        resp = requests.post(f"{ollama_url}/api/chat", json=payload,
                             timeout=OLLAMA_TIMEOUT_SECONDS, stream=True)
    except requests.RequestException as e:
        logger.warning("classify_p3: Ollama request failed: %s", e)
        return _p3_fallback(text, reason=f"request_error:{e}")

    if resp.status_code != 200:
        logger.warning("classify_p3: Ollama %d: %s",
                       resp.status_code, resp.text[:200])
        return _p3_fallback(text, reason=f"http_{resp.status_code}")

    try:
        content = _drain_ollama_stream(resp)
        parsed = json.loads(content)
    except (ValueError, json.JSONDecodeError, requests.RequestException) as e:
        logger.warning("classify_p3: malformed response (%s)", e)
        return _p3_fallback(text, reason=f"parse_error:{e}")

    raw = parsed.get("verdict")
    try:
        verdict = P3Verdict(raw)
    except ValueError:
        logger.warning("classify_p3: unknown verdict %r", raw)
        return _p3_fallback(text, reason=f"unknown_verdict:{raw}")

    logger.info("classify_p3: verdict=%s reason=%s",
                verdict.value, parsed.get("reason"))
    return verdict


def _p3_fallback(text: str = "", *, reason: str) -> P3Verdict:
    if _looks_like_external_customer_incident(text):
        logger.info("classify_p3: fallback reason=%s verdict=incident heuristic=external_customer", reason)
        return P3Verdict.INCIDENT
    logger.info("classify_p3: fallback reason=%s verdict=not_incident", reason)
    return P3Verdict.NOT_INCIDENT


class ResolutionVerdict(str, Enum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


# Runs on a single Slack reply in an active incident thread. Reply text
# only — no channel, no thread_ts, no prior messages, no user id. Keeps
# the classifier stateless and matches the pattern established by
# classify_p3. A false RESOLVED silently closes a live incident, so the
# prompt biases hard toward unresolved.
_RESOLUTION_PROMPT = """You classify a single Slack reply in an active incident thread as one of:
- resolved: the reply plainly states the incident is over ("resolved", "fixed", "all good now", "cleared", "back up", "working again", "no longer seeing errors")
- unresolved: anything else — diagnostics, questions, status updates, chatter, partial findings

Default: unresolved. Only return `resolved` when the reply unambiguously declares the whole incident is over, not a sub-step.

Reply:
<<TEXT>>

Reply with JSON only: {"verdict": "resolved"|"unresolved", "reason": "<one short sentence>"}"""


def classify_resolution(text: str, *, ollama_url: str,
                        ollama_model: str) -> ResolutionVerdict:
    """Two-way resolution classifier. Fail-closed to UNRESOLVED.

    Mirrors classify_p3 exactly: same timeout, same format=json payload,
    same JSON-only system prompt, same str.replace() substitution so
    stray `{` / `}` in Slack text can never break the call. Never raises.
    """
    prompt = _RESOLUTION_PROMPT.replace("<<TEXT>>", text[:TEXT_CHAR_LIMIT])
    payload = {
        "model": ollama_model,
        "format": "json",
        "stream": True,
        "messages": [
            {"role": "system",
             "content": "You are a strict JSON classifier. Output only the requested JSON."},
            {"role": "user", "content": prompt},
        ],
    }
    try:
        resp = requests.post(f"{ollama_url}/api/chat", json=payload,
                             timeout=OLLAMA_TIMEOUT_SECONDS, stream=True)
    except requests.RequestException as e:
        logger.warning("classify_resolution: Ollama request failed: %s", e)
        return _resolution_fallback(reason=f"request_error:{e}")

    if resp.status_code != 200:
        logger.warning("classify_resolution: Ollama %d: %s",
                       resp.status_code, resp.text[:200])
        return _resolution_fallback(reason=f"http_{resp.status_code}")

    try:
        content = _drain_ollama_stream(resp)
        parsed = json.loads(content)
    except (ValueError, json.JSONDecodeError, requests.RequestException) as e:
        logger.warning("classify_resolution: malformed response (%s)", e)
        return _resolution_fallback(reason=f"parse_error:{e}")

    raw = parsed.get("verdict")
    try:
        verdict = ResolutionVerdict(raw)
    except ValueError:
        logger.warning("classify_resolution: unknown verdict %r", raw)
        return _resolution_fallback(reason=f"unknown_verdict:{raw}")

    logger.info("classify_resolution: verdict=%s reason=%s",
                verdict.value, parsed.get("reason"))
    return verdict


def _resolution_fallback(*, reason: str) -> ResolutionVerdict:
    logger.info("classify_resolution: fallback reason=%s verdict=unresolved",
                reason)
    return ResolutionVerdict.UNRESOLVED
