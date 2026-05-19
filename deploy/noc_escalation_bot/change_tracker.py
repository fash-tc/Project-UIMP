"""Change Tracker: scheduled Jira CR scanner that posts a daily summary to Slack."""

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict

import requests

from jira_cr import CRWindowEntry

logger = logging.getLogger(__name__)

# Products whose CRs we skip entirely — not within NOC scope.
EXCLUDED_KEYWORDS = ("ting", "wavelo")
VALID_BUCKETS = {"has_impact", "unclear_impact", "no_impact"}
DESCRIPTION_CHAR_LIMIT = 2000
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 5.0


@dataclass
class Classification:
    bucket: str            # one of VALID_BUCKETS
    affected_service: str  # short label (service or system affected), may be ""
    classification_failed: bool
    reason: str            # one-line LLM reason (stored, not rendered)


def _is_excluded(cr: CRWindowEntry) -> bool:
    """True if the CR is for a product we don't track (Ting / Wavelo)."""
    blob = " ".join([
        cr.summary or "", cr.description or "", cr.impacted_services or "",
    ]).lower()
    return any(kw in blob for kw in EXCLUDED_KEYWORDS)


def _build_classify_prompt(cr: CRWindowEntry) -> str:
    description_truncated = (cr.description or "")[:DESCRIPTION_CHAR_LIMIT]
    services_line = cr.impacted_services or "(empty)"
    return (
        "You are classifying the real-world impact of a Jira Change Request.\n\n"
        "IMPACT = something that disrupts service availability or degrades "
        "functionality for a system, a user, or a customer during the change. "
        "Implementation steps, procedures, or work being performed on the "
        "system are NOT impact. A CR describing only \"we will run X, then Y, "
        "then restart Z\" has NO described impact unless it also states that "
        "users/customers/services will see downtime, errors, latency, or "
        "degraded behavior.\n\n"
        "Return ONLY valid JSON with exactly these keys:\n"
        "  \"bucket\": one of \"has_impact\", \"unclear_impact\", \"no_impact\"\n"
        "    - \"has_impact\"     — the CR explicitly describes user/customer/service disruption\n"
        "    - \"unclear_impact\" — impact is plausible but not clearly described; ambiguous wording\n"
        "    - \"no_impact\"      — only implementation steps; no disruption described, or explicitly \"no customer impact\"\n"
        "  \"affected_service\": short label of the affected system/service (e.g. \"OpenSRS API\"), "
        "or \"\" if bucket is \"no_impact\"\n"
        "  \"reason\": one short sentence explaining the classification\n\n"
        "Prefer \"unclear_impact\" over guessing. Do NOT treat procedural steps as impact.\n\n"
        f"CR summary: {cr.summary}\n"
        f"Impacted Services: {services_line}\n"
        "Description:\n---\n"
        f"{description_truncated}\n"
        "---"
    )


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("%s must be numeric, using %.1f", name, default)
        return default
    return max(0.5, value)


def _ollama_timeout_seconds() -> float:
    return _env_float("CHANGE_TRACKER_OLLAMA_TIMEOUT_SEC", DEFAULT_OLLAMA_TIMEOUT_SECONDS)


def _fail(reason: str = "classification failed") -> Classification:
    return Classification(bucket="unclear_impact", affected_service="",
                          classification_failed=True, reason=reason)


def classify_cr(cr: CRWindowEntry, ollama_url: str, ollama_model: str) -> Classification:
    """Call Ollama to classify a CR into a bucket. Never raises."""
    payload = {
        "model": ollama_model,
        "messages": [
            {"role": "system", "content": "You output valid JSON only."},
            {"role": "user", "content": _build_classify_prompt(cr)},
        ],
        "stream": False,
        "format": "json",
    }

    try:
        timeout = _ollama_timeout_seconds()
        resp = requests.post(
            f"{ollama_url}/api/chat", json=payload, timeout=timeout,
        )
    except requests.RequestException as e:
        logger.warning("classify_cr: ollama request failed for %s: %s", cr.key, e)
        return _fail("ollama request failed")

    if resp.status_code != 200:
        logger.warning(
            "classify_cr: ollama %d for %s: %s",
            resp.status_code, cr.key, resp.text[:200],
        )
        return _fail()

    try:
        raw = resp.json()["message"]["content"]
        parsed = json.loads(raw)
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        logger.warning("classify_cr: parse error for %s: %s", cr.key, e)
        return _fail()

    bucket = parsed.get("bucket", "")
    if bucket not in VALID_BUCKETS:
        logger.warning("classify_cr: bad bucket %r for %s", bucket, cr.key)
        return _fail()

    # Cap the LLM-supplied affected_service length to keep the line sane;
    # strip mrkdwn control chars to prevent mention/link injection.
    raw_affected = str(parsed.get("affected_service") or "")
    affected = "" if bucket == "no_impact" else _escape_slack(raw_affected)[:80]

    return Classification(
        bucket=bucket,
        affected_service=affected,
        classification_failed=False,
        reason=parsed.get("reason", ""),
    )


@dataclass
class StateEntry:
    title: str
    planned_start: str
    bucket: str
    affected_service: str
    classification_failed: bool


class ChangeTrackerState:
    """File-backed state for the current UTC day's post."""

    def __init__(self, path: str):
        self._path = path
        self.date: str = ""           # 'YYYY-MM-DD'
        self.message_ts: str = ""     # Slack ts of the daily post
        self.channel_id: str = ""     # Slack channel snapshotted at post creation
        self.entries: Dict[str, StateEntry] = {}

    def load(self) -> None:
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("ChangeTrackerState: load failed (%s), starting fresh", e)
            return
        self.date = data.get("date", "") or ""
        self.message_ts = data.get("message_ts", "") or ""
        self.channel_id = data.get("channel_id", "") or ""
        # Legacy buckets → new impact-based buckets.
        _BUCKET_MIGRATE = {
            "impacts_us": "has_impact",
            "unclear":    "unclear_impact",
            "unrelated":  "no_impact",
        }
        self.entries = {}
        for key, raw in (data.get("entries") or {}).items():
            try:
                legacy = raw.get("bucket", "unclear_impact")
                bucket = _BUCKET_MIGRATE.get(legacy, legacy)
                if bucket not in VALID_BUCKETS:
                    bucket = "unclear_impact"
                self.entries[key] = StateEntry(
                    title=raw.get("title", ""),
                    planned_start=raw.get("planned_start", ""),
                    bucket=bucket,
                    affected_service=raw.get("affected_service", ""),
                    classification_failed=bool(raw.get("classification_failed", False)),
                )
            except (TypeError, AttributeError):
                logger.warning("ChangeTrackerState: skipping malformed entry %s", key)

    def save(self) -> None:
        data = {
            "date": self.date,
            "message_ts": self.message_ts,
            "channel_id": self.channel_id,
            "entries": {k: asdict(v) for k, v in self.entries.items()},
        }
        tmp = self._path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self._path)
        except OSError as e:
            logger.warning("ChangeTrackerState: save failed: %s", e)
            # Best-effort cleanup; ignore secondary failure
            try:
                os.remove(tmp)
            except OSError:
                pass

    def reset_for_new_day(self, new_date: str) -> None:
        self.date = new_date
        self.message_ts = ""
        self.channel_id = ""
        self.entries = {}


OTHER_BUCKET_LIMIT = 10
CRITICAL_BUCKETS_CHAR_LIMIT = 3500
CHANGE_TRACKER_SLACK_TEXT_LIMIT = 3900


def _fmt_planned_start(s: str) -> str:
    if not s:
        return "unscheduled"
    cleaned = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(cleaned)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return s


def _escape_slack(s: str) -> str:
    """Escape Slack mrkdwn control chars to prevent mention/link injection."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cr_line(key: str, entry: "StateEntry", jira_base_url: str) -> str:
    link = f"<{jira_base_url}/browse/{key}|{key}>"
    prefix = "\u26a0\ufe0f " if entry.classification_failed else ""
    when = _fmt_planned_start(entry.planned_start)
    title = _escape_slack(entry.title or "(no title)")
    return f"  \u2022 {prefix}{link} \u2013 {title} \u2014 {when}"


def render_slack_message(
    state: "ChangeTrackerState",
    jira_base_url: str,
    last_updated_utc: datetime,
    next_poll_utc: datetime,
) -> str:
    buckets: Dict[str, list] = {
        "has_impact": [], "unclear_impact": [], "no_impact": [],
    }
    for key, entry in state.entries.items():
        if entry.bucket in buckets:
            buckets[entry.bucket].append((key, entry))

    for k in buckets:
        buckets[k].sort(key=lambda kv: kv[1].planned_start or "")

    total = sum(len(v) for v in buckets.values())
    header = [
        f"\U0001f4cb Changes for {state.date or last_updated_utc.strftime('%Y-%m-%d')} (rolling \u00b124h) \u2014 {total} total",
        f"  \U0001f534 {len(buckets['has_impact'])} has impact",
        f"  \U0001f7e1 {len(buckets['unclear_impact'])} unclear impact",
        f"  \u26aa {len(buckets['no_impact'])} no impact defined",
    ]

    footer = (
        f"_Last updated: {last_updated_utc.strftime('%Y-%m-%d %H:%M UTC')} "
        f"(next poll {next_poll_utc.strftime('%H:%M UTC')})_"
    )
    header_text = "\n".join(header)

    def _render_with_caps(caps: Dict[str, int], truncated: bool = False) -> str:
        sections: list = []

        def add_bucket(bucket: str, label: str) -> None:
            items = buckets[bucket]
            if not items:
                return
            cap = max(0, min(caps.get(bucket, len(items)), len(items)))
            omitted = len(items) - cap
            if omitted:
                suffix = "; message truncated" if truncated else ""
                sections.append(f"{label} ({len(items)} \u2014 {omitted} not shown{suffix})")
            else:
                sections.append(label)
            sections.extend(_cr_line(k, e, jira_base_url) for k, e in items[:cap])

        add_bucket("has_impact", "\U0001f534 Has Impact")
        add_bucket("unclear_impact", "\U0001f7e1 Unclear Impact")
        add_bucket("no_impact", "\u26aa No Impact Defined")
        if truncated and not any(len(buckets[k]) > caps.get(k, len(buckets[k])) for k in buckets):
            sections.append("_message truncated_")

        body_parts = [header_text]
        if sections:
            body_parts.append("\n".join(sections))
        body_parts.append(footer)
        return "\n\n".join(body_parts)

    caps = {
        "has_impact": len(buckets["has_impact"]),
        "unclear_impact": len(buckets["unclear_impact"]),
        "no_impact": min(len(buckets["no_impact"]), OTHER_BUCKET_LIMIT),
    }
    rendered = _render_with_caps(caps)

    # Safety: if Our Systems + Needs Review exceed the char limit, collapse
    # Other to a one-line summary first, then cap critical buckets as needed
    # to stay under Slack's 4000-char ceiling.
    critical_chars = sum(
        len(_cr_line(k, e, jira_base_url)) + 1
        for k, e in buckets["has_impact"] + buckets["unclear_impact"]
    )
    if critical_chars > CRITICAL_BUCKETS_CHAR_LIMIT and buckets["no_impact"]:
        logger.warning(
            "change_tracker: critical buckets exceed %d chars, collapsing No Impact Defined",
            CRITICAL_BUCKETS_CHAR_LIMIT,
        )
        caps["no_impact"] = 0
        rendered = _render_with_caps(caps, truncated=True)

    while len(rendered) > CHANGE_TRACKER_SLACK_TEXT_LIMIT:
        reducible = [k for k in ("has_impact", "unclear_impact", "no_impact") if caps[k] > 0]
        if not reducible:
            break
        bucket = max(reducible, key=lambda k: caps[k])
        caps[bucket] -= max(1, caps[bucket] // 4)
        logger.warning(
            "change_tracker: rendered Slack message exceeded %d chars, capping %s to %d",
            CHANGE_TRACKER_SLACK_TEXT_LIMIT,
            bucket,
            caps[bucket],
        )
        rendered = _render_with_caps(caps, truncated=True)

    if len(rendered) > CHANGE_TRACKER_SLACK_TEXT_LIMIT:
        logger.warning(
            "change_tracker: rendered Slack message still exceeded %d chars after capping",
            CHANGE_TRACKER_SLACK_TEXT_LIMIT,
        )
        rendered = "\n\n".join([
            header_text,
            "_CR list omitted because message exceeded Slack limit (message truncated)_",
            footer,
        ])
    return rendered


POLL_SLOT_HOURS = [0, 5, 10, 15, 20]


def _next_slot_delay(now: datetime) -> tuple[float, datetime]:
    """Seconds until the next fixed UTC slot, and the slot's datetime.

    If `now` is exactly on a slot, returns the NEXT slot (never 0).
    After the last slot of the day, wraps to slot[0] of tomorrow.
    """
    today = now.replace(minute=0, second=0, microsecond=0)
    for hour in POLL_SLOT_HOURS:
        candidate = today.replace(hour=hour)
        if candidate > now:
            return (candidate - now).total_seconds(), candidate
    tomorrow = (now + timedelta(days=1)).replace(
        hour=POLL_SLOT_HOURS[0], minute=0, second=0, microsecond=0
    )
    return (tomorrow - now).total_seconds(), tomorrow


class ChangeTracker:
    def __init__(
        self,
        slack_client,
        jira_client,
        config,
        activity,
        state_path: str,
        jira_base_url: str,
        default_channel_id: str,
        ollama_url: str,
        ollama_model: str,
        now_fn=None,
    ):
        self._slack = slack_client
        self._jira = jira_client
        self._config = config
        self._activity = activity
        self._state = ChangeTrackerState(state_path)
        self._state.load()
        self._jira_base_url = jira_base_url
        self._default_channel_id = default_channel_id
        self._ollama_url = ollama_url
        self._ollama_model = ollama_model
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._thread: threading.Thread | None = None
        self._last_poll_ts: datetime | None = None
        self._next_poll_ts: datetime | None = None

    def snapshot(self) -> dict:
        return {
            "last_poll_ts": self._last_poll_ts.isoformat() if self._last_poll_ts else None,
            "next_poll_ts": self._next_poll_ts.isoformat() if self._next_poll_ts else None,
            "today_date": self._state.date,
            "today_count": len(self._state.entries),
        }

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            now = self._now_fn()
            delay, slot = _next_slot_delay(now)
            self._next_poll_ts = slot
            logger.info("change_tracker: sleeping %.0fs until %s", delay, slot.isoformat())
            time.sleep(delay)
            try:
                self._poll()
            except Exception:
                logger.exception("change_tracker: poll failed")
                self._activity.add("change_tracker_failed", "poll raised; see logs")

    def _poll(self) -> None:
        cfg = self._config.get_all()
        if not cfg.get("change_tracker_enabled", True):
            logger.debug("change_tracker: disabled via config, skipping")
            return

        now = self._now_fn()
        self._last_poll_ts = now
        _, next_slot = _next_slot_delay(now)
        self._next_poll_ts = next_slot
        today = now.strftime("%Y-%m-%d")
        if self._state.date != today:
            logger.info("change_tracker: new UTC day %s, resetting state", today)
            self._state.reset_for_new_day(today)

        window_start = now - timedelta(hours=24)
        window_end = now + timedelta(hours=24)
        try:
            entries = self._jira.search_crs_in_window(window_start, window_end)
        except Exception as e:
            logger.warning("change_tracker: jira query failed: %s", e)
            return

        new_count = 0
        ollama_unavailable = False
        for entry in entries:
            existing = self._state.entries.get(entry.key)
            if existing and not existing.classification_failed:
                continue
            if _is_excluded(entry):
                logger.debug("change_tracker: skipping %s (Ting/Wavelo)", entry.key)
                continue
            if ollama_unavailable:
                classification = _fail("ollama unavailable for poll")
            else:
                classification = classify_cr(entry, self._ollama_url, self._ollama_model)
                if (
                    classification.classification_failed
                    and classification.reason == "ollama request failed"
                ):
                    ollama_unavailable = True
                    logger.warning(
                        "change_tracker: Ollama unavailable; skipping remaining CR classifications this poll"
                    )
            self._state.entries[entry.key] = StateEntry(
                title=entry.summary,
                planned_start=entry.planned_start,
                bucket=classification.bucket,
                affected_service=classification.affected_service,
                classification_failed=classification.classification_failed,
            )
            if not existing:
                new_count += 1

        body = render_slack_message(
            self._state, self._jira_base_url, now, next_slot,
        )

        try:
            if not self._state.message_ts:
                channel = cfg.get("change_tracker_channel_id") or self._default_channel_id
                if not channel:
                    logger.warning("change_tracker: no channel configured, skipping post")
                    return
                resp = self._slack.chat_postMessage(channel=channel, text=body)
                self._state.message_ts = resp["ts"]
                self._state.channel_id = channel
                self._activity.add(
                    "change_tracker_posted",
                    f"{today}: {len(self._state.entries)} CRs",
                )
            else:
                self._slack.chat_update(
                    channel=self._state.channel_id,
                    ts=self._state.message_ts,
                    text=body,
                )
                if new_count:
                    self._activity.add(
                        "change_tracker_updated",
                        f"{today}: +{new_count} new, {len(self._state.entries)} total",
                    )
        except Exception as e:
            logger.warning("change_tracker: slack write failed: %s", e)
            return

        self._state.save()
