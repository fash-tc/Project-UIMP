#!/usr/bin/env python3
"""Enhanced LLM-powered alert enrichment service.
Polls Keep for new alerts, performs deduplication assessment,
sends to Ollama for deep analysis with service dependency context,
and writes structured enrichment back to Keep."""

import json
import time
import os
import logging
from urllib.request import Request, urlopen
from urllib.error import HTTPError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("alert-enricher")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
KEEP_URL = os.environ.get("KEEP_URL", "http://keep-api:8080")
KEEP_API_KEY = os.environ.get("KEEP_API_KEY", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))

enriched_cache = set()

# === Service Dependency Map ===
SERVICE_DEPS = {
    "dns": {
        "desc": "Authoritative DNS servers",
        "upstream": ["core-db", "zone-manager"],
        "downstream": ["domain-resolution", "external-clients", "all-registrar-partners"],
        "criticality": "P0",
    },
    "whois": {
        "desc": "WHOIS query service",
        "upstream": ["core-db"],
        "downstream": ["registrar-partners", "compliance", "ICANN-reporting"],
        "criticality": "P1",
    },
    "epp": {
        "desc": "EPP domain registration protocol",
        "upstream": ["core-db", "billing-service"],
        "downstream": ["registrar-partners", "domain-lifecycle", "opensrs-api"],
        "criticality": "P0",
    },
    "billing": {
        "desc": "Billing and payment processing",
        "upstream": ["payment-gateway", "core-db"],
        "downstream": ["epp-server", "customer-portal", "opensrs-api"],
        "criticality": "P0",
    },
    "db": {
        "desc": "Central databases (PostgreSQL/MySQL)",
        "upstream": [],
        "downstream": ["dns", "whois", "epp", "billing", "opensrs-api", "ascio", "enom"],
        "criticality": "P0",
    },
    "opensrs": {
        "desc": "OpenSRS reseller platform",
        "upstream": ["core-db", "epp-server", "billing"],
        "downstream": ["reseller-clients", "domain-registrations"],
        "criticality": "P0",
    },
    "ascio": {
        "desc": "Ascio registrar platform",
        "upstream": ["core-db"],
        "downstream": ["registrar-partners", "EU-domain-registrations"],
        "criticality": "P1",
    },
    "enom": {
        "desc": "Enom registrar platform",
        "upstream": ["core-db"],
        "downstream": ["registrar-partners", "domain-registrations"],
        "criticality": "P1",
    },
    "registry": {
        "desc": "Tucows Registry Services (TRS)",
        "upstream": ["core-db", "dns"],
        "downstream": ["TLD-operations", "ICANN-compliance"],
        "criticality": "P0",
    },
    "network": {
        "desc": "Core network infrastructure",
        "upstream": [],
        "downstream": ["all-services", "dns", "epp", "opensrs"],
        "criticality": "P0",
    },
    "mysql": {
        "desc": "MySQL database servers",
        "upstream": [],
        "downstream": ["opensrs", "enom", "ascio", "billing"],
        "criticality": "P0",
    },
    "postgres": {
        "desc": "PostgreSQL database servers",
        "upstream": [],
        "downstream": ["registry", "monitoring"],
        "criticality": "P0",
    },
    "replication": {
        "desc": "Database replication",
        "upstream": ["mysql", "postgres"],
        "downstream": ["read-replicas", "reporting", "disaster-recovery"],
        "criticality": "P1",
    },
}


class AlertPatternTracker:
    """Track recent alert patterns for frequency and dedup analysis."""
    def __init__(self, window_size=200):
        self.recent = []
        self.window_size = window_size

    def add(self, alert):
        self.recent.append({
            "name": alert.get("name", ""),
            "host": get_host(alert),
            "severity": alert.get("severity", ""),
            "fingerprint": alert.get("fingerprint", ""),
            "time": alert.get("lastReceived", ""),
        })
        if len(self.recent) > self.window_size:
            self.recent = self.recent[-self.window_size:]

    def find_similar(self, alert, max_results=3):
        name = alert.get("name", "").lower()
        host = get_host(alert).lower()
        fp = alert.get("fingerprint", "")
        similar = []
        for a in self.recent:
            if a["fingerprint"] == fp:
                continue
            if a["host"].lower() == host and host:
                similar.append(a)
            elif len(name) > 10 and a["name"][:30].lower() == name[:30]:
                similar.append(a)
        return similar[:max_results]

    def get_frequency(self, alert_name):
        return sum(1 for a in self.recent if a["name"].lower() == alert_name.lower())


pattern_tracker = AlertPatternTracker()


class FeedbackTracker:
    """Collect SRE feedback from past alerts and build lessons-learned context."""
    def __init__(self, max_items=50):
        self.items = []

    def ingest(self, alert, feedback):
        entry = {
            "alert_name": alert.get("name", "")[:80],
            "host": get_host(alert),
            "feedback": feedback,
        }
        key = f"{entry['alert_name']}|{entry['host']}"
        for existing in self.items:
            if f"{existing['alert_name']}|{existing['host']}" == key:
                existing["feedback"] = feedback
                return
        self.items.append(entry)
        if len(self.items) > 50:
            self.items = self.items[-50:]

    def build_lessons_context(self, alert, max_lessons=5):
        if not self.items:
            return ""
        alert_name = alert.get("name", "").lower()
        alert_host = get_host(alert).lower()
        stop_words = {"on", "the", "is", "for", "at", "in", "a", "-", "", "not", "to"}
        scored = []
        for item in self.items:
            fb = item["feedback"]
            if fb.get("rating") == "positive" and not fb.get("corrected_severity") and not fb.get("corrected_noise"):
                continue
            score = 0
            if item["host"].lower() == alert_host and alert_host != "unknown":
                score += 3
            if len(alert_name) > 10 and item["alert_name"][:30].lower() == alert_name[:30]:
                score += 5
            alert_words = set(alert_name.split()) - stop_words
            item_words = set(item["alert_name"].lower().split()) - stop_words
            if len(alert_words & item_words) >= 2:
                score += 2
            if score > 0:
                scored.append((score, item))
        if not scored:
            return ""
        scored.sort(key=lambda x: -x[0])
        lines = ["\nSRE FEEDBACK FROM PAST ALERTS (lessons learned -- apply these insights):"]
        for _, item in scored[:max_lessons]:
            fb = item["feedback"]
            line = f'  - Alert "{item["alert_name"][:50]}" on {item["host"]}:'
            if fb.get("rating") == "negative":
                line += " [SRE DISAGREED]"
            if fb.get("corrected_severity"):
                line += f" SRE corrected severity to {fb['corrected_severity']}."
            if fb.get("corrected_noise"):
                line += f" SRE corrected noise to {fb['corrected_noise']}/10."
            if fb.get("comment"):
                line += f' SRE said: "{fb["comment"][:120]}"'
            lines.append(line)
        lines.append("  Use these SRE corrections to calibrate your severity and noise assessments.\n")
        return "\n".join(lines)


feedback_tracker = FeedbackTracker()


def parse_sre_feedback(note):
    """Extract SRE feedback from the note field."""
    if not note:
        return None
    start_marker = "---SRE-FEEDBACK---"
    end_marker = "---END-SRE-FEEDBACK---"
    start_idx = note.find(start_marker)
    if start_idx == -1:
        return None
    end_idx = note.find(end_marker, start_idx)
    block = note[start_idx + len(start_marker):end_idx] if end_idx != -1 else note[start_idx + len(start_marker):]
    feedback = {}
    field_map = {
        "RATING": "rating",
        "CORRECTED_SEVERITY": "corrected_severity",
        "CORRECTED_NOISE": "corrected_noise",
        "COMMENT": "comment",
        "SRE_USER": "sre_user",
        "TIMESTAMP": "timestamp",
    }
    for line in block.split("\n"):
        line = line.strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        field = field_map.get(key.strip())
        if field:
            if field == "corrected_noise":
                try:
                    feedback[field] = int(val.strip())
                except ValueError:
                    pass
            else:
                feedback[field] = val.strip()
    return feedback if feedback else None


def get_host(alert):
    return alert.get("hostName", "") or alert.get("hostname", "") or "unknown"


def keep_request(path, method="GET", data=None):
    url = f"{KEEP_URL}{path}"
    body = json.dumps(data).encode() if data else None
    req = Request(url, data=body, method=method, headers={
        "X-API-KEY": KEEP_API_KEY,
        "Content-Type": "application/json",
    })
    try:
        resp = urlopen(req, timeout=30)
        raw = resp.read()
        return json.loads(raw) if raw else {}
    except HTTPError as e:
        if e.code == 404:
            return None
        body_text = ""
        try:
            body_text = e.read().decode()[:200]
        except Exception:
            pass
        log.error(f"Keep API error {e.code} on {method} {path}: {body_text}")
        return None
    except Exception as e:
        log.error(f"Keep request failed: {e}")
        return None


def ollama_generate(prompt, timeout=120):
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 768,
        },
    }).encode()
    req = Request(
        f"{OLLAMA_URL}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urlopen(req, timeout=timeout)
        data = json.loads(resp.read())
        return data.get("response", "").strip()
    except Exception as e:
        log.error(f"Ollama error: {e}")
        return None


def wait_for_ollama():
    log.info(f"Waiting for Ollama at {OLLAMA_URL}...")
    for attempt in range(60):
        try:
            resp = urlopen(f"{OLLAMA_URL}/api/tags", timeout=5)
            data = json.loads(resp.read())
            models = [m["name"] for m in data.get("models", [])]
            if any(OLLAMA_MODEL in m for m in models):
                log.info(f"Model {OLLAMA_MODEL} is ready")
                return True
            else:
                log.info(f"Available models: {models}. Pulling {OLLAMA_MODEL}...")
                pull_model()
                return True
        except Exception:
            pass
        time.sleep(10)
    log.error("Ollama not available after 10 minutes")
    return False


def pull_model():
    log.info(f"Pulling model {OLLAMA_MODEL} (this may take a few minutes)...")
    body = json.dumps({"name": OLLAMA_MODEL, "stream": False}).encode()
    req = Request(f"{OLLAMA_URL}/api/pull", data=body,
                  headers={"Content-Type": "application/json"})
    try:
        resp = urlopen(req, timeout=600)
        log.info(f"Model pull complete: {resp.read().decode()[:200]}")
    except Exception as e:
        log.error(f"Model pull failed: {e}")


def find_service_context(alert):
    """Match alert host/name against service dependency map."""
    name = alert.get("name", "").lower()
    host = get_host(alert).lower()
    combined = f"{name} {host}"

    for svc_key, svc in SERVICE_DEPS.items():
        if svc_key in combined:
            return (
                f"\nSERVICE CONTEXT:\n"
                f"- Service: {svc_key} -- {svc['desc']}\n"
                f"- Criticality: {svc['criticality']}\n"
                f"- Upstream dependencies: {', '.join(svc['upstream']) or 'none'}\n"
                f"- Downstream dependents: {', '.join(svc['downstream']) or 'none'}\n"
                f"- If this service fails, it impacts: {', '.join(svc['downstream'])}\n"
            )
    return ""


def build_enrichment_prompt(alert, similar_alerts):
    name = alert.get("name", "Unknown")
    severity = alert.get("severity", "unknown")
    status = alert.get("status", "unknown")
    host = get_host(alert)
    description = alert.get("description", "") or name
    source = alert.get("source", [])
    tags = alert.get("tags", [])
    last_received = alert.get("lastReceived", "")

    tag_str = ", ".join(
        f"{t.get('tag', t.get('name', ''))}: {t.get('value', '')}"
        for t in (tags if isinstance(tags, list) else [])
    ) or "none"
    source_str = ", ".join(source) if isinstance(source, list) else str(source)

    service_context = find_service_context(alert)

    dedup_context = ""
    if similar_alerts:
        lines = []
        for sa in similar_alerts:
            lines.append(f'  - "{sa["name"][:60]}" on {sa["host"]} (severity: {sa["severity"]})')
        dedup_context = (
            f"\nRECENT SIMILAR/RELATED ALERTS ({len(similar_alerts)}):\n"
            + "\n".join(lines) + "\n"
        )

    freq = pattern_tracker.get_frequency(name)
    freq_context = ""
    if freq > 1:
        freq_context = f"\nPATTERN: This alert has appeared {freq} times in the recent window.\n"

    # SRE feedback context
    lessons_context = feedback_tracker.build_lessons_context(alert)
    direct_feedback = parse_sre_feedback(alert.get("note", "") or "")
    direct_fb_context = ""
    if direct_feedback:
        direct_fb_context = f"\nDIRECT SRE FEEDBACK ON THIS ALERT:\n  Rating: {direct_feedback.get('rating', 'none')}\n"
        if direct_feedback.get("corrected_severity"):
            direct_fb_context += f"  SRE says correct severity is: {direct_feedback['corrected_severity']}\n"
        if direct_feedback.get("corrected_noise"):
            direct_fb_context += f"  SRE says correct noise score is: {direct_feedback['corrected_noise']}/10\n"
        if direct_feedback.get("comment"):
            direct_fb_context += f'  SRE comment: "{direct_feedback["comment"][:200]}"\n'
        direct_fb_context += "  IMPORTANT: Respect the SRE's corrections in your assessment.\n"

    return (
        "You are a senior SRE alert analyst for Tucows Domains, a major domain "
        "registrar operating critical DNS, EPP, WHOIS, and billing infrastructure "
        "across OpenSRS, Ascio, Enom, and Tucows Registry Services platforms.\n\n"
        "Apply Google SRE principles in your analysis:\n"
        "- FOCUS ON USER IMPACT: Assess whether real users (registrars, domain owners, "
        "partners) are affected. An alert without user-facing impact is lower priority "
        "regardless of the internal metric's raw value.\n"
        "- FOUR GOLDEN SIGNALS: Consider which signal this alert relates to "
        "(Latency, Traffic, Errors, Saturation). Saturation alerts (CPU, memory, disk) "
        "are early warnings — assess how close the resource is to hard limits and whether "
        "it is actively degrading user-facing SLIs.\n"
        "- SYMPTOMS vs CAUSES: Distinguish what is broken (the symptom users see) from "
        "why it is broken (the underlying cause). Frame your analysis around the symptom.\n"
        "- TRIAGE FIRST: Prioritize mitigation (restore service) over root-cause analysis. "
        "Remediation steps should focus on stopping the bleeding first, then investigating.\n"
        "- WHAT CHANGED: Consider recent deployments, config changes, traffic shifts, or "
        "upstream failures as likely triggers. Systems maintain inertia — something changed.\n"
        "- CORRELATION vs CAUSATION: If similar alerts exist, determine whether they share "
        "a root cause or are coincidental. Shared infrastructure (same host, same rack, "
        "same service) increases the probability of a common cause.\n"
        "- ACTIONABILITY: Every page should require human intelligence to resolve. If this "
        "alert would auto-resolve, is flapping, or requires no human action, it is noise.\n"
        "- ERROR BUDGET THINKING: Frame severity by how much this eats into the service's "
        "reliability budget. A brief CPU spike on a redundant DNS node is very different "
        "from sustained saturation on a single-point-of-failure database.\n\n"
        f"ALERT:\n"
        f"- Name: {name}\n"
        f"- Original Severity: {severity}\n"
        f"- Status: {status}\n"
        f"- Host: {host}\n"
        f"- Description: {description}\n"
        f"- Source: {source_str}\n"
        f"- Tags: {tag_str}\n"
        f"- Time: {last_received}\n"
        f"{service_context}"
        f"{dedup_context}"
        f"{freq_context}"
        f"{lessons_context}"
        f"{direct_fb_context}\n"
        "Respond in this EXACT format. Keep each field concise (1-3 sentences max):\n\n"
        "ASSESSED_SEVERITY: [critical/high/warning/low/info — base this on USER IMPACT "
        "and SLO risk, not just the raw metric. critical=active user-facing outage or "
        "imminent SLO breach; high=degraded service or high risk of escalation; "
        "warning=early saturation signal, no current user impact; low=informational, "
        "redundancy covers it; info=no action needed]\n"
        "LIKELY_CAUSE: [root cause hypothesis. Apply 'what changed?' thinking. "
        "Distinguish symptom from cause. Prefer simple explanations (Occam's Razor).]\n"
        "REMEDIATION: [concrete steps for on-call. TRIAGE FIRST: list immediate "
        "mitigation (failover, restart, shed load) before investigation steps. "
        "Include rollback if a recent change is suspected.]\n"
        "IMPACT_SCOPE: [affected services and users. Be specific: which SLIs are at "
        "risk? Is this a single redundant node or a single point of failure? "
        "Include upstream/downstream blast radius.]\n"
        "DEDUP_ASSESSMENT: [DUPLICATE if repeat of a similar alert above, "
        "CORRELATED if likely shares a root cause with related alerts, "
        "UNIQUE if standalone]\n"
        "DEDUP_REASON: [brief explanation. If CORRELATED, state the hypothesized "
        "shared root cause.]\n"
        "NOISE_SCORE: [1-10. 1=definitely actionable (user impact, requires human "
        "intelligence). 10=noise (auto-resolves, flapping, no user impact, or would "
        "be better as a ticket than a page). Consider: does this require urgent human "
        "action right now?]\n"
        "NOISE_REASON: [why this score, referencing actionability and user impact]\n"
        "SUMMARY: [one-line plain English for on-call. Lead with the user impact, "
        "then the technical detail.]\n"
    )


def parse_enrichment(response):
    enrichment = {
        "assessed_severity": "unknown",
        "likely_cause": "",
        "remediation": "",
        "impact_scope": "",
        "dedup_assessment": "UNIQUE",
        "dedup_reason": "",
        "noise_score": 5,
        "noise_reason": "",
        "summary": "",
    }

    field_map = {
        "ASSESSED_SEVERITY": "assessed_severity",
        "LIKELY_CAUSE": "likely_cause",
        "REMEDIATION": "remediation",
        "IMPACT_SCOPE": "impact_scope",
        "DEDUP_ASSESSMENT": "dedup_assessment",
        "DEDUP_REASON": "dedup_reason",
        "NOISE_SCORE": "noise_score",
        "NOISE_REASON": "noise_reason",
        "SUMMARY": "summary",
    }

    for line in response.split("\n"):
        line = line.strip()
        for prefix, key in field_map.items():
            if line.upper().startswith(prefix + ":"):
                val = line.split(":", 1)[1].strip()
                if key == "assessed_severity":
                    val = val.lower().strip("[]")
                    if val in ("critical", "high", "warning", "low", "info"):
                        enrichment[key] = val
                elif key == "noise_score":
                    try:
                        score = int(val.strip("[]").split("/")[0].split(" ")[0])
                        enrichment[key] = max(1, min(10, score))
                    except (ValueError, IndexError):
                        pass
                elif key == "dedup_assessment":
                    val_upper = val.upper().strip("[]")
                    if val_upper in ("DUPLICATE", "CORRELATED", "UNIQUE"):
                        enrichment[key] = val_upper
                else:
                    enrichment[key] = val
                break

    return enrichment


def enrich_alert(alert, similar_alerts):
    prompt = build_enrichment_prompt(alert, similar_alerts)
    response = ollama_generate(prompt)
    if not response:
        return None

    enrichment = parse_enrichment(response)
    enrichment["llm_model"] = OLLAMA_MODEL
    return enrichment


def post_enrichment_to_keep(alert, enrichment):
    fingerprint = alert.get("fingerprint", "")
    if not fingerprint:
        return False

    enrichment_note = (
        "---AI-ENRICHMENT-V2---\n"
        f"ASSESSED_SEVERITY: {enrichment['assessed_severity']}\n"
        f"LIKELY_CAUSE: {enrichment['likely_cause']}\n"
        f"REMEDIATION: {enrichment['remediation']}\n"
        f"IMPACT_SCOPE: {enrichment['impact_scope']}\n"
        f"DEDUP_ASSESSMENT: {enrichment['dedup_assessment']}\n"
        f"DEDUP_REASON: {enrichment['dedup_reason']}\n"
        f"NOISE_SCORE: {enrichment['noise_score']}\n"
        f"NOISE_REASON: {enrichment['noise_reason']}\n"
        f"SUMMARY: {enrichment['summary']}\n"
        f"MODEL: {enrichment.get('llm_model', 'unknown')}\n"
        "---END-AI-ENRICHMENT---"
    )

    # Preserve existing SRE feedback if present
    existing_note = alert.get("note", "") or ""
    feedback_block = ""
    fb_start = existing_note.find("---SRE-FEEDBACK---")
    if fb_start != -1:
        fb_end = existing_note.find("---END-SRE-FEEDBACK---", fb_start)
        if fb_end != -1:
            feedback_block = "\n" + existing_note[fb_start:fb_end + len("---END-SRE-FEEDBACK---")]
        else:
            feedback_block = "\n" + existing_note[fb_start:]

    note = enrichment_note + feedback_block

    result = keep_request(
        "/alerts/enrich",
        method="POST",
        data={
            "fingerprint": fingerprint,
            "enrichments": {"note": note},
        },
    )
    if result is not None:
        return True

    log.warning(f"Enrichment POST failed for {fingerprint[:16]}")
    return False


def poll_and_enrich():
    alerts_data = keep_request("/alerts?limit=250")
    if not alerts_data:
        return 0

    items = (
        alerts_data.get("items", alerts_data)
        if isinstance(alerts_data, dict)
        else alerts_data
    )
    if not isinstance(items, list):
        return 0

    # Harvest SRE feedback from all alerts for lessons learned
    fb_count = 0
    for alert in items:
        note = alert.get("note", "") or ""
        if "---SRE-FEEDBACK---" in note:
            fb = parse_sre_feedback(note)
            if fb:
                feedback_tracker.ingest(alert, fb)
                fb_count += 1
    if fb_count:
        log.info(f"Ingested {fb_count} SRE feedback entries for lessons learned")

    # Filter out resolved/ok alerts — don't waste LLM time on them
    active_alerts = []
    for alert in items:
        status = (alert.get("status") or "").lower()
        if status in ("resolved", "ok"):
            # Cache resolved fingerprints so we never revisit them
            fp = alert.get("fingerprint", "")
            if fp:
                enriched_cache.add(fp)
            continue
        active_alerts.append(alert)

    log.info(f"Found {len(active_alerts)} active alerts (skipped {len(items) - len(active_alerts)} resolved)")

    enriched_count = 0
    for alert in active_alerts:
        fingerprint = alert.get("fingerprint", "")
        if not fingerprint or fingerprint in enriched_cache:
            continue

        note = alert.get("note", "") or ""
        if "---AI-ENRICHMENT-V2---" in note or note.startswith("AI Summary:"):
            enriched_cache.add(fingerprint)
            continue

        name = alert.get("name", "unknown")
        log.info(f"Enriching: {name[:60]} (fp: {fingerprint[:16]}...)")

        similar = pattern_tracker.find_similar(alert)
        enrichment = enrich_alert(alert, similar)
        if enrichment:
            success = post_enrichment_to_keep(alert, enrichment)
            if success:
                enriched_cache.add(fingerprint)
                pattern_tracker.add(alert)
                enriched_count += 1
                log.info(
                    f"  -> severity={enrichment['assessed_severity']} "
                    f"noise={enrichment['noise_score']}/10 "
                    f"dedup={enrichment['dedup_assessment']} "
                    f"| {enrichment['summary'][:60]}"
                )
            else:
                log.warning("  -> Failed to post enrichment to Keep")
        else:
            log.warning("  -> LLM returned no response")

    return enriched_count


def main():
    log.info("Starting Enhanced LLM Alert Enrichment Service v2")
    log.info(f"Ollama: {OLLAMA_URL} | Model: {OLLAMA_MODEL}")
    log.info(f"Keep: {KEEP_URL} | Poll interval: {POLL_INTERVAL}s")

    if not wait_for_ollama():
        log.error("Cannot start without Ollama. Exiting.")
        return

    log.info("Testing LLM connectivity...")
    test = ollama_generate("Say 'ready' if you can process alerts.")
    if test:
        log.info(f"LLM test: {test[:100]}")
    else:
        log.warning("LLM test failed, will retry during enrichment")

    while True:
        try:
            count = poll_and_enrich()
            if count > 0:
                log.info(f"Enriched {count} alerts this cycle")
        except Exception as e:
            log.error(f"Enrichment cycle failed: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
