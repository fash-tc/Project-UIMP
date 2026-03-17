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
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))
FLAP_WINDOW = int(os.environ.get("FLAP_WINDOW_SECONDS", "600"))
DEDUP_WINDOW = int(os.environ.get("DEDUP_WINDOW_SECONDS", "1800"))
NOISE_THRESHOLD = int(os.environ.get("NOISE_THRESHOLD", "8"))
ALERT_STATE_API_URL = os.environ.get("ALERT_STATE_API_URL", "http://alert-state-api:8092")

enriched_cache = set()

# In-memory tracking for noise suppression
recent_enrichments = {}  # fingerprint -> {alert_name, host, enrichment_text, noise_score, enriched_at, resolve_count, last_resolved_at}

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

RUNBOOK_API_URL = os.environ.get("RUNBOOK_API_URL", "http://runbook-api:8090")



def fetch_runbook_entries(alert_name, hostname, service=None):
    """Query the runbook API for matching remediation entries."""
    from urllib.parse import quote
    params = f"alert_name={quote(alert_name)}"
    if hostname and hostname.lower() not in ("unknown", "n/a", ""):
        params += f"&hostname={quote(hostname)}"
    if service:
        params += f"&service={quote(service)}"
    url = f"{RUNBOOK_API_URL}/api/runbook/match?{params}&limit=5"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data if isinstance(data, list) else []
    except Exception as e:
        log.debug(f"Runbook API query failed (non-fatal): {e}")
        return []


def fetch_runbook_feedback(entry_ids):
    """Fetch SRE feedback on runbook entries from alert-state-api."""
    if not entry_ids:
        return []
    ids_str = ",".join(str(i) for i in entry_ids)
    url = f"{ALERT_STATE_API_URL}/api/alert-states/runbook-feedback?entry_ids={ids_str}"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data if isinstance(data, list) else []
    except Exception as e:
        log.debug(f"Runbook feedback fetch failed (non-fatal): {e}")
        return []


def fetch_ai_instructions():
    """Fetch active global AI instructions from the runbook API."""
    url = f"{RUNBOOK_API_URL}/api/runbook/ai-instructions"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data if isinstance(data, list) else []
    except Exception as e:
        log.debug(f"AI instructions fetch failed (non-fatal): {e}")
        return []




def fetch_feedback_matches(alert_name, service=""):
    """Fetch structured SRE feedback corrections for similar alerts."""
    from urllib.parse import quote
    params = f"alert_name={quote(alert_name)}"
    if service:
        params += f"&service={quote(service)}"
    url = f"{RUNBOOK_API_URL}/api/runbook/feedback/match?{params}"
    req = Request(url, headers={"Content-Type": "application/json"})
    try:
        resp = urlopen(req, timeout=5)
        return json.loads(resp.read())
    except Exception as e:
        log.warning(f"Feedback match fetch failed: {e}")
        return []


def infer_service(alert):
    """Infer the service name from alert name/hostname using the service dependency map."""
    name = alert.get("name", "").lower()
    host = get_host(alert).lower()
    combined = f"{name} {host}"
    for svc_key in SERVICE_DEPS:
        if svc_key in combined:
            return svc_key
    return None


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


def ollama_generate(prompt, timeout=45):
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "think": False,
        "options": {
            "num_predict": 1024,
        },
    }).encode()
    req = Request(
        f"{OLLAMA_URL}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    for attempt in range(2):
        try:
            resp = urlopen(req, timeout=timeout)
            data = json.loads(resp.read())
            msg = data.get("message", {})
            return msg.get("content", "").strip()
        except Exception as e:
            if attempt == 0:
                log.warning(f"Ollama timeout/error (attempt 1), retrying: {e}")
                time.sleep(2)
            else:
                log.error(f"Ollama failed after 2 attempts: {e}")
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
    zabbix_instance = alert.get("zabbixInstance", "")
    if zabbix_instance:
        source_str = f"{source_str} ({zabbix_instance})"

    service_context = find_service_context(alert)

    # Log correlation is on-demand only (via UI) — Loki is too resource-heavy for auto-queries
    log_context = ""

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

    # Structured SRE feedback from similar alerts
    service = infer_service(alert)
    feedback_matches = fetch_feedback_matches(name, service or "")
    feedback_context = ""
    if feedback_matches:
        lines = ["\nSRE CORRECTIONS FOR SIMILAR ALERTS (apply these corrections to your analysis):"]
        for fb in feedback_matches:
            lines.append(f'  - Pattern: "{fb["alert_pattern"]}" (by {fb["sre_user"]})')
            if fb.get("severity_correction"):
                lines.append(f'    Severity should be: {fb["severity_correction"]}')
            if fb.get("cause_correction"):
                lines.append(f'    Cause correction: {fb["cause_correction"]}')
            if fb.get("remediation_correction"):
                lines.append(f'    Remediation: {fb["remediation_correction"]}')
            if fb.get("full_text"):
                lines.append(f'    Notes: {fb["full_text"][:200]}')
        lines.append("  IMPORTANT: Apply these SRE corrections to your assessment.\n")
        feedback_context = "\n".join(lines)

    # Legacy lessons context (secondary signal)
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

    # Runbook entries context (with SRE feedback integration)
    runbook_entries = fetch_runbook_entries(name, host, service)

    # Fetch SRE feedback on runbook entries
    entry_ids = [e.get("id") for e in runbook_entries if e.get("id")]
    feedback_rows = fetch_runbook_feedback(entry_ids)

    # Aggregate votes per entry_id: net score (up=+1, down=-1)
    vote_scores = {}
    for fb in feedback_rows:
        eid = fb.get("runbook_entry_id")
        v = 1 if fb.get("vote") == "up" else -1
        vote_scores[eid] = vote_scores.get(eid, 0) + v

    runbook_context = ""
    if runbook_entries:
        good_lines = ["\nRUNBOOK ENTRIES (real SRE remediation experience for similar alerts — use as authoritative reference):"]
        bad_lines = ["\nDOWNVOTED REMEDIATION (marked irrelevant by SREs — do NOT recommend these):"]
        has_good = False
        has_bad = False
        for entry in runbook_entries[:5]:
            date = (entry.get("created_at") or "unknown")[:10]
            user = entry.get("sre_user") or "unknown"
            e_name = (entry.get("alert_name") or "")[:60]
            e_host = entry.get("hostname") or "N/A"
            rem = (entry.get("remediation") or "")[:300]
            eid = entry.get("id")
            score = vote_scores.get(eid, 0)
            line1 = f'  - [{date}, {user}] Alert: "{e_name}" | Host: {e_host}'
            line2 = f'    Remediation: "{rem}"'
            if score < 0:
                bad_lines.append(line1)
                bad_lines.append(line2)
                has_bad = True
            else:
                good_lines.append(line1)
                good_lines.append(line2)
                has_good = True
        if has_good:
            good_lines.append("  Apply these SRE-validated remediation steps to your REMEDIATION field when relevant.\n")
            runbook_context += "\n".join(good_lines)
        if has_bad:
            bad_lines.append("  These have been flagged as unhelpful. Do not use them.\n")
            runbook_context += "\n".join(bad_lines)

    # Global AI instructions from SRE team
    ai_instructions = fetch_ai_instructions()
    instructions_context = ""
    if ai_instructions:
        lines = ["\nGLOBAL SRE DIRECTIVES (instructions from SRE team — follow these):"]
        for i, instr in enumerate(ai_instructions, 1):
            text = (instr.get("instruction") or "")[:300]
            lines.append(f"  {i}. {text}")
        lines.append("  Apply these directives to your analysis.\n")
        instructions_context = "\n".join(lines)

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
        f"{log_context}"
        f"{dedup_context}"
        f"{freq_context}"
        f"{feedback_context}"
        f"{lessons_context}"
        f"{direct_fb_context}"
        f"{runbook_context}"
        f"{instructions_context}\n"
        "Respond with a JSON object containing exactly these fields (keep values concise, 1-3 sentences):\n"
        '{"assessed_severity": "critical|high|warning|low|info",\n'
        '"likely_cause": "root cause hypothesis",\n'
        '"remediation": "concrete triage-first steps for on-call",\n'
        '"impact_scope": "affected services/users, SLIs at risk, blast radius",\n'
        '"dedup_assessment": "DUPLICATE|CORRELATED|UNIQUE",\n'
        '"dedup_reason": "brief explanation",\n'
        '"noise_score": 1,\n'
        '"noise_reason": "why this score",\n'
        '"summary": "one-line for on-call, lead with user impact"}\n\n'
        "Rules: assessed_severity must be one of critical/high/warning/low/info. "
        "noise_score must be integer 1-10 (1=actionable, 10=noise). "
        "dedup_assessment must be DUPLICATE, CORRELATED, or UNIQUE. "
        "Output ONLY valid JSON, no commentary.\n"
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

    # Try JSON parsing first (preferred — matches Modelfile output format)
    try:
        # Strip markdown code fences if present
        text = response.strip()
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:])
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()
        data = json.loads(text)
        if isinstance(data, dict):
            for key in enrichment:
                if key in data:
                    val = data[key]
                    if key == "assessed_severity":
                        val = str(val).lower().strip()
                        if val in ("critical", "high", "warning", "low", "info"):
                            enrichment[key] = val
                    elif key == "noise_score":
                        try:
                            enrichment[key] = max(1, min(10, int(val)))
                        except (ValueError, TypeError):
                            pass
                    elif key == "dedup_assessment":
                        val_upper = str(val).upper().strip()
                        if val_upper in ("DUPLICATE", "CORRELATED", "UNIQUE"):
                            enrichment[key] = val_upper
                    else:
                        enrichment[key] = str(val).strip()
            log.debug("Parsed enrichment as JSON")
    except (json.JSONDecodeError, ValueError):
        # Fall back to text-based parsing (ASSESSED_SEVERITY: ... format)
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
        log.debug("Parsed enrichment as text")

    # Fill empty critical fields with fallback values
    if not enrichment["remediation"]:
        enrichment["remediation"] = (
            "1. Check current resource utilization on the affected host. "
            "2. Review recent changes or deployments. "
            "3. Escalate to the responsible team if the issue persists."
        )
    if not enrichment["likely_cause"]:
        enrichment["likely_cause"] = "Unable to determine root cause from available context."
    if not enrichment["impact_scope"]:
        enrichment["impact_scope"] = "Impact assessment requires manual investigation."
    if not enrichment["noise_reason"]:
        enrichment["noise_reason"] = "Insufficient context to determine noise level."

    return enrichment


def enrich_alert(alert, similar_alerts):
    prompt = build_enrichment_prompt(alert, similar_alerts)
    response = ollama_generate(prompt)
    if not response:
        # Tag alert as pending so it gets retried next cycle
        fingerprint = alert.get("fingerprint", "")
        if fingerprint:
            pending_note = "ENRICHMENT_PENDING: LLM timeout — will retry next cycle"
            keep_request("/alerts/enrich", method="POST", data={
                "fingerprint": fingerprint,
                "enrichments": {"note": pending_note},
            })
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


def check_suppression(alert):
    """Check if alert should be suppressed from enrichment. Returns (suppress: bool, reason: str, copied_enrichment: str|None)."""
    fp = alert.get("fingerprint", "")
    name = alert.get("name", "")
    host = get_host(alert)
    now = time.time()

    # Evict stale entries (older than 2 hours)
    stale = [k for k, v in recent_enrichments.items() if now - v["enriched_at"] > 7200]
    for k in stale:
        del recent_enrichments[k]

    # Rule 1: Flapping detection
    if fp in recent_enrichments:
        entry = recent_enrichments[fp]
        if entry.get("last_resolved_at") and (now - entry["last_resolved_at"]) < FLAP_WINDOW:
            count = entry.get("resolve_count", 0)
            return True, f"NOISE: FLAPPING — same alert resolved and re-fired {count} times in last hour. Enrichment suppressed.", None

    # Rule 2: Recent duplicate (same name+host already enriched)
    for efp, entry in recent_enrichments.items():
        if efp == fp:
            continue
        if entry["alert_name"] == name and entry["host"] == host:
            if (now - entry["enriched_at"]) < DEDUP_WINDOW:
                return True, f"ENRICHMENT (copied from {efp[:16]} at {time.strftime('%H:%M', time.localtime(entry['enriched_at']))}): duplicate suppressed.", entry["enrichment_text"]

    # Rule 3: High noise pattern
    for efp, entry in recent_enrichments.items():
        if entry["alert_name"] == name and entry.get("noise_score", 0) >= NOISE_THRESHOLD:
            return True, f"NOISE: Score {entry['noise_score']}/10 from previous instance. Enrichment reused.", entry["enrichment_text"]

    return False, "", None


def fetch_force_enrich_fingerprints():
    """Get fingerprints that SREs have manually requested enrichment for."""
    try:
        req = Request(f"{ALERT_STATE_API_URL}/api/alert-states?force_enrich=true")
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return {item["alert_fingerprint"] for item in data}
    except Exception:
        return set()


def clear_force_enrich(fingerprint):
    """Clear the force_enrich flag after enrichment."""
    try:
        body = json.dumps({"fingerprint": fingerprint}).encode()
        req = Request(f"{ALERT_STATE_API_URL}/api/alert-states/clear-force-enrich",
                      data=body, headers={"Content-Type": "application/json"})
        urlopen(req, timeout=5)
    except Exception:
        pass


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
                # Track resolve counts for flapping detection
                if fp in recent_enrichments:
                    recent_enrichments[fp]["resolve_count"] = recent_enrichments[fp].get("resolve_count", 0) + 1
                    recent_enrichments[fp]["last_resolved_at"] = time.time()
            continue
        active_alerts.append(alert)

    log.info(f"Found {len(active_alerts)} active alerts (skipped {len(items) - len(active_alerts)} resolved)")

    # Fetch force-enrich requests from SREs
    force_enrich_fps = fetch_force_enrich_fingerprints()
    suppressed_count = 0

    enriched_count = 0
    for alert in active_alerts:
        fingerprint = alert.get("fingerprint", "")
        if not fingerprint or fingerprint in enriched_cache:
            continue

        note = alert.get("note", "") or ""
        if "---AI-ENRICHMENT-V2---" in note or note.startswith("AI Summary:"):
            enriched_cache.add(fingerprint)
            continue
        # Allow retry of pending alerts (don't cache them)
        if note.startswith("ENRICHMENT_PENDING:"):
            log.info(f"Retrying pending enrichment: {alert.get('name', '')[:60]}")
        elif fingerprint in enriched_cache:
            continue

        name = alert.get("name", "unknown")

        # Check noise suppression (skip if force-enriched)
        if fingerprint not in force_enrich_fps:
            suppress, reason, copied = check_suppression(alert)
            if suppress:
                # Write suppression note to Keep
                note_text = reason
                if copied:
                    note_text = copied  # Use the copied enrichment
                keep_request("/alerts/enrich", method="POST", data={
                    "fingerprint": fingerprint,
                    "enrichments": {"note": note_text},
                })
                enriched_cache.add(fingerprint)
                suppressed_count += 1
                log.info(f"  Suppressed: {name[:40]} — {reason[:60]}")
                continue
        else:
            log.info(f"  Force-enriching: {name[:40]} (requested by SRE)")
            clear_force_enrich(fingerprint)

        log.info(f"Enriching: {name[:60]} (fp: {fingerprint[:16]}...)")

        similar = pattern_tracker.find_similar(alert)
        enrichment = enrich_alert(alert, similar)
        if enrichment:
            success = post_enrichment_to_keep(alert, enrichment)
            if success:
                enriched_cache.add(fingerprint)
                pattern_tracker.add(alert)
                enriched_count += 1
                # Track for noise suppression
                recent_enrichments[fingerprint] = {
                    "alert_name": name,
                    "host": get_host(alert),
                    "enrichment_text": (
                        f"---AI-ENRICHMENT-V2---\n"
                        f"ASSESSED_SEVERITY: {enrichment['assessed_severity']}\n"
                        f"LIKELY_CAUSE: {enrichment['likely_cause']}\n"
                        f"REMEDIATION: {enrichment['remediation']}\n"
                        f"IMPACT_SCOPE: {enrichment['impact_scope']}\n"
                        f"NOISE_SCORE: {enrichment['noise_score']}\n"
                        f"SUMMARY: {enrichment['summary']}\n"
                        f"---END-AI-ENRICHMENT---"
                    ),
                    "noise_score": int(enrichment.get("noise_score", 0)),
                    "enriched_at": time.time(),
                    "resolve_count": 0,
                    "last_resolved_at": None,
                }
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

    if suppressed_count:
        log.info(f"Suppressed {suppressed_count} alerts (noise/flapping/dedup)")

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
