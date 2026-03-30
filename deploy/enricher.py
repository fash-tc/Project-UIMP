#!/usr/bin/env python3
"""Enhanced LLM-powered alert enrichment service.
Polls Keep for new alerts, performs deduplication assessment,
sends to Ollama for deep analysis with service dependency context,
and writes structured enrichment back to Keep."""

import json
import time
import os
import logging
import hashlib
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
MAINT_API_URL = os.environ.get("MAINT_API_URL", "http://10.177.154.174/api/active-now")
STALE_RESOLVE_SECONDS = int(os.environ.get("STALE_RESOLVE_SECONDS", "7200"))  # Auto-resolve after 2h with no update

enriched_cache = {}  # {fingerprint: timestamp} — entries expire after 600s

# In-memory tracking for noise suppression
recent_enrichments = {}  # fingerprint -> {alert_name, host, enrichment_text, noise_score, enriched_at, resolve_count, last_resolved_at}

# Vendor keyword -> operator IDs for maintenance correlation
VENDOR_OPERATOR_MAP = {
    'verisign': ['verisign'],
    'centralnic': ['centralnic'],
    'afilias': ['identity-digital'],
    'identity digital': ['identity-digital'],
    'donuts': ['identity-digital'],
    'neustar': ['godaddy-registry'],
    'godaddy registry': ['godaddy-registry'],
    'godaddy': ['godaddy-registry'],
    'cira': ['cira'],
    'nominet': ['nominet'],
    'pir': ['pir'],
    'afnic': ['afnic'],
    'eurid': ['eurid'],
    'denic': ['denic'],
    'sidn': ['sidn'],
    'red.es': ['red'],
    'gmo': ['gmo-registry'],
    'google': ['google-registry'],
    'ari': ['ari-registry'],
    'corenic': ['corenic'],
    'nic.at': ['nic-at'],
    'switch': ['switch'],
    'registro': ['registro'],
    'nicit': ['nicit'],
    'opensrs': ['trs'],
    'tucows registry': ['trs'],
}

REGISTRY_KEYWORDS = ["registry", "registrar", "epp", "whois", "rdap", "tld", "proxy", "domain"]

_last_summary_hash = ""
_last_summary_time = 0
_SUMMARY_COOLDOWN = 300

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


def fetch_sre_feedback_by_name(alert_name):
    """Fetch all SRE feedback entries for an alert name (for learning)."""
    from urllib.parse import quote
    url = f"{ALERT_STATE_API_URL}/api/alert-states/sre-feedback/by-alert-name?name={quote(alert_name)}"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data if isinstance(data, list) else []
    except Exception as e:
        log.warning(f"Failed to fetch SRE feedback for '{alert_name}': {e}")
    return []


def fetch_sre_feedback_by_fingerprint(fingerprint):
    """Fetch SRE feedback for a specific alert instance."""
    from urllib.parse import quote
    url = f"{ALERT_STATE_API_URL}/api/alert-states/sre-feedback?fingerprint={quote(fingerprint)}"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data if isinstance(data, list) else []
    except Exception as e:
        log.warning(f"Failed to fetch SRE feedback for fp {fingerprint[:16]}: {e}")
    return []


def fetch_active_maintenance():
    """Fetch currently active maintenance events from the maintenance API."""
    try:
        req = Request(MAINT_API_URL, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data.get("results", []) if isinstance(data, dict) else []
    except Exception as e:
        log.debug(f"Maintenance API fetch failed (non-fatal): {e}")
        return []


def match_maintenance_to_alert(alert, maintenance_events):
    """Check if any active maintenance events are related to this alert."""
    name = alert.get("name", "").lower()
    description = (alert.get("description", "") or "").lower()
    host = (alert.get("hostName", "") or alert.get("hostname", "") or "").lower()
    combined = f"{name} {description} {host}"

    # Only check registry-related alerts
    is_registry = any(kw in combined for kw in REGISTRY_KEYWORDS)
    if not is_registry:
        return []

    matched = []
    for event in maintenance_events:
        vendor = (event.get("vendor", "") or "").lower()
        title = (event.get("title", "") or "").lower()
        event_text = f"{vendor} {title}"

        for keyword, operator_ids in VENDOR_OPERATOR_MAP.items():
            if keyword in event_text and keyword in combined:
                matched.append(event)
                break
            # Also check if vendor keyword matches any part of the alert
            if keyword in event_text:
                # Check if alert mentions any TLD or registry term that links to this vendor
                for kw in REGISTRY_KEYWORDS:
                    if kw in combined:
                        matched.append(event)
                        break
                break

    # Deduplicate
    seen = set()
    unique = []
    for m in matched:
        mid = m.get("id", id(m))
        if mid not in seen:
            seen.add(mid)
            unique.append(m)
    return unique


def fetch_runbook_exclusions(alert_name):
    """Fetch runbook exclusions for an alert name."""
    from urllib.parse import quote
    url = f"{ALERT_STATE_API_URL}/api/alert-states/runbook-exclusions?alert_name={quote(alert_name)}"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data if isinstance(data, list) else []
    except Exception as e:
        log.warning(f"Failed to fetch runbook exclusions for '{alert_name}': {e}")
    return []


def fetch_runbook_feedback_aggregate(entry_ids):
    """Fetch aggregate vote scores for runbook entries across all alerts."""
    if not entry_ids:
        return {}
    ids_str = ",".join(str(i) for i in entry_ids)
    url = f"{ALERT_STATE_API_URL}/api/alert-states/runbook-feedback/aggregate?entry_ids={ids_str}"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data if isinstance(data, dict) else {}
    except Exception as e:
        log.warning(f"Failed to fetch runbook feedback aggregate: {e}")
    return {}


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

    # Fetch SRE feedback from alert-state-api (replaces note-field parsing)
    fingerprint = alert.get("fingerprint", "")

    # Historical feedback for learning (all instances of this alert)
    sre_feedback_historical = fetch_sre_feedback_by_name(name)
    # Current instance feedback
    sre_feedback_current = fetch_sre_feedback_by_fingerprint(fingerprint)

    # Build SRE feedback prompt section
    direct_fb_context = ""
    if sre_feedback_current:
        direct_fb_context += "\nDIRECT SRE FEEDBACK ON THIS ALERT INSTANCE:\n"
        for fb in sre_feedback_current:
            vote_label = ""
            vs = fb.get("vote_score", 0)
            if vs > 0:
                vote_label = f" [SRE TEAM CONSENSUS, +{vs}]"
            elif vs < 0:
                vote_label = f" [DISPUTED, {vs}]"
            direct_fb_context += f"  - {fb.get('user', 'SRE')}: {fb.get('rating', 'unknown')}{vote_label}\n"
            if fb.get("corrected_severity"):
                direct_fb_context += f"    Corrected severity: {fb['corrected_severity']}\n"
            if fb.get("corrected_noise") is not None:
                direct_fb_context += f"    Corrected noise: {fb['corrected_noise']}/10\n"
            if fb.get("comment"):
                direct_fb_context += f"    Comment: {fb['comment']}\n"

    if sre_feedback_historical:
        # Filter out entries already shown in current instance
        current_ids = {fb.get("id") for fb in sre_feedback_current}
        historical_only = [fb for fb in sre_feedback_historical if fb.get("id") not in current_ids]
        if historical_only:
            direct_fb_context += "\nHISTORICAL SRE FEEDBACK ON SIMILAR ALERTS:\n"
            for fb in historical_only[:10]:  # Limit to top 10
                vote_label = ""
                vs = fb.get("vote_score", 0)
                if vs > 0:
                    vote_label = f" [VALIDATED, +{vs}]"
                elif vs < 0:
                    vote_label = f" [DISPUTED, {vs}]"
                else:
                    vote_label = " [UNVALIDATED]"
                direct_fb_context += f"  - {fb.get('user', 'SRE')}: {fb.get('rating', 'unknown')}{vote_label}\n"
                if fb.get("corrected_severity"):
                    direct_fb_context += f"    Corrected severity: {fb['corrected_severity']}\n"
                if fb.get("corrected_noise") is not None:
                    direct_fb_context += f"    Corrected noise: {fb['corrected_noise']}/10\n"
                if fb.get("comment"):
                    direct_fb_context += f"    Comment: {fb['comment']}\n"

    if direct_fb_context:
        direct_fb_context += "\nIMPORTANT: Respect the SRE's corrections in your assessment. Feedback with positive vote scores represents team consensus.\n"

    # Fallback: if no API feedback found, try legacy note-field parsing
    if not sre_feedback_current and not sre_feedback_historical:
        legacy_feedback = parse_sre_feedback(alert.get("note", "") or "")
        if legacy_feedback:
            direct_fb_context = f"\nDIRECT SRE FEEDBACK ON THIS ALERT:\n"
            direct_fb_context += f"  Rating: {legacy_feedback.get('rating', 'unknown')}\n"
            if legacy_feedback.get("corrected_severity"):
                direct_fb_context += f"  Corrected severity: {legacy_feedback['corrected_severity']}\n"
            if legacy_feedback.get("corrected_noise"):
                direct_fb_context += f"  Corrected noise: {legacy_feedback['corrected_noise']}/10\n"
            if legacy_feedback.get("comment"):
                direct_fb_context += f"  Comment: {legacy_feedback['comment']}\n"
            direct_fb_context += "\nIMPORTANT: Respect the SRE's corrections in your assessment.\n"

    # Runbook entries context (with SRE feedback integration)
    runbook_entries = fetch_runbook_entries(name, host, service)

    # Fetch runbook exclusions
    exclusions = fetch_runbook_exclusions(name)
    excluded_ids = {e.get("runbook_entry_id") for e in exclusions}

    # Filter out excluded entries
    runbook_entries = [e for e in runbook_entries if e.get("id") not in excluded_ids]

    # Fetch aggregate historical vote scores
    entry_ids = [e.get("id") for e in runbook_entries if e.get("id")]
    agg_scores = fetch_runbook_feedback_aggregate(entry_ids) if entry_ids else {}

    # Build runbook prompt section with vote weighting
    runbook_context = ""
    if runbook_entries:
        upvoted = []
        neutral = []
        downvoted = []
        for entry in runbook_entries[:5]:
            eid = str(entry.get("id", ""))
            agg = agg_scores.get(eid, {})
            net_score = agg.get("net_score", 0)
            date = (entry.get("created_at") or "unknown")[:10]
            user = entry.get("sre_user") or "unknown"
            e_name = (entry.get("alert_name") or "")[:60]
            e_host = entry.get("hostname") or "N/A"
            rem = (entry.get("remediation") or "")[:300]
            detail = f'  [{date}, {user}] Alert: "{e_name}" | Host: {e_host}\n    Remediation: "{rem}"'
            if net_score > 0:
                upvoted.append((detail, net_score))
            elif net_score < 0:
                downvoted.append((detail, net_score))
            else:
                neutral.append(detail)

        if upvoted:
            runbook_context += "\nSRE-VALIDATED REMEDIATION (use as authoritative reference):\n"
            for detail, score in upvoted:
                runbook_context += f"  [+{score}] {detail}\n"
            runbook_context += "  Apply these SRE-validated remediation steps to your REMEDIATION field when relevant.\n"
        if neutral:
            runbook_context += "\nRUNBOOK ENTRIES (unvalidated):\n"
            for detail in neutral:
                runbook_context += f"  {detail}\n"
        if downvoted:
            runbook_context += "\nLOW-CONFIDENCE REMEDIATION (historically disputed — use with caution):\n"
            for detail, score in downvoted:
                runbook_context += f"  [{score}] {detail}\n"
            runbook_context += "  These have been flagged as unhelpful. Do not use them.\n"

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

    # Maintenance context
    maintenance_context = ""
    try:
        maintenance_events = fetch_active_maintenance()
        maintenance_matches = match_maintenance_to_alert(alert, maintenance_events)
        if maintenance_matches:
            maintenance_context = "\nACTIVE MAINTENANCE WINDOWS (factor into noise/severity assessment):\n"
            for m in maintenance_matches[:3]:
                end = m.get("end_time", "unknown")
                maintenance_context += f'  - "{m.get("title", "")}" ({m.get("vendor", "")}), until {end}\n'
            maintenance_context += "  NOTE: Alerts during scheduled maintenance are typically high-noise (8-10/10). Consider this in your assessment.\n"
    except Exception as e:
        log.debug(f"Maintenance context build failed (non-fatal): {e}")

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
        f"{instructions_context}"
        f"{maintenance_context}\n"
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


def fetch_silence_rules():
    """Fetch active silence rules from alert-state-api."""
    try:
        req = Request(f"{ALERT_STATE_API_URL}/api/alert-states/silence-rules")
        resp = urlopen(req, timeout=5)
        return json.loads(resp.read())
    except Exception:
        return []


def is_alert_silenced(alert, silence_rules):
    """Check if an alert matches any active silence rule. Returns matched rule or None."""
    import re as _re
    name = (alert.get("name") or "").lower()
    host = get_host(alert).lower()
    for rule in silence_rules:
        pattern = (rule.get("alert_name_pattern") or "").lower()
        if not pattern or pattern not in name:
            continue
        host_pattern = rule.get("hostname_pattern")
        if host_pattern:
            hp = host_pattern.lower()
            if "*" in hp:
                regex_str = hp.replace(".", r"\.").replace("*", ".*")
                if not _re.search(r"(^|\.)"+regex_str+r"$", host):
                    continue
            else:
                if hp not in host:
                    continue
        return rule
    return None


# ── Alert Clustering ──────────────────────────────────────
def cluster_alerts(active_alerts):
    """Group related active alerts using deterministic rules."""
    by_host = {}
    by_prefix = {}
    for a in active_alerts:
        host = get_host(a)
        if host and host != "unknown":
            by_host.setdefault(host, []).append(a)
        name = a.get("name", "")
        if ":" in name:
            prefix = name.split(":")[0].strip()
            if len(prefix) > 2:
                by_prefix.setdefault(prefix, []).append(a)

    assigned = set()
    clusters = []
    sev_order = {"critical": 0, "high": 1, "warning": 2, "low": 3, "info": 4}

    def get_top_severity(alerts_list):
        severities = []
        for a in alerts_list:
            note = a.get("note", "") or ""
            for line in note.split("\n"):
                if line.startswith("ASSESSED_SEVERITY:"):
                    severities.append(line.split(":", 1)[1].strip())
                    break
        return min(severities, key=lambda s: sev_order.get(s, 5)) if severities else "unknown"

    # Rule 1: Same host
    for host, alerts in sorted(by_host.items(), key=lambda x: -len(x[1])):
        fps = [a.get("fingerprint", "") for a in alerts if a.get("fingerprint", "") not in assigned]
        if len(fps) >= 2:
            cluster_list = [a for a in alerts if a.get("fingerprint", "") in set(fps)]
            names = [a.get("name", "")[:60] for a in cluster_list]
            top_sev = get_top_severity(cluster_list)
            cid = "c_" + hashlib.sha256(",".join(sorted(fps)).encode()).hexdigest()[:12]
            clusters.append({
                "cluster_id": cid, "label": host, "fingerprints": fps,
                "alert_names": names, "top_severity": top_sev,
                "count": len(fps), "hosts": [host],
            })
            assigned.update(fps)

    # Rule 2: Same service prefix (across hosts)
    for prefix, alerts in sorted(by_prefix.items(), key=lambda x: -len(x[1])):
        fps = [a.get("fingerprint", "") for a in alerts if a.get("fingerprint", "") not in assigned]
        if len(fps) >= 2:
            cluster_list = [a for a in alerts if a.get("fingerprint", "") in set(fps)]
            names = [a.get("name", "")[:60] for a in cluster_list]
            hosts = sorted(set(get_host(a) for a in cluster_list))
            top_sev = get_top_severity(cluster_list)
            cid = "c_" + hashlib.sha256(",".join(sorted(fps)).encode()).hexdigest()[:12]
            clusters.append({
                "cluster_id": cid, "label": f"{prefix} (multi-host)", "fingerprints": fps,
                "alert_names": names, "top_severity": top_sev,
                "count": len(fps), "hosts": hosts,
            })
            assigned.update(fps)

    # Remaining: single-alert clusters
    for a in active_alerts:
        fp = a.get("fingerprint", "")
        if fp and fp not in assigned:
            clusters.append({
                "cluster_id": "c_" + fp[:12], "label": get_host(a) or a.get("name", "unknown")[:30],
                "fingerprints": [fp], "alert_names": [a.get("name", "")[:60]],
                "top_severity": "unknown", "count": 1, "hosts": [get_host(a)],
            })

    return clusters


def merge_related_clusters(clusters):
    """Merge clusters whose host labels differ only by trailing digits."""
    import re

    def normalize_label(label):
        """Strip trailing digits from each hostname segment for pattern matching."""
        if "(" in label:
            return label  # Skip service-prefix labels like "MySQL (multi-host)"
        parts = label.split(".")
        normalized = []
        for p in parts:
            normalized.append(re.sub(r'\d+$', '', p))
        return ".".join(normalized)

    # Group clusters by normalized label
    groups = {}
    for c in clusters:
        norm = normalize_label(c["label"])
        groups.setdefault(norm, []).append(c)

    merged = []
    for norm, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue
        # Merge all clusters in this group
        all_fps = []
        all_names = []
        all_hosts = []
        top_sev = "info"
        sev_order = {"critical": 0, "high": 1, "warning": 2, "low": 3, "info": 4}
        for c in group:
            all_fps.extend(c.get("fingerprints", []))
            all_names.extend(c.get("alert_names", []))
            all_hosts.extend(c.get("hosts", []))
            c_sev = c.get("top_severity", "info")
            if sev_order.get(c_sev, 5) < sev_order.get(top_sev, 5):
                top_sev = c_sev
        # Build wildcard label
        labels = [c["label"] for c in group]
        parts = labels[0].split(".")
        wild_parts = []
        for i, p in enumerate(parts):
            variants = set(l.split(".")[i] if i < len(l.split(".")) else "" for l in labels)
            if len(variants) > 1:
                wild_parts.append(re.sub(r'\d+$', '', p) + "*")
            else:
                wild_parts.append(p)
        wild_label = ".".join(wild_parts)

        cid = "c_" + hashlib.sha256(",".join(sorted(all_fps)).encode()).hexdigest()[:12]
        merged.append({
            "cluster_id": cid,
            "label": wild_label,
            "fingerprints": all_fps,
            "alert_names": all_names,
            "top_severity": top_sev,
            "count": len(all_fps),
            "hosts": sorted(set(all_hosts)),
        })

    # Second pass: merge singletons and small clusters by domain suffix
    # e.g., phx01.dns1.tucows.net and sea01.dns1.tucows.net share dns1.tucows.net
    final = []
    suffix_groups = {}
    for c in merged:
        label = c["label"]
        parts = label.split(".")
        # Use last 3 segments (or all if fewer) as suffix key, normalized
        suffix_parts = parts[-3:] if len(parts) >= 3 else parts
        suffix = ".".join(re.sub(r'\d+$', '', p) for p in suffix_parts)
        suffix_groups.setdefault(suffix, []).append(c)

    for suffix, group in suffix_groups.items():
        if len(group) == 1:
            final.append(group[0])
            continue
        # Only merge if total alert count > 1 (don't merge two unrelated singletons)
        total = sum(c["count"] for c in group)
        if total < 2:
            final.extend(group)
            continue
        all_fps = []
        all_names = []
        all_hosts = []
        top_sev = "info"
        sev_order = {"critical": 0, "high": 1, "warning": 2, "low": 3, "info": 4}
        for c in group:
            all_fps.extend(c.get("fingerprints", []))
            all_names.extend(c.get("alert_names", []))
            all_hosts.extend(c.get("hosts", []))
            c_sev = c.get("top_severity", "info")
            if sev_order.get(c_sev, 5) < sev_order.get(top_sev, 5):
                top_sev = c_sev
        wild_label = "*." + suffix.replace(".", "*.") if not suffix.startswith("*") else suffix
        # Clean up label: *.dns*.tucows*.net -> *.dns*.tucows.net
        cid = "c_" + hashlib.sha256(",".join(sorted(all_fps)).encode()).hexdigest()[:12]
        final.append({
            "cluster_id": cid,
            "label": wild_label,
            "fingerprints": all_fps,
            "alert_names": all_names,
            "top_severity": top_sev,
            "count": len(all_fps),
            "hosts": sorted(set(all_hosts)),
        })

    return final


def generate_situation_summary(clusters, active_alerts, resolved_count):
    """Generate an AI situation summary from clustered alerts."""
    global _last_summary_hash, _last_summary_time

    fps = sorted(a.get("fingerprint", "") for a in active_alerts)
    alert_hash = hashlib.sha256(",".join(fps).encode()).hexdigest()[:16]

    now = time.time()
    if alert_hash == _last_summary_hash and (now - _last_summary_time) < _SUMMARY_COOLDOWN:
        return None

    noise_count = 0
    cluster_info = []
    for c in clusters:
        if c["count"] == 1:
            continue
        cluster_info.append(
            f"- Cluster '{c['label']}': {c['count']} alerts, "
            f"top severity={c['top_severity']}, "
            f"alerts: {', '.join(c['alert_names'][:5])}"
        )

    for a in active_alerts:
        note = a.get("note", "") or ""
        for line in note.split("\n"):
            if line.startswith("NOISE_SCORE:"):
                try:
                    score = int(line.split(":")[1].strip())
                    if score >= 8:
                        noise_count += 1
                except (ValueError, IndexError):
                    pass
                break

    singleton_count = sum(1 for c in clusters if c["count"] == 1)

    prompt = f"""You are an SRE situation analyst. Analyze the current alert state and produce a JSON situation summary.

CURRENT STATE:
- Active alerts: {len(active_alerts)}
- Resolved alerts (recent): {resolved_count}
- Noise alerts (score >= 8): {noise_count}
- Alert clusters: {len([c for c in clusters if c['count'] > 1])}
- Unclustered alerts: {singleton_count}

CLUSTERS:
{chr(10).join(cluster_info) if cluster_info else "No multi-alert clusters detected."}

INDIVIDUAL ACTIVE ALERTS:
"""
    for a in active_alerts[:30]:
        note = a.get("note", "") or ""
        summary_line = ""
        sev_line = ""
        for line in note.split("\n"):
            if line.startswith("SUMMARY:"):
                summary_line = line.split(":", 1)[1].strip()[:100]
            elif line.startswith("ASSESSED_SEVERITY:"):
                sev_line = line.split(":", 1)[1].strip()
        name = a.get("name", "")[:50]
        host = get_host(a)
        prompt += f"- [{sev_line}] {name} on {host}: {summary_line}\n"

    prompt += """
Respond with JSON only:
{
  "one_liner": "Brief 1-sentence situation overview with alert counts and top priority",
  "clusters": [
    {"cluster_id": "<id from input>", "assessment": "1-sentence assessment", "priority": 1}
  ],
  "shift_context": {
    "new_since_last": 0,
    "resolved_since_last": 0,
    "trend": "improving|stable|worsening",
    "recurring": ["patterns that keep firing"]
  },
  "recommended_actions": [
    "Numbered action items, most urgent first"
  ],
  "suggested_merges": [
    {"clusters": ["c_id1", "c_id2"], "reason": "Why these should be merged"}
  ]
}

Rules:
- one_liner: concise, lead with most critical issue
- clusters: ordered by priority (1 = most urgent), only clusters with count > 1
- recommended_actions: specific and actionable
- trend: "improving" if more resolving, "worsening" if more firing, "stable" otherwise
- suggested_merges: suggest if any remaining clusters appear related but weren't grouped
"""

    response = ollama_generate(prompt, timeout=15)
    if not response:
        log.warning("Situation summary LLM call failed")
        return None

    try:
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        if text.startswith("json"):
            text = text[4:].strip()
        summary = json.loads(text)
    except (json.JSONDecodeError, ValueError) as e:
        log.warning(f"Situation summary JSON parse failed: {e}")
        return None

    payload = {
        "one_liner": summary.get("one_liner", ""),
        "clusters": summary.get("clusters", []),
        "shift_context": summary.get("shift_context", {}),
        "recommended_actions": summary.get("recommended_actions", []),
        "suggested_merges": summary.get("suggested_merges", []),
        "alert_hash": alert_hash,
    }

    try:
        body = json.dumps(payload).encode()
        req = Request(
            f"{ALERT_STATE_API_URL}/api/alert-states/situation-summary",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        urlopen(req, timeout=5)
        _last_summary_hash = alert_hash
        _last_summary_time = now
        log.info(f"Situation summary updated: {summary.get('one_liner', '')[:80]}")
    except Exception as e:
        log.warning(f"Failed to store situation summary: {e}")

    return summary


# ── Zabbix verification for stale alert auto-resolve ──

import ssl as _ssl

_zabbix_ssl_ctx = _ssl.create_default_context()
_zabbix_ssl_ctx.check_hostname = False
_zabbix_ssl_ctx.verify_mode = _ssl.CERT_NONE

# Zabbix instances the enricher can verify against (URL + credentials).
# Only instances with credentials are checked; others are skipped.
ZABBIX_INSTANCES = {
    "domains-shared": {
        "url": "https://zabbix.prod-domains-shared.bra2.tucows.systems/api_jsonrpc.php",
        "user": os.environ.get("ZABBIX_DS_USER", "uip-poller"),
        "password": os.environ.get("ZABBIX_DS_PASS", "UipPoller2026!"),
    },
    "enom": {
        "url": "https://zabbix.enom.net/api_jsonrpc.php",
        "user": os.environ.get("ZABBIX_ENOM_USER", ""),
        "password": os.environ.get("ZABBIX_ENOM_PASS", ""),
    },
}

_zabbix_auth_cache = {}  # instance -> (auth_token, expiry_epoch)
_last_stale_check = 0
_STALE_CHECK_INTERVAL = 600  # Only run stale check every 10 minutes


def _zabbix_api(instance_url, method, params, auth=None):
    """Call Zabbix JSON-RPC API."""
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1, "auth": auth}).encode()
    req = Request(instance_url, data=body, headers={"Content-Type": "application/json"})
    resp = urlopen(req, timeout=10, context=_zabbix_ssl_ctx)
    data = json.loads(resp.read())
    if "error" in data:
        raise Exception(data["error"].get("data", data["error"].get("message", str(data["error"]))))
    return data["result"]


def _zabbix_login(instance_key):
    """Login to Zabbix and cache the auth token (reused for 30 min)."""
    now = time.time()
    cached = _zabbix_auth_cache.get(instance_key)
    if cached and cached[1] > now:
        return cached[0]
    cfg = ZABBIX_INSTANCES.get(instance_key)
    if not cfg or not cfg["user"] or not cfg["password"]:
        return None
    try:
        auth = _zabbix_api(cfg["url"], "user.login", {"user": cfg["user"], "password": cfg["password"]})
        _zabbix_auth_cache[instance_key] = (auth, now + 1800)
        return auth
    except Exception as e:
        log.warning(f"Zabbix login failed for {instance_key}: {e}")
        return None


def _check_triggers_in_zabbix(instance_key, trigger_ids):
    """Query Zabbix for trigger status. Returns set of trigger IDs that are still in PROBLEM state."""
    cfg = ZABBIX_INSTANCES.get(instance_key)
    if not cfg:
        return None  # Unknown instance — can't verify
    auth = _zabbix_login(instance_key)
    if not auth:
        return None  # Can't login — skip verification
    try:
        triggers = _zabbix_api(cfg["url"], "trigger.get", {
            "triggerids": list(trigger_ids),
            "output": ["triggerid", "value"],
        }, auth)
        # value "1" = PROBLEM, "0" = OK
        return {t["triggerid"] for t in triggers if t["value"] == "1"}
    except Exception as e:
        log.warning(f"Zabbix trigger check failed for {instance_key}: {e}")
        return None


def auto_resolve_stale_alerts(active_alerts):
    """Auto-resolve firing alerts whose triggers no longer exist or have resolved in Zabbix.

    When Zabbix triggers are deleted (not resolved), no recovery webhook is sent,
    leaving alerts stuck in 'firing' forever. This verifies against the Zabbix API
    before resolving — only alerts whose triggers are deleted or in OK state get resolved.
    """
    global _last_stale_check
    from datetime import datetime as _dt, timezone as _tz

    now = time.time()
    # Only run this check every _STALE_CHECK_INTERVAL seconds
    if now - _last_stale_check < _STALE_CHECK_INTERVAL:
        return
    _last_stale_check = now

    # Collect candidate alerts: must have a triggerId and zabbixInstance,
    # and not have received an update recently (pre-filter to avoid unnecessary API calls)
    candidates = []
    for alert in active_alerts:
        trigger_id = alert.get("triggerId")
        instance = alert.get("zabbixInstance")
        if not trigger_id or not instance:
            continue
        if instance not in ZABBIX_INSTANCES:
            continue
        # Pre-filter: only check alerts that haven't been updated in STALE_RESOLVE_SECONDS
        last_received = alert.get("lastReceived") or alert.get("firingStartTime") or ""
        if last_received:
            try:
                lr = last_received.replace("Z", "+00:00")
                lr_epoch = _dt.fromisoformat(lr).timestamp()
                if now - lr_epoch < STALE_RESOLVE_SECONDS:
                    continue
            except (ValueError, TypeError):
                pass
        candidates.append(alert)

    if not candidates:
        return

    # Group candidates by Zabbix instance
    by_instance = {}
    for alert in candidates:
        inst = alert["zabbixInstance"]
        by_instance.setdefault(inst, []).append(alert)

    resolved_count = 0
    for instance_key, alerts in by_instance.items():
        trigger_ids = {a["triggerId"] for a in alerts}
        log.info(f"Checking {len(trigger_ids)} stale trigger(s) against Zabbix ({instance_key})")

        # Query Zabbix — returns set of trigger IDs still in PROBLEM state
        still_problem = _check_triggers_in_zabbix(instance_key, trigger_ids)
        if still_problem is None:
            log.info(f"  Skipping — could not verify against Zabbix ({instance_key})")
            continue

        for alert in alerts:
            tid = alert["triggerId"]
            if tid in still_problem:
                continue  # Trigger is still active in Zabbix — don't resolve

            fp = alert.get("fingerprint", "")
            name = alert.get("name", "unknown")
            host = get_host(alert)
            log.info(f"  Auto-resolving (trigger gone/OK in Zabbix): {name[:60]}")

            resolve_payload = {
                "id": f"auto-resolve-{fp[:16]}",
                "triggerId": tid,
                "name": name,
                "status": "ok",
                "severity": alert.get("severity", "warning"),
                "hostName": host,
                "lastReceived": _dt.now(_tz.utc).strftime("%Y.%m.%d %H:%M:%S"),
                "description": f"Auto-resolved: trigger no longer active in Zabbix",
                "tags": "[]",
                "zabbixInstance": alert.get("zabbixInstance", ""),
            }
            try:
                body = json.dumps(resolve_payload).encode()
                req = Request(
                    f"{KEEP_URL}/alerts/event/zabbix",
                    data=body,
                    method="POST",
                    headers={"X-API-KEY": KEEP_API_KEY, "Content-Type": "application/json"},
                )
                urlopen(req, timeout=10)
                enriched_cache[fp] = time.time()
                resolved_count += 1
            except Exception as e:
                log.warning(f"  Failed to auto-resolve {name[:40]}: {e}")

    if resolved_count:
        log.info(f"Auto-resolved {resolved_count} alert(s) confirmed gone in Zabbix")


def poll_and_enrich():
    # Prune expired cache entries (older than 10 minutes)
    now = time.time()
    expired = [fp for fp, ts in enriched_cache.items() if now - ts > 600]
    for fp in expired:
        del enriched_cache[fp]
    if expired:
        log.info(f"Pruned {len(expired)} expired entries from enrichment cache")

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
                enriched_cache[fp] = time.time()
                # Track resolve counts for flapping detection
                if fp in recent_enrichments:
                    recent_enrichments[fp]["resolve_count"] = recent_enrichments[fp].get("resolve_count", 0) + 1
                    recent_enrichments[fp]["last_resolved_at"] = time.time()
            continue
        active_alerts.append(alert)

    log.info(f"Found {len(active_alerts)} active alerts (skipped {len(items) - len(active_alerts)} resolved)")

    # Fetch force-enrich requests from SREs
    force_enrich_fps = fetch_force_enrich_fingerprints()
    # Fetch active silence rules — silenced alerts skip enrichment entirely
    silence_rules = fetch_silence_rules()
    suppressed_count = 0
    silenced_count = 0

    enriched_count = 0
    for alert in active_alerts:
        fingerprint = alert.get("fingerprint", "")
        if not fingerprint or fingerprint in enriched_cache:
            continue

        # Skip silenced alerts — no enrichment needed
        if silence_rules and fingerprint not in force_enrich_fps:
            matched_rule = is_alert_silenced(alert, silence_rules)
            if matched_rule:
                enriched_cache[fingerprint] = time.time()
                silenced_count += 1
                continue

        note = alert.get("note", "") or ""
        if "---AI-ENRICHMENT-V2---" in note or note.startswith("AI Summary:"):
            enriched_cache[fingerprint] = time.time()
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
                result = keep_request("/alerts/enrich", method="POST", data={
                    "fingerprint": fingerprint,
                    "enrichments": {"note": note_text},
                })
                if result is not None:
                    enriched_cache[fingerprint] = time.time()
                    suppressed_count += 1
                    log.info(f"  Suppressed: {name[:40]} — {reason[:60]}")
                else:
                    log.warning(f"  Suppression write failed for {name[:40]}, will retry")
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
                enriched_cache[fingerprint] = time.time()
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
    if silenced_count:
        log.info(f"Skipped {silenced_count} silenced alerts")

    # ── Auto-resolve stale firing alerts ──
    # Alerts that haven't received an update from Zabbix in STALE_RESOLVE_SECONDS
    # are likely from deleted triggers — resolve them automatically.
    if STALE_RESOLVE_SECONDS > 0:
        auto_resolve_stale_alerts(active_alerts)

    # ── Clustering & Situation Summary ──
    # Exclude silenced alerts from clustering and summary
    non_silenced_alerts = active_alerts
    if silence_rules:
        non_silenced_alerts = [a for a in active_alerts if not is_alert_silenced(a, silence_rules)]
    if non_silenced_alerts:
        clusters = cluster_alerts(non_silenced_alerts)
        clusters = merge_related_clusters(clusters)  # Merge clusters whose labels differ only by trailing digits
        multi_clusters = [c for c in clusters if c["count"] > 1]
        if multi_clusters:
            log.info(f"Clustered {sum(c['count'] for c in multi_clusters)} alerts into {len(multi_clusters)} groups")
        generate_situation_summary(clusters, non_silenced_alerts, len(items) - len(active_alerts))

    return enriched_count


def migrate_note_feedback_to_api():
    """One-time migration: move SRE feedback from alert note fields to alert-state-api."""
    flag_path = "/data/.feedback_migrated"
    if os.path.exists(flag_path):
        return

    log.info("Starting one-time SRE feedback migration from note fields...")
    try:
        alerts_data = keep_request("/alerts?limit=500")
        if not alerts_data:
            log.warning("Feedback migration: no alerts returned from Keep")
            return
        items = (
            alerts_data.get("items", alerts_data)
            if isinstance(alerts_data, dict)
            else alerts_data
        )
        if not isinstance(items, list):
            return

        migrated = 0
        for alert in items:
            note = alert.get("note", "") or ""
            if "---SRE-FEEDBACK---" not in note:
                continue
            feedback = parse_sre_feedback(note)
            if not feedback:
                continue
            fingerprint = alert.get("fingerprint", "")
            alert_name = alert.get("name", "")
            if not fingerprint or not alert_name:
                continue

            try:
                body = json.dumps({
                    "fingerprint": fingerprint,
                    "alert_name": alert_name,
                    "rating": feedback.get("rating"),
                    "corrected_severity": feedback.get("corrected_severity"),
                    "corrected_noise": feedback.get("corrected_noise"),
                    "comment": feedback.get("comment"),
                    "user": feedback.get("sre_user", "migration"),
                }).encode()
                req = Request(
                    f"{ALERT_STATE_API_URL}/api/alert-states/sre-feedback",
                    data=body,
                    headers={"Content-Type": "application/json"},
                )
                urlopen(req, timeout=5)
                migrated += 1
            except Exception as e:
                log.warning(f"Failed to migrate feedback for {fingerprint[:16]}: {e}")

        # Write flag file
        try:
            os.makedirs("/data", exist_ok=True)
            from datetime import datetime as _dt
            with open(flag_path, "w") as f:
                f.write(f"Migrated {migrated} feedback entries at {_dt.now().isoformat()}\n")
        except OSError:
            # /data may not be writable in all environments — log instead
            log.info("Could not write migration flag file; migration will re-run next restart")
        log.info(f"Feedback migration complete: {migrated} entries migrated")
    except Exception as e:
        log.error(f"Feedback migration failed: {e}")


def main():
    log.info("Starting Enhanced LLM Alert Enrichment Service v2")
    log.info(f"Ollama: {OLLAMA_URL} | Model: {OLLAMA_MODEL}")
    log.info(f"Keep: {KEEP_URL} | Poll interval: {POLL_INTERVAL}s")

    if not wait_for_ollama():
        log.error("Cannot start without Ollama. Exiting.")
        return

    # Run one-time migration of note-field feedback to alert-state-api
    migrate_note_feedback_to_api()

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
