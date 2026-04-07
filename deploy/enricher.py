#!/usr/bin/env python3
"""Enhanced LLM-powered alert enrichment service.
Polls Keep for new alerts, performs deduplication assessment,
sends to Ollama for deep analysis with service dependency context,
and writes structured enrichment back to Keep."""

import json
import re
import time
import os
import logging
import base64
import hashlib
import hmac as hmac_mod
from urllib.request import Request, urlopen
from urllib.error import HTTPError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("alert-enricher")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://aicompute01.cnco1.tucows.cloud:31434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen-tooling")
ACTIVE_OLLAMA_MODEL = OLLAMA_MODEL
KEEP_URL = os.environ.get("KEEP_URL", "http://keep-api:8080")
KEEP_API_KEY = os.environ.get("KEEP_API_KEY", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))
FLAP_WINDOW = int(os.environ.get("FLAP_WINDOW_SECONDS", "600"))
DEDUP_WINDOW = int(os.environ.get("DEDUP_WINDOW_SECONDS", "1800"))
NOISE_THRESHOLD = int(os.environ.get("NOISE_THRESHOLD", "8"))
ALERT_STATE_API_URL = os.environ.get("ALERT_STATE_API_URL", "http://alert-state-api:8092")
MAINT_API_URL = os.environ.get("MAINT_API_URL", "http://10.177.154.174/api/active-now")
STALE_RESOLVE_SECONDS = int(os.environ.get("STALE_RESOLVE_SECONDS", "7200"))  # Auto-resolve after 2h with no update
STALE_RECONCILE_INTERVAL_SECONDS = int(os.environ.get("STALE_RECONCILE_INTERVAL_SECONDS", "60"))
STALE_RECONCILE_GRACE_SECONDS = int(os.environ.get("STALE_RECONCILE_GRACE_SECONDS", "300"))
STALE_RECONCILE_MAX_PER_INSTANCE = int(os.environ.get("STALE_RECONCILE_MAX_PER_INSTANCE", "25"))
STALE_RECONCILE_MISSES_REQUIRED = int(os.environ.get("STALE_RECONCILE_MISSES_REQUIRED", "2"))
GRAFANA_IRM_URL = os.environ.get("GRAFANA_IRM_URL", "").strip().rstrip("/")
GRAFANA_IRM_API_TOKEN = os.environ.get("GRAFANA_IRM_API_TOKEN", "").strip()
GRAFANA_IRM_POLL_INTERVAL_SECONDS = int(os.environ.get("GRAFANA_IRM_POLL_INTERVAL_SECONDS", "300"))
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")

enriched_cache = {}  # {fingerprint: timestamp} — entries expire after 600s
stale_reconcile_tracker = {}
_last_stale_reconcile_run = 0
_last_grafana_irm_poll_run = 0

# ── Routing Rules Engine ──────────────────────────────
# Re-evaluation guard: set of (rule_id, fingerprint) tuples already acted on.
# Cleared when alert resolves or rule is modified.
_routing_acted_on = set()

SEVERITY_ORDINAL = {"critical": 5, "high": 4, "warning": 3, "low": 2, "info": 1, "unknown": 0}


def _alert_payload_text(alert):
    """Concatenate all alert fields into one searchable string."""
    parts = []
    for key in ("name", "description", "hostName", "hostname", "severity", "status", "note", "zabbixInstance"):
        val = alert.get(key)
        if val:
            parts.append(str(val))
    sources = alert.get("source") or []
    if isinstance(sources, list):
        for src in sources:
            parts.append(str(src))
    elif sources:
        parts.append(str(sources))
    tags = alert.get("tags") or []
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, dict):
                parts.append(str(tag.get("value", "")))
                parts.append(str(tag.get("name", "")))
            else:
                parts.append(str(tag))
    elif tags:
        parts.append(str(tags))
    return " ".join(parts)


def _create_internal_auth_cookie(username, ttl_hours=24):
    """Create a signed internal auth cookie compatible with auth/alert-state services."""
    if not AUTH_SECRET:
        return None
    payload = {
        "u": username,
        "e": int(time.time()) + ttl_hours * 3600,
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac_mod.new(AUTH_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"uip_auth={payload_b64}.{sig}"


def evaluate_condition(alert, condition):
    """Recursively evaluate a condition tree against an alert.
    Returns True if the alert matches the condition."""
    if not isinstance(condition, dict):
        return False
    # Logical operators
    if "AND" in condition:
        return all(evaluate_condition(alert, c) for c in condition["AND"])
    if "OR" in condition:
        return any(evaluate_condition(alert, c) for c in condition["OR"])
    # Leaf condition: {"field": ..., "op": ..., "value": ...}
    field = condition.get("field", "")
    op = condition.get("op", "")
    value = condition.get("value", "")
    # Extract field value from alert
    if field == "payload":
        actual = _alert_payload_text(alert)
    elif field == "hostname":
        actual = alert.get("hostName") or alert.get("hostname") or ""
    elif field == "source":
        sources = alert.get("source") or []
        actual = ",".join(str(s) for s in sources) if isinstance(sources, list) else str(sources)
    else:
        actual = alert.get(field, "") or ""
    actual_str = str(actual).lower()
    value_str = str(value).lower()
    # Severity comparison
    if field == "severity" and op in (">=", "<=", ">", "<"):
        actual_ord = SEVERITY_ORDINAL.get(actual_str, 0)
        value_ord = SEVERITY_ORDINAL.get(value_str, 0)
        if op == ">=": return actual_ord >= value_ord
        if op == "<=": return actual_ord <= value_ord
        if op == ">": return actual_ord > value_ord
        if op == "<": return actual_ord < value_ord
    # String operators (case-insensitive)
    if op == "equals": return actual_str == value_str
    if op == "not_equals": return actual_str != value_str
    if op == "contains": return value_str in actual_str
    if op == "not_contains": return value_str not in actual_str
    if op == "starts_with": return actual_str.startswith(value_str)
    if op == "ends_with": return actual_str.endswith(value_str)
    if op == "regex":
        try:
            return bool(re.search(value, str(actual), re.IGNORECASE))
        except re.error:
            return False
    return False


def fetch_routing_rules():
    """Fetch active routing rules from alert-state-api."""
    try:
        req = Request(f"{ALERT_STATE_API_URL}/api/alert-states/rules?type=routing")
        resp = urlopen(req, timeout=5)
        rules = json.loads(resp.read())
        return [r for r in rules if r.get("enabled")]
    except Exception as e:
        log.warning(f"Failed to fetch routing rules: {e}")
        return []


def execute_routing_action(alert, rule):
    """Execute the action specified by a routing rule."""
    action = rule.get("action", "")
    fingerprint = alert.get("fingerprint", "")
    alert_name = alert.get("name", "")
    params = rule.get("action_params") or {}

    try:
        if action == "auto_ack":
            body = json.dumps({
                "fingerprints": [fingerprint],
                "alert_names": {fingerprint: alert_name},
                "firing_starts": {fingerprint: alert.get("firingStartTime") or alert.get("startedAt") or ""},
                "username": "routing-engine",
            }).encode()
            headers = {"Content-Type": "application/json"}
            auth_cookie = _create_internal_auth_cookie("routing-engine")
            if auth_cookie:
                headers["Cookie"] = auth_cookie
            req = Request(f"{ALERT_STATE_API_URL}/api/alert-states/acknowledge",
                          data=body, headers=headers, method="POST")
            urlopen(req, timeout=5)
            log.info(f"Auto-acknowledged {alert_name} (fp={fingerprint[:16]}) by rule '{rule['name']}'")

        elif action == "auto_resolve":
            body = json.dumps({"fingerprint": fingerprint, "enrichments": {"status": "resolved"}}).encode()
            req = Request(f"{KEEP_URL}/alerts/enrich", data=body,
                          headers={"Content-Type": "application/json", "x-api-key": KEEP_API_KEY}, method="POST")
            urlopen(req, timeout=5)
            log.info(f"Auto-resolved {alert_name} (fp={fingerprint[:16]}) by rule '{rule['name']}'")

        elif action == "auto_silence":
            duration = params.get("duration", "2h")
            # Parse duration string to hours
            hours = 2
            if duration.endswith("h"):
                hours = int(duration[:-1])
            elif duration.endswith("m"):
                hours = int(duration[:-1]) / 60
            from datetime import datetime, timezone, timedelta
            now = datetime.now(timezone.utc)
            expires = (now + timedelta(hours=hours)).isoformat()
            body = json.dumps({
                "alert_name_pattern": alert_name,
                "hostname_pattern": alert.get("hostName") or alert.get("hostname") or "",
                "reason": f"Auto-silenced by rule: {rule['name']}",
                "duration_hours": hours,
                "username": "routing-engine",
            }).encode()
            req = Request(f"{ALERT_STATE_API_URL}/api/alert-states/silence-rules",
                          data=body, headers={"Content-Type": "application/json"}, method="POST")
            urlopen(req, timeout=5)
            log.info(f"Auto-silenced {alert_name} by rule '{rule['name']}'")

        elif action == "auto_escalate":
            team = params.get("team", "")
            if team:
                log.info(f"Auto-escalate {alert_name} to team '{team}' by rule '{rule['name']}' (escalation API call skipped — requires team resolution)")

    except Exception as e:
        log.error(f"Failed to execute routing action '{action}' for {alert_name}: {e}")


def apply_routing_rules(alerts):
    """Evaluate routing rules against all firing alerts and execute actions."""
    global _routing_acted_on
    rules = fetch_routing_rules()
    if not rules:
        return

    # Clean up acted_on entries for alerts that have resolved
    active_fps = {a.get("fingerprint") for a in alerts if a.get("status") == "firing"}
    _routing_acted_on = {(rid, fp) for rid, fp in _routing_acted_on if fp in active_fps}

    firing = [a for a in alerts if a.get("status") == "firing"]
    acted = 0
    for alert in firing:
        fp = alert.get("fingerprint", "")
        for rule in rules:
            rid = rule.get("id")
            if (rid, fp) in _routing_acted_on:
                continue
            conditions = rule.get("conditions_json", {})
            if evaluate_condition(alert, conditions):
                execute_routing_action(alert, rule)
                _routing_acted_on.add((rid, fp))
                acted += 1
                break  # First match wins
    if acted:
        log.info(f"Routing engine: acted on {acted} alerts")

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
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {"raw": raw.decode("utf-8", errors="replace")}
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


def _grafana_irm_keep_timestamp(value):
    raw = str(value or "").strip()
    if raw:
        try:
            parsed = time.strptime(raw.replace("T", " ").replace("Z", "")[:19], "%Y-%m-%d %H:%M:%S")
            return time.strftime("%Y.%m.%d %H:%M:%S", parsed)
        except ValueError:
            pass
    return time.strftime("%Y.%m.%d %H:%M:%S", time.gmtime())


def _grafana_irm_collect_labels(group):
    labels = group.get("labels") or {}
    if isinstance(labels, dict):
        return {str(key): str(value) for key, value in labels.items() if value not in (None, "")}
    return {}


def _grafana_irm_extract_host(labels):
    for key in ("host", "hostname", "instance", "node", "pod", "resource"):
        value = str(labels.get(key) or "").strip()
        if value:
            return value
    return ""


def _grafana_irm_normalize_severity(value):
    raw = str(value or "").strip().lower()
    if raw in {"critical", "high", "warning", "low", "info"}:
        return raw
    if raw in {"major", "urgent", "disaster"}:
        return "critical"
    if raw in {"minor", "medium"}:
        return "warning"
    if raw in {"ok", "resolved", "normal"}:
        return "info"
    return "warning"


def _grafana_irm_status_for_group(group, status_override=None):
    if status_override:
        return status_override
    if str(group.get("state") or "").strip().lower() == "resolved":
        return "ok"
    return "firing"


def _grafana_irm_tags_json(labels, integration_name):
    tags = [{"tag": "uip_source", "value": "grafana-irm"}]
    if integration_name:
        tags.append({"tag": "grafana_irm_integration", "value": integration_name})
    for key in sorted(labels.keys()):
        tags.append({"tag": key, "value": labels[key]})
    return json.dumps(tags)


def _grafana_irm_group_keep_event(group, status_override=None):
    labels = _grafana_irm_collect_labels(group)
    integration = group.get("integration") or {}
    integration_name = str(integration.get("name") or integration.get("id") or group.get("service") or "").strip()
    name = str(group.get("title") or group.get("name") or "Grafana IRM alert group")
    description = str(group.get("summary") or group.get("description") or name)
    return {
        "id": str(group["id"]),
        "name": name,
        "status": _grafana_irm_status_for_group(group, status_override=status_override),
        "severity": _grafana_irm_normalize_severity(labels.get("severity") or group.get("severity")),
        "service": integration_name or "Grafana IRM",
        "hostName": _grafana_irm_extract_host(labels),
        "hostIp": "",
        "lastReceived": _grafana_irm_keep_timestamp(
            group.get("resolved_at") or group.get("updated_at") or group.get("created_at") or ""
        ),
        "description": f"{description}\nuip_source: grafana-irm",
        "tags": _grafana_irm_tags_json(labels, integration_name),
    }


def _send_grafana_irm_group_to_keep(group, status_override=None):
    return keep_request(
        "/alerts/event/grafana-irm",
        method="POST",
        data=_grafana_irm_group_keep_event(group, status_override=status_override),
    )


def _fetch_grafana_irm_active_alert_groups():
    if not GRAFANA_IRM_URL or not GRAFANA_IRM_API_TOKEN:
        return None
    req = Request(
        f"{GRAFANA_IRM_URL}/api/v1/alert_groups/?state=alerting",
        headers={
            "Authorization": f"Bearer {GRAFANA_IRM_API_TOKEN}",
            "Accept": "application/json",
        },
    )
    try:
        resp = urlopen(req, timeout=10)
        payload = json.loads(resp.read())
        if isinstance(payload, dict):
            return payload.get("results") or payload.get("alert_groups") or []
        if isinstance(payload, list):
            return payload
    except Exception as e:
        log.warning(f"Grafana IRM fetch failed: {e}")
    return None


def _fetch_existing_grafana_irm_open_alerts():
    alerts = keep_request("/alerts?limit=500") or []
    items = alerts.get("items", alerts) if isinstance(alerts, dict) else alerts
    if not isinstance(items, list):
        return {}
    existing = {}
    for alert in items:
        status = (alert.get("status") or "").lower()
        if status in ("resolved", "ok"):
            continue
        provider = (alert.get("providerType") or "").lower()
        sources = _alert_source_values(alert)
        if provider != "grafana-irm" and "grafana-irm" not in sources:
            continue
        alert_id = str(alert.get("id") or "").strip()
        if alert_id:
            existing[alert_id] = alert
    return existing


def reconcile_grafana_irm_alert_groups():
    global _last_grafana_irm_poll_run
    if not GRAFANA_IRM_URL or not GRAFANA_IRM_API_TOKEN:
        return
    now_epoch = time.time()
    if (
        GRAFANA_IRM_POLL_INTERVAL_SECONDS > 0
        and now_epoch - _last_grafana_irm_poll_run < GRAFANA_IRM_POLL_INTERVAL_SECONDS
    ):
        return
    groups = _fetch_grafana_irm_active_alert_groups()
    _last_grafana_irm_poll_run = now_epoch
    if groups is None:
        return

    active_ids = set()
    for group in groups:
        group_id = str(group.get("id") or "").strip()
        if not group_id:
            continue
        active_ids.add(group_id)
        _send_grafana_irm_group_to_keep(group)

    existing_open = _fetch_existing_grafana_irm_open_alerts()
    for alert_id in sorted(set(existing_open.keys()) - active_ids):
        _send_grafana_irm_group_to_keep(existing_open[alert_id], status_override="ok")


def ollama_generate(prompt, timeout=45):
    global ACTIVE_OLLAMA_MODEL

    def _build_chat_request(model_name):
        body = json.dumps({
            "model": model_name,
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "think": False,
            "options": {
                "num_predict": 1024,
            },
        }).encode()
        return Request(
            f"{OLLAMA_URL}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
        )

    def _build_generate_request(model_name):
        body = json.dumps({
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 1024,
            },
        }).encode()
        return Request(
            f"{OLLAMA_URL}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
        )

    model_name = ACTIVE_OLLAMA_MODEL or OLLAMA_MODEL
    for attempt in range(2):
        try:
            resp = urlopen(_build_chat_request(model_name), timeout=timeout)
            data = json.loads(resp.read())
            msg = data.get("message", {})
            return msg.get("content", "").strip()
        except HTTPError as e:
            if e.code == 404:
                try:
                    resp = urlopen(_build_generate_request(model_name), timeout=timeout)
                    data = json.loads(resp.read())
                    return (data.get("response") or "").strip()
                except Exception as fallback_error:
                    e = fallback_error
            if attempt == 0:
                log.warning(f"Ollama timeout/error (attempt 1), retrying: {e}")
                time.sleep(2)
            else:
                log.error(f"Ollama failed after 2 attempts: {e}")
        except Exception as e:
            if attempt == 0:
                log.warning(f"Ollama timeout/error (attempt 1), retrying: {e}")
                time.sleep(2)
            else:
                log.error(f"Ollama failed after 2 attempts: {e}")
    return None


def wait_for_ollama():
    global ACTIVE_OLLAMA_MODEL
    log.info(f"Waiting for Ollama at {OLLAMA_URL}...")
    for attempt in range(60):
        try:
            resp = urlopen(f"{OLLAMA_URL}/api/tags", timeout=5)
            data = json.loads(resp.read())
            models = [m["name"] for m in data.get("models", [])]
            if any(OLLAMA_MODEL in m for m in models):
                ACTIVE_OLLAMA_MODEL = OLLAMA_MODEL
                log.info(f"Model {ACTIVE_OLLAMA_MODEL} is ready")
                return True
            if models and attempt == 0:
                log.error(
                    f"Configured Ollama model '{OLLAMA_MODEL}' not available at {OLLAMA_URL}; "
                    f"available models: {models}"
                )
        except Exception:
            pass
        time.sleep(10)
    log.error("Ollama not available after 10 minutes")
    return False


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

    response = ollama_generate(prompt, timeout=45)
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


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "_", (text or "").strip().lower()).strip("_")


def _trim_k8s_suffix(name):
    value = (name or "").strip().lower()
    if re.search(r"-[0-9a-f]{9,10}-[a-z0-9]{5}$", value):
        return re.sub(r"-[0-9a-f]{9,10}-[a-z0-9]{5}$", "", value)
    if re.search(r"-[0-9a-f]{9,10}$", value):
        return re.sub(r"-[0-9a-f]{9,10}$", "", value)
    return value


def _alert_tags_dict(alert):
    raw_tags = alert.get("tags") or {}
    if isinstance(raw_tags, dict):
        return raw_tags
    if isinstance(raw_tags, list):
        tags = {}
        for item in raw_tags:
            if not isinstance(item, dict):
                continue
            key = item.get("tag") or item.get("name")
            value = item.get("value")
            if key:
                tags[str(key)] = value
        return tags
    if isinstance(raw_tags, str):
        try:
            parsed = json.loads(raw_tags)
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, list):
                tags = {}
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    key = item.get("tag") or item.get("name")
                    value = item.get("value")
                    if key:
                        tags[str(key)] = value
                return tags
            return {}
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
    return {}


def _parse_runtime_timestamp(value):
    from datetime import datetime as _dt, timezone as _tz

    if not value:
        return 0.0

    text = str(value).strip()
    parsed = None
    try:
        parsed = _dt.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        try:
            parsed = _dt.strptime(text, "%Y.%m.%d %H:%M:%S")
        except (TypeError, ValueError):
            return 0.0

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_tz.utc)
    return parsed.timestamp()


def build_stable_zabbix_signature(alert):
    instance = (alert.get("zabbixInstance") or "").strip()
    if not instance:
        return None

    tags = _alert_tags_dict(alert)
    namespace = (tags.get("namespace") or "").strip().lower()
    target = (tags.get("target") or "").strip().lower()
    name = alert.get("name") or ""
    name_lc = name.lower()

    if "replicaset mismatch" in name_lc:
        alert_family = "replicaset_mismatch"
    elif "pod is crash looping" in name_lc:
        alert_family = "pod_crash_looping"
    else:
        return None

    target_family = "kubernetes" if target == "kubernetes" else "nodes" if target == "nodes" else "generic"

    if tags.get("pod"):
        scope = _trim_k8s_suffix(tags["pod"])
    elif tags.get("replicaset"):
        scope = _trim_k8s_suffix(tags["replicaset"])
    elif tags.get("node"):
        scope = (tags["node"] or "").strip().lower()
    else:
        scope = (alert.get("hostName") or alert.get("hostname") or "").strip().lower()

    if not scope:
        return None
    return f"{instance}|{target_family}|{alert_family}|{namespace}|{scope}"


def find_superseded_alerts(active_alerts):
    def _ts(value):
        return _parse_runtime_timestamp(value)

    def _sort_key(alert):
        last_received = _ts(alert.get("lastReceived"))
        started_at = _ts(alert.get("startedAt"))
        firing_start = _ts(alert.get("firingStartTime"))
        return (
            last_received,
            max(started_at, firing_start),
            started_at,
            firing_start,
            str(alert.get("fingerprint") or ""),
        )

    newest_by_signature = {}
    superseded = []
    for alert in sorted(active_alerts, key=_sort_key):
        signature = build_stable_zabbix_signature(alert)
        if not signature:
            continue
        previous = newest_by_signature.get(signature)
        if previous is not None:
            superseded.append(previous)
        newest_by_signature[signature] = alert
    return superseded


def _parse_alert_time_epoch(value):
    return _parse_runtime_timestamp(value)


def _missing_from_zabbix_reason(misses_required):
    if misses_required == 2:
        return "missing from Zabbix for 2 consecutive reconciliation checks"
    return f"missing from Zabbix for {misses_required} consecutive reconciliation checks"


def _alert_source_values(alert):
    source = alert.get("source") or []
    if isinstance(source, list):
        return [str(item).lower() for item in source]
    return [str(source).lower()]


def _domains_shared_overlap_key(alert):
    return (
        (alert.get("name") or "").strip().lower(),
        (alert.get("hostName") or alert.get("hostname") or "").strip().lower(),
    )


def prefer_grafana_irm_over_domains_shared(alerts):
    preferred = {}
    for alert in alerts:
        key = _domains_shared_overlap_key(alert)
        if not key[0]:
            continue
        current = preferred.get(key)
        if current is None:
            preferred[key] = alert
            continue
        current_is_irm = (
            (current.get("providerType") or "").lower() == "grafana-irm"
            or "grafana-irm" in _alert_source_values(current)
        )
        candidate_is_irm = (
            (alert.get("providerType") or "").lower() == "grafana-irm"
            or "grafana-irm" in _alert_source_values(alert)
        )
        current_is_domains_shared = (
            (current.get("providerType") or "").lower() == "zabbix"
            and (current.get("zabbixInstance") or "").strip().lower() == "domains-shared"
        )
        candidate_is_domains_shared = (
            (alert.get("providerType") or "").lower() == "zabbix"
            and (alert.get("zabbixInstance") or "").strip().lower() == "domains-shared"
        )
        if candidate_is_irm and current_is_domains_shared:
            preferred[key] = alert
        elif current_is_irm and candidate_is_domains_shared:
            continue

    seen = set()
    result = []
    for alert in alerts:
        key = _domains_shared_overlap_key(alert)
        if key[0]:
            if key in seen:
                continue
            chosen = preferred.get(key)
            if chosen is not None:
                result.append(chosen)
                seen.add(key)
                continue
        result.append(alert)
    return result


def collect_reconcile_candidates(active_alerts, now_epoch, tracker, grace_seconds, max_per_instance):
    batches = {}
    signed_prioritized = []

    for alert in active_alerts:
        instance = alert.get("zabbixInstance")
        trigger_id = alert.get("triggerId")
        if not instance or not trigger_id:
            continue
        if instance not in ZABBIX_INSTANCES:
            continue
        if (alert.get("status") or "").lower() in ("resolved", "ok"):
            continue
        if (alert.get("providerType") or "").lower() != "zabbix" and "zabbix" not in _alert_source_values(alert):
            continue

        last_received = alert.get("lastReceived") or alert.get("firingStartTime") or alert.get("startedAt") or ""
        if _parse_alert_time_epoch(last_received) > now_epoch - grace_seconds:
            continue

        signature = build_stable_zabbix_signature(alert)
        if not signature:
            continue

        signed_prioritized.append({
            "instance": instance,
            "fingerprint": alert.get("fingerprint", ""),
            "trigger_id": str(trigger_id),
            "signature": signature,
            "tracker_key": signature,
        })

    for item in signed_prioritized:
        bucket = batches.setdefault(item["instance"], [])
        if len(bucket) < max_per_instance:
            bucket.append(item)

    return batches


def update_missing_counters(candidates, still_problem, tracker, misses_required, now_epoch):
    to_resolve = []
    grouped = {}
    order = []
    for candidate in candidates:
        key = candidate.get("tracker_key") or candidate.get("signature") or f"{candidate['instance']}|trigger|{candidate['trigger_id']}"
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(candidate)

    for key in order:
        group = grouped[key]
        candidate = group[0]
        state = tracker.setdefault(key, {
            "fingerprint": candidate["fingerprint"],
            "trigger_id": candidate["trigger_id"],
            "consecutive_missing_checks": 0,
            "last_checked_at": 0,
        })
        state["fingerprint"] = candidate["fingerprint"]
        state["trigger_id"] = candidate["trigger_id"]
        state["last_checked_at"] = now_epoch
        if any(item["trigger_id"] in still_problem for item in group):
            state["consecutive_missing_checks"] = 0
            continue
        state["consecutive_missing_checks"] += 1
        if state["consecutive_missing_checks"] >= misses_required:
            to_resolve.append(candidate)
    return to_resolve


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


def _resolve_synthetic_keep_ok(alert, reason):
    """Resolve a stale alert directly in Keep by fingerprint."""
    fp = alert.get("fingerprint", "")
    name = alert.get("name", "unknown")
    if not fp:
        log.warning(f"  Failed to auto-resolve {name[:40]}: missing fingerprint")
        return False
    try:
        result = keep_request(
            "/alerts/enrich",
            method="POST",
            data={
                "fingerprint": fp,
                "enrichments": {"status": "resolved"},
            },
        )
        if result is not None:
            enriched_cache[fp] = time.time()
            return True
        log.warning(f"  Failed to auto-resolve {name[:40]}: Keep enrichment returned no result")
        return False
    except Exception as e:
        log.warning(f"  Failed to auto-resolve {name[:40]}: {e}")
        return False


def reconcile_stale_zabbix_alerts(active_alerts):
    """Bounded stale reconciliation for Zabbix alerts inside the runtime poll loop."""
    global _last_stale_reconcile_run

    now_epoch = time.time()
    if STALE_RECONCILE_INTERVAL_SECONDS > 0 and (
        now_epoch - _last_stale_reconcile_run < STALE_RECONCILE_INTERVAL_SECONDS
    ):
        remaining = STALE_RECONCILE_INTERVAL_SECONDS - (now_epoch - _last_stale_reconcile_run)
        log.info(f"Stale reconcile skipped due to rate limit; next run in {max(0, int(remaining))}s")
        return
    _last_stale_reconcile_run = now_epoch

    active_tracker_keys = set()
    for alert in active_alerts:
        instance = alert.get("zabbixInstance")
        trigger_id = alert.get("triggerId")
        if not instance or not trigger_id:
            continue
        signature = build_stable_zabbix_signature(alert)
        if signature:
            active_tracker_keys.add(signature)
    stale_keys = [key for key in stale_reconcile_tracker if key not in active_tracker_keys]
    for key in stale_keys:
        log.info("Stale reconcile pruning tracker entry for disappeared alert key=%s", key)
        stale_reconcile_tracker.pop(key, None)

    resolved_count = 0
    superseded_alerts = find_superseded_alerts(active_alerts)
    superseded_fingerprints = {alert.get("fingerprint", "") for alert in superseded_alerts}
    remaining_alerts = [
        alert for alert in active_alerts
        if alert.get("fingerprint", "") not in superseded_fingerprints
    ]
    remaining_signatures = {
        signature
        for alert in remaining_alerts
        for signature in [build_stable_zabbix_signature(alert)]
        if signature
    }
    for alert in superseded_alerts:
        signature = build_stable_zabbix_signature(alert)
        reason = "superseded by newer Zabbix alert with same stable signature"
        log.info(
            "Stale reconcile supersede decision: resolving fingerprint=%s trigger=%s signature=%s reason=%s",
            alert.get("fingerprint", ""),
            alert.get("triggerId", ""),
            signature or "n/a",
            reason,
        )
        if _resolve_synthetic_keep_ok(alert, reason):
            log.info("Stale reconcile resolved fingerprint=%s reason=%s", alert.get("fingerprint", ""), reason)
            resolved_count += 1
            if signature and signature not in remaining_signatures:
                stale_reconcile_tracker.pop(signature, None)
    batches = collect_reconcile_candidates(
        remaining_alerts,
        now_epoch=now_epoch,
        tracker=stale_reconcile_tracker,
        grace_seconds=STALE_RECONCILE_GRACE_SECONDS,
        max_per_instance=STALE_RECONCILE_MAX_PER_INSTANCE,
    )
    if not batches:
        if resolved_count:
            log.info(f"Stale reconcile auto-resolved {resolved_count} alert(s)")
        return

    for instance_key, candidates in batches.items():
        trigger_ids = {candidate["trigger_id"] for candidate in candidates}
        log.info(f"Checking {len(trigger_ids)} stale trigger(s) against Zabbix ({instance_key})")
        still_problem = _check_triggers_in_zabbix(instance_key, trigger_ids)
        if still_problem is None:
            log.info(f"  Skipping - could not verify against Zabbix ({instance_key})")
            continue

        for candidate in candidates:
            tracker_state = stale_reconcile_tracker.get(candidate["tracker_key"], {})
            if candidate["trigger_id"] in still_problem:
                log.info(
                    "Stale reconcile verification: fingerprint=%s trigger=%s still present in Zabbix; resetting misses",
                    candidate["fingerprint"],
                    candidate["trigger_id"],
                )
            else:
                next_miss_count = tracker_state.get("consecutive_missing_checks", 0) + 1
                log.info(
                    "Stale reconcile verification: fingerprint=%s trigger=%s missing from Zabbix; miss %s/%s",
                    candidate["fingerprint"],
                    candidate["trigger_id"],
                    next_miss_count,
                    STALE_RECONCILE_MISSES_REQUIRED,
                )

        for candidate in update_missing_counters(
            candidates,
            still_problem,
            stale_reconcile_tracker,
            STALE_RECONCILE_MISSES_REQUIRED,
            now_epoch,
        ):
            alert = next(
                (item for item in remaining_alerts if item.get("fingerprint", "") == candidate["fingerprint"]),
                None,
            )
            if alert is None:
                continue
            reason = _missing_from_zabbix_reason(STALE_RECONCILE_MISSES_REQUIRED)
            log.info(
                "Stale reconcile resolution decision: fingerprint=%s trigger=%s tracker_key=%s reason=%s",
                candidate["fingerprint"],
                candidate["trigger_id"],
                candidate["tracker_key"],
                reason,
            )
            if _resolve_synthetic_keep_ok(alert, reason):
                log.info("Stale reconcile resolved fingerprint=%s reason=%s", candidate["fingerprint"], reason)
                resolved_count += 1
                stale_reconcile_tracker.pop(candidate["tracker_key"], None)

    if resolved_count:
        log.info(f"Stale reconcile auto-resolved {resolved_count} alert(s)")


def poll_and_enrich():
    # Prune expired cache entries (older than 10 minutes)
    now = time.time()
    expired = [fp for fp, ts in enriched_cache.items() if now - ts > 600]
    for fp in expired:
        del enriched_cache[fp]
    if expired:
        log.info(f"Pruned {len(expired)} expired entries from enrichment cache")

    reconcile_grafana_irm_alert_groups()

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

    active_alerts = prefer_grafana_irm_over_domains_shared(active_alerts)

    log.info(f"Found {len(active_alerts)} active alerts (skipped {len(items) - len(active_alerts)} resolved)")

    # Apply routing rules before slower enrichment and summary work so actions engage quickly.
    try:
        apply_routing_rules(items)
    except Exception as e:
        log.error(f"Routing rules evaluation failed: {e}")

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

    # ── Bounded stale reconciliation for Zabbix alerts ──
    reconcile_stale_zabbix_alerts(active_alerts)

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
