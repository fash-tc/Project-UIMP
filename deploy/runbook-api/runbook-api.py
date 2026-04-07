"""
UIP Runbook API — Remediation knowledge base and Jira integration service.
Stores SRE remediation notes in SQLite, provides fuzzy matching for the
AI enricher, and proxies Jira incident creation with per-user credentials.
"""

import json
import os
import logging
import sqlite3
import re
import base64
import hashlib
import hmac as hmac_mod
import time
import threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("runbook-api")

API_PORT = int(os.environ.get("API_PORT", "8090"))
DB_PATH = os.environ.get("DB_PATH", "/data/runbook.db")
KEEP_URL = os.environ.get("KEEP_URL", "http://keep-api:8080").rstrip("/")
KEEP_API_KEY = os.environ.get("KEEP_API_KEY", "")
JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")
AUTH_API_URL = os.environ.get("AUTH_API_URL", "http://auth-api:8093")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://aicompute01.cnco1.tucows.cloud:31434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen-tooling")
MAINT_DASHBOARD_URL = os.environ.get("MAINT_DASHBOARD_URL", "http://10.177.154.174")
GRAFANA_WEBHOOK_SECRET = os.environ.get("GRAFANA_WEBHOOK_SECRET", "")
GRAFANA_IRM_WEBHOOK_SECRET = os.environ.get("GRAFANA_IRM_WEBHOOK_SECRET", "").strip()
STATUSPAGE_API_KEY = os.environ.get("STATUSPAGE_API_KEY", "")
STATUSPAGE_PAGE_ID = os.environ.get("STATUSPAGE_PAGE_ID", "l7mgndhgstnc")

STOP_WORDS = {
    "on", "the", "is", "for", "at", "in", "a", "an", "not", "to",
    "of", "has", "with", "from", "alert", "check", "problem", "trigger",
    "and", "or", "be", "was", "are", "been", "being", "have", "had",
    "do", "does", "did", "but", "if", "no", "than", "too", "very",
    "can", "will", "just", "-", "",
}

_db_lock = threading.Lock()

# ── Webhook Test Receiver — in-memory ring buffer ──
_webhook_test_buffer = []
_webhook_test_lock = threading.Lock()
_WEBHOOK_TEST_MAX = 50
_PLACEHOLDER_WEBHOOK_SECRETS = {"placeholder", "changeme", "example", "test"}


def keep_request(path, method="GET", data=None, headers=None):
    url = f"{KEEP_URL}{path}"
    body = json.dumps(data).encode() if data is not None else None
    request_headers = {"Content-Type": "application/json"}
    if KEEP_API_KEY:
        request_headers["X-API-KEY"] = KEEP_API_KEY
    if headers:
        request_headers.update(headers)
    req = Request(url, data=body, method=method, headers=request_headers)
    resp = urlopen(req, timeout=10)
    raw = resp.read()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw.decode("utf-8", errors="replace")}


def _grafana_irm_webhook_is_authorized(handler):
    expected = (GRAFANA_IRM_WEBHOOK_SECRET or "").strip()
    provided_source = (handler.headers.get("X-UIP-Webhook-Source", "") or "").strip().lower()
    provided_secret = (handler.headers.get("X-UIP-Webhook-Secret", "") or "").strip()
    return bool(expected) and provided_source == "grafana-irm" and hmac_mod.compare_digest(provided_secret, expected)


def _grafana_irm_keep_timestamp(value):
    raw = (value or "").strip()
    if raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y.%m.%d %H:%M:%S")
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime("%Y.%m.%d %H:%M:%S")


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


def _grafana_irm_collect_labels(payload):
    alert_group = payload.get("alert_group") or {}
    alert_payload = payload.get("alert_payload") or {}
    collected = {}
    for source in (alert_group.get("labels"), alert_payload.get("labels")):
        if isinstance(source, dict):
            for key, value in source.items():
                if value not in (None, "") and key not in collected:
                    collected[str(key)] = str(value)
    return collected


def _grafana_irm_extract_host(labels):
    for key in ("host", "hostname", "instance", "node", "pod", "resource"):
        value = (labels.get(key) or "").strip()
        if value:
            return value
    return ""


def _grafana_irm_tags_json(labels, integration_name):
    tags = [{"tag": "uip_source", "value": "grafana-irm"}]
    if integration_name:
        tags.append({"tag": "grafana_irm_integration", "value": integration_name})
    for key in sorted(labels.keys()):
        tags.append({"tag": key, "value": labels[key]})
    return json.dumps(tags)


def _normalize_grafana_irm_event(payload):
    alert_group = payload.get("alert_group") or {}
    alert_payload = payload.get("alert_payload") or {}
    integration = payload.get("integration") or {}
    event = payload.get("event") or {}
    upstream_id = str(alert_group.get("id") or "").strip()
    if not upstream_id:
        raise ValueError("Missing alert_group.id")
    labels = _grafana_irm_collect_labels(payload)
    annotations = alert_payload.get("annotations") if isinstance(alert_payload, dict) else {}
    annotations = annotations if isinstance(annotations, dict) else {}
    title = (
        alert_group.get("title")
        or alert_group.get("name")
        or labels.get("alertname")
        or "Grafana IRM alert group"
    )
    state = str(alert_group.get("state") or "").strip().lower()
    event_type = str(event.get("type") or "").strip()
    description = (
        annotations.get("description")
        or annotations.get("summary")
        or alert_group.get("summary")
        or title
    )
    integration_name = str(integration.get("name") or integration.get("id") or "").strip()
    permalink = ""
    permalinks = alert_group.get("permalinks") or {}
    if isinstance(permalinks, dict):
        permalink = str(permalinks.get("web") or permalinks.get("detail") or "").strip()
    timestamp = (
        alert_group.get("resolved_at")
        or alert_group.get("updated_at")
        or alert_group.get("created_at")
        or event.get("time")
        or ""
    )
    return {
        "event_type": event_type,
        "upstream_id": upstream_id,
        "title": str(title),
        "state": state,
        "severity": _grafana_irm_normalize_severity(labels.get("severity") or alert_group.get("severity")),
        "service": integration_name,
        "hostName": _grafana_irm_extract_host(labels),
        "description": str(description),
        "timestamp": _grafana_irm_keep_timestamp(timestamp),
        "permalink": permalink,
        "labels": labels,
    }


def _grafana_irm_status_for_keep(event):
    event_type = (event.get("event_type") or "").strip().lower()
    state = (event.get("state") or "").strip().lower()
    if event_type == "resolved" or state == "resolved":
        return "ok"
    return "firing"


def _build_grafana_irm_keep_event(event):
    description_parts = [event.get("description") or event.get("title") or "Grafana IRM alert group"]
    description_parts.append("uip_source: grafana-irm")
    if event.get("service"):
        description_parts.append(f"grafana_irm_integration: {event['service']}")
    if event.get("permalink"):
        description_parts.append(f"upstream_url: {event['permalink']}")
    return {
        "id": event["upstream_id"],
        "name": event["title"],
        "status": _grafana_irm_status_for_keep(event),
        "severity": event["severity"],
        "service": event.get("service") or "Grafana IRM",
        "hostName": event.get("hostName") or "",
        "hostIp": "",
        "lastReceived": event["timestamp"],
        "description": "\n".join(description_parts),
        "tags": _grafana_irm_tags_json(event.get("labels") or {}, event.get("service") or ""),
    }


def _handle_grafana_irm_alert_group_event(payload):
    normalized = _normalize_grafana_irm_event(payload)
    keep_event = _build_grafana_irm_keep_event(normalized)
    keep_request("/alerts/event/grafana-irm", method="POST", data=keep_event)
    return {
        "ok": True,
        "upstream_id": normalized["upstream_id"],
        "status": keep_event["status"],
    }


def normalize_alert_pattern(alert_name, hostname=""):
    """Normalize alert name for feedback matching: lowercase, strip hostname suffix."""
    pattern = (alert_name or "").lower().strip()
    if hostname:
        host_lower = hostname.lower()
        for sep in [" on ", " for ", " at ", " - ", ": "]:
            idx = pattern.find(sep + host_lower)
            if idx != -1:
                pattern = pattern[:idx].strip()
                break
        if pattern.endswith(host_lower):
            pattern = pattern[:len(pattern) - len(host_lower)].rstrip(" -:")
    # Strip timestamps
    pattern = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?', '', pattern).strip()
    return pattern


def _normalized_optional(value):
    return (value or "").strip().lower()


def _manual_link_score(link_row, hostname="", service=""):
    score = min(int(link_row["attach_count"] or 1), 5) * 6
    link_host = _normalized_optional(link_row["hostname"])
    link_service = _normalized_optional(link_row["service"])
    query_host = _normalized_optional(hostname)
    query_service = _normalized_optional(service)
    if link_host and link_host == query_host:
        score += 10
    elif link_host:
        score += 2
    if link_service and link_service == query_service:
        score += 8
    elif link_service:
        score += 2
    return score


def _fetch_manual_link_scores(db, alert_name, hostname="", service=""):
    pattern = normalize_alert_pattern(alert_name, hostname)
    cursor = db.execute(
        """
        SELECT runbook_entry_id, hostname, service, attach_count
        FROM runbook_manual_links
        WHERE alert_pattern = ?
        """,
        (pattern,),
    )
    scores = {}
    for row in cursor.fetchall():
        entry_id = int(row["runbook_entry_id"])
        scores[entry_id] = max(scores.get(entry_id, 0), _manual_link_score(row, hostname, service))
    return scores


def record_manual_runbook_link(db, entry_id, alert_name, hostname="", service="", username=""):
    pattern = normalize_alert_pattern(alert_name, hostname)
    host_norm = _normalized_optional(hostname)
    service_norm = _normalized_optional(service)
    existing = db.execute(
        """
        SELECT id, attach_count FROM runbook_manual_links
        WHERE alert_pattern = ? AND hostname = ? AND service = ? AND runbook_entry_id = ?
        """,
        (pattern, host_norm, service_norm, entry_id),
    ).fetchone()
    if existing:
        db.execute(
            """
            UPDATE runbook_manual_links
            SET attach_count = attach_count + 1,
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (existing["id"],),
        )
        return existing["id"], existing["attach_count"] + 1
    cursor = db.execute(
        """
        INSERT INTO runbook_manual_links
            (alert_pattern, hostname, service, runbook_entry_id, attached_by)
        VALUES (?, ?, ?, ?, ?)
        """,
        (pattern, host_norm, service_norm, entry_id, username or "unknown"),
    )
    return cursor.lastrowid, 1


# ── Database ──────────────────────────────────────────

def init_db():
    """Initialize the SQLite database and create tables if needed."""
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS runbook_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_name TEXT NOT NULL,
            alert_fingerprint TEXT,
            hostname TEXT,
            service TEXT,
            severity TEXT,
            remediation TEXT NOT NULL,
            sre_user TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_re_alert_name ON runbook_entries(alert_name)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_re_hostname ON runbook_entries(hostname)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_re_service ON runbook_entries(service)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS runbook_manual_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_pattern TEXT NOT NULL,
            hostname TEXT DEFAULT '',
            service TEXT DEFAULT '',
            runbook_entry_id INTEGER NOT NULL REFERENCES runbook_entries(id) ON DELETE CASCADE,
            attached_by TEXT NOT NULL,
            attach_count INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            UNIQUE(alert_pattern, hostname, service, runbook_entry_id)
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_runbook_manual_links_pattern ON runbook_manual_links(alert_pattern)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS ai_instructions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instruction TEXT NOT NULL,
            sre_user TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_pattern TEXT NOT NULL,
            service TEXT DEFAULT '',
            severity_correction TEXT DEFAULT '',
            cause_correction TEXT DEFAULT '',
            remediation_correction TEXT DEFAULT '',
            full_text TEXT DEFAULT '',
            sre_user TEXT NOT NULL,
            usefulness_score REAL DEFAULT 1.0,
            created_at TEXT DEFAULT (datetime('now')),
            reinforced_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_feedback_pattern ON feedback(alert_pattern)")
    db.commit()
    log.info(f"Database initialized at {DB_PATH}")
    return db


# ── Authentication ────────────────────────────────────

def _verify_auth_token(token):
    """Verify token and return full payload dict or None.
    Payload contains: u (username), e (expiry), p (permissions list), r (role_id)."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        expected = hmac_mod.new(AUTH_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
        if not hmac_mod.compare_digest(sig, expected):
            return None
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if payload.get("e", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def _get_token_from_request(handler):
    """Extract and verify auth token from cookies. Returns full payload dict or None."""
    cookie_header = handler.headers.get("Cookie", "")
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.strip() == "uip_auth":
                return _verify_auth_token(v.strip())
    return None


def _get_username_from_request(handler):
    """Extract username from auth token. Backward-compatible wrapper."""
    payload = _get_token_from_request(handler)
    if payload:
        return payload.get("u")
    return None


def _require_permission(handler, permission):
    """Check if the authenticated user has a specific permission.
    Returns username if authorized, None if not (and sends 401/403)."""
    payload = _get_token_from_request(handler)
    if not payload:
        handler._send_json(401, {"error": "Not authenticated"})
        return None
    perms = payload.get("p", [])
    if permission not in perms:
        handler._send_json(403, {"error": f"Permission denied: {permission} required"})
        return None
    return payload.get("u")


# ── Text Matching ────────────────────────────────────

def tokenize(text):
    """Split text into lowercase keyword tokens, removing stop words."""
    words = re.split(r'[\s/\-_:,.;()\[\]]+', text.lower())
    return {w for w in words if w and w not in STOP_WORDS}


# ── Ollama AI Assessment ──────────────────────────────

def ollama_generate(prompt, model=None, timeout=45, num_predict=512, temperature=0.3):
    """Call the configured LLM endpoint and return the response text."""
    model_name = model or OLLAMA_MODEL

    chat_payload = json.dumps({
        "model": model_name,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "think": False,
        "options": {"temperature": temperature, "num_predict": num_predict},
    }).encode()
    chat_req = Request(
        f"{OLLAMA_URL}/api/chat",
        data=chat_payload,
        headers={"Content-Type": "application/json"},
    )

    generate_payload = json.dumps({
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": num_predict},
    }).encode()
    generate_req = Request(
        f"{OLLAMA_URL}/api/generate",
        data=generate_payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urlopen(chat_req, timeout=timeout)
        data = json.loads(resp.read())
        message = data.get("message", {}) or {}
        return (message.get("content") or data.get("response") or "").strip()
    except HTTPError as e:
        if e.code != 404:
            log.error(f"Ollama call failed: {e}")
            return None
        try:
            resp = urlopen(generate_req, timeout=timeout)
            data = json.loads(resp.read())
            return (data.get("response") or "").strip()
        except Exception as fallback_error:
            log.error(f"Ollama fallback call failed: {fallback_error}")
            return None
    except Exception as e:
        log.error(f"Ollama call failed: {e}")
        return None


def assess_incident_description(title, description):
    """Use Ollama to grade an incident description for customer-appropriateness."""
    prompt = f"""Review this quick initial incident notice for customers.
This is an early heads-up, so vague language is acceptable if it is calm, truthful, and clearly says there is an issue under investigation.
Grade A-F based on whether it avoids internal hostnames, IPs, ticket numbers, and obviously internal tooling names.
Reply as JSON only: {{"grade":"X","feedback":"One short sentence."}}
Title: {title}
Description: {description}"""

    raw = ollama_generate(prompt, timeout=7, num_predict=96, temperature=0.1)
    if not raw:
        return _fallback_incident_assessment(title, description)
    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        # Fallback: extract grade letter from raw text
        grade_match = re.search(r'"grade"\s*:\s*"([A-F?])"', raw)
        grade = grade_match.group(1) if grade_match else "?"
        if grade == "?":
            return _fallback_incident_assessment(title, description)
        return {"grade": grade, "feedback": raw.strip()[:500]}


def _fallback_incident_assessment(title, description):
    """Fast local heuristic so incident reviews stay responsive during active incidents."""
    text = f"{title}\n{description}".strip()
    lowered = text.lower()
    issues = []
    grade = "A"

    if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        issues.append("Remove internal IP addresses from the customer notice.")
        grade = "F"

    if re.search(r"\b[a-z0-9][\w-]*\.(?:internal|local|corp|cnco1|tucows\.cloud|tucows\.systems)\b", lowered):
        issues.append("Remove internal hostnames or infrastructure identifiers.")
        grade = "F"

    if re.search(r"\b(?:occir|inc-\d+|jira|ticket|zabbix|grafana|ollama)\b", lowered):
        issues.append("Avoid internal tooling or platform jargon.")
        if grade not in {"F"}:
            grade = "C"

    if len(description.strip()) < 40:
        issues.append("Add a little more customer-facing context if you can.")
        if grade == "A":
            grade = "B"

    customer_terms = ("customer", "service", "dns", "email", "domain", "portal", "api", "registration", "update")
    if not any(term in lowered for term in customer_terms):
        issues.append("Naming the affected service would make the notice a bit stronger, but it is optional for an initial heads-up.")
        if grade == "A":
            grade = "B"

    if not issues:
        return {
            "grade": "A",
            "feedback": "Clear and customer-appropriate for an initial incident notice."
        }

    return {"grade": grade, "feedback": " ".join(issues[:2])}


def _webhook_secret_is_configured(secret):
    normalized = (secret or "").strip().lower()
    return bool(normalized) and normalized not in _PLACEHOLDER_WEBHOOK_SECRETS


def _is_builtin_local_test_subscriber(subscriber):
    name = (subscriber.get("name") or "").strip().lower()
    url = (subscriber.get("url") or "").strip().lower()
    return name == "local test" and (
        "localhost:8000/api/webhooks/receive-test" in url
        or "app:8000/api/webhooks/receive-test" in url
    )


def _fetch_active_webhook_subscribers():
    req = Request(
        f"{MAINT_DASHBOARD_URL}/api/webhooks/subscribers",
        headers={"Accept": "application/json"},
    )
    resp = urlopen(req, timeout=10)
    data = json.loads(resp.read())
    if not isinstance(data, list):
        raise ValueError("Webhook subscribers response was not a list")
    return [
        subscriber for subscriber in data
        if subscriber.get("is_active")
        and (subscriber.get("url") or "").strip()
        and not _is_builtin_local_test_subscriber(subscriber)
    ]


def _fetch_webhook_signing_secrets():
    req = Request(
        f"{AUTH_API_URL}/api/auth/internal/webhook-subscriber-secrets",
        headers={"Accept": "application/json", "X-UIP-Internal-Auth": AUTH_SECRET},
    )
    resp = urlopen(req, timeout=10)
    data = json.loads(resp.read())
    items = data.get("items", {})
    return items if isinstance(items, dict) else {}


def _fanout_incident_webhook_direct(payload_obj, payload):
    subscribers = _fetch_active_webhook_subscribers()
    if not subscribers:
        return False, "No active webhook subscribers are configured"

    try:
        secret_map = _fetch_webhook_signing_secrets()
    except Exception as e:
        log.warning(f"Failed to load mirrored webhook signing secrets: {e}")
        secret_map = {}
    failures = []
    timestamp = str(int(time.time()))
    for subscriber in subscribers:
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Timestamp": timestamp,
            "X-Webhook-Event": "incident",
            "X-UIP-Source": "runbook-api",
        }
        mirrored = secret_map.get(str(subscriber.get("id"))) or {}
        subscriber_secret = (mirrored.get("secret") or subscriber.get("secret") or "").strip()
        if subscriber_secret:
            headers["X-Webhook-Signature"] = hmac_mod.new(
                subscriber_secret.encode(),
                payload,
                hashlib.sha256,
            ).hexdigest()
        req = Request(subscriber["url"], data=payload, headers=headers)
        try:
            urlopen(req, timeout=10)
        except HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:200]
            failures.append(f'{subscriber.get("name") or subscriber["url"]}: HTTP {e.code}: {body}')
        except Exception as e:
            failures.append(f'{subscriber.get("name") or subscriber["url"]}: {e}')

    if failures:
        return False, "; ".join(failures)
    return True, None


# ── Webhook & Statuspage helpers ──────────────────────

def send_incident_webhook(title, description, started_at, preview_only=False):
    """Send incident notification to maintenance dashboard webhook system."""
    def _capture_preview():
        preview_sig = hashlib.sha256(payload).hexdigest()
        preview_ts = str(int(time.time()))
        delivery = {
            "id": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "headers": {
                "Content-Type": "application/json",
                "X-Webhook-Signature": preview_sig,
                "X-Webhook-Timestamp": preview_ts,
                "X-Preview-Mode": "incident-fallback",
            },
            "body": payload_obj,
            "signature_header": preview_sig,
            "signature_result": "captured",
            "content_length": len(payload),
        }
        with _webhook_test_lock:
            delivery["id"] = len(_webhook_test_buffer) + 1
            _webhook_test_buffer.append(delivery)
            if len(_webhook_test_buffer) > _WEBHOOK_TEST_MAX:
                _webhook_test_buffer.pop(0)
        return True, None

    payload_obj = {
        "event_type": "incident",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "title": title,
            "description": description,
            "source": "uip_sre",
            "started_at": started_at or datetime.now(timezone.utc).isoformat(),
            "raw_payload": {},
        },
    }
    payload = json.dumps(payload_obj).encode()
    secret = (GRAFANA_WEBHOOK_SECRET or "").strip()
    if preview_only and not _webhook_secret_is_configured(secret):
        return _capture_preview()
    if not _webhook_secret_is_configured(secret):
        try:
            return _fanout_incident_webhook_direct(payload_obj, payload)
        except Exception as e:
            return False, str(e)
    req = Request(f"{MAINT_DASHBOARD_URL}/api/webhooks/incidents",
                  data=payload,
                  headers={
                      "Content-Type": "application/json",
                      "X-Grafana-Secret": secret,
                  })
    try:
        resp = urlopen(req, timeout=10)
        return True, None
    except HTTPError as e:
        body = e.read().decode()[:200]
        if "GRAFANA_WEBHOOK_SECRET not configured" in body:
            if preview_only:
                return _capture_preview()
            return _fanout_incident_webhook_direct(payload_obj, payload)
        if e.code == 401 or "Invalid or missing X-Grafana-Secret" in body:
            if preview_only:
                return _capture_preview()
            return _fanout_incident_webhook_direct(payload_obj, payload)
        return False, f"Webhook API {e.code}: {body}"
    except Exception as e:
        return False, str(e)


def fetch_statuspage_components():
    """Fetch components from Statuspage.io."""
    if not STATUSPAGE_API_KEY:
        return None, "STATUSPAGE_API_KEY not configured"
    req = Request(
        f"https://api.statuspage.io/v1/pages/{STATUSPAGE_PAGE_ID}/components",
        headers={"Authorization": f"OAuth {STATUSPAGE_API_KEY}"},
    )
    try:
        resp = urlopen(req, timeout=10)
        data = json.loads(resp.read())
        return [{"id": c["id"], "name": c["name"], "status": c.get("status", "operational"),
                 "description": c.get("description", "")} for c in data], None
    except Exception as e:
        return None, str(e)


def _normalize_statuspage_component_updates(components):
    normalized = []
    for item in components or []:
        if not isinstance(item, dict):
            continue
        component_id = str(item.get("component_id") or item.get("id") or "").strip()
        if not component_id:
            continue
        status = str(item.get("status") or "operational").strip() or "operational"
        normalized.append({"component_id": component_id, "status": status})
    return normalized


def _build_statuspage_component_payload(components):
    normalized = _normalize_statuspage_component_updates(components)
    component_ids = [item["component_id"] for item in normalized]
    component_statuses = {item["component_id"]: item["status"] for item in normalized}
    return component_ids, component_statuses


def _normalize_statuspage_incident(incident):
    return {
        "id": incident.get("id"),
        "name": incident.get("name", ""),
        "status": incident.get("status", ""),
        "impact": incident.get("impact", incident.get("impact_override", "")),
        "shortlink": incident.get("shortlink", ""),
        "updated_at": incident.get("updated_at", ""),
        "components": [
            {
                "id": component.get("id"),
                "name": component.get("name", ""),
                "status": component.get("status", "operational"),
                "description": component.get("description", ""),
            }
            for component in (incident.get("components") or [])
        ],
    }


def fetch_statuspage_active_incidents():
    """Fetch unresolved incidents from Statuspage.io."""
    if not STATUSPAGE_API_KEY:
        return None, "STATUSPAGE_API_KEY not configured"
    req = Request(
        f"https://api.statuspage.io/v1/pages/{STATUSPAGE_PAGE_ID}/incidents",
        headers={"Authorization": f"OAuth {STATUSPAGE_API_KEY}"},
    )
    try:
        resp = urlopen(req, timeout=10)
        data = json.loads(resp.read())
        incidents = [
            _normalize_statuspage_incident(incident)
            for incident in data
            if incident.get("status") not in {"resolved", "postmortem"}
        ]
        return incidents, None
    except HTTPError as e:
        body = e.read().decode()[:500]
        return None, f"Statuspage API {e.code}: {body}"
    except Exception as e:
        return None, str(e)


def create_statuspage_incident(name, body, components, status, impact):
    """Create an incident on Statuspage.io."""
    if not STATUSPAGE_API_KEY:
        return None, "STATUSPAGE_API_KEY not configured"
    component_ids, component_statuses = _build_statuspage_component_payload(components)
    payload = {
        "incident": {
            "name": name,
            "body": body,
            "status": status or "investigating",
            "impact_override": impact or "minor",
            "component_ids": component_ids,
            "components": component_statuses,
        }
    }
    req = Request(
        f"https://api.statuspage.io/v1/pages/{STATUSPAGE_PAGE_ID}/incidents",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"OAuth {STATUSPAGE_API_KEY}",
        },
        method="POST",
    )
    try:
        resp = urlopen(req, timeout=15)
        data = json.loads(resp.read())
        return _normalize_statuspage_incident(data), None
    except HTTPError as e:
        body = e.read().decode()[:500]
        return None, f"Statuspage API {e.code}: {body}"
    except Exception as e:
        return None, str(e)


def update_statuspage_incident(incident_id, name, body, status, impact, components):
    """Update an existing incident on Statuspage.io."""
    if not STATUSPAGE_API_KEY:
        return None, "STATUSPAGE_API_KEY not configured"
    component_ids, component_statuses = _build_statuspage_component_payload(components)
    payload = {
        "incident": {
            "name": name,
            "body": body,
            "status": status or "investigating",
            "impact_override": impact or "minor",
            "component_ids": component_ids,
            "components": component_statuses,
        }
    }
    req = Request(
        f"https://api.statuspage.io/v1/pages/{STATUSPAGE_PAGE_ID}/incidents/{incident_id}",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"OAuth {STATUSPAGE_API_KEY}",
        },
        method="PATCH",
    )
    try:
        resp = urlopen(req, timeout=15)
        data = json.loads(resp.read())
        return _normalize_statuspage_incident(data), None
    except HTTPError as e:
        body = e.read().decode()[:500]
        return None, f"Statuspage API {e.code}: {body}"
    except Exception as e:
        return None, str(e)


def match_entries(db, alert_name, hostname=None, service=None, limit=10):
    """Find runbook entries relevant to the given alert, scored by relevance."""
    query_tokens = tokenize(alert_name)
    alert_lower = alert_name.lower().strip()
    alert_prefix = alert_lower[:30]
    normalized_alert = normalize_alert_pattern(alert_name, hostname or "")
    query_host = _normalized_optional(hostname)
    query_service = _normalized_optional(service)
    manual_link_scores = _fetch_manual_link_scores(db, alert_name, hostname or "", service or "")

    cursor = db.execute(
        "SELECT * FROM runbook_entries ORDER BY created_at DESC LIMIT 500"
    )
    candidates = cursor.fetchall()

    scored = []
    for row in candidates:
        score = 0
        entry_name = (row["alert_name"] or "").lower().strip()
        normalized_entry = normalize_alert_pattern(row["alert_name"] or "", row["hostname"] or "")
        entry_host = _normalized_optional(row["hostname"])
        entry_service = _normalized_optional(row["service"])

        # Exact match
        if entry_name == alert_lower:
            score += 14
        if normalized_entry == normalized_alert:
            score += 18
        else:
            # Prefix match
            if len(alert_lower) > 10 and entry_name[:30] == alert_prefix:
                score += 6

            # Token overlap
            entry_tokens = tokenize(row["alert_name"] or "")
            overlap = query_tokens & entry_tokens
            if len(overlap) >= 3:
                score += 6
            elif len(overlap) >= 2:
                score += 3
            elif len(overlap) >= 1:
                score += 1

        # Hostname match
        if query_host and entry_host:
            if entry_host == query_host:
                score += 8
            elif query_host in entry_host or entry_host in query_host:
                score += 3
        elif query_host and not entry_host:
            score -= 1

        # Service match
        if query_service and entry_service:
            if entry_service == query_service:
                score += 6
        elif query_service and not entry_service:
            score -= 1

        score += manual_link_scores.get(int(row["id"]), 0)

        if score > 0:
            entry = dict(row)
            entry["score"] = score
            scored.append(entry)

    scored.sort(key=lambda x: (-x["score"], -x["id"]))
    return scored[:limit]


def row_to_dict(row):
    """Convert a sqlite3.Row to a plain dict."""
    return dict(row)


# ── Jira Integration ─────────────────────────────────

def text_to_adf(text):
    """Convert plain text to Atlassian Document Format."""
    paragraphs = text.split('\n\n') if '\n\n' in text else text.split('\n')
    content = []
    for p in paragraphs:
        p = p.strip()
        if p:
            content.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": p}]
            })
    if not content:
        content.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": "No description provided"}]
        })
    return {"type": "doc", "version": 1, "content": content}


def _jira_api_url(path, cloud_id=None):
    """Build Jira API URL — uses OAuth cloud API when cloud_id is provided, otherwise direct."""
    if cloud_id:
        return f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3{path}"
    return f"{JIRA_BASE_URL}/rest/api/3{path}"


def _jira_auth_header(oauth_token=None, jira_email=None, jira_api_token=None, allow_global_fallback=True):
    """Build Authorization header — prefers OAuth bearer, falls back to Basic."""
    if oauth_token:
        return f"Bearer {oauth_token}"
    email = jira_email
    token = jira_api_token
    if allow_global_fallback:
        email = email or JIRA_EMAIL
        token = token or JIRA_API_TOKEN
    if email and token:
        auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        return f"Basic {auth}"
    return None


def create_jira_incident(data, jira_email=None, jira_api_token=None, oauth_token=None, cloud_id=None, allow_global_fallback=True):
    """Create a Jira incident in the OCCIR project."""
    auth_header = _jira_auth_header(
        oauth_token,
        jira_email,
        jira_api_token,
        allow_global_fallback=allow_global_fallback,
    )
    if not auth_header:
        return None, "Jira integration not configured — connect your Jira account in Settings"

    fields = {
        "project": {"key": "OCCIR"},
        "issuetype": {"id": "10333"},
        "summary": (data.get("summary") or "")[:255],
        "description": text_to_adf(data.get("description") or ""),
    }

    if data.get("classId"):
        fields["customfield_10306"] = {"id": data["classId"]}
    if data.get("operationalServiceId"):
        fields["customfield_10307"] = {"id": data["operationalServiceId"]}
    if data.get("alertLink"):
        fields["customfield_10308"] = data["alertLink"]

    payload = json.dumps({"fields": fields}).encode()

    req = Request(
        _jira_api_url("/issue", cloud_id),
        data=payload,
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", auth_header)

    try:
        resp = urlopen(req, timeout=15)
        result = json.loads(resp.read())
        issue_key = result.get("key", "")
        log.info(f"Created Jira incident: {issue_key}")

        # Upload attachments if provided
        attachments = data.get("attachments") or []
        attach_errors = []
        for i, att in enumerate(attachments):
            att_data = att.get("data", "")
            att_name = att.get("filename", f"screenshot_{i+1}.png")
            err = attach_file_to_jira_issue(
                issue_key, att_data, att_name,
                jira_email=jira_email, jira_api_token=jira_api_token,
                oauth_token=oauth_token, cloud_id=cloud_id,
                allow_global_fallback=allow_global_fallback,
            )
            if err:
                attach_errors.append(err)

        resp_data = {
            "issue_key": issue_key,
            "issue_url": f"{JIRA_BASE_URL}/browse/{issue_key}",
        }
        if attach_errors:
            resp_data["attachment_errors"] = attach_errors
        return resp_data, None
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log.error(f"Jira API error {e.code}: {body[:500]}")
        return None, f"Jira API error {e.code}: {body[:200]}"
    except (URLError, Exception) as e:
        log.error(f"Jira request failed: {e}")
        return None, str(e)


def attach_file_to_jira_issue(issue_key, base64_data, filename, jira_email=None, jira_api_token=None, oauth_token=None, cloud_id=None, allow_global_fallback=True):
    """Attach a base64-encoded file to an existing Jira issue."""
    auth_header = _jira_auth_header(
        oauth_token,
        jira_email,
        jira_api_token,
        allow_global_fallback=allow_global_fallback,
    )
    if not auth_header:
        return "Jira integration not configured"

    try:
        file_bytes = base64.b64decode(base64_data)
    except Exception as e:
        log.error(f"Failed to decode attachment base64: {e}")
        return f"Invalid base64 data for {filename}"

    boundary = f"----UIPBoundary{id(file_bytes)}"
    body_parts = []
    body_parts.append(f"--{boundary}".encode())
    body_parts.append(f'Content-Disposition: form-data; name="file"; filename="{filename}"'.encode())
    body_parts.append(b"Content-Type: application/octet-stream")
    body_parts.append(b"")
    body_parts.append(file_bytes)
    body_parts.append(f"--{boundary}--".encode())
    body = b"\r\n".join(body_parts)

    req = Request(
        _jira_api_url(f"/issue/{issue_key}/attachments", cloud_id),
        data=body,
        method="POST",
    )
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("Authorization", auth_header)
    req.add_header("X-Atlassian-Token", "no-check")

    try:
        urlopen(req, timeout=30)
        log.info(f"Attached {filename} to {issue_key}")
        return None
    except HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        log.error(f"Jira attachment error {e.code}: {err_body[:300]}")
        return f"Failed to attach {filename}: {e.code}"
    except Exception as e:
        log.error(f"Jira attachment failed: {e}")
        return f"Failed to attach {filename}: {e}"


# ── HTTP Handler ──────────────────────────────────────

def _resolve_request_jira_oauth(handler):
    """Resolve the authenticated user's Jira OAuth token for user-initiated ticket creation."""
    username = _get_username_from_request(handler)
    if not username:
        return None, None, None, (401, "Not authenticated")

    oauth_token, cloud_id = None, None
    token_lookup_error = None
    try:
        token_req = Request(
            f"{AUTH_API_URL}/api/auth/jira-token?username={username}",
            headers={"X-UIP-Internal-Auth": AUTH_SECRET},
        )
        token_resp = urlopen(token_req, timeout=5)
        token_data = json.loads(token_resp.read())
        oauth_token = token_data.get("access_token")
        cloud_id = token_data.get("cloud_id")
        if oauth_token:
            log.info(f"Using OAuth token for {username}")
    except HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
            token_lookup_error = json.loads(body).get("error") or f"HTTP {e.code}"
        except Exception:
            token_lookup_error = f"HTTP {e.code}"
    except Exception as e:
        token_lookup_error = str(e)

    if not oauth_token:
        log.warning(f"Refusing Jira fallback for {username}: {token_lookup_error or 'OAuth token unavailable'}")
        return username, None, None, (
            409,
            token_lookup_error or "Connect or reconnect your Jira account in Settings before creating a ticket",
        )
    return username, oauth_token, cloud_id, None


class RunbookHandler(BaseHTTPRequestHandler):

    def _send_json(self, status, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        if path == "/api/runbook/match":
            alert_name = params.get("alert_name", [""])[0]
            if not alert_name:
                self._send_json(400, {"error": "alert_name is required"})
                return
            hostname = params.get("hostname", [None])[0]
            service = params.get("service", [None])[0]
            limit = min(int(params.get("limit", ["10"])[0]), 20)
            results = match_entries(db, alert_name, hostname, service, limit)
            self._send_json(200, results)

        elif path == "/api/runbook/entries":
            limit = min(int(params.get("limit", ["50"])[0]), 200)
            search = params.get("search", [""])[0].strip()
            page_param = params.get("page", [None])[0]

            # Build WHERE clause for search
            where_clause = ""
            sql_params = []
            if search:
                where_clause = (
                    " WHERE alert_name LIKE ? OR hostname LIKE ? OR remediation LIKE ?"
                )
                like_val = f"%{search}%"
                sql_params = [like_val, like_val, like_val]

            if page_param is not None:
                # Paginated response format
                page = max(int(page_param), 1)
                offset = (page - 1) * limit

                total = db.execute(
                    f"SELECT COUNT(*) FROM runbook_entries{where_clause}",
                    sql_params,
                ).fetchone()[0]

                cursor = db.execute(
                    f"SELECT * FROM runbook_entries{where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    sql_params + [limit, offset],
                )
                rows = [row_to_dict(r) for r in cursor.fetchall()]
                self._send_json(200, {
                    "items": rows,
                    "total": total,
                    "page": page,
                    "limit": limit,
                })
            else:
                # Legacy array response (backward compat)
                offset = int(params.get("offset", ["0"])[0])
                cursor = db.execute(
                    f"SELECT * FROM runbook_entries{where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    sql_params + [limit, offset],
                )
                rows = [row_to_dict(r) for r in cursor.fetchall()]
                self._send_json(200, rows)

        elif path == "/api/runbook/ai-instructions":
            cursor = db.execute(
                "SELECT * FROM ai_instructions WHERE active = 1 ORDER BY created_at DESC"
            )
            rows = [row_to_dict(r) for r in cursor.fetchall()]
            self._send_json(200, rows)

        elif path == "/api/runbook/ai-feedback-summary":
            entry_count = db.execute("SELECT COUNT(*) FROM runbook_entries").fetchone()[0]
            instr_count = db.execute("SELECT COUNT(*) FROM ai_instructions WHERE active = 1").fetchone()[0]
            recent = db.execute(
                "SELECT * FROM runbook_entries ORDER BY created_at DESC LIMIT 5"
            ).fetchall()
            self._send_json(200, {
                "total_runbook_entries": entry_count,
                "recent_entries": [row_to_dict(r) for r in recent],
                "active_instructions": instr_count,
            })

        elif path == "/api/runbook/feedback/match":
            alert_name = params.get("alert_name", [""])[0]
            service = params.get("service", [""])[0].lower()
            if not alert_name:
                self._send_json(400, {"error": "alert_name required"})
                return

            pattern = normalize_alert_pattern(alert_name)
            pattern_tokens = set(pattern.lower().split())
            stop_words = {"the", "a", "an", "is", "on", "for", "at", "in", "to", "of", "and", "or"}
            pattern_tokens -= stop_words

            with _db_lock:
                # Apply decay: one-time halve for entries not reinforced in 90 days
                db.execute(
                    "UPDATE feedback SET usefulness_score = 0.5 "
                    "WHERE reinforced_at < datetime('now', '-90 days') AND usefulness_score >= 1.0"
                )
                db.commit()

                rows = db.execute(
                    "SELECT * FROM feedback WHERE usefulness_score >= 0.1 ORDER BY created_at DESC LIMIT 100"
                ).fetchall()

            results = []
            for row in rows:
                row_tokens = set(row["alert_pattern"].lower().split()) - stop_words
                if not row_tokens:
                    continue
                overlap = len(pattern_tokens & row_tokens)
                if overlap == 0:
                    continue
                score = overlap / max(len(pattern_tokens), 1)
                if service and row["service"] == service:
                    score += 0.3
                results.append({
                    "id": row["id"],
                    "alert_pattern": row["alert_pattern"],
                    "service": row["service"],
                    "severity_correction": row["severity_correction"],
                    "cause_correction": row["cause_correction"],
                    "remediation_correction": row["remediation_correction"],
                    "full_text": row["full_text"],
                    "sre_user": row["sre_user"],
                    "score": round(score * row["usefulness_score"], 3),
                    "created_at": row["created_at"],
                })

            results.sort(key=lambda x: (-x["score"], x["created_at"]))
            self._send_json(200, results[:5])

        elif path.startswith("/api/runbook/entries/"):
            try:
                entry_id = int(path.split("/")[-1])
            except ValueError:
                self._send_json(400, {"error": "invalid id"})
                return
            cursor = db.execute("SELECT * FROM runbook_entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            if row:
                self._send_json(200, row_to_dict(row))
            else:
                self._send_json(404, {"error": "not found"})

        elif path == "/api/runbook/statuspage/components":
            components, error = fetch_statuspage_components()
            if error:
                self._send_json(502, {"error": error})
            else:
                self._send_json(200, components)

        elif path == "/api/runbook/statuspage/incidents":
            incidents, error = fetch_statuspage_active_incidents()
            if error:
                self._send_json(502, {"error": error})
            else:
                self._send_json(200, incidents)

        elif path == "/api/runbook/webhook-test/deliveries":
            with _webhook_test_lock:
                self._send_json(200, list(_webhook_test_buffer))

        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        attach_match = re.match(r"^/api/runbook/entries/(\d+)/attach$", path)
        if attach_match:
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "auth required"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return

            entry_id = int(attach_match.group(1))
            alert_name = (data.get("alert_name") or "").strip()
            if not alert_name:
                self._send_json(400, {"error": "alert_name is required"})
                return

            with _db_lock:
                entry = db.execute("SELECT * FROM runbook_entries WHERE id = ?", (entry_id,)).fetchone()
                if not entry:
                    self._send_json(404, {"error": "runbook entry not found"})
                    return
                link_id, attach_count = record_manual_runbook_link(
                    db,
                    entry_id,
                    alert_name,
                    data.get("hostname") or "",
                    data.get("service") or "",
                    username,
                )
                db.commit()
            self._send_json(200, {
                "ok": True,
                "link_id": link_id,
                "attach_count": attach_count,
                "entry": row_to_dict(entry),
            })

        elif path == "/api/runbook/entries":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return

            alert_name = (data.get("alert_name") or "").strip()
            remediation = (data.get("remediation") or "").strip()

            if not alert_name or not remediation:
                self._send_json(400, {"error": "alert_name and remediation are required"})
                return

            # Cap remediation length
            remediation = remediation[:5000]

            cursor = db.execute(
                """INSERT INTO runbook_entries
                   (alert_name, alert_fingerprint, hostname, service, severity, remediation, sre_user)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert_name,
                    data.get("alert_fingerprint"),
                    data.get("hostname"),
                    data.get("service"),
                    data.get("severity"),
                    remediation,
                    data.get("sre_user"),
                ),
            )
            db.commit()
            entry_id = cursor.lastrowid
            log.info(f"Created runbook entry #{entry_id}: {alert_name[:60]}")
            self._send_json(201, {"id": entry_id, "status": "created"})

        elif path == "/api/runbook/feedback":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "auth required"})
                return

            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return

            alert_pattern = normalize_alert_pattern(
                data.get("alert_name", ""),
                data.get("hostname", "")
            )
            if not alert_pattern:
                self._send_json(400, {"error": "alert_name required"})
                return

            service = (data.get("service") or "").lower().strip()
            sev = (data.get("severity_correction") or "").strip()
            cause = (data.get("cause_correction") or "").strip()
            remed = (data.get("remediation_correction") or "").strip()
            full = (data.get("full_text") or "").strip()

            with _db_lock:
                existing = db.execute(
                    "SELECT id FROM feedback WHERE alert_pattern = ? AND service = ? AND sre_user = ?",
                    (alert_pattern, service, username)
                ).fetchone()
                if existing:
                    db.execute(
                        "UPDATE feedback SET reinforced_at = datetime('now'), usefulness_score = 1.0, "
                        "severity_correction = ?, cause_correction = ?, remediation_correction = ?, full_text = ? "
                        "WHERE id = ?",
                        (sev, cause, remed, full, existing["id"])
                    )
                    db.commit()
                    self._send_json(200, {"status": "reinforced", "id": existing["id"]})
                else:
                    cursor = db.execute(
                        "INSERT INTO feedback (alert_pattern, service, severity_correction, cause_correction, "
                        "remediation_correction, full_text, sre_user) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (alert_pattern, service, sev, cause, remed, full, username)
                    )
                    db.commit()
                    self._send_json(201, {"status": "created", "id": cursor.lastrowid})

        elif path == "/api/runbook/ai-instructions":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            instruction = (data.get("instruction") or "").strip()
            if not instruction:
                self._send_json(400, {"error": "instruction is required"})
                return
            instruction = instruction[:2000]
            cursor = db.execute(
                "INSERT INTO ai_instructions (instruction, sre_user) VALUES (?, ?)",
                (instruction, data.get("sre_user")),
            )
            db.commit()
            log.info(f"Created AI instruction #{cursor.lastrowid}")
            self._send_json(201, {"id": cursor.lastrowid, "status": "created"})

        elif path == "/api/runbook/jira/incident":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return

            if not (data.get("summary") or "").strip():
                self._send_json(400, {"error": "summary is required"})
                return

            username, oauth_token, cloud_id, auth_error = _resolve_request_jira_oauth(self)
            if auth_error:
                status, error_message = auth_error
                self._send_json(status, {"error": error_message})
                return

            result, error = create_jira_incident(
                data,
                oauth_token=oauth_token,
                cloud_id=cloud_id,
                allow_global_fallback=False,
            )
            if error:
                self._send_json(502, {"error": error})
            else:
                self._send_json(201, result)

        # ── Incident Notification Endpoints ───────────────

        elif path == "/api/runbook/incident/assess":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            title = (data.get("title") or "").strip()
            description = (data.get("description") or "").strip()
            if not description:
                self._send_json(400, {"error": "description is required"})
                return
            result = assess_incident_description(title, description)
            self._send_json(200, result)

        elif path == "/api/runbook/incident/webhook":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            title = (data.get("title") or "").strip()
            description = (data.get("description") or "").strip()
            if not title:
                self._send_json(400, {"error": "title is required"})
                return
            started_at = data.get("started_at") or datetime.now(timezone.utc).isoformat()
            preview_only = bool(data.get("preview_only"))
            ok, error = send_incident_webhook(title, description, started_at, preview_only=preview_only)
            if ok:
                log.info(f"Incident webhook sent: {title}")
                self._send_json(200, {"ok": True})
            else:
                log.error(f"Incident webhook failed: {error}")
                self._send_json(502, {"ok": False, "error": error})

        elif path == "/api/runbook/grafana-irm/alert-group-event":
            if not _grafana_irm_webhook_is_authorized(self):
                self._send_json(401, {"error": "Invalid Grafana IRM webhook auth"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            try:
                result = _handle_grafana_irm_alert_group_event(data)
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
                return
            except Exception as e:
                log.exception("Grafana IRM webhook failed")
                self._send_json(502, {"error": str(e)})
                return
            self._send_json(200, result)

        elif path == "/api/runbook/statuspage/incident":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            name = (data.get("name") or "").strip()
            if not name:
                self._send_json(400, {"error": "name is required"})
                return
            result, error = create_statuspage_incident(
                name=name,
                body=(data.get("body") or "").strip(),
                components=data.get("components") or ([
                    {"component_id": component_id, "status": "major_outage"}
                    for component_id in (data.get("component_ids") or [])
                ]),
                status=data.get("status") or "investigating",
                impact=data.get("impact_override") or "minor",
            )
            if error:
                log.error(f"Statuspage incident failed: {error}")
                self._send_json(502, {"error": error})
            else:
                log.info(f"Statuspage incident created: {result}")
                self._send_json(201, result)

        elif path == "/api/runbook/webhook-test/receive":
            # Webhook test receiver — catches incoming webhook deliveries
            raw_body = b""
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                raw_body = self.rfile.read(content_length)

            # Capture the forwarded signature for inspection. The preview
            # receiver does not have access to each subscriber's webhook secret,
            # so it should not label forwarded deliveries as invalid.
            sig_header = self.headers.get("X-Webhook-Signature", "")
            sig_result = "captured" if sig_header else "missing"

            # Parse body
            try:
                body = json.loads(raw_body) if raw_body else {}
            except Exception:
                body = {"raw": raw_body.decode("utf-8", errors="replace")}

            # Extract headers
            headers_dict = {}
            for key in self.headers:
                headers_dict[key] = self.headers[key]

            delivery = {
                "id": len(_webhook_test_buffer) + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "headers": headers_dict,
                "body": body,
                "signature_header": sig_header,
                "signature_result": sig_result,
                "content_length": content_length,
            }

            with _webhook_test_lock:
                _webhook_test_buffer.append(delivery)
                if len(_webhook_test_buffer) > _WEBHOOK_TEST_MAX:
                    _webhook_test_buffer.pop(0)

            log.info(f"Webhook test delivery #{delivery['id']} received (sig={sig_result})")
            self._send_json(200, {"status": "received", "id": delivery["id"]})

        else:
            self._send_json(404, {"error": "not found"})

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/api/runbook/ai-instructions/"):
            try:
                instr_id = int(path.split("/")[-1])
            except ValueError:
                self._send_json(400, {"error": "invalid id"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            sets, vals = [], []
            if "instruction" in data:
                sets.append("instruction = ?")
                vals.append((data["instruction"] or "").strip()[:2000])
            if "active" in data:
                sets.append("active = ?")
                vals.append(1 if data["active"] else 0)
            if not sets:
                self._send_json(400, {"error": "nothing to update"})
                return
            sets.append("updated_at = datetime('now')")
            vals.append(instr_id)
            db.execute(f"UPDATE ai_instructions SET {', '.join(sets)} WHERE id = ?", vals)
            db.commit()
            log.info(f"Updated AI instruction #{instr_id}")
            self._send_json(200, {"status": "updated"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_PATCH(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if re.match(r"^/api/runbook/statuspage/incidents/[^/]+$", path):
            incident_id = path.split("/")[-1]
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return

            name = (data.get("name") or "").strip()
            if not name:
                self._send_json(400, {"error": "name is required"})
                return

            result, error = update_statuspage_incident(
                incident_id=incident_id,
                name=name,
                body=(data.get("body") or "").strip(),
                status=(data.get("status") or "investigating").strip(),
                impact=(data.get("impact_override") or "minor").strip(),
                components=data.get("components") or [],
            )
            if error:
                log.error(f"Statuspage incident update failed: {error}")
                self._send_json(502, {"error": error})
            else:
                self._send_json(200, result)
            return

        self._send_json(404, {"error": "not found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/api/runbook/entries/"):
            try:
                entry_id = int(path.split("/")[-1])
            except ValueError:
                self._send_json(400, {"error": "invalid id"})
                return
            cursor = db.execute("DELETE FROM runbook_entries WHERE id = ?", (entry_id,))
            db.commit()
            if cursor.rowcount > 0:
                log.info(f"Deleted runbook entry #{entry_id}")
                self._send_json(200, {"status": "deleted"})
            else:
                self._send_json(404, {"error": "not found"})

        elif path.startswith("/api/runbook/ai-instructions/"):
            try:
                instr_id = int(path.split("/")[-1])
            except ValueError:
                self._send_json(400, {"error": "invalid id"})
                return
            cursor = db.execute("DELETE FROM ai_instructions WHERE id = ?", (instr_id,))
            db.commit()
            if cursor.rowcount > 0:
                log.info(f"Deleted AI instruction #{instr_id}")
                self._send_json(200, {"status": "deleted"})
            else:
                self._send_json(404, {"error": "not found"})

        elif path == "/api/runbook/webhook-test/deliveries":
            with _webhook_test_lock:
                count = len(_webhook_test_buffer)
                _webhook_test_buffer.clear()
            log.info(f"Cleared {count} webhook test deliveries")
            self._send_json(200, {"status": "cleared", "count": count})

        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, format, *args):
        pass


# ── Main ──────────────────────────────────────────────

def main():
    global db
    db = init_db()

    count = db.execute("SELECT COUNT(*) FROM runbook_entries").fetchone()[0]
    log.info(f"Runbook API starting on port {API_PORT} ({count} entries)")

    server = ThreadingHTTPServer(("0.0.0.0", API_PORT), RunbookHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
