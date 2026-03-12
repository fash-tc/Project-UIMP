"""
UIP Runbook API — Persistent remediation knowledge base.
Stores SRE remediation notes in SQLite and provides fuzzy matching
so the AI enricher and frontend can find relevant past remediations.
"""

import json
import os
import logging
import sqlite3
import re
import ssl
import base64
import hashlib
import hmac as hmac_mod
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("runbook-api")

API_PORT = int(os.environ.get("API_PORT", "8090"))
DB_PATH = os.environ.get("DB_PATH", "/data/runbook.db")
JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")

# ── Loki / Registry Health Config ──
GRAFANA_URL = os.environ.get("GRAFANA_URL", "")
GRAFANA_USER = os.environ.get("GRAFANA_USER", "")
GRAFANA_PASS = os.environ.get("GRAFANA_PASS", "")
LOKI_DS_ID = os.environ.get("LOKI_DATASOURCE_ID", "17")
LOKI_POLL_INTERVAL = int(os.environ.get("LOKI_POLL_INTERVAL", "300"))
LOKI_QUERY_WINDOW = int(os.environ.get("LOKI_QUERY_WINDOW", "3600"))

STOP_WORDS = {
    "on", "the", "is", "for", "at", "in", "a", "an", "not", "to",
    "of", "has", "with", "from", "alert", "check", "problem", "trigger",
    "and", "or", "be", "was", "are", "been", "being", "have", "had",
    "do", "does", "did", "but", "if", "no", "than", "too", "very",
    "can", "will", "just", "-", "",
}

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
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            display_name TEXT NOT NULL,
            jira_email TEXT DEFAULT '',
            jira_api_token TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS alert_states (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_fingerprint TEXT NOT NULL,
            alert_name TEXT DEFAULT '',
            investigating_user TEXT DEFAULT NULL,
            investigating_since TEXT DEFAULT NULL,
            acknowledged_by TEXT DEFAULT NULL,
            acknowledged_at TEXT DEFAULT NULL,
            ack_firing_start TEXT DEFAULT NULL,
            is_updated INTEGER DEFAULT 0,
            updated_detected_at TEXT DEFAULT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_as_fingerprint ON alert_states(alert_fingerprint)")
    db.commit()
    _seed_users(db)
    log.info(f"Database initialized at {DB_PATH}")
    return db


# ── Authentication ────────────────────────────────────

_SEED_USERS = [
    ("jpratt", "jpratt"),
    ("azatari", "azatari"),
    ("aplacid", "aplacid"),
    ("dcolley", "dcolley"),
    ("fash", "fash"),
    ("isulaiman", "isulaiman"),
    ("smalik", "smalik"),
    ("talkaraki", "talkaraki"),
]
_DEFAULT_PASSWORD = "SreTeam2026!"


def _hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return h.hex(), salt.hex()


def _verify_password(password, stored_hash, stored_salt):
    salt = bytes.fromhex(stored_salt)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return h.hex() == stored_hash


def _seed_users(db):
    for username, display_name in _SEED_USERS:
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not existing:
            pw_hash, pw_salt = _hash_password(_DEFAULT_PASSWORD)
            db.execute(
                "INSERT INTO users (username, password_hash, password_salt, display_name) VALUES (?, ?, ?, ?)",
                (username, pw_hash, pw_salt, display_name),
            )
            log.info(f"Seeded user: {username}")
    db.commit()


def _create_auth_token(username, ttl_hours=24):
    payload = {"u": username, "e": int(time.time()) + ttl_hours * 3600}
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac_mod.new(AUTH_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def _verify_auth_token(token):
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
        return payload.get("u")
    except Exception:
        return None


def _get_username_from_request(handler):
    cookie_header = handler.headers.get("Cookie", "")
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.strip() == "uip_auth":
                return _verify_auth_token(v.strip())
    return None


# ── Text Matching ────────────────────────────────────

def tokenize(text):
    """Split text into lowercase keyword tokens, removing stop words."""
    words = re.split(r'[\s/\-_:,.;()\[\]]+', text.lower())
    return {w for w in words if w and w not in STOP_WORDS}


def match_entries(db, alert_name, hostname=None, service=None, limit=10):
    """Find runbook entries relevant to the given alert, scored by relevance."""
    query_tokens = tokenize(alert_name)
    alert_lower = alert_name.lower().strip()
    alert_prefix = alert_lower[:30]

    cursor = db.execute(
        "SELECT * FROM runbook_entries ORDER BY created_at DESC LIMIT 500"
    )
    candidates = cursor.fetchall()

    scored = []
    for row in candidates:
        score = 0
        entry_name = (row["alert_name"] or "").lower().strip()

        # Exact match
        if entry_name == alert_lower:
            score += 10
        else:
            # Prefix match
            if len(alert_lower) > 10 and entry_name[:30] == alert_prefix:
                score += 6

            # Token overlap
            entry_tokens = tokenize(row["alert_name"] or "")
            overlap = query_tokens & entry_tokens
            if len(overlap) >= 3:
                score += 4
            elif len(overlap) >= 2:
                score += 2
            elif len(overlap) >= 1:
                score += 1

        # Hostname match
        if hostname and row["hostname"]:
            host_lower = hostname.lower()
            entry_host = row["hostname"].lower()
            if entry_host == host_lower:
                score += 3
            elif host_lower in entry_host or entry_host in host_lower:
                score += 1

        # Service match
        if service and row["service"]:
            if row["service"].lower() == service.lower():
                score += 2

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


def create_jira_incident(data, jira_email=None, jira_api_token=None):
    """Create a Jira incident in the OCCIR project."""
    email = jira_email or JIRA_EMAIL
    token = jira_api_token or JIRA_API_TOKEN
    if not all([JIRA_BASE_URL, email, token]):
        return None, "Jira integration not configured"

    auth = base64.b64encode(f"{email}:{token}".encode()).decode()

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
        f"{JIRA_BASE_URL}/rest/api/3/issue",
        data=payload,
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Basic {auth}")

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
            err = attach_file_to_jira_issue(issue_key, att_data, att_name, email, token)
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


def attach_file_to_jira_issue(issue_key, base64_data, filename, jira_email=None, jira_api_token=None):
    """Attach a base64-encoded file to an existing Jira issue."""
    email = jira_email or JIRA_EMAIL
    token = jira_api_token or JIRA_API_TOKEN
    if not all([JIRA_BASE_URL, email, token]):
        return "Jira integration not configured"

    try:
        file_bytes = base64.b64decode(base64_data)
    except Exception as e:
        log.error(f"Failed to decode attachment base64: {e}")
        return f"Invalid base64 data for {filename}"

    auth = base64.b64encode(f"{email}:{token}".encode()).decode()

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
        f"{JIRA_BASE_URL}/rest/api/3/issue/{issue_key}/attachments",
        data=body,
        method="POST",
    )
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("Authorization", f"Basic {auth}")
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


# ── Registry Health (Loki) ────────────────────────────

# Maps Loki registry_agent label values to frontend operator IDs.
AGENT_OPERATOR_MAP = {
    "ARIProxy": "ari-registry",
    "AUProxy": "ari-registry",
    "BrProxy": "registro",
    "CATProxy": "corenic",
    "CentralNicCoProxy": "centralnic",
    "CentralNicProxy": "centralnic",
    "ComNetBatchProxy": "verisign",
    "ComNetProxy": "verisign",
    "CymruProxy": "nominet",
    "DonutsProxy": "identity-digital",
    "EuProxy": "eurid",
    "FuryCaProxy": "cira",
    "FuryNzProxy": "internetnz",
    "GMOProxy": "gmo-registry",
    "GMOShopProxy": "gmo-registry",
    "KNetProxy": "knet-zdns",
    "NLProxy": "sidn",
    "PIRProxy": "pir",
    "ScotProxy": "corenic",
    "UkProxy": "nominet",
    "UniregistryINTeaProxy": "uniregistry",
    "UniregistryMMXProxy": "uniregistry",
    "UniregistryProxy": "uniregistry",
    "VerisignProxy": "verisign",
    "WSProxy": "website-ws",
    "WalesProxy": "nominet",
    "ZACRAfricaProxy": "zacr",
    "ZACRCoZaProxy": "zacr",
    "ZACRProxy": "zacr",
}

_TIMING_RE = re.compile(
    r"sendRecv=(\d+).*?total=(\d+)\s+ms\s+for\s+([\w\s]+?)\s+with\s+resp\s+(\d+)"
)
_EPP_CODE_RE = re.compile(r'result code="(\d{4})"')

_registry_health_cache = {
    "last_updated": None,
    "query_window_seconds": 3600,
    "poll_interval_seconds": 300,
    "operators": {},
    "unmapped_agents": [],
    "loki_error": None,
}
_cache_lock = threading.Lock()

_log_samples_cache = {
    "last_updated": None,
    "operators": {},  # op_id -> {"errors": [...], "slow": [...], "epp_errors": [...]}
}

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def _loki_query(logql):
    """Execute a LogQL query via Grafana's datasource proxy."""
    now_ns = int(time.time() * 1e9)
    start_ns = now_ns - (LOKI_QUERY_WINDOW * int(1e9))

    params = urlencode({
        "query": logql,
        "start": str(start_ns),
        "end": str(now_ns),
        "limit": "5000",
        "direction": "backward",
    })

    url = f"{GRAFANA_URL}/api/datasources/proxy/{LOKI_DS_ID}/loki/api/v1/query_range?{params}"
    auth = base64.b64encode(f"{GRAFANA_USER}:{GRAFANA_PASS}".encode()).decode()

    req = Request(url)
    req.add_header("Authorization", f"Basic {auth}")

    resp = urlopen(req, timeout=30, context=_ssl_ctx)
    return json.loads(resp.read())


def _aggregate_health(timing_data, epp_data):
    """Process raw Loki results into per-operator health metrics."""
    raw = {}  # operator_id -> {total_times, sendrecv_times, resp_codes, epp_codes, operations}
    unmapped = set()
    log_samples = {}  # operator_id -> {errors, slow, epp_errors}

    def _bucket(op_id):
        if op_id not in raw:
            raw[op_id] = {
                "total_times": [], "sendrecv_times": [],
                "resp_codes": {}, "epp_codes": {}, "operations": {},
            }
        if op_id not in log_samples:
            log_samples[op_id] = {"errors": [], "slow": [], "epp_errors": []}
        return raw[op_id]

    # Parse timing logs
    for stream in (timing_data.get("data") or {}).get("result") or []:
        agent = stream.get("stream", {}).get("registry_agent", "")
        op_id = AGENT_OPERATOR_MAP.get(agent)
        if not op_id:
            unmapped.add(agent)
            continue

        b = _bucket(op_id)
        s = log_samples[op_id]
        for _, line in stream.get("values") or []:
            try:
                msg = json.loads(line).get("message", "")
            except (json.JSONDecodeError, AttributeError):
                msg = line
            m = _TIMING_RE.search(msg)
            if not m:
                continue
            total_ms = int(m.group(2))
            sendrecv_ms = int(m.group(1))
            resp = int(m.group(4))
            op = m.group(3).strip()
            b["total_times"].append(total_ms)
            b["sendrecv_times"].append(sendrecv_ms)
            b["resp_codes"][resp] = b["resp_codes"].get(resp, 0) + 1
            b["operations"][op] = b["operations"].get(op, 0) + 1
            if resp >= 400 and len(s["errors"]) < 10:
                s["errors"].append({"agent": agent, "op": op, "resp": resp, "ms": total_ms})
            if total_ms > 5000 and len(s["slow"]) < 5:
                s["slow"].append({"agent": agent, "op": op, "ms": total_ms})

    # Parse EPP XML responses
    for stream in (epp_data.get("data") or {}).get("result") or []:
        agent = stream.get("stream", {}).get("registry_agent", "")
        op_id = AGENT_OPERATOR_MAP.get(agent)
        if not op_id:
            unmapped.add(agent)
            continue

        b = _bucket(op_id)
        s = log_samples.get(op_id) or {"errors": [], "slow": [], "epp_errors": []}
        log_samples[op_id] = s
        for _, line in stream.get("values") or []:
            try:
                msg = json.loads(line).get("message", "")
            except (json.JSONDecodeError, AttributeError):
                msg = line
            for code_str in _EPP_CODE_RE.findall(msg):
                code = int(code_str)
                b["epp_codes"][code] = b["epp_codes"].get(code, 0) + 1
                if code >= 2000 and len(s["epp_errors"]) < 10:
                    s["epp_errors"].append({"agent": agent, "epp_code": code})

    # Compute final metrics per operator
    result = {}
    for op_id, d in raw.items():
        n = len(d["total_times"])
        if n == 0:
            result[op_id] = {
                "status": "no_data", "request_count": 0,
                "avg_response_ms": 0, "avg_sendrecv_ms": 0, "p95_response_ms": 0,
                "error_rate": 0, "resp_codes": {}, "epp_error_rate": 0,
                "epp_codes": {}, "top_operations": {},
            }
            continue

        avg_total = sum(d["total_times"]) / n
        avg_sr = sum(d["sendrecv_times"]) / n
        sorted_t = sorted(d["total_times"])
        p95 = sorted_t[min(int(n * 0.95), n - 1)]

        err_resp = sum(v for k, v in d["resp_codes"].items() if k >= 400)
        ok_resp = sum(v for k, v in d["resp_codes"].items() if k < 400)
        total_resp = err_resp + ok_resp
        error_rate = (err_resp / total_resp) if total_resp > 0 else 0

        epp_err = sum(v for k, v in d["epp_codes"].items() if k >= 2000)
        epp_ok = sum(v for k, v in d["epp_codes"].items() if k < 2000)
        epp_total = epp_err + epp_ok
        epp_error_rate = (epp_err / epp_total) if epp_total > 0 else 0

        status = "healthy"
        if error_rate > 0.5 or epp_error_rate > 0.5 or avg_total > 10000:
            status = "down"
        elif error_rate > 0.1 or epp_error_rate > 0.1 or avg_total > 5000:
            status = "degraded"

        top_ops = dict(sorted(d["operations"].items(), key=lambda x: -x[1])[:5])
        resp_sorted = {str(k): v for k, v in sorted(d["resp_codes"].items())}
        epp_sorted = {str(k): v for k, v in sorted(d["epp_codes"].items())}

        result[op_id] = {
            "status": status,
            "request_count": n,
            "avg_response_ms": round(avg_total, 1),
            "avg_sendrecv_ms": round(avg_sr, 1),
            "p95_response_ms": p95,
            "error_rate": round(error_rate, 4),
            "resp_codes": resp_sorted,
            "epp_error_rate": round(epp_error_rate, 4),
            "epp_codes": epp_sorted,
            "top_operations": top_ops,
        }

    return result, sorted(unmapped), log_samples


def _loki_poller():
    """Background thread that polls Loki on interval and updates the cache."""
    log.info(f"Loki poller started: interval={LOKI_POLL_INTERVAL}s, window={LOKI_QUERY_WINDOW}s")

    while True:
        try:
            log.info("Polling Loki for registry health metrics...")
            timing = _loki_query('{app="ra", registry_agent=~".+"} |~ "total="')
            epp = _loki_query('{app="ra", registry_agent=~".+"} |~ "result code"')
            operators, unmapped, samples = _aggregate_health(timing, epp)

            with _cache_lock:
                _registry_health_cache.update({
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "query_window_seconds": LOKI_QUERY_WINDOW,
                    "poll_interval_seconds": LOKI_POLL_INTERVAL,
                    "operators": operators,
                    "unmapped_agents": unmapped,
                    "loki_error": None,
                })
                _log_samples_cache.update({
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "operators": samples,
                })
            log.info(f"Registry health updated: {len(operators)} operators, {len(unmapped)} unmapped")

        except Exception as e:
            log.error(f"Loki poll failed: {e}")
            with _cache_lock:
                _registry_health_cache["loki_error"] = str(e)
                _registry_health_cache["last_updated"] = datetime.now(timezone.utc).isoformat()

        time.sleep(LOKI_POLL_INTERVAL)


def _build_log_context(alert_name, hostname):
    """Build log context from cached registry health + log samples for an alert."""
    with _cache_lock:
        health = dict(_registry_health_cache)
        samples = dict(_log_samples_cache)

    operators = health.get("operators")
    if not operators:
        return {"has_context": False}

    issues = []
    for op_id, metrics in operators.items():
        if metrics.get("status") in ("degraded", "down"):
            issues.append((op_id, metrics))

    total = len(operators)
    healthy = sum(1 for m in operators.values() if m.get("status") == "healthy")
    degraded = sum(1 for m in operators.values() if m.get("status") == "degraded")
    down = sum(1 for m in operators.values() if m.get("status") == "down")

    result = {
        "has_context": True,
        "last_updated": health.get("last_updated"),
        "total_operators": total,
        "healthy_count": healthy,
        "degraded_count": degraded,
        "down_count": down,
        "operator_issues": [],
    }

    op_samples = samples.get("operators", {})
    for op_id, metrics in issues:
        op_data = {
            "operator": op_id,
            "status": metrics.get("status", "unknown"),
            "avg_response_ms": metrics.get("avg_response_ms", 0),
            "error_rate": metrics.get("error_rate", 0),
            "epp_error_rate": metrics.get("epp_error_rate", 0),
            "request_count": metrics.get("request_count", 0),
        }
        samp = op_samples.get(op_id, {})
        if samp.get("errors"):
            op_data["recent_errors"] = samp["errors"][:5]
        if samp.get("epp_errors"):
            op_data["recent_epp_errors"] = samp["epp_errors"][:5]
        if samp.get("slow"):
            op_data["slow_requests"] = samp["slow"][:3]
        result["operator_issues"].append(op_data)

    if not issues:
        result["all_healthy"] = True

    return result


def _loki_query_custom(logql, limit=200, range_seconds=3600):
    """Execute a LogQL query with custom parameters for interactive use."""
    now_ns = int(time.time() * 1e9)
    start_ns = now_ns - (range_seconds * int(1e9))

    params = urlencode({
        "query": logql,
        "start": str(start_ns),
        "end": str(now_ns),
        "limit": str(min(limit, 1000)),
        "direction": "backward",
    })

    url = f"{GRAFANA_URL}/api/datasources/proxy/{LOKI_DS_ID}/loki/api/v1/query_range?{params}"
    auth = base64.b64encode(f"{GRAFANA_USER}:{GRAFANA_PASS}".encode()).decode()

    req = Request(url)
    req.add_header("Authorization", f"Basic {auth}")

    resp = urlopen(req, timeout=30, context=_ssl_ctx)
    return json.loads(resp.read())


def _parse_loki_entries(raw_data):
    """Flatten Loki response into a sorted list of log entries."""
    entries = []
    for stream in (raw_data.get("data") or {}).get("result") or []:
        labels = stream.get("stream", {})
        for ts_ns, line in stream.get("values") or []:
            ts_sec = int(ts_ns) / 1e9
            dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
            try:
                parsed = json.loads(line)
                message = parsed.get("message", line)
            except (json.JSONDecodeError, AttributeError):
                message = line
            entries.append({
                "timestamp": dt.isoformat(),
                "labels": labels,
                "message": message,
            })
    entries.sort(key=lambda e: e["timestamp"], reverse=True)
    return entries


# ── HTTP Handler ──────────────────────────────────────

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
            offset = int(params.get("offset", ["0"])[0])
            cursor = db.execute(
                "SELECT * FROM runbook_entries ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
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

        elif path == "/api/runbook/registry-health":
            with _cache_lock:
                cache_copy = dict(_registry_health_cache)
            self._send_json(200, cache_copy)

        elif path == "/api/runbook/log-context":
            alert_name = params.get("alert_name", [""])[0]
            hostname = params.get("hostname", [""])[0]
            ctx = _build_log_context(alert_name, hostname)
            self._send_json(200, ctx)

        elif path == "/api/runbook/auth/me":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "Not authenticated"})
                return
            row = db.execute("SELECT username, display_name, jira_email, jira_api_token, created_at FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                self._send_json(401, {"error": "User not found"})
                return
            self._send_json(200, {
                "username": row["username"],
                "display_name": row["display_name"],
                "jira_email": row["jira_email"] or "",
                "has_jira_token": bool(row["jira_api_token"]),
                "created_at": row["created_at"],
            })

        elif path == "/api/runbook/alert-states":
            cursor = db.execute("""
                SELECT * FROM alert_states
                WHERE investigating_user IS NOT NULL
                   OR acknowledged_by IS NOT NULL
                   OR is_updated = 1
                ORDER BY updated_at DESC
            """)
            rows = [row_to_dict(r) for r in cursor.fetchall()]
            self._send_json(200, rows)

        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/runbook/entries":
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

        elif path == "/api/runbook/logs/query":
            if not GRAFANA_URL:
                self._send_json(503, {"error": "Loki not configured"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            query = (data.get("query") or "").strip()
            if not query:
                self._send_json(400, {"error": "query is required"})
                return
            limit = min(int(data.get("limit", 200)), 1000)
            range_seconds = min(int(data.get("range", 3600)), 86400)
            try:
                raw = _loki_query_custom(query, limit, range_seconds)
                entries = _parse_loki_entries(raw)
                self._send_json(200, {
                    "entries": entries,
                    "total": len(entries),
                    "query": query,
                    "range_seconds": range_seconds,
                })
            except HTTPError as e:
                body = ""
                try:
                    body = e.read().decode()[:200]
                except Exception:
                    pass
                self._send_json(502, {"error": f"Loki query failed ({e.code})", "detail": body})
            except Exception as e:
                self._send_json(502, {"error": f"Loki query failed: {str(e)}"})

        elif path == "/api/runbook/auth/login":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            username = (data.get("username") or "").strip().lower()
            password = data.get("password") or ""
            if not username or not password:
                self._send_json(400, {"error": "username and password required"})
                return
            row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not row or not _verify_password(password, row["password_hash"], row["password_salt"]):
                self._send_json(401, {"error": "Invalid username or password"})
                return
            token = _create_auth_token(username)
            resp_body = json.dumps({"ok": True, "user": {
                "username": row["username"],
                "display_name": row["display_name"],
            }}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"uip_auth={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
            self.send_header("Set-Cookie", f"uip_user={username}; Path=/; SameSite=Lax; Max-Age=86400")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            log.info(f"User logged in: {username}")

        elif path == "/api/runbook/auth/logout":
            resp_body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "uip_auth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            self.send_header("Set-Cookie", "uip_user=; Path=/; SameSite=Lax; Max-Age=0")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

        elif path == "/api/runbook/auth/change-password":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "Not authenticated"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            current_pw = data.get("current_password") or ""
            new_pw = data.get("new_password") or ""
            if len(new_pw) < 8:
                self._send_json(400, {"error": "New password must be at least 8 characters"})
                return
            row = db.execute("SELECT password_hash, password_salt FROM users WHERE username = ?", (username,)).fetchone()
            if not row or not _verify_password(current_pw, row["password_hash"], row["password_salt"]):
                self._send_json(401, {"error": "Current password is incorrect"})
                return
            pw_hash, pw_salt = _hash_password(new_pw)
            db.execute("UPDATE users SET password_hash = ?, password_salt = ?, updated_at = datetime('now') WHERE username = ?",
                       (pw_hash, pw_salt, username))
            db.commit()
            log.info(f"Password changed for user: {username}")
            self._send_json(200, {"ok": True})

        elif path == "/api/runbook/auth/jira-config":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "Not authenticated"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            jira_email = (data.get("jira_email") or "").strip()
            jira_token = (data.get("jira_api_token") or "").strip()
            db.execute("UPDATE users SET jira_email = ?, jira_api_token = ?, updated_at = datetime('now') WHERE username = ?",
                       (jira_email, jira_token, username))
            db.commit()
            log.info(f"Jira config updated for user: {username}")
            self._send_json(200, {"ok": True, "has_jira_token": bool(jira_token)})

        elif path == "/api/runbook/jira/incident":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return

            if not (data.get("summary") or "").strip():
                self._send_json(400, {"error": "summary is required"})
                return

            # Per-user Jira credentials
            user_jira_email, user_jira_token = None, None
            username = _get_username_from_request(self)
            if username:
                user_row = db.execute(
                    "SELECT jira_email, jira_api_token FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
                if user_row and user_row["jira_email"] and user_row["jira_api_token"]:
                    user_jira_email = user_row["jira_email"]
                    user_jira_token = user_row["jira_api_token"]
                    log.info(f"Using per-user Jira creds for {username}")

            result, error = create_jira_incident(data, user_jira_email, user_jira_token)
            if error:
                self._send_json(502, {"error": error})
            else:
                self._send_json(201, result)

        elif path == "/api/runbook/alert-states/investigate":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            fingerprint = (data.get("fingerprint") or "").strip()
            if not fingerprint:
                self._send_json(400, {"error": "fingerprint is required"})
                return
            alert_name = (data.get("alert_name") or "").strip()
            row = db.execute(
                "SELECT investigating_user FROM alert_states WHERE alert_fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row and row["investigating_user"] == username:
                db.execute("""
                    UPDATE alert_states
                    SET investigating_user = NULL, investigating_since = NULL, updated_at = datetime('now')
                    WHERE alert_fingerprint = ?
                """, (fingerprint,))
                db.commit()
                self._send_json(200, {"status": "stopped", "investigating_user": None})
            else:
                now = datetime.now(timezone.utc).isoformat()
                db.execute("""
                    INSERT INTO alert_states (alert_fingerprint, alert_name, investigating_user, investigating_since, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(alert_fingerprint) DO UPDATE SET
                        investigating_user = excluded.investigating_user,
                        investigating_since = excluded.investigating_since,
                        alert_name = COALESCE(excluded.alert_name, alert_states.alert_name),
                        updated_at = datetime('now')
                """, (fingerprint, alert_name, username, now))
                db.commit()
                self._send_json(200, {"status": "investigating", "investigating_user": username})

        elif path == "/api/runbook/alert-states/acknowledge":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            fingerprints = data.get("fingerprints") or []
            alert_names = data.get("alert_names") or {}
            firing_starts = data.get("firing_starts") or {}
            if not fingerprints:
                self._send_json(400, {"error": "fingerprints list is required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            for fp in fingerprints:
                db.execute("""
                    INSERT INTO alert_states (alert_fingerprint, alert_name, acknowledged_by, acknowledged_at, ack_firing_start, is_updated, updated_at)
                    VALUES (?, ?, ?, ?, ?, 0, datetime('now'))
                    ON CONFLICT(alert_fingerprint) DO UPDATE SET
                        acknowledged_by = excluded.acknowledged_by,
                        acknowledged_at = excluded.acknowledged_at,
                        ack_firing_start = excluded.ack_firing_start,
                        alert_name = COALESCE(excluded.alert_name, alert_states.alert_name),
                        is_updated = 0,
                        updated_at = datetime('now')
                """, (fp, alert_names.get(fp, ""), username, now, firing_starts.get(fp, "")))
            db.commit()
            log.info(f"{username} acknowledged {len(fingerprints)} alert(s)")
            self._send_json(200, {"status": "acknowledged", "count": len(fingerprints)})

        elif path == "/api/runbook/alert-states/unacknowledge":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            fingerprints = data.get("fingerprints") or []
            if not fingerprints:
                self._send_json(400, {"error": "fingerprints list is required"})
                return
            for fp in fingerprints:
                db.execute("""
                    UPDATE alert_states SET
                        acknowledged_by = NULL, acknowledged_at = NULL,
                        ack_firing_start = NULL, is_updated = 0, updated_at = datetime('now')
                    WHERE alert_fingerprint = ?
                """, (fp,))
            db.commit()
            self._send_json(200, {"status": "unacknowledged", "count": len(fingerprints)})

        elif path == "/api/runbook/alert-states/mark-updated":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            fingerprints = data.get("fingerprints") or []
            now = datetime.now(timezone.utc).isoformat()
            for fp in fingerprints:
                db.execute("""
                    UPDATE alert_states SET
                        acknowledged_by = NULL, acknowledged_at = NULL,
                        is_updated = 1, updated_detected_at = ?,
                        updated_at = datetime('now')
                    WHERE alert_fingerprint = ?
                """, (now, fp))
            db.commit()
            if fingerprints:
                log.info(f"Marked {len(fingerprints)} alert(s) as updated (re-fired)")
            self._send_json(200, {"status": "marked_updated", "count": len(fingerprints)})

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

    # Automatic Loki poller DISABLED to avoid overloading Loki instance.
    # Interactive log queries via POST /api/runbook/logs/query still work.
    log.info("Loki automatic poller disabled — interactive queries only")

    server = HTTPServer(("0.0.0.0", API_PORT), RunbookHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
