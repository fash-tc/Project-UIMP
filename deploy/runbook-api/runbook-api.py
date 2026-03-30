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
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
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
AUTH_API_URL = os.environ.get("AUTH_API_URL", "http://auth-api:8093")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
MAINT_DASHBOARD_URL = os.environ.get("MAINT_DASHBOARD_URL", "http://10.177.154.174")
GRAFANA_WEBHOOK_SECRET = os.environ.get("GRAFANA_WEBHOOK_SECRET", "")
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


# ── Ollama AI Assessment ──────────────────────────────

def ollama_generate(prompt, model="qwen2.5:3b"):
    """Call Ollama /api/generate and return the response text."""
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 512},
    }).encode()
    req = Request(f"{OLLAMA_URL}/api/generate", data=payload,
                  headers={"Content-Type": "application/json"})
    try:
        resp = urlopen(req, timeout=30)
        data = json.loads(resp.read())
        return data.get("response", "")
    except Exception as e:
        log.error(f"Ollama call failed: {e}")
        return None


def assess_incident_description(title, description):
    """Use Ollama to grade an incident description for customer-appropriateness."""
    prompt = f"""You are an SRE incident communication reviewer. Grade this incident notification that will be sent to CUSTOMERS and PARTNERS via webhook and statuspage.

The description should be:
- Customer-appropriate (no internal jargon, no hostnames, no internal IPs, no ticket numbers)
- Clear about what is affected from the customer's perspective
- Honest but not alarming
- Free of technical implementation details customers don't need

Title: {title}
Description: {description}

Grade on A-F:
- A: Excellent — clear, professional, customer-appropriate
- B: Good — minor improvements possible
- C: Adequate — some internal jargon or unclear impact
- D: Poor — too technical or vague for customers
- F: Unacceptable — contains hostnames, IPs, or incomprehensible to customers

Respond in EXACTLY this JSON format, no other text:
{{"grade": "X", "feedback": "One or two sentences explaining the grade and what to improve."}}"""

    raw = ollama_generate(prompt)
    if not raw:
        return {"grade": "?", "feedback": "AI assessment unavailable — Ollama did not respond."}
    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        # Fallback: extract grade letter from raw text
        grade_match = re.search(r'"grade"\s*:\s*"([A-F?])"', raw)
        grade = grade_match.group(1) if grade_match else "?"
        return {"grade": grade, "feedback": raw.strip()[:500]}


# ── Webhook & Statuspage helpers ──────────────────────

def send_incident_webhook(title, description, started_at):
    """Send incident notification to maintenance dashboard webhook system."""
    if not GRAFANA_WEBHOOK_SECRET:
        return False, "GRAFANA_WEBHOOK_SECRET not configured"
    payload = json.dumps({
        "event_type": "incident",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "title": title,
            "description": description,
            "source": "uip_sre",
            "started_at": started_at or datetime.now(timezone.utc).isoformat(),
            "raw_payload": {},
        },
    }).encode()
    req = Request(f"{MAINT_DASHBOARD_URL}/api/webhooks/incidents",
                  data=payload,
                  headers={
                      "Content-Type": "application/json",
                      "X-Grafana-Secret": GRAFANA_WEBHOOK_SECRET,
                  })
    try:
        resp = urlopen(req, timeout=10)
        return True, None
    except HTTPError as e:
        body = e.read().decode()[:200]
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


def create_statuspage_incident(name, body, component_ids, status, impact):
    """Create an incident on Statuspage.io."""
    if not STATUSPAGE_API_KEY:
        return None, "STATUSPAGE_API_KEY not configured"
    payload = {
        "incident": {
            "name": name,
            "body": body,
            "status": status or "investigating",
            "impact_override": impact or "minor",
            "component_ids": component_ids or [],
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
        return {"id": data.get("id"), "shortlink": data.get("shortlink"),
                "status": data.get("status")}, None
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


def _jira_api_url(path, cloud_id=None):
    """Build Jira API URL — uses OAuth cloud API when cloud_id is provided, otherwise direct."""
    if cloud_id:
        return f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3{path}"
    return f"{JIRA_BASE_URL}/rest/api/3{path}"


def _jira_auth_header(oauth_token=None, jira_email=None, jira_api_token=None):
    """Build Authorization header — prefers OAuth bearer, falls back to Basic."""
    if oauth_token:
        return f"Bearer {oauth_token}"
    email = jira_email or JIRA_EMAIL
    token = jira_api_token or JIRA_API_TOKEN
    if email and token:
        auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        return f"Basic {auth}"
    return None


def create_jira_incident(data, jira_email=None, jira_api_token=None, oauth_token=None, cloud_id=None):
    """Create a Jira incident in the OCCIR project."""
    auth_header = _jira_auth_header(oauth_token, jira_email, jira_api_token)
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


def attach_file_to_jira_issue(issue_key, base64_data, filename, jira_email=None, jira_api_token=None, oauth_token=None, cloud_id=None):
    """Attach a base64-encoded file to an existing Jira issue."""
    auth_header = _jira_auth_header(oauth_token, jira_email, jira_api_token)
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

            # Try to get user's OAuth token from auth-api, fall back to global API key
            username = _get_username_from_request(self)
            oauth_token, cloud_id = None, None
            if username:
                try:
                    token_req = Request(
                        f"{AUTH_API_URL}/api/auth/jira-token?username={username}",
                    )
                    token_resp = urlopen(token_req, timeout=5)
                    token_data = json.loads(token_resp.read())
                    oauth_token = token_data.get("access_token")
                    cloud_id = token_data.get("cloud_id")
                    if oauth_token:
                        log.info(f"Using OAuth token for {username}")
                except Exception as e:
                    log.debug(f"No OAuth token for {username}: {e}")

            result, error = create_jira_incident(data, oauth_token=oauth_token, cloud_id=cloud_id)
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
            ok, error = send_incident_webhook(title, description, started_at)
            if ok:
                log.info(f"Incident webhook sent: {title}")
                self._send_json(200, {"ok": True})
            else:
                log.error(f"Incident webhook failed: {error}")
                self._send_json(502, {"ok": False, "error": error})

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
                component_ids=data.get("component_ids") or [],
                status=data.get("status") or "investigating",
                impact=data.get("impact_override") or "minor",
            )
            if error:
                log.error(f"Statuspage incident failed: {error}")
                self._send_json(502, {"error": error})
            else:
                log.info(f"Statuspage incident created: {result}")
                self._send_json(201, result)

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

    server = HTTPServer(("0.0.0.0", API_PORT), RunbookHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
