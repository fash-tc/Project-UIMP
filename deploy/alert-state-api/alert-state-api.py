"""alert-state-api: Alert investigation and acknowledgment tracking service for UIP."""

import json
import os
import logging
import sqlite3
import base64
import hashlib
import hmac as hmac_mod
import threading
import time
from datetime import datetime, timezone
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("alert-state-api")

API_PORT = int(os.environ.get("API_PORT", "8092"))
DB_PATH = os.environ.get("DB_PATH", "/data/alert-states.db")
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")

_db_lock = threading.Lock()

# ── SSE Infrastructure ────────────────────────────────────
_sse_lock = threading.Lock()
_sse_clients = set()          # Set of wfile objects
_sse_event_counter = 0
_sse_ring_buffer = deque(maxlen=100)  # Ring buffer for replay
_SSE_MAX_CLIENTS = 50


def _sse_broadcast(event_type, payload):
    """Broadcast an SSE event to all connected clients."""
    global _sse_event_counter, _sse_clients
    with _sse_lock:
        _sse_event_counter += 1
        event_id = _sse_event_counter
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        payload["type"] = event_type
        msg = f"id: {event_id}\nevent: state_change\ndata: {json.dumps(payload, default=str)}\n\n"
        _sse_ring_buffer.append((event_id, msg))
        dead = set()
        for client in _sse_clients:
            try:
                client.write(msg.encode())
                client.flush()
            except Exception:
                dead.add(client)
        _sse_clients -= dead
        if dead:
            log.info(f"Removed {len(dead)} dead SSE client(s), {len(_sse_clients)} remaining")


# ── Database ───────────────────────────────────────────

def _init_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("""
        CREATE TABLE IF NOT EXISTS alert_states (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_fingerprint TEXT UNIQUE NOT NULL,
            alert_name TEXT DEFAULT '',
            investigating_user TEXT DEFAULT NULL,
            investigating_since TEXT DEFAULT NULL,
            acknowledged_by TEXT DEFAULT NULL,
            acknowledged_at TEXT DEFAULT NULL,
            ack_firing_start TEXT DEFAULT NULL,
            is_updated INTEGER DEFAULT 0,
            updated_detected_at TEXT DEFAULT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_as_fingerprint ON alert_states(alert_fingerprint)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS runbook_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_fingerprint TEXT NOT NULL,
            alert_name TEXT NOT NULL,
            runbook_entry_id INTEGER NOT NULL,
            vote TEXT NOT NULL,
            user TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(alert_fingerprint, runbook_entry_id, user)
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_feedback_entry_id ON runbook_feedback(runbook_entry_id)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS situation_summary (
            id INTEGER PRIMARY KEY DEFAULT 1,
            one_liner TEXT,
            clusters_json TEXT,
            shift_context_json TEXT,
            actions_json TEXT,
            suggested_merges_json TEXT,
            generated_at TEXT,
            alert_hash TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS silence_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_name_pattern TEXT NOT NULL,
            hostname_pattern TEXT DEFAULT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            reason TEXT DEFAULT '',
            active INTEGER DEFAULT 1
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_silence_active ON silence_rules(active, expires_at)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS sre_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_fingerprint TEXT NOT NULL,
            alert_name TEXT NOT NULL,
            rating TEXT,
            corrected_severity TEXT,
            corrected_noise INTEGER,
            comment TEXT,
            user TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_sre_feedback_fp ON sre_feedback(alert_fingerprint)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_sre_feedback_name ON sre_feedback(alert_name)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS sre_feedback_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feedback_id INTEGER NOT NULL REFERENCES sre_feedback(id) ON DELETE CASCADE,
            user TEXT NOT NULL,
            vote TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(feedback_id, user)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runbook_exclusions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_name TEXT NOT NULL,
            runbook_entry_id INTEGER NOT NULL,
            excluded_by TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(alert_name, runbook_entry_id)
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_runbook_excl_name ON runbook_exclusions(alert_name)")
    db.commit()
    # Add force_enrich column if it doesn't exist (migration)
    try:
        db.execute("ALTER TABLE alert_states ADD COLUMN force_enrich INTEGER DEFAULT 0")
        db.commit()
        log.info("Added force_enrich column to alert_states")
    except sqlite3.OperationalError:
        pass  # Column already exists
    # Migration: add incident and escalation columns
    existing = {row[1] for row in db.execute("PRAGMA table_info(alert_states)").fetchall()}
    for col, default in [
        ("incident_jira_key", "NULL"),
        ("incident_jira_url", "NULL"),
        ("incident_created_by", "NULL"),
        ("incident_created_at", "NULL"),
        ("escalated_to", "NULL"),
        ("escalated_by", "NULL"),
        ("escalated_at", "NULL"),
        ("severity_override", "NULL"),
        ("severity_override_by", "NULL"),
        ("severity_override_at", "NULL"),
    ]:
        if col not in existing:
            db.execute(f"ALTER TABLE alert_states ADD COLUMN {col} TEXT DEFAULT {default}")
            log.info(f"Migrated: added '{col}' column to alert_states")
    db.commit()
    # Migrate situation_summary table
    existing_ss = {row[1] for row in db.execute("PRAGMA table_info(situation_summary)").fetchall()}
    if "suggested_merges_json" not in existing_ss:
        db.execute("ALTER TABLE situation_summary ADD COLUMN suggested_merges_json TEXT DEFAULT NULL")
        log.info("Migrated: added 'suggested_merges_json' to situation_summary")
    db.commit()
    log.info(f"Database initialized at {DB_PATH}")
    return db


# ── Authentication ─────────────────────────────────────

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


# ── HTTP Handler ───────────────────────────────────────

class AlertStateHandler(BaseHTTPRequestHandler):

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

    def log_message(self, fmt, *args):
        log.info("%s - - %s" % (self.address_string(), fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/alert-states":
            qs = parse_qs(parsed.query)
            with _db_lock:
                if qs.get("force_enrich", [""])[0].lower() == "true":
                    cursor = db.execute("""
                        SELECT * FROM alert_states
                        WHERE force_enrich = 1
                        ORDER BY updated_at DESC
                    """)
                else:
                    cursor = db.execute("""
                        SELECT * FROM alert_states
                        WHERE investigating_user IS NOT NULL
                           OR acknowledged_by IS NOT NULL
                           OR is_updated = 1
                           OR incident_jira_key IS NOT NULL
                           OR escalated_to IS NOT NULL
                        ORDER BY updated_at DESC
                    """)
                rows = [dict(r) for r in cursor.fetchall()]
            self._send_json(200, rows)

        elif path == "/api/alert-states/runbook-feedback/aggregate":
            qs = parse_qs(parsed.query)
            entry_ids_str = qs.get("entry_ids", [""])[0]
            if not entry_ids_str:
                self._send_json(400, {"error": "entry_ids query param required"})
                return
            try:
                entry_ids = [int(x.strip()) for x in entry_ids_str.split(",") if x.strip()]
            except ValueError:
                self._send_json(400, {"error": "entry_ids must be comma-separated integers"})
                return
            with _db_lock:
                placeholders = ",".join("?" * len(entry_ids))
                cursor = db.execute(f"""
                    SELECT runbook_entry_id,
                        SUM(CASE WHEN vote = 'up' THEN 1 ELSE 0 END) as up_votes,
                        SUM(CASE WHEN vote = 'down' THEN 1 ELSE 0 END) as down_votes,
                        SUM(CASE WHEN vote = 'up' THEN 1 WHEN vote = 'down' THEN -1 ELSE 0 END) as net_score,
                        COUNT(DISTINCT alert_fingerprint) as alert_count
                    FROM runbook_feedback
                    WHERE runbook_entry_id IN ({placeholders})
                    GROUP BY runbook_entry_id
                """, entry_ids)
                rows = {str(r["runbook_entry_id"]): dict(r) for r in cursor.fetchall()}
            self._send_json(200, rows)

        elif path == "/api/alert-states/runbook-feedback":
            qs = parse_qs(parsed.query)
            entry_ids_str = qs.get("entry_ids", [""])[0]
            fingerprint = qs.get("fingerprint", [""])[0]
            if not entry_ids_str:
                self._send_json(400, {"error": "entry_ids query param required"})
                return
            if not fingerprint:
                self._send_json(400, {"error": "fingerprint query param required"})
                return
            try:
                entry_ids = [int(x.strip()) for x in entry_ids_str.split(",") if x.strip()]
            except ValueError:
                self._send_json(400, {"error": "entry_ids must be comma-separated integers"})
                return
            with _db_lock:
                placeholders = ",".join("?" * len(entry_ids))
                cursor = db.execute(f"""
                    SELECT * FROM runbook_feedback
                    WHERE runbook_entry_id IN ({placeholders}) AND alert_fingerprint = ?
                    ORDER BY created_at DESC
                """, entry_ids + [fingerprint])
                rows = [dict(r) for r in cursor.fetchall()]
            self._send_json(200, rows)

        elif path == "/api/alert-states/sre-feedback/all":
            qs = parse_qs(parsed.query)
            page = int(qs.get("page", ["1"])[0])
            limit = min(int(qs.get("limit", ["50"])[0]), 200)
            search = qs.get("search", [""])[0].strip()
            rating_filter = qs.get("rating", [""])[0].strip()
            user_filter = qs.get("user", [""])[0].strip()
            sort = qs.get("sort", ["date"])[0].strip()
            offset = (page - 1) * limit

            conditions = []
            params = []
            if search:
                conditions.append("(f.alert_name LIKE ? OR f.comment LIKE ?)")
                params.extend([f"%{search}%", f"%{search}%"])
            if rating_filter:
                conditions.append("f.rating = ?")
                params.append(rating_filter)
            if user_filter:
                conditions.append("f.user = ?")
                params.append(user_filter)

            where = "WHERE " + " AND ".join(conditions) if conditions else ""
            order = "f.created_at DESC" if sort == "date" else "vote_score DESC"

            with _db_lock:
                count_row = db.execute(f"SELECT COUNT(*) as cnt FROM sre_feedback f {where}", params).fetchone()
                total = count_row["cnt"]
                cursor = db.execute(f"""
                    SELECT f.*,
                        COALESCE(SUM(CASE WHEN v.vote = 'up' THEN 1 WHEN v.vote = 'down' THEN -1 ELSE 0 END), 0) as vote_score
                    FROM sre_feedback f
                    LEFT JOIN sre_feedback_votes v ON v.feedback_id = f.id
                    {where}
                    GROUP BY f.id
                    ORDER BY {order}
                    LIMIT ? OFFSET ?
                """, params + [limit, offset])
                rows = [dict(r) for r in cursor.fetchall()]
            self._send_json(200, {"items": rows, "total": total, "page": page, "limit": limit})

        elif path == "/api/alert-states/sre-feedback/by-alert-name":
            qs = parse_qs(parsed.query)
            name = qs.get("name", [""])[0]
            if not name:
                self._send_json(400, {"error": "name query param required"})
                return
            with _db_lock:
                cursor = db.execute("""
                    SELECT f.*,
                        COALESCE(SUM(CASE WHEN v.vote = 'up' THEN 1 WHEN v.vote = 'down' THEN -1 ELSE 0 END), 0) as vote_score
                    FROM sre_feedback f
                    LEFT JOIN sre_feedback_votes v ON v.feedback_id = f.id
                    WHERE f.alert_name = ?
                    GROUP BY f.id
                    ORDER BY vote_score DESC, f.created_at DESC
                """, (name,))
                rows = [dict(r) for r in cursor.fetchall()]
            self._send_json(200, rows)

        elif path == "/api/alert-states/sre-feedback":
            qs = parse_qs(parsed.query)
            fingerprint = qs.get("fingerprint", [""])[0]
            if not fingerprint:
                self._send_json(400, {"error": "fingerprint query param required"})
                return
            username = _get_username_from_request(self)
            with _db_lock:
                cursor = db.execute("""
                    SELECT f.*,
                        COALESCE(SUM(CASE WHEN v.vote = 'up' THEN 1 WHEN v.vote = 'down' THEN -1 ELSE 0 END), 0) as vote_score
                    FROM sre_feedback f
                    LEFT JOIN sre_feedback_votes v ON v.feedback_id = f.id
                    WHERE f.alert_fingerprint = ?
                    GROUP BY f.id
                    ORDER BY f.created_at DESC
                """, (fingerprint,))
                rows = [dict(r) for r in cursor.fetchall()]
                # Add current user's vote to each entry
                if username:
                    for row in rows:
                        vote_row = db.execute(
                            "SELECT vote FROM sre_feedback_votes WHERE feedback_id = ? AND user = ?",
                            (row["id"], username)
                        ).fetchone()
                        row["user_vote"] = vote_row["vote"] if vote_row else None
                else:
                    for row in rows:
                        row["user_vote"] = None
            self._send_json(200, rows)

        elif path == "/api/alert-states/runbook-exclusions/all":
            qs = parse_qs(parsed.query)
            page = int(qs.get("page", ["1"])[0])
            limit = min(int(qs.get("limit", ["50"])[0]), 200)
            search = qs.get("search", [""])[0].strip()
            offset = (page - 1) * limit

            conditions = []
            params = []
            if search:
                conditions.append("alert_name LIKE ?")
                params.append(f"%{search}%")
            where = "WHERE " + " AND ".join(conditions) if conditions else ""

            with _db_lock:
                count_row = db.execute(f"SELECT COUNT(*) as cnt FROM runbook_exclusions {where}", params).fetchone()
                total = count_row["cnt"]
                cursor = db.execute(f"""
                    SELECT * FROM runbook_exclusions {where} ORDER BY created_at DESC LIMIT ? OFFSET ?
                """, params + [limit, offset])
                rows = [dict(r) for r in cursor.fetchall()]
            self._send_json(200, {"items": rows, "total": total, "page": page, "limit": limit})

        elif path == "/api/alert-states/runbook-exclusions":
            qs = parse_qs(parsed.query)
            alert_name = qs.get("alert_name", [""])[0]
            if not alert_name:
                self._send_json(400, {"error": "alert_name query param required"})
                return
            with _db_lock:
                cursor = db.execute("""
                    SELECT * FROM runbook_exclusions WHERE alert_name = ? ORDER BY created_at DESC
                """, (alert_name,))
                rows = [dict(r) for r in cursor.fetchall()]
            self._send_json(200, rows)

        elif path == "/api/alert-states/events":
            # SSE stream endpoint
            with _sse_lock:
                if len(_sse_clients) >= _SSE_MAX_CLIENTS:
                    self._send_json(503, {"error": "too many SSE connections"})
                    return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            # Register client and replay missed events atomically to avoid gaps
            last_id_str = self.headers.get("Last-Event-ID", "")
            with _sse_lock:
                _sse_clients.add(self.wfile)
                if last_id_str:
                    try:
                        last_id = int(last_id_str)
                        found = False
                        for eid, msg in _sse_ring_buffer:
                            if eid == last_id:
                                found = True
                                continue
                            if found:
                                self.wfile.write(msg.encode())
                        if not found and _sse_ring_buffer:
                            reset_msg = f"id: {_sse_ring_buffer[-1][0]}\nevent: reset\ndata: {{}}\n\n"
                            self.wfile.write(reset_msg.encode())
                    except (ValueError, TypeError):
                        pass
            self.wfile.flush()
            log.info(f"SSE client connected ({len(_sse_clients)} total)")
            try:
                while True:
                    time.sleep(30)
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except Exception:
                        break
            finally:
                with _sse_lock:
                    _sse_clients.discard(self.wfile)
                log.info(f"SSE client disconnected ({len(_sse_clients)} remaining)")

        elif path == "/api/alert-states/sse-status":
            with _sse_lock:
                count = len(_sse_clients)
            self._send_json(200, {"connected_clients": count})

        elif path == "/api/alert-states/silence-rules":
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                # Auto-expire old rules
                db.execute("UPDATE silence_rules SET active = 0 WHERE active = 1 AND expires_at < ?", (now,))
                db.commit()
                cursor = db.execute("""
                    SELECT * FROM silence_rules WHERE active = 1 ORDER BY created_at DESC
                """)
                rows = [dict(r) for r in cursor.fetchall()]
            self._send_json(200, rows)

        elif path == "/api/alert-states/situation-summary":
            with _db_lock:
                cursor = db.execute("SELECT * FROM situation_summary WHERE id = 1")
                row = cursor.fetchone()
            if row:
                self._send_json(200, {
                    "one_liner": row["one_liner"],
                    "clusters": json.loads(row["clusters_json"] or "[]"),
                    "shift_context": json.loads(row["shift_context_json"] or "{}"),
                    "recommended_actions": json.loads(row["actions_json"] or "[]"),
                    "suggested_merges": json.loads(row["suggested_merges_json"] or "[]"),
                    "generated_at": row["generated_at"],
                    "alert_hash": row["alert_hash"],
                })
            else:
                self._send_json(200, {"one_liner": None})

        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/alert-states/investigate":
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
            with _db_lock:
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
                    _sse_broadcast("investigate", {"fingerprint": fingerprint, "user": username, "active": False})
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
                    _sse_broadcast("investigate", {"fingerprint": fingerprint, "user": username, "active": True})
                    self._send_json(200, {"status": "investigating", "investigating_user": username})

        elif path == "/api/alert-states/acknowledge":
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
            with _db_lock:
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
            _sse_broadcast("acknowledge", {"fingerprints": fingerprints, "user": username})
            log.info(f"{username} acknowledged {len(fingerprints)} alert(s)")
            self._send_json(200, {"status": "acknowledged", "count": len(fingerprints)})

        elif path == "/api/alert-states/unacknowledge":
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
            with _db_lock:
                for fp in fingerprints:
                    db.execute("""
                        UPDATE alert_states SET
                            acknowledged_by = NULL, acknowledged_at = NULL,
                            ack_firing_start = NULL, is_updated = 0, updated_at = datetime('now')
                        WHERE alert_fingerprint = ?
                    """, (fp,))
                db.commit()
            _sse_broadcast("unacknowledge", {"fingerprints": fingerprints})
            self._send_json(200, {"status": "unacknowledged", "count": len(fingerprints)})

        elif path == "/api/alert-states/mark-updated":
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
            with _db_lock:
                for fp in fingerprints:
                    db.execute("""
                        UPDATE alert_states SET
                            acknowledged_by = NULL, acknowledged_at = NULL,
                            investigating_user = NULL, investigating_since = NULL,
                            is_updated = 1, updated_detected_at = ?,
                            incident_jira_key = NULL, incident_jira_url = NULL,
                            incident_created_by = NULL, incident_created_at = NULL,
                            escalated_to = NULL, escalated_by = NULL, escalated_at = NULL,
                            severity_override = NULL, severity_override_by = NULL, severity_override_at = NULL,
                            updated_at = datetime('now')
                        WHERE alert_fingerprint = ?
                    """, (now, fp))
                db.commit()
            _sse_broadcast("mark_updated", {"fingerprints": fingerprints})
            if fingerprints:
                log.info(f"Marked {len(fingerprints)} alert(s) as updated (re-fired)")
            self._send_json(200, {"status": "marked_updated", "count": len(fingerprints)})

        elif path == "/api/alert-states/force-enrich":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            fingerprint = (data.get("fingerprint") or "").strip()
            if not fingerprint:
                self._send_json(400, {"error": "fingerprint is required"})
                return
            with _db_lock:
                db.execute("""
                    INSERT INTO alert_states (alert_fingerprint, force_enrich)
                    VALUES (?, 1)
                    ON CONFLICT(alert_fingerprint) DO UPDATE SET
                        force_enrich = 1, updated_at = datetime('now')
                """, (fingerprint,))
                db.commit()
            _sse_broadcast("force_enrich", {"fingerprint": fingerprint})
            log.info(f"Force-enrich queued for {fingerprint[:16]}")
            self._send_json(200, {"status": "queued"})

        elif path == "/api/alert-states/clear-force-enrich":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            fingerprint = (data.get("fingerprint") or "").strip()
            if not fingerprint:
                self._send_json(400, {"error": "fingerprint is required"})
                return
            with _db_lock:
                db.execute("""
                    UPDATE alert_states SET force_enrich = 0, updated_at = datetime('now')
                    WHERE alert_fingerprint = ?
                """, (fingerprint,))
                db.commit()
            self._send_json(200, {"status": "cleared"})

        elif path == "/api/alert-states/incident":
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
            jira_key = (data.get("jira_key") or "").strip()
            jira_url = (data.get("jira_url") or "").strip()
            if not fingerprint or not jira_key:
                self._send_json(400, {"error": "fingerprint and jira_key are required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                db.execute("""
                    INSERT INTO alert_states (alert_fingerprint, incident_jira_key, incident_jira_url,
                        incident_created_by, incident_created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(alert_fingerprint) DO UPDATE SET
                        incident_jira_key = excluded.incident_jira_key,
                        incident_jira_url = excluded.incident_jira_url,
                        incident_created_by = excluded.incident_created_by,
                        incident_created_at = excluded.incident_created_at,
                        updated_at = datetime('now')
                """, (fingerprint, jira_key, jira_url, username, now))
                db.commit()
            _sse_broadcast("incident_created", {
                "fingerprint": fingerprint, "user": username,
                "jira_key": jira_key, "jira_url": jira_url,
            })
            log.info(f"{username} created incident {jira_key} for {fingerprint[:16]}")
            self._send_json(200, {"status": "stored", "jira_key": jira_key})

        elif path == "/api/alert-states/escalation":
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
            escalated_to = (data.get("escalated_to") or "").strip()
            if not fingerprint or not escalated_to:
                self._send_json(400, {"error": "fingerprint and escalated_to are required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                db.execute("""
                    INSERT INTO alert_states (alert_fingerprint, escalated_to, escalated_by, escalated_at, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(alert_fingerprint) DO UPDATE SET
                        escalated_to = excluded.escalated_to,
                        escalated_by = excluded.escalated_by,
                        escalated_at = excluded.escalated_at,
                        updated_at = datetime('now')
                """, (fingerprint, escalated_to, username, now))
                db.commit()
            _sse_broadcast("escalated", {
                "fingerprint": fingerprint, "user": username, "escalated_to": escalated_to,
            })
            log.info(f"{username} escalated {fingerprint[:16]} to {escalated_to}")
            self._send_json(200, {"status": "stored", "escalated_to": escalated_to})

        elif path == "/api/alert-states/runbook-feedback":
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
            alert_name = (data.get("alert_name") or "").strip()
            entry_id = data.get("entry_id")
            vote = (data.get("vote") or "").strip()
            if not fingerprint or not entry_id or vote not in ("up", "down", "none"):
                self._send_json(400, {"error": "fingerprint, entry_id, and vote (up/down/none) required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                if vote == "none":
                    db.execute("""
                        DELETE FROM runbook_feedback
                        WHERE alert_fingerprint = ? AND runbook_entry_id = ? AND user = ?
                    """, (fingerprint, entry_id, username))
                else:
                    db.execute("""
                        INSERT INTO runbook_feedback (alert_fingerprint, alert_name, runbook_entry_id, vote, user, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(alert_fingerprint, runbook_entry_id, user) DO UPDATE SET
                            vote = excluded.vote, created_at = excluded.created_at
                    """, (fingerprint, alert_name, entry_id, vote, username, now))
                db.commit()
            _sse_broadcast("runbook_feedback", {
                "fingerprint": fingerprint, "entry_id": entry_id,
                "vote": vote, "user": username,
            })
            self._send_json(200, {"status": "stored", "vote": vote})

        elif path == "/api/alert-states/sre-feedback/update":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            feedback_id = data.get("id")
            if not feedback_id:
                self._send_json(400, {"error": "id is required"})
                return
            with _db_lock:
                row = db.execute("SELECT user FROM sre_feedback WHERE id = ?", (feedback_id,)).fetchone()
                if not row:
                    self._send_json(404, {"error": "feedback not found"})
                    return
                if row["user"] != username:
                    self._send_json(403, {"error": "only the original author can edit"})
                    return
                updates = []
                params = []
                for field in ["rating", "corrected_severity", "comment"]:
                    if field in data:
                        val = (data[field] or "").strip() or None
                        if field == "comment" and val and len(val) > 2000:
                            val = val[:2000]
                        updates.append(f"{field} = ?")
                        params.append(val)
                if "corrected_noise" in data:
                    updates.append("corrected_noise = ?")
                    params.append(data["corrected_noise"])
                if not updates:
                    self._send_json(400, {"error": "no fields to update"})
                    return
                updates.append("updated_at = datetime('now')")
                params.append(feedback_id)
                db.execute(f"UPDATE sre_feedback SET {', '.join(updates)} WHERE id = ?", params)
                db.commit()
            _sse_broadcast("sre_feedback_updated", {"id": feedback_id, "user": username})
            self._send_json(200, {"status": "updated"})

        elif path == "/api/alert-states/sre-feedback/delete":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            feedback_id = data.get("id")
            if not feedback_id:
                self._send_json(400, {"error": "id is required"})
                return
            with _db_lock:
                row = db.execute("SELECT id FROM sre_feedback WHERE id = ?", (feedback_id,)).fetchone()
                if not row:
                    self._send_json(404, {"error": "feedback not found"})
                    return
                db.execute("DELETE FROM sre_feedback WHERE id = ?", (feedback_id,))
                db.commit()
            _sse_broadcast("sre_feedback_deleted", {"id": feedback_id, "user": username})
            log.info(f"{username} deleted feedback #{feedback_id}")
            self._send_json(200, {"status": "deleted"})

        elif path == "/api/alert-states/sre-feedback/vote":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            feedback_id = data.get("id")
            vote = (data.get("vote") or "").strip()
            if not feedback_id or vote not in ("up", "down", "none"):
                self._send_json(400, {"error": "id and vote (up/down/none) required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                if vote == "none":
                    db.execute("DELETE FROM sre_feedback_votes WHERE feedback_id = ? AND user = ?",
                               (feedback_id, username))
                else:
                    db.execute("""
                        INSERT INTO sre_feedback_votes (feedback_id, user, vote, created_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(feedback_id, user) DO UPDATE SET vote = excluded.vote, created_at = excluded.created_at
                    """, (feedback_id, username, vote, now))
                db.commit()
            _sse_broadcast("sre_feedback_vote", {"feedback_id": feedback_id, "vote": vote, "user": username})
            self._send_json(200, {"status": "stored", "vote": vote})

        elif path == "/api/alert-states/sre-feedback/bulk-delete":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            ids = data.get("ids") or []
            if not ids:
                self._send_json(400, {"error": "ids list is required"})
                return
            with _db_lock:
                placeholders = ",".join("?" * len(ids))
                db.execute(f"DELETE FROM sre_feedback WHERE id IN ({placeholders})", ids)
                db.commit()
            _sse_broadcast("sre_feedback_bulk_deleted", {"ids": ids, "user": username})
            log.info(f"{username} bulk-deleted {len(ids)} feedback entries")
            self._send_json(200, {"status": "deleted", "count": len(ids)})

        elif path == "/api/alert-states/sre-feedback":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            # Auth: cookie-based for SREs, or body-provided user for internal services
            username = _get_username_from_request(self)
            if not username:
                username = (data.get("user") or "").strip()
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            fingerprint = (data.get("fingerprint") or "").strip()
            alert_name = (data.get("alert_name") or "").strip()
            rating = (data.get("rating") or "").strip()
            if not fingerprint or not alert_name:
                self._send_json(400, {"error": "fingerprint and alert_name are required"})
                return
            if rating and rating not in ("positive", "negative", "correction"):
                self._send_json(400, {"error": "rating must be positive, negative, or correction"})
                return
            corrected_severity = (data.get("corrected_severity") or "").strip() or None
            corrected_noise = data.get("corrected_noise")
            comment = (data.get("comment") or "").strip() or None
            if comment and len(comment) > 2000:
                comment = comment[:2000]
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                cursor = db.execute("""
                    INSERT INTO sre_feedback (alert_fingerprint, alert_name, rating, corrected_severity,
                        corrected_noise, comment, user, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (fingerprint, alert_name, rating or None, corrected_severity,
                      corrected_noise, comment, username, now, now))
                feedback_id = cursor.lastrowid
                db.commit()
            _sse_broadcast("sre_feedback", {"fingerprint": fingerprint, "user": username, "id": feedback_id})
            log.info(f"{username} submitted feedback #{feedback_id} for {fingerprint[:16]}")
            self._send_json(200, {"status": "created", "id": feedback_id})

        elif path == "/api/alert-states/runbook-exclusions/delete":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            exclusion_id = data.get("id")
            if not exclusion_id:
                self._send_json(400, {"error": "id is required"})
                return
            with _db_lock:
                row = db.execute("SELECT id FROM runbook_exclusions WHERE id = ?", (exclusion_id,)).fetchone()
                if not row:
                    self._send_json(404, {"error": "exclusion not found"})
                    return
                db.execute("DELETE FROM runbook_exclusions WHERE id = ?", (exclusion_id,))
                db.commit()
            _sse_broadcast("runbook_exclusion_removed", {"id": exclusion_id, "user": username})
            log.info(f"{username} removed runbook exclusion #{exclusion_id}")
            self._send_json(200, {"status": "deleted"})

        elif path == "/api/alert-states/runbook-exclusions":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            alert_name = (data.get("alert_name") or "").strip()
            entry_id = data.get("runbook_entry_id")
            if not alert_name or not entry_id:
                self._send_json(400, {"error": "alert_name and runbook_entry_id are required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                try:
                    cursor = db.execute("""
                        INSERT INTO runbook_exclusions (alert_name, runbook_entry_id, excluded_by, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (alert_name, entry_id, username, now))
                    exclusion_id = cursor.lastrowid
                    db.commit()
                except sqlite3.IntegrityError:
                    self._send_json(409, {"error": "exclusion already exists"})
                    return
            _sse_broadcast("runbook_exclusion", {"alert_name": alert_name, "entry_id": entry_id, "user": username})
            log.info(f"{username} excluded runbook entry #{entry_id} from '{alert_name}'")
            self._send_json(200, {"status": "created", "id": exclusion_id})

        elif path == "/api/alert-states/severity-override":
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
            severity = (data.get("severity") or "").strip()
            if not fingerprint or severity not in ("critical", "high", "warning", "info", "none"):
                self._send_json(400, {"error": "fingerprint and severity (critical/high/warning/info/none) required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                if severity == "none":
                    db.execute("""
                        UPDATE alert_states SET severity_override = NULL,
                            severity_override_by = NULL, severity_override_at = NULL,
                            updated_at = datetime('now')
                        WHERE alert_fingerprint = ?
                    """, (fingerprint,))
                else:
                    db.execute("""
                        INSERT INTO alert_states (alert_fingerprint, severity_override, severity_override_by,
                            severity_override_at, updated_at)
                        VALUES (?, ?, ?, ?, datetime('now'))
                        ON CONFLICT(alert_fingerprint) DO UPDATE SET
                            severity_override = excluded.severity_override,
                            severity_override_by = excluded.severity_override_by,
                            severity_override_at = excluded.severity_override_at,
                            updated_at = datetime('now')
                    """, (fingerprint, severity, username, now))
                db.commit()
            _sse_broadcast("severity_override", {
                "fingerprint": fingerprint, "severity": severity,
                "user": username,
            })
            log.info(f"{username} overrode severity to {severity} for {fingerprint[:16]}")
            self._send_json(200, {"status": "stored", "severity": severity})

        elif path == "/api/alert-states/silence-rules":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            alert_name_pattern = (data.get("alert_name_pattern") or "").strip()
            hostname_pattern = (data.get("hostname_pattern") or "").strip() or None
            duration_seconds = data.get("duration_seconds", 3600)
            reason = (data.get("reason") or "").strip()
            if not alert_name_pattern:
                self._send_json(400, {"error": "alert_name_pattern is required"})
                return
            now = datetime.now(timezone.utc)
            from datetime import timedelta
            expires_at = (now + timedelta(seconds=int(duration_seconds))).isoformat()
            now_str = now.isoformat()
            with _db_lock:
                cursor = db.execute("""
                    INSERT INTO silence_rules (alert_name_pattern, hostname_pattern, created_by,
                        created_at, expires_at, reason, active)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                """, (alert_name_pattern, hostname_pattern, username, now_str, expires_at, reason))
                rule_id = cursor.lastrowid
                db.commit()
            _sse_broadcast("silence_created", {
                "rule_id": rule_id, "alert_name_pattern": alert_name_pattern,
                "hostname_pattern": hostname_pattern, "user": username,
                "expires_at": expires_at,
            })
            log.info(f"{username} created silence rule #{rule_id}: '{alert_name_pattern}' host='{hostname_pattern}' until {expires_at}")
            self._send_json(200, {"status": "created", "id": rule_id, "expires_at": expires_at})

        elif path == "/api/alert-states/silence-rules/cancel":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            rule_id = data.get("id")
            if not rule_id:
                self._send_json(400, {"error": "id is required"})
                return
            with _db_lock:
                db.execute("UPDATE silence_rules SET active = 0 WHERE id = ?", (rule_id,))
                db.commit()
            _sse_broadcast("silence_cancelled", {"rule_id": rule_id, "user": username})
            log.info(f"{username} cancelled silence rule #{rule_id}")
            self._send_json(200, {"status": "cancelled", "id": rule_id})

        elif path == "/api/alert-states/invalidate-summary":
            with _db_lock:
                db.execute("UPDATE situation_summary SET alert_hash = '' WHERE id = 1")
                db.commit()
            self._send_json(200, {"status": "invalidated"})

        elif path == "/api/alert-states/situation-summary":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            one_liner = (data.get("one_liner") or "").strip()
            clusters = data.get("clusters", [])
            shift_context = data.get("shift_context", {})
            actions = data.get("recommended_actions", [])
            suggested_merges = data.get("suggested_merges", [])
            alert_hash = (data.get("alert_hash") or "").strip()
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                db.execute("""
                    INSERT INTO situation_summary (id, one_liner, clusters_json, shift_context_json,
                        actions_json, suggested_merges_json, generated_at, alert_hash)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        one_liner = excluded.one_liner,
                        clusters_json = excluded.clusters_json,
                        shift_context_json = excluded.shift_context_json,
                        actions_json = excluded.actions_json,
                        suggested_merges_json = excluded.suggested_merges_json,
                        generated_at = excluded.generated_at,
                        alert_hash = excluded.alert_hash
                """, (one_liner, json.dumps(clusters), json.dumps(shift_context),
                      json.dumps(actions), json.dumps(suggested_merges), now, alert_hash))
                db.commit()
            _sse_broadcast("situation_update", {"generated_at": now})
            self._send_json(200, {"status": "stored"})

        else:
            self._send_json(404, {"error": "not found"})


# ── Main ───────────────────────────────────────────────

if not AUTH_SECRET:
    log.warning("AUTH_SECRET is not set — tokens will use an empty secret")

db = _init_db()

server = ThreadingHTTPServer(("0.0.0.0", API_PORT), AlertStateHandler)
log.info(f"alert-state-api listening on port {API_PORT}")
server.serve_forever()
