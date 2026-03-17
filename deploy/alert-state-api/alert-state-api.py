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
    global _sse_event_counter
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
    # Add force_enrich column if it doesn't exist (migration)
    try:
        db.execute("ALTER TABLE alert_states ADD COLUMN force_enrich INTEGER DEFAULT 0")
        db.commit()
        log.info("Added force_enrich column to alert_states")
    except sqlite3.OperationalError:
        pass  # Column already exists
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
                        ORDER BY updated_at DESC
                    """)
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
                            is_updated = 1, updated_detected_at = ?,
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

        else:
            self._send_json(404, {"error": "not found"})


# ── Main ───────────────────────────────────────────────

if not AUTH_SECRET:
    log.warning("AUTH_SECRET is not set — tokens will use an empty secret")

db = _init_db()

server = ThreadingHTTPServer(("0.0.0.0", API_PORT), AlertStateHandler)
log.info(f"alert-state-api listening on port {API_PORT}")
server.serve_forever()
