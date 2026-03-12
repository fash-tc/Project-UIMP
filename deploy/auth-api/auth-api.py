"""auth-api: User authentication and management service for UIP."""

import json
import os
import logging
import sqlite3
import base64
import hashlib
import hmac as hmac_mod
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("auth-api")

API_PORT = int(os.environ.get("API_PORT", "8093"))
DB_PATH = os.environ.get("DB_PATH", "/data/auth.db")
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")

_db_lock = threading.Lock()


# ── Database ───────────────────────────────────────────

def _init_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            display_name TEXT,
            jira_email TEXT DEFAULT '',
            jira_api_token TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    db.commit()
    _seed_users(db)
    log.info(f"Database initialized at {DB_PATH}")
    return db


# ── Authentication ─────────────────────────────────────

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


# ── HTTP Handler ───────────────────────────────────────

class AuthHandler(BaseHTTPRequestHandler):

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

        if path == "/api/auth/me":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "Not authenticated"})
                return
            with _db_lock:
                row = db.execute(
                    "SELECT username, display_name, jira_email, jira_api_token, created_at FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
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

        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/auth/login":
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
            with _db_lock:
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
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Set-Cookie", f"uip_auth={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
            self.send_header("Set-Cookie", f"uip_user={username}; Path=/; SameSite=Lax; Max-Age=86400")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            log.info(f"User logged in: {username}")

        elif path == "/api/auth/logout":
            resp_body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Set-Cookie", "uip_auth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            self.send_header("Set-Cookie", "uip_user=; Path=/; SameSite=Lax; Max-Age=0")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

        elif path == "/api/auth/change-password":
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
            with _db_lock:
                row = db.execute(
                    "SELECT password_hash, password_salt FROM users WHERE username = ?", (username,)
                ).fetchone()
                if not row or not _verify_password(current_pw, row["password_hash"], row["password_salt"]):
                    self._send_json(401, {"error": "Current password is incorrect"})
                    return
                pw_hash, pw_salt = _hash_password(new_pw)
                db.execute(
                    "UPDATE users SET password_hash = ?, password_salt = ?, updated_at = datetime('now') WHERE username = ?",
                    (pw_hash, pw_salt, username),
                )
                db.commit()
            log.info(f"Password changed for user: {username}")
            self._send_json(200, {"ok": True})

        elif path == "/api/auth/jira-config":
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
            with _db_lock:
                db.execute(
                    "UPDATE users SET jira_email = ?, jira_api_token = ?, updated_at = datetime('now') WHERE username = ?",
                    (jira_email, jira_token, username),
                )
                db.commit()
            log.info(f"Jira config updated for user: {username}")
            self._send_json(200, {"ok": True, "has_jira_token": bool(jira_token)})

        else:
            self._send_json(404, {"error": "not found"})


# ── Main ───────────────────────────────────────────────

if not AUTH_SECRET:
    log.warning("AUTH_SECRET is not set — tokens will use an empty secret")

db = _init_db()

server = HTTPServer(("0.0.0.0", API_PORT), AuthHandler)
log.info(f"auth-api listening on port {API_PORT}")
server.serve_forever()
