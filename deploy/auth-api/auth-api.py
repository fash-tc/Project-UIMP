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
from urllib.parse import urlparse, parse_qs, urlencode, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("auth-api")

API_PORT = int(os.environ.get("API_PORT", "8093"))
DB_PATH = os.environ.get("DB_PATH", "/data/auth.db")
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")

# ── Atlassian OAuth 2.0 (3LO) ────────────────────────
JIRA_OAUTH_CLIENT_ID = os.environ.get("JIRA_OAUTH_CLIENT_ID", "")
JIRA_OAUTH_CLIENT_SECRET = os.environ.get("JIRA_OAUTH_CLIENT_SECRET", "")
JIRA_OAUTH_REDIRECT_URI = os.environ.get("JIRA_OAUTH_REDIRECT_URI", "")
# Scopes needed: create issues, attach files, read project metadata
JIRA_OAUTH_SCOPES = "write:jira-work read:jira-work read:me offline_access"

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

    # Add OAuth columns if they don't exist
    for col, coldef in [
        ("jira_oauth_access_token", "TEXT DEFAULT ''"),
        ("jira_oauth_refresh_token", "TEXT DEFAULT ''"),
        ("jira_oauth_expires_at", "INTEGER DEFAULT 0"),
        ("jira_oauth_cloud_id", "TEXT DEFAULT ''"),
        ("jira_oauth_email", "TEXT DEFAULT ''"),
    ]:
        try:
            db.execute(f"ALTER TABLE users ADD COLUMN {col} {coldef}")
            log.info(f"Added column: {col}")
        except sqlite3.OperationalError:
            pass  # column already exists

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


# ── Atlassian OAuth Helpers ───────────────────────────

def _create_oauth_state(username):
    """Create a signed state parameter that includes the username."""
    payload = {"u": username, "e": int(time.time()) + 600}  # 10 minute TTL
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac_mod.new(AUTH_SECRET.encode(), ("oauth:" + payload_b64).encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload_b64}.{sig}"


def _verify_oauth_state(state):
    """Verify the OAuth state parameter and return the username."""
    try:
        parts = state.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        expected = hmac_mod.new(AUTH_SECRET.encode(), ("oauth:" + payload_b64).encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac_mod.compare_digest(sig, expected):
            return None
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if payload.get("e", 0) < time.time():
            return None
        return payload.get("u")
    except Exception:
        return None


def _exchange_oauth_code(code):
    """Exchange authorization code for access + refresh tokens."""
    payload = json.dumps({
        "grant_type": "authorization_code",
        "client_id": JIRA_OAUTH_CLIENT_ID,
        "client_secret": JIRA_OAUTH_CLIENT_SECRET,
        "code": code,
        "redirect_uri": JIRA_OAUTH_REDIRECT_URI,
    }).encode()
    req = Request(
        "https://auth.atlassian.com/oauth/token",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urlopen(req, timeout=15)
        return json.loads(resp.read()), None
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log.error(f"OAuth token exchange failed ({e.code}): {body[:300]}")
        return None, f"Token exchange failed: {body[:200]}"
    except Exception as e:
        log.error(f"OAuth token exchange error: {e}")
        return None, str(e)


def _refresh_oauth_token(refresh_token):
    """Refresh an expired access token."""
    payload = json.dumps({
        "grant_type": "refresh_token",
        "client_id": JIRA_OAUTH_CLIENT_ID,
        "client_secret": JIRA_OAUTH_CLIENT_SECRET,
        "refresh_token": refresh_token,
    }).encode()
    req = Request(
        "https://auth.atlassian.com/oauth/token",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urlopen(req, timeout=15)
        return json.loads(resp.read()), None
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log.error(f"OAuth refresh failed ({e.code}): {body[:300]}")
        return None, f"Token refresh failed: {body[:200]}"
    except Exception as e:
        log.error(f"OAuth refresh error: {e}")
        return None, str(e)


def _fetch_atlassian_me(access_token):
    """Get the user's Atlassian profile (email, account_id)."""
    req = Request(
        "https://api.atlassian.com/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    try:
        resp = urlopen(req, timeout=10)
        return json.loads(resp.read()), None
    except Exception as e:
        return None, str(e)


def _fetch_accessible_resources(access_token):
    """Get the user's accessible Atlassian cloud sites to find the cloud ID."""
    req = Request(
        "https://api.atlassian.com/oauth/token/accessible-resources",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
    )
    try:
        resp = urlopen(req, timeout=10)
        sites = json.loads(resp.read())
        return sites, None
    except Exception as e:
        return None, str(e)


def _get_valid_oauth_token(username):
    """Get a valid OAuth access token for a user, refreshing if needed.
    Returns (access_token, cloud_id, error)."""
    with _db_lock:
        row = db.execute(
            "SELECT jira_oauth_access_token, jira_oauth_refresh_token, jira_oauth_expires_at, jira_oauth_cloud_id "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if not row or not row["jira_oauth_refresh_token"]:
        return None, None, "No Jira OAuth connection"

    access_token = row["jira_oauth_access_token"]
    refresh_token = row["jira_oauth_refresh_token"]
    expires_at = row["jira_oauth_expires_at"] or 0
    cloud_id = row["jira_oauth_cloud_id"] or ""

    # Refresh if token expires within 60 seconds
    if time.time() > (expires_at - 60):
        log.info(f"Refreshing OAuth token for {username}")
        token_data, err = _refresh_oauth_token(refresh_token)
        if err:
            return None, None, err
        access_token = token_data["access_token"]
        new_refresh = token_data.get("refresh_token", refresh_token)
        new_expires = int(time.time()) + token_data.get("expires_in", 3600)
        with _db_lock:
            db.execute(
                "UPDATE users SET jira_oauth_access_token = ?, jira_oauth_refresh_token = ?, "
                "jira_oauth_expires_at = ?, updated_at = datetime('now') WHERE username = ?",
                (access_token, new_refresh, new_expires, username),
            )
            db.commit()
        log.info(f"OAuth token refreshed for {username}")

    return access_token, cloud_id, None


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

    def _send_redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

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
        qs = parse_qs(parsed.query)

        if path == "/api/auth/me":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "Not authenticated"})
                return
            with _db_lock:
                row = db.execute(
                    "SELECT username, display_name, jira_email, jira_api_token, "
                    "jira_oauth_access_token, jira_oauth_refresh_token, jira_oauth_email, jira_oauth_cloud_id, "
                    "created_at FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
            if not row:
                self._send_json(401, {"error": "User not found"})
                return
            has_oauth = bool(row["jira_oauth_refresh_token"])
            self._send_json(200, {
                "username": row["username"],
                "display_name": row["display_name"],
                "jira_email": row["jira_oauth_email"] or row["jira_email"] or "",
                "has_jira_token": has_oauth or bool(row["jira_api_token"]),
                "jira_connected": has_oauth,
                "jira_oauth_email": row["jira_oauth_email"] or "",
                "created_at": row["created_at"],
            })

        # ── OAuth: Start authorization flow ───────────
        elif path == "/api/auth/jira/connect":
            username = _get_username_from_request(self)
            if not username:
                self._send_redirect("/login?error=auth_required")
                return
            if not JIRA_OAUTH_CLIENT_ID:
                self._send_json(500, {"error": "Jira OAuth not configured on the server"})
                return

            state = _create_oauth_state(username)
            params = urlencode({
                "audience": "api.atlassian.com",
                "client_id": JIRA_OAUTH_CLIENT_ID,
                "scope": JIRA_OAUTH_SCOPES,
                "redirect_uri": JIRA_OAUTH_REDIRECT_URI,
                "state": state,
                "response_type": "code",
                "prompt": "consent",
            })
            self._send_redirect(f"https://auth.atlassian.com/authorize?{params}")

        # ── OAuth: Handle callback ────────────────────
        elif path == "/api/auth/jira/callback":
            error = (qs.get("error") or [None])[0]
            if error:
                log.warning(f"OAuth callback error: {error}")
                self._send_redirect(f"/settings?jira_error={quote(error)}")
                return

            code = (qs.get("code") or [None])[0]
            state = (qs.get("state") or [None])[0]
            if not code or not state:
                self._send_redirect("/settings?jira_error=missing_params")
                return

            username = _verify_oauth_state(state)
            if not username:
                self._send_redirect("/settings?jira_error=invalid_state")
                return

            # Exchange code for tokens
            token_data, err = _exchange_oauth_code(code)
            if err:
                log.error(f"OAuth exchange failed for {username}: {err}")
                self._send_redirect(f"/settings?jira_error={quote('token_exchange_failed')}")
                return

            access_token = token_data.get("access_token", "")
            refresh_token = token_data.get("refresh_token", "")
            expires_in = token_data.get("expires_in", 3600)
            expires_at = int(time.time()) + expires_in

            # Fetch user profile
            me_data, _ = _fetch_atlassian_me(access_token)
            oauth_email = (me_data or {}).get("email", "")

            # Fetch accessible resources to get cloud ID
            cloud_id = ""
            sites, _ = _fetch_accessible_resources(access_token)
            if sites and len(sites) > 0:
                # Prefer the Tucows site, otherwise take the first
                for site in sites:
                    if "tucows" in (site.get("name", "") + site.get("url", "")).lower():
                        cloud_id = site.get("id", "")
                        break
                if not cloud_id:
                    cloud_id = sites[0].get("id", "")

            # Store tokens
            with _db_lock:
                db.execute(
                    "UPDATE users SET jira_oauth_access_token = ?, jira_oauth_refresh_token = ?, "
                    "jira_oauth_expires_at = ?, jira_oauth_cloud_id = ?, jira_oauth_email = ?, "
                    "updated_at = datetime('now') WHERE username = ?",
                    (access_token, refresh_token, expires_at, cloud_id, oauth_email, username),
                )
                db.commit()

            log.info(f"Jira OAuth connected for {username} (email={oauth_email}, cloud_id={cloud_id[:8]}...)")
            self._send_redirect("/settings?jira_connected=true")

        # ── Internal API: Get user's OAuth token (called by runbook-api) ──
        elif path == "/api/auth/jira-token":
            # Internal endpoint — get a valid access token for a user
            target_user = (qs.get("username") or [None])[0]
            if not target_user:
                self._send_json(400, {"error": "username required"})
                return
            access_token, cloud_id, err = _get_valid_oauth_token(target_user)
            if err:
                self._send_json(404, {"error": err})
                return
            self._send_json(200, {
                "access_token": access_token,
                "cloud_id": cloud_id,
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
            # Legacy API token config — kept for backward compatibility
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

        elif path == "/api/auth/jira/disconnect":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "Not authenticated"})
                return
            with _db_lock:
                db.execute(
                    "UPDATE users SET jira_oauth_access_token = '', jira_oauth_refresh_token = '', "
                    "jira_oauth_expires_at = 0, jira_oauth_cloud_id = '', jira_oauth_email = '', "
                    "updated_at = datetime('now') WHERE username = ?",
                    (username,),
                )
                db.commit()
            log.info(f"Jira OAuth disconnected for {username}")
            self._send_json(200, {"ok": True})

        else:
            self._send_json(404, {"error": "not found"})


# ── Main ───────────────────────────────────────────────

if not AUTH_SECRET:
    log.warning("AUTH_SECRET is not set — tokens will use an empty secret")

if JIRA_OAUTH_CLIENT_ID:
    log.info(f"Jira OAuth configured (client_id={JIRA_OAUTH_CLIENT_ID[:8]}..., redirect={JIRA_OAUTH_REDIRECT_URI})")
else:
    log.warning("JIRA_OAUTH_CLIENT_ID not set — Jira OAuth disabled, falling back to API token auth")

db = _init_db()

server = HTTPServer(("0.0.0.0", API_PORT), AuthHandler)
log.info(f"auth-api listening on port {API_PORT}")
server.serve_forever()
