"""auth-api: User authentication and management service for UIP."""

import json
import os
import logging
import re
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
SHARED_INTEGRATIONS_SECRET = os.environ.get("SHARED_INTEGRATIONS_SECRET", "") or AUTH_SECRET
MAINTENANCE_API_BASE = os.environ.get("MAINTENANCE_API_BASE", "http://maintenance-api:8000")

# ── Atlassian OAuth 2.0 (3LO) ────────────────────────
JIRA_OAUTH_CLIENT_ID = os.environ.get("JIRA_OAUTH_CLIENT_ID", "")
JIRA_OAUTH_CLIENT_SECRET = os.environ.get("JIRA_OAUTH_CLIENT_SECRET", "")
JIRA_OAUTH_REDIRECT_URI = os.environ.get("JIRA_OAUTH_REDIRECT_URI", "")
FRONTEND_BASE_PATH = (os.environ.get("FRONTEND_BASE_PATH", "/portal") or "/portal").strip() or "/portal"
# Scopes needed: create issues, attach files, read project metadata
JIRA_OAUTH_SCOPES = "write:jira-work read:jira-work read:me offline_access"

_db_lock = threading.Lock()

# ── RBAC: Permissions & Roles ─────────────────────────

ALL_PERMISSIONS = [
    "view_dashboard", "view_alerts", "view_knowledge_base",
    "ack_alerts", "resolve_alerts", "silence_alerts", "investigate_alerts",
    "escalate_alerts", "create_tickets", "create_incidents", "override_severity",
    "manage_routing_rules", "manage_highlight_rules", "manage_webhooks",
    "manage_users", "manage_roles",
    "view_settings", "view_webhooks", "view_admin",
]

_SEED_ROLES = [
    (1, "Admin", "Full access to all features", 1, [
        "view_dashboard", "view_alerts", "view_knowledge_base",
        "ack_alerts", "resolve_alerts", "silence_alerts", "investigate_alerts",
        "escalate_alerts", "create_tickets", "create_incidents", "override_severity",
        "manage_routing_rules", "manage_highlight_rules", "manage_webhooks",
        "manage_users", "manage_roles",
        "view_settings", "view_webhooks", "view_admin",
    ]),
    (2, "SRE", "Operational access for SRE team members", 1, [
        "view_dashboard", "view_alerts", "view_knowledge_base",
        "ack_alerts", "resolve_alerts", "silence_alerts", "investigate_alerts",
        "escalate_alerts", "create_tickets", "create_incidents", "override_severity",
        "manage_routing_rules", "manage_highlight_rules", "manage_webhooks",
        "view_settings", "view_webhooks",
    ]),
    (3, "Viewer", "Read-only access to dashboards", 1, [
        "view_dashboard", "view_alerts", "view_settings",
    ]),
]

# In-memory set of invalidated tokens (cleared on restart — acceptable for single-instance)
_invalidated_tokens = set()


# ── Database ───────────────────────────────────────────

def _init_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
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
        ("role_id", "INTEGER DEFAULT 2"),
    ]:
        try:
            db.execute(f"ALTER TABLE users ADD COLUMN {col} {coldef}")
            log.info(f"Added column: {col}")
        except sqlite3.OperationalError:
            pass  # column already exists

    # ── Roles + Permissions tables ──
    db.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '',
            is_system INTEGER DEFAULT 0,
            created_by TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission TEXT NOT NULL,
            PRIMARY KEY (role_id, permission),
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS shared_integrations (
            key TEXT PRIMARY KEY,
            username TEXT NOT NULL DEFAULT '',
            password_ciphertext TEXT NOT NULL DEFAULT '',
            updated_by TEXT DEFAULT '',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS webhook_subscriber_secrets (
            subscriber_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            url TEXT NOT NULL DEFAULT '',
            secret_ciphertext TEXT NOT NULL DEFAULT '',
            updated_by TEXT DEFAULT '',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Seed roles and permissions
    for role_id, name, desc, is_system, perms in _SEED_ROLES:
        existing = db.execute("SELECT id FROM roles WHERE id = ?", (role_id,)).fetchone()
        if not existing:
            db.execute(
                "INSERT INTO roles (id, name, description, is_system, created_by) VALUES (?, ?, ?, ?, 'system')",
                (role_id, name, desc, is_system),
            )
            for perm in perms:
                db.execute("INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?, ?)", (role_id, perm))
            log.info(f"Seeded role: {name} with {len(perms)} permissions")

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


def _require_shared_integrations_secret():
    if not SHARED_INTEGRATIONS_SECRET:
        raise RuntimeError("SHARED_INTEGRATIONS_SECRET is required")
    return SHARED_INTEGRATIONS_SECRET.encode("utf-8")


def _encrypt_shared_secret(raw_password):
    key = hashlib.sha256(_require_shared_integrations_secret()).digest()
    raw = raw_password.encode("utf-8")
    return base64.urlsafe_b64encode(bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))).decode("ascii")


def _decrypt_shared_secret(ciphertext):
    key = hashlib.sha256(_require_shared_integrations_secret()).digest()
    raw = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)).decode("utf-8")


def _set_shared_integration_secret(db_conn, key, username, password, updated_by):
    db_conn.execute(
        """
        INSERT INTO shared_integrations (key, username, password_ciphertext, updated_by, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
            username = excluded.username,
            password_ciphertext = excluded.password_ciphertext,
            updated_by = excluded.updated_by,
            updated_at = CURRENT_TIMESTAMP
        """,
        (key, username, _encrypt_shared_secret(password), updated_by),
    )
    db_conn.commit()


def _get_shared_integration_secret(db_conn, key):
    row = db_conn.execute(
        "SELECT key, username, password_ciphertext, updated_by, updated_at FROM shared_integrations WHERE key = ?",
        (key,),
    ).fetchone()
    if not row or not row["password_ciphertext"]:
        return None
    return {
        "key": row["key"],
        "username": row["username"],
        "password": _decrypt_shared_secret(row["password_ciphertext"]),
        "updated_by": row["updated_by"],
        "updated_at": row["updated_at"],
    }


def _get_shared_integration_metadata(db_conn, key):
    row = db_conn.execute(
        "SELECT username, updated_by, updated_at, password_ciphertext FROM shared_integrations WHERE key = ?",
        (key,),
    ).fetchone()
    return {
        "configured": bool(row and row["username"] and row["password_ciphertext"]),
        "username": row["username"] if row else "",
        "updated_by": row["updated_by"] if row else "",
        "updated_at": row["updated_at"] if row else "",
    }


def _clear_shared_integration_secret(db_conn, key):
    db_conn.execute("DELETE FROM shared_integrations WHERE key = ?", (key,))
    db_conn.commit()


def _frontend_path(path):
    base = FRONTEND_BASE_PATH
    if not base.startswith("/"):
        base = f"/{base}"
    if base != "/":
        base = base.rstrip("/")
    suffix = path or "/"
    if not suffix.startswith("/"):
        suffix = f"/{suffix}"
    if base == "/":
        return suffix
    return f"{base}{suffix}"


def _set_webhook_subscriber_secret(db_conn, subscriber_id, name, url, secret, updated_by):
    db_conn.execute(
        """
        INSERT INTO webhook_subscriber_secrets
            (subscriber_id, name, url, secret_ciphertext, updated_by, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(subscriber_id) DO UPDATE SET
            name = excluded.name,
            url = excluded.url,
            secret_ciphertext = excluded.secret_ciphertext,
            updated_by = excluded.updated_by,
            updated_at = CURRENT_TIMESTAMP
        """,
        (int(subscriber_id), name, url, _encrypt_shared_secret(secret), updated_by),
    )
    db_conn.commit()


def _get_webhook_subscriber_secret_map(db_conn):
    rows = db_conn.execute(
        """
        SELECT subscriber_id, name, url, secret_ciphertext, updated_by, updated_at
        FROM webhook_subscriber_secrets
        """
    ).fetchall()
    results = {}
    for row in rows:
        if not row["secret_ciphertext"]:
            continue
        results[str(row["subscriber_id"])] = {
            "name": row["name"],
            "url": row["url"],
            "secret": _decrypt_shared_secret(row["secret_ciphertext"]),
            "updated_by": row["updated_by"],
            "updated_at": row["updated_at"],
        }
    return results


def _login_to_maintenance_api(username, password):
    req = Request(
        f"{MAINTENANCE_API_BASE}/api/auth/login",
        data=json.dumps({"username": username, "password": password}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _can_bootstrap_maintenance(db_conn, auth_payload):
    if not auth_payload:
        return False, "unauthorized"
    username = auth_payload.get("u")
    if not username:
        return False, "unauthorized"
    role = _get_user_role(db_conn, username)
    if role["name"] not in {"Admin", "SRE"}:
        return False, "forbidden"
    return True, None


def _bootstrap_maintenance_token(db_conn, auth_payload):
    allowed, reason = _can_bootstrap_maintenance(db_conn, auth_payload)
    if not allowed:
        raise PermissionError(reason)
    secret = _get_shared_integration_secret(db_conn, "maintenance_api")
    if not secret:
        raise LookupError("Shared maintenance auth is not configured.")
    return _login_to_maintenance_api(secret["username"], secret["password"])


def _seed_users(db):
    for username, display_name in _SEED_USERS:
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not existing:
            pw_hash, pw_salt = _hash_password(_DEFAULT_PASSWORD)
            role_id = 1 if username == "fash" else 2  # fash = Admin, others = SRE
            db.execute(
                "INSERT INTO users (username, password_hash, password_salt, display_name, role_id) VALUES (?, ?, ?, ?, ?)",
                (username, pw_hash, pw_salt, display_name, role_id),
            )
            log.info(f"Seeded user: {username} (role_id={role_id})")
    # Ensure fash is always Admin even if already seeded
    db.execute("UPDATE users SET role_id = 1 WHERE username = 'fash'")
    db.commit()


def _get_user_permissions(db_conn, username):
    """Get the permission list for a user based on their role."""
    row = db_conn.execute(
        "SELECT rp.permission FROM role_permissions rp "
        "JOIN users u ON u.role_id = rp.role_id "
        "WHERE u.username = ?", (username,)
    ).fetchall()
    return [r["permission"] for r in row]


def _get_user_role(db_conn, username):
    """Get the role info for a user."""
    row = db_conn.execute(
        "SELECT r.id, r.name FROM roles r JOIN users u ON u.role_id = r.id WHERE u.username = ?",
        (username,),
    ).fetchone()
    if row:
        return {"id": row["id"], "name": row["name"]}
    return {"id": 2, "name": "SRE"}


def _create_auth_token(username, permissions=None, role_id=None, ttl_hours=24):
    payload = {
        "u": username,
        "e": int(time.time()) + ttl_hours * 3600,
    }
    if permissions is not None:
        payload["p"] = permissions
    if role_id is not None:
        payload["r"] = role_id
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac_mod.new(AUTH_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


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
        # Check invalidated tokens
        if token in _invalidated_tokens:
            return None
        return payload
    except Exception:
        return None


def _get_token_from_request(handler):
    """Extract and verify the auth token from cookies. Returns full payload dict or None."""
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
    Returns username if authorized, None if not (and sends 403)."""
    payload = _get_token_from_request(handler)
    if not payload:
        handler._send_json(401, {"error": "Not authenticated"})
        return None
    username = payload.get("u")
    if not username:
        handler._send_json(401, {"error": "Not authenticated"})
        return None
    # Always resolve permissions from the current DB role so existing sessions
    # immediately reflect role/permission changes.
    with _db_lock:
        perms = _get_user_permissions(db, username)
    if permission not in perms:
        handler._send_json(403, {"error": f"Permission denied: {permission} required"})
        return None
    return username


def _is_internal_request(handler):
    """Allow trusted service-to-service calls using the shared AUTH_SECRET."""
    header_secret = handler.headers.get("X-UIP-Internal-Auth", "")
    return bool(AUTH_SECRET) and hmac_mod.compare_digest(header_secret, AUTH_SECRET)


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
                    "created_at, role_id FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
            if not row:
                self._send_json(401, {"error": "User not found"})
                return
            has_oauth = bool(row["jira_oauth_refresh_token"])
            with _db_lock:
                role = _get_user_role(db, username)
                permissions = _get_user_permissions(db, username)
            self._send_json(200, {
                "username": row["username"],
                "display_name": row["display_name"],
                "jira_email": row["jira_oauth_email"] or row["jira_email"] or "",
                "has_jira_token": has_oauth or bool(row["jira_api_token"]),
                "jira_connected": has_oauth,
                "jira_oauth_email": row["jira_oauth_email"] or "",
                "created_at": row["created_at"],
                "role": role,
                "permissions": permissions,
            })

        # ── OAuth: Start authorization flow ───────────
        elif path == "/api/auth/jira/connect":
            username = _get_username_from_request(self)
            if not username:
                self._send_redirect(_frontend_path("/login?error=auth_required"))
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
                self._send_redirect(_frontend_path(f"/settings?jira_error={quote(error)}"))
                return

            code = (qs.get("code") or [None])[0]
            state = (qs.get("state") or [None])[0]
            if not code or not state:
                self._send_redirect(_frontend_path("/settings?jira_error=missing_params"))
                return

            username = _verify_oauth_state(state)
            if not username:
                self._send_redirect(_frontend_path("/settings?jira_error=invalid_state"))
                return

            # Exchange code for tokens
            token_data, err = _exchange_oauth_code(code)
            if err:
                log.error(f"OAuth exchange failed for {username}: {err}")
                self._send_redirect(_frontend_path(f"/settings?jira_error={quote('token_exchange_failed')}"))
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
            self._send_redirect(_frontend_path("/settings?jira_connected=true"))

        # ── Internal API: Get user's OAuth token (called by runbook-api) ──
        elif path == "/api/auth/jira-token":
            # Internal endpoint — get a valid access token for a user
            target_user = (qs.get("username") or [None])[0]
            if not target_user:
                self._send_json(400, {"error": "username required"})
                return
            caller = _get_username_from_request(self)
            if not (_is_internal_request(self) or caller == target_user):
                self._send_json(403, {"error": "forbidden"})
                return
            access_token, cloud_id, err = _get_valid_oauth_token(target_user)
            if err:
                self._send_json(404, {"error": err})
                return
            self._send_json(200, {
                "access_token": access_token,
                "cloud_id": cloud_id,
            })

        # ── Admin: List users ──
        elif path == "/api/auth/internal/webhook-subscriber-secrets":
            if not _is_internal_request(self):
                self._send_json(403, {"error": "forbidden"})
                return
            with _db_lock:
                secrets = _get_webhook_subscriber_secret_map(db)
            self._send_json(200, {"items": secrets})

        elif path == "/api/auth/users":
            caller = _require_permission(self, "view_admin")
            if not caller:
                return
            with _db_lock:
                rows = db.execute(
                    "SELECT u.id, u.username, u.display_name, u.role_id, u.created_at, "
                    "r.name as role_name FROM users u LEFT JOIN roles r ON u.role_id = r.id "
                    "ORDER BY u.id"
                ).fetchall()
            users = []
            for r in rows:
                users.append({
                    "id": r["id"], "username": r["username"],
                    "display_name": r["display_name"],
                    "role_id": r["role_id"], "role_name": r["role_name"] or "SRE",
                    "created_at": r["created_at"],
                })
            self._send_json(200, users)

        # ── Admin: List roles ──
        elif path == "/api/auth/roles":
            caller = _require_permission(self, "view_admin")
            if not caller:
                return
            with _db_lock:
                roles = db.execute("SELECT * FROM roles ORDER BY id").fetchall()
                result = []
                for role in roles:
                    perms = db.execute(
                        "SELECT permission FROM role_permissions WHERE role_id = ?", (role["id"],)
                    ).fetchall()
                    user_count = db.execute(
                        "SELECT COUNT(*) as cnt FROM users WHERE role_id = ?", (role["id"],)
                    ).fetchone()["cnt"]
                    result.append({
                        "id": role["id"], "name": role["name"],
                        "description": role["description"],
                        "is_system": bool(role["is_system"]),
                        "permissions": [p["permission"] for p in perms],
                        "user_count": user_count,
                        "created_by": role["created_by"],
                        "created_at": role["created_at"],
                    })
            self._send_json(200, result)

        elif path == "/api/auth/shared-integrations/maintenance":
            caller = _require_permission(self, "manage_roles")
            if not caller:
                return
            with _db_lock:
                metadata = _get_shared_integration_metadata(db, "maintenance_api")
            self._send_json(200, metadata)

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
            with _db_lock:
                permissions = _get_user_permissions(db, username)
                role = _get_user_role(db, username)
            token = _create_auth_token(username, permissions=permissions, role_id=role["id"])
            resp_body = json.dumps({"ok": True, "user": {
                "username": row["username"],
                "display_name": row["display_name"],
                "role": role,
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

        # ── Admin: Create user ──
        elif path == "/api/auth/users":
            caller = _require_permission(self, "manage_users")
            if not caller:
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            uname = (data.get("username") or "").strip().lower()
            display = (data.get("display_name") or uname).strip()
            password = data.get("password") or ""
            role_id = data.get("role_id", 2)
            if not uname or not password:
                self._send_json(400, {"error": "username and password required"})
                return
            if len(password) < 8:
                self._send_json(400, {"error": "Password must be at least 8 characters"})
                return
            pw_hash, pw_salt = _hash_password(password)
            try:
                with _db_lock:
                    db.execute(
                        "INSERT INTO users (username, password_hash, password_salt, display_name, role_id) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (uname, pw_hash, pw_salt, display, role_id),
                    )
                    db.commit()
                    new_user = db.execute("SELECT id FROM users WHERE username = ?", (uname,)).fetchone()
            except sqlite3.IntegrityError:
                self._send_json(409, {"error": f"Username '{uname}' already exists"})
                return
            log.info(f"User created by {caller}: {uname} (role_id={role_id})")
            self._send_json(201, {"ok": True, "id": new_user["id"], "username": uname})

        # ── Admin: Create role ──
        elif path == "/api/auth/roles":
            caller = _require_permission(self, "manage_roles")
            if not caller:
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            name = (data.get("name") or "").strip()
            desc = (data.get("description") or "").strip()
            permissions = data.get("permissions", [])
            if not name:
                self._send_json(400, {"error": "Role name required"})
                return
            # Validate permissions
            invalid = [p for p in permissions if p not in ALL_PERMISSIONS]
            if invalid:
                self._send_json(400, {"error": f"Invalid permissions: {', '.join(invalid)}"})
                return
            try:
                with _db_lock:
                    db.execute(
                        "INSERT INTO roles (name, description, is_system, created_by) VALUES (?, ?, 0, ?)",
                        (name, desc, caller),
                    )
                    role_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                    for perm in permissions:
                        db.execute("INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)", (role_id, perm))
                    db.commit()
            except sqlite3.IntegrityError:
                self._send_json(409, {"error": f"Role '{name}' already exists"})
                return
            log.info(f"Role created by {caller}: {name} (id={role_id})")
            self._send_json(201, {"ok": True, "id": role_id, "name": name})

        elif path == "/api/auth/shared-integrations/maintenance/test":
            caller = _require_permission(self, "manage_roles")
            if not caller:
                return
            try:
                with _db_lock:
                    secret = _get_shared_integration_secret(db, "maintenance_api")
                if not secret:
                    self._send_json(409, {"error": "Shared maintenance auth is not configured."})
                    return
                result = _login_to_maintenance_api(secret["username"], secret["password"])
                if not result.get("token"):
                    self._send_json(502, {"error": "Stored shared maintenance auth is invalid."})
                    return
                self._send_json(200, {"ok": True})
            except HTTPError as exc:
                if exc.code in (400, 401, 403):
                    self._send_json(502, {"error": "Stored shared maintenance auth is invalid."})
                    return
                self._send_json(502, {"error": "Maintenance API is unavailable."})
            except (URLError, TimeoutError, ValueError, KeyError):
                self._send_json(502, {"error": "Maintenance API is unavailable."})

        elif path == "/api/auth/maintenance/bootstrap":
            auth_payload = _get_token_from_request(self)
            try:
                with _db_lock:
                    result = _bootstrap_maintenance_token(db, auth_payload)
                token = result.get("token")
                if not token:
                    self._send_json(502, {"error": "Stored shared maintenance auth is invalid."})
                    return
                self._send_json(200, {"ok": True, "token": token})
            except PermissionError as exc:
                status = 401 if str(exc) == "unauthorized" else 403
                self._send_json(status, {"error": "Not eligible for shared maintenance bootstrap"})
            except LookupError:
                self._send_json(409, {"error": "Shared maintenance auth is not configured."})
            except HTTPError as exc:
                if exc.code in (400, 401, 403):
                    self._send_json(502, {"error": "Stored shared maintenance auth is invalid."})
                    return
                self._send_json(502, {"error": "Maintenance API is unavailable."})
            except (URLError, TimeoutError, ValueError, KeyError):
                self._send_json(502, {"error": "Maintenance API is unavailable."})

        else:
            self._send_json(404, {"error": "not found"})

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # ── Admin: Update user ──
        user_match = re.match(r"^/api/auth/users/(\d+)$", path)
        webhook_secret_match = re.match(r"^/api/auth/webhook-subscriber-secrets/(\d+)$", path)
        role_match = re.match(r"^/api/auth/roles/(\d+)$", path)
        role_perms_match = re.match(r"^/api/auth/roles/(\d+)/permissions$", path)

        if path == "/api/auth/shared-integrations/maintenance":
            caller = _require_permission(self, "manage_roles")
            if not caller:
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            username = (data.get("username") or "").strip()
            password = data.get("password") or ""
            if not username or not password:
                self._send_json(400, {"error": "username and password required"})
                return
            with _db_lock:
                _set_shared_integration_secret(db, "maintenance_api", username, password, caller)
                metadata = _get_shared_integration_metadata(db, "maintenance_api")
            self._send_json(200, {"ok": True, **metadata})

        elif webhook_secret_match:
            caller = _require_permission(self, "manage_webhooks")
            if not caller:
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            subscriber_id = int(webhook_secret_match.group(1))
            name = (data.get("name") or "").strip()
            url = (data.get("url") or "").strip()
            secret = data.get("secret") or ""
            if not name or not url or not secret:
                self._send_json(400, {"error": "name, url, and secret are required"})
                return
            with _db_lock:
                _set_webhook_subscriber_secret(db, subscriber_id, name, url, secret, caller)
            self._send_json(200, {"ok": True})

        elif user_match:
            caller = _require_permission(self, "manage_users")
            if not caller:
                return
            user_id = int(user_match.group(1))
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            with _db_lock:
                row = db.execute("SELECT username, role_id FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                self._send_json(404, {"error": "User not found"})
                return
            updates = []
            params = []
            if "display_name" in data:
                updates.append("display_name = ?")
                params.append(data["display_name"])
            if "role_id" in data:
                new_role_id = data["role_id"]
                # Verify role exists
                with _db_lock:
                    role_exists = db.execute("SELECT id FROM roles WHERE id = ?", (new_role_id,)).fetchone()
                if not role_exists:
                    self._send_json(400, {"error": "Role not found"})
                    return
                updates.append("role_id = ?")
                params.append(new_role_id)
            if "password" in data:
                if len(data["password"]) < 8:
                    self._send_json(400, {"error": "Password must be at least 8 characters"})
                    return
                pw_hash, pw_salt = _hash_password(data["password"])
                updates.append("password_hash = ?")
                params.append(pw_hash)
                updates.append("password_salt = ?")
                params.append(pw_salt)
            if not updates:
                self._send_json(400, {"error": "No fields to update"})
                return
            updates.append("updated_at = datetime('now')")
            params.append(user_id)
            with _db_lock:
                db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
                db.commit()
            # Invalidate user's existing tokens if role changed
            if "role_id" in data and data["role_id"] != row["role_id"]:
                # We can't enumerate all tokens, but we mark the username for invalidation
                # by adding a marker. In practice, the user will need to re-login.
                log.info(f"Role changed for {row['username']} by {caller}: {row['role_id']} → {data['role_id']}")
            log.info(f"User {row['username']} updated by {caller}")
            self._send_json(200, {"ok": True})

        elif role_perms_match:
            caller = _require_permission(self, "manage_roles")
            if not caller:
                return
            role_id = int(role_perms_match.group(1))
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            permissions = data.get("permissions", [])
            invalid = [p for p in permissions if p not in ALL_PERMISSIONS]
            if invalid:
                self._send_json(400, {"error": f"Invalid permissions: {', '.join(invalid)}"})
                return
            with _db_lock:
                role = db.execute("SELECT id, name FROM roles WHERE id = ?", (role_id,)).fetchone()
            if not role:
                self._send_json(404, {"error": "Role not found"})
                return
            with _db_lock:
                db.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
                for perm in permissions:
                    db.execute("INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)", (role_id, perm))
                db.commit()
            log.info(f"Permissions updated for role {role['name']} by {caller}: {len(permissions)} permissions")
            self._send_json(200, {"ok": True})

        elif role_match:
            caller = _require_permission(self, "manage_roles")
            if not caller:
                return
            role_id = int(role_match.group(1))
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            with _db_lock:
                role = db.execute("SELECT * FROM roles WHERE id = ?", (role_id,)).fetchone()
            if not role:
                self._send_json(404, {"error": "Role not found"})
                return
            if role["is_system"] and "name" in data:
                self._send_json(400, {"error": "Cannot rename system roles"})
                return
            updates = []
            params = []
            if "name" in data:
                updates.append("name = ?")
                params.append(data["name"])
            if "description" in data:
                updates.append("description = ?")
                params.append(data["description"])
            if not updates:
                self._send_json(400, {"error": "No fields to update"})
                return
            params.append(role_id)
            try:
                with _db_lock:
                    db.execute(f"UPDATE roles SET {', '.join(updates)} WHERE id = ?", params)
                    db.commit()
            except sqlite3.IntegrityError:
                self._send_json(409, {"error": f"Role name already exists"})
                return
            log.info(f"Role {role['name']} updated by {caller}")
            self._send_json(200, {"ok": True})

        else:
            self._send_json(404, {"error": "not found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        user_match = re.match(r"^/api/auth/users/(\d+)$", path)
        role_match = re.match(r"^/api/auth/roles/(\d+)$", path)

        if path == "/api/auth/shared-integrations/maintenance":
            caller = _require_permission(self, "manage_roles")
            if not caller:
                return
            with _db_lock:
                _clear_shared_integration_secret(db, "maintenance_api")
            self._send_json(200, {"ok": True})

        elif user_match:
            caller = _require_permission(self, "manage_users")
            if not caller:
                return
            user_id = int(user_match.group(1))
            with _db_lock:
                row = db.execute("SELECT username, role_id FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                self._send_json(404, {"error": "User not found"})
                return
            if row["username"] == caller:
                self._send_json(400, {"error": "Cannot delete yourself"})
                return
            # Check if this is the last admin
            if row["role_id"] == 1:
                with _db_lock:
                    admin_count = db.execute("SELECT COUNT(*) as cnt FROM users WHERE role_id = 1").fetchone()["cnt"]
                if admin_count <= 1:
                    self._send_json(400, {"error": "Cannot delete the last admin user"})
                    return
            with _db_lock:
                db.execute("DELETE FROM users WHERE id = ?", (user_id,))
                db.commit()
            log.info(f"User {row['username']} deleted by {caller}")
            self._send_json(200, {"ok": True})

        elif role_match:
            caller = _require_permission(self, "manage_roles")
            if not caller:
                return
            role_id = int(role_match.group(1))
            with _db_lock:
                role = db.execute("SELECT * FROM roles WHERE id = ?", (role_id,)).fetchone()
            if not role:
                self._send_json(404, {"error": "Role not found"})
                return
            if role["is_system"]:
                self._send_json(400, {"error": "Cannot delete system roles"})
                return
            with _db_lock:
                user_count = db.execute("SELECT COUNT(*) as cnt FROM users WHERE role_id = ?", (role_id,)).fetchone()["cnt"]
            if user_count > 0:
                self._send_json(409, {"error": f"Cannot delete role with {user_count} assigned user(s). Reassign them first."})
                return
            with _db_lock:
                db.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
                db.execute("DELETE FROM roles WHERE id = ?", (role_id,))
                db.commit()
            log.info(f"Role {role['name']} deleted by {caller}")
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
