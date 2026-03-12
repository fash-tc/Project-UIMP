"""escalation-api: Grafana IRM escalation integration for UIP."""

import json
import os
import logging
import time
import base64
import hashlib
import hmac as hmac_mod
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("escalation-api")

API_PORT = int(os.environ.get("API_PORT", "8094"))
GRAFANA_ONCALL_URL = os.environ.get("GRAFANA_ONCALL_URL", "").rstrip("/")
GRAFANA_ONCALL_API_KEY = os.environ.get("GRAFANA_ONCALL_API_KEY", "")
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")

# In-memory cache for teams/users (5-minute TTL)
_cache = {}  # key -> {"data": ..., "expires": float}
CACHE_TTL = 300  # 5 minutes


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


# ── Grafana OnCall helpers ─────────────────────────────

def _oncall_request(path, method="GET", data=None):
    """Make an authenticated request to Grafana OnCall API."""
    if not GRAFANA_ONCALL_URL:
        return None, "GRAFANA_ONCALL_URL not configured"
    url = f"{GRAFANA_ONCALL_URL}/api/v1{path}"
    body = json.dumps(data).encode() if data else None
    req = Request(url, data=body, method=method, headers={
        "Authorization": GRAFANA_ONCALL_API_KEY,
        "Content-Type": "application/json",
    })
    try:
        resp = urlopen(req, timeout=15)
        raw = resp.read()
        return json.loads(raw) if raw else {}, None
    except HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode()[:500]
        except Exception:
            pass
        return None, f"OnCall API {e.code}: {body_text}"
    except Exception as e:
        return None, str(e)


def _cached_get(cache_key, oncall_path):
    """Fetch from cache or Grafana OnCall, handling pagination."""
    now = time.time()
    if cache_key in _cache and _cache[cache_key]["expires"] > now:
        return _cache[cache_key]["data"], None

    all_items = []
    page = 1
    while True:
        sep = "&" if "?" in oncall_path else "?"
        paginated_path = f"{oncall_path}{sep}page={page}&page_size=50"
        data, err = _oncall_request(paginated_path)
        if err:
            if all_items:
                break  # Return what we have
            return None, err

        items = data
        if isinstance(data, dict):
            items = data.get("results", data.get("data", []))
            all_items.extend(items if isinstance(items, list) else [])
            if not data.get("next"):
                break
            page += 1
        else:
            all_items.extend(items if isinstance(items, list) else [])
            break

    _cache[cache_key] = {"data": all_items, "expires": now + CACHE_TTL}
    return all_items, None


# ── HTTP Handler ───────────────────────────────────────

class EscalationHandler(BaseHTTPRequestHandler):

    def _send_json(self, status, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, fmt, *args):
        log.info("%s - - %s" % (self.address_string(), fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/escalation/health":
            configured = bool(GRAFANA_ONCALL_URL and GRAFANA_ONCALL_API_KEY)
            self._send_json(200, {
                "status": "ok",
                "grafana_oncall_configured": configured,
            })

        elif path == "/api/escalation/teams":
            teams, err = _cached_get("teams", "/teams/")
            if err:
                self._send_json(502, {"error": err})
                return
            # Normalize to [{id, name}]
            result = []
            if isinstance(teams, list):
                for t in teams:
                    result.append({
                        "id": t.get("id", ""),
                        "name": t.get("name", t.get("display_name", "")),
                    })
            self._send_json(200, result)

        elif path == "/api/escalation/users":
            users, err = _cached_get("users", "/users/")
            if err:
                self._send_json(502, {"error": err})
                return
            result = []
            if isinstance(users, list):
                for u in users:
                    result.append({
                        "id": u.get("id", ""),
                        "name": u.get("username", u.get("name", "")),
                        "email": u.get("email", ""),
                    })
            self._send_json(200, result)

        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/escalation/escalate":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return

            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return

            team_id = data.get("team_id", "")
            user_ids = data.get("user_ids", [])
            alert_name = data.get("alert_name", "Unknown Alert")
            severity = data.get("severity", "unknown")
            summary = data.get("summary", "")
            message = data.get("message", "")
            uip_link = data.get("uip_link", "")

            if not team_id and not user_ids:
                self._send_json(400, {"error": "team_id or user_ids is required"})
                return

            title = f"[{severity.upper()}] {alert_name}"
            full_message = summary
            if message:
                full_message += f"\n\nAdditional context from {username}:\n{message}"
            if uip_link:
                full_message += f"\n\nUIP: {uip_link}"

            payload = {
                "title": title,
                "message": full_message,
            }
            if uip_link:
                payload["source_url"] = uip_link

            if team_id:
                payload["team"] = team_id
            elif user_ids:
                payload["users"] = [{"id": uid, "important": True} for uid in user_ids]

            log.info(f"Escalation by {username}: {title} -> {'team=' + team_id if team_id else 'users=' + str(user_ids)}")

            result, err = _oncall_request("/escalation/", method="POST", data=payload)
            if err:
                log.error(f"Escalation failed: {err}")
                self._send_json(502, {"success": False, "error": err})
                return

            log.info(f"Escalation successful: {result}")
            self._send_json(200, {"success": True})

        else:
            self._send_json(404, {"error": "not found"})


# ── Main ───────────────────────────────────────────────

if not GRAFANA_ONCALL_URL:
    log.warning("GRAFANA_ONCALL_URL not set — escalation will fail until configured")
if not GRAFANA_ONCALL_API_KEY:
    log.warning("GRAFANA_ONCALL_API_KEY not set — escalation will fail until configured")
if not AUTH_SECRET:
    log.warning("AUTH_SECRET not set — tokens will use an empty secret")

server = HTTPServer(("0.0.0.0", API_PORT), EscalationHandler)
log.info(f"escalation-api listening on port {API_PORT}")
server.serve_forever()
