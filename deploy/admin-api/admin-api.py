"""UIP admin-api — runtime config + control plane.

Stdlib http.server pattern (matches alert-state-api, auth-api, runbook-api).
"""
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import sys as _sys, os as _os
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".."))

from db import apply_seed, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("admin-api")

API_PORT = int(os.environ.get("API_PORT", "8096"))
DB_PATH = os.environ.get("DB_PATH", "/data/admin.db")
AUTH_API_URL = os.environ.get("AUTH_API_URL", "http://auth-api:8093")
try:
    AUTH_SECRET = os.environ["AUTH_SECRET"]
except KeyError:
    sys.exit("AUTH_SECRET environment variable is required")
ADMIN_BYPASS_TOKEN = os.environ.get("ADMIN_BYPASS_TOKEN") or None
CLUSTER_ENDPOINT = os.environ.get("CLUSTER_ENDPOINT", "")


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _parse(self):
        u = urlparse(self.path)
        from urllib.parse import parse_qs
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        return u.path, q

    def do_GET(self) -> None:
        from routes import config as r_config
        path, query = self._parse()
        if path == "/health":
            return self._send_json(200, {"ok": True, "service": "admin-api"})
        if path == "/api/admin/config/events":
            return self._handle_sse()
        if r_config.handle(self, "GET", path, query, DB_PATH):
            return
        self._send_json(404, {"error": "not found", "path": path})

    def do_PATCH(self) -> None:
        from routes import config as r_config
        path, query = self._parse()
        if r_config.handle(self, "PATCH", path, query, DB_PATH):
            return
        self._send_json(404, {"error": "not found", "path": path})

    def do_DELETE(self) -> None:
        from routes import config as r_config
        path, query = self._parse()
        if r_config.handle(self, "DELETE", path, query, DB_PATH):
            return
        self._send_json(404, {"error": "not found", "path": path})

    def _handle_sse(self) -> None:
        from sse import add_client, remove_client
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            add_client(self.wfile)
            # Block until client disconnects. ThreadingHTTPServer handles many.
            # We rely on broadcast() to write; we just hold the connection.
            try:
                while True:
                    # Send a keepalive every 25s
                    import time
                    time.sleep(25)
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except Exception:
                        break
            finally:
                remove_client(self.wfile)
        except Exception as e:
            log.warning("SSE handler error: %s", e)

    def log_message(self, fmt: str, *args) -> None:
        # Route http.server logs through logging instead of stderr
        log.info("%s - %s", self.address_string(), fmt % args)


def main() -> None:
    log.info("admin-api starting on :%s (DB=%s)", API_PORT, DB_PATH)
    init_db(DB_PATH)
    log.info("schema bootstrapped at %s", DB_PATH)
    apply_seed(DB_PATH)
    log.info("seed applied")
    with ThreadingHTTPServer(("0.0.0.0", API_PORT), Handler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            log.info("admin-api stopped")


if __name__ == "__main__":
    main()
