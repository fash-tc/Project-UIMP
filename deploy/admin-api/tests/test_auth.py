import http.server
import json
import os
import socket
import sys
import threading
import time
from contextlib import closing

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest

from auth import resolve_user, BypassUser


def _free_port():
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeAuthApi(http.server.BaseHTTPRequestHandler):
    """In-process fake auth-api that returns canned /me responses."""
    canned_responses = {}  # cookie → (status, body)

    def do_GET(self):
        if self.path != "/me":
            self.send_error(404); return
        cookie = self.headers.get("Cookie", "")
        status, body = self.canned_responses.get(cookie, (401, {"error": "unauth"}))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        body_bytes = json.dumps(body).encode()
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, *args):
        pass  # quiet


@pytest.fixture
def fake_auth():
    port = _free_port()
    FakeAuthApi.canned_responses = {}
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), FakeAuthApi)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    yield port, FakeAuthApi.canned_responses
    server.shutdown()


def test_resolve_user_with_valid_session(fake_auth, monkeypatch):
    port, canned = fake_auth
    canned["session=abc"] = (200, {"username": "alice", "permissions": ["manage_ai"]})
    monkeypatch.setenv("AUTH_API_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("ADMIN_BYPASS_TOKEN", "")
    user = resolve_user(cookie="session=abc", bypass_header=None)
    assert user.username == "alice"
    assert "manage_ai" in user.permissions


def test_resolve_user_with_bypass_token(monkeypatch):
    monkeypatch.setenv("AUTH_API_URL", "http://127.0.0.1:1")  # unreachable on purpose
    monkeypatch.setenv("ADMIN_BYPASS_TOKEN", "secret-bypass")
    user = resolve_user(cookie=None, bypass_header="secret-bypass", remote_ip="10.0.0.5")
    assert isinstance(user, BypassUser)
    assert user.username == "__bypass__:10.0.0.5"


def test_resolve_user_wrong_bypass_token_falls_to_session(monkeypatch):
    monkeypatch.setenv("AUTH_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("ADMIN_BYPASS_TOKEN", "real")
    user = resolve_user(cookie=None, bypass_header="wrong", remote_ip="10.0.0.5")
    assert user is None  # no valid session, bypass mismatch


def test_resolve_user_no_session_no_bypass(monkeypatch):
    monkeypatch.setenv("AUTH_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("ADMIN_BYPASS_TOKEN", "")
    assert resolve_user(cookie=None, bypass_header=None) is None
