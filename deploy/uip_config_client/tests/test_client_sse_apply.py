import http.server
import json
import os
import socket
import sys
import threading
import time
from contextlib import closing


def _free_port():
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeAdminApi(http.server.BaseHTTPRequestHandler):
    """Fake admin-api: serves snapshot + SSE stream from a shared event list."""
    pending_events = []
    snapshot_items = []

    def do_GET(self):
        if self.path == "/api/admin/config":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"items": FakeAdminApi.snapshot_items}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/admin/config/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            # Push everything in pending_events, then hang
            for event_type, payload in FakeAdminApi.pending_events:
                msg = f"id: 1\nevent: {event_type}\ndata: {json.dumps(payload)}\n\n"
                self.wfile.write(msg.encode())
                self.wfile.flush()
            time.sleep(2)  # keep alive a bit so client thread can read
            return
        self.send_error(404)

    def log_message(self, *a):
        pass


def _start_fake():
    port = _free_port()
    FakeAdminApi.pending_events = []
    FakeAdminApi.snapshot_items = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), FakeAdminApi)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return port, server


def test_client_picks_up_initial_snapshot():
    port, server = _start_fake()
    FakeAdminApi.snapshot_items = [
        {"key": "ai.enricher.model", "value": "qwen3-32b-thinking", "value_type": "string"},
    ]
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from uip_config_client import ConfigClient
        cfg = ConfigClient(admin_api=f"http://127.0.0.1:{port}", env_fallback=False, poll_interval_sec=0)
        assert cfg.get("ai.enricher.model") == "qwen3-32b-thinking"
    finally:
        server.shutdown()


def test_sse_event_updates_value():
    port, server = _start_fake()
    FakeAdminApi.snapshot_items = [
        {"key": "ai.enricher.model", "value": "qwen3-32b-thinking", "value_type": "string"},
    ]
    FakeAdminApi.pending_events = [
        ("config_changed", {"key": "ai.enricher.model", "new_value": "qwen3-235b-thinking", "updated_by": "test", "updated_at": "2026-05-19T22:00:00Z", "reload_kind": "hot", "restart_target": None}),
    ]
    try:
        from uip_config_client import ConfigClient
        cfg = ConfigClient(admin_api=f"http://127.0.0.1:{port}", env_fallback=False, poll_interval_sec=0)
        # Give the SSE thread a moment
        time.sleep(0.5)
        assert cfg.get("ai.enricher.model") == "qwen3-235b-thinking"
    finally:
        server.shutdown()


def test_on_change_callback_fires():
    port, server = _start_fake()
    FakeAdminApi.snapshot_items = [
        {"key": "ai.enricher.model", "value": "qwen3-32b-thinking", "value_type": "string"},
    ]
    FakeAdminApi.pending_events = [
        ("config_changed", {"key": "ai.enricher.model", "new_value": "qwen3-235b-thinking", "updated_by": "test", "updated_at": "2026-05-19T22:00:00Z", "reload_kind": "hot", "restart_target": None}),
    ]
    seen = []
    try:
        from uip_config_client import ConfigClient
        cfg = ConfigClient(admin_api=f"http://127.0.0.1:{port}", env_fallback=False, poll_interval_sec=0)
        cfg.on_change("ai.enricher.model", lambda old, new: seen.append((old, new)))
        time.sleep(0.5)
        assert seen == [("qwen3-32b-thinking", "qwen3-235b-thinking")]
    finally:
        server.shutdown()
