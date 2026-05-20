import http.server
import json
import socket
import sys, os, time, threading
from contextlib import closing


def _free_port():
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]


class FakeApi(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/admin/config":
            body = json.dumps({"items": [{"key": "pipeline.enricher.poll_interval_sec", "value": 60, "value_type": "int"}]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        if self.path == "/api/admin/config/events":
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            # Push an event with wrong type (string instead of int)
            msg = 'id: 1\nevent: config_changed\ndata: {"key":"pipeline.enricher.poll_interval_sec","new_value":"not-an-int","updated_by":"x","updated_at":"2026","reload_kind":"hot","restart_target":null}\n\n'
            self.wfile.write(msg.encode()); self.wfile.flush(); time.sleep(2); return
        self.send_error(404)

    def log_message(self, *a):
        pass


def test_invalid_payload_keeps_old_value_and_fires_handler():
    port = _free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), FakeApi)
    t = threading.Thread(target=server.serve_forever, daemon=True); t.start()
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from uip_config_client import ConfigClient
        seen = []
        cfg = ConfigClient(admin_api=f"http://127.0.0.1:{port}", env_fallback=False, poll_interval_sec=0,
                           on_invalid_payload=lambda p, e: seen.append((p, e)))
        time.sleep(0.5)
        # Value must still be 60, not the bogus string
        assert cfg.get("pipeline.enricher.poll_interval_sec") == 60
        # Handler must have fired once
        assert len(seen) == 1
        assert seen[0][0]["key"] == "pipeline.enricher.poll_interval_sec"
    finally:
        server.shutdown()
