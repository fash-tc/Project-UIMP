import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import urllib.request
import urllib.error
import json


def _call(port, method, path, body=None, headers=None):
    headers = dict(headers or {})
    headers.setdefault("X-Admin-Bypass", "test-bypass")  # fixture sets this token
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_sse_endpoint_responds_with_event_stream(admin_api_server):
    """Verify the SSE endpoint returns 200 + text/event-stream headers.

    NOTE: End-to-end broadcast verification (broadcast -> SSE client receives event)
    requires an in-process trigger. The subprocess fixture cannot share the in-process
    _clients set with the test process. Full end-to-end coverage is deferred to Task 11,
    which wires PATCH /api/admin/config/{key} -> broadcast() inside the server process.
    """
    port, _, _db_path = admin_api_server
    import socket
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    s.sendall(b"GET /api/admin/config/events HTTP/1.1\r\nHost: localhost\r\n\r\n")
    s.settimeout(2)
    data = s.recv(1024)
    s.close()
    text = data.decode(errors="replace")
    assert "200 OK" in text
    assert "text/event-stream" in text.lower()


def test_sse_broadcast_in_process():
    """Direct unit test of the broadcast() helper — doesn't need the subprocess.

    Uses BytesIO to simulate a wfile. BytesIO.flush() is a no-op but the method
    exists, so broadcast() won't error on it.
    """
    from sse import add_client, broadcast, remove_client
    import io
    buf = io.BytesIO()
    add_client(buf)
    try:
        broadcast("config_changed", {"key": "test.key", "new_value": "test"})
    finally:
        remove_client(buf)
    output = buf.getvalue().decode()
    assert "event: config_changed" in output
    assert "test.key" in output


def test_get_config_lists_seeded_keys(admin_api_server):
    port, _, _db_path = admin_api_server
    status, body = _call(port, "GET", "/api/admin/config")
    assert status == 200
    keys = {item["key"] for item in body["items"]}
    assert "ai.cluster.endpoint" in keys


def test_get_config_filtered_by_scope(admin_api_server):
    port, _, _db_path = admin_api_server
    status, body = _call(port, "GET", "/api/admin/config?scope=ai")
    assert status == 200
    assert all(item["key"].startswith("ai.") for item in body["items"])
    assert len(body["items"]) >= 2


def test_get_single_key(admin_api_server):
    port, _, _db_path = admin_api_server
    status, body = _call(port, "GET", "/api/admin/config/ai.cluster.endpoint")
    assert status == 200
    assert body["key"] == "ai.cluster.endpoint"
    assert body["value"].startswith("http")


def test_patch_writes_history_and_broadcasts(admin_api_server):
    port, _, db_path = admin_api_server
    status, body = _call(port, "PATCH", "/api/admin/config/ai.enricher.model",
                          body={"value": "qwen3-235b-thinking", "reason": "test bump"})
    assert status == 200, body
    # Read back
    status, body = _call(port, "GET", "/api/admin/config/ai.enricher.model")
    assert body["value"] == "qwen3-235b-thinking"
    # Verify config_history row was written
    import sqlite3
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT new_value, reason, source FROM config_history WHERE key=? ORDER BY changed_at DESC LIMIT 1",
            ("ai.enricher.model",),
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    import json as _json
    assert _json.loads(row[0]) == "qwen3-235b-thinking"
    assert row[1] == "test bump"
    assert row[2] == "user"


def test_patch_validation_failure_returns_400(admin_api_server):
    port, _, _db_path = admin_api_server
    status, body = _call(port, "PATCH", "/api/admin/config/pipeline.enricher.poll_interval_sec",
                          body={"value": 2})  # below min=5
    assert status == 400


def test_delete_resets_to_default(admin_api_server):
    port, _, _db_path = admin_api_server
    # Capture default from GET
    status, body = _call(port, "GET", "/api/admin/config/ai.enricher.model")
    expected_default = body["default"]
    # Mutate
    _call(port, "PATCH", "/api/admin/config/ai.enricher.model", body={"value": "qwen3-235b-thinking"})
    # Reset
    status, body = _call(port, "DELETE", "/api/admin/config/ai.enricher.model")
    assert status == 200
    # Verify reset to default
    status, body = _call(port, "GET", "/api/admin/config/ai.enricher.model")
    assert body["value"] == expected_default


def test_get_schemas_version(admin_api_server):
    port, _, _db_path = admin_api_server
    status, body = _call(port, "GET", "/api/admin/config/schemas/version")
    assert status == 200
    assert body["seed_version"] >= 1


def test_unauthenticated_returns_401(admin_api_server):
    port, _, _db_path = admin_api_server
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/admin/config")
    try:
        urllib.request.urlopen(req, timeout=2)
        assert False, "expected 401"
    except urllib.error.HTTPError as e:
        assert e.code == 401


def test_patch_secret_key_returns_409(admin_api_server):
    """PATCH must refuse is_secret=1 keys (use rotate-secret instead)."""
    port, _, db_path = admin_api_server
    import sqlite3
    # Inject an is_secret=1 row directly into the live DB so we don't depend on seed evolution
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "INSERT INTO config (key, scope, value, value_type, reload_kind, default_value, is_secret, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
            ("integrations.jira.api_token", "integrations", '"old-ciphertext"', "secret", "hot", '""', "2026-05-19T00:00:00Z", "__test__")
        )
        conn.commit()
    finally:
        conn.close()
    status, body = _call(port, "PATCH", "/api/admin/config/integrations.jira.api_token",
                          body={"value": "new-plaintext"})
    assert status == 409, body
    assert "rotate-secret" in str(body).lower()
