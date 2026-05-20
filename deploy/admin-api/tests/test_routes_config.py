import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


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
