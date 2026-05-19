import urllib.request


def test_health_endpoint_returns_200(admin_api_server):
    port, _, _ = admin_api_server
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
        assert r.status == 200
        body = r.read().decode()
        assert "ok" in body.lower()
