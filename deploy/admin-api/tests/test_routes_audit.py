import urllib.request
import urllib.error
import json
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _call(port, method, path, body=None):
    headers = {"X-Admin-Bypass": "test-bypass"}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status, r.read().decode(), r.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers.get("Content-Type")


def test_audit_returns_seed_inserts(admin_api_server):
    port, _, _db_path = admin_api_server
    # seed runs on boot — 4 audit rows from initial inserts
    status, body, _ = _call(port, "GET", "/api/admin/audit")
    assert status == 200
    data = json.loads(body)
    assert len(data["items"]) >= 4
    assert all("changed_by" in r for r in data["items"])


def test_audit_filtered_by_key(admin_api_server):
    port, _, _db_path = admin_api_server
    status, body, _ = _call(port, "GET", "/api/admin/audit?key=ai.enricher.model")
    data = json.loads(body)
    assert len(data["items"]) >= 1
    assert all(r["key"] == "ai.enricher.model" for r in data["items"])


def test_audit_export_csv(admin_api_server):
    port, _, _db_path = admin_api_server
    status, body, ctype = _call(port, "GET", "/api/admin/audit/export")
    assert status == 200
    assert "csv" in ctype.lower()
    assert "key,old_value,new_value,changed_by,changed_at,reason,source" in body.splitlines()[0]
