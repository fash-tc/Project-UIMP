import importlib.util
import json
from io import BytesIO
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "runbook-api" / "runbook-api.py"


def load_runbook_api():
    spec = importlib.util.spec_from_file_location("runbook_api", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


def make_handler(module, method, path, payload_obj=None):
    body = json.dumps(payload_obj or {}).encode("utf-8")
    handler = module.RunbookHandler.__new__(module.RunbookHandler)
    handler.path = path
    handler.headers = {"Content-Length": str(len(body))}
    handler.rfile = BytesIO(body)
    handler.wfile = BytesIO()
    handler.command = method
    handler.request_version = "HTTP/1.1"
    handler.client_address = ("127.0.0.1", 0)
    handler.server = None

    result = {}

    def send_response(code):
        result["code"] = code

    def send_header(_key, _value):
        pass

    def end_headers():
        pass

    handler.send_response = send_response
    handler.send_header = send_header
    handler.end_headers = end_headers
    return handler, result


def test_create_statuspage_incident_uses_component_status_mapping(monkeypatch):
    runbook_api = load_runbook_api()
    captured = {}

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse({
            "id": "inc123",
            "shortlink": "https://status.example/inc123",
            "status": "investigating",
        })

    monkeypatch.setattr(runbook_api, "STATUSPAGE_API_KEY", "token")
    monkeypatch.setattr(runbook_api, "STATUSPAGE_PAGE_ID", "page123")
    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    result, error = runbook_api.create_statuspage_incident(
        name="DNS Service Disruption",
        body="Investigating service issues.",
        components=[
            {"component_id": "cmp-a", "status": "partial_outage"},
            {"component_id": "cmp-b", "status": "degraded_performance"},
        ],
        status="investigating",
        impact="major",
    )

    assert error is None
    assert result["id"] == "inc123"
    assert captured["url"] == "https://api.statuspage.io/v1/pages/page123/incidents"
    assert captured["method"] == "POST"
    assert captured["body"]["incident"]["component_ids"] == ["cmp-a", "cmp-b"]
    assert captured["body"]["incident"]["components"] == {
        "cmp-a": "partial_outage",
        "cmp-b": "degraded_performance",
    }


def test_list_statuspage_incidents_maps_active_incident_fields(monkeypatch):
    runbook_api = load_runbook_api()

    def fake_urlopen(req, timeout=0):
        return FakeResponse([
            {
                "id": "inc123",
                "name": "Customer API Issue",
                "status": "investigating",
                "impact": "major",
                "shortlink": "https://status.example/inc123",
                "updated_at": "2026-04-02T10:00:00Z",
                "components": [
                    {"id": "cmp-a", "name": "API", "status": "partial_outage", "description": "Customer API"},
                ],
            },
            {
                "id": "inc999",
                "name": "Resolved Incident",
                "status": "resolved",
                "impact": "none",
                "shortlink": "https://status.example/inc999",
                "updated_at": "2026-04-02T09:00:00Z",
                "components": [],
            },
        ])

    monkeypatch.setattr(runbook_api, "STATUSPAGE_API_KEY", "token")
    monkeypatch.setattr(runbook_api, "STATUSPAGE_PAGE_ID", "page123")
    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    incidents, error = runbook_api.fetch_statuspage_active_incidents()

    assert error is None
    assert len(incidents) == 1
    assert incidents[0] == {
        "id": "inc123",
        "name": "Customer API Issue",
        "status": "investigating",
        "impact": "major",
        "shortlink": "https://status.example/inc123",
        "updated_at": "2026-04-02T10:00:00Z",
        "components": [
            {"id": "cmp-a", "name": "API", "status": "partial_outage", "description": "Customer API"},
        ],
    }


def test_update_statuspage_incident_sends_resolve_and_operational_reset(monkeypatch):
    runbook_api = load_runbook_api()
    captured = {}

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse({
            "id": "inc123",
            "shortlink": "https://status.example/inc123",
            "status": "resolved",
        })

    monkeypatch.setattr(runbook_api, "STATUSPAGE_API_KEY", "token")
    monkeypatch.setattr(runbook_api, "STATUSPAGE_PAGE_ID", "page123")
    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    result, error = runbook_api.update_statuspage_incident(
        incident_id="inc123",
        name="Customer API Issue",
        body="Issue resolved.",
        status="resolved",
        impact="none",
        components=[{"component_id": "cmp-a", "status": "operational"}],
    )

    assert error is None
    assert result["status"] == "resolved"
    assert captured["url"] == "https://api.statuspage.io/v1/pages/page123/incidents/inc123"
    assert captured["method"] == "PATCH"
    assert captured["body"]["incident"]["status"] == "resolved"
    assert captured["body"]["incident"]["components"] == {"cmp-a": "operational"}


def test_statuspage_incidents_route_returns_active_incidents(monkeypatch):
    runbook_api = load_runbook_api()
    monkeypatch.setattr(
        runbook_api,
        "fetch_statuspage_active_incidents",
        lambda: ([{"id": "inc123", "name": "Customer API Issue"}], None),
    )
    handler, result = make_handler(runbook_api, "GET", "/api/runbook/statuspage/incidents")

    handler.do_GET()

    assert result["code"] == 200


def test_statuspage_incidents_patch_route_updates_incident(monkeypatch):
    runbook_api = load_runbook_api()
    captured = {}

    def fake_update_statuspage_incident(**kwargs):
        captured.update(kwargs)
        return ({"id": kwargs["incident_id"], "status": kwargs["status"]}, None)

    monkeypatch.setattr(runbook_api, "update_statuspage_incident", fake_update_statuspage_incident)
    handler, result = make_handler(
        runbook_api,
        "PATCH",
        "/api/runbook/statuspage/incidents/inc123",
        payload_obj={
            "name": "Customer API Issue",
            "body": "Still investigating",
            "status": "identified",
            "impact_override": "major",
            "components": [{"component_id": "cmp-a", "status": "degraded_performance"}],
        },
    )

    handler.do_PATCH()

    assert result["code"] == 200
    assert captured["incident_id"] == "inc123"
    assert captured["status"] == "identified"
