import importlib.util
import json
from http import HTTPStatus
from io import BytesIO
from pathlib import Path


RUNBOOK_API_PATH = Path(__file__).resolve().parents[1] / "runbook-api" / "runbook-api.py"


def load_runbook_api():
    spec = importlib.util.spec_from_file_location("runbook_api_under_test", RUNBOOK_API_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def make_handler(module, path, payload_obj=None, headers=None):
    body = json.dumps(payload_obj or {}).encode()
    header_values = {"Content-Length": str(len(body))}
    if headers:
        header_values.update(headers)

    handler = module.RunbookHandler.__new__(module.RunbookHandler)
    handler.path = path
    handler.headers = header_values
    handler.rfile = BytesIO(body)
    handler.wfile = BytesIO()
    handler.command = "POST"
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


def test_grafana_irm_webhook_rejects_invalid_secret(monkeypatch):
    module = load_runbook_api()
    monkeypatch.setattr(module, "GRAFANA_IRM_WEBHOOK_SECRET", "expected-secret")

    handler, result = make_handler(
        module,
        "/api/runbook/grafana-irm/alert-group-event",
        payload_obj={"alert_group": {"id": "AG1"}},
        headers={
            "X-UIP-Webhook-Source": "grafana-irm",
            "X-UIP-Webhook-Secret": "wrong-secret",
        },
    )

    handler.do_POST()

    assert result["code"] == HTTPStatus.UNAUTHORIZED


def test_grafana_irm_webhook_forwards_normalized_keep_event(monkeypatch):
    module = load_runbook_api()
    monkeypatch.setattr(module, "GRAFANA_IRM_WEBHOOK_SECRET", "expected-secret")
    monkeypatch.setattr(module, "KEEP_URL", "http://keep-api:8080")
    monkeypatch.setattr(module, "KEEP_API_KEY", "keep-key")

    seen = {}

    class FakeResponse:
        status = 202

        def read(self):
            return json.dumps({"ok": True}).encode()

    def fake_urlopen(req, timeout=0):
        seen["url"] = req.full_url
        seen["method"] = req.get_method()
        seen["headers"] = dict(req.header_items())
        seen["payload"] = json.loads(req.data.decode())
        return FakeResponse()

    monkeypatch.setattr(module, "urlopen", fake_urlopen)

    payload = {
        "event": {"type": "Alert group created", "time": "2026-04-02T18:20:00Z"},
        "alert_group": {
            "id": "AG1",
            "title": "Disk space low",
            "state": "alerting",
            "created_at": "2026-04-02T18:20:00Z",
            "labels": {"host": "srv-01", "severity": "critical", "service_name": "storage"},
            "permalinks": {"web": "https://grafana.example/alert-groups/AG1"},
        },
        "alert_payload": {
            "labels": {"instance": "srv-01", "alertname": "Disk space low"},
            "annotations": {"description": "/data is above 90%"},
        },
        "integration": {"name": "Domains Shared"},
    }
    handler, result = make_handler(
        module,
        "/api/runbook/grafana-irm/alert-group-event",
        payload_obj=payload,
        headers={
            "X-UIP-Webhook-Source": "grafana-irm",
            "X-UIP-Webhook-Secret": "expected-secret",
        },
    )

    handler.do_POST()

    assert result["code"] == HTTPStatus.OK
    assert seen["url"] == "http://keep-api:8080/alerts/event/grafana-irm"
    assert seen["method"] == "POST"
    assert seen["headers"]["X-api-key"] == "keep-key"
    assert seen["payload"]["id"] == "AG1"
    assert seen["payload"]["name"] == "Disk space low"
    assert seen["payload"]["status"] == "firing"
    assert seen["payload"]["severity"] == "critical"
    assert seen["payload"]["service"] == "Domains Shared"
    assert seen["payload"]["hostName"] == "srv-01"
    assert "uip_source" in seen["payload"]["description"]


def test_grafana_irm_resolved_event_maps_to_ok_status(monkeypatch):
    module = load_runbook_api()
    monkeypatch.setattr(module, "GRAFANA_IRM_WEBHOOK_SECRET", "expected-secret")
    monkeypatch.setattr(module, "KEEP_URL", "http://keep-api:8080")

    seen = {}

    class FakeResponse:
        status = 202

        def read(self):
            return b"{}"

    def fake_urlopen(req, timeout=0):
        seen["payload"] = json.loads(req.data.decode())
        return FakeResponse()

    monkeypatch.setattr(module, "urlopen", fake_urlopen)

    payload = {
        "event": {"type": "Resolved", "time": "2026-04-02T18:25:00Z"},
        "alert_group": {
            "id": "AG2",
            "title": "Disk space low",
            "state": "resolved",
            "resolved_at": "2026-04-02T18:25:00Z",
        },
        "integration": {"name": "Domains Shared"},
    }
    handler, result = make_handler(
        module,
        "/api/runbook/grafana-irm/alert-group-event",
        payload_obj=payload,
        headers={
            "X-UIP-Webhook-Source": "grafana-irm",
            "X-UIP-Webhook-Secret": "expected-secret",
        },
    )

    handler.do_POST()

    assert result["code"] == HTTPStatus.OK
    assert seen["payload"]["id"] == "AG2"
    assert seen["payload"]["status"] == "ok"


def test_grafana_irm_webhook_accepts_plain_text_keep_responses(monkeypatch):
    module = load_runbook_api()
    monkeypatch.setattr(module, "GRAFANA_IRM_WEBHOOK_SECRET", "expected-secret")
    monkeypatch.setattr(module, "KEEP_URL", "http://keep-api:8080")

    class FakeResponse:
        status = 202

        def read(self):
            return b"created"

    monkeypatch.setattr(module, "urlopen", lambda req, timeout=0: FakeResponse())

    handler, result = make_handler(
        module,
        "/api/runbook/grafana-irm/alert-group-event",
        payload_obj={
            "event": {"type": "Alert group created"},
            "alert_group": {"id": "AG3", "title": "Disk low"},
            "integration": {"name": "Domains Shared"},
        },
        headers={
            "X-UIP-Webhook-Source": "grafana-irm",
            "X-UIP-Webhook-Secret": "expected-secret",
        },
    )

    handler.do_POST()

    assert result["code"] == HTTPStatus.OK


def test_grafana_irm_webhook_rejects_missing_alert_group_id(monkeypatch):
    module = load_runbook_api()
    monkeypatch.setattr(module, "GRAFANA_IRM_WEBHOOK_SECRET", "expected-secret")

    handler, result = make_handler(
        module,
        "/api/runbook/grafana-irm/alert-group-event",
        payload_obj={"event": {"type": "Resolved"}, "alert_group": {}},
        headers={
            "X-UIP-Webhook-Source": "grafana-irm",
            "X-UIP-Webhook-Secret": "expected-secret",
        },
    )

    handler.do_POST()

    assert result["code"] == HTTPStatus.BAD_REQUEST
