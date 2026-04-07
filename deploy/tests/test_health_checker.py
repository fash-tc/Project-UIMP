import importlib.util
from pathlib import Path


HEALTH_CHECKER_PATH = Path(__file__).resolve().parents[1] / "health-checker.py"


def load_health_checker():
    spec = importlib.util.spec_from_file_location("health_checker_module", HEALTH_CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_health_checker_does_not_auto_http_check_loki_gateway(monkeypatch):
    health_checker = load_health_checker()

    assert "loki-gateway" not in health_checker.HTTP_CHECKS

    def fake_get_container_status():
        return {
            "loki-gateway": {
                "name": "Loki Gateway",
                "role": "Log Queries",
                "container": "uip-loki-gateway",
                "state": "running",
                "status": "Up 1 hour",
                "healthy": True,
            },
            "keep-api": {
                "name": "Keep API",
                "role": "Alert Backend",
                "container": "uip-keep-api",
                "state": "running",
                "status": "Up 1 hour",
                "healthy": True,
            },
        }

    monkeypatch.setattr(health_checker, "get_container_status", fake_get_container_status)
    monkeypatch.setattr(health_checker, "http_health_check", lambda _url: {"reachable": True, "status_code": 200, "response_ms": 0})
    monkeypatch.setattr(health_checker, "check_data_freshness", lambda: {"status": "ok"})

    report = health_checker.build_health_report()
    services = {svc["container"]: svc for svc in report["services"]}

    assert "http_check" not in services["uip-loki-gateway"]
    assert services["uip-loki-gateway"]["healthy"] is True
    assert services["uip-keep-api"]["http_check"]["status_code"] == 200
