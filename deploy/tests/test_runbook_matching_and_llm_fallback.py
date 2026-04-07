import importlib.util
import json
import sqlite3
from pathlib import Path
from urllib.error import HTTPError
from io import BytesIO

import deploy.enricher as enricher


RUNBOOK_API_PATH = Path(__file__).resolve().parents[1] / "runbook-api" / "runbook-api.py"


def load_runbook_api():
    spec = importlib.util.spec_from_file_location("runbook_api_module", RUNBOOK_API_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def make_runbook_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute(
        """
        CREATE TABLE runbook_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_name TEXT NOT NULL,
            alert_fingerprint TEXT,
            hostname TEXT,
            service TEXT,
            severity TEXT,
            remediation TEXT NOT NULL,
            sre_user TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
        """
    )
    db.execute(
        """
        CREATE TABLE runbook_manual_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_pattern TEXT NOT NULL,
            hostname TEXT DEFAULT '',
            service TEXT DEFAULT '',
            runbook_entry_id INTEGER NOT NULL,
            attached_by TEXT NOT NULL,
            attach_count INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            UNIQUE(alert_pattern, hostname, service, runbook_entry_id)
        )
        """
    )
    return db


def test_match_entries_prefers_specific_host_entry_over_generic_overlap():
    runbook_api = load_runbook_api()
    db = make_runbook_db()
    db.execute(
        """
        INSERT INTO runbook_entries (alert_name, hostname, remediation, sre_user, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "Pod is crash looping",
            "",
            "Restart the deployment and review recent rollout health.",
            "generic",
            "2026-03-30 10:00:00",
        ),
    )
    db.execute(
        """
        INSERT INTO runbook_entries (alert_name, hostname, remediation, sre_user, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "Node [ip-10-108-24-11.ec2.internal] Pod [order-api-tdp-865488c957-nhh2l]: Pod is crash looping",
            "tdp-prod_kubernetes nodes",
            "Rollback the order-api deployment on the affected node pool.",
            "specific",
            "2026-03-31 10:00:00",
        ),
    )

    results = runbook_api.match_entries(
        db,
        "Node [ip-10-108-24-11.ec2.internal] Pod [order-api-tdp-7b8d4f66db-abc12]: Pod is crash looping",
        hostname="tdp-prod_kubernetes nodes",
        service="order-api",
        limit=5,
    )

    assert results[0]["hostname"] == "tdp-prod_kubernetes nodes"
    assert "Rollback the order-api deployment" in results[0]["remediation"]


def test_match_entries_boosts_entries_manually_attached_for_same_alert_pattern():
    runbook_api = load_runbook_api()
    db = make_runbook_db()
    generic_id = db.execute(
        """
        INSERT INTO runbook_entries (alert_name, hostname, remediation, sre_user, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "TangoTelProxy connection failure",
            "",
            "Restart the affected proxy service and verify upstream reachability.",
            "generic",
            "2026-03-30 10:00:00",
        ),
    ).lastrowid
    preferred_id = db.execute(
        """
        INSERT INTO runbook_entries (alert_name, hostname, service, remediation, sre_user, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "Registry TLS handshake failures",
            "",
            "registry-proxy",
            "Drain the tangotel proxy, restart the connector, and verify TLS to the registry.",
            "specific",
            "2026-03-29 10:00:00",
        ),
    ).lastrowid
    db.execute(
        """
        INSERT INTO runbook_manual_links (alert_pattern, hostname, service, runbook_entry_id, attached_by, attach_count)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            runbook_api.normalize_alert_pattern(
                "TangoTelProxy connection failure on bra01.tucows.systems",
                "bra01.tucows.systems",
            ),
            "",
            "registry-proxy",
            preferred_id,
            "fash",
            3,
        ),
    )

    results = runbook_api.match_entries(
        db,
        "TangoTelProxy connection failure on bra01.tucows.systems",
        hostname="bra01.tucows.systems",
        service="registry-proxy",
        limit=5,
    )

    assert results[0]["id"] == preferred_id
    assert all(entry["id"] in {generic_id, preferred_id} for entry in results[:2])


def test_ollama_generate_falls_back_to_generate_when_chat_returns_404(monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode()

    def fake_urlopen(req, timeout=0):
        url = req.full_url
        calls.append(url)
        if url.endswith("/api/chat"):
            raise HTTPError(url, 404, "Not Found", hdrs=None, fp=None)
        if url.endswith("/api/generate"):
            return FakeResponse({"response": "ready"})
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(enricher, "urlopen", fake_urlopen)
    monkeypatch.setattr(enricher.time, "sleep", lambda *_args, **_kwargs: None)

    result = enricher.ollama_generate("say ready", timeout=1)

    assert result == "ready"
    assert calls == [
        f"{enricher.OLLAMA_URL}/api/chat",
        f"{enricher.OLLAMA_URL}/api/generate",
    ]


def test_wait_for_ollama_does_not_fallback_to_local_qwen_models(monkeypatch):
    original_model = enricher.OLLAMA_MODEL
    original_active_model = enricher.ACTIVE_OLLAMA_MODEL
    monkeypatch.setattr(enricher, "OLLAMA_MODEL", "qwen-tooling")
    monkeypatch.setattr(enricher, "ACTIVE_OLLAMA_MODEL", "qwen-tooling")

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode()

    def fake_urlopen(req, timeout=0):
        if isinstance(req, str):
            url = req
        else:
            url = req.full_url
        if url.endswith("/api/tags"):
            return FakeResponse({"models": [{"name": "qwen2.5:3b"}, {"name": "qwen2.5:7b"}]})
        raise AssertionError(f"unexpected request {url}")

    monkeypatch.setattr(enricher, "urlopen", fake_urlopen)
    monkeypatch.setattr(enricher.time, "sleep", lambda *_args, **_kwargs: None)

    assert enricher.wait_for_ollama() is False
    assert enricher.ACTIVE_OLLAMA_MODEL == "qwen-tooling"

    monkeypatch.setattr(enricher, "OLLAMA_MODEL", original_model)
    monkeypatch.setattr(enricher, "ACTIVE_OLLAMA_MODEL", original_active_model)


def test_runbook_ollama_generate_uses_configured_default_model(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "qwen-tooling")
    monkeypatch.setenv("OLLAMA_URL", "http://aicompute01.cnco1.tucows.cloud:31434")
    runbook_api = load_runbook_api()
    seen = {}

    class FakeResponse:
        def read(self):
            return json.dumps({"response": "cluster ready"}).encode()

    def fake_urlopen(req, timeout=0):
        seen["url"] = req.full_url
        seen["payload"] = json.loads(req.data.decode())
        return FakeResponse()

    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    result = runbook_api.ollama_generate("say ready")

    assert result == "cluster ready"
    assert seen["url"] == "http://aicompute01.cnco1.tucows.cloud:31434/api/chat"
    assert seen["payload"]["model"] == "qwen-tooling"
    assert seen["payload"]["messages"][0]["content"] == "say ready"
    assert seen["payload"]["options"]["num_predict"] == 512


def test_runbook_ollama_generate_falls_back_to_generate_when_chat_returns_404(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "qwen-tooling")
    monkeypatch.setenv("OLLAMA_URL", "http://aicompute01.cnco1.tucows.cloud:31434")
    runbook_api = load_runbook_api()
    calls = []

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode()

    def fake_urlopen(req, timeout=0):
        url = req.full_url
        calls.append(url)
        if url.endswith("/api/chat"):
            raise HTTPError(url, 404, "Not Found", hdrs=None, fp=None)
        if url.endswith("/api/generate"):
            return FakeResponse({"response": "fallback ready"})
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    result = runbook_api.ollama_generate("say ready")

    assert result == "fallback ready"
    assert calls == [
        "http://aicompute01.cnco1.tucows.cloud:31434/api/chat",
        "http://aicompute01.cnco1.tucows.cloud:31434/api/generate",
    ]


def test_assess_incident_description_uses_fast_timeout_and_small_response_budget(monkeypatch):
    runbook_api = load_runbook_api()
    seen = {}

    def fake_ollama_generate(prompt, model=None, timeout=0, num_predict=0, temperature=0):
        seen["timeout"] = timeout
        seen["num_predict"] = num_predict
        seen["temperature"] = temperature
        seen["prompt"] = prompt
        return '{"grade":"A","feedback":"ready"}'

    monkeypatch.setattr(runbook_api, "ollama_generate", fake_ollama_generate)

    result = runbook_api.assess_incident_description("Customer outage", "Customer-facing description")

    assert result["grade"] == "A"
    assert seen["timeout"] == 7
    assert seen["num_predict"] == 96
    assert seen["temperature"] == 0.1
    assert "Reply as JSON only" in seen["prompt"]
    assert "quick initial incident notice" in seen["prompt"]


def test_assess_incident_description_falls_back_to_fast_heuristic_when_llm_times_out(monkeypatch):
    runbook_api = load_runbook_api()

    monkeypatch.setattr(runbook_api, "ollama_generate", lambda *args, **kwargs: None)

    result = runbook_api.assess_incident_description(
        "DNS disruption",
        "Customers may experience intermittent DNS update delays while we investigate elevated error rates.",
    )

    assert result["grade"] in {"A", "B", "C", "D", "F"}
    assert "AI assessment unavailable" not in result["feedback"]


def test_assess_incident_description_accepts_vague_initial_notice_language(monkeypatch):
    runbook_api = load_runbook_api()

    monkeypatch.setattr(runbook_api, "ollama_generate", lambda *args, **kwargs: None)

    result = runbook_api.assess_incident_description(
        "Service disruption",
        "Customers may experience intermittent service disruption while we investigate elevated error rates.",
    )

    assert result["grade"] in {"A", "B"}
    assert "internal tooling or platform jargon" not in result["feedback"].lower()


def test_generate_situation_summary_uses_longer_timeout_for_cluster_model(monkeypatch):
    monkeypatch.setattr(enricher, "_last_summary_hash", "")
    monkeypatch.setattr(enricher, "_last_summary_time", 0)
    monkeypatch.setattr(enricher.time, "time", lambda: 10_000)
    monkeypatch.setattr(enricher, "get_host", lambda alert: alert.get("hostName", ""))
    seen = {}

    def fake_ollama_generate(prompt, timeout=0):
        seen["timeout"] = timeout
        return json.dumps(
            {
                "one_liner": "ready",
                "clusters": [],
                "shift_context": {
                    "new_since_last": 0,
                    "resolved_since_last": 0,
                    "trend": "stable",
                    "recurring": [],
                },
                "recommended_actions": [],
                "suggested_merges": [],
            }
        )

    class FakeResponse:
        def read(self):
            return b"{}"

    def fake_urlopen(req, timeout=0):
        seen["store_url"] = req.full_url
        return FakeResponse()

    monkeypatch.setattr(enricher, "ollama_generate", fake_ollama_generate)
    monkeypatch.setattr(enricher, "urlopen", fake_urlopen)

    summary = enricher.generate_situation_summary(
        [{"label": "cluster-a", "count": 2, "top_severity": "critical", "alert_names": ["a", "b"]}],
        [{"fingerprint": "fp-1", "name": "CPU high", "hostName": "host-1", "note": ""}],
        0,
    )

    assert summary is not None
    assert seen["timeout"] == 45
    assert seen["store_url"].endswith("/api/alert-states/situation-summary")


def test_send_incident_webhook_preview_mode_captures_when_secret_is_placeholder(monkeypatch):
    runbook_api = load_runbook_api()
    monkeypatch.setattr(runbook_api, "GRAFANA_WEBHOOK_SECRET", "placeholder")
    monkeypatch.setattr(runbook_api, "_webhook_test_buffer", [])

    ok, error = runbook_api.send_incident_webhook(
        "Preview incident",
        "Preview description",
        "2026-04-01T01:00:00Z",
        preview_only=True,
    )

    assert ok is True
    assert error is None
    assert len(runbook_api._webhook_test_buffer) == 1
    assert runbook_api._webhook_test_buffer[0]["headers"]["X-Preview-Mode"] == "incident-fallback"


def test_send_incident_webhook_directly_fans_out_when_secret_is_placeholder(monkeypatch):
    runbook_api = load_runbook_api()
    monkeypatch.setattr(runbook_api, "GRAFANA_WEBHOOK_SECRET", "placeholder")
    monkeypatch.setattr(runbook_api, "_fetch_webhook_signing_secrets", lambda: {})

    seen = []

    class FakeResponse:
        def __init__(self, payload=b"{}"):
            self._payload = payload

        def read(self):
            return self._payload

    def fake_urlopen(req, timeout=0):
        seen.append((req.full_url, req.get_method(), dict(req.header_items()), json.loads(req.data.decode()) if req.data else None))
        if req.full_url.endswith("/api/webhooks/subscribers"):
            return FakeResponse(json.dumps([
                {"id": 1, "name": "Active A", "url": "https://hooks.example/a", "is_active": True},
                {"id": 2, "name": "Inactive B", "url": "https://hooks.example/b", "is_active": False},
                {"id": 3, "name": "Active C", "url": "https://hooks.example/c", "is_active": True},
            ]).encode())
        if req.full_url in {"https://hooks.example/a", "https://hooks.example/c"}:
            return FakeResponse()
        raise AssertionError(f"unexpected request {req.full_url}")

    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    ok, error = runbook_api.send_incident_webhook(
        "Customer outage",
        "Customer-facing impact summary",
        "2026-04-01T01:00:00Z",
    )

    assert ok is True
    assert error is None
    assert [url for url, *_rest in seen] == [
        "http://10.177.154.174/api/webhooks/subscribers",
        "https://hooks.example/a",
        "https://hooks.example/c",
    ]
    assert seen[1][3]["incident"]["title"] == "Customer outage"
    assert seen[2][3]["incident"]["title"] == "Customer outage"


def test_send_incident_webhook_directly_skips_builtin_local_test_subscriber(monkeypatch):
    runbook_api = load_runbook_api()
    monkeypatch.setattr(runbook_api, "GRAFANA_WEBHOOK_SECRET", "placeholder")
    monkeypatch.setattr(runbook_api, "_fetch_webhook_signing_secrets", lambda: {})

    seen = []

    class FakeResponse:
        def __init__(self, payload=b"{}"):
            self._payload = payload

        def read(self):
            return self._payload

    def fake_urlopen(req, timeout=0):
        seen.append(req.full_url)
        if req.full_url.endswith("/api/webhooks/subscribers"):
            return FakeResponse(json.dumps([
                {"id": 1, "name": "Local Test", "url": "http://app:8000/api/webhooks/receive-test", "is_active": True},
                {"id": 2, "name": "Customer Preview", "url": "https://hooks.example/c", "is_active": True},
            ]).encode())
        if req.full_url == "https://hooks.example/c":
            return FakeResponse()
        raise AssertionError(f"unexpected request {req.full_url}")

    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    ok, error = runbook_api.send_incident_webhook(
        "Customer outage",
        "Customer-facing impact summary",
        "2026-04-01T01:00:00Z",
    )

    assert ok is True
    assert error is None
    assert seen == [
        "http://10.177.154.174/api/webhooks/subscribers",
        "https://hooks.example/c",
    ]


def test_send_incident_webhook_directly_signs_with_mirrored_subscriber_secret(monkeypatch):
    runbook_api = load_runbook_api()
    monkeypatch.setattr(runbook_api, "GRAFANA_WEBHOOK_SECRET", "placeholder")
    monkeypatch.setattr(
        runbook_api,
        "_fetch_webhook_signing_secrets",
        lambda: {
            "1": {
                "secret": "secret-a",
                "name": "Active A",
                "url": "https://hooks.example/a",
            }
        },
    )

    seen = []

    class FakeResponse:
        def __init__(self, payload=b"{}"):
            self._payload = payload

        def read(self):
            return self._payload

    def fake_urlopen(req, timeout=0):
        seen.append((req.full_url, dict(req.header_items())))
        if req.full_url.endswith("/api/webhooks/subscribers"):
            return FakeResponse(json.dumps([
                {"id": 1, "name": "Active A", "url": "https://hooks.example/a", "is_active": True},
            ]).encode())
        if req.full_url == "https://hooks.example/a":
            return FakeResponse()
        raise AssertionError(f"unexpected request {req.full_url}")

    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    ok, error = runbook_api.send_incident_webhook(
        "Customer outage",
        "Customer-facing impact summary",
        "2026-04-01T01:00:00Z",
    )

    assert ok is True
    assert error is None
    assert "x-webhook-signature" in {key.lower() for key in seen[1][1]}


def test_send_incident_webhook_preview_mode_captures_when_upstream_rejects_secret(monkeypatch):
    runbook_api = load_runbook_api()
    monkeypatch.setattr(runbook_api, "GRAFANA_WEBHOOK_SECRET", "real-looking-secret")
    monkeypatch.setattr(runbook_api, "_webhook_test_buffer", [])

    def fake_urlopen(req, timeout=0):
        raise HTTPError(req.full_url, 401, "Unauthorized", hdrs=None, fp=BytesIO(b'{"detail":"Invalid or missing X-Grafana-Secret"}'))

    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    ok, error = runbook_api.send_incident_webhook(
        "Preview incident",
        "Preview description",
        "2026-04-01T01:00:00Z",
        preview_only=True,
    )

    assert ok is True
    assert error is None
    assert len(runbook_api._webhook_test_buffer) == 1


def test_jira_request_auth_requires_authenticated_user(monkeypatch):
    runbook_api = load_runbook_api()

    class DummyHandler:
        headers = {}

    monkeypatch.setattr(runbook_api, "_get_username_from_request", lambda _handler: None)

    username, oauth_token, cloud_id, auth_error = runbook_api._resolve_request_jira_oauth(DummyHandler())

    assert username is None
    assert oauth_token is None
    assert cloud_id is None
    assert auth_error == (401, "Not authenticated")


def test_create_jira_incident_can_disable_global_fallback(monkeypatch):
    runbook_api = load_runbook_api()
    monkeypatch.setattr(runbook_api, "JIRA_EMAIL", "fash@example.com")
    monkeypatch.setattr(runbook_api, "JIRA_API_TOKEN", "global-token")

    result, error = runbook_api.create_jira_incident(
        {"summary": "Customer outage", "description": "Something happened"},
        allow_global_fallback=False,
    )

    assert result is None
    assert error == "Jira integration not configured — connect your Jira account in Settings"


def test_jira_request_auth_returns_users_oauth_token(monkeypatch):
    runbook_api = load_runbook_api()

    class DummyHandler:
        headers = {}

    monkeypatch.setattr(runbook_api, "_get_username_from_request", lambda _handler: "jpratt")

    class FakeResponse:
        def read(self):
            return json.dumps({"access_token": "user-oauth", "cloud_id": "cloud-123"}).encode()

    def fake_urlopen(req, timeout=0):
        assert req.full_url.endswith("/api/auth/jira-token?username=jpratt")
        return FakeResponse()

    monkeypatch.setattr(runbook_api, "urlopen", fake_urlopen)

    username, oauth_token, cloud_id, auth_error = runbook_api._resolve_request_jira_oauth(DummyHandler())

    assert username == "jpratt"
    assert oauth_token == "user-oauth"
    assert cloud_id == "cloud-123"
    assert auth_error is None


def test_poll_and_enrich_applies_routing_rules_before_summary_generation(monkeypatch):
    order = []

    monkeypatch.setattr(
        enricher,
        "keep_request",
        lambda path, method="GET", data=None: [
            {
                "fingerprint": "fp-1",
                "name": "CPU high",
                "status": "firing",
                "source": ["zabbix"],
                "lastReceived": "2026-03-31T17:00:00.000Z",
            }
        ] if path == "/alerts?limit=250" else {},
    )
    monkeypatch.setattr(enricher, "fetch_force_enrich_fingerprints", lambda: set())
    monkeypatch.setattr(enricher, "fetch_silence_rules", lambda: [])
    monkeypatch.setattr(enricher, "check_suppression", lambda alert: (False, "", ""))
    monkeypatch.setattr(enricher, "enrich_alert", lambda alert, similar: None)
    monkeypatch.setattr(enricher, "post_enrichment_to_keep", lambda alert, enrichment: True)
    monkeypatch.setattr(enricher, "cluster_alerts", lambda alerts: [])
    monkeypatch.setattr(enricher, "merge_related_clusters", lambda clusters: clusters)
    monkeypatch.setattr(enricher, "reconcile_stale_zabbix_alerts", lambda alerts: None)
    monkeypatch.setattr(enricher, "pattern_tracker", type("Tracker", (), {"find_similar": lambda *_args: [], "add": lambda *_args: None})())
    monkeypatch.setattr(enricher, "parse_sre_feedback", lambda note: None)
    monkeypatch.setattr(enricher, "is_alert_silenced", lambda alert, rules: False)

    def fake_apply(alerts):
        order.append("routing")

    def fake_summary(clusters, alerts, resolved_count):
        order.append("summary")
        return None

    monkeypatch.setattr(enricher, "apply_routing_rules", fake_apply)
    monkeypatch.setattr(enricher, "generate_situation_summary", fake_summary)
    monkeypatch.setattr(enricher, "enriched_cache", {})

    enricher.poll_and_enrich()

    assert order == ["routing", "summary"]
