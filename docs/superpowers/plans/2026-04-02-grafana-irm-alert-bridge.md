# Grafana IRM Alert Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest Grafana IRM alert-group lifecycle events into UIP, repair state by polling IRM, and prepare Domains Shared for cutover away from direct Zabbix delivery without duplicate board entries.

**Architecture:** `runbook-api` will expose a new authenticated Grafana IRM webhook endpoint that normalizes alert-group events into UIP alert lifecycle updates. `enricher.py` will gain a low-frequency IRM reconciliation loop that backfills active IRM alert groups and repairs missed webhook drift. Tests will cover webhook auth, state transitions, poll-based repair, and overlap-aware source handling.

**Tech Stack:** Python `BaseHTTPRequestHandler`, existing UIP Keep API integration, existing alert-state APIs, Grafana IRM/OnCall HTTP APIs, pytest

---

### File Structure

Implementation touches these files:

- Modify: `C:\Users\fash\Documents\UIP\deploy\runbook-api\runbook-api.py`
  - Add Grafana IRM webhook auth/config helpers
  - Add payload normalization helpers
  - Add `POST /api/runbook/grafana-irm/alert-group-event`
  - Add helper(s) to create/update/resolve UIP alerts using Keep APIs

- Modify: `C:\Users\fash\Documents\UIP\deploy\enricher.py`
  - Add Grafana IRM polling config
  - Add IRM service-account/API helpers
  - Add reconciliation loop for active alert groups
  - Add overlap-aware source preference/cutover guardrails

- Modify: `C:\Users\fash\Documents\UIP\deploy\docker-compose.yml`
  - Wire `GRAFANA_IRM_WEBHOOK_SECRET`
  - Wire IRM polling env vars/token/url

- Create: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py`
  - Focused tests for webhook auth, normalization, and lifecycle handling

- Create: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py`
  - Focused tests for IRM poll repair, backfill, and overlap behavior

- Modify: `C:\Users\fash\Documents\UIP\deploy\tests\test_runbook_matching_and_llm_fallback.py`
  - Only if existing server-test scaffolding is the best place to reuse request helpers

### Task 1: Add Grafana IRM Webhook API Contract

**Files:**
- Modify: `C:\Users\fash\Documents\UIP\deploy\runbook-api\runbook-api.py`
- Test: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py`

- [ ] **Step 1: Write the failing webhook auth and routing tests**

```python
from http import HTTPStatus
from pathlib import Path
import importlib.util
import json


RUNBOOK_API_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\runbook-api\runbook-api.py")


def load_runbook_api():
    spec = importlib.util.spec_from_file_location("runbook_api_under_test", RUNBOOK_API_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def make_handler(module, path, body, headers):
    handler = module.Handler.__new__(module.Handler)
    handler.path = path
    handler.headers = headers
    handler.rfile = __import__("io").BytesIO(body)
    handler.wfile = __import__("io").BytesIO()
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

    payload = json.dumps({"alert_group": {"id": "AG1"}}).encode()
    headers = {
        "Content-Length": str(len(payload)),
        "X-UIP-Webhook-Source": "grafana-irm",
        "X-UIP-Webhook-Secret": "wrong-secret",
    }
    handler, result = make_handler(module, "/api/runbook/grafana-irm/alert-group-event", payload, headers)

    handler.do_POST()

    assert result["code"] == HTTPStatus.UNAUTHORIZED


def test_grafana_irm_webhook_accepts_valid_secret(monkeypatch):
    module = load_runbook_api()
    monkeypatch.setattr(module, "GRAFANA_IRM_WEBHOOK_SECRET", "expected-secret")
    calls = []
    monkeypatch.setattr(module, "_handle_grafana_irm_alert_group_event", lambda payload: calls.append(payload) or {"ok": True})

    payload_obj = {"alert_group": {"id": "AG1"}, "event": {"type": "created"}}
    payload = json.dumps(payload_obj).encode()
    headers = {
        "Content-Length": str(len(payload)),
        "X-UIP-Webhook-Source": "grafana-irm",
        "X-UIP-Webhook-Secret": "expected-secret",
    }
    handler, result = make_handler(module, "/api/runbook/grafana-irm/alert-group-event", payload, headers)

    handler.do_POST()

    assert result["code"] == HTTPStatus.OK
    assert calls == [payload_obj]
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py -q
```

Expected: FAIL because the new endpoint and helpers do not exist yet.

- [ ] **Step 3: Write minimal webhook config and dispatch helpers**

Add these pieces near the other config/helper definitions in `runbook-api.py`:

```python
GRAFANA_IRM_WEBHOOK_SECRET = os.environ.get("GRAFANA_IRM_WEBHOOK_SECRET", "").strip()


def _grafana_irm_webhook_is_authorized(handler):
    expected = (GRAFANA_IRM_WEBHOOK_SECRET or "").strip()
    provided_source = (handler.headers.get("X-UIP-Webhook-Source", "") or "").strip().lower()
    provided_secret = (handler.headers.get("X-UIP-Webhook-Secret", "") or "").strip()
    return bool(expected) and provided_source == "grafana-irm" and hmac_mod.compare_digest(provided_secret, expected)


def _handle_grafana_irm_alert_group_event(payload):
    return {"ok": True, "payload": payload}
```

And add the route in `do_POST`:

```python
        elif path == "/api/runbook/grafana-irm/alert-group-event":
            if not _grafana_irm_webhook_is_authorized(self):
                self._send_json(401, {"error": "Invalid Grafana IRM webhook auth"})
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                payload = json.loads(raw_body.decode("utf-8") or "{}")
            except Exception:
                self._send_json(400, {"error": "Malformed JSON payload"})
                return

            result = _handle_grafana_irm_alert_group_event(payload)
            self._send_json(200, result if isinstance(result, dict) else {"ok": True})
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py -q
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add deploy/runbook-api/runbook-api.py deploy/tests/test_grafana_irm_webhook_api.py
git commit -m "feat: add grafana irm webhook endpoint shell"
```

### Task 2: Normalize Grafana IRM Lifecycle Events Into UIP Actions

**Files:**
- Modify: `C:\Users\fash\Documents\UIP\deploy\runbook-api\runbook-api.py`
- Test: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py`

- [ ] **Step 1: Extend the failing tests for create, resolve, and reopen normalization**

Add to `test_grafana_irm_webhook_api.py`:

```python
def test_grafana_irm_event_create_maps_to_upsert(monkeypatch):
    module = load_runbook_api()
    recorded = []
    monkeypatch.setattr(module, "_upsert_grafana_irm_alert_in_keep", lambda event: recorded.append(("upsert", event)))
    monkeypatch.setattr(module, "_resolve_grafana_irm_alert_in_keep", lambda event: recorded.append(("resolve", event)))

    payload = {
        "event": {"type": "Alert group created"},
        "alert_group": {"id": "AG1", "title": "Disk low", "state": "firing"},
        "integration": {"name": "domains-shared"},
    }

    result = module._handle_grafana_irm_alert_group_event(payload)

    assert result["ok"] is True
    assert recorded[0][0] == "upsert"
    assert recorded[0][1]["upstream_id"] == "AG1"


def test_grafana_irm_event_resolved_maps_to_resolve(monkeypatch):
    module = load_runbook_api()
    recorded = []
    monkeypatch.setattr(module, "_upsert_grafana_irm_alert_in_keep", lambda event: recorded.append(("upsert", event)))
    monkeypatch.setattr(module, "_resolve_grafana_irm_alert_in_keep", lambda event: recorded.append(("resolve", event)))

    payload = {
        "event": {"type": "Resolved"},
        "alert_group": {"id": "AG2", "title": "Disk low", "state": "resolved"},
        "integration": {"name": "domains-shared"},
    }

    result = module._handle_grafana_irm_alert_group_event(payload)

    assert result["ok"] is True
    assert recorded == [("resolve", recorded[0][1])]
    assert recorded[0][1]["upstream_id"] == "AG2"
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py -q
```

Expected: FAIL because normalization and lifecycle handlers are still stubs.

- [ ] **Step 3: Implement normalization and lifecycle dispatch**

Replace the stub handler in `runbook-api.py` with:

```python
def _normalize_grafana_irm_event(payload):
    alert_group = payload.get("alert_group") or {}
    integration = payload.get("integration") or {}
    event = payload.get("event") or {}
    event_type = str(event.get("type") or "").strip()
    upstream_id = str(alert_group.get("id") or "").strip()
    if not upstream_id:
        raise ValueError("Missing alert_group.id")

    return {
        "event_type": event_type,
        "upstream_source": "grafana-irm",
        "upstream_id": upstream_id,
        "upstream_integration": integration.get("name") or integration.get("id") or "",
        "title": alert_group.get("title") or alert_group.get("name") or "Grafana IRM alert group",
        "state": alert_group.get("state") or "",
        "created_at": alert_group.get("created_at") or "",
        "resolved_at": alert_group.get("resolved_at") or "",
        "payload": payload,
    }


def _upsert_grafana_irm_alert_in_keep(event):
    return {"ok": True, "action": "upsert", "event": event}


def _resolve_grafana_irm_alert_in_keep(event):
    return {"ok": True, "action": "resolve", "event": event}


def _handle_grafana_irm_alert_group_event(payload):
    event = _normalize_grafana_irm_event(payload)
    event_type = (event.get("event_type") or "").lower()
    if event_type in ("resolved",):
        _resolve_grafana_irm_alert_in_keep(event)
        return {"ok": True, "action": "resolved", "upstream_id": event["upstream_id"]}
    if event_type in ("alert group created", "unresolved", "status change"):
        _upsert_grafana_irm_alert_in_keep(event)
        return {"ok": True, "action": "upserted", "upstream_id": event["upstream_id"]}
    _upsert_grafana_irm_alert_in_keep(event)
    return {"ok": True, "action": "upserted", "upstream_id": event["upstream_id"]}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py -q
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add deploy/runbook-api/runbook-api.py deploy/tests/test_grafana_irm_webhook_api.py
git commit -m "feat: normalize grafana irm webhook lifecycle events"
```

### Task 3: Persist IRM-Backed UIP Alerts Through Keep Enrichment

**Files:**
- Modify: `C:\Users\fash\Documents\UIP\deploy\runbook-api\runbook-api.py`
- Test: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py`

- [ ] **Step 1: Add failing tests for the Keep payload shape**

Add:

```python
def test_upsert_grafana_irm_alert_posts_expected_keep_payload(monkeypatch):
    module = load_runbook_api()
    calls = []
    monkeypatch.setattr(module, "keep_request", lambda path, method="GET", data=None, headers=None: calls.append((path, method, data)) or {"status": "ok"})

    event = {
        "upstream_source": "grafana-irm",
        "upstream_id": "AG100",
        "upstream_integration": "domains-shared",
        "title": "Disk low",
        "state": "firing",
        "payload": {"alert_group": {"id": "AG100"}},
    }

    module._upsert_grafana_irm_alert_in_keep(event)

    assert calls == [
        (
            "/alerts/enrich",
            "POST",
            {
                "fingerprint": "grafana-irm:AG100",
                "enrichments": {
                    "name": "Disk low",
                    "status": "firing",
                    "providerType": "grafana-irm",
                    "source": ["grafana-irm"],
                    "note": '{"upstream_source":"grafana-irm","upstream_id":"AG100","upstream_integration":"domains-shared"}',
                },
            },
        )
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py -q
```

Expected: FAIL because `_upsert_grafana_irm_alert_in_keep` is still a stub.

- [ ] **Step 3: Implement the Keep upsert/resolve helpers**

Replace the stubs in `runbook-api.py` with:

```python
def _grafana_irm_fingerprint(upstream_id):
    return f"grafana-irm:{upstream_id}"


def _grafana_irm_note_metadata(event):
    return json.dumps({
        "upstream_source": event.get("upstream_source", "grafana-irm"),
        "upstream_id": event.get("upstream_id", ""),
        "upstream_integration": event.get("upstream_integration", ""),
    }, separators=(",", ":"))


def _upsert_grafana_irm_alert_in_keep(event):
    return keep_request(
        "/alerts/enrich",
        method="POST",
        data={
            "fingerprint": _grafana_irm_fingerprint(event["upstream_id"]),
            "enrichments": {
                "name": event.get("title") or "Grafana IRM alert group",
                "status": "firing",
                "providerType": "grafana-irm",
                "source": ["grafana-irm"],
                "note": _grafana_irm_note_metadata(event),
            },
        },
    )


def _resolve_grafana_irm_alert_in_keep(event):
    return keep_request(
        "/alerts/enrich",
        method="POST",
        data={
            "fingerprint": _grafana_irm_fingerprint(event["upstream_id"]),
            "enrichments": {"status": "resolved"},
        },
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py -q
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add deploy/runbook-api/runbook-api.py deploy/tests/test_grafana_irm_webhook_api.py
git commit -m "feat: upsert grafana irm alert groups into keep"
```

### Task 4: Add IRM Polling Configuration And Fetch Helpers

**Files:**
- Modify: `C:\Users\fash\Documents\UIP\deploy\enricher.py`
- Modify: `C:\Users\fash\Documents\UIP\deploy\docker-compose.yml`
- Test: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py`

- [ ] **Step 1: Write failing tests for IRM polling config and fetch shell**

Create `test_grafana_irm_polling.py` with:

```python
from deploy import enricher


def test_grafana_irm_polling_defaults_are_defined():
    assert enricher.GRAFANA_IRM_POLL_INTERVAL_SECONDS == 300
    assert enricher.GRAFANA_IRM_URL == ""
    assert enricher.GRAFANA_IRM_API_TOKEN == ""


def test_grafana_irm_group_fingerprint_is_stable():
    assert enricher._grafana_irm_fingerprint("AG123") == "grafana-irm:AG123"
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py -q
```

Expected: FAIL because the new config and helper do not exist.

- [ ] **Step 3: Add minimal IRM poller config and fingerprint helper**

Add near the top of `enricher.py`:

```python
GRAFANA_IRM_URL = os.environ.get("GRAFANA_IRM_URL", "").strip().rstrip("/")
GRAFANA_IRM_API_TOKEN = os.environ.get("GRAFANA_IRM_API_TOKEN", "").strip()
GRAFANA_IRM_POLL_INTERVAL_SECONDS = int(os.environ.get("GRAFANA_IRM_POLL_INTERVAL_SECONDS", "300"))
_last_grafana_irm_poll_run = 0


def _grafana_irm_fingerprint(alert_group_id):
    return f"grafana-irm:{alert_group_id}"
```

Add to `docker-compose.yml` under the `alert-enricher` service:

```yaml
      GRAFANA_IRM_URL: ${GRAFANA_IRM_URL:-}
      GRAFANA_IRM_API_TOKEN: ${GRAFANA_IRM_API_TOKEN:-}
      GRAFANA_IRM_POLL_INTERVAL_SECONDS: ${GRAFANA_IRM_POLL_INTERVAL_SECONDS:-300}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py -q
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add deploy/enricher.py deploy/docker-compose.yml deploy/tests/test_grafana_irm_polling.py
git commit -m "feat: add grafana irm polling configuration"
```

### Task 5: Implement Active Alert-Group Repair Polling

**Files:**
- Modify: `C:\Users\fash\Documents\UIP\deploy\enricher.py`
- Test: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py`

- [ ] **Step 1: Write failing tests for backfill and drift repair**

Add:

```python
def test_reconcile_grafana_irm_backfills_open_groups(monkeypatch):
    groups = [{"id": "AG1", "title": "Disk low", "state": "firing", "integration": {"name": "domains-shared"}}]
    monkeypatch.setattr(enricher, "_fetch_grafana_irm_active_alert_groups", lambda: groups)
    calls = []
    monkeypatch.setattr(enricher, "_upsert_grafana_irm_group_in_keep", lambda group: calls.append(("upsert", group["id"])))
    monkeypatch.setattr(enricher, "_resolve_grafana_irm_group_in_keep", lambda group: calls.append(("resolve", group["id"])))
    monkeypatch.setattr(enricher, "_fetch_existing_grafana_irm_open_fingerprints", lambda: set())
    monkeypatch.setattr(enricher.time, "time", lambda: 1711908000)
    monkeypatch.setattr(enricher, "_last_grafana_irm_poll_run", 0)

    enricher.reconcile_grafana_irm_alert_groups()

    assert calls == [("upsert", "AG1")]


def test_reconcile_grafana_irm_resolves_missing_open_group(monkeypatch):
    monkeypatch.setattr(enricher, "_fetch_grafana_irm_active_alert_groups", lambda: [])
    monkeypatch.setattr(enricher, "_fetch_existing_grafana_irm_open_fingerprints", lambda: {"grafana-irm:AG2"})
    calls = []
    monkeypatch.setattr(enricher, "_upsert_grafana_irm_group_in_keep", lambda group: calls.append(("upsert", group["id"])))
    monkeypatch.setattr(enricher, "_resolve_grafana_irm_group_in_keep", lambda group: calls.append(("resolve", group["id"])))
    monkeypatch.setattr(enricher.time, "time", lambda: 1711908000)
    monkeypatch.setattr(enricher, "_last_grafana_irm_poll_run", 0)

    enricher.reconcile_grafana_irm_alert_groups()

    assert calls == [("resolve", "AG2")]
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py -q
```

Expected: FAIL because fetch/reconcile helpers do not exist.

- [ ] **Step 3: Implement the fetch and reconcile loop**

Add to `enricher.py`:

```python
def _grafana_irm_headers():
    return {
        "Authorization": f"Bearer {GRAFANA_IRM_API_TOKEN}",
        "Accept": "application/json",
    }


def _fetch_grafana_irm_active_alert_groups():
    if not GRAFANA_IRM_URL or not GRAFANA_IRM_API_TOKEN:
        return []
    req = Request(
        f"{GRAFANA_IRM_URL}/api/v1/alert_groups/?state=alerting",
        headers=_grafana_irm_headers(),
    )
    resp = urlopen(req, timeout=10)
    payload = json.loads(resp.read().decode("utf-8"))
    return payload.get("results", payload if isinstance(payload, list) else [])


def _fetch_existing_grafana_irm_open_fingerprints():
    alerts = keep_request("/alerts?limit=250") or []
    return {
        alert.get("fingerprint", "")
        for alert in alerts
        if alert.get("providerType") == "grafana-irm" and (alert.get("status") or "").lower() not in ("resolved", "ok")
    }


def _upsert_grafana_irm_group_in_keep(group):
    return keep_request(
        "/alerts/enrich",
        method="POST",
        data={
            "fingerprint": _grafana_irm_fingerprint(group["id"]),
            "enrichments": {
                "name": group.get("title") or "Grafana IRM alert group",
                "status": "firing",
                "providerType": "grafana-irm",
                "source": ["grafana-irm"],
            },
        },
    )


def _resolve_grafana_irm_group_in_keep(group):
    return keep_request(
        "/alerts/enrich",
        method="POST",
        data={
            "fingerprint": _grafana_irm_fingerprint(group["id"]),
            "enrichments": {"status": "resolved"},
        },
    )


def reconcile_grafana_irm_alert_groups():
    global _last_grafana_irm_poll_run
    now_epoch = time.time()
    if GRAFANA_IRM_POLL_INTERVAL_SECONDS > 0 and now_epoch - _last_grafana_irm_poll_run < GRAFANA_IRM_POLL_INTERVAL_SECONDS:
        return
    _last_grafana_irm_poll_run = now_epoch

    groups = _fetch_grafana_irm_active_alert_groups()
    active_fingerprints = set()
    for group in groups:
        active_fingerprints.add(_grafana_irm_fingerprint(group["id"]))
        _upsert_grafana_irm_group_in_keep(group)

    existing_open = _fetch_existing_grafana_irm_open_fingerprints()
    for fingerprint in sorted(existing_open - active_fingerprints):
        _resolve_grafana_irm_group_in_keep({"id": fingerprint.split(":", 1)[1]})
```

Call it from `poll_and_enrich()` after fetching alerts but before clustering:

```python
    reconcile_grafana_irm_alert_groups()
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py -q
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add deploy/enricher.py deploy/tests/test_grafana_irm_polling.py
git commit -m "feat: add grafana irm repair polling"
```

### Task 6: Add Domains Shared Overlap Guardrail

**Files:**
- Modify: `C:\Users\fash\Documents\UIP\deploy\enricher.py`
- Test: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py`

- [ ] **Step 1: Write failing tests for temporary overlap suppression preference**

Add:

```python
def test_prefers_grafana_irm_alert_over_domains_shared_overlap():
    irm_alert = {
        "fingerprint": "grafana-irm:AG1",
        "providerType": "grafana-irm",
        "name": "/data: Disk space is low",
        "hostName": "osrs-log01.prod-opensrs.bra2.tucows.systems",
        "status": "firing",
    }
    zabbix_alert = {
        "fingerprint": "zbx-1",
        "providerType": "zabbix",
        "zabbixInstance": "domains-shared",
        "name": "/data: Disk space is low",
        "hostName": "osrs-log01.prod-opensrs.bra2.tucows.systems",
        "status": "firing",
    }

    result = enricher.prefer_grafana_irm_over_domains_shared([zabbix_alert, irm_alert])

    assert result == [irm_alert]
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py -q
```

Expected: FAIL because the overlap suppression helper does not exist.

- [ ] **Step 3: Implement the temporary overlap suppression helper**

Add to `enricher.py`:

```python
def _domains_shared_overlap_key(alert):
    return (
        (alert.get("name") or "").strip().lower(),
        (alert.get("hostName") or alert.get("hostname") or "").strip().lower(),
    )


def prefer_grafana_irm_over_domains_shared(alerts):
    preferred = {}
    ordered = []
    for alert in alerts:
        key = _domains_shared_overlap_key(alert)
        if not key[0]:
            ordered.append(alert)
            continue
        current = preferred.get(key)
        if current is None:
            preferred[key] = alert
            continue
        current_is_irm = current.get("providerType") == "grafana-irm"
        candidate_is_irm = alert.get("providerType") == "grafana-irm"
        if candidate_is_irm and not current_is_irm:
            preferred[key] = alert
    seen_keys = set()
    result = []
    for alert in alerts:
        key = _domains_shared_overlap_key(alert)
        if key[0]:
            if key in seen_keys:
                continue
            chosen = preferred.get(key)
            if chosen is not None:
                result.append(chosen)
                seen_keys.add(key)
                continue
        result.append(alert)
    return result
```

Use it in `poll_and_enrich()` immediately after filtering active alerts:

```python
    active_alerts = prefer_grafana_irm_over_domains_shared(active_alerts)
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py -q
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add deploy/enricher.py deploy/tests/test_grafana_irm_polling.py
git commit -m "feat: prefer grafana irm alerts during domains shared overlap"
```

### Task 7: Wire Runtime Configuration And End-To-End Verification

**Files:**
- Modify: `C:\Users\fash\Documents\UIP\deploy\docker-compose.yml`
- Modify: `C:\Users\fash\Documents\UIP\deploy\runbook-api\runbook-api.py`
- Modify: `C:\Users\fash\Documents\UIP\deploy\enricher.py`
- Test: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py`
- Test: `C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py`

- [ ] **Step 1: Add final failing tests for env defaults and malformed payload handling**

Add to `test_grafana_irm_webhook_api.py`:

```python
def test_grafana_irm_webhook_rejects_missing_alert_group_id(monkeypatch):
    module = load_runbook_api()
    monkeypatch.setattr(module, "GRAFANA_IRM_WEBHOOK_SECRET", "expected-secret")
    payload = json.dumps({"event": {"type": "Resolved"}, "alert_group": {}}).encode()
    headers = {
        "Content-Length": str(len(payload)),
        "X-UIP-Webhook-Source": "grafana-irm",
        "X-UIP-Webhook-Secret": "expected-secret",
    }
    handler, result = make_handler(module, "/api/runbook/grafana-irm/alert-group-event", payload, headers)

    handler.do_POST()

    assert result["code"] == 400
```

- [ ] **Step 2: Run focused tests to verify the remaining gap**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py -q
```

Expected: FAIL because malformed normalized payloads are not yet surfaced as `400`.

- [ ] **Step 3: Add the final validation and env wiring**

Update `runbook-api.py` route block:

```python
            try:
                result = _handle_grafana_irm_alert_group_event(payload)
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
                return
            except Exception as e:
                log.exception("Grafana IRM webhook failed")
                self._send_json(500, {"error": str(e)})
                return
            self._send_json(200, result if isinstance(result, dict) else {"ok": True})
```

Add to `docker-compose.yml` under `runbook-api`:

```yaml
      GRAFANA_IRM_WEBHOOK_SECRET: ${GRAFANA_IRM_WEBHOOK_SECRET:-}
```

- [ ] **Step 4: Run full verification**

Run:
```bash
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_webhook_api.py C:\Users\fash\Documents\UIP\deploy\tests\test_grafana_irm_polling.py -q
python -m py_compile C:\Users\fash\Documents\UIP\deploy\runbook-api\runbook-api.py C:\Users\fash\Documents\UIP\deploy\enricher.py
```

Expected:
- pytest: PASS
- py_compile: no output

- [ ] **Step 5: Commit**

```bash
git add deploy/runbook-api/runbook-api.py deploy/enricher.py deploy/docker-compose.yml deploy/tests/test_grafana_irm_webhook_api.py deploy/tests/test_grafana_irm_polling.py
git commit -m "feat: wire grafana irm alert bridge"
```

## Self-Review

Spec coverage check:
- Webhook ingress: covered by Tasks 1-3 and 7
- Poll-based repair loop: covered by Tasks 4-5
- Domains Shared overlap and cutover preparation: covered by Task 6
- Runtime configuration and security secret: covered by Tasks 1, 4, and 7
- Testing expectations: covered across Tasks 1-7

Placeholder scan:
- No `TBD`, `TODO`, or “implement later” placeholders remain.
- Each code-changing step includes explicit code.

Type consistency:
- Stable naming used throughout:
  - `GRAFANA_IRM_WEBHOOK_SECRET`
  - `_handle_grafana_irm_alert_group_event`
  - `_grafana_irm_fingerprint`
  - `reconcile_grafana_irm_alert_groups`
  - `prefer_grafana_irm_over_domains_shared`

