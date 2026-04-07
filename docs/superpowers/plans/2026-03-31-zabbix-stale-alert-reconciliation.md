# Zabbix Stale Alert Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make stale Node/Kubernetes Zabbix alerts disappear from the Command Center within minutes by adding stable-signature reconciliation, bounded consecutive-miss checks, and immediate supersede cleanup for recreated alerts.

**Architecture:** Keep all reconciliation logic inside the alert enricher so the live behavior changes in one place. Add a small pure-function layer for signature building and candidate selection, then hang a bounded in-memory tracker plus batched Zabbix verification off the existing poll loop. Preserve the current trigger-based fallback for generic Zabbix alerts that do not produce a trustworthy stable signature.

**Tech Stack:** Python 3.12, pytest, docker compose, Zabbix JSON-RPC, Keep alert ingestion

---

## File Map

- Modify: `deploy/enricher.py`
  - Add stable-signature helpers, tracker state, candidate collection, supersede resolution, and bounded reconciliation flow.
- Modify: `deploy/docker-compose.yml`
  - Add new alert-enricher environment defaults for reconciliation interval, grace period, per-instance cap, and misses required.
- Create: `deploy/tests/test_zabbix_stale_reconciliation.py`
  - Add focused pytest coverage for signature generation, superseded alert resolution decisions, candidate capping, and consecutive-miss tracking.

### Task 1: Add Failing Tests For Stable Signatures And Supersede Detection

**Files:**
- Create: `deploy/tests/test_zabbix_stale_reconciliation.py`
- Modify: `deploy/enricher.py:1682-1818`

- [ ] **Step 1: Write the failing test module**

```python
from deploy.enricher import (
    build_stable_zabbix_signature,
    find_superseded_alerts,
)


def make_alert(**overrides):
    alert = {
        "fingerprint": "fp-old",
        "name": "Node [ip-10-108-24-11.ec2.internal] Pod [order-api-tdp-865488c957-nhh2l]: Pod is crash looping",
        "status": "firing",
        "providerType": "zabbix",
        "source": ["zabbix"],
        "zabbixInstance": "domains-shared",
        "triggerId": "32310474",
        "lastReceived": "2026-03-31T17:00:00.000Z",
        "hostName": "tdp-prod_kubernetes nodes",
        "tags": {
            "namespace": "default",
            "node": "ip-10-108-24-11.ec2.internal",
            "pod": "order-api-tdp-865488c957-nhh2l",
            "target": "nodes",
        },
    }
    alert.update(overrides)
    return alert


def test_build_stable_signature_normalizes_kubernetes_pod_suffixes():
    alert = make_alert()
    signature = build_stable_zabbix_signature(alert)
    assert signature == "domains-shared|nodes|pod_crash_looping|default|order-api-tdp"


def test_build_stable_signature_normalizes_replicaset_hashes():
    alert = make_alert(
        name="Kubernetes: Namespace [default] RS [ryinterface-nominet-cymru-enom-tdp-6f5c8f6d75]: ReplicaSet mismatch",
        hostName="tdp-prod_Kubernetes_Cluster_State",
        tags={
            "namespace": "default",
            "replicaset": "ryinterface-nominet-cymru-enom-tdp-6f5c8f6d75",
            "target": "kubernetes",
        },
    )
    signature = build_stable_zabbix_signature(alert)
    assert signature == "domains-shared|kubernetes|replicaset_mismatch|default|ryinterface-nominet-cymru-enom-tdp"


def test_find_superseded_alerts_returns_older_alert_when_same_signature_reappears():
    old_alert = make_alert(
        fingerprint="fp-old",
        triggerId="32310474",
        lastReceived="2026-03-31T17:00:00.000Z",
    )
    new_alert = make_alert(
        fingerprint="fp-new",
        triggerId="32319999",
        lastReceived="2026-03-31T17:03:00.000Z",
        name="Node [ip-10-108-24-11.ec2.internal] Pod [order-api-tdp-7b8d4f66db-abc12]: Pod is crash looping",
        tags={
            "namespace": "default",
            "node": "ip-10-108-24-11.ec2.internal",
            "pod": "order-api-tdp-7b8d4f66db-abc12",
            "target": "nodes",
        },
    )
    stale = find_superseded_alerts([old_alert, new_alert])
    assert [alert["fingerprint"] for alert in stale] == ["fp-old"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```powershell
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_zabbix_stale_reconciliation.py -q
```

Expected: `ImportError` or `AttributeError` because `build_stable_zabbix_signature` and `find_superseded_alerts` do not exist yet.

- [ ] **Step 3: Add minimal pure helpers to make the signature and supersede tests pass**

Add to `deploy/enricher.py` near the current Zabbix stale helpers:

```python
def _slug(text):
    return re.sub(r"[^a-z0-9]+", "_", (text or "").strip().lower()).strip("_")


def _trim_k8s_suffix(name):
    value = (name or "").strip().lower()
    value = re.sub(r"-[0-9a-f]{5,10}$", "", value)
    value = re.sub(r"-[0-9a-z]{5}$", "", value)
    return value


def build_stable_zabbix_signature(alert):
    instance = (alert.get("zabbixInstance") or "").strip()
    if not instance:
        return None

    raw_tags = alert.get("tags") or {}
    tags = raw_tags if isinstance(raw_tags, dict) else {}
    namespace = (tags.get("namespace") or "").strip().lower()
    target = (tags.get("target") or "").strip().lower()
    name = alert.get("name") or ""

    if "replicaset mismatch" in name.lower():
        alert_family = "replicaset_mismatch"
    elif "pod is crash looping" in name.lower():
        alert_family = "pod_crash_looping"
    else:
        return None

    target_family = "kubernetes" if target == "kubernetes" else "nodes" if target == "nodes" else "generic"

    if tags.get("pod"):
        scope = _trim_k8s_suffix(tags["pod"])
    elif tags.get("replicaset"):
        scope = _trim_k8s_suffix(tags["replicaset"])
    elif tags.get("node"):
        scope = (tags["node"] or "").strip().lower()
    else:
        scope = (alert.get("hostName") or alert.get("hostname") or "").strip().lower()

    if not scope:
        return None
    return f"{instance}|{target_family}|{alert_family}|{namespace}|{scope}"


def find_superseded_alerts(active_alerts):
    newest_by_signature = {}
    superseded = []
    for alert in sorted(active_alerts, key=lambda a: a.get("lastReceived") or ""):
        signature = build_stable_zabbix_signature(alert)
        if not signature:
            continue
        previous = newest_by_signature.get(signature)
        if previous is not None:
            superseded.append(previous)
        newest_by_signature[signature] = alert
    return superseded
```

- [ ] **Step 4: Re-run the tests and make sure they pass**

Run:

```powershell
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_zabbix_stale_reconciliation.py -q
```

Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add deploy/enricher.py deploy/tests/test_zabbix_stale_reconciliation.py
git commit -m "test: cover stale zabbix signature helpers"
```

### Task 2: Add Failing Tests For Bounded Candidate Selection And Miss Tracking

**Files:**
- Modify: `deploy/tests/test_zabbix_stale_reconciliation.py`
- Modify: `deploy/enricher.py:1702-1818`

- [ ] **Step 1: Extend the test module with bounded-reconciliation tests**

```python
from deploy.enricher import collect_reconcile_candidates, update_missing_counters


def test_collect_reconcile_candidates_prioritizes_signed_alerts_and_caps_per_instance():
    signed = [
        make_alert(fingerprint=f"fp-signed-{i}", triggerId=str(1000 + i), lastReceived="2026-03-31T16:40:00.000Z")
        for i in range(30)
    ]
    generic = [
        make_alert(
            fingerprint=f"fp-generic-{i}",
            triggerId=str(2000 + i),
            name="Filesystem nearly full",
            tags={},
        )
        for i in range(10)
    ]
    tracker = {
        "domains-shared|nodes|pod_crash_looping|default|order-api-tdp": {
            "fingerprint": "fp-signed-0",
            "consecutive_missing_checks": 1,
            "last_checked_at": 0,
        }
    }
    batches = collect_reconcile_candidates(
        signed + generic,
        now_epoch=1711908000,
        tracker=tracker,
        grace_seconds=300,
        max_per_instance=25,
    )
    assert len(batches["domains-shared"]) == 25
    assert all(candidate["signature"] is not None for candidate in batches["domains-shared"][:25])


def test_update_missing_counters_requires_two_consecutive_misses():
    tracker = {
        "domains-shared|nodes|pod_crash_looping|default|order-api-tdp": {
            "fingerprint": "fp-old",
            "trigger_id": "32310474",
            "consecutive_missing_checks": 0,
            "last_checked_at": 0,
        }
    }
    candidates = [{
        "tracker_key": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
        "fingerprint": "fp-old",
        "trigger_id": "32310474",
        "signature": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
    }]

    first = update_missing_counters(candidates, set(), tracker, misses_required=2, now_epoch=1711908000)
    assert first == []
    assert tracker[candidates[0]["tracker_key"]]["consecutive_missing_checks"] == 1

    second = update_missing_counters(candidates, set(), tracker, misses_required=2, now_epoch=1711908060)
    assert [item["fingerprint"] for item in second] == ["fp-old"]
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run:

```powershell
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_zabbix_stale_reconciliation.py -q
```

Expected: failures for missing `collect_reconcile_candidates` and `update_missing_counters`.

- [ ] **Step 3: Implement minimal candidate selection and miss-counter helpers**

Add to `deploy/enricher.py`:

```python
def collect_reconcile_candidates(active_alerts, now_epoch, tracker, grace_seconds, max_per_instance):
    batches = {}
    prioritized = []
    fallback = []
    for alert in active_alerts:
        instance = alert.get("zabbixInstance")
        trigger_id = alert.get("triggerId")
        if not instance or not trigger_id:
            continue
        if (alert.get("status") or "").lower() in ("resolved", "ok"):
            continue
        last_received = alert.get("lastReceived") or alert.get("firingStartTime") or alert.get("startedAt") or ""
        if _parse_alert_time(last_received) > now_epoch - grace_seconds:
            continue
        signature = build_stable_zabbix_signature(alert)
        item = {
            "instance": instance,
            "fingerprint": alert.get("fingerprint", ""),
            "trigger_id": str(trigger_id),
            "signature": signature,
            "tracker_key": f"{instance}|{signature}" if signature else None,
        }
        if signature:
            prioritized.append(item)
        else:
            fallback.append(item)

    for item in prioritized + fallback:
        bucket = batches.setdefault(item["instance"], [])
        if len(bucket) < max_per_instance:
            bucket.append(item)
    return batches


def update_missing_counters(candidates, still_problem, tracker, misses_required, now_epoch):
    to_resolve = []
    for candidate in candidates:
        key = candidate["tracker_key"] or f"{candidate['instance']}|trigger|{candidate['trigger_id']}"
        state = tracker.setdefault(key, {
            "fingerprint": candidate["fingerprint"],
            "trigger_id": candidate["trigger_id"],
            "consecutive_missing_checks": 0,
            "last_checked_at": 0,
        })
        state["last_checked_at"] = now_epoch
        if candidate["trigger_id"] in still_problem:
            state["consecutive_missing_checks"] = 0
            continue
        state["consecutive_missing_checks"] += 1
        if state["consecutive_missing_checks"] >= misses_required:
            to_resolve.append(candidate)
    return to_resolve
```

- [ ] **Step 4: Re-run the tests and make sure they pass**

Run:

```powershell
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_zabbix_stale_reconciliation.py -q
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add deploy/enricher.py deploy/tests/test_zabbix_stale_reconciliation.py
git commit -m "test: add bounded stale reconciliation coverage"
```

### Task 3: Replace The Current Stale Reconcile Flow In The Enricher

**Files:**
- Modify: `deploy/enricher.py:1684-1818`
- Modify: `deploy/enricher.py:1820-1976`

- [ ] **Step 1: Add reconciliation configuration and tracker state**

Insert near the current Zabbix globals in `deploy/enricher.py`:

```python
STALE_RECONCILE_INTERVAL_SECONDS = int(os.environ.get("STALE_RECONCILE_INTERVAL_SECONDS", "60"))
STALE_RECONCILE_GRACE_SECONDS = int(os.environ.get("STALE_RECONCILE_GRACE_SECONDS", "300"))
STALE_RECONCILE_MAX_PER_INSTANCE = int(os.environ.get("STALE_RECONCILE_MAX_PER_INSTANCE", "25"))
STALE_RECONCILE_MISSES_REQUIRED = int(os.environ.get("STALE_RECONCILE_MISSES_REQUIRED", "2"))

stale_reconcile_tracker = {}
_last_stale_reconcile_run = 0
```

- [ ] **Step 2: Add a small time parser and Keep resolver helper**

Add to `deploy/enricher.py` above the reconciliation functions:

```python
def _parse_alert_time(value):
    if not value:
        return 0
    normalized = str(value).replace("Z", "+00:00")
    try:
        return _dt.fromisoformat(normalized).timestamp()
    except Exception:
        return 0


def _resolve_alert_via_keep(alert, reason):
    fp = alert.get("fingerprint", "")
    payload = {
        "id": f"auto-resolve-{fp[:16]}",
        "triggerId": alert.get("triggerId", ""),
        "name": alert.get("name", "unknown"),
        "status": "ok",
        "severity": alert.get("severity", "warning"),
        "hostName": get_host(alert),
        "lastReceived": _dt.now(_tz.utc).strftime("%Y.%m.%d %H:%M:%S"),
        "description": reason,
        "tags": "[]",
        "zabbixInstance": alert.get("zabbixInstance", ""),
    }
    req = Request(
        f"{KEEP_URL}/alerts/event/zabbix",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"X-API-KEY": KEEP_API_KEY, "Content-Type": "application/json"},
    )
    urlopen(req, timeout=10)
```

- [ ] **Step 3: Replace `auto_resolve_stale_alerts` with bounded reconciliation**

Refactor the current section into:

```python
def reconcile_stale_zabbix_alerts(active_alerts):
    global _last_stale_reconcile_run
    now = time.time()
    if now - _last_stale_reconcile_run < STALE_RECONCILE_INTERVAL_SECONDS:
        return
    _last_stale_reconcile_run = now

    superseded = find_superseded_alerts(active_alerts)
    for alert in superseded:
        log.info("Auto-resolving superseded alert %s (%s)", alert.get("name", ""), alert.get("fingerprint", "")[:16])
        _resolve_alert_via_keep(alert, "Auto-resolved: superseded by newer Zabbix alert with same stable signature")

    batches = collect_reconcile_candidates(
        active_alerts,
        now_epoch=now,
        tracker=stale_reconcile_tracker,
        grace_seconds=STALE_RECONCILE_GRACE_SECONDS,
        max_per_instance=STALE_RECONCILE_MAX_PER_INSTANCE,
    )
    for instance_key, candidates in batches.items():
        trigger_ids = {candidate["trigger_id"] for candidate in candidates}
        log.info("Checking %s reconcile candidate(s) against Zabbix (%s)", len(trigger_ids), instance_key)
        still_problem = _check_triggers_in_zabbix(instance_key, trigger_ids)
        if still_problem is None:
            log.info("Skipping reconcile batch for %s due to Zabbix verification failure", instance_key)
            continue
        to_resolve = update_missing_counters(
            candidates,
            still_problem,
            stale_reconcile_tracker,
            misses_required=STALE_RECONCILE_MISSES_REQUIRED,
            now_epoch=now,
        )
        active_by_fp = {alert.get("fingerprint"): alert for alert in active_alerts}
        for candidate in to_resolve:
            alert = active_by_fp.get(candidate["fingerprint"])
            if not alert:
                continue
            _resolve_alert_via_keep(alert, "Auto-resolved: missing from Zabbix for 2 consecutive reconciliation checks")
```

- [ ] **Step 4: Call the new reconciler from the poll loop**

Replace the old poll-loop call in `deploy/enricher.py`:

```python
if STALE_RESOLVE_SECONDS > 0:
    auto_resolve_stale_alerts(active_alerts)
```

with:

```python
reconcile_stale_zabbix_alerts(active_alerts)
```

- [ ] **Step 5: Run the focused tests**

Run:

```powershell
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_zabbix_stale_reconciliation.py -q
python -m py_compile C:\Users\fash\Documents\UIP\deploy\enricher.py
```

Expected:
- pytest passes
- `py_compile` exits with code 0 and no output

- [ ] **Step 6: Commit**

```bash
git add deploy/enricher.py deploy/tests/test_zabbix_stale_reconciliation.py
git commit -m "feat: add bounded stale zabbix reconciliation"
```

### Task 4: Wire New Enricher Settings And Verify Locally

**Files:**
- Modify: `deploy/docker-compose.yml:116-136`
- Modify: `deploy/tests/test_zabbix_stale_reconciliation.py`

- [ ] **Step 1: Add alert-enricher environment defaults**

Update the `alert-enricher` service in `deploy/docker-compose.yml`:

```yaml
      STALE_RECONCILE_INTERVAL_SECONDS: "${STALE_RECONCILE_INTERVAL_SECONDS:-60}"
      STALE_RECONCILE_GRACE_SECONDS: "${STALE_RECONCILE_GRACE_SECONDS:-300}"
      STALE_RECONCILE_MAX_PER_INSTANCE: "${STALE_RECONCILE_MAX_PER_INSTANCE:-25}"
      STALE_RECONCILE_MISSES_REQUIRED: "${STALE_RECONCILE_MISSES_REQUIRED:-2}"
```

- [ ] **Step 2: Add one configuration-oriented regression test**

Append to `deploy/tests/test_zabbix_stale_reconciliation.py`:

```python
def test_collect_reconcile_candidates_skips_recent_alerts_inside_grace_window():
    fresh = make_alert(lastReceived="2026-03-31T17:04:30.000Z")
    batches = collect_reconcile_candidates(
        [fresh],
        now_epoch=1711904700,
        tracker={},
        grace_seconds=300,
        max_per_instance=25,
    )
    assert batches == {}
```

- [ ] **Step 3: Run the local verification commands**

Run:

```powershell
python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_zabbix_stale_reconciliation.py -q
python -m py_compile C:\Users\fash\Documents\UIP\deploy\enricher.py
git diff -- deploy/enricher.py deploy/docker-compose.yml deploy/tests/test_zabbix_stale_reconciliation.py
```

Expected:
- pytest passes
- `py_compile` exits cleanly
- diff only shows the intended reconciliation and config changes

- [ ] **Step 4: Commit**

```bash
git add deploy/docker-compose.yml deploy/tests/test_zabbix_stale_reconciliation.py
git commit -m "chore: configure stale zabbix reconciliation limits"
```

### Task 5: Deploy And Smoke-Test The Live Reconciler

**Files:**
- Modify: `deploy/enricher.py`
- Modify: `deploy/docker-compose.yml`
- Modify: `deploy/tests/test_zabbix_stale_reconciliation.py`

- [ ] **Step 1: Copy the changed files to the server**

Run:

```powershell
C:\Windows\System32\OpenSSH\scp.exe -i C:\Users\fash\.ssh\id_uip_deploy -o StrictHostKeyChecking=no -o ConnectTimeout=15 C:\Users\fash\Documents\UIP\deploy\enricher.py fash@10.177.154.196:/home/fash/uip/enricher/enricher.py
C:\Windows\System32\OpenSSH\scp.exe -i C:\Users\fash\.ssh\id_uip_deploy -o StrictHostKeyChecking=no -o ConnectTimeout=15 C:\Users\fash\Documents\UIP\deploy\docker-compose.yml fash@10.177.154.196:/home/fash/uip/docker-compose.yml
```

Expected: both copies complete without errors.

- [ ] **Step 2: Recreate the live alert-enricher container**

Run:

```powershell
C:\Windows\System32\OpenSSH\ssh.exe -i C:\Users\fash\.ssh\id_uip_deploy -o StrictHostKeyChecking=no -o ConnectTimeout=15 fash@10.177.154.196 "cd /home/fash/uip && docker compose up -d --force-recreate alert-enricher"
```

Expected: `uip-alert-enricher` is recreated and returns to `Up`.

- [ ] **Step 3: Verify the live logs show bounded reconciliation**

Run:

```powershell
C:\Windows\System32\OpenSSH\ssh.exe -i C:\Users\fash\.ssh\id_uip_deploy -o StrictHostKeyChecking=no -o ConnectTimeout=15 fash@10.177.154.196 "docker logs --tail 200 uip-alert-enricher 2>&1"
```

Expected log evidence:
- `Checking N reconcile candidate(s) against Zabbix (domains-shared)`
- no per-alert Zabbix spam
- either `superseded_by_newer_signature_match` or `resolved_after_consecutive_zabbix_misses` when stale alerts are present

- [ ] **Step 4: Verify the live board converges**

Run:

```powershell
C:\Windows\System32\OpenSSH\ssh.exe -i C:\Users\fash\.ssh\id_uip_deploy -o StrictHostKeyChecking=no -o ConnectTimeout=15 fash@10.177.154.196 "docker exec uip-nginx wget --header='X-API-KEY: ca5ee58d-1a50-4817-aac5-9a538e40590d' -qO- http://keep-api:8080/alerts?limit=250"
```

Expected:
- older Node/Kubernetes duplicates are no longer left firing alongside newer recreated alerts
- affected alert families move to `resolved` within the grace plus two-check window

- [ ] **Step 5: Commit the deployment-ready changes**

```bash
git add deploy/enricher.py deploy/docker-compose.yml deploy/tests/test_zabbix_stale_reconciliation.py
git commit -m "feat: deploy aggressive stale zabbix reconciliation"
```

---

## Self-Review

- Spec coverage:
  - stable signature design is covered in Tasks 1 and 3
  - bounded candidate selection and rate limits are covered in Tasks 2 and 4
  - superseded-by-newer cleanup is covered in Tasks 1 and 3
  - consecutive-miss verification is covered in Tasks 2 and 3
  - live Zabbix-safe verification is covered in Task 5
- Placeholder scan:
  - no `TODO`, `TBD`, or vague "handle appropriately" instructions remain
- Type consistency:
  - the plan consistently uses `build_stable_zabbix_signature`, `find_superseded_alerts`, `collect_reconcile_candidates`, `update_missing_counters`, and `reconcile_stale_zabbix_alerts`
