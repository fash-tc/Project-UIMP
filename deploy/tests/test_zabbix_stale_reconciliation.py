import deploy.enricher as enricher
from deploy.enricher import (
    _trim_k8s_suffix,
    build_stable_zabbix_signature,
    collect_reconcile_candidates,
    find_superseded_alerts,
    poll_and_enrich,
    reconcile_stale_zabbix_alerts,
    update_missing_counters,
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


def test_build_stable_signature_accepts_string_tags_from_live_webhook():
    alert = make_alert(
        tags='{"namespace":"default","node":"ip-10-108-24-11.ec2.internal","pod":"order-api-tdp-865488c957-nhh2l","target":"nodes"}',
    )
    signature = build_stable_zabbix_signature(alert)
    assert signature == "domains-shared|nodes|pod_crash_looping|default|order-api-tdp"


def test_build_stable_signature_accepts_stringified_array_of_tag_objects():
    alert = make_alert(
        tags='[{"tag":"namespace","value":"default"},{"tag":"node","value":"ip-10-108-24-11.ec2.internal"},{"tag":"pod","value":"order-api-tdp-865488c957-nhh2l"},{"tag":"target","value":"nodes"}]',
    )
    signature = build_stable_zabbix_signature(alert)
    assert signature == "domains-shared|nodes|pod_crash_looping|default|order-api-tdp"


def test_trim_k8s_suffix_preserves_legitimate_trailing_numbers():
    assert _trim_k8s_suffix("orders-api-20241") == "orders-api-20241"


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


def test_find_superseded_alerts_uses_started_at_when_last_received_is_missing():
    old_alert = make_alert(
        fingerprint="fp-old",
        lastReceived="",
        startedAt="2026-03-31T17:00:00.000Z",
    )
    new_alert = make_alert(
        fingerprint="fp-new",
        lastReceived="",
        startedAt="2026-03-31T17:05:00.000Z",
    )
    stale = find_superseded_alerts([old_alert, new_alert])
    assert [alert["fingerprint"] for alert in stale] == ["fp-old"]


def test_find_superseded_alerts_supports_dotted_runtime_timestamps():
    old_alert = make_alert(
        fingerprint="fp-old",
        lastReceived="2026.03.31 16:40:00",
        tags='{"namespace":"default","node":"ip-10-108-24-11.ec2.internal","pod":"order-api-tdp-865488c957-nhh2l","target":"nodes"}',
    )
    new_alert = make_alert(
        fingerprint="fp-new",
        triggerId="32319999",
        lastReceived="2026.03.31 16:42:00",
        name="Node [ip-10-108-24-11.ec2.internal] Pod [order-api-tdp-7b8d4f66db-abc12]: Pod is crash looping",
        tags='{"namespace":"default","node":"ip-10-108-24-11.ec2.internal","pod":"order-api-tdp-7b8d4f66db-abc12","target":"nodes"}',
    )

    stale = find_superseded_alerts([new_alert, old_alert])

    assert [alert["fingerprint"] for alert in stale] == ["fp-old"]


def test_collect_reconcile_candidates_prioritizes_signed_alerts_and_caps_per_instance():
    signed = [
        make_alert(
            fingerprint=f"fp-signed-{i}",
            triggerId=str(1000 + i),
            lastReceived="2026-03-31T16:40:00.000Z",
        )
        for i in range(30)
    ]
    generic = [
        make_alert(
            fingerprint=f"fp-generic-{i}",
            triggerId=str(2000 + i),
            name="Filesystem nearly full",
            lastReceived="2026-03-31T16:40:00.000Z",
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
        generic + signed,
        now_epoch=1774976400,
        tracker=tracker,
        grace_seconds=300,
        max_per_instance=25,
    )

    assert len(batches["domains-shared"]) == 25
    assert all(candidate["signature"] is not None for candidate in batches["domains-shared"])
    assert [candidate["fingerprint"] for candidate in batches["domains-shared"]] == [
        f"fp-signed-{i}" for i in range(25)
    ]


def test_collect_reconcile_candidates_skips_generic_alerts_even_with_existing_miss_tracker():
    unsigned = make_alert(
        fingerprint="fp-unsigned",
        triggerId="4001",
        name="Filesystem nearly full",
        lastReceived="2026-03-31T16:40:00.000Z",
        tags={},
    )
    signed = make_alert(
        fingerprint="fp-signed",
        triggerId="4002",
        lastReceived="2026-03-31T16:40:00.000Z",
    )
    tracker = {
        "domains-shared|trigger|4001": {
            "fingerprint": "fp-unsigned",
            "trigger_id": "4001",
            "consecutive_missing_checks": 1,
            "last_checked_at": 0,
        }
    }

    batches = collect_reconcile_candidates(
        [unsigned, signed],
        now_epoch=1774976400,
        tracker=tracker,
        grace_seconds=300,
        max_per_instance=25,
    )

    assert [candidate["fingerprint"] for candidate in batches["domains-shared"]] == ["fp-signed"]


def test_collect_reconcile_candidates_uses_stable_signature_for_signed_tracker_key():
    signed = make_alert(
        fingerprint="fp-signed",
        triggerId="5001",
        lastReceived="2026-03-31T16:40:00.000Z",
    )

    batches = collect_reconcile_candidates(
        [signed],
        now_epoch=1774976400,
        tracker={},
        grace_seconds=300,
        max_per_instance=25,
    )

    candidate = batches["domains-shared"][0]
    assert candidate["signature"] == "domains-shared|nodes|pod_crash_looping|default|order-api-tdp"
    assert candidate["tracker_key"] == candidate["signature"]


def test_collect_reconcile_candidates_skips_recent_alerts_inside_grace_window():
    recent_signed = make_alert(
        fingerprint="fp-recent-signed",
        triggerId="3001",
        lastReceived="2026-03-31T17:59:30.000Z",
    )
    recent_unsigned = make_alert(
        fingerprint="fp-recent-unsigned",
        triggerId="3002",
        lastReceived="2026-03-31T17:59:30.000Z",
        name="Filesystem nearly full",
        tags={},
    )

    batches = collect_reconcile_candidates(
        [recent_signed, recent_unsigned],
        now_epoch=1774976400,
        tracker={},
        grace_seconds=300,
        max_per_instance=25,
    )

    assert batches == {}


def test_collect_reconcile_candidates_skips_non_targeted_zabbix_alert_families():
    generic_alert = make_alert(
        fingerprint="fp-generic",
        triggerId="3011",
        name="Filesystem nearly full",
        lastReceived="2026-03-31T16:40:00.000Z",
        tags={},
    )

    batches = collect_reconcile_candidates(
        [generic_alert],
        now_epoch=1774976400,
        tracker={},
        grace_seconds=300,
        max_per_instance=25,
    )

    assert batches == {}


def test_collect_reconcile_candidates_accepts_scalar_zabbix_source():
    scalar_source = make_alert(
        fingerprint="fp-scalar-source",
        triggerId="3003",
        lastReceived="2026-03-31T16:40:00.000Z",
        source="zabbix",
    )

    batches = collect_reconcile_candidates(
        [scalar_source],
        now_epoch=1774976400,
        tracker={},
        grace_seconds=300,
        max_per_instance=25,
    )

    assert [candidate["fingerprint"] for candidate in batches["domains-shared"]] == ["fp-scalar-source"]


def test_collect_reconcile_candidates_supports_dotted_runtime_timestamps():
    dotted_alert = make_alert(
        fingerprint="fp-dotted-time",
        triggerId="3010",
        lastReceived="2026.03.31 16:40:00",
    )

    batches = collect_reconcile_candidates(
        [dotted_alert],
        now_epoch=1774976400,
        tracker={},
        grace_seconds=300,
        max_per_instance=25,
    )

    assert [candidate["fingerprint"] for candidate in batches["domains-shared"]] == ["fp-dotted-time"]


def test_update_missing_counters_deduplicates_duplicate_signature_candidates_before_counting():
    tracker = {
        "domains-shared|nodes|pod_crash_looping|default|order-api-tdp": {
            "fingerprint": "fp-old",
            "trigger_id": "32310474",
            "consecutive_missing_checks": 0,
            "last_checked_at": 0,
        }
    }
    candidates = [
        {
            "tracker_key": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
            "fingerprint": "fp-old-a",
            "trigger_id": "32310474",
            "signature": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
        },
        {
            "tracker_key": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
            "fingerprint": "fp-old-b",
            "trigger_id": "32310474",
            "signature": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
        },
    ]

    first = update_missing_counters(candidates, set(), tracker, misses_required=2, now_epoch=1711908000)
    assert first == []
    assert tracker["domains-shared|nodes|pod_crash_looping|default|order-api-tdp"]["consecutive_missing_checks"] == 1

    second = update_missing_counters(candidates, set(), tracker, misses_required=2, now_epoch=1711908060)
    assert [item["fingerprint"] for item in second] == ["fp-old-a"]


def test_update_missing_counters_resets_when_any_duplicate_signature_trigger_is_still_problem():
    tracker = {
        "domains-shared|nodes|pod_crash_looping|default|order-api-tdp": {
            "fingerprint": "fp-old",
            "trigger_id": "32310474",
            "consecutive_missing_checks": 0,
            "last_checked_at": 0,
        }
    }
    candidates = [
        {
            "tracker_key": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
            "fingerprint": "fp-old-a",
            "trigger_id": "32310474",
            "signature": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
        },
        {
            "tracker_key": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
            "fingerprint": "fp-old-b",
            "trigger_id": "32319999",
            "signature": "domains-shared|nodes|pod_crash_looping|default|order-api-tdp",
        },
    ]

    result = update_missing_counters(
        candidates,
        {"32319999"},
        tracker,
        misses_required=1,
        now_epoch=1711908000,
    )

    assert result == []
    assert tracker["domains-shared|nodes|pod_crash_looping|default|order-api-tdp"]["consecutive_missing_checks"] == 0


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


def test_reconcile_stale_zabbix_alerts_rate_limits_runs(monkeypatch):
    now_epoch = 1711908000
    alert = make_alert(lastReceived="2026-03-31T16:40:00.000Z")

    monkeypatch.setattr(enricher.time, "time", lambda: now_epoch)
    monkeypatch.setattr(enricher, "_last_stale_reconcile_run", now_epoch - enricher.STALE_RECONCILE_INTERVAL_SECONDS + 1)

    check_calls = []
    monkeypatch.setattr(enricher, "_check_triggers_in_zabbix", lambda instance, trigger_ids: check_calls.append((instance, trigger_ids)) or set())
    monkeypatch.setattr(enricher, "_resolve_synthetic_keep_ok", lambda alert, reason: True)

    reconcile_stale_zabbix_alerts([alert])

    assert check_calls == []


def test_reconcile_stale_zabbix_alerts_resolves_superseded_and_after_required_misses(monkeypatch):
    now_epoch = 1774983600
    old_alert = make_alert(
        fingerprint="fp-old",
        triggerId="32310474",
        lastReceived="2026-03-31T16:40:00.000Z",
    )
    new_alert = make_alert(
        fingerprint="fp-new",
        triggerId="32319999",
        lastReceived="2026-03-31T16:42:00.000Z",
        name="Node [ip-10-108-24-11.ec2.internal] Pod [order-api-tdp-7b8d4f66db-abc12]: Pod is crash looping",
        tags={
            "namespace": "default",
            "node": "ip-10-108-24-11.ec2.internal",
            "pod": "order-api-tdp-7b8d4f66db-abc12",
            "target": "nodes",
        },
    )
    missing_signed_alert = make_alert(
        fingerprint="fp-missing",
        triggerId="32318888",
        lastReceived="2026-03-31T16:41:00.000Z",
        name="Node [ip-10-108-24-11.ec2.internal] Pod [billing-api-tdp-6ff7f6d9db-plk9h]: Pod is crash looping",
        tags={
            "namespace": "default",
            "node": "ip-10-108-24-11.ec2.internal",
            "pod": "billing-api-tdp-6ff7f6d9db-plk9h",
            "target": "nodes",
        },
    )
    missing_signature = build_stable_zabbix_signature(missing_signed_alert)

    tracker = {
        missing_signature: {
            "fingerprint": "fp-missing",
            "trigger_id": "32318888",
            "consecutive_missing_checks": enricher.STALE_RECONCILE_MISSES_REQUIRED - 1,
            "last_checked_at": 0,
        }
    }
    monkeypatch.setattr(enricher, "stale_reconcile_tracker", tracker)
    monkeypatch.setattr(enricher.time, "time", lambda: now_epoch)
    monkeypatch.setattr(enricher, "_last_stale_reconcile_run", 0)

    resolved = []
    monkeypatch.setattr(enricher, "_resolve_synthetic_keep_ok", lambda alert, reason: resolved.append((alert["fingerprint"], reason)) or True)

    checks = []

    def fake_check(instance, trigger_ids):
        checks.append((instance, set(trigger_ids)))
        return {"32319999"}

    monkeypatch.setattr(enricher, "_check_triggers_in_zabbix", fake_check)

    reconcile_stale_zabbix_alerts([old_alert, new_alert, missing_signed_alert])

    assert checks == [("domains-shared", {"32319999", "32318888"})]
    assert [fingerprint for fingerprint, _ in resolved] == ["fp-old", "fp-missing"]
    assert resolved[0][1] == "superseded by newer Zabbix alert with same stable signature"
    assert resolved[1][1] == "missing from Zabbix for 2 consecutive reconciliation checks"
    assert missing_signature not in tracker


def test_reconcile_stale_zabbix_alerts_preserves_signature_miss_counter_when_superseded_alert_resolves(monkeypatch):
    now_epoch = 1774983600
    old_alert = make_alert(
        fingerprint="fp-old",
        triggerId="32310474",
        lastReceived="2026-03-31T16:40:00.000Z",
    )
    new_alert = make_alert(
        fingerprint="fp-new",
        triggerId="32319999",
        lastReceived="2026-03-31T16:42:00.000Z",
        name="Node [ip-10-108-24-11.ec2.internal] Pod [order-api-tdp-7b8d4f66db-abc12]: Pod is crash looping",
        tags={
            "namespace": "default",
            "node": "ip-10-108-24-11.ec2.internal",
            "pod": "order-api-tdp-7b8d4f66db-abc12",
            "target": "nodes",
        },
    )
    signature = build_stable_zabbix_signature(new_alert)
    tracker = {
        signature: {
            "fingerprint": "fp-older-sibling",
            "trigger_id": "32310000",
            "consecutive_missing_checks": enricher.STALE_RECONCILE_MISSES_REQUIRED - 1,
            "last_checked_at": 0,
        }
    }
    monkeypatch.setattr(enricher, "stale_reconcile_tracker", tracker)
    monkeypatch.setattr(enricher.time, "time", lambda: now_epoch)
    monkeypatch.setattr(enricher, "_last_stale_reconcile_run", 0)

    resolved = []
    monkeypatch.setattr(enricher, "_resolve_synthetic_keep_ok", lambda alert, reason: resolved.append((alert["fingerprint"], reason)) or True)
    monkeypatch.setattr(enricher, "_check_triggers_in_zabbix", lambda instance, trigger_ids: set())

    reconcile_stale_zabbix_alerts([old_alert, new_alert])

    assert [fingerprint for fingerprint, _ in resolved] == ["fp-old", "fp-new"]
    assert resolved[1][1] == "missing from Zabbix for 2 consecutive reconciliation checks"
    assert signature not in tracker


def test_reconcile_stale_zabbix_alerts_prunes_tracker_entries_for_disappeared_alerts(monkeypatch):
    now_epoch = 1774983600
    stale_key = "domains-shared|trigger|4001"
    tracker = {
        stale_key: {
            "fingerprint": "fp-gone",
            "trigger_id": "4001",
            "consecutive_missing_checks": 1,
            "last_checked_at": 0,
        }
    }
    active_alert = make_alert(
        fingerprint="fp-current",
        triggerId="5001",
        lastReceived="2026.03.31 16:40:00",
    )
    monkeypatch.setattr(enricher, "stale_reconcile_tracker", tracker)
    monkeypatch.setattr(enricher.time, "time", lambda: now_epoch)
    monkeypatch.setattr(enricher, "_last_stale_reconcile_run", 0)
    monkeypatch.setattr(enricher, "_check_triggers_in_zabbix", lambda instance, trigger_ids: {"5001"})
    monkeypatch.setattr(enricher, "_resolve_synthetic_keep_ok", lambda alert, reason: True)

    reconcile_stale_zabbix_alerts([active_alert])

    assert stale_key not in tracker
    assert tracker["domains-shared|nodes|pod_crash_looping|default|order-api-tdp"]["consecutive_missing_checks"] == 0


def test_reconcile_stale_zabbix_alerts_uses_dynamic_reason_when_miss_threshold_changes(monkeypatch):
    now_epoch = 1774983600
    alert = make_alert(
        fingerprint="fp-dynamic",
        triggerId="7001",
        lastReceived="2026-03-31T16:40:00.000Z",
    )
    signature = build_stable_zabbix_signature(alert)
    tracker = {
        signature: {
            "fingerprint": "fp-dynamic",
            "trigger_id": "7001",
            "consecutive_missing_checks": 2,
            "last_checked_at": 0,
        }
    }
    monkeypatch.setattr(enricher, "stale_reconcile_tracker", tracker)
    monkeypatch.setattr(enricher.time, "time", lambda: now_epoch)
    monkeypatch.setattr(enricher, "_last_stale_reconcile_run", 0)
    monkeypatch.setattr(enricher, "STALE_RECONCILE_MISSES_REQUIRED", 3)
    monkeypatch.setattr(enricher, "_check_triggers_in_zabbix", lambda instance, trigger_ids: set())

    resolved = []
    monkeypatch.setattr(enricher, "_resolve_synthetic_keep_ok", lambda alert, reason: resolved.append(reason) or True)

    reconcile_stale_zabbix_alerts([alert])

    assert resolved == ["missing from Zabbix for 3 consecutive reconciliation checks"]


def test_resolve_synthetic_keep_ok_updates_alert_status_by_fingerprint(monkeypatch):
    calls = []

    monkeypatch.setattr(
        enricher,
        "keep_request",
        lambda path, method="GET", data=None, headers=None: calls.append((path, method, data)) or {"status": "ok"},
    )
    monkeypatch.setattr(enricher.time, "time", lambda: 1711908000)
    enricher.enriched_cache.clear()

    alert = make_alert(fingerprint="fp-resolve")

    assert enricher._resolve_synthetic_keep_ok(alert, "missing from Zabbix") is True
    assert calls == [
        (
            "/alerts/enrich",
            "POST",
            {
                "fingerprint": "fp-resolve",
                "enrichments": {"status": "resolved"},
            },
        )
    ]
    assert enricher.enriched_cache["fp-resolve"] == 1711908000


def test_reconcile_defaults_match_task_3_spec():
    assert enricher.STALE_RECONCILE_INTERVAL_SECONDS == 60
    assert enricher.STALE_RECONCILE_GRACE_SECONDS == 300
    assert enricher.STALE_RECONCILE_MAX_PER_INSTANCE == 25
    assert enricher.STALE_RECONCILE_MISSES_REQUIRED == 2


def test_poll_and_enrich_calls_reconcile_stale_zabbix_alerts_directly(monkeypatch):
    active_alert = make_alert(fingerprint="fp-active")
    monkeypatch.setattr(enricher, "keep_request", lambda path, method="GET", data=None: [active_alert])
    monkeypatch.setattr(enricher, "fetch_force_enrich_fingerprints", lambda: set())
    monkeypatch.setattr(enricher, "fetch_silence_rules", lambda: [])
    monkeypatch.setattr(enricher, "check_suppression", lambda alert: (False, "", ""))
    monkeypatch.setattr(enricher, "enrich_alert", lambda alert, similar: None)
    monkeypatch.setattr(enricher, "cluster_alerts", lambda alerts: [])
    monkeypatch.setattr(enricher, "merge_related_clusters", lambda clusters: clusters)
    monkeypatch.setattr(enricher, "generate_situation_summary", lambda clusters, alerts, skipped: None)
    monkeypatch.setattr(enricher, "apply_routing_rules", lambda alerts: None)
    monkeypatch.setattr(enricher.pattern_tracker, "find_similar", lambda alert: [])
    monkeypatch.setattr(enricher, "enriched_cache", {})
    monkeypatch.setattr(enricher, "recent_enrichments", {})

    calls = []
    monkeypatch.setattr(enricher, "reconcile_stale_zabbix_alerts", lambda alerts: calls.append(alerts))

    result = poll_and_enrich()

    assert result == 0
    assert calls == [[active_alert]]
