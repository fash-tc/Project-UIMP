import deploy.enricher as enricher


def test_grafana_irm_polling_defaults_are_defined():
    assert enricher.GRAFANA_IRM_POLL_INTERVAL_SECONDS == 300
    assert enricher.GRAFANA_IRM_URL == ""
    assert enricher.GRAFANA_IRM_API_TOKEN == ""


def test_reconcile_grafana_irm_backfills_open_groups(monkeypatch):
    groups = [{
        "id": "AG1",
        "title": "Disk low",
        "state": "alerting",
        "integration": {"name": "Domains Shared"},
        "labels": {"host": "srv-01", "severity": "critical"},
    }]
    monkeypatch.setattr(enricher, "GRAFANA_IRM_URL", "https://grafana.example")
    monkeypatch.setattr(enricher, "GRAFANA_IRM_API_TOKEN", "token")
    monkeypatch.setattr(enricher, "_fetch_grafana_irm_active_alert_groups", lambda: groups)
    monkeypatch.setattr(enricher, "_fetch_existing_grafana_irm_open_alerts", lambda: {})
    monkeypatch.setattr(enricher.time, "time", lambda: 1711908000)
    monkeypatch.setattr(enricher, "_last_grafana_irm_poll_run", 0)

    calls = []
    monkeypatch.setattr(
        enricher,
        "_send_grafana_irm_group_to_keep",
        lambda group, status_override=None: calls.append((group["id"], status_override or "firing")) or {"ok": True},
    )

    enricher.reconcile_grafana_irm_alert_groups()

    assert calls == [("AG1", "firing")]


def test_reconcile_grafana_irm_resolves_missing_open_group(monkeypatch):
    monkeypatch.setattr(enricher, "GRAFANA_IRM_URL", "https://grafana.example")
    monkeypatch.setattr(enricher, "GRAFANA_IRM_API_TOKEN", "token")
    monkeypatch.setattr(enricher, "_fetch_grafana_irm_active_alert_groups", lambda: [])
    monkeypatch.setattr(
        enricher,
        "_fetch_existing_grafana_irm_open_alerts",
        lambda: {
            "AG2": {
                "id": "AG2",
                "name": "Disk low",
                "severity": "critical",
                "status": "firing",
                "service": "Domains Shared",
                "hostName": "srv-01",
            }
        },
    )
    monkeypatch.setattr(enricher.time, "time", lambda: 1711908000)
    monkeypatch.setattr(enricher, "_last_grafana_irm_poll_run", 0)

    calls = []
    monkeypatch.setattr(
        enricher,
        "_send_grafana_irm_group_to_keep",
        lambda group, status_override=None: calls.append((group["id"], status_override)) or {"ok": True},
    )

    enricher.reconcile_grafana_irm_alert_groups()

    assert calls == [("AG2", "ok")]


def test_prefers_grafana_irm_alert_over_domains_shared_overlap():
    irm_alert = {
        "fingerprint": "grafana-irm:AG1",
        "providerType": "grafana-irm",
        "source": ["grafana-irm"],
        "name": "/data: Disk space is low",
        "hostName": "osrs-log01.prod-opensrs.bra2.tucows.systems",
        "status": "firing",
    }
    zabbix_alert = {
        "fingerprint": "zbx-1",
        "providerType": "zabbix",
        "source": ["zabbix"],
        "zabbixInstance": "domains-shared",
        "name": "/data: Disk space is low",
        "hostName": "osrs-log01.prod-opensrs.bra2.tucows.systems",
        "status": "firing",
    }

    result = enricher.prefer_grafana_irm_over_domains_shared([zabbix_alert, irm_alert])

    assert result == [irm_alert]
