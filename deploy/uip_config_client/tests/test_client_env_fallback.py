import os
import pytest


def test_get_returns_default_when_admin_api_unreachable_and_env_unset():
    from uip_config_client import ConfigClient
    cfg = ConfigClient(admin_api="http://127.0.0.1:1", env_fallback=True, poll_interval_sec=0)
    assert cfg.get("pipeline.enricher.poll_interval_sec", default=42) == 42


def test_get_reads_env_legacy_when_admin_api_unreachable(monkeypatch):
    from uip_config_client import ConfigClient
    monkeypatch.setenv("POLL_INTERVAL", "120")
    cfg = ConfigClient(admin_api="http://127.0.0.1:1", env_fallback=True, poll_interval_sec=0,
                       env_legacy_map={"pipeline.enricher.poll_interval_sec": ("POLL_INTERVAL", "int")})
    assert cfg.get("pipeline.enricher.poll_interval_sec") == 120


def test_get_raises_when_no_default_no_env_no_admin(monkeypatch):
    from uip_config_client import ConfigClient
    cfg = ConfigClient(admin_api="http://127.0.0.1:1", env_fallback=True, poll_interval_sec=0)
    with pytest.raises(KeyError):
        cfg.get("nonexistent.key.no.fallback")
