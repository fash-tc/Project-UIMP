import sqlite3
import os

import pytest

# Make admin-api dir importable; tests run from its parent.
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db import init_db, get_conn


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    path = str(tmp_path / "admin.db")
    monkeypatch.setenv("DB_PATH", path)
    yield path
    # tmp_path cleanup is automatic; remove WAL sidecars if Windows held them
    for suf in ("", "-wal", "-shm"):
        try:
            if os.path.exists(path + suf):
                os.unlink(path + suf)
        except OSError:
            pass


def test_init_db_creates_all_tables(tmp_db):
    init_db(tmp_db)
    conn = sqlite3.connect(tmp_db)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert {
        "config", "config_history", "prompt_templates", "prompt_versions",
        "cluster_merge_rules", "zabbix_instances", "service_restart_log",
        "schema_migrations",
    }.issubset(names)


def test_init_db_is_idempotent(tmp_db):
    init_db(tmp_db)
    init_db(tmp_db)  # second call must not raise


def test_init_db_enables_wal(tmp_db):
    init_db(tmp_db)
    conn = sqlite3.connect(tmp_db)
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()
    assert mode.lower() == "wal"


def test_get_conn_yields_row_factory_and_closes(tmp_db):
    init_db(tmp_db)
    with get_conn(tmp_db) as conn:
        conn.execute(
            "INSERT INTO config (key, scope, value, value_type, reload_kind, default_value, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("test.key", "test", '"v"', "string", "hot", '"v"', "2026-05-19T00:00:00Z"),
        )
        row = conn.execute("SELECT key, scope FROM config WHERE key=?", ("test.key",)).fetchone()
        assert row["key"] == "test.key"
        assert row["scope"] == "test"
    # connection is closed after context exit
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


def test_apply_seed_inserts_missing_keys(tmp_db, monkeypatch):
    from db import init_db, apply_seed, get_conn
    init_db(tmp_db)
    apply_seed(tmp_db)
    with get_conn(tmp_db) as conn:
        rows = list(conn.execute("SELECT key, scope, value, value_type FROM config ORDER BY key"))
    keys = [r["key"] for r in rows]
    assert "ai.cluster.endpoint" in keys
    assert "ai.enricher.model" in keys
    assert "pipeline.enricher.poll_interval_sec" in keys
    assert "features.admin.ai_sandbox" in keys


def test_apply_seed_is_idempotent(tmp_db):
    from db import init_db, apply_seed, get_conn
    init_db(tmp_db)
    apply_seed(tmp_db)
    apply_seed(tmp_db)  # second run should not duplicate or error
    with get_conn(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM config").fetchone()[0]
    assert n == 4


def test_apply_seed_honors_env_legacy_on_first_boot(tmp_db, monkeypatch):
    """If a key has env_legacy set and that env is present, seed uses env value not default."""
    from db import init_db, apply_seed, get_conn
    monkeypatch.setenv("OLLAMA_MODEL", "qwen3-235b-thinking")  # override default
    init_db(tmp_db)
    apply_seed(tmp_db)
    with get_conn(tmp_db) as conn:
        row = conn.execute("SELECT value FROM config WHERE key=?", ("ai.enricher.model",)).fetchone()
    import json
    assert json.loads(row["value"]) == "qwen3-235b-thinking"


def test_apply_seed_skips_env_legacy_on_subsequent_boots(tmp_db, monkeypatch):
    """Env override only takes effect when the row doesn't exist yet."""
    from db import init_db, apply_seed, get_conn
    init_db(tmp_db)
    # First boot — no env, uses default
    apply_seed(tmp_db)
    # User changes value via UI (simulated)
    with get_conn(tmp_db) as conn:
        conn.execute(
            "UPDATE config SET value=?, updated_at=? WHERE key=?",
            ('"user-edited-value"', "2026-05-19T22:00:00Z", "ai.enricher.model"),
        )
    # Second boot with env set — must NOT clobber user value
    monkeypatch.setenv("OLLAMA_MODEL", "would-clobber")
    apply_seed(tmp_db)
    with get_conn(tmp_db) as conn:
        row = conn.execute("SELECT value FROM config WHERE key=?", ("ai.enricher.model",)).fetchone()
    import json
    assert json.loads(row["value"]) == "user-edited-value"


def test_load_services_seed_returns_allowlist():
    from db import load_services_seed
    services = load_services_seed()
    assert "uip-alert-enricher" in services
    assert "uip-admin-api" not in services
