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
