import sqlite3
import tempfile
import os

import pytest

# Make admin-api dir importable; tests run from its parent.
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db import init_db, get_conn


@pytest.fixture
def tmp_db(monkeypatch):
    path = tempfile.mktemp(suffix=".db")
    monkeypatch.setenv("DB_PATH", path)
    yield path
    # WAL mode leaves -shm/-wal sidecars; remove all three on Windows.
    for suffix in ("", "-shm", "-wal"):
        p = path + suffix
        if os.path.exists(p):
            try:
                os.unlink(p)
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
