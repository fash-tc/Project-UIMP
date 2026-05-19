"""SQLite WAL connection helper + schema bootstrap.

Pattern mirrors existing services (auth-api, alert-state-api): inline
CREATE TABLE IF NOT EXISTS for the initial schema, plus a
schema_migrations table that future versions consult before applying
incremental migrations.
"""
import os
import sqlite3
from contextlib import contextmanager
from typing import Iterator

# Path is supplied by caller (init_db) or env. Connection helper reads env.

DDL_STATEMENTS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS config (
      key                 TEXT PRIMARY KEY,
      scope               TEXT NOT NULL,
      value               TEXT NOT NULL,
      value_type          TEXT NOT NULL,
      reload_kind         TEXT NOT NULL,
      restart_target      TEXT,
      default_value       TEXT NOT NULL,
      description         TEXT,
      validation          TEXT,
      is_secret           INTEGER NOT NULL DEFAULT 0,
      secret_rotated_at   TEXT,
      updated_at          TEXT NOT NULL,
      updated_by          TEXT,
      seed_version        INTEGER NOT NULL DEFAULT 1
    )
    """,
    "CREATE INDEX IF NOT EXISTS config_scope_idx ON config(scope)",
    """
    CREATE TABLE IF NOT EXISTS config_history (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      key         TEXT NOT NULL,
      old_value   TEXT,
      new_value   TEXT NOT NULL,
      changed_by  TEXT NOT NULL,
      changed_at  TEXT NOT NULL,
      reason      TEXT,
      source      TEXT NOT NULL DEFAULT 'user'
    )
    """,
    "CREATE INDEX IF NOT EXISTS config_history_key_at  ON config_history(key, changed_at DESC)",
    "CREATE INDEX IF NOT EXISTS config_history_user_at ON config_history(changed_by, changed_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS prompt_templates (
      call_site      TEXT PRIMARY KEY,
      template       TEXT NOT NULL,
      model_key      TEXT NOT NULL,
      temperature    REAL NOT NULL DEFAULT 0.2,
      max_tokens     INTEGER NOT NULL DEFAULT 4096,
      timeout_sec    INTEGER NOT NULL DEFAULT 30,
      enabled        INTEGER NOT NULL DEFAULT 1,
      updated_at     TEXT NOT NULL,
      updated_by     TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS prompt_versions (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      call_site    TEXT NOT NULL,
      template     TEXT NOT NULL,
      model_key    TEXT NOT NULL,
      temperature  REAL NOT NULL,
      max_tokens   INTEGER NOT NULL,
      timeout_sec  INTEGER NOT NULL,
      created_at   TEXT NOT NULL,
      created_by   TEXT NOT NULL,
      note         TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS prompt_versions_site_at ON prompt_versions(call_site, created_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS cluster_merge_rules (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      pattern     TEXT NOT NULL,
      replacement TEXT NOT NULL,
      enabled     INTEGER NOT NULL DEFAULT 1,
      priority    INTEGER NOT NULL DEFAULT 100,
      created_by  TEXT,
      created_at  TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS zabbix_instances (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      name           TEXT UNIQUE NOT NULL,
      api_url        TEXT NOT NULL,
      poller_user    TEXT NOT NULL,
      poller_pass    BLOB NOT NULL,
      webhook_user   TEXT,
      webhook_userid INTEGER,
      media_type_id  INTEGER,
      action_id      INTEGER,
      last_setup_at  TEXT,
      last_setup_ok  INTEGER,
      enabled        INTEGER NOT NULL DEFAULT 1
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS service_restart_log (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      service      TEXT NOT NULL,
      triggered_by TEXT NOT NULL,
      triggered_at TEXT NOT NULL,
      reason       TEXT,
      exit_code    INTEGER,
      duration_ms  INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL,
      note       TEXT
    )
    """,
]


def init_db(path: str) -> None:
    """Bootstrap schema. Idempotent (CREATE IF NOT EXISTS)."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        for stmt in DDL_STATEMENTS:
            conn.execute(stmt)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def get_conn(path: str | None = None) -> Iterator[sqlite3.Connection]:
    """Yield a connection with WAL + foreign keys. Caller commits / rolls back."""
    p = path or os.environ.get("DB_PATH") or "/data/admin.db"
    conn = sqlite3.connect(p, isolation_level=None)  # autocommit; caller uses transactions explicitly
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        conn.close()
