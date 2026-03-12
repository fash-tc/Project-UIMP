#!/bin/bash
# migrate-db.sh — One-time migration from monolith runbook.db to per-service databases
# Run BEFORE starting the new services for the first time.
#
# Usage: ./migrate-db.sh /path/to/runbook.db /path/to/auth.db /path/to/alert-states.db

set -euo pipefail

RUNBOOK_DB="${1:?Usage: migrate-db.sh <runbook.db> <auth.db> <alert-states.db>}"
AUTH_DB="${2:?}"
ALERT_STATE_DB="${3:?}"

if [ ! -f "$RUNBOOK_DB" ]; then
    echo "Source database not found: $RUNBOOK_DB"
    exit 1
fi

echo "=== Backing up original database ==="
cp "$RUNBOOK_DB" "${RUNBOOK_DB}.backup-$(date +%Y%m%d%H%M%S)"

echo "=== Migrating users table to auth.db ==="
sqlite3 "$AUTH_DB" <<'SQL'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    display_name TEXT,
    jira_email TEXT,
    jira_api_token TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
SQL

sqlite3 "$RUNBOOK_DB" ".dump users" | grep -E '^INSERT' | sqlite3 "$AUTH_DB" || echo "No user rows to migrate (will be seeded on startup)"

echo "=== Migrating alert_states table to alert-states.db ==="
sqlite3 "$ALERT_STATE_DB" <<'SQL'
CREATE TABLE IF NOT EXISTS alert_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_fingerprint TEXT UNIQUE NOT NULL,
    alert_name TEXT,
    investigating_user TEXT,
    investigating_since TEXT,
    acknowledged_by TEXT,
    acknowledged_at TEXT,
    ack_firing_start TEXT,
    is_updated INTEGER DEFAULT 0,
    updated_detected_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_as_fingerprint ON alert_states(alert_fingerprint);
SQL

sqlite3 "$RUNBOOK_DB" ".dump alert_states" | grep -E '^INSERT' | sqlite3 "$ALERT_STATE_DB" || echo "No alert_state rows to migrate"

echo "=== Migration complete ==="
echo "  auth.db:         $AUTH_DB"
echo "  alert-states.db: $ALERT_STATE_DB"
echo "  runbook.db:      $RUNBOOK_DB (unchanged, backup created)"
