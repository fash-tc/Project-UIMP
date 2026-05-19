# UIP Admin Page — Slice 1 (Foundation) Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `admin-api` service, the `uip_config_client` shared library, the auth-api permission extension, the nginx routing, and the empty admin tab scaffolding — so that subsequent slices (2-7) can add tabs and migrate consumers without rebuilding plumbing.

**Architecture:** New Python service `uip-admin-api` (port 8096) backed by `admin.db` (SQLite/WAL). New shared Python package `uip_config_client/` for consumers. Auth-api gets 8 new permissions seeded into existing roles. Nginx routes `/api/admin/*` to admin-api with separate locations for SSE (24h read timeout) and sandbox streaming (180s). Frontend gets a tab-nav layout at `/admin/*` with permission-gated rendering — no tab content yet (that's Slice 2+).

**Tech Stack:** Python 3.12 stdlib `http.server` + SQLite/WAL (matches existing service pattern); `cryptography` (Fernet, for secrets at rest); Next.js 14 (existing frontend); nginx (reverse proxy, existing). Deployment via SCP to `fash@10.177.154.196:~/uip/`. No new build pipeline.

**Spec reference:** [`docs/superpowers/specs/2026-05-19-uip-admin-page-design.md`](../specs/2026-05-19-uip-admin-page-design.md) — read sections 1, 3, 5, 6 (slice 1 only) before starting.

**Estimated effort:** 1 week (~5 working days at one engineer).

---

## Prerequisites (Slice 0)

Slice 0 — reconciling drift between server `~/uip/` and local `deploy/` — is out of scope for this plan but is a **hard prerequisite**. If the local repo doesn't match what's running on the server, this plan will produce code that conflicts with live config.

- [ ] **P1: Verify Slice 0 is complete**

Run:
```bash
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 'wc -l ~/uip/auth-api/auth-api.py'
wc -l deploy/auth-api/auth-api.py
```

Expected: line counts within 5% of each other. If local is significantly smaller (e.g., 302 vs 1285), STOP — Slice 0 hasn't been done. Run rsync first:

```bash
rsync -avz -e "ssh -i ~/.ssh/id_uip_deploy" \
  fash@10.177.154.196:~/uip/ \
  ./deploy/ \
  --exclude='*.bak-*' --exclude='backups/' --exclude='codex_tmp_test/' \
  --exclude='*.db' --exclude='*_data/' --exclude='postgres-init/' \
  --exclude='static/' --exclude='*.bak.codex-*' \
  --exclude='fix_*.py' --exclude='patch_*.py' --exclude='update_*.py' \
  --exclude='uip-*.tsx' --exclude='uip-*.ts' --exclude='uip-*.py' \
  --exclude='sre-frontend/node_modules' --exclude='sre-frontend/.next'
```

Commit the rsync result as a "drift reconciliation" commit before starting this plan.

- [ ] **P2: Create worktree for the implementation**

```bash
git worktree add ../UIP-admin-foundation -b feature/admin-foundation
cd ../UIP-admin-foundation
```

All steps below run from the worktree.

- [ ] **P3: Verify server access**

```bash
ssh -i ~/.ssh/id_uip_deploy -o BatchMode=yes fash@10.177.154.196 'hostname; docker ps --format "{{.Names}}" | wc -l'
```

Expected: prints `projectuimp` and a number ≥ 20. If this fails, fix SSH before continuing.

- [ ] **P4: Verify AI cluster reachability** (Slice 1 needs the cluster only for the model registry endpoint in Slice 3; this check is preflight)

```bash
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 'curl -s -m 5 http://aicompute01.cnco1.tucows.cloud:31434/api/version'
```

Expected: a JSON response. If it fails, cluster team should fix before proceeding.

---

## File Structure

This slice creates/modifies the following files. Each task references its files explicitly. Paths are relative to the repo root.

### Created

```
deploy/admin-api/
├── admin-api.py                      # entrypoint
├── requirements.txt                  # cryptography==42.*
├── db.py                             # schema bootstrap, WAL connection helper
├── auth.py                           # session validation against auth-api
├── secretbox.py                      # Fernet wrapper + HKDF derivation (NOT secrets.py — shadows stdlib)
├── sse.py                            # SSE broadcaster (ported from alert-state-api)
├── docker_ops.py                     # docker.sock client (stub for slice 2)
├── cluster.py                        # AI cluster /api/tags + /api/chat client
├── build_schemas.py                  # generates uip_config_client/schemas.py from config_seed.json
├── seeds/
│   ├── config_seed.json              # initial v1 seed (small; grows per slice)
│   └── services_seed.json            # restartable-container allowlist
├── routes/
│   ├── __init__.py
│   ├── _common.py                    # shared decorators (@requires_perm), JSON helpers
│   ├── config.py                     # /api/admin/config*, schemas/version, events (SSE)
│   └── audit.py                      # /api/admin/audit
└── tests/
    ├── conftest.py                   # pytest fixtures (temp DB, fake auth-api)
    ├── test_db.py
    ├── test_secrets.py
    ├── test_routes_config.py
    └── test_routes_audit.py

deploy/uip_config_client/
├── __init__.py                       # exports ConfigClient, KeySchema
├── client.py                         # ConfigClient implementation
├── schemas.py                        # GENERATED — do not edit by hand
└── tests/
    ├── conftest.py
    ├── test_client_env_fallback.py
    ├── test_client_sse_apply.py
    └── test_client_invalid_payload.py

docs/operator/
└── admin-api.md                      # one-page operator guide stub (filled in slice 7)
```

### Modified

```
deploy/auth-api/auth-api.py           # add 8 perms to ALL_PERMISSIONS, role-mapping seed migration
deploy/sre-frontend/src/lib/keep-api.ts   # add 8 perms to ALL_PERMISSIONS constant (line ~1786)
deploy/sre-frontend/src/app/admin/layout.tsx   # NEW file — tab nav, permission-gated rendering
deploy/sre-frontend/src/app/admin/page.tsx    # replace existing redirect logic (preserves users/roles tabs)
deploy/nginx-default.conf             # 4 new location blocks for /api/admin/*
deploy/docker-compose.yml             # add admin-api service + admin_data volume
deploy/.env.example                   # add ADMIN_BYPASS_TOKEN with empty default
```

### Untouched (but referenced)

```
deploy/alert-state-api/alert-state-api.py  # copy SSE pattern from here, do not modify
deploy/sre-frontend/src/lib/auth.ts        # useAuth hook is already present — reuse, do not modify
deploy/sre-frontend/src/hooks/useSSE.ts    # existing SSE hook — reuse in slice 2+
```

---

## Chunk 1: admin-api scaffolding + DB + secrets

### Task 1: Create admin-api directory and entrypoint

**Files:**
- Create: `deploy/admin-api/admin-api.py`
- Create: `deploy/admin-api/requirements.txt`

- [ ] **Step 1: Create directories and requirements**

Run from Git Bash / WSL (PowerShell doesn't expand `{a,b,c}`):
```bash
mkdir -p deploy/admin-api/routes deploy/admin-api/seeds deploy/admin-api/tests
```

Write `deploy/admin-api/requirements.txt`:
```
cryptography==42.0.5
pytest==8.1.1
```

Install for local development BEFORE running any tests:
```bash
pip install -r deploy/admin-api/requirements.txt
```

If you're not in a venv, the writing-plans skill recommends creating one:
```bash
python -m venv .venv && source .venv/bin/activate && pip install -r deploy/admin-api/requirements.txt
```

- [ ] **Step 2: Write the failing test (entrypoint health probe)**

Create `deploy/admin-api/tests/conftest.py`:
```python
import os
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import closing

import pytest


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def admin_api_server():
    """Spawn admin-api.py as a subprocess on a free port; yield (port, proc)."""
    port = _free_port()
    db_path = tempfile.mktemp(suffix=".db")
    env = {
        **os.environ,
        "API_PORT": str(port),
        "DB_PATH": db_path,
        "AUTH_API_URL": "http://127.0.0.1:1",   # invalid; tests override per-case
        "AUTH_SECRET": "test-secret-32-bytes-long-xxxxxx",
        "CLUSTER_ENDPOINT": "http://127.0.0.1:1",
        "ADMIN_BYPASS_TOKEN": "test-bypass",
    }
    proc = subprocess.Popen(
        [sys.executable, "-u", os.path.join(os.path.dirname(__file__), "..", "admin-api.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    # wait for port to open
    deadline = time.time() + 5
    while time.time() < deadline:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.05)
    else:
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=2)
            out_text = out.decode() if out else ""
        except subprocess.TimeoutExpired:
            proc.kill()
            out_text = "(timed out reading admin-api stdout)"
        raise RuntimeError(f"admin-api failed to start. Output:\n{out_text}")
    yield port, proc
    proc.terminate()
    try:
        # communicate() drains stdout/stderr and reaps the process; safe even
        # if the child still has pipe data buffered.
        proc.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    if os.path.exists(db_path):
        os.unlink(db_path)
```

Create `deploy/admin-api/tests/test_db.py` (a stub — we'll fill in Task 4):
```python
def test_smoke():
    """Placeholder so pytest collects the tests/ dir."""
    assert True
```

Create `deploy/admin-api/tests/test_health.py` (health/smoke probe lives here; route-specific tests go in `test_routes_*.py`):
```python
import urllib.request


def test_health_endpoint_returns_200(admin_api_server):
    port, _ = admin_api_server
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
        assert r.status == 200
        body = r.read().decode()
        assert "ok" in body.lower()
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd deploy/admin-api && python -m pytest tests/test_health.py::test_health_endpoint_returns_200 -v
```

Expected: FAIL — `admin-api.py` doesn't exist yet, fixture raises `RuntimeError: admin-api failed to start`.

- [ ] **Step 4: Write minimal entrypoint**

Create `deploy/admin-api/admin-api.py`:
```python
"""UIP admin-api — runtime config + control plane.

Stdlib http.server pattern (matches alert-state-api, auth-api, runbook-api).
"""
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("admin-api")

API_PORT = int(os.environ.get("API_PORT", "8096"))
DB_PATH = os.environ.get("DB_PATH", "/data/admin.db")
AUTH_API_URL = os.environ.get("AUTH_API_URL", "http://auth-api:8093")
AUTH_SECRET = os.environ["AUTH_SECRET"]  # required; crash fast if missing
ADMIN_BYPASS_TOKEN = os.environ.get("ADMIN_BYPASS_TOKEN") or None
CLUSTER_ENDPOINT = os.environ.get("CLUSTER_ENDPOINT", "")


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            return self._send_json(200, {"ok": True, "service": "admin-api"})
        self._send_json(404, {"error": "not found", "path": path})

    def log_message(self, fmt: str, *args) -> None:
        # Route http.server logs through logging instead of stderr
        log.info("%s - %s", self.address_string(), fmt % args)


def main() -> None:
    log.info("admin-api starting on :%s (DB=%s)", API_PORT, DB_PATH)
    server = ThreadingHTTPServer(("0.0.0.0", API_PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("admin-api stopped")
        server.shutdown()


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd deploy/admin-api && python -m pytest tests/test_health.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add deploy/admin-api/
git commit -m "feat(admin-api): scaffold service with /health endpoint"
```

---

### Task 2: SQLite schema bootstrap

**Files:**
- Create: `deploy/admin-api/db.py`
- Modify: `deploy/admin-api/admin-api.py` (wire `init_db` into startup)
- Test: `deploy/admin-api/tests/test_db.py`

- [ ] **Step 1: Write the failing test**

Replace `deploy/admin-api/tests/test_db.py`:
```python
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
    if os.path.exists(path):
        os.unlink(path)


def test_init_db_creates_all_tables(tmp_db):
    init_db(tmp_db)
    conn = sqlite3.connect(tmp_db)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
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
    assert mode.lower() == "wal"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd deploy/admin-api && python -m pytest tests/test_db.py -v
```

Expected: FAIL — `db.py` doesn't exist (ImportError).

- [ ] **Step 3: Write `db.py`**

Create `deploy/admin-api/db.py`:
```python
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
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd deploy/admin-api && python -m pytest tests/test_db.py -v
```

Expected: 3 PASS.

- [ ] **Step 5: Wire init_db into admin-api startup**

In `deploy/admin-api/admin-api.py`, add `from db import init_db` to the module-level imports at the top (next to `import json`, `import logging`, etc.) — lazy-imports inside `main()` mask startup ImportErrors.

Then in `main()`, before `server = ThreadingHTTPServer(...)`, insert:
```python
    init_db(DB_PATH)
    log.info("schema bootstrapped at %s", DB_PATH)
```

- [ ] **Step 6: Verify integrated startup test still passes**

```bash
cd deploy/admin-api && python -m pytest tests/ -v
```

Expected: all PASS (including the existing health test).

- [ ] **Step 7: Commit**

```bash
git add deploy/admin-api/db.py deploy/admin-api/admin-api.py deploy/admin-api/tests/test_db.py
git commit -m "feat(admin-api): SQLite schema bootstrap with WAL"
```

---

### Task 3: Secret box module (Fernet + HKDF)

**Files:**
- Create: `deploy/admin-api/secretbox.py` (NOT `secrets.py` — that name shadows the stdlib `secrets` module which is transitively imported by `cryptography`, `pytest`, and other deps when our package directory is on `sys.path`)
- Test: `deploy/admin-api/tests/test_secretbox.py`

- [ ] **Step 1: Write the failing test**

Create `deploy/admin-api/tests/test_secretbox.py`:
```python
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from secretbox import SecretBox, derive_fernet_key


def test_derive_fernet_key_is_deterministic():
    k1 = derive_fernet_key("master-secret-abc")
    k2 = derive_fernet_key("master-secret-abc")
    assert k1 == k2
    assert len(k1) == 44  # base64url-encoded 32 bytes


def test_derive_fernet_key_different_inputs_different_keys():
    assert derive_fernet_key("a") != derive_fernet_key("b")


def test_secretbox_roundtrip():
    box = SecretBox("master-secret-abc")
    cipher = box.encrypt(b"hello world")
    assert cipher != b"hello world"
    assert box.decrypt(cipher) == b"hello world"


def test_secretbox_rejects_tampered_ciphertext():
    box = SecretBox("master-secret-abc")
    cipher = bytearray(box.encrypt(b"hello"))
    cipher[-1] ^= 0x01  # flip a bit
    with pytest.raises(Exception):  # cryptography raises InvalidToken
        box.decrypt(bytes(cipher))


def test_secretbox_rejects_wrong_key():
    a = SecretBox("master-a").encrypt(b"hello")
    with pytest.raises(Exception):
        SecretBox("master-b").decrypt(a)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd deploy/admin-api && python -m pytest tests/test_secretbox.py -v
```

Expected: FAIL — `secretbox.py` doesn't exist (ModuleNotFoundError).

- [ ] **Step 3: Install dependency in dev**

```bash
pip install 'cryptography==42.0.5' pytest
```

- [ ] **Step 4: Write `secretbox.py`**

Create `deploy/admin-api/secretbox.py`:
```python
"""Symmetric encryption for is_secret=1 config values and zabbix poller_pass.

Key derivation: HKDF-SHA256 over AUTH_SECRET with a build-constant salt.
Encryption: Fernet (AES-128-CBC + HMAC-SHA256 with random IV per record).

WARNING: rotating AUTH_SECRET will brick every encrypted row. See spec §10.
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Build-constant salt. Rotating this == rotating master key. Do not change
# without a planned migration. 32 bytes.
_HKDF_SALT = bytes.fromhex(
    "9c1f0c8d4b21e3a6f54b7c2d8e9a05f1"
    "23456789abcdef0123456789abcdef01"
)
_HKDF_INFO = b"admin-api-secrets-v1"


def derive_fernet_key(master_secret: str) -> bytes:
    """Return a base64url-encoded 32-byte key suitable for Fernet."""
    if not master_secret:
        raise ValueError("master_secret must be non-empty")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    )
    key = hkdf.derive(master_secret.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


class SecretBox:
    """Lightweight wrapper around Fernet so callers don't see crypto primitives."""

    def __init__(self, master_secret: str | None = None) -> None:
        secret = master_secret if master_secret is not None else os.environ["AUTH_SECRET"]
        self._fernet = Fernet(derive_fernet_key(secret))

    def encrypt(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        return self._fernet.encrypt(bytes(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._fernet.decrypt(ciphertext)

    def encrypt_str(self, plaintext: str) -> bytes:
        return self.encrypt(plaintext.encode("utf-8"))

    def decrypt_str(self, ciphertext: bytes) -> str:
        return self.decrypt(ciphertext).decode("utf-8")
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd deploy/admin-api && python -m pytest tests/test_secretbox.py -v
```

Expected: 5 PASS.

- [ ] **Step 6: Commit**

```bash
git add deploy/admin-api/secretbox.py deploy/admin-api/tests/test_secretbox.py deploy/admin-api/requirements.txt
git commit -m "feat(admin-api): Fernet+HKDF SecretBox (avoid stdlib secrets shadow)"
```

---

### Task 4: Seed files (config_seed.json v1 + services_seed.json)

**Files:**
- Create: `deploy/admin-api/seeds/config_seed.json`
- Create: `deploy/admin-api/seeds/services_seed.json`

This task creates the **minimal v1 seed**. The full enumeration of every legacy env var → config key happens in Slice 1 as a separate sweep, but for the foundation we only need a small set so we can validate the schema-load path. Subsequent slices add more keys.

- [ ] **Step 1: Write `services_seed.json`**

Create `deploy/admin-api/seeds/services_seed.json`:
```json
{
  "version": 1,
  "restartable_containers": [
    "uip-alert-enricher",
    "uip-alert-state-api",
    "uip-auth-api",
    "uip-escalation-api",
    "uip-health-checker",
    "uip-loki-gateway",
    "uip-noc-escalation-bot-1",
    "uip-opensrs-health-api",
    "uip-runbook-api",
    "uip-sre-frontend",
    "uip-statuspage-api",
    "uip-uptime-watchdog"
  ],
  "notes": [
    "Allowlist for docker restart endpoint (§5.6). Container names verified live on server 2026-05-19.",
    "uip-keep-api, uip-keep-ui, uip-nginx, uip-postgres, uip-open-webui, uip-n8n, portainer intentionally excluded — restart via SSH only.",
    "uip-admin-api self-exclusion is enforced in docker_ops.py regardless of seed."
  ]
}
```

- [ ] **Step 2: Write `config_seed.json` v1**

Create `deploy/admin-api/seeds/config_seed.json`:
```json
{
  "version": 1,
  "keys": {
    "ai.cluster.endpoint": {
      "scope": "ai",
      "value_type": "string",
      "default": "http://aicompute01.cnco1.tucows.cloud:31434",
      "reload_kind": "hot",
      "description": "Base URL of the AI compute cluster.",
      "validation": {"regex": "^https?://[a-zA-Z0-9.\\-]+(:[0-9]+)?(/.*)?$"},
      "is_secret": false,
      "env_legacy": "OLLAMA_URL",
      "consumed_by": ["alert-enricher", "noc-escalation-bot", "opensrs-health-api"]
    },
    "ai.enricher.model": {
      "scope": "ai",
      "value_type": "string",
      "default": "qwen3-32b-thinking",
      "reload_kind": "hot",
      "description": "Model name for alert-enricher LLM calls.",
      "validation": null,
      "is_secret": false,
      "env_legacy": "OLLAMA_MODEL",
      "consumed_by": ["alert-enricher"]
    },
    "pipeline.enricher.poll_interval_sec": {
      "scope": "pipeline",
      "value_type": "int",
      "default": 60,
      "reload_kind": "hot",
      "description": "Seconds between enricher poll cycles.",
      "validation": {"min": 5, "max": 3600},
      "is_secret": false,
      "env_legacy": "POLL_INTERVAL",
      "consumed_by": ["alert-enricher"]
    },
    "features.admin.ai_sandbox": {
      "scope": "features",
      "value_type": "bool",
      "default": true,
      "reload_kind": "hot",
      "description": "Allow the /admin/ai sandbox to send test requests to the cluster.",
      "validation": null,
      "is_secret": false,
      "env_legacy": null,
      "consumed_by": ["admin-api"]
    }
  },
  "notes": [
    "v1 seed deliberately minimal. Slices 2-7 will add their own keys via seed bumps + migrations.",
    "Every entry must include: scope, value_type, default, reload_kind, description, validation, is_secret, env_legacy, consumed_by.",
    "env_legacy is null when the key has no historical env-var equivalent."
  ]
}
```

- [ ] **Step 3: Add unit tests that validate seed structure (separate file)**

Create `deploy/admin-api/tests/test_seeds.py` (keeps seed JSON validation independent from DB schema tests):
```python
import json
import os


def test_config_seed_has_required_fields():
    seed_path = os.path.join(os.path.dirname(__file__), "..", "seeds", "config_seed.json")
    with open(seed_path) as f:
        seed = json.load(f)
    assert seed["version"] >= 1
    required = {"scope", "value_type", "default", "reload_kind", "description", "validation", "is_secret", "env_legacy", "consumed_by"}
    for key, entry in seed["keys"].items():
        assert required.issubset(entry.keys()), f"{key} missing fields: {required - entry.keys()}"
        assert entry["value_type"] in {"int", "float", "string", "bool", "json", "secret"}
        assert entry["reload_kind"] in {"hot", "restart"}
        assert isinstance(entry["is_secret"], bool)


def test_services_seed_has_uip_admin_api_excluded():
    seed_path = os.path.join(os.path.dirname(__file__), "..", "seeds", "services_seed.json")
    with open(seed_path) as f:
        seed = json.load(f)
    assert "uip-admin-api" not in seed["restartable_containers"], \
        "admin-api must not be in restartable list (self-restart loops)"
```

- [ ] **Step 4: Run tests**

```bash
cd deploy/admin-api && python -m pytest tests/test_db.py tests/test_seeds.py -v
```

Expected: 5 PASS (3 from test_db.py, 2 from test_seeds.py).

- [ ] **Step 5: Commit**

```bash
git add deploy/admin-api/seeds/ deploy/admin-api/tests/test_seeds.py
git commit -m "feat(admin-api): seed v1 with 4 config keys + 12 restartable services"
```

---

## Chunk 2: Seed loader + schema generator + ConfigClient skeleton

### Task 5: Seed loader (config + services)

**Files:**
- Modify: `deploy/admin-api/db.py` (add `apply_seed` and `load_services_seed`)
- Modify: `deploy/admin-api/admin-api.py` (call seed loader on boot)
- Test: `deploy/admin-api/tests/test_db.py`

- [ ] **Step 1: Write the failing test**

Append to `deploy/admin-api/tests/test_db.py`:
```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd deploy/admin-api && python -m pytest tests/test_db.py -v
```

Expected: 5 NEW tests fail with import errors (`apply_seed` and `load_services_seed` not yet defined in `db`).

- [ ] **Step 3: Implement seed loader**

Append to `deploy/admin-api/db.py`:
```python
import json
import logging
from datetime import datetime, timezone

log = logging.getLogger("admin-api.db")

_SEEDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def apply_seed(db_path: str) -> None:
    """Apply config_seed.json. Idempotent. Honours env_legacy on first insert only."""
    seed_path = os.path.join(_SEEDS_DIR, "config_seed.json")
    with open(seed_path) as f:
        seed = json.load(f)
    seed_version = int(seed.get("version", 1))

    with get_conn(db_path) as conn:
        existing = {r["key"] for r in conn.execute("SELECT key FROM config")}
        now = _utc_now_iso()
        for key, entry in seed["keys"].items():
            if key in existing:
                continue
            # Use env_legacy if set on first insert, otherwise default
            env_legacy = entry.get("env_legacy")
            raw_value = os.environ.get(env_legacy) if env_legacy else None
            value = _parse_env_value(raw_value, entry["value_type"]) if raw_value is not None else entry["default"]
            conn.execute(
                """
                INSERT INTO config
                (key, scope, value, value_type, reload_kind, restart_target,
                 default_value, description, validation, is_secret,
                 updated_at, updated_by, seed_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    entry["scope"],
                    json.dumps(value),
                    entry["value_type"],
                    entry["reload_kind"],
                    entry.get("restart_target"),
                    json.dumps(entry["default"]),
                    entry.get("description"),
                    json.dumps(entry.get("validation")) if entry.get("validation") is not None else None,
                    1 if entry.get("is_secret") else 0,
                    now,
                    "__seed__",
                    seed_version,
                ),
            )
            conn.execute(
                "INSERT INTO config_history (key, old_value, new_value, changed_by, changed_at, reason, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (key, None, json.dumps(value), "__seed__", now, f"seed v{seed_version}", "seed"),
            )
            log.info("seed: inserted key=%s value_source=%s", key, "env_legacy" if raw_value else "default")


def _parse_env_value(raw: str, value_type: str):
    if value_type == "int":
        return int(raw)
    if value_type == "float":
        return float(raw)
    if value_type == "bool":
        return raw.lower() in {"1", "true", "yes", "on"}
    if value_type == "json":
        return json.loads(raw)
    # string, secret
    return raw


def load_services_seed() -> list[str]:
    path = os.path.join(_SEEDS_DIR, "services_seed.json")
    with open(path) as f:
        return json.load(f)["restartable_containers"]
```

- [ ] **Step 4: Wire into admin-api.py startup**

In `deploy/admin-api/admin-api.py` `main()`, after `init_db(DB_PATH)`, add:
```python
    from db import apply_seed
    apply_seed(DB_PATH)
    log.info("seed applied")
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd deploy/admin-api && python -m pytest tests/ -v
```

Expected: 8 PASS (3 from test_db.py original + 5 new test_db.py seed-loader tests + 2 from test_seeds.py + 1 from test_health.py + Task 3 test_secretbox tests if already run). Count by file rather than total — Step 5 only asserts no failures.

- [ ] **Step 6: Commit**

```bash
git add deploy/admin-api/db.py deploy/admin-api/admin-api.py deploy/admin-api/tests/test_db.py
git commit -m "feat(admin-api): seed loader with env_legacy bridge"
```

---

### Task 6: Schema generator (build_schemas.py)

**Files:**
- Create: `deploy/admin-api/build_schemas.py`
- Create: `deploy/uip_config_client/__init__.py`
- Create: `deploy/uip_config_client/schemas.py` (initial empty placeholder)

- [ ] **Step 1: Create generator skeleton**

Create `deploy/admin-api/build_schemas.py`:
```python
"""Regenerates uip_config_client/schemas.py from config_seed.json.

Run from repo root: python deploy/admin-api/build_schemas.py

Output: deploy/uip_config_client/schemas.py — a frozen dataclass dict that
consumers load to validate SSE payloads (spec §5.5.1).
"""
import json
import os
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
SEED = HERE / "seeds" / "config_seed.json"
OUT = HERE.parent / "uip_config_client" / "schemas.py"

HEADER = '''"""GENERATED FILE. Do not edit by hand.

Regenerate with: python deploy/admin-api/build_schemas.py

Source: deploy/admin-api/seeds/config_seed.json
"""
from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class KeySchema:
    value_type: Literal["int", "float", "string", "bool", "json", "secret"]
    validation_rule: dict | None
    seed_version: int


'''


def render() -> str:
    seed = json.loads(SEED.read_text())
    seed_version = int(seed.get("version", 1))
    lines = [HEADER, f"SEED_VERSION = {seed_version}\n\n", "SCHEMAS: dict[str, KeySchema] = {\n"]
    for key in sorted(seed["keys"]):
        entry = seed["keys"][key]
        vt = entry["value_type"]
        v = entry.get("validation")
        v_repr = repr(v) if v is not None else "None"
        lines.append(
            f"    {key!r}: KeySchema(value_type={vt!r}, validation_rule={v_repr}, seed_version={seed_version}),\n"
        )
    lines.append("}\n")
    return "".join(lines)


def main() -> int:
    out_dir = OUT.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    # __init__.py is hand-authored in Task 6 Step 2 and intentionally not
    # overwritten here; the generator owns ONLY schemas.py.
    OUT.write_text(render())
    print(f"wrote {OUT} ({len(json.loads(SEED.read_text())['keys'])} keys)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Create placeholder package init**

Create `deploy/uip_config_client/__init__.py`:
```python
"""uip_config_client — shared library for consuming admin-api config.

Imported by every UIP service (alert-enricher, noc-escalation-bot, etc.)
that needs to read runtime config from admin-api with env fallback.
"""
from .client import ConfigClient  # noqa: F401
from .schemas import KeySchema, SEED_VERSION, SCHEMAS  # noqa: F401
```

Note: `client.py` doesn't exist yet (created in Task 7) and `schemas.py` is a placeholder until Step 3. Both imports will fail at import time **right now**, which is fine — Task 6 Step 3 generates a valid `schemas.py` and Task 7 Step 3 creates `client.py`. Tests in this task run only the generator script (subprocess) and don't `import uip_config_client`, so they pass without the package being loadable yet.

Create `deploy/uip_config_client/schemas.py` (placeholder; will be overwritten):
```python
"""Placeholder. Run `python deploy/admin-api/build_schemas.py` to generate."""
SEED_VERSION = 0
SCHEMAS = {}
```

- [ ] **Step 3: Run the generator**

```bash
python deploy/admin-api/build_schemas.py
```

Expected output:
```
wrote deploy/uip_config_client/schemas.py (4 keys)
```

- [ ] **Step 4: Verify the generated file**

```bash
cat deploy/uip_config_client/schemas.py
```

Should contain four entries: `ai.cluster.endpoint`, `ai.enricher.model`, `pipeline.enricher.poll_interval_sec`, `features.admin.ai_sandbox`.

- [ ] **Step 5: Write a test that locks the generator round-trip**

Create `deploy/admin-api/tests/test_build_schemas.py`:
```python
import json
import os
import subprocess
import sys
from pathlib import Path


def test_generator_writes_expected_keys(tmp_path):
    # Generate to tmp; compare contents
    here = Path(__file__).resolve().parent.parent
    out = subprocess.check_output([sys.executable, str(here / "build_schemas.py")], text=True)
    assert "wrote" in out
    schemas = (here.parent / "uip_config_client" / "schemas.py").read_text()
    seed = json.loads((here / "seeds" / "config_seed.json").read_text())
    for key in seed["keys"]:
        assert key in schemas, f"key {key} missing from generated schemas"
    assert f"SEED_VERSION = {seed['version']}" in schemas
```

- [ ] **Step 6: Run the test**

```bash
cd deploy/admin-api && python -m pytest tests/test_build_schemas.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add deploy/admin-api/build_schemas.py deploy/uip_config_client/ deploy/admin-api/tests/test_build_schemas.py
git commit -m "feat(admin-api): build_schemas.py generates uip_config_client/schemas.py from seed"
```

---

### Task 7: ConfigClient skeleton (env-only fallback)

**Files:**
- Create: `deploy/uip_config_client/client.py`
- Create: `deploy/uip_config_client/tests/__init__.py` (empty)
- Test: `deploy/uip_config_client/tests/test_client_env_fallback.py`

This task implements the **env-fallback path only**. SSE and live polling are added in Task 8 so we can keep this commit small.

- [ ] **Step 1: Write the failing test**

Create `deploy/uip_config_client/tests/conftest.py`:
```python
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
```

Create `deploy/uip_config_client/tests/test_client_env_fallback.py`:
```python
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
```

- [ ] **Step 2: Run test — verify failure**

```bash
cd deploy/uip_config_client && python -m pytest tests/ -v
```

Expected: FAIL — `ConfigClient` not implemented.

- [ ] **Step 3: Implement minimal ConfigClient**

Create `deploy/uip_config_client/client.py`:
```python
"""ConfigClient — shared library for consuming admin-api config.

This is the env-fallback skeleton (Task 7). SSE + live polling come in Task 8.
"""
import json
import logging
import os
import threading
import urllib.request
from typing import Any, Callable

from .schemas import SCHEMAS, KeySchema

log = logging.getLogger("uip_config_client")

_SENTINEL = object()


class ConfigClient:
    def __init__(
        self,
        admin_api: str = "http://admin-api:8096",
        env_fallback: bool = True,
        poll_interval_sec: int = 30,
        sse_reconnect_max_sec: int = 60,
        on_invalid_payload: Callable[[dict, Exception], None] | None = None,
        schemas: dict[str, KeySchema] | None = None,
        env_legacy_map: dict[str, tuple[str, str]] | None = None,
    ) -> None:
        self._admin_api = admin_api.rstrip("/")
        self._env_fallback = env_fallback
        self._poll_interval = poll_interval_sec
        self._sse_max = sse_reconnect_max_sec
        self._on_invalid = on_invalid_payload or self._default_on_invalid
        self._schemas: dict[str, KeySchema] = dict(SCHEMAS)
        if schemas:
            self._schemas.update(schemas)
        # env_legacy_map: {key: (env_var_name, value_type)}.
        # In Task 8 this is loaded from admin-api; for now caller passes it.
        self._env_legacy = env_legacy_map or {}
        self._values: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._listeners: dict[str, list[Callable[[Any, Any], None]]] = {}
        self._snapshot_loaded = False
        # Cold-start snapshot attempt (silent if admin-api is down)
        self._try_initial_snapshot()

    # --- public ---

    def register_schema(self, key: str, schema: KeySchema) -> None:
        with self._lock:
            self._schemas[key] = schema

    def get(self, key: str, default: Any = _SENTINEL) -> Any:
        with self._lock:
            if key in self._values:
                return self._values[key]
        # Snapshot didn't have it. Try env_legacy.
        if self._env_fallback and key in self._env_legacy:
            env_name, vtype = self._env_legacy[key]
            raw = os.environ.get(env_name)
            if raw is not None:
                return self._coerce(raw, vtype)
        # Or env via UPPER_SNAKE conversion (best-effort, only if env_fallback)
        if self._env_fallback:
            snake = key.upper().replace(".", "_")
            raw = os.environ.get(snake)
            if raw is not None:
                # we don't know value_type from key alone; check schema
                schema = self._schemas.get(key)
                if schema:
                    return self._coerce(raw, schema.value_type)
        if default is not _SENTINEL:
            return default
        raise KeyError(key)

    def on_change(self, key: str, callback: Callable[[Any, Any], None]) -> None:
        with self._lock:
            self._listeners.setdefault(key, []).append(callback)

    def get_all(self, scope: str | None = None) -> dict[str, Any]:
        with self._lock:
            if scope is None:
                return dict(self._values)
            # We don't track scope locally in the values dict; if needed,
            # consumers can call /api/admin/config?scope=… directly. Returning
            # the union is fine for boot-time dumps.
            return {k: v for k, v in self._values.items() if k.startswith(f"{scope}.")}

    # --- internals ---

    def _coerce(self, raw: str, vtype: str) -> Any:
        if vtype == "int":
            return int(raw)
        if vtype == "float":
            return float(raw)
        if vtype == "bool":
            return raw.lower() in {"1", "true", "yes", "on"}
        if vtype == "json":
            return json.loads(raw)
        return raw

    def _try_initial_snapshot(self) -> None:
        try:
            with urllib.request.urlopen(f"{self._admin_api}/api/admin/config", timeout=2) as r:
                data = json.loads(r.read().decode())
                with self._lock:
                    for entry in data.get("items", []):
                        self._values[entry["key"]] = entry["value"]
                    self._snapshot_loaded = True
                log.info("initial snapshot loaded: %d keys", len(self._values))
        except Exception as e:
            log.warning("initial snapshot failed (will use env fallback): %s", e)

    def _default_on_invalid(self, payload: dict, exc: Exception) -> None:
        log.warning("invalid_config=true key=%s err=%s", payload.get("key"), exc)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd deploy/uip_config_client && python -m pytest tests/ -v
```

Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/uip_config_client/client.py deploy/uip_config_client/tests/
git commit -m "feat(uip_config_client): ConfigClient env-fallback resolution"
```

---

## Chunk 3: SSE + auth + routes

### Task 8: SSE broadcaster (ported from alert-state-api)

**Files:**
- Create: `deploy/admin-api/sse.py`
- Test: extend `deploy/admin-api/tests/test_routes_config.py`

- [ ] **Step 1: Reference the existing pattern**

Read `deploy/alert-state-api/alert-state-api.py` lines 29-54 and 695-726 to confirm the pattern matches. (After Slice 0 rsync, these line ranges should match the server.) Don't change that file.

- [ ] **Step 2: Write a failing test for /api/admin/config/events**

Append to `deploy/admin-api/tests/test_routes_config.py`:
```python
import threading
import time


def test_sse_events_endpoint_streams(admin_api_server):
    port, _ = admin_api_server

    received = []

    def reader():
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/admin/config/events", timeout=5) as r:
            for line in r:
                received.append(line.decode())
                if len(received) >= 3:
                    return

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    time.sleep(0.3)  # let client connect

    # broadcast something
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from sse import broadcast
    broadcast("config_changed", {"key": "test.key", "new_value": "test", "updated_by": "test", "updated_at": "2026-05-19T22:00:00Z", "reload_kind": "hot", "restart_target": None})

    t.join(timeout=2)
    blob = "".join(received)
    assert "event: config_changed" in blob
    assert "test.key" in blob
```

- [ ] **Step 3: Run — verify failure**

```bash
cd deploy/admin-api && python -m pytest tests/test_routes_config.py::test_sse_events_endpoint_streams -v
```

Expected: FAIL — no `/events` endpoint exists.

- [ ] **Step 4: Implement sse.py**

Create `deploy/admin-api/sse.py`:
```python
"""SSE broadcaster — same pattern as alert-state-api.py _sse_broadcast.

Holds a set of `wfile` writers. broadcast() iterates and removes dead ones.
The route handler in routes/config.py wires up subscribers.
"""
import json
import logging
import threading
from typing import Any

log = logging.getLogger("admin-api.sse")

_lock = threading.Lock()
_clients: set[Any] = set()  # set of BufferedWriter (handler.wfile)
_event_counter = 0
_MAX_CLIENTS = 50


def add_client(wfile) -> None:
    with _lock:
        if len(_clients) >= _MAX_CLIENTS:
            raise RuntimeError("SSE client limit reached")
        _clients.add(wfile)
        log.info("SSE client connected (total=%d)", len(_clients))


def remove_client(wfile) -> None:
    with _lock:
        _clients.discard(wfile)
        log.info("SSE client disconnected (total=%d)", len(_clients))


def broadcast(event_type: str, payload: dict) -> None:
    """Push an SSE event to all connected clients. Drops dead writers."""
    global _event_counter
    with _lock:
        _event_counter += 1
        event_id = _event_counter
        clients = list(_clients)

    data = json.dumps(payload)
    msg = f"id: {event_id}\nevent: {event_type}\ndata: {data}\n\n".encode()
    dead = []
    for c in clients:
        try:
            c.write(msg)
            c.flush()
        except Exception as e:
            log.warning("SSE write failed: %s", e)
            dead.append(c)
    if dead:
        with _lock:
            for d in dead:
                _clients.discard(d)
            log.info("Removed %d dead SSE client(s), %d remaining", len(dead), len(_clients))
```

- [ ] **Step 5: Wire SSE endpoint into the handler**

Edit `deploy/admin-api/admin-api.py` `Handler.do_GET`:

Replace the existing `do_GET` body with:
```python
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            return self._send_json(200, {"ok": True, "service": "admin-api"})
        if path == "/api/admin/config/events":
            return self._handle_sse()
        self._send_json(404, {"error": "not found", "path": path})

    def _handle_sse(self) -> None:
        from sse import add_client, remove_client
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            add_client(self.wfile)
            # Block until client disconnects. ThreadingHTTPServer handles many.
            # We rely on broadcast() to write; we just hold the connection.
            try:
                while True:
                    # Send a keepalive every 25s
                    import time
                    time.sleep(25)
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except Exception:
                        break
            finally:
                remove_client(self.wfile)
        except Exception as e:
            log.warning("SSE handler error: %s", e)
```

- [ ] **Step 6: Run test — verify PASS**

```bash
cd deploy/admin-api && python -m pytest tests/test_routes_config.py -v
```

Expected: 2 PASS (health + SSE).

- [ ] **Step 7: Commit**

```bash
git add deploy/admin-api/sse.py deploy/admin-api/admin-api.py deploy/admin-api/tests/test_routes_config.py
git commit -m "feat(admin-api): SSE /api/admin/config/events with broadcast()"
```

---

### Task 9: Auth client (session validation against auth-api)

**Files:**
- Create: `deploy/admin-api/auth.py`
- Test: `deploy/admin-api/tests/test_auth.py`

- [ ] **Step 1: Write the failing test**

Create `deploy/admin-api/tests/test_auth.py`:
```python
import http.server
import json
import os
import socket
import sys
import threading
import time
from contextlib import closing

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest

from auth import resolve_user, BypassUser


def _free_port():
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeAuthApi(http.server.BaseHTTPRequestHandler):
    """In-process fake auth-api that returns canned /me responses."""
    canned_responses = {}  # cookie → (status, body)

    def do_GET(self):
        if self.path != "/me":
            self.send_error(404); return
        cookie = self.headers.get("Cookie", "")
        status, body = self.canned_responses.get(cookie, (401, {"error": "unauth"}))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        body_bytes = json.dumps(body).encode()
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, *args):
        pass  # quiet


@pytest.fixture
def fake_auth():
    port = _free_port()
    FakeAuthApi.canned_responses = {}
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), FakeAuthApi)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    yield port, FakeAuthApi.canned_responses
    server.shutdown()


def test_resolve_user_with_valid_session(fake_auth, monkeypatch):
    port, canned = fake_auth
    canned["session=abc"] = (200, {"username": "alice", "permissions": ["manage_ai"]})
    monkeypatch.setenv("AUTH_API_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("ADMIN_BYPASS_TOKEN", "")
    user = resolve_user(cookie="session=abc", bypass_header=None)
    assert user.username == "alice"
    assert "manage_ai" in user.permissions


def test_resolve_user_with_bypass_token(monkeypatch):
    monkeypatch.setenv("AUTH_API_URL", "http://127.0.0.1:1")  # unreachable on purpose
    monkeypatch.setenv("ADMIN_BYPASS_TOKEN", "secret-bypass")
    user = resolve_user(cookie=None, bypass_header="secret-bypass", remote_ip="10.0.0.5")
    assert isinstance(user, BypassUser)
    assert user.username == "__bypass__:10.0.0.5"


def test_resolve_user_wrong_bypass_token_falls_to_session(monkeypatch):
    monkeypatch.setenv("AUTH_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("ADMIN_BYPASS_TOKEN", "real")
    user = resolve_user(cookie=None, bypass_header="wrong", remote_ip="10.0.0.5")
    assert user is None  # no valid session, bypass mismatch


def test_resolve_user_no_session_no_bypass(monkeypatch):
    monkeypatch.setenv("AUTH_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("ADMIN_BYPASS_TOKEN", "")
    assert resolve_user(cookie=None, bypass_header=None) is None
```

- [ ] **Step 2: Run — verify failure**

```bash
cd deploy/admin-api && python -m pytest tests/test_auth.py -v
```

Expected: FAIL — `auth.py` not implemented.

- [ ] **Step 3: Implement auth.py**

Create `deploy/admin-api/auth.py`:
```python
"""Session validation client. Asks auth-api /me to resolve cookie → user.

Also supports the ADMIN_BYPASS_TOKEN escape hatch (spec §3.3).
"""
import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger("admin-api.auth")


@dataclass
class User:
    username: str
    permissions: list[str] = field(default_factory=list)


@dataclass
class BypassUser(User):
    """Synthetic user materialized when X-Admin-Bypass header matches the token."""
    pass


def _all_permissions() -> list[str]:
    """Returns the full UIP permission set. Used by BypassUser for full access.
    Kept simple: bypass has '*' which routes treat as omnipotent."""
    return ["*"]


def resolve_user(cookie: str | None, bypass_header: str | None, remote_ip: str = "0.0.0.0") -> User | None:
    """Return a User if the request is authenticated, else None.

    Priority:
      1. X-Admin-Bypass header matching ADMIN_BYPASS_TOKEN (if set) → BypassUser.
      2. Session cookie → /me on auth-api → User.
      3. Otherwise None (handler returns 401).
    """
    token = (os.environ.get("ADMIN_BYPASS_TOKEN") or "").strip()
    if bypass_header:
        # Log every bypass attempt — match goes through, mismatch is noisy security signal.
        if token and bypass_header == token:
            log.warning("audit_bypass=true result=match ip=%s", remote_ip)
            return BypassUser(username=f"__bypass__:{remote_ip}", permissions=_all_permissions())
        log.warning("audit_bypass=true result=reject ip=%s", remote_ip)

    if not cookie:
        return None
    base = os.environ.get("AUTH_API_URL", "http://auth-api:8093").rstrip("/")
    req = urllib.request.Request(f"{base}/me", headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            if r.status != 200:
                return None
            data = json.loads(r.read().decode())
            return User(username=data.get("username", ""), permissions=data.get("permissions", []))
    except urllib.error.HTTPError:
        return None
    except Exception as e:
        log.warning("auth-api unreachable: %s", e)
        return None
```

- [ ] **Step 4: Run tests — verify PASS**

```bash
cd deploy/admin-api && python -m pytest tests/test_auth.py -v
```

Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/admin-api/auth.py deploy/admin-api/tests/test_auth.py
git commit -m "feat(admin-api): auth.py with ADMIN_BYPASS_TOKEN escape hatch"
```

---

### Task 10: routes/_common.py — permission decorator + JSON helpers

**Files:**
- Create: `deploy/admin-api/routes/__init__.py` (empty)
- Create: `deploy/admin-api/routes/_common.py`
- Test: `deploy/admin-api/tests/test_routes_common.py`

- [ ] **Step 1: Write the failing test**

Create `deploy/admin-api/routes/__init__.py` (empty).

Create `deploy/admin-api/tests/test_routes_common.py`:
```python
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest

from auth import User, BypassUser
from routes._common import has_permission


def test_user_with_perm_passes():
    u = User(username="alice", permissions=["manage_ai", "view_audit"])
    assert has_permission(u, "manage_ai")


def test_user_without_perm_fails():
    u = User(username="bob", permissions=["view_audit"])
    assert not has_permission(u, "manage_ai")


def test_bypass_user_has_all_perms():
    b = BypassUser(username="__bypass__:0", permissions=["*"])
    assert has_permission(b, "manage_ai")
    assert has_permission(b, "any.weird.perm")
```

- [ ] **Step 2: Run — verify failure**

```bash
cd deploy/admin-api && python -m pytest tests/test_routes_common.py -v
```

Expected: FAIL — `routes._common` not implemented.

- [ ] **Step 3: Implement _common.py**

Create `deploy/admin-api/routes/_common.py`:
```python
"""Shared helpers for route modules: permission check, JSON IO."""
import json
import logging
from http.server import BaseHTTPRequestHandler

from auth import User

log = logging.getLogger("admin-api.routes")


def has_permission(user: User | None, perm: str) -> bool:
    if user is None:
        return False
    if "*" in user.permissions:
        return True
    return perm in user.permissions


def send_json(handler: BaseHTTPRequestHandler, status: int, body) -> None:
    data = json.dumps(body).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def read_json_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    return json.loads(raw.decode())


def forbid(handler: BaseHTTPRequestHandler) -> None:
    send_json(handler, 403, {"error": "forbidden"})


def unauthorized(handler: BaseHTTPRequestHandler) -> None:
    send_json(handler, 401, {"error": "unauthorized"})
```

- [ ] **Step 4: Run tests — verify PASS**

```bash
cd deploy/admin-api && python -m pytest tests/test_routes_common.py -v
```

Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/admin-api/routes/
git commit -m "feat(admin-api): routes/_common.py with has_permission helper"
```

---

### Task 11: routes/config.py — config read/write + schemas/version

**Files:**
- Create: `deploy/admin-api/routes/config.py`
- Modify: `deploy/admin-api/admin-api.py` (wire route dispatch)
- Test: extend `deploy/admin-api/tests/test_routes_config.py`

- [ ] **Step 1: Write failing tests for GET / PATCH / DELETE**

Append to `deploy/admin-api/tests/test_routes_config.py`:
```python
import urllib.request
import urllib.error
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _call(port, method, path, body=None, headers=None):
    headers = dict(headers or {})
    headers.setdefault("X-Admin-Bypass", "test-bypass")  # fixture sets this token
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_get_config_lists_seeded_keys(admin_api_server):
    port, _ = admin_api_server
    status, body = _call(port, "GET", "/api/admin/config")
    assert status == 200
    keys = {item["key"] for item in body["items"]}
    assert "ai.cluster.endpoint" in keys


def test_get_config_filtered_by_scope(admin_api_server):
    port, _ = admin_api_server
    status, body = _call(port, "GET", "/api/admin/config?scope=ai")
    assert status == 200
    assert all(item["key"].startswith("ai.") for item in body["items"])
    assert len(body["items"]) >= 2


def test_get_single_key(admin_api_server):
    port, _ = admin_api_server
    status, body = _call(port, "GET", "/api/admin/config/ai.cluster.endpoint")
    assert status == 200
    assert body["key"] == "ai.cluster.endpoint"
    assert body["value"].startswith("http")


def test_patch_writes_history_and_broadcasts(admin_api_server):
    port, _ = admin_api_server
    status, body = _call(port, "PATCH", "/api/admin/config/ai.enricher.model",
                          body={"value": "qwen3-235b-thinking", "reason": "test bump"})
    assert status == 200, body
    # Read back
    status, body = _call(port, "GET", "/api/admin/config/ai.enricher.model")
    assert body["value"] == "qwen3-235b-thinking"


def test_patch_validation_failure_returns_400(admin_api_server):
    port, _ = admin_api_server
    status, body = _call(port, "PATCH", "/api/admin/config/pipeline.enricher.poll_interval_sec",
                          body={"value": 2})  # below min=5
    assert status == 400


def test_delete_resets_to_default(admin_api_server):
    port, _ = admin_api_server
    _call(port, "PATCH", "/api/admin/config/ai.enricher.model", body={"value": "qwen3-235b-thinking"})
    status, body = _call(port, "DELETE", "/api/admin/config/ai.enricher.model")
    assert status == 200
    status, body = _call(port, "GET", "/api/admin/config/ai.enricher.model")
    assert body["value"] == "qwen3-32b-thinking"  # default


def test_get_schemas_version(admin_api_server):
    port, _ = admin_api_server
    status, body = _call(port, "GET", "/api/admin/config/schemas/version")
    assert status == 200
    assert body["seed_version"] >= 1


def test_unauthenticated_returns_401(admin_api_server):
    port, _ = admin_api_server
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/admin/config")
    try:
        urllib.request.urlopen(req, timeout=2)
        assert False, "expected 401"
    except urllib.error.HTTPError as e:
        assert e.code == 401
```

- [ ] **Step 2: Run — verify failure**

```bash
cd deploy/admin-api && python -m pytest tests/test_routes_config.py -v
```

Expected: 8 FAIL (all new tests; SSE/health still pass).

- [ ] **Step 3: Implement routes/config.py**

Create `deploy/admin-api/routes/config.py`:
```python
"""GET/PATCH/DELETE /api/admin/config* + /schemas/version.

Validation rules live alongside the value in the config row (`validation`
column). We re-validate server-side here, even though the UI also validates.
"""
import json
import logging
import re
from datetime import datetime, timezone

from db import get_conn
from sse import broadcast
from routes._common import has_permission, send_json, read_json_body, forbid, unauthorized
from auth import resolve_user

log = logging.getLogger("admin-api.routes.config")


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_dict(row) -> dict:
    return {
        "key": row["key"],
        "scope": row["scope"],
        "value": "***SET***" if row["is_secret"] else json.loads(row["value"]),
        "value_type": row["value_type"],
        "reload_kind": row["reload_kind"],
        "restart_target": row["restart_target"],
        "default": json.loads(row["default_value"]),
        "description": row["description"],
        "validation": json.loads(row["validation"]) if row["validation"] else None,
        "is_secret": bool(row["is_secret"]),
        "secret_rotated_at": row["secret_rotated_at"],
        "updated_at": row["updated_at"],
        "updated_by": row["updated_by"],
        "seed_version": row["seed_version"],
    }


def _validate(value, vtype: str, rule: dict | None) -> str | None:
    """Return error message if invalid, else None."""
    # Type check
    if vtype == "int":
        if not isinstance(value, int) or isinstance(value, bool):
            return f"expected int, got {type(value).__name__}"
    elif vtype == "float":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return f"expected number, got {type(value).__name__}"
    elif vtype == "bool":
        if not isinstance(value, bool):
            return f"expected bool, got {type(value).__name__}"
    elif vtype == "string":
        if not isinstance(value, str):
            return f"expected string, got {type(value).__name__}"
    # Rule check
    if not rule:
        return None
    if vtype in ("int", "float"):
        if "min" in rule and value < rule["min"]:
            return f"value {value} below min {rule['min']}"
        if "max" in rule and value > rule["max"]:
            return f"value {value} above max {rule['max']}"
    if vtype == "string":
        if "regex" in rule and not re.match(rule["regex"], value):
            return f"value does not match regex {rule['regex']}"
        if "enum" in rule and value not in rule["enum"]:
            return f"value not in enum {rule['enum']}"
    return None


def handle(handler, method: str, path: str, query: dict, db_path: str) -> bool:
    """Dispatch /api/admin/config* routes. Returns True if handled."""
    # Auth
    cookie = handler.headers.get("Cookie")
    bypass = handler.headers.get("X-Admin-Bypass")
    user = resolve_user(cookie, bypass, remote_ip=handler.client_address[0])

    if path == "/api/admin/config" and method == "GET":
        if user is None:
            unauthorized(handler); return True
        if not has_permission(user, "view_admin"):
            # Slice 1 gates by view_admin only; Slice 2+ tightens to per-scope perms.
            forbid(handler); return True
        scope = query.get("scope")
        with get_conn(db_path) as conn:
            if scope:
                rows = conn.execute("SELECT * FROM config WHERE scope=? ORDER BY key", (scope,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM config ORDER BY key").fetchall()
        send_json(handler, 200, {"items": [_row_to_dict(r) for r in rows]})
        return True

    if path == "/api/admin/config/schemas/version" and method == "GET":
        from uip_config_client.schemas import SEED_VERSION
        send_json(handler, 200, {"seed_version": SEED_VERSION})
        return True

    # /api/admin/config/{key}  (GET, PATCH, DELETE)
    if path.startswith("/api/admin/config/") and "/" not in path[len("/api/admin/config/"):]:
        key = path[len("/api/admin/config/"):]
        if not key:
            send_json(handler, 400, {"error": "missing key"}); return True

        if method == "GET":
            if user is None: unauthorized(handler); return True
            with get_conn(db_path) as conn:
                row = conn.execute("SELECT * FROM config WHERE key=?", (key,)).fetchone()
            if row is None:
                send_json(handler, 404, {"error": "not found", "key": key}); return True
            send_json(handler, 200, _row_to_dict(row))
            return True

        if method == "PATCH":
            if user is None: unauthorized(handler); return True
            if not has_permission(user, "view_admin"):
                forbid(handler); return True
            body = read_json_body(handler)
            new_value = body.get("value")
            reason = body.get("reason")
            with get_conn(db_path) as conn:
                row = conn.execute("SELECT * FROM config WHERE key=?", (key,)).fetchone()
                if row is None:
                    send_json(handler, 404, {"error": "not found", "key": key}); return True
                # Secrets must go through POST /rotate-secret (Fernet path); PATCH on is_secret=1
                # would overwrite ciphertext with raw plaintext.
                if row["is_secret"]:
                    send_json(handler, 409, {"error": "use POST /api/admin/config/{key}/rotate-secret for is_secret=1 keys"}); return True
                rule = json.loads(row["validation"]) if row["validation"] else None
                err = _validate(new_value, row["value_type"], rule)
                if err:
                    send_json(handler, 400, {"error": err}); return True
                old_value_json = row["value"]
                new_value_json = json.dumps(new_value)
                now = _now_iso()
                conn.execute(
                    "UPDATE config SET value=?, updated_at=?, updated_by=? WHERE key=?",
                    (new_value_json, now, user.username, key),
                )
                conn.execute(
                    "INSERT INTO config_history (key, old_value, new_value, changed_by, changed_at, reason, source) VALUES (?, ?, ?, ?, ?, ?, 'user')",
                    (key, old_value_json, new_value_json, user.username, now, reason),
                )
            broadcast("config_changed", {
                "key": key,
                "new_value": new_value,
                "updated_by": user.username,
                "updated_at": now,
                "reload_kind": row["reload_kind"],
                "restart_target": row["restart_target"],
            })
            send_json(handler, 200, {"ok": True, "key": key, "value": new_value})
            return True

        if method == "DELETE":
            if user is None: unauthorized(handler); return True
            if not has_permission(user, "view_admin"):
                forbid(handler); return True
            with get_conn(db_path) as conn:
                row = conn.execute("SELECT * FROM config WHERE key=?", (key,)).fetchone()
                if row is None:
                    send_json(handler, 404, {"error": "not found", "key": key}); return True
                default_value = json.loads(row["default_value"])
                old_value_json = row["value"]
                new_value_json = row["default_value"]
                now = _now_iso()
                conn.execute(
                    "UPDATE config SET value=?, updated_at=?, updated_by=? WHERE key=?",
                    (new_value_json, now, user.username, key),
                )
                conn.execute(
                    "INSERT INTO config_history (key, old_value, new_value, changed_by, changed_at, reason, source) VALUES (?, ?, ?, ?, ?, ?, 'rollback')",
                    (key, old_value_json, new_value_json, user.username, now, "reset to default"),
                )
            broadcast("config_changed", {
                "key": key,
                "new_value": default_value,
                "updated_by": user.username,
                "updated_at": now,
                "reload_kind": row["reload_kind"],
                "restart_target": row["restart_target"],
            })
            send_json(handler, 200, {"ok": True, "key": key, "value": default_value})
            return True

    return False
```

- [ ] **Step 4: Wire route dispatch into admin-api.py**

Replace `do_GET` body and add `do_PATCH`, `do_DELETE` in `deploy/admin-api/admin-api.py`:
```python
    def _parse(self):
        u = urlparse(self.path)
        from urllib.parse import parse_qs
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        return u.path, q

    def do_GET(self) -> None:
        from routes import config as r_config
        path, query = self._parse()
        if path == "/health":
            return self._send_json(200, {"ok": True, "service": "admin-api"})
        if path == "/api/admin/config/events":
            return self._handle_sse()
        if r_config.handle(self, "GET", path, query, DB_PATH):
            return
        self._send_json(404, {"error": "not found", "path": path})

    def do_PATCH(self) -> None:
        from routes import config as r_config
        path, query = self._parse()
        if r_config.handle(self, "PATCH", path, query, DB_PATH):
            return
        self._send_json(404, {"error": "not found", "path": path})

    def do_DELETE(self) -> None:
        from routes import config as r_config
        path, query = self._parse()
        if r_config.handle(self, "DELETE", path, query, DB_PATH):
            return
        self._send_json(404, {"error": "not found", "path": path})
```

- [ ] **Step 5: Make sys.path see uip_config_client during tests**

The schemas/version endpoint imports `uip_config_client.schemas`. Add the parent of `uip_config_client/` to admin-api's sys.path at startup. Edit `deploy/admin-api/admin-api.py` top, before any other imports:

```python
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".."))
```

- [ ] **Step 6: Run tests — verify PASS**

```bash
cd deploy/admin-api && python -m pytest tests/test_routes_config.py -v
```

Expected: 10 PASS.

- [ ] **Step 7: Commit**

```bash
git add deploy/admin-api/routes/config.py deploy/admin-api/admin-api.py deploy/admin-api/tests/test_routes_config.py
git commit -m "feat(admin-api): routes/config.py — GET/PATCH/DELETE config + schemas/version"
```

---

### Task 12: routes/audit.py — audit log read + CSV export

**Files:**
- Create: `deploy/admin-api/routes/audit.py`
- Modify: `deploy/admin-api/admin-api.py` (add dispatch line)
- Test: `deploy/admin-api/tests/test_routes_audit.py`

- [ ] **Step 1: Write the failing test**

Create `deploy/admin-api/tests/test_routes_audit.py`:
```python
import urllib.request
import urllib.error
import json
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _call(port, method, path, body=None):
    headers = {"X-Admin-Bypass": "test-bypass"}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status, r.read().decode(), r.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers.get("Content-Type")


def test_audit_returns_seed_inserts(admin_api_server):
    port, _ = admin_api_server
    # seed runs on boot — 4 audit rows from initial inserts
    status, body, _ = _call(port, "GET", "/api/admin/audit")
    assert status == 200
    data = json.loads(body)
    assert len(data["items"]) >= 4
    assert all("changed_by" in r for r in data["items"])


def test_audit_filtered_by_key(admin_api_server):
    port, _ = admin_api_server
    status, body, _ = _call(port, "GET", "/api/admin/audit?key=ai.enricher.model")
    data = json.loads(body)
    assert len(data["items"]) >= 1
    assert all(r["key"] == "ai.enricher.model" for r in data["items"])


def test_audit_export_csv(admin_api_server):
    port, _ = admin_api_server
    status, body, ctype = _call(port, "GET", "/api/admin/audit/export")
    assert status == 200
    assert "csv" in ctype.lower()
    assert "key,old_value,new_value,changed_by,changed_at,reason,source" in body.splitlines()[0]
```

- [ ] **Step 2: Run — verify failure**

```bash
cd deploy/admin-api && python -m pytest tests/test_routes_audit.py -v
```

Expected: 3 FAIL.

- [ ] **Step 3: Implement audit.py**

Create `deploy/admin-api/routes/audit.py`:
```python
"""/api/admin/audit — list + CSV export."""
import csv
import io
import logging

from db import get_conn
from routes._common import has_permission, send_json, unauthorized
from auth import resolve_user

log = logging.getLogger("admin-api.routes.audit")


def _rows(conn, where_clauses, params, limit=500):
    q = "SELECT id, key, old_value, new_value, changed_by, changed_at, reason, source FROM config_history"
    if where_clauses:
        q += " WHERE " + " AND ".join(where_clauses)
    q += " ORDER BY changed_at DESC LIMIT ?"
    params = list(params) + [limit]
    return conn.execute(q, params).fetchall()


def handle(handler, method: str, path: str, query: dict, db_path: str) -> bool:
    user = resolve_user(handler.headers.get("Cookie"), handler.headers.get("X-Admin-Bypass"),
                        remote_ip=handler.client_address[0])
    if path in ("/api/admin/audit", "/api/admin/audit/export") and method == "GET":
        if user is None: unauthorized(handler); return True
        if not (has_permission(user, "view_audit") or has_permission(user, "view_admin")):
            send_json(handler, 403, {"error": "forbidden"}); return True
        where, params = [], []
        if key := query.get("key"): where.append("key=?"); params.append(key)
        if by := query.get("by"): where.append("changed_by=?"); params.append(by)
        if frm := query.get("from"): where.append("changed_at>=?"); params.append(frm)
        if to := query.get("to"): where.append("changed_at<=?"); params.append(to)
        with get_conn(db_path) as conn:
            rows = _rows(conn, where, params)
        items = [dict(r) for r in rows]

        if path == "/api/admin/audit/export":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["key", "old_value", "new_value", "changed_by", "changed_at", "reason", "source"])
            for r in items:
                w.writerow([r["key"], r["old_value"], r["new_value"], r["changed_by"], r["changed_at"], r["reason"], r["source"]])
            body = buf.getvalue().encode()
            handler.send_response(200)
            handler.send_header("Content-Type", "text/csv; charset=utf-8")
            handler.send_header("Content-Disposition", "attachment; filename=admin-audit.csv")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
            return True

        send_json(handler, 200, {"items": items})
        return True
    return False
```

- [ ] **Step 4: Wire into admin-api.py**

In `deploy/admin-api/admin-api.py`, add to each of `do_GET` (and as needed `do_PATCH`/`do_DELETE` if the routes file grows):

```python
        if r_config.handle(self, "GET", path, query, DB_PATH):
            return
        from routes import audit as r_audit
        if r_audit.handle(self, "GET", path, query, DB_PATH):
            return
```

- [ ] **Step 5: Run tests — verify PASS**

```bash
cd deploy/admin-api && python -m pytest tests/test_routes_audit.py -v
```

Expected: 3 PASS.

- [ ] **Step 6: Run the full test suite**

```bash
cd deploy/admin-api && python -m pytest -v
```

Expected: all PASS (~20+).

- [ ] **Step 7: Commit**

```bash
git add deploy/admin-api/routes/audit.py deploy/admin-api/admin-api.py deploy/admin-api/tests/test_routes_audit.py
git commit -m "feat(admin-api): routes/audit.py with CSV export"
```

---

## Chunk 4: ConfigClient SSE + auth-api extension

**Hard prerequisite check before running any task in this chunk:**

```bash
wc -l deploy/auth-api/auth-api.py
grep -c "ALL_PERMISSIONS" deploy/sre-frontend/src/lib/keep-api.ts
```

If `auth-api.py` is ≤500 lines OR `ALL_PERMISSIONS` count is 0, Slice 0 (server↔local rsync) is incomplete. STOP. Reconcile drift first — Tasks 14 and 15 in this chunk modify infrastructure that exists ONLY on the server until Slice 0 lands locally.


### Task 13: ConfigClient SSE consumer + invalid-payload handler

**Files:**
- Modify: `deploy/uip_config_client/client.py` (add SSE thread)
- Test: `deploy/uip_config_client/tests/test_client_sse_apply.py`, `test_client_invalid_payload.py`

- [ ] **Step 1: Write failing tests for SSE apply + invalid payload**

Create `deploy/uip_config_client/tests/test_client_sse_apply.py`:
```python
import http.server
import json
import os
import socket
import sys
import threading
import time
from contextlib import closing


def _free_port():
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeAdminApi(http.server.BaseHTTPRequestHandler):
    """Fake admin-api: serves snapshot + SSE stream from a shared event list."""
    pending_events = []
    snapshot_items = []

    def do_GET(self):
        if self.path == "/api/admin/config":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"items": FakeAdminApi.snapshot_items}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/admin/config/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            # Push everything in pending_events, then hang
            for event_type, payload in FakeAdminApi.pending_events:
                msg = f"id: 1\nevent: {event_type}\ndata: {json.dumps(payload)}\n\n"
                self.wfile.write(msg.encode())
                self.wfile.flush()
            time.sleep(2)  # keep alive a bit so client thread can read
            return
        self.send_error(404)

    def log_message(self, *a):
        pass


def _start_fake():
    port = _free_port()
    FakeAdminApi.pending_events = []
    FakeAdminApi.snapshot_items = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), FakeAdminApi)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return port, server


def test_client_picks_up_initial_snapshot():
    port, server = _start_fake()
    FakeAdminApi.snapshot_items = [
        {"key": "ai.enricher.model", "value": "qwen3-32b-thinking", "value_type": "string"},
    ]
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from uip_config_client import ConfigClient
        cfg = ConfigClient(admin_api=f"http://127.0.0.1:{port}", env_fallback=False, poll_interval_sec=0)
        assert cfg.get("ai.enricher.model") == "qwen3-32b-thinking"
    finally:
        server.shutdown()


def test_sse_event_updates_value():
    port, server = _start_fake()
    FakeAdminApi.snapshot_items = [
        {"key": "ai.enricher.model", "value": "qwen3-32b-thinking", "value_type": "string"},
    ]
    FakeAdminApi.pending_events = [
        ("config_changed", {"key": "ai.enricher.model", "new_value": "qwen3-235b-thinking", "updated_by": "test", "updated_at": "2026-05-19T22:00:00Z", "reload_kind": "hot", "restart_target": None}),
    ]
    try:
        from uip_config_client import ConfigClient
        cfg = ConfigClient(admin_api=f"http://127.0.0.1:{port}", env_fallback=False, poll_interval_sec=0)
        # Give the SSE thread a moment
        time.sleep(0.5)
        assert cfg.get("ai.enricher.model") == "qwen3-235b-thinking"
    finally:
        server.shutdown()


def test_on_change_callback_fires():
    port, server = _start_fake()
    FakeAdminApi.snapshot_items = [
        {"key": "ai.enricher.model", "value": "qwen3-32b-thinking", "value_type": "string"},
    ]
    FakeAdminApi.pending_events = [
        ("config_changed", {"key": "ai.enricher.model", "new_value": "qwen3-235b-thinking", "updated_by": "test", "updated_at": "2026-05-19T22:00:00Z", "reload_kind": "hot", "restart_target": None}),
    ]
    seen = []
    try:
        from uip_config_client import ConfigClient
        cfg = ConfigClient(admin_api=f"http://127.0.0.1:{port}", env_fallback=False, poll_interval_sec=0)
        cfg.on_change("ai.enricher.model", lambda old, new: seen.append((old, new)))
        time.sleep(0.5)
        assert seen == [("qwen3-32b-thinking", "qwen3-235b-thinking")]
    finally:
        server.shutdown()
```

Create `deploy/uip_config_client/tests/test_client_invalid_payload.py`:
```python
import http.server
import json
import socket
import sys, os, time, threading
from contextlib import closing


def _free_port():
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]


class FakeApi(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/admin/config":
            body = json.dumps({"items": [{"key": "pipeline.enricher.poll_interval_sec", "value": 60, "value_type": "int"}]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        if self.path == "/api/admin/config/events":
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            # Push an event with wrong type (string instead of int)
            msg = 'id: 1\nevent: config_changed\ndata: {"key":"pipeline.enricher.poll_interval_sec","new_value":"not-an-int","updated_by":"x","updated_at":"2026","reload_kind":"hot","restart_target":null}\n\n'
            self.wfile.write(msg.encode()); self.wfile.flush(); time.sleep(2); return
        self.send_error(404)

    def log_message(self, *a):
        pass


def test_invalid_payload_keeps_old_value_and_fires_handler():
    port = _free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), FakeApi)
    t = threading.Thread(target=server.serve_forever, daemon=True); t.start()
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from uip_config_client import ConfigClient
        seen = []
        cfg = ConfigClient(admin_api=f"http://127.0.0.1:{port}", env_fallback=False, poll_interval_sec=0,
                           on_invalid_payload=lambda p, e: seen.append((p, e)))
        time.sleep(0.5)
        # Value must still be 60, not the bogus string
        assert cfg.get("pipeline.enricher.poll_interval_sec") == 60
        # Handler must have fired once
        assert len(seen) == 1
        assert seen[0][0]["key"] == "pipeline.enricher.poll_interval_sec"
    finally:
        server.shutdown()
```

- [ ] **Step 2: Run — verify failure**

```bash
cd deploy/uip_config_client && python -m pytest tests/ -v
```

Expected: 4 FAIL (the new SSE tests).

- [ ] **Step 3: Add SSE consumer thread to `client.py`**

Append to `deploy/uip_config_client/client.py`:
```python
    def _start_sse_thread(self) -> None:
        t = threading.Thread(target=self._sse_loop, name="config-sse", daemon=True)
        t.start()
        self._sse_thread = t

    def _sse_loop(self) -> None:
        url = f"{self._admin_api}/api/admin/config/events"
        backoff = 1
        while not getattr(self, "_stop_sse", False):
            try:
                req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
                with urllib.request.urlopen(req, timeout=None) as r:
                    # Reset backoff only after we receive the first real frame, not
                    # just on connection open — a server that accepts then immediately
                    # drops would otherwise spin in a tight loop.
                    received_first_frame = False
                    event_type, data_lines = None, []
                    for raw in r:
                        line = raw.decode().rstrip("\n").rstrip("\r")
                        if line.startswith("event:"):
                            event_type = line[len("event:"):].strip()
                        elif line.startswith("data:"):
                            data_lines.append(line[len("data:"):].strip())
                        elif line == "" and event_type:
                            try:
                                payload = json.loads("\n".join(data_lines))
                                if event_type == "config_changed":
                                    self._apply_event(payload)
                                if not received_first_frame:
                                    backoff = 1
                                    received_first_frame = True
                            except Exception as e:
                                log.warning("SSE parse error: %s", e)
                            event_type, data_lines = None, []
            except Exception as e:
                log.warning("SSE reconnect in %ds: %s", backoff, e)
                import time as _time
                _time.sleep(backoff)
                backoff = min(backoff * 2, self._sse_max)

    def _apply_event(self, payload: dict) -> None:
        key = payload.get("key")
        new_value = payload.get("new_value")
        if key is None: return
        # Validate against local schema
        schema = self._schemas.get(key)
        if schema is not None:
            err = self._validate(new_value, schema)
            if err:
                try:
                    self._on_invalid(payload, ValueError(err))
                except Exception as ee:
                    log.warning("on_invalid_payload raised: %s", ee)
                return
        with self._lock:
            old_value = self._values.get(key)
            self._values[key] = new_value
            listeners = list(self._listeners.get(key, []))
        for cb in listeners:
            try:
                cb(old_value, new_value)
            except Exception as e:
                log.warning("on_change callback raised: %s", e)

    def _validate(self, value, schema) -> str | None:
        vtype = schema.value_type
        rule = schema.validation_rule
        if vtype == "int":
            if not isinstance(value, int) or isinstance(value, bool):
                return f"expected int, got {type(value).__name__}"
        elif vtype == "float":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return f"expected number, got {type(value).__name__}"
        elif vtype == "bool":
            if not isinstance(value, bool):
                return f"expected bool, got {type(value).__name__}"
        elif vtype == "string":
            if not isinstance(value, str):
                return f"expected string, got {type(value).__name__}"
        if not rule: return None
        if vtype in ("int", "float"):
            if "min" in rule and value < rule["min"]: return f"value {value} below min {rule['min']}"
            if "max" in rule and value > rule["max"]: return f"value {value} above max {rule['max']}"
        if vtype == "string":
            import re
            if "regex" in rule and not re.match(rule["regex"], value):
                return f"value does not match regex"
            if "enum" in rule and value not in rule["enum"]:
                return f"value not in enum"
        return None
```

Also add to `ConfigClient.__init__`, at the end (after `_try_initial_snapshot`):
```python
        self._stop_sse = False
        self._start_sse_thread()
```

- [ ] **Step 4: Run tests — verify PASS**

```bash
cd deploy/uip_config_client && python -m pytest tests/ -v
```

Expected: 7 PASS (3 from Task 7 `test_client_env_fallback.py` + 3 from `test_client_sse_apply.py` + 1 from `test_client_invalid_payload.py`).

- [ ] **Step 5: Commit**

```bash
git add deploy/uip_config_client/client.py deploy/uip_config_client/tests/
git commit -m "feat(uip_config_client): SSE consumer + invalid-payload handler"
```

---

### Task 14: auth-api permission extension

**Files:**
- Modify: `deploy/auth-api/auth-api.py` (extend `ALL_PERMISSIONS` + add migration that seeds 8 new perms into Admin & SRE roles)

This task ASSUMES Slice 0 (server↔local rsync) has been done. If `wc -l deploy/auth-api/auth-api.py` is still ~302, STOP and reconcile first.

- [ ] **Step 1: Locate ALL_PERMISSIONS in auth-api.py**

```bash
grep -n "ALL_PERMISSIONS" deploy/auth-api/auth-api.py
```

Expected: a line near 39 with `ALL_PERMISSIONS = [`. If not present, Slice 0 not done.

- [ ] **Step 2: Extend ALL_PERMISSIONS**

Edit `deploy/auth-api/auth-api.py` at the `ALL_PERMISSIONS = [` block. After the last existing permission (e.g. `"view_admin",`), add:

```python
    # Admin tab permissions (added Slice 1 — UIP admin page)
    "manage_ai",
    "manage_pipeline",
    "manage_zabbix",
    "manage_integrations",
    "manage_services",
    "manage_features",
    "manage_runbooks",
    "view_audit",
```

- [ ] **Step 3a: Verify role_permissions schema before writing the INSERT**

```bash
grep -nE "CREATE TABLE.*role_permissions|role_permissions \(" deploy/auth-api/auth-api.py | head -5
```

Confirm the column layout. The seed below assumes `(role_id INTEGER, permission TEXT)` with the permission stored inline as text (verified live on server: `role_permissions(role_id, permission)`). If the schema uses a separate `permissions` table with FK, this task must be reworked to insert into both tables.

- [ ] **Step 3b: Locate where existing role-permission seeds run**

```bash
grep -nE "INSERT.*role_permissions|seed.*permission|seed.*role" deploy/auth-api/auth-api.py | head -10
```

Find the function called on container boot (likely `_seed_users` or `_init_db` or similar). The new function `seed_admin_tab_permissions(conn)` must be invoked from inside that function, *after* the existing role permissions are seeded. Note the exact line number of the call site for Step 3d.

- [ ] **Step 3c: Add an idempotent seed function for default role assignments**

```python
NEW_ADMIN_TAB_PERMS = [
    "manage_ai", "manage_pipeline", "manage_zabbix", "manage_integrations",
    "manage_services", "manage_features", "manage_runbooks", "view_audit",
]


def seed_admin_tab_permissions(conn):
    """Idempotent: ensure Admin and SRE roles get the new admin-tab perms; Viewer gets view_audit only."""
    # Admin (id=1) and SRE (id=2) — all 8
    for role_id in (1, 2):
        for perm in NEW_ADMIN_TAB_PERMS:
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?, ?)",
                (role_id, perm),
            )
    # Viewer (id=3) — view_audit only
    conn.execute(
        "INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?, ?)",
        (3, "view_audit"),
    )
    conn.commit()
```

- [ ] **Step 3d: Call the seed function from the init path**

Add `seed_admin_tab_permissions(conn)` immediately after the existing role-permission seeding loop you found in Step 3b. This must run on every container boot (idempotent). Confirm by tailing the function and ensuring the call lands inside whatever wraps the init transaction.

- [ ] **Step 4: Write a quick verification script (not a pytest test, just a one-shot check)**

Create `deploy/auth-api/verify_admin_tab_seed.py`:
```python
"""Run inside the container after deploying: python /app/verify_admin_tab_seed.py"""
import sqlite3
import sys

db = sqlite3.connect("/data/auth.db")
expected = ["manage_ai", "manage_pipeline", "manage_zabbix", "manage_integrations",
            "manage_services", "manage_features", "manage_runbooks", "view_audit"]
for role_id, role_name, expected_perms in [(1, "Admin", expected), (2, "SRE", expected), (3, "Viewer", ["view_audit"])]:
    rows = db.execute("SELECT permission FROM role_permissions WHERE role_id=?", (role_id,)).fetchall()
    perms = {r[0] for r in rows}
    missing = set(expected_perms) - perms
    if missing:
        print(f"FAIL: {role_name} missing {missing}")
        sys.exit(1)
print("OK: all roles have correct admin-tab perms")
```

- [ ] **Step 5: Deploy auth-api changes**

```bash
SSH_KEY=~/.ssh/id_uip_deploy
SERVER=fash@10.177.154.196
scp -i $SSH_KEY deploy/auth-api/auth-api.py $SERVER:~/uip/auth-api/auth-api.py
scp -i $SSH_KEY deploy/auth-api/verify_admin_tab_seed.py $SERVER:~/uip/auth-api/verify_admin_tab_seed.py
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker compose restart auth-api && sleep 5 && docker exec uip-auth-api python3 /app/verify_admin_tab_seed.py"
```

Expected: `OK: all roles have correct admin-tab perms`.

- [ ] **Step 6: Commit**

```bash
git add deploy/auth-api/
git commit -m "feat(auth-api): add 8 admin-tab perms with role-mapping seed"
```

---

### Task 15: Frontend ALL_PERMISSIONS constant update

**Files:**
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts` (around line 1786)

- [ ] **Step 1: Locate ALL_PERMISSIONS in keep-api.ts**

```bash
grep -n "ALL_PERMISSIONS" deploy/sre-frontend/src/lib/keep-api.ts
```

Expected: a line near 1786 with `export const ALL_PERMISSIONS = [`. (If not, Slice 0 incomplete.)

- [ ] **Step 2: Add 8 new permissions**

In `keep-api.ts`, after the last existing `manage_*` / `view_*` entry in the `ALL_PERMISSIONS` array, add:

```typescript
  { key: 'manage_ai', label: 'Manage AI', group: 'Admin' },
  { key: 'manage_pipeline', label: 'Manage Pipeline', group: 'Admin' },
  { key: 'manage_zabbix', label: 'Manage Zabbix', group: 'Admin' },
  { key: 'manage_integrations', label: 'Manage Integrations', group: 'Admin' },
  { key: 'manage_services', label: 'Manage Services', group: 'Admin' },
  { key: 'manage_features', label: 'Manage Features', group: 'Admin' },
  { key: 'manage_runbooks', label: 'Manage Runbooks', group: 'Admin' },
  { key: 'view_audit', label: 'View Audit Log', group: 'Admin' },
```

- [ ] **Step 3: Type-check**

```bash
cd deploy/sre-frontend && npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add deploy/sre-frontend/src/lib/keep-api.ts
git commit -m "feat(frontend): add 8 admin-tab permissions to ALL_PERMISSIONS"
```

---

## Chunk 5: nginx + frontend admin layout + compose + deploy

### Task 16: nginx routing

**Files:**
- Modify: `deploy/nginx-default.conf` (add 4 location blocks)

- [ ] **Step 1: Add the 4 location blocks**

Find an appropriate insertion point — after the existing `/api/alert-states/events` block (so the long-timeout SSE locations sit together). Add:

```nginx
    # admin-api — config event stream (SSE; long-lived)
    location /api/admin/config/events {
        proxy_pass http://admin-api:8096;
        proxy_buffering off;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400s;
    }

    # admin-api — AI sandbox stream (chunked HTTP; up to 3 minutes per model call)
    location /api/admin/ai/test {
        proxy_pass http://admin-api:8096;
        proxy_buffering off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 180s;
    }

    # admin-api — Zabbix setup stream (chunked HTTP; setup script can run a while)
    location ~ ^/api/admin/zabbix/instances/[0-9]+/setup$ {
        proxy_pass http://admin-api:8096;
        proxy_buffering off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
    }

    # admin-api — everything else
    location /api/admin/ {
        proxy_pass http://admin-api:8096;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 75s;
    }
```

- [ ] **Step 2: Lint nginx config**

```bash
SSH_KEY=~/.ssh/id_uip_deploy
SERVER=fash@10.177.154.196
scp -i $SSH_KEY deploy/nginx-default.conf $SERVER:~/uip/nginx-default.conf
ssh -i $SSH_KEY $SERVER "docker exec uip-nginx nginx -t -c /etc/nginx/nginx.conf 2>&1"
```

Expected: `nginx: configuration file /etc/nginx/nginx.conf test is successful`. (Note: admin-api isn't yet deployed, so reload may fail upstream lookup. That's OK — the syntax test passes.)

- [ ] **Step 3: Commit**

```bash
git add deploy/nginx-default.conf
git commit -m "feat(nginx): route /api/admin/* to admin-api with SSE/streaming exceptions"
```

---

### Task 17: Frontend admin layout + tab nav

**Files:**
- Create: `deploy/sre-frontend/src/app/admin/layout.tsx`
- Modify: `deploy/sre-frontend/src/app/admin/page.tsx` (existing — change redirect)

- [ ] **Step 1: Check existing admin/page.tsx**

```bash
ls deploy/sre-frontend/src/app/admin/
```

Expected: at least `page.tsx`. If empty/absent, Slice 0 incomplete.

- [ ] **Step 2a: Create shared TABS constant**

Create `deploy/sre-frontend/src/app/admin/_components/tabs.ts`:
```ts
export type Tab = { href: string; label: string; perm: string };

export const ADMIN_TABS: Tab[] = [
  { href: '/portal/admin/users',         label: 'Users',         perm: 'manage_users' },
  { href: '/portal/admin/roles',         label: 'Roles',         perm: 'manage_roles' },
  { href: '/portal/admin/ai',            label: 'AI',            perm: 'manage_ai' },
  { href: '/portal/admin/pipeline',      label: 'Pipeline',      perm: 'manage_pipeline' },
  { href: '/portal/admin/zabbix',        label: 'Zabbix',        perm: 'manage_zabbix' },
  { href: '/portal/admin/integrations',  label: 'Integrations',  perm: 'manage_integrations' },
  { href: '/portal/admin/services',      label: 'Services',      perm: 'manage_services' },
  { href: '/portal/admin/features',      label: 'Features',      perm: 'manage_features' },
  { href: '/portal/admin/runbooks',      label: 'Runbooks',      perm: 'manage_runbooks' },
  { href: '/portal/admin/audit',         label: 'Audit',         perm: 'view_audit' },
];
```

- [ ] **Step 2b: Write layout.tsx**

Create `deploy/sre-frontend/src/app/admin/layout.tsx`:
```tsx
'use client';

import { useAuth } from '@/lib/auth';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ReactNode } from 'react';
import { ADMIN_TABS } from './_components/tabs';

export default function AdminLayout({ children }: { children: ReactNode }) {
  const { hasPermission, loading } = useAuth();
  const pathname = usePathname();

  if (loading) {
    return <div className="p-8 text-muted">Loading admin…</div>;
  }
  if (!hasPermission('view_admin')) {
    return <div className="p-8 text-red-400">Access denied. Admin permission required.</div>;
  }
  const allowed = ADMIN_TABS.filter((t) => hasPermission(t.perm));
  return (
    <div className="space-y-4">
      <nav className="border-b border-border">
        <ul className="flex gap-1 overflow-x-auto">
          {allowed.map((t) => {
            // Exact match OR strict subpath match (avoids /users matching /users-management)
            const active = pathname === t.href || pathname?.startsWith(t.href + '/');
            return (
              <li key={t.href}>
                <Link
                  href={t.href}
                  className={`inline-block px-4 py-2 text-sm border-b-2 -mb-px transition-colors ${
                    active
                      ? 'border-accent text-accent'
                      : 'border-transparent text-muted hover:text-text-bright'
                  }`}
                >
                  {t.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      <div>{children}</div>
    </div>
  );
}
```

- [ ] **Step 3: Update admin/page.tsx to redirect to first allowed tab**

Edit `deploy/sre-frontend/src/app/admin/page.tsx`. The existing file has user/role logic — but per spec, that's now under `/admin/users` and `/admin/roles` paths. We keep the file but change it to a small redirect. If the existing file IS the users/roles UI, MOVE it first:

```bash
# Only if it has users/roles UI inline:
mkdir -p deploy/sre-frontend/src/app/admin/users
git mv deploy/sre-frontend/src/app/admin/page.tsx deploy/sre-frontend/src/app/admin/users/page.tsx
```

Then create a new `deploy/sre-frontend/src/app/admin/page.tsx`:
```tsx
'use client';

import { useAuth } from '@/lib/auth';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { ADMIN_TABS } from './_components/tabs';

export default function AdminIndex() {
  const { hasPermission, loading } = useAuth();
  const router = useRouter();
  useEffect(() => {
    if (loading) return;
    // Walk every tab in display order; first one the user can see wins.
    // Derives from ADMIN_TABS so we never get stuck on the loading screen
    // when the user only has e.g. manage_zabbix or manage_runbooks.
    for (const tab of ADMIN_TABS) {
      if (hasPermission(tab.perm)) {
        router.replace(tab.href);
        return;
      }
    }
  }, [loading, hasPermission, router]);
  return <div className="p-8 text-muted">Loading admin…</div>;
}
```

- [ ] **Step 4: Add placeholder pages for new tabs (Slice 2+ will fill these)**

For each of the 8 new tabs, create a placeholder so the routes don't 404:

```bash
for tab in ai pipeline zabbix integrations services features runbooks audit; do
  mkdir -p deploy/sre-frontend/src/app/admin/$tab
  cat > deploy/sre-frontend/src/app/admin/$tab/page.tsx <<'EOF'
'use client';
export default function Page() {
  return <div className="p-6 text-muted">This tab is implemented in a later slice.</div>;
}
EOF
done
```

- [ ] **Step 5: Type-check**

```bash
cd deploy/sre-frontend && npx tsc --noEmit
```

Expected: no errors. (If `useAuth` from `@/lib/auth` is missing, Slice 0 incomplete — that hook is at `src/lib/auth.ts:18` on the server.)

- [ ] **Step 6: Commit**

```bash
git add deploy/sre-frontend/src/app/admin/
git commit -m "feat(frontend): admin/layout.tsx with permission-gated tab nav + 8 tab placeholders"
```

---

### Task 18: Compose entry for admin-api

**Files:**
- Modify: `deploy/docker-compose.yml`
- Modify: `deploy/.env.example` (add `ADMIN_BYPASS_TOKEN` default)

- [ ] **Step 1: Add the service definition**

Edit `deploy/docker-compose.yml`. Find the existing `auth-api` block and insert this entry directly below it (so depends_on resolves cleanly):

```yaml
  # ============================================
  # Admin API — Runtime Config + Control Plane
  # ============================================
  admin-api:
    image: python:3.12-slim
    container_name: uip-admin-api
    restart: unless-stopped
    command: sh -c "pip install -q -r /app/requirements.txt && python3 -u /app/admin-api.py"
    volumes:
      - ./admin-api:/app:ro
      - ./uip_config_client:/uip_config_client:ro
      - admin_data:/data
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      API_PORT: "8096"
      DB_PATH: /data/admin.db
      AUTH_API_URL: http://auth-api:8093
      AUTH_SECRET: "${AUTH_SECRET}"
      CLUSTER_ENDPOINT: "${OLLAMA_URL}"
      ADMIN_BYPASS_TOKEN: "${ADMIN_BYPASS_TOKEN:-}"
      PYTHONPATH: "/:/app"
    depends_on:
      auth-api:
        condition: service_started
    deploy:
      resources:
        limits: { memory: 256M, cpus: "0.5" }
    networks:
      - uip-net
```

Note: `uip_config_client` is mounted at `/uip_config_client` so admin-api can `from uip_config_client.schemas import SEED_VERSION`. `PYTHONPATH: "/:/app"` makes both importable.

- [ ] **Step 2: Add the volume**

In the `volumes:` top-level block at the bottom of `docker-compose.yml`, add:
```yaml
  admin_data:
```

- [ ] **Step 3: Add admin-api to nginx depends_on**

In the nginx service `depends_on:` list, add:
```yaml
      - admin-api
```

- [ ] **Step 4: Add ADMIN_BYPASS_TOKEN to .env.example (idempotent)**

```bash
if ! grep -q "^ADMIN_BYPASS_TOKEN=" deploy/.env.example; then
  printf '\n# Optional escape hatch for admin-api RBAC bootstrap. Leave empty in production.\nADMIN_BYPASS_TOKEN=\n' >> deploy/.env.example
fi
```

- [ ] **Step 5: Validate compose**

```bash
cd deploy && docker compose config --quiet
```

Expected: no output (success).

- [ ] **Step 6: Commit**

```bash
git add deploy/docker-compose.yml deploy/.env.example
git commit -m "feat(deploy): add admin-api service + admin_data volume + nginx depends_on"
```

---

## Chunk 6: Deploy + ship gate

### Task 19: Deploy to server and verify ship gate

**Files:** All previously-modified.

- [ ] **Step 1: SCP all changed files to server**

```bash
SSH_KEY=~/.ssh/id_uip_deploy
SERVER=fash@10.177.154.196

# admin-api new code
ssh -i $SSH_KEY $SERVER "mkdir -p ~/uip/admin-api ~/uip/uip_config_client"
scp -i $SSH_KEY -r deploy/admin-api/* $SERVER:~/uip/admin-api/
scp -i $SSH_KEY -r deploy/uip_config_client/* $SERVER:~/uip/uip_config_client/

# compose + nginx + auth-api + frontend (auth-api + frontend already deployed in their tasks)
scp -i $SSH_KEY deploy/docker-compose.yml $SERVER:~/uip/docker-compose.yml
scp -i $SSH_KEY deploy/nginx-default.conf $SERVER:~/uip/nginx-default.conf
scp -i $SSH_KEY -r deploy/sre-frontend/src/app/admin $SERVER:~/uip/sre-frontend/src/app/admin
scp -i $SSH_KEY deploy/sre-frontend/src/lib/keep-api.ts $SERVER:~/uip/sre-frontend/src/lib/keep-api.ts
```

- [ ] **Step 2: Bring up admin-api (first boot includes pip install — can take 60s)**

```bash
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker compose up -d admin-api"
# Poll /health until ready (max ~90s)
for i in $(seq 1 30); do
  status=$(ssh -i $SSH_KEY $SERVER "curl -s -o /dev/null -w '%{http_code}' http://localhost:8096/health 2>/dev/null || echo 000")
  [ "$status" = "200" ] && break
  sleep 3
done
ssh -i $SSH_KEY $SERVER "docker logs uip-admin-api --tail 40"
```

Expected log lines (or similar):
- `admin-api starting on :8096 (DB=/data/admin.db)`
- `schema bootstrapped at /data/admin.db`
- `seed applied`

Note: `admin-api` boots in the `uip-net` Docker network, not on localhost. The host-side `curl http://localhost:8096` works only if you exposed the port — adjust to `docker exec uip-admin-api curl -s http://127.0.0.1:8096/health` if needed.

- [ ] **Step 3: Restart nginx to pick up new locations**

```bash
ssh -i $SSH_KEY $SERVER "docker exec uip-nginx nginx -t && docker exec uip-nginx nginx -s reload"
```

Expected: `signal process started`.

- [ ] **Step 4: Rebuild frontend**

```bash
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker compose up -d --build sre-frontend"
```

- [ ] **Step 5: Ship gate — verify endpoints (the §8 Slice 1 ship gate from spec)**

```bash
# 5a. admin-api up (use /health not /events — SSE blocks and confuses curl exit codes)
curl -s -m 3 -o /dev/null -w "health: %{http_code}\n" http://10.177.154.196/api/admin/config -H "X-Admin-Bypass: ignored"
# Expected: health: 401 (no bypass token set yet, BUT the route is reachable — proves admin-api is up via nginx)

# 5b. Config list (unauthenticated)
curl -s -o /dev/null -w "config: %{http_code}\n" http://10.177.154.196/api/admin/config
# Expected: config: 401

# 5c. Set up a temporary bypass token for ship-gate checks
# Robust against pre-existing empty/value ADMIN_BYPASS_TOKEN= lines.
SHIPGATE_TOKEN="verify-shipgate-$(date +%s)"
ssh -i $SSH_KEY $SERVER "sed -i -E '/^ADMIN_BYPASS_TOKEN=/d' ~/uip/.env && echo 'ADMIN_BYPASS_TOKEN=$SHIPGATE_TOKEN' >> ~/uip/.env && cd ~/uip && docker compose up -d admin-api"
# Wait for admin-api to come back up
for i in $(seq 1 20); do
  s=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Admin-Bypass: $SHIPGATE_TOKEN" http://10.177.154.196/api/admin/config)
  [ "$s" = "200" ] && break
  sleep 2
done

# 5d. Verify the 4 seeded keys are visible
curl -s -H "X-Admin-Bypass: $SHIPGATE_TOKEN" http://10.177.154.196/api/admin/config | jq '.items | length'
# Expected: 4 (NOTE: spec §8 Slice 1 ship gate says "empty list" but Task 4 seeds 4 keys.
# The plan supersedes the spec wording here — 4 is correct.)

# 5e. Schemas version
curl -s -H "X-Admin-Bypass: $SHIPGATE_TOKEN" http://10.177.154.196/api/admin/config/schemas/version
# Expected: {"seed_version": 1}

# 5f. Audit
curl -s -H "X-Admin-Bypass: $SHIPGATE_TOKEN" http://10.177.154.196/api/admin/audit | jq '.items | length'
# Expected: 4 (one seed insert per key)

# 5g. Existing admin pages still work (regression — both per spec §8 Slice 1)
curl -s -o /dev/null -w "/portal/admin/users: %{http_code}\n" http://10.177.154.196/portal/admin/users
curl -s -o /dev/null -w "/portal/admin/roles: %{http_code}\n" http://10.177.154.196/portal/admin/roles
# Expected: both 200

# 5h. Existing alerts page hasn't regressed
curl -s -o /dev/null -w "/portal/command-center: %{http_code}\n" http://10.177.154.196/portal/command-center
# Expected: 200

# 5i. SSE works (auth-free probe; SSE endpoint accepts any client to broadcast non-sensitive events)
timeout 4 curl -s -N -H "X-Admin-Bypass: $SHIPGATE_TOKEN" http://10.177.154.196/api/admin/config/events | head -1
# Expected: "event: " line or a `: keepalive` line within 4 seconds
```

- [ ] **Step 6: Remove the temporary bypass token (restore to empty placeholder)**

```bash
ssh -i $SSH_KEY $SERVER "sed -i -E '/^ADMIN_BYPASS_TOKEN=/d' ~/uip/.env && echo 'ADMIN_BYPASS_TOKEN=' >> ~/uip/.env && cd ~/uip && docker compose up -d admin-api"
```

Restores the empty placeholder that matches `.env.example`. Verify removal:
```bash
ssh -i $SSH_KEY $SERVER 'grep ^ADMIN_BYPASS_TOKEN ~/uip/.env'
# Expected: ADMIN_BYPASS_TOKEN=    (empty value)
```

- [ ] **Step 7: Document in operator guide**

Create `docs/operator/admin-api.md` (stub — Slice 7 expands):
```markdown
# admin-api Operator Guide (Slice 1)

## Running locally
- Port 8096 (proxied through nginx at `/api/admin/*`)
- DB: `/data/admin.db` inside the container, `admin_data` volume on host.

## Bypass token (emergency RBAC override)
Set `ADMIN_BYPASS_TOKEN=<random-string>` in `~/uip/.env`, restart admin-api, then:
```
curl -H "X-Admin-Bypass: <token>" http://10.177.154.196/api/admin/config
```
Every bypass request emits `audit_bypass=true` log line. Unset the token after use.

## Resetting seeds
Bumping `config_seed.json` version + restarting admin-api auto-applies new keys.
The existing values are preserved.

## Reading the audit log
```
curl -H "Cookie: session=<your-cookie>" http://10.177.154.196/api/admin/audit?key=ai.enricher.model | jq
```

## Regenerating uip_config_client/schemas.py
After editing `admin-api/seeds/config_seed.json`:
```
python deploy/admin-api/build_schemas.py
```
Commit the generated file.
```

- [ ] **Step 8: Final commit**

```bash
git add docs/operator/admin-api.md
git commit -m "docs: Slice 1 operator guide stub"
```

- [ ] **Step 9: Open PR**

```bash
git push -u origin feature/admin-foundation
gh pr create --title "feat: admin-api foundation (Slice 1)" --body "$(cat <<'EOF'
## Summary
- New service `admin-api` (port 8096) with SQLite/WAL admin.db
- Shared Python package `uip_config_client/` with SSE + env fallback + schema validation
- 8 new permissions in auth-api `ALL_PERMISSIONS` + idempotent role-mapping seed (Admin/SRE get all 8; Viewer gets view_audit)
- Frontend `src/lib/keep-api.ts` `ALL_PERMISSIONS` constant updated with the same 8
- New frontend `src/app/admin/layout.tsx` with permission-gated tab nav + shared `_components/tabs.ts`
- 8 tab placeholder pages (`ai/`, `pipeline/`, `zabbix/`, `integrations/`, `services/`, `features/`, `runbooks/`, `audit/`) — content fills in slices 2-7
- nginx 4 new location blocks: `/api/admin/config/events` (SSE, 86400s), `/api/admin/ai/test` (chunked, 180s), `/api/admin/zabbix/instances/*/setup` (chunked, 300s), `/api/admin/` (general, 75s)
- `docker-compose.yml`: new `admin-api` service entry + `admin_data` volume + nginx `depends_on: admin-api`
- `.env.example`: `ADMIN_BYPASS_TOKEN=` placeholder
- `docs/operator/admin-api.md`: Slice 1 operator guide stub

## Test plan
- [x] `pytest deploy/admin-api/tests` green
- [x] `pytest deploy/uip_config_client/tests` green
- [x] Ship gate 5d: 4 seeded keys visible via /api/admin/config
- [x] Ship gate 5e: schemas/version returns seed_version=1
- [x] Ship gate 5f: audit log has 4 `__seed__` rows
- [x] Ship gate 5g: existing /portal/admin/users AND /portal/admin/roles both 200
- [x] Ship gate 5h: /portal/command-center unchanged
- [x] Ship gate 5i: SSE event stream connects within 4s
- [x] `docker exec uip-nginx nginx -t` clean
- [x] No container restart-count regressions

## Spec
docs/superpowers/specs/2026-05-19-uip-admin-page-design.md v3 (commit 2daae70)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Done check (Slice 1 complete when…)

- [ ] `curl http://10.177.154.196/api/admin/config` returns 401 unauthenticated.
- [ ] Same endpoint with valid session cookie returns 4 seeded keys.
- [ ] SSE endpoint streams (use `curl -N http://10.177.154.196/api/admin/config/events -m 5` to verify).
- [ ] Audit log has 4 seed rows for `__seed__` user.
- [ ] All 10 tab links visible in nav for Admin role; only tabs they have perms for show for other roles.
- [ ] All non-tab pages (alerts, command-center, etc.) unchanged.
- [ ] No consumer service is using ConfigClient yet — that's Slice 2's first migration (`health-checker`).

## What Slice 2 picks up

- Services tab implementation
- Features tab implementation
- `health-checker` migrated to ConfigClient (first real consumer)
- New seed keys for service health probes
- Three ship-gate checks per spec §8 Slice 2

When Slice 1 is merged and the ship-gate is green, brainstorm Slice 2's plan as a separate document: `docs/superpowers/plans/<date>-uip-admin-page-slice-2-services-features.md`.
