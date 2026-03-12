# UIP Frontend Refactor & Backend Split — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decompose the runbook-api monolith into 4 focused services, merge Alerts into Command Center as tabs, rename Registry Contacts to Registry with on-demand Loki trends, re-enable the Logs page, and remove the Zabbix poller.

**Architecture:** Backend splits into auth-api (port 8093), alert-state-api (8092), loki-gateway (8091), and a slimmed runbook-api (8090). Nginx routes by path prefix. Frontend migrates from single `/api/runbook/*` base to per-service prefixes. Command Center gains Dashboard/All Alerts tabs. Registry page gets on-demand Loki trends. All Loki queries are manual-only (no auto-polling).

**Tech Stack:** Python 3.12 (http.server), Next.js 14, Tailwind CSS, SQLite, Docker Compose, Nginx

**Spec:** `docs/superpowers/specs/2026-03-12-frontend-refactor-backend-split-design.md`

---

## Chunk 1: Backend — Extract auth-api

### Task 1: Create auth-api.py

**Files:**
- Create: `deploy/auth-api/auth-api.py`
- Reference: `deploy/runbook-api/runbook-api.py` (lines 84-98 for users table, lines 120-195 for auth logic, lines 838-854 for /auth/me, lines 962-1065 for login/logout/change-password/jira-config)

- [ ] **Step 1: Create the auth-api directory and file**

Create `deploy/auth-api/auth-api.py`. This is a standalone Python HTTP server extracted from runbook-api.py. It owns the `users` table and all `/api/auth/*` endpoints.

The file must include:
1. **Imports** — same stdlib pattern as runbook-api.py: `http.server`, `json`, `sqlite3`, `hashlib`, `hmac`, `base64`, `os`, `time`, `threading`, `urllib.parse`
2. **Database init** — create `users` table with columns: `id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, display_name TEXT, jira_email TEXT, jira_api_token TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP`. Add unique index on username. Seed 8 default users (same as runbook-api.py lines 122-158) with password `SreTeam2026!` using PBKDF2-HMAC-SHA256, 100k iterations.
3. **Auth helpers** — copy `hash_password()`, `verify_password()`, `create_token()`, `verify_token()` from runbook-api.py lines 135-195. These use `AUTH_SECRET` env var.
4. **CORS helpers** — `send_cors_headers()` and OPTIONS handler (same pattern as runbook-api.py).
5. **HTTP Handler** extending `BaseHTTPRequestHandler` with:
   - `GET /api/auth/me` — verify token from `uip_auth` cookie, return user profile (username, display_name, jira_email, has_jira_token, created_at)
   - `POST /api/auth/login` — verify username+password, set `uip_auth` and `uip_user` cookies (HttpOnly, SameSite=Lax, Max-Age=86400, Path=/)
   - `POST /api/auth/logout` — clear both cookies (Max-Age=0)
   - `POST /api/auth/change-password` — requires auth, verify current password, set new password hash
   - `POST /api/auth/jira-config` — requires auth, update jira_email and optionally jira_api_token
6. **Main** — read `API_PORT` (default 8093), `DB_PATH` (default `/data/auth.db`), `AUTH_SECRET` from env. Start server.

```python
#!/usr/bin/env python3
"""auth-api: User authentication and management service for UIP."""
```

- [ ] **Step 2: Verify auth-api.py runs standalone**

```bash
cd deploy/auth-api
AUTH_SECRET=test-secret DB_PATH=./test-auth.db API_PORT=8093 python3 auth-api.py &
sleep 2
# Test login
curl -s -X POST http://localhost:8093/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"fash","password":"SreTeam2026!"}' -v 2>&1 | grep -E 'Set-Cookie|HTTP/'
# Should see: Set-Cookie: uip_auth=... and HTTP/1.1 200
kill %1
rm -f test-auth.db
```

- [ ] **Step 3: Commit**

```bash
git add deploy/auth-api/auth-api.py
git commit -m "feat: extract auth-api service from runbook-api monolith"
```

---

### Task 2: Create alert-state-api.py

**Files:**
- Create: `deploy/alert-state-api/alert-state-api.py`
- Reference: `deploy/runbook-api/runbook-api.py` (lines 98-114 for alert_states table, lines 855-872 for GET /alert-states, lines 1075-1200 for investigate/acknowledge/unacknowledge/mark-updated)

- [ ] **Step 1: Create alert-state-api.py**

Standalone Python HTTP server owning the `alert_states` table and all `/api/alert-states/*` endpoints.

Include:
1. **Database init** — `alert_states` table: `id INTEGER PRIMARY KEY AUTOINCREMENT, alert_fingerprint TEXT UNIQUE NOT NULL, alert_name TEXT, investigating_user TEXT, investigating_since TEXT, acknowledged_by TEXT, acknowledged_at TEXT, ack_firing_start TEXT, is_updated INTEGER DEFAULT 0, updated_detected_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP`. Unique index on `alert_fingerprint`.
2. **Auth verification** — copy `verify_token()` function (needs `AUTH_SECRET` env var, same HMAC logic). Extract username from verified token for investigation/acknowledgment tracking.
3. **HTTP Handler** with:
   - `GET /api/alert-states` — return all rows as JSON array
   - `POST /api/alert-states/investigate` — toggle investigation state. Body: `{fingerprint, alert_name}`. If user is already investigating, clear it. Otherwise set `investigating_user` + `investigating_since`.
   - `POST /api/alert-states/acknowledge` — bulk acknowledge. Body: `{fingerprints[], alert_names[], firing_starts[]}`. Upsert rows with `acknowledged_by`, `acknowledged_at`, `ack_firing_start`.
   - `POST /api/alert-states/unacknowledge` — bulk remove ack. Body: `{fingerprints[]}`. Clear `acknowledged_by`, `acknowledged_at`.
   - `POST /api/alert-states/mark-updated` — mark alerts as re-fired. Body: `{fingerprints[]}`. Set `is_updated=1`, `updated_detected_at`.
4. **Main** — port 8092, `DB_PATH` default `/data/alert-states.db`.

- [ ] **Step 2: Verify alert-state-api.py runs standalone**

```bash
cd deploy/alert-state-api
AUTH_SECRET=test-secret DB_PATH=./test-as.db API_PORT=8092 python3 alert-state-api.py &
sleep 2
curl -s http://localhost:8092/api/alert-states
# Should return: []
kill %1
rm -f test-as.db
```

- [ ] **Step 3: Commit**

```bash
git add deploy/alert-state-api/alert-state-api.py
git commit -m "feat: extract alert-state-api service from runbook-api monolith"
```

---

### Task 3: Create loki-gateway.py

**Files:**
- Create: `deploy/loki-gateway/loki-gateway.py`
- Reference: `deploy/runbook-api/runbook-api.py` (lines 400-738 for Loki integration, lines 827-836 for registry-health endpoint, lines 832-836 for log-context, lines 928-960 for logs/query)

- [ ] **Step 1: Create loki-gateway.py**

Standalone Python HTTP server for all Loki/registry-health interactions. This service is **stateless** — no SQLite, queries Loki via Grafana datasource proxy.

**CRITICAL CONSTRAINT:** No automatic Loki queries. All endpoints are request-response only. No background polling threads. The `start_health_poller()` function from runbook-api.py must NOT be included.

Include:
1. **Loki query helper** — `query_loki(logql, limit, range_seconds)` function. Uses `GRAFANA_URL`, `GRAFANA_USER`, `GRAFANA_PASS`, `LOKI_DATASOURCE_ID` env vars. Sends POST to `{GRAFANA_URL}/api/ds/query` with Loki datasource. Copy pattern from runbook-api.py lines 460-480.
2. **Agent-to-operator mapping** — copy `AGENT_OPERATOR_MAP` dict from runbook-api.py lines 403-433.
3. **Health aggregation logic** — copy `aggregate_registry_health()` from runbook-api.py lines 483-603. This parses Loki timing logs into per-operator metrics.
4. **Log context builder** — copy `build_log_context()` from runbook-api.py lines 641-693.
5. **Auth verification** — `verify_token()` with shared `AUTH_SECRET`. The `/api/loki/log-context` endpoint must be **exempted from auth** since it is called by the enricher service (which does not have user auth tokens). Use a simple check: if the request comes without a token, allow it only for `/api/loki/log-context` (internal-only endpoint). All other endpoints require auth.
6. **HTTP Handler** with:
   - `GET /api/loki/registry-health` — run Loki query on-demand (NOT from cache), aggregate, return. Since no auto-polling, each request queries Loki live. Add a simple response timeout. Requires auth.
   - `GET /api/loki/log-context?alert_name=X&hostname=Y` — query Loki on-demand for recent logs matching alert context, build structured response. **No auth required** (called by enricher service internally).
   - `POST /api/loki/logs/query` — interactive LogQL query. Body: `{query, limit, range}`. Validate limit (max 1000) and range (max 86400s). Forward to Loki, parse results, return entries. Requires auth.
   - `GET /api/loki/registry-trends?operator=X&range=N` — NEW endpoint. Query Loki for hourly buckets of response time, error rate, request count for the given operator over `range` hours (allowed: 6, 24, 168). Return 400 Bad Request for invalid range values. Returns JSON per spec. Requires auth.
7. **Main** — port 8091.

- [ ] **Step 2: Verify loki-gateway.py starts (Loki connection will fail without infra)**

```bash
cd deploy/loki-gateway
AUTH_SECRET=test-secret API_PORT=8091 python3 loki-gateway.py &
sleep 2
# Verify it starts and responds (Loki queries will error, which is expected)
curl -s http://localhost:8091/api/loki/registry-health -w '\n%{http_code}'
# Should return error about Loki connection, but HTTP server is up
kill %1
```

- [ ] **Step 3: Commit**

```bash
git add deploy/loki-gateway/loki-gateway.py
git commit -m "feat: extract loki-gateway service from runbook-api monolith"
```

---

## Chunk 2: Backend Infrastructure — Slim runbook-api, migration, nginx, docker-compose

### Task 4: Slim down runbook-api.py

**Files:**
- Modify: `deploy/runbook-api/runbook-api.py`

- [ ] **Step 1: Remove extracted code from runbook-api.py**

Remove the following sections (keep the rest intact):
1. **Users table init** (lines ~84-98) — moved to auth-api
2. **alert_states table init** (lines ~98-114) — moved to alert-state-api
3. **User seeding** (lines ~122-158) — moved to auth-api
4. **Auth endpoints**: `/auth/login`, `/auth/logout`, `/auth/change-password`, `/auth/jira-config`, `/auth/me` — moved to auth-api
5. **Alert state endpoints**: `/alert-states`, `/alert-states/investigate`, `/alert-states/acknowledge`, `/alert-states/unacknowledge`, `/alert-states/mark-updated` — moved to alert-state-api
6. **Loki/registry health section** (lines ~400-738): `AGENT_OPERATOR_MAP`, `query_loki()`, `aggregate_registry_health()`, `build_log_context()`, `start_health_poller()`, health cache — moved to loki-gateway
7. **Loki endpoints**: `/registry-health`, `/log-context`, `/logs/query` — moved to loki-gateway

**Keep** in runbook-api.py:
- `runbook_entries` table + `ai_instructions` table + `ai_feedback` table (these stay in `runbook.db`)
- Auth helper functions (`verify_token`, `hash_password` etc.) — still needed for `/api/runbook/entries` auth checks
- Runbook endpoints: `/match`, `/entries`, `/ai-instructions`, `/ai-feedback-summary`
- Jira integration: `/jira/incident` and all Jira helper functions
- CORS, JSON helpers

- [ ] **Step 2: Verify slimmed runbook-api.py starts**

```bash
cd deploy/runbook-api
AUTH_SECRET=test-secret DB_PATH=./test-rb.db API_PORT=8090 python3 runbook-api.py &
sleep 2
curl -s http://localhost:8090/api/runbook/entries
# Should return: {"entries": [], "total": 0}
kill %1
rm -f test-rb.db
```

- [ ] **Step 3: Commit**

```bash
git add deploy/runbook-api/runbook-api.py
git commit -m "refactor: slim runbook-api to only runbook + jira endpoints"
```

---

### Task 5: Create database migration script

**Files:**
- Create: `deploy/migrate-db.sh`

- [ ] **Step 1: Write migrate-db.sh**

```bash
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
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x deploy/migrate-db.sh
git add deploy/migrate-db.sh
git commit -m "feat: add database migration script for service decomposition"
```

---

### Task 6: Update nginx configuration

**Files:**
- Modify: `deploy/nginx-default.conf` (currently has single `/api/runbook/` block around line 95)

- [ ] **Step 1: Add new location blocks for split services**

Find the existing `/api/runbook/` location block and add the new service blocks **before** it (nginx matches first matching location). The `/api/runbook/` block stays to handle the slimmed runbook-api endpoints.

Add these location blocks:

```nginx
    # Auth API — user management and authentication
    location /api/auth/ {
        proxy_pass http://auth-api:8093;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Alert State API — investigation and acknowledgment tracking
    # Note: use prefix match without trailing slash to catch both
    # /api/alert-states and /api/alert-states/investigate etc.
    location /api/alert-states {
        proxy_pass http://alert-state-api:8092;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Loki Gateway — log queries, registry health, trends
    location /api/loki/ {
        proxy_pass http://loki-gateway:8091;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 30s;
    }
```

The existing `/api/runbook/` block stays as-is, still pointing to runbook-api:8090.

- [ ] **Step 2: Commit**

```bash
git add deploy/nginx-default.conf
git commit -m "feat: add nginx routing for auth-api, alert-state-api, loki-gateway"
```

---

### Task 7: Update docker-compose.yml

**Files:**
- Modify: `deploy/docker-compose.yml`

- [ ] **Step 1: Add auth-api service**

Add after the `runbook-api` service block:

```yaml
  auth-api:
    image: python:3.12-slim
    container_name: auth-api
    command: python3 -u /app/auth-api.py
    restart: unless-stopped
    volumes:
      - ./auth-api/auth-api.py:/app/auth-api.py:ro
      - auth_data:/data
    environment:
      API_PORT: "8093"
      DB_PATH: /data/auth.db
      AUTH_SECRET: ${AUTH_SECRET:-change-me-in-production}
    networks:
      - uip-net
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: "0.25"
```

- [ ] **Step 2: Add alert-state-api service**

```yaml
  alert-state-api:
    image: python:3.12-slim
    container_name: alert-state-api
    command: python3 -u /app/alert-state-api.py
    restart: unless-stopped
    volumes:
      - ./alert-state-api/alert-state-api.py:/app/alert-state-api.py:ro
      - alert_state_data:/data
    environment:
      API_PORT: "8092"
      DB_PATH: /data/alert-states.db
      AUTH_SECRET: ${AUTH_SECRET:-change-me-in-production}
    networks:
      - uip-net
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: "0.25"
```

- [ ] **Step 3: Add loki-gateway service**

```yaml
  loki-gateway:
    image: python:3.12-slim
    container_name: loki-gateway
    command: python3 -u /app/loki-gateway.py
    restart: unless-stopped
    volumes:
      - ./loki-gateway/loki-gateway.py:/app/loki-gateway.py:ro
    environment:
      API_PORT: "8091"
      AUTH_SECRET: ${AUTH_SECRET:-change-me-in-production}
      GRAFANA_URL: ${GRAFANA_URL}
      GRAFANA_USER: ${GRAFANA_USER}
      GRAFANA_PASS: ${GRAFANA_PASS}
      LOKI_DATASOURCE_ID: ${LOKI_DATASOURCE_ID:-17}
    networks:
      - uip-net
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: "0.25"
```

- [ ] **Step 4: Remove zabbix-poller service**

Delete the entire `zabbix-poller` service block (currently lines ~144-167 in docker-compose.yml).

- [ ] **Step 5: Add AUTH_SECRET to runbook-api environment**

In the existing `runbook-api` service, ensure `AUTH_SECRET` is present:

```yaml
      AUTH_SECRET: ${AUTH_SECRET:-change-me-in-production}
```

- [ ] **Step 6: Add named volumes**

In the `volumes:` section at the bottom, add:

```yaml
  auth_data:
  alert_state_data:
```

- [ ] **Step 7: Add loki-gateway to enricher's depends_on**

In the `alert-enricher` service, add `loki-gateway` to its `depends_on` list so the enricher doesn't start before loki-gateway is ready:

```yaml
    depends_on:
      keep-api:
        condition: service_healthy
      loki-gateway:
        condition: service_started
```

- [ ] **Step 8: Update nginx depends_on**

Add the new services to the `nginx` service's `depends_on`:

```yaml
    depends_on:
      - keep-api
      - keep-frontend
      - sre-frontend
      - runbook-api
      - auth-api
      - alert-state-api
      - loki-gateway
      - health-checker
      - n8n
```

- [ ] **Step 9: Commit**

```bash
git add deploy/docker-compose.yml
git commit -m "feat: add new services, remove zabbix-poller, add volumes"
```

---

### Task 8: Update enricher.py for path changes

**Files:**
- Modify: `deploy/enricher/enricher.py` (lines 213-261 — runbook API client calls)

- [ ] **Step 1: Audit enricher endpoints**

The enricher calls these runbook-api endpoints (lines 213-261):
- `GET /api/runbook/match` — stays on runbook-api (unchanged)
- `GET /api/runbook/ai-instructions` — stays on runbook-api (unchanged)
- `GET /api/runbook/log-context` — **moved** to loki-gateway at `/api/loki/log-context`

The enricher uses `RUNBOOK_API_URL` env var (default `http://runbook-api:8090`) to construct all paths.

- [ ] **Step 2: Add LOKI_GATEWAY_URL env var and update log-context call**

In enricher.py, add a new env var:
```python
LOKI_GATEWAY_URL = os.environ.get('LOKI_GATEWAY_URL', 'http://loki-gateway:8091')
```

Find the `fetch_log_context()` function (around line 243) and change its base URL from `RUNBOOK_API_URL` to `LOKI_GATEWAY_URL`, and update the path from `/api/runbook/log-context` to `/api/loki/log-context`.

- [ ] **Step 3: Add LOKI_GATEWAY_URL to enricher service in docker-compose.yml**

```yaml
      LOKI_GATEWAY_URL: http://loki-gateway:8091
```

- [ ] **Step 4: Commit**

```bash
git add deploy/enricher/enricher.py deploy/docker-compose.yml
git commit -m "fix: update enricher to use loki-gateway for log-context endpoint"
```

---

### Task 9: Delete poller.py

**Files:**
- Delete: `deploy/poller.py`

- [ ] **Step 1: Remove poller file**

```bash
rm deploy/poller.py
```

Also remove the root-level copy if it exists:
```bash
rm -f poller.py
```

- [ ] **Step 2: Commit**

```bash
git add -A deploy/poller* poller.py
git commit -m "chore: remove zabbix poller (replaced by webhooks)"
```

---

## Chunk 3: Frontend — API Path Migration

### Task 10: Update keep-api.ts base URLs

**Files:**
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts` (line 264 — `RUNBOOK_BASE`)

- [ ] **Step 1: Add per-service base URL constants**

At line 264, replace the single `RUNBOOK_BASE` with multiple base constants:

```typescript
// API base URLs — one per backend service
const RUNBOOK_BASE = '/api/runbook';
const AUTH_BASE = '/api/auth';
const ALERT_STATE_BASE = '/api/alert-states';
const LOKI_BASE = '/api/loki';
```

- [ ] **Step 2: Update all auth endpoint calls**

Find and replace these patterns in keep-api.ts:
- `${RUNBOOK_BASE}/auth/me` → `${AUTH_BASE}/me`
- `${RUNBOOK_BASE}/auth/login` → `${AUTH_BASE}/login`
- `${RUNBOOK_BASE}/auth/logout` → `${AUTH_BASE}/logout`
- `${RUNBOOK_BASE}/auth/change-password` → `${AUTH_BASE}/change-password`
- `${RUNBOOK_BASE}/auth/jira-config` → `${AUTH_BASE}/jira-config`

- [ ] **Step 3: Update all alert-state endpoint calls**

Find and replace:
- `${RUNBOOK_BASE}/alert-states/investigate` → `${ALERT_STATE_BASE}/investigate`
- `${RUNBOOK_BASE}/alert-states/acknowledge` → `${ALERT_STATE_BASE}/acknowledge`
- `${RUNBOOK_BASE}/alert-states/unacknowledge` → `${ALERT_STATE_BASE}/unacknowledge`
- `${RUNBOOK_BASE}/alert-states/mark-updated` → `${ALERT_STATE_BASE}/mark-updated`
- `${RUNBOOK_BASE}/alert-states` (the GET all) → `${ALERT_STATE_BASE}`

- [ ] **Step 4: Update all Loki endpoint calls**

Find and replace:
- `${RUNBOOK_BASE}/registry-health` → `${LOKI_BASE}/registry-health`
- `${RUNBOOK_BASE}/log-context` → `${LOKI_BASE}/log-context`
- `${RUNBOOK_BASE}/logs/query` → `${LOKI_BASE}/logs/query`

- [ ] **Step 5: Add new registry-trends fetch function**

Add a new exported function:

```typescript
export async function fetchRegistryTrends(operatorId: string, rangeHours: number = 24) {
  const res = await fetch(`${LOKI_BASE}/registry-trends?operator=${encodeURIComponent(operatorId)}&range=${rangeHours}`);
  if (!res.ok) throw new Error(`Registry trends failed: ${res.status}`);
  return res.json();
}
```

- [ ] **Step 6: Commit**

```bash
git add deploy/sre-frontend/src/lib/keep-api.ts
git commit -m "refactor: migrate keep-api.ts to per-service API base URLs"
```

---

### Task 11: Update hardcoded auth paths in frontend components

**Files:**
- Modify: `deploy/sre-frontend/src/app/UserMenu.tsx` (line 29)
- Modify: `deploy/sre-frontend/src/app/login/page.tsx` (line 17)
- Modify: `deploy/sre-frontend/src/app/settings/page.tsx` (lines 31, 56, 82)

- [ ] **Step 1: Update UserMenu.tsx**

Change line 29 from:
```typescript
await fetch('/api/runbook/auth/logout', { method: 'POST' });
```
to:
```typescript
await fetch('/api/auth/logout', { method: 'POST' });
```

- [ ] **Step 2: Update login/page.tsx**

Change line 17 from:
```typescript
const res = await fetch('/api/runbook/auth/login', {
```
to:
```typescript
const res = await fetch('/api/auth/login', {
```

- [ ] **Step 3: Update settings/page.tsx**

Change all three auth paths:
- Line 31: `/api/runbook/auth/me` → `/api/auth/me`
- Line 56: `/api/runbook/auth/change-password` → `/api/auth/change-password`
- Line 82: `/api/runbook/auth/jira-config` → `/api/auth/jira-config`

- [ ] **Step 4: Commit**

```bash
git add deploy/sre-frontend/src/app/UserMenu.tsx deploy/sre-frontend/src/app/login/page.tsx deploy/sre-frontend/src/app/settings/page.tsx
git commit -m "refactor: update hardcoded auth paths to use /api/auth/ prefix"
```

---

## Chunk 4: Frontend — Command Center Tabs

### Task 12: Extract DashboardView.tsx from command-center/page.tsx

**Files:**
- Create: `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`
- Modify: `deploy/sre-frontend/src/app/command-center/page.tsx`

- [ ] **Step 1: Read the current command-center/page.tsx to identify extraction boundaries**

The current page.tsx contains stats cards, charts, and a recent alerts table all in one large component. We need to extract everything after the header into a `DashboardView` component that accepts alerts + alert states as props.

- [ ] **Step 2: Create DashboardView.tsx**

Create `deploy/sre-frontend/src/app/command-center/DashboardView.tsx` as a `'use client'` component.

Props interface:
```typescript
interface DashboardViewProps {
  alerts: Alert[];
  alertStates: AlertState[];
  loading: boolean;
}
```

Move into this file:
- The stat cards section (Active, Critical, High, Warning, Likely Noise)
- Severity breakdown chart
- Active alerts by source chart
- Recent alerts table (top 30)
- All helper functions used only by these sections

The component receives parsed alerts and renders the dashboard content. It does NOT fetch data — that stays in the parent.

- [ ] **Step 3: Verify build**

```bash
cd deploy/sre-frontend && npm run build
```

Fix any TypeScript errors from the extraction.

- [ ] **Step 4: Commit extraction**

```bash
git add deploy/sre-frontend/src/app/command-center/DashboardView.tsx deploy/sre-frontend/src/app/command-center/page.tsx
git commit -m "refactor: extract DashboardView component from command-center page"
```

---

### Task 13: Extract AlertsTableView.tsx from alerts/page.tsx

**Files:**
- Create: `deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx`
- Reference: `deploy/sre-frontend/src/app/alerts/page.tsx` (lines 22-341)

- [ ] **Step 1: Create AlertsTableView.tsx**

Create `deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx` as a `'use client'` component.

Props interface:
```typescript
interface AlertsTableViewProps {
  alerts: Alert[];
  alertStates: AlertState[];
  loading: boolean;
}
```

Copy the full alert explorer functionality from `alerts/page.tsx`:
- Search input (name, host, AI summary)
- Severity dropdown filter
- Status dropdown filter (Active / Resolved / All)
- Sortable columns (severity, name, host, noise, time)
- Result count display
- Pagination (page size 25/50/100/All)
- `paginationRange()` helper

All alert detail links point to `/portal/alerts/{fingerprint}` (unchanged route).

The component does NOT fetch data — receives it via props.

- [ ] **Step 2: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx
git commit -m "feat: create AlertsTableView component for command-center tabs"
```

---

### Task 14: Wire up tabs in command-center/page.tsx

**Files:**
- Modify: `deploy/sre-frontend/src/app/command-center/page.tsx`

- [ ] **Step 1: Add tab state and imports**

At the top of the component, add:
```typescript
import DashboardView from './DashboardView';
import AlertsTableView from './AlertsTableView';

// Inside the component:
const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts'>('dashboard');
```

- [ ] **Step 2: Update fetchAlerts call from 100 to 250**

Find the `fetchAlerts(100)` call and change to `fetchAlerts(250)`.

- [ ] **Step 3: Replace the page body with tab bar + view switcher**

After the page header, add a tab bar:

```tsx
{/* Tab bar — styled like existing Active/Acknowledged pattern */}
<div className="flex gap-1 mb-6 border-b border-gray-700">
  <button
    onClick={() => setActiveTab('dashboard')}
    className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
      activeTab === 'dashboard'
        ? 'border-purple-500 text-purple-400'
        : 'border-transparent text-gray-400 hover:text-gray-300'
    }`}
  >
    Dashboard
  </button>
  <button
    onClick={() => setActiveTab('alerts')}
    className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
      activeTab === 'alerts'
        ? 'border-purple-500 text-purple-400'
        : 'border-transparent text-gray-400 hover:text-gray-300'
    }`}
  >
    All Alerts
  </button>
</div>

{activeTab === 'dashboard' ? (
  <DashboardView alerts={alerts} alertStates={alertStates} loading={loading} />
) : (
  <AlertsTableView alerts={alerts} alertStates={alertStates} loading={loading} />
)}
```

Remove the inline dashboard content that was extracted to DashboardView.

- [ ] **Step 4: Verify the page renders with both tabs**

```bash
cd deploy/sre-frontend && npm run build
```

Check for TypeScript/build errors. Fix any missing imports or prop mismatches.

- [ ] **Step 5: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/page.tsx
git commit -m "feat: add Dashboard/All Alerts tab switching to command center"
```

---

### Task 15: Delete standalone alerts page

**Files:**
- Delete: `deploy/sre-frontend/src/app/alerts/page.tsx`
- Keep: `deploy/sre-frontend/src/app/alerts/[fingerprint]/page.tsx` (alert detail stays)

- [ ] **Step 1: Delete alerts/page.tsx**

```bash
rm deploy/sre-frontend/src/app/alerts/page.tsx
```

- [ ] **Step 2: Verify alert detail page still works**

```bash
cd deploy/sre-frontend && npm run build
```

The `alerts/[fingerprint]/page.tsx` route must still compile. It has no dependency on the deleted `alerts/page.tsx`.

- [ ] **Step 3: Commit**

```bash
git add deploy/sre-frontend/src/app/alerts/page.tsx
git commit -m "chore: remove standalone alerts page (merged into command center)"
```

---

## Chunk 5: Frontend — Registry Page Rename + Dedup + Trends

### Task 16: Rename registry-contacts to registry

**Files:**
- Move: `deploy/sre-frontend/src/app/registry-contacts/` → `deploy/sre-frontend/src/app/registry/`
- Move: `deploy/sre-frontend/src/lib/registry-contacts.ts` → `deploy/sre-frontend/src/lib/registry.ts`

- [ ] **Step 1: Move the directory and data file**

```bash
cd deploy/sre-frontend/src
mv app/registry-contacts app/registry
mv lib/registry-contacts.ts lib/registry.ts
```

- [ ] **Step 2: Update imports in registry/page.tsx**

Change the import from:
```typescript
import { ... } from '../../lib/registry-contacts';
```
to:
```typescript
import { ... } from '../../lib/registry';
```

- [ ] **Step 3: Update page title**

In `registry/page.tsx`, find the page title text "Registry Contacts" and change to "Registry".

- [ ] **Step 4: Update any other files that import registry-contacts**

Search for `registry-contacts` across the frontend:
```bash
grep -r "registry-contacts" deploy/sre-frontend/src/ --include="*.ts" --include="*.tsx"
```

Update all found imports to use the new path.

- [ ] **Step 5: Verify build**

```bash
cd deploy/sre-frontend && npm run build
```

- [ ] **Step 6: Commit**

```bash
git add -A deploy/sre-frontend/src/
git commit -m "refactor: rename registry-contacts to registry"
```

---

### Task 17: Deduplicate Identity Digital registry entries

**Files:**
- Modify: `deploy/sre-frontend/src/lib/registry.ts`

- [ ] **Step 1: Remove duplicate operator entries**

In the `REGISTRY_OPERATORS` array, find and remove:
- The `identity-digital-me` entry (dedicated .ME operator)
- The `identity-digital-mobi` entry (dedicated .MOBI operator)

The main `identity-digital` entry already has per-TLD contacts for .ME and .MOBI, so these are pure duplicates.

Keep `afilias-au` as a separate entry (different ops team).

- [ ] **Step 2: Fix TLD_OPERATOR_MAP**

In `TLD_OPERATOR_MAP`:
- Ensure `.me` maps to `'identity-digital'` (not `'identity-digital-me'`)
- Ensure `.mobi` maps to `'identity-digital'` (not `'identity-digital-mobi'`)
- Fix `.tv` mapping: change from `'godaddy-registry'` to `'verisign'` (Verisign operates .TV)

- [ ] **Step 3: Verify build**

```bash
cd deploy/sre-frontend && npm run build
```

- [ ] **Step 4: Commit**

```bash
git add deploy/sre-frontend/src/lib/registry.ts
git commit -m "fix: deduplicate Identity Digital entries, fix .tv TLD mapping"
```

---

### Task 18: Add on-demand trends to registry detail modal

**Prerequisite:** Task 10 must be completed first (defines `fetchRegistryTrends` in keep-api.ts).

**Files:**
- Modify: `deploy/sre-frontend/src/app/registry/page.tsx` (OperatorDetailModal component, around line 480)

- [ ] **Step 1: Add trends state and fetch logic to OperatorDetailModal**

Inside the `OperatorDetailModal` component, add:

```typescript
import { fetchRegistryTrends } from '../../lib/keep-api';

// State
const [trendsData, setTrendsData] = useState<any>(null);
const [trendsLoading, setTrendsLoading] = useState(false);
const [trendsError, setTrendsError] = useState<string | null>(null);
const [trendsRange, setTrendsRange] = useState(24); // hours

const loadTrends = async (hours: number) => {
  setTrendsLoading(true);
  setTrendsError(null);
  setTrendsRange(hours);
  try {
    const data = await fetchRegistryTrends(operator.id, hours);
    setTrendsData(data);
  } catch (err: any) {
    setTrendsError(err.message || 'Failed to load trends');
    setTrendsData(null);
  } finally {
    setTrendsLoading(false);
  }
};
```

- [ ] **Step 2: Add trends UI section below EPP Health Metrics**

After the existing EPP Health Metrics section in the modal, add:

```tsx
{/* On-Demand Trends */}
<div className="mt-6">
  <div className="flex items-center justify-between mb-3">
    <h4 className="text-sm font-semibold text-gray-300">Performance Trends</h4>
    <div className="flex gap-1">
      {[6, 24, 168].map(h => (
        <button
          key={h}
          onClick={() => loadTrends(h)}
          className={`px-3 py-1 text-xs rounded-full transition-colors ${
            trendsRange === h && trendsData
              ? 'bg-purple-600 text-white'
              : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
          }`}
        >
          {h === 168 ? '7d' : `${h}h`}
        </button>
      ))}
    </div>
  </div>

  {trendsLoading && (
    <div className="text-center py-8 text-gray-500 text-sm">Loading trends...</div>
  )}

  {trendsError && (
    <div className="text-center py-4 text-red-400 text-sm">{trendsError}</div>
  )}

  {trendsData && trendsData.buckets && trendsData.buckets.length > 0 && (
    <TrendsChart buckets={trendsData.buckets} />
  )}

  {trendsData && (!trendsData.buckets || trendsData.buckets.length === 0) && (
    <div className="text-center py-4 text-gray-500 text-sm">No trend data available for this period.</div>
  )}

  {!trendsData && !trendsLoading && !trendsError && (
    <div className="text-center py-4 text-gray-500 text-sm">
      Click a time range above to load performance trends.
    </div>
  )}
</div>
```

- [ ] **Step 3: Create TrendsChart inline component**

Add a lightweight SVG chart component within the same file (or as a sibling component):

```tsx
function TrendsChart({ buckets }: { buckets: Array<{ timestamp: string; avg_response_ms: number; error_rate: number; request_count: number }> }) {
  if (!buckets.length) return null;

  const width = 600;
  const height = 200;
  const padding = { top: 20, right: 60, bottom: 30, left: 50 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const maxMs = Math.max(...buckets.map(b => b.avg_response_ms), 1);
  const maxErr = Math.max(...buckets.map(b => b.error_rate), 0.01);
  const maxReq = Math.max(...buckets.map(b => b.request_count), 1);

  const xScale = (i: number) => padding.left + (i / (buckets.length - 1 || 1)) * chartW;
  const yMs = (v: number) => padding.top + chartH - (v / maxMs) * chartH;
  const yErr = (v: number) => padding.top + chartH - (v / maxErr) * chartH;

  const msLine = buckets.map((b, i) => `${i === 0 ? 'M' : 'L'}${xScale(i)},${yMs(b.avg_response_ms)}`).join(' ');
  const errLine = buckets.map((b, i) => `${i === 0 ? 'M' : 'L'}${xScale(i)},${yErr(b.error_rate)}`).join(' ');

  const barW = Math.max(chartW / buckets.length - 2, 2);

  return (
    <div className="bg-gray-800/50 rounded-lg p-4">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ maxHeight: '200px' }}>
        {/* Request count bars (background) */}
        {buckets.map((b, i) => (
          <rect
            key={i}
            x={xScale(i) - barW / 2}
            y={padding.top + chartH - (b.request_count / maxReq) * chartH}
            width={barW}
            height={(b.request_count / maxReq) * chartH}
            fill="rgba(139, 92, 246, 0.15)"
          />
        ))}
        {/* Response time line */}
        <path d={msLine} fill="none" stroke="#a78bfa" strokeWidth="2" />
        {/* Error rate line */}
        <path d={errLine} fill="none" stroke="#f87171" strokeWidth="2" />
      </svg>
      <div className="flex gap-4 mt-2 text-xs text-gray-500 justify-center">
        <span className="flex items-center gap-1">
          <span className="w-3 h-0.5 bg-purple-400 inline-block" /> Avg Response (ms)
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-0.5 bg-red-400 inline-block" /> Error Rate
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-1 bg-purple-400/20 inline-block" /> Requests
        </span>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Verify build**

```bash
cd deploy/sre-frontend && npm run build
```

- [ ] **Step 5: Commit**

```bash
git add deploy/sre-frontend/src/app/registry/page.tsx
git commit -m "feat: add on-demand performance trends to registry detail modal"
```

---

## Chunk 6: Frontend — Logs, Navigation, Final Cleanup

### Task 19: Update navigation in layout.tsx

**Files:**
- Modify: `deploy/sre-frontend/src/app/layout.tsx` (lines 14-57)

- [ ] **Step 1: Replace dropdown nav with flat top-level links**

Replace the current dropdown-based navigation (lines 22-48) with flat links:

```tsx
<nav className="flex items-center gap-1">
  <a href="/portal/command-center" className="px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 rounded-md transition-colors">
    Command Center
  </a>
  <a href="/portal/logs" className="px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 rounded-md transition-colors">
    Logs
  </a>
  <a href="/portal/registry" className="px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 rounded-md transition-colors">
    Registry
  </a>
  <a href="/portal/maintenance" className="px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 rounded-md transition-colors">
    Maintenance
  </a>
  <a href="/portal/health" className="px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 rounded-md transition-colors">
    Health
  </a>
  <a href="/portal/ai-manage" className="px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 rounded-md transition-colors">
    AI Manage
  </a>
  <a href="/portal/settings" className="px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-800 rounded-md transition-colors">
    Settings
  </a>
</nav>
```

Key changes:
- **Removed**: "All Alerts" link (merged into Command Center tabs)
- **Renamed**: "Registry Contacts" → "Registry" with new path `/portal/registry`
- **Added**: "Logs" as top-level link
- **Flat layout**: No dropdown, all items visible

- [ ] **Step 2: Verify build**

```bash
cd deploy/sre-frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add deploy/sre-frontend/src/app/layout.tsx
git commit -m "refactor: replace dropdown nav with flat top-level links"
```

---

### Task 20: Verify logs page works with new API paths

**Files:**
- Modify: `deploy/sre-frontend/src/app/logs/page.tsx` (if needed)

- [ ] **Step 1: Check if logs page uses keep-api.ts or hardcodes paths**

Read the logs page and check whether it calls `queryLokiLogs()` from keep-api.ts or has its own hardcoded `/api/runbook/logs/query` path.

- [ ] **Step 2: Update any hardcoded log query paths**

If the page hardcodes `/api/runbook/logs/query`, change to `/api/loki/logs/query`.
If it uses `queryLokiLogs()` from keep-api.ts, it was already updated in Task 10 — no changes needed.

- [ ] **Step 3: Verify build**

```bash
cd deploy/sre-frontend && npm run build
```

- [ ] **Step 4: Commit (if changes were needed)**

```bash
git add deploy/sre-frontend/src/app/logs/page.tsx
git commit -m "fix: update logs page to use loki-gateway API path"
```

---

### Task 21: Disable automatic registry health polling in frontend

**Files:**
- Modify: `deploy/sre-frontend/src/app/registry/page.tsx`

- [ ] **Step 1: Check for auto-polling of registry health**

Search the registry page for any `setInterval`, `useEffect` with timer, or automatic `fetchRegistryHealth()` calls. Per the spec constraint, all Loki queries must be manual.

- [ ] **Step 2: Convert auto-fetch to manual "Refresh Health" button**

If the page auto-fetches registry health on load, change it to:
- Show a "Load Health Data" button instead of auto-loading
- User clicks to trigger `fetchRegistryHealth()` on-demand
- Display a message like "Click to load registry health metrics" in the health section placeholder

If it was already manual (loaded via user action), no changes needed.

- [ ] **Step 3: Commit (if changes were needed)**

```bash
git add deploy/sre-frontend/src/app/registry/page.tsx
git commit -m "fix: disable auto registry health polling, make it on-demand only"
```

---

### Task 22: Final build verification and cleanup

**Files:**
- All modified frontend files

- [ ] **Step 1: Full frontend build**

```bash
cd deploy/sre-frontend && npm run build
```

Fix any TypeScript errors, missing imports, or broken references.

- [ ] **Step 2: Verify no stale references remain**

```bash
# Check for any remaining references to old paths
grep -r "registry-contacts" deploy/sre-frontend/src/ --include="*.ts" --include="*.tsx"
grep -r "/api/runbook/auth" deploy/sre-frontend/src/ --include="*.ts" --include="*.tsx"
grep -r "/api/runbook/alert-states" deploy/sre-frontend/src/ --include="*.ts" --include="*.tsx"
grep -r "/api/runbook/registry-health" deploy/sre-frontend/src/ --include="*.ts" --include="*.tsx"
grep -r "/api/runbook/log-context" deploy/sre-frontend/src/ --include="*.ts" --include="*.tsx"
grep -r "/api/runbook/logs" deploy/sre-frontend/src/ --include="*.ts" --include="*.tsx"
# Check for stale deduplication references
grep -r "identity-digital-me\|identity-digital-mobi" deploy/sre-frontend/src/ --include="*.ts" --include="*.tsx"
```

All of the above should return no results. If any are found, fix them.

- [ ] **Step 3: Commit any fixes**

```bash
git add -A deploy/sre-frontend/src/
git commit -m "fix: resolve remaining stale API path references"
```

- [ ] **Step 4: Verify docker-compose.yml is valid**

```bash
cd deploy && docker compose config --quiet
```

- [ ] **Step 5: Final commit — update README**

Update `README.md` to reflect the new 4-service architecture, updated navigation, and the removal of the Zabbix poller.

```bash
git add README.md
git commit -m "docs: update README for new service architecture"
```

---

## Task Dependency Graph

```
Chunk 1 (Backend services):    Task 1 → Task 2 → Task 3    (independent of each other, but sequential for clarity)
Chunk 2 (Infrastructure):      Task 4 → Task 5 → Task 6 → Task 7 → Task 8 → Task 9
Chunk 3 (Frontend API):        Task 10 → Task 11           (depends on Chunk 1+2 for path correctness)
Chunk 4 (Command Center):      Task 12 → Task 13 → Task 14 → Task 15
Chunk 5 (Registry):            Task 16 → Task 17 → Task 18
Chunk 6 (Cleanup):             Task 19 → Task 20 → Task 21 → Task 22

Parallelizable groups:
- Tasks 1, 2, 3 can run in parallel (independent service files)
- Tasks 12, 13 can run in parallel (independent component extractions)
- Tasks 16, 17 can run in parallel (rename vs dedup)
- Chunk 4 can run in parallel with Chunks 3+5 (no dependencies between them)
- Chunk 5 (Task 18 specifically) depends on Chunk 3 (Task 10 defines fetchRegistryTrends)
```
