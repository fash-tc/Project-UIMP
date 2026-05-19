# UIP Admin Page — Design Spec

**Date:** 2026-05-19
**Author:** fash (with Claude)
**Status:** Draft — pending spec review

## Problem

UIP has grown to ~15 services with dozens of tunable knobs scattered across `~/uip/.env`, hardcoded compose values, and magic numbers in code. Today the new AI cluster rollout broke every AI feature for hours because `qwen-tooling` / `qwen-assistant` / `qwen2.5:32b` no longer exist on the cluster — a model rename that should have been a one-click change required SSH, `.env` edits, and container recreates. The existing `ai-manage` and `settings` pages cover only a sliver of what operators need. The server-side `/admin` page handles users/roles but nothing else.

**Goal:** a single granular admin surface that owns every runtime knob in the platform, hot-reloads them where safe, audits every change, and prevents silent breakage from undocumented config drift.

## Constraints

- Stay within the existing stack: Next.js 14 frontend, Python 3.12 stdlib `http.server` services, SQLite/WAL, nginx reverse proxy, Docker Compose deployment.
- No hard dependency on the new admin service — if it's down, services run on last-known config / env fallback.
- RBAC integrates with the existing `view_admin` permission system in `auth-api`.
- Reuse existing patterns: SSE infra from `alert-state-api` (commit `bbe36aa`), `useSSE` hook from `e178939`, design tokens already in use.
- Migration must be reversible at every step; legacy env vars remain authoritative until each consumer is cut over.

## Success criteria

1. A new operator can change the LLM model for every call site, edit a prompt template, and see the new prompt in production within 5 seconds — without SSH.
2. Adding a new Zabbix instance is a UI form submission, not a Python script invocation.
3. Every config change has an audit row: who, when, key, old → new, optional reason.
4. `.env` shrinks from ~50 lines to ≤15 (secrets + boot-only).
5. No service hard-depends on admin-api at boot; degraded mode is "use env defaults."
6. RBAC supports per-tab permissions so NOC operators can flip feature flags without seeing role management.

---

## 1. Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  sre-frontend (/admin/*)                  │
│  React tabs → POST /api/admin/config/{key} → SSE updates  │
└──────────────────────────────────────────────────────────┘
                              │
                              ▼  (HTTP + SSE)
┌──────────────────────────────────────────────────────────┐
│              admin-api  (new service, port 8096)          │
│  - GET /api/admin/config?scope=…                          │
│  - PATCH /api/admin/config/{key}                          │
│  - GET /api/admin/config/events  (SSE)                    │
│  - GET /api/admin/audit?…                                 │
│  - POST /api/admin/ai/test  (live sandbox)                │
│  - POST /api/admin/services/{name}/restart                │
│  - POST /api/admin/zabbix/instances  …etc.                │
└──────────────────────────────────────────────────────────┘
       │             │              │              │
       ▼             ▼              ▼              ▼
   admin.db    auth-api      docker.sock      cluster
  (config,    (perms)         (restart)       /api/tags
   audit,
   versions)
       │
       ▼ (SSE: config_changed)
┌──────────────────────────────────────────────────────────┐
│  consumers: alert-enricher, noc-bot, opensrs-health-api,  │
│  alert-state-api, runbook-api — each holds a ConfigClient │
│  that subscribes to /api/admin/config/events, hot-reloads │
│  values in-memory, falls back to env on cold start.       │
└──────────────────────────────────────────────────────────┘
```

**Decisions baked in:**

- **New service `admin-api`** (not extending `auth-api`) — isolates blast radius and lets RBAC reads stay in their lane. Auth-api remains source of truth for users/roles/permissions.
- **DB:** `admin.db` — SQLite/WAL, same pattern as existing service DBs.
- **Propagation:** SSE channel `config_changed`, mirroring the proven `/api/alert-states/events` plumbing.
- **Boot order:** services read env on cold start, then connect to SSE. If admin-api is down, fall back to env. No hard dependency.
- **Hot vs restart:** every config key has a `reload_kind` flag. Hot keys propagate via SSE; restart keys flag a banner ("changes pending, restart `<svc>` to apply"). The Services tab does the restart.

## 2. Tab inventory

Eight tabs under `/portal/admin/*`. Each maps 1:1 to a permission and a config scope.

| Tab | Permission | Purpose |
|---|---|---|
| `users` (exists) | `manage_users` | Users CRUD + role assignment |
| `roles` (exists, extend) | `manage_roles` | Roles CRUD + permission editor; adds 8 new perms |
| `ai` | `manage_ai` | Models, prompts, sandbox, instructions, kill switches |
| `pipeline` | `manage_pipeline` | Intervals, thresholds, cluster-merge rules, severity overrides |
| `zabbix` | `manage_zabbix` | Instance CRUD, "Run setup" button, action filters |
| `integrations` | `manage_integrations` | Slack, Grafana IRM, Jira, n8n, Confluence |
| `services` | `manage_services` | Per-container status, restart, logs, env viewer |
| `features` | `manage_features` | Grid of every boolean flag |
| `runbooks` | `manage_runbooks` | Runbook CRUD, Confluence import, re-embed |
| `audit` | `view_audit` | Append-only change log; CSV export |

Default role mapping (seeded):
- `sre`: all `manage_*` + `view_audit`
- `noc`: `manage_features`, `view_audit`
- `viewer`: `view_audit` only

## 3. Data model (`admin.db`)

```sql
-- Single source of truth for runtime knobs
CREATE TABLE config (
  key            TEXT PRIMARY KEY,        -- e.g. "enricher.poll_interval"
  scope          TEXT NOT NULL,           -- ai|pipeline|zabbix|integrations|services|features|runbooks
  value          TEXT NOT NULL,           -- JSON-encoded
  value_type     TEXT NOT NULL,           -- int|float|string|bool|json|secret
  reload_kind    TEXT NOT NULL,           -- hot | restart
  restart_target TEXT,                    -- which service to restart if reload_kind=restart
  default_value  TEXT NOT NULL,
  description    TEXT,
  validation     TEXT,                    -- JSON: {"min":1,"max":3600} or {"enum":[...]} or regex
  is_secret      INTEGER NOT NULL DEFAULT 0,
  updated_at     TEXT NOT NULL,
  updated_by     TEXT
);
CREATE INDEX config_scope_idx ON config(scope);

-- Audit + rollback
CREATE TABLE config_history (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  key         TEXT NOT NULL,
  old_value   TEXT,
  new_value   TEXT NOT NULL,
  changed_by  TEXT NOT NULL,
  changed_at  TEXT NOT NULL,
  reason      TEXT
);
CREATE INDEX config_history_key_at ON config_history(key, changed_at DESC);
CREATE INDEX config_history_user_at ON config_history(changed_by, changed_at DESC);

-- AI tab content
CREATE TABLE prompt_templates (
  call_site      TEXT PRIMARY KEY,        -- "enricher.summary", "noc_bot.alert_qa", etc.
  template       TEXT NOT NULL,
  model_key      TEXT NOT NULL,           -- references config.key
  temperature    REAL NOT NULL DEFAULT 0.2,
  max_tokens     INTEGER NOT NULL DEFAULT 4096,
  timeout_sec    INTEGER NOT NULL DEFAULT 30,
  enabled        INTEGER NOT NULL DEFAULT 1,
  updated_at     TEXT NOT NULL,
  updated_by     TEXT
);

CREATE TABLE prompt_versions (
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
);
CREATE INDEX prompt_versions_site_at ON prompt_versions(call_site, created_at DESC);

-- Pipeline tab
CREATE TABLE cluster_merge_rules (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern     TEXT NOT NULL,
  replacement TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  priority    INTEGER NOT NULL DEFAULT 100,
  created_by  TEXT,
  created_at  TEXT NOT NULL
);

-- Zabbix tab
CREATE TABLE zabbix_instances (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  name           TEXT UNIQUE NOT NULL,
  api_url        TEXT NOT NULL,
  poller_user    TEXT NOT NULL,
  poller_pass    TEXT NOT NULL,         -- encrypted at rest
  webhook_user   TEXT,
  webhook_userid INTEGER,
  media_type_id  INTEGER,
  action_id      INTEGER,
  last_setup_at  TEXT,
  last_setup_ok  INTEGER,
  enabled        INTEGER NOT NULL DEFAULT 1
);

-- Services tab
CREATE TABLE service_restart_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  service      TEXT NOT NULL,
  triggered_by TEXT NOT NULL,
  triggered_at TEXT NOT NULL,
  reason       TEXT,
  exit_code    INTEGER,
  duration_ms  INTEGER
);
```

**Notes:**
- Secrets (`is_secret=1`) encrypted with `AUTH_SECRET`-derived key (Fernet pattern from existing `auth-api`). API returns `***SET***`, never the value. UI edits use "leave blank to keep existing" semantics from `settings/page.tsx`.
- Validation enforced client-side (per `validation` JSON) and server-side.
- `DELETE /api/admin/config/{key}` → reset to default from seed file.
- Seed file `admin-api/seeds/config_seed.json` is the source of "every knob that exists." On boot, missing keys get inserted from seed (with values from `env_legacy` if set).
- Permission table extension lives in `auth.db`, not `admin.db`: add the 8 new entries to `ALL_PERMISSIONS`.

## 4. AI tab deep-dive

### 4.1 Layout

Three regions on `/admin/ai`:
1. **Model registry** — table proxying cluster `/api/tags` with an "approved for prod" flag; cluster endpoint field with edit + probe.
2. **Call sites** — collapsible list, one row per call site (enricher.summary, enricher.classify, noc_bot.alert_qa, noc_bot.change_tracker, noc_bot.turnover, noc_bot.escalation_classifier, opensrs_health.report, runbook_api.rag).
3. **Global instructions** — migrated from existing `ai-manage` page; injected into every prompt template.

### 4.2 Call-site expanded view (the editor + sandbox)

Side-by-side: template editor on the left, sandbox panel on the right.

- Model picker, temperature, max_tokens, timeout.
- Template editor with `{{placeholder}}` syntax.
- Sandbox: fill placeholders manually or "Load real alert" from `alert-state-api`.
- "Run" hits `POST /api/admin/ai/test` — server resolves placeholders, calls cluster, streams chunks back via SSE.
- "Save" stages (writes to `prompt_templates` + `prompt_versions`); "Save & deploy" additionally emits SSE `config_changed`.
- Sandbox calls do NOT count as production traffic (separate metrics/audit channel).

### 4.3 Version drawer

Per call site, paginated list of `prompt_versions` rows: timestamp, author, note, [diff] [load] [rollback]. Rollback overwrites `prompt_templates` and emits SSE; original version is preserved as an immutable history row.

### 4.4 Cluster failover

Cluster endpoint is a config key `ai.cluster.endpoint`. Edit triggers synchronous probe (`/api/tags`). If models referenced by call sites don't exist on the new cluster, modal lists conflicts and blocks save until user remaps. Save = SSE deploy = all services repoint instantly.

### 4.5 Out of scope

- Fine-tuning / training (cluster team owns).
- Cluster infrastructure (Kubernetes, GPU allocation).
- Editing `bge-m3` (embedding model — locked to RAG role).

## 5. Backend `admin-api` shape

New Python service, same pattern as the existing six. Port `8096`. Container `uip-admin-api`. Memory cap 256 MiB.

### 5.1 Code layout

```
admin-api/
├── admin-api.py          # entrypoint: server bootstrap + route table
├── routes/
│   ├── config.py         # /api/admin/config* — read/write/SSE
│   ├── audit.py          # /api/admin/audit
│   ├── ai.py             # /api/admin/ai/* — sandbox, models, prompts
│   ├── pipeline.py
│   ├── zabbix.py         # instance CRUD + setup runner
│   ├── integrations.py
│   ├── services.py       # docker.sock client; restart, logs
│   ├── features.py
│   └── runbooks.py
├── db.py                 # SQLite WAL + schema bootstrap + seed loader
├── seeds/
│   └── config_seed.json
├── sse.py                # SSE broadcaster (port from alert-state-api)
├── auth.py               # session validation client → auth-api
├── secrets.py            # Fernet encrypt/decrypt for is_secret keys
├── docker_ops.py         # docker.sock client
├── cluster.py            # cluster /api/tags + /api/chat for sandbox
└── tests/
```

### 5.2 Endpoint inventory

```
Config:
  GET    /api/admin/config?scope=<scope>
  GET    /api/admin/config/{key}
  PATCH  /api/admin/config/{key}        {value, reason?}
  DELETE /api/admin/config/{key}        reset to default
  GET    /api/admin/config/events       SSE

Audit:
  GET    /api/admin/audit?from=&to=&by=&key=
  GET    /api/admin/audit/export        CSV

AI:
  GET    /api/admin/ai/models
  POST   /api/admin/ai/models/refresh
  GET    /api/admin/ai/call-sites
  GET    /api/admin/ai/call-sites/{site}
  PUT    /api/admin/ai/call-sites/{site}
  POST   /api/admin/ai/call-sites/{site}/deploy
  POST   /api/admin/ai/call-sites/{site}/rollback   {version_id}
  POST   /api/admin/ai/test             streams response
  GET    /api/admin/ai/instructions
  POST   /api/admin/ai/instructions
  DELETE /api/admin/ai/instructions/{id}

Pipeline:
  GET    /api/admin/pipeline/cluster-merge-rules
  POST   /api/admin/pipeline/cluster-merge-rules
  PATCH  /api/admin/pipeline/cluster-merge-rules/{id}
  DELETE /api/admin/pipeline/cluster-merge-rules/{id}
  (severity-overrides, suggested-merges queue: same shape)

Zabbix:
  GET    /api/admin/zabbix/instances
  POST   /api/admin/zabbix/instances
  PATCH  /api/admin/zabbix/instances/{id}
  POST   /api/admin/zabbix/instances/{id}/setup   streams script output
  GET    /api/admin/zabbix/instances/{id}/health

Services:
  GET    /api/admin/services            list + status + mem/cpu
  GET    /api/admin/services/{name}
  GET    /api/admin/services/{name}/logs?tail=N
  POST   /api/admin/services/{name}/restart

Features:
  GET    /api/admin/features
  PATCH  /api/admin/features/{flag}

Runbooks:
  GET    /api/admin/runbooks
  POST   /api/admin/runbooks/import-confluence    {space_key}
  POST   /api/admin/runbooks/reembed
```

### 5.3 Auth flow

Every request → `auth.py` validates session cookie via `GET auth-api:/me` → fetches `permissions` → route declares required perm via `@requires("manage_ai")` decorator → 403 if missing.

### 5.4 SSE broadcaster

Lifted verbatim from `alert-state-api.py` `_sse_broadcast` (commit `bbe36aa`). Same `ThreadingHTTPServer`, same `_sse_clients` list. Event payload:
```json
{
  "key": "ai.enricher.model",
  "new_value": "qwen3-235b-thinking",
  "updated_by": "fash",
  "updated_at": "2026-05-19T20:55:00Z",
  "reload_kind": "hot",
  "restart_target": null
}
```

### 5.5 Consumer client (`uip_config_client.py`)

Shared lib imported by every consuming service:

```python
class ConfigClient:
    def __init__(self, admin_api="http://admin-api:8096", env_fallback=True): ...
    def get(self, key, default=None) -> Any: ...
    def on_change(self, key, callback): ...
```

Bootstrap sequence:
1. Read env (cold start; admin-api may be down).
2. Attempt initial `GET /api/admin/config` (full snapshot).
3. Spawn SSE thread → `/api/admin/config/events` → apply.

Failure modes:
- admin-api unreachable → use env.
- SSE drops → reconnect with exponential backoff; poll `/api/admin/config?scope=…` every 30 s as belt-and-suspenders.

### 5.6 Docker integration

Mount `/var/run/docker.sock:/var/run/docker.sock:ro` (same as existing `uip-health-checker`). Use either python `docker` SDK or raw HTTP over the socket — match `health-checker.py` precedent.

### 5.7 Compose entry

```yaml
admin-api:
  image: python:3.12-slim
  container_name: uip-admin-api
  restart: unless-stopped
  command: python3 -u /app/admin-api.py
  volumes:
    - ./admin-api:/app:ro
    - admin_data:/data
    - /var/run/docker.sock:/var/run/docker.sock:ro
  environment:
    API_PORT: "8096"
    DB_PATH: /data/admin.db
    AUTH_API_URL: http://auth-api:8093
    AUTH_SECRET: "${AUTH_SECRET}"
    CLUSTER_ENDPOINT: "${OLLAMA_URL}"
  deploy:
    resources:
      limits: { memory: 256M, cpus: "0.5" }
  depends_on:
    auth-api: { condition: service_started }
  networks: [uip-net]
```

### 5.8 Nginx

```
location /api/admin/config/events {
    proxy_pass http://admin-api:8096;
    proxy_buffering off;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_read_timeout 86400s;
}
location /api/admin/ {
    proxy_pass http://admin-api:8096;
    proxy_read_timeout 75s;        # zabbix setup can be slow
}
```

## 6. Frontend structure

Stay within the existing Next.js 14 app. No new build pipeline, no new design system.

### 6.1 Routes (`deploy/sre-frontend/src/app/admin/`)

```
admin/
├── layout.tsx              # tab nav + permission-gated rendering
├── page.tsx                # redirect to first allowed tab
├── _components/            # shared admin primitives
│   ├── ConfigField.tsx
│   ├── ConfigTable.tsx
│   ├── HistoryDrawer.tsx
│   ├── RestartBanner.tsx
│   ├── SaveBar.tsx
│   └── useAdminConfig.ts
├── users/page.tsx          (exists, keep)
├── roles/page.tsx          (exists, extend)
├── ai/
│   ├── page.tsx
│   ├── [site]/page.tsx
│   └── _components/
│       ├── ModelRegistry.tsx
│       ├── PromptEditor.tsx
│       ├── SandboxPanel.tsx
│       └── VersionDrawer.tsx
├── pipeline/page.tsx
├── zabbix/page.tsx
├── integrations/page.tsx
├── services/
│   ├── page.tsx
│   └── [name]/page.tsx
├── features/page.tsx
├── runbooks/page.tsx
└── audit/page.tsx
```

### 6.2 `useAdminConfig` hook

```ts
function useAdminConfig(scope: AdminScope) {
  const [values, setValues] = useState<Record<string, ConfigValue>>({});
  const [dirty, setDirty] = useState<Record<string, ConfigValue>>({});
  // GET /api/admin/config?scope=<scope> on mount
  // SSE: /api/admin/config/events → on event, if value === server, swap; if dirty, flag conflict
  return { values, dirty, set, save, saveAndDeploy, reset, conflicts };
}
```

### 6.3 SSE consumption

Reuse `src/hooks/useSSE.ts` (commit `e178939`). Wire each tab to `config_changed` filtered by scope.

### 6.4 Permission gating

```tsx
const { hasPermission, loading } = useAuth();
if (loading) return <Spinner/>;
if (!hasPermission('manage_ai')) return <Forbidden/>;
```

Tab nav in `layout.tsx` only renders tabs the user has permission for.

### 6.5 Form patterns

| Type | Control |
|---|---|
| `bool` | toggle switch |
| `enum` | `<select>` (styled) |
| `int`/`float` | `<input type=number>` with min/max from validation |
| `string` | `<input>` + on-blur regex check if defined |
| `secret` | `<input type=password>` with `••••••` placeholder when `is_secret && value_set` |
| `json` | `<textarea>` with JSON.parse on blur, inline error |

### 6.6 Conflict UX

If user is editing while someone else saves the same key, SSE delivers the change. Show yellow banner: *"jrose changed this value 2s ago. [Their value] [Your value]."* Optimistic-concurrency, no locks.

### 6.7 Audit drawer

`HistoryDrawer.tsx` opens from a 📜 button next to any field. Shows last 20 changes of that key. Click row → modal with full diff + "Rollback to this".

### 6.8 No state libraries

Plain `useState`/`useEffect` matches the rest of the app. SSE delivers freshness.

### 6.9 Bundle impact

8 new route files, ~200-400 LOC each. Heaviest: AI sandbox (streaming). Net ~60-80 KB gzipped.

## 7. Migration plan

Goal: every existing knob becomes a `config` row, every service reads it via `ConfigClient`, zero behaviour change at cutover.

### Step 1 — inventory & seed file

Sweep three sources into `admin-api/seeds/config_seed.json`:
- `~/uip/.env` lines
- `docker-compose.yml` env defaults (`${VAR:-default}`)
- Magic numbers in code (e.g., hardcoded `POLL_INTERVAL: "60"` in compose, `FLAP_WINDOW_SECONDS` default 600, cluster-merge regex hardcoded in enricher)

Each entry includes `env_legacy` — a bridge field. On boot, if a key has no DB row but the legacy env var is set, seed the DB with the env value (not the default).

### Step 2 — consumer rewrite, service by service

Per service:
1. Add `from uip_config_client import ConfigClient`.
2. Replace `os.environ.get("X")` with `cfg.get("namespace.x")`.
3. For hot-reload keys, register `cfg.on_change(...)`.
4. For restart-only keys, value read once at boot.

Ship order (smallest blast radius first):
1. `health-checker`
2. `runbook-api`
3. `opensrs-health-api`
4. `alert-enricher`
5. `alert-state-api`
6. `auth-api`
7. `noc-escalation-bot` (most keys, ship last)

Each service: own commit + deploy + 1–2 day observation. Fallback: legacy env still works; revert by reverting the service code.

### Step 3 — UI cutover

`/admin/ai`, `/admin/pipeline`, etc. read from `/api/admin/config?scope=…` and `prompt_templates`. Existing `/portal/ai-manage` redirects to `/admin/ai`.

### Step 4 — env file shrink

Once each legacy env var has a confirmed DB row + working consumer:
- Comment out (keep for one release as safety net)
- Then remove
- Final `.env` ≤15 lines: secrets, boot-only (DB paths, ports, inter-service URLs)

### Step 5 — Zabbix and runbook migrations

- Existing Zabbix instance config → `zabbix_instances` table.
- `runbook.db` unchanged; admin UI just reads the existing table.

### Step 6 — clean up old admin surfaces

- Delete `/portal/ai-manage` route (redirect one release, then remove).

## 8. Rollout strategy (within big bang)

Big bang as a project, sliced for shippability.

### Slice 1 — Foundation (week 1)

- `admin-api` service + `admin.db` schema + seed loader
- `ConfigClient` shared lib (Python) — tested, no consumers yet
- `auth-api` extension: 8 new permissions, role-mapping seed
- `nginx-default.conf` adds `/api/admin/*` proxy
- Frontend: `admin/layout.tsx` + tab nav, no tab content yet

**Ship gate:** hit `/api/admin/config` from browser, see empty list, no breakage anywhere.

### Slice 2 — Services + Features tabs (week 1)

Easiest tabs technically, biggest ops payoff. Exercise `docker_ops`, SSE, generic `ConfigField` without touching AI plumbing.
- `services/page.tsx`: list, status, mem/cpu, restart, logs
- `features/page.tsx`: grid of every `*_ENABLED` flag
- First consumer: `health-checker` (proves the client lib in prod)

**Ship gate:** restart noisy service from UI; flip `ALERT_QA_ENABLED` flag and see noc-bot react.

### Slice 3 — AI tab (week 2)

- Model registry + cluster endpoint editor
- Call-sites list, per-site editor
- Sandbox endpoint + SSE streaming
- Version history + rollback
- Migrate `alert-enricher`, `opensrs-health-api`, `noc-bot` AI keys to `ConfigClient`

**Ship gate:** change `enricher.model` in UI; new model in use within 5s without restart; rollback works.

### Slice 4 — Pipeline tab (week 2–3)

- Intervals, thresholds, cluster-merge rules, severity overrides, suggested-merges queue
- Migrate remaining `alert-enricher` keys + `alert-state-api`

**Ship gate:** change poll interval, see new interval in enricher logs within one cycle.

### Slice 5 — Zabbix + Integrations + Runbooks (week 3–4)

- Zabbix instance CRUD + "Run setup" streaming output
- Integrations: Slack channel mappings, Grafana IRM, Jira, n8n, Confluence
- Runbooks tab + Confluence bulk import + re-embed

**Ship gate:** add a new Zabbix instance via UI, click setup, see webhook configured.

### Slice 6 — Audit + RBAC polish (week 4)

- Audit log viewer + CSV export
- Per-tab permission UX in roles editor
- Conflict-detection banner
- Secret rotation timestamps

**Ship gate:** full RBAC matrix tested with sre/noc/viewer roles.

### Slice 7 — Cleanup + env shrink (week 4–5)

- Drop legacy env vars
- Delete `/portal/ai-manage`
- One-page operator guide

**Ship gate:** `.env` ≤15 lines; new SRE onboards a Zabbix instance without SSH.

## 9. Risk register

| Risk | Mitigation |
|---|---|
| SSE flake | Consumers poll every 30s as belt-and-suspenders if no events seen in 60s |
| admin-api down | Consumers serve last-known value; cold start uses env. No hard dependency. |
| Bad config saved | `Save` (stage) vs `Save & deploy` (push) — extra click to deploy. One-click rollback. Audit log. |
| Permission misconfig locks out | `sre` role seeded with full access; emergency `super_admin` env flag bypasses RBAC |
| Secrets leaked via API | `is_secret=1` → API returns `***SET***`, never value. Encrypted at rest with `AUTH_SECRET`-derived key. |
| Migration breaks a consumer | Per-service rollout with 1–2 day observation window; legacy env remains authoritative until cutover |
| docker.sock RW exposure | Mount read-only by default; restart endpoint uses a vetted subset of API |

## 10. Out of scope

- Multi-region / HA admin-api
- Config versioning across services (e.g., snapshot whole admin.db, restore)
- A/B testing of prompts
- External SSO (continues to use existing auth-api login)
- Mobile/responsive optimization beyond what the rest of the app already has

## 11. Open questions

- Should the AI sandbox count against any rate limits the cluster has per key?
- Should "Save & deploy" require a second confirmation for high-stakes keys (e.g., `ai.cluster.endpoint`)?
- For audit retention — keep `config_history` forever, or aged-out after N months?
- Confluence bulk import: incremental (only new pages) or full re-sync each run?

These can be resolved during implementation planning.
