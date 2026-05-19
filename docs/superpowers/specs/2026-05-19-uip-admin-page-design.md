# UIP Admin Page — Design Spec

**Date:** 2026-05-19
**Author:** fash (with Claude)
**Status:** Draft v2 — addresses spec-review feedback

## Problem

UIP has grown to ~15 services with dozens of tunable knobs scattered across `~/uip/.env`, hardcoded compose values, and magic numbers in code. Today the new AI cluster rollout broke every AI feature for hours because `qwen-tooling` / `qwen-assistant` / `qwen2.5:32b` no longer exist on the cluster — a model rename that should have been a one-click change required SSH, `.env` edits, and container recreates. The existing `ai-manage` and `settings` pages cover only a sliver of what operators need.

**Goal:** a single granular admin surface that owns every runtime knob in the platform, hot-reloads them where safe, audits every change, and prevents silent breakage from undocumented config drift.

## Baseline assumption — server state, not local repo

This spec is grounded in **what's currently running on `fash@10.177.154.196:~/uip/`**, not what's in the local `deploy/` directory. The local repo has drifted significantly:

| Component | Local LOC | Server LOC | Notes |
|---|---|---|---|
| `auth-api.py` | 302 | 1285 | Server has full RBAC; local is stub |
| `sre-frontend/src/app/admin/` | absent | exists | Server has users + roles + permissions UI |
| `src/lib/auth.ts` `useAuth` hook | absent locally | `auth.ts:18` on server | `hasPermission(perm)` already wired |
| `auth.db` schema | minimal | `users, roles, role_permissions, shared_integrations, webhook_subscriber_secrets` | Verified via `docker exec uip-auth-api python3` |
| `ALL_PERMISSIONS` constant | absent | `auth-api.py:39`, `keep-api.ts:1786` | view_admin, manage_users, manage_roles, etc. already defined |
| Roles seeded | n/a | `Admin (1), SRE (2), Viewer (3)` | Verified in live `auth.db` |

**Required prerequisite (Slice 0):** rsync server `~/uip/` → local `deploy/`. This reconciliation is a precondition to executing this spec. Without it, anyone reading the spec against the local repo will conclude it's based on phantom infrastructure. The reconciliation itself is out of scope for this spec — it's the first sub-project in the queue from the broader brainstorm.

## Constraints

- Stay within the existing stack: Next.js 14 frontend, Python 3.12 stdlib `http.server` services, SQLite/WAL, nginx reverse proxy, Docker Compose deployment on a single host.
- Build atop the **server**'s `auth-api` RBAC (1285-line version, with `ALL_PERMISSIONS` and `_require_permission` decorator).
- Reuse existing patterns: SSE infra from `alert-state-api.py` (commit `bbe36aa`), `useSSE` hook from `e178939`, `useAuth` from `src/lib/auth.ts:18`, design tokens already in use.
- No hard dependency on the new admin service — if it's down, services run on last-known config / env fallback.
- Migration must be reversible at every step; legacy env vars remain authoritative until each consumer is cut over.
- New runtime dependency: the `cryptography` library, added to `admin-api/requirements.txt` for Fernet symmetric encryption of secrets at rest. Other services unchanged.

## Success criteria

1. A new operator can change the LLM model for every call site, edit a prompt template, and see the new prompt in production within 5 seconds — without SSH.
2. Adding a new Zabbix instance is a UI form submission, not a Python script invocation.
3. Every config change has an audit row: who, when, key, old → new, optional reason.
4. `.env` shrinks from ~50 lines to ≤15 (secrets + boot-only).
5. No service hard-depends on admin-api at boot; degraded mode is "use env defaults."
6. RBAC supports per-tab permissions so NOC operators can flip feature flags without seeing role management.
7. An invalid value pushed via SSE never crashes a consumer; it's rejected and logged, the previous value sticks.

## Glossary

| Term | Meaning |
|---|---|
| **scope** | Top-level config category. One of: `ai`, `pipeline`, `zabbix`, `integrations`, `services`, `features`, `runbooks`. Determines which tab the key appears under and which permission gates editing. |
| **key** | Dotted identifier of a single tunable knob, e.g. `ai.enricher.model`, `pipeline.enricher.poll_interval`. Unique within `admin.db.config`. |
| **call_site** | A named LLM invocation point in a service, e.g. `enricher.summary`, `noc_bot.alert_qa`, `noc_bot.change_tracker`. Each has its own prompt template, model, sampling params. |
| **reload_kind** | `hot` (SSE propagation; consumer swaps in memory) or `restart` (config is read at boot only; UI shows banner that a restart is needed). |
| **restart_target** | When `reload_kind=restart`, the docker compose service name that must be restarted to pick up the change. |
| **env_legacy** | Bridge field in the seed: name of the pre-existing env var whose value is used to seed the DB on first boot. |
| **ConfigClient** | Shared Python module (`uip_config_client.py`) that each consumer imports. Reads config via HTTP+SSE from admin-api, falls back to env. |

---

## 1. Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  sre-frontend (/admin/*)                  │
│  React tabs → PATCH /api/admin/config/{key} → SSE updates │
└──────────────────────────────────────────────────────────┘
                              │
                              ▼  (HTTP + SSE)
┌──────────────────────────────────────────────────────────┐
│              admin-api  (new service, port 8096)          │
│  - GET /api/admin/config?scope=…                          │
│  - PATCH /api/admin/config/{key}                          │
│  - GET /api/admin/config/events  (SSE)                    │
│  - GET /api/admin/audit?…                                 │
│  - POST /api/admin/ai/test  (live sandbox; HTTP chunked)  │
│  - POST /api/admin/services/{name}/restart                │
│  - POST /api/admin/zabbix/instances  …etc.                │
└──────────────────────────────────────────────────────────┘
       │             │              │              │
       ▼             ▼              ▼              ▼
   admin.db    auth-api      docker.sock      cluster
  (config,    (perms)       (restart, logs)   /api/tags
   audit,
   versions)
       │
       ▼ (SSE: config_changed)
┌──────────────────────────────────────────────────────────┐
│  consumers: alert-enricher, noc-bot, opensrs-health-api,  │
│  alert-state-api, runbook-api, health-checker — each      │
│  holds a ConfigClient that subscribes to /api/admin/      │
│  config/events, hot-reloads values in-memory, falls back  │
│  to env on cold start.                                    │
└──────────────────────────────────────────────────────────┘
```

**Decisions baked in:**

- **New service `admin-api`** (not extending `auth-api`) — isolates blast radius and lets RBAC reads stay in their lane. Auth-api remains source of truth for users/roles/permissions.
- **DB:** `admin.db` — SQLite/WAL, same pattern as existing service DBs.
- **Propagation:** SSE channel `config_changed`, mirroring the proven `/api/alert-states/events` plumbing.
- **Boot order:** services read env on cold start, then connect to SSE. If admin-api is down, fall back to env. No hard dependency.
- **Hot vs restart:** every config key has a `reload_kind` flag. Hot keys propagate via SSE; restart keys flag a banner ("changes pending, restart `<svc>` to apply"). The Services tab does the restart.
- **AI sandbox transport:** HTTP chunked-transfer-encoding response (NOT shared SSE), because the sandbox call is request-scoped and shouldn't multiplex with the config event channel. Nginx route gets its own location with extended timeout (Section 5.8).

## 2. Tab inventory

Ten tabs under `/admin/*` (mounted at `/portal/admin/*` by the existing Next.js base-path config; the spec uses `/admin/…` for brevity throughout). The first two are pre-existing on the server (verified live) and will be touched only to extend permissions. The remaining eight are new.

| Tab | Permission | Status | Purpose |
|---|---|---|---|
| `users` | `manage_users` | exists | Users CRUD + role assignment |
| `roles` | `manage_roles` | exists, extend | Roles CRUD + permission editor; adds 8 new perms to `ALL_PERMISSIONS` |
| `ai` | `manage_ai` | new | Models, prompts, sandbox, instructions, kill switches |
| `pipeline` | `manage_pipeline` | new | Intervals, thresholds, cluster-merge rules, severity overrides |
| `zabbix` | `manage_zabbix` | new | Instance CRUD, "Run setup", action filters |
| `integrations` | `manage_integrations` | new | Slack, Grafana IRM, Jira, n8n, Confluence |
| `services` | `manage_services` | new | Per-container status, restart, logs, env viewer |
| `features` | `manage_features` | new | Grid of every boolean flag |
| `runbooks` | `manage_runbooks` | new | Runbook CRUD, Confluence import, re-embed |
| `audit` | `view_audit` | new | Append-only change log; CSV export |

**Eight new permissions** to add to `ALL_PERMISSIONS` (in both `auth-api.py:39` and `sre-frontend/src/lib/keep-api.ts:1786`): `manage_ai`, `manage_pipeline`, `manage_zabbix`, `manage_integrations`, `manage_services`, `manage_features`, `manage_runbooks`, `view_audit`. One permission per new tab.

Default role mapping (delta to existing seed):
- `Admin (id=1)`: receives all 8 new permissions.
- `SRE (id=2)`: receives all 8 new permissions.
- `Viewer (id=3)`: receives `view_audit` only.

## 3. Data model (`admin.db`)

```sql
-- Single source of truth for runtime knobs
CREATE TABLE config (
  key                 TEXT PRIMARY KEY,
  scope               TEXT NOT NULL,
  value               TEXT NOT NULL,        -- JSON-encoded
  value_type          TEXT NOT NULL,        -- int|float|string|bool|json|secret
  reload_kind         TEXT NOT NULL,        -- hot | restart
  restart_target      TEXT,
  default_value       TEXT NOT NULL,
  description         TEXT,
  validation          TEXT,                 -- JSON: {"min":1,"max":3600} or {"enum":[…]} or {"regex":…}
  is_secret           INTEGER NOT NULL DEFAULT 0,
  secret_rotated_at   TEXT,                 -- only meaningful if is_secret=1
  updated_at          TEXT NOT NULL,
  updated_by          TEXT,
  seed_version        INTEGER NOT NULL DEFAULT 1   -- last seed file version that touched this row
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
  reason      TEXT,
  source      TEXT NOT NULL DEFAULT 'user'  -- user | seed | rotation | rollback
);
CREATE INDEX config_history_key_at  ON config_history(key, changed_at DESC);
CREATE INDEX config_history_user_at ON config_history(changed_by, changed_at DESC);

-- AI tab content
CREATE TABLE prompt_templates (
  call_site      TEXT PRIMARY KEY,
  template       TEXT NOT NULL,
  model_key      TEXT NOT NULL,             -- references config.key
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
  poller_pass    BLOB NOT NULL,            -- Fernet-encrypted; stores bytes
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

-- Schema versioning
CREATE TABLE schema_migrations (
  version    INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL,
  note       TEXT
);
```

### 3.1 Secret storage and rotation

- The `cryptography` library is added to `admin-api/requirements.txt`. Fernet (AES-128-CBC + HMAC-SHA256, with a random 16-byte IV per record) is used to encrypt anything where `is_secret=1` and the `poller_pass` field of `zabbix_instances`.
- The Fernet key is derived from `AUTH_SECRET` via HKDF-SHA256 (info=`"admin-api-secrets-v1"`, salt=32 fixed bytes constant to the build). Stored in memory only.
- API responses for secret keys return the sentinel string `"***SET***"` when set, `""` when unset, never the plaintext. UI uses the "leave blank to keep existing" pattern from `settings/page.tsx:255`.
- `POST /api/admin/config/{key}/rotate-secret` accepts a new plaintext, writes the new ciphertext, updates `secret_rotated_at`. Adds a `config_history` row with `source='rotation'` and `new_value="***ROTATED***"` so the audit log shows when secrets changed without exposing them.
- **Rotating `AUTH_SECRET` itself is out of scope** for this spec — that requires re-encrypting every Fernet record and is treated as a separate operational procedure. A future spec will add an `admin-api rotate-master-key` CLI.

### 3.2 Seed evolution and schema migrations

- `admin-api/seeds/config_seed.json` is versioned by a top-level `"version"` integer.
- On boot, admin-api compares its embedded seed version to the `seed_version` column of `config` rows.
- **New keys**: any seed entry with no matching DB row is inserted using `env_legacy` (if set) or `default_value`. `seed_version` set to current.
- **Renamed keys**: seed entry includes optional `renamed_from` field. On boot, if `renamed_from` exists in DB and the new key doesn't, the row is renamed (key updated, `seed_version` bumped). Audit row written with `source='seed'`.
- **Removed keys**: seed entry includes optional `deprecated: true`. The row stays in DB (history preservation) but is hidden from UI and rejected by writes. After two releases marked deprecated, a future seed bump can delete the row.
- **Tightened validation**: on boot, after seed apply, admin-api re-validates every row. If a row violates current validation, it's flagged in a `seed_warnings` log line and exposed via `GET /api/admin/config?warnings=1`; the value is preserved (not auto-corrected) and the operator sees a banner.
- **Changed `value_type`**: treated as a rename — old key marked deprecated, new key seeded with default. Manual operator action to migrate the value.
- **`admin.db` schema migrations**: `schema_migrations` table tracks applied versions. Each Python migration file in `admin-api/migrations/NNNN_description.py` exports `apply(conn)`. Boot sequence runs unapplied migrations in order. Mirrors the pattern from `auth-api`'s own migration files (verified in server `~/uip/auth-api/`).

### 3.3 RBAC bootstrap escape

To prevent locking everyone out:

- Admin-api reads `ADMIN_BYPASS_TOKEN` env var on boot. If set (and non-empty), any request bearing `X-Admin-Bypass: <token>` header in the absence of (or in addition to) a session cookie is treated as a synthetic user `__bypass__` with **all** permissions. Every such request writes an audit row with `source='user'`, `changed_by='__bypass__:<requester_ip>'`. The token is set in `.env` outside the UI's control, never exposed via API.
- Recovery flow: operator SSHes to the server, sets `ADMIN_BYPASS_TOKEN` in `.env`, restarts admin-api, then uses the token via `curl -H "X-Admin-Bypass: …"` to repair role assignments, then unsets the token and restarts.
- The bypass is logged loudly: every request with the header emits a structured log entry tagged `audit_bypass=true`.

## 4. AI tab deep-dive

### 4.1 Layout

Three regions on `/admin/ai`:
1. **Model registry** — table proxying cluster `/api/tags` with an "approved for prod" flag; cluster endpoint field with edit + probe.
2. **Call sites** — collapsible list, one row per call site (`enricher.summary`, `enricher.classify`, `noc_bot.alert_qa`, `noc_bot.change_tracker`, `noc_bot.turnover`, `noc_bot.escalation_classifier`, `opensrs_health.report`, `runbook_api.rag`).
3. **Global instructions** — migrated from existing `ai-manage` page; injected into every prompt template.

### 4.2 Call-site expanded view

Side-by-side: template editor on the left, sandbox panel on the right.

- Model picker, temperature, max_tokens, timeout.
- Template with `{{placeholder}}` syntax.
- Sandbox: fill placeholders manually or "Load real alert" from `alert-state-api`.
- "Run" issues `POST /api/admin/ai/test` (no special `Accept` header — plain `application/json` request body). Server resolves placeholders, calls cluster, streams the model's tokens back to the client over the same connection using HTTP chunked transfer encoding (NOT SSE — see §1 and §5.8). Frontend reads via `ReadableStream` on the `fetch()` Response.body.
- "Save" stages (writes to `prompt_templates` + `prompt_versions`). "Save & deploy" additionally emits SSE `config_changed`.
- Sandbox calls do NOT count as production traffic; admin-api tags `metrics_channel="sandbox"` on the call so it's excluded from SLI dashboards. (Sandbox calls are still subject to whatever rate-limits the cluster enforces — admin-api passes them through unmodified. If sandbox traffic hurts production, the operator can disable sandboxing via a `feature.admin.ai_sandbox` flag.)

### 4.3 Version drawer

Per call site, paginated list of `prompt_versions` rows: timestamp, author, note, [diff] [load] [rollback]. Rollback overwrites `prompt_templates` and emits SSE; the original version is preserved as an immutable history row.

### 4.4 Cluster failover

Cluster endpoint is a config key `ai.cluster.endpoint`. Edit triggers a synchronous probe (`GET /api/tags`). If models referenced by call sites don't exist on the new cluster, a modal lists conflicts and **blocks save** until the operator remaps the conflicting call sites. Save = SSE deploy = all services repoint instantly.

`ai.cluster.endpoint` is treated as a **high-stakes key**: the save requires a confirmation dialog ("This will repoint every AI service. Type 'repoint' to confirm.") and is rate-limited to 1 change per 60 seconds. No second confirmation beyond that. No other config key requires typed confirmation in this iteration.

### 4.5 Out of scope

- Fine-tuning / training (cluster team owns).
- Cluster infrastructure (Kubernetes, GPU allocation).
- Editing `bge-m3` (embedding model — locked to RAG role).
- A/B testing of prompts.

## 5. Backend `admin-api` shape

New Python service, same pattern as the existing six. Port `8096`. Container `uip-admin-api`. Memory cap 256 MiB. Estimated 1500-2500 LOC across modules.

### 5.1 Code layout

```
admin-api/
├── admin-api.py          # entrypoint
├── routes/
│   ├── config.py         # /api/admin/config*
│   ├── audit.py          # /api/admin/audit
│   ├── ai.py             # /api/admin/ai/*
│   ├── pipeline.py
│   ├── zabbix.py
│   ├── integrations.py
│   ├── services.py       # docker.sock
│   ├── features.py
│   └── runbooks.py
├── db.py                 # SQLite WAL + schema bootstrap + seed loader
├── migrations/
│   ├── 0001_initial.py
│   └── …
├── seeds/
│   ├── config_seed.json
│   └── services_seed.json     # restartable-container allowlist (§5.6)
├── sse.py                # SSE broadcaster (port from alert-state-api)
├── auth.py               # session validation client → auth-api
├── secrets.py            # Fernet wrapper + HKDF derivation
├── docker_ops.py         # docker.sock client
├── cluster.py            # /api/tags + /api/chat client
├── requirements.txt      # cryptography==42.*
└── tests/
```

### 5.2 Endpoint inventory

```
Config:
  GET    /api/admin/config?scope=<scope>&warnings=<0|1>
  GET    /api/admin/config/{key}
  PATCH  /api/admin/config/{key}              {value, reason?}
  POST   /api/admin/config/{key}/rotate-secret  {value}  (is_secret=1 keys only)
  DELETE /api/admin/config/{key}              reset to default
  GET    /api/admin/config/events             SSE; channel "config_changed"

Audit:
  GET    /api/admin/audit?from=&to=&by=&key=
  GET    /api/admin/audit/export              CSV

AI:
  GET    /api/admin/ai/models
  POST   /api/admin/ai/models/refresh
  GET    /api/admin/ai/call-sites
  GET    /api/admin/ai/call-sites/{site}
  PUT    /api/admin/ai/call-sites/{site}
  POST   /api/admin/ai/call-sites/{site}/deploy
  POST   /api/admin/ai/call-sites/{site}/rollback   {version_id}
  POST   /api/admin/ai/test                    chunked-transfer-encoding stream
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
  POST   /api/admin/zabbix/instances/{id}/setup   chunked streams script output
  GET    /api/admin/zabbix/instances/{id}/health

Services:
  GET    /api/admin/services
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

Every request → `auth.py` validates session cookie via `GET auth-api:/me` → fetches `permissions` → route declares required perm via `@requires("manage_ai")` decorator → 403 if missing. Bypass header `X-Admin-Bypass` (§3.3) short-circuits this with elevated audit tagging.

### 5.4 SSE broadcaster

Lifted from `alert-state-api.py` `_sse_broadcast` (commit `bbe36aa`). Event payload:

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

Shared library imported by every consuming service. Full interface:

```python
class ConfigClient:
    def __init__(
        self,
        admin_api: str = "http://admin-api:8096",
        env_fallback: bool = True,
        poll_interval_sec: int = 30,
        sse_reconnect_max_sec: int = 60,
        on_invalid_payload: Callable[[dict, Exception], None] | None = None,
        schemas: dict[str, KeySchema] | None = None,   # see §5.5.1
    ): ...

    def register_schema(self, key: str, schema: KeySchema) -> None:
        """
        Register or override the local validation schema for a single key.
        Idempotent. Can be called at any time, including after init, to support
        consumers that register a subset of keys lazily.
        """

    def get(self, key: str, default: Any = _SENTINEL) -> Any:
        """
        Resolution order:
          1. In-memory cache (most recent SSE-applied value or initial snapshot).
          2. If admin-api was reachable but key absent: env via env_legacy mapping.
          3. If admin-api unreachable at startup: env directly (UPPER_SNAKE of key).
          4. If both fail: the `default` arg. If no default and no fallback: raise KeyError.
        """

    def on_change(self, key: str, callback: Callable[[Any, Any], None]) -> None:
        """
        callback(old_value, new_value) fires on the SSE reader thread.
        Callbacks must be thread-safe and non-blocking; long work should hop to a worker.
        Callback exceptions are caught + logged; do not stop event processing.
        """

    def get_all(self, scope: str | None = None) -> dict[str, Any]:
        """Snapshot. Useful for boot-time dumps."""
```

### 5.5.1 Schema source-of-truth and packaging

To prevent drift between admin-api's authoritative validation and the client-side check that protects consumers:

- **Single source of truth**: `admin-api/seeds/config_seed.json`. Each entry carries the same `validation` JSON that ends up in `admin.db.config.validation`.
- **Generated module**: `admin-api/build_schemas.py` reads the seed JSON and emits `uip_config_client/schemas.py` — a plain Python module exporting `SCHEMAS: dict[str, KeySchema]` where `KeySchema` is a simple `@dataclass(frozen=True)` holding `value_type`, `validation_rule`, and `seed_version`. Generated at deploy time (Slice 1 ship step), committed to git so consumer images get it via bind-mount of the shared lib.
- **`KeySchema` type**:
  ```python
  @dataclass(frozen=True)
  class KeySchema:
      value_type: Literal["int", "float", "string", "bool", "json", "secret"]
      validation_rule: dict | None  # e.g. {"min": 1, "max": 3600} or {"enum": [...]} or {"regex": "..."}
      seed_version: int
  ```
- **Registration default**: when `ConfigClient(schemas=None)`, the constructor calls `register_schema()` for every key in `uip_config_client.schemas.SCHEMAS`. Consumers don't need to register anything for the happy path; they only call `register_schema()` if they want to override or add a key (e.g., a service-private key not in the global seed).
- **Version mismatch detection**: at startup, the client compares its `SCHEMAS` `seed_version` to admin-api's `GET /api/admin/config/schemas/version`. If they diverge by more than 1, the client logs a structured warning `schema_version_drift=N` so operators see stale consumers after a seed upgrade. The client keeps working; it just flags the gap.

**Invalid-payload handling** (success criterion 7):

- Every received value is validated against the registered `KeySchema`.
- If validation fails:
  - Old in-memory value is **kept**.
  - `on_invalid_payload(payload, exception)` is called (defaults to a structured log entry tagged `invalid_config=true`).
  - A counter `config_invalid_total{key=…}` is incremented (Prometheus metric).
- This guarantees the original incident class (model rename to nonexistent name) cannot crash a consumer; it surfaces in logs and metrics so an operator can investigate.

**Thread safety**: `get()` reads from an `RLock`-guarded dict. `on_change` callbacks run on a single dedicated reader thread; consumers must not block. For consumers that need an event loop, a glue helper `ConfigClient.bridge_to_asyncio(loop)` posts callbacks to the loop.

**Freshness contract**: SSE-delivered values are visible to `get()` within milliseconds. If SSE drops, the 30-s poll catches up. Maximum staleness with both broken: 30 s + reconnect backoff (max 60 s) = ~90 s, then env fallback if admin-api stays down.

### 5.6 Docker integration

Mount `/var/run/docker.sock:/var/run/docker.sock:ro` (same as existing `uip-health-checker`). The restart endpoint sends a `POST /containers/{id}/restart` to the socket — admin-api maintains an allowlist of restartable container names (loaded from `services_seed.json`). Anything outside the allowlist returns 400.

### 5.7 Compose entry

```yaml
admin-api:
  image: python:3.12-slim
  container_name: uip-admin-api
  restart: unless-stopped
  command: sh -c "pip install -q -r /app/requirements.txt && python3 -u /app/admin-api.py"
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
    ADMIN_BYPASS_TOKEN: "${ADMIN_BYPASS_TOKEN:-}"
  deploy:
    resources:
      limits: { memory: 256M, cpus: "0.5" }
  depends_on:
    auth-api: { condition: service_started }
  networks: [uip-net]

# Append to top-level volumes:
volumes:
  …
  admin_data:
```

### 5.8 Nginx

```
# Sandbox stream — long-lived, chunked
location /api/admin/ai/test {
    proxy_pass http://admin-api:8096;
    proxy_buffering off;
    proxy_http_version 1.1;
    proxy_read_timeout 180s;
}

# Zabbix setup stream
location ~ ^/api/admin/zabbix/instances/[0-9]+/setup$ {
    proxy_pass http://admin-api:8096;
    proxy_buffering off;
    proxy_http_version 1.1;
    proxy_read_timeout 300s;
}

# Config event channel (SSE)
location /api/admin/config/events {
    proxy_pass http://admin-api:8096;
    proxy_buffering off;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_read_timeout 86400s;
}

# Everything else
location /api/admin/ {
    proxy_pass http://admin-api:8096;
    proxy_read_timeout 75s;
}
```

## 6. Frontend structure

Stay within the existing Next.js 14 app. No new build pipeline.

### 6.1 Routes

```
src/app/admin/
├── layout.tsx              # tab nav + permission-gated rendering
├── page.tsx                # redirect to first allowed tab
├── _components/
│   ├── ConfigField.tsx
│   ├── ConfigTable.tsx
│   ├── HistoryDrawer.tsx
│   ├── RestartBanner.tsx
│   ├── SaveBar.tsx
│   └── useAdminConfig.ts
├── users/page.tsx          # exists on server, no changes
├── roles/page.tsx          # exists on server, add 8 new perms to displayed ALL_PERMISSIONS
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

### 6.2 Hooks

- `useAuth` (existing — `src/lib/auth.ts:18`): returns `{user, permissions, loading, hasPermission}`. No changes.
- `useSSE` (existing — `src/hooks/useSSE.ts`, commit `e178939`): generic SSE consumer.
- `useAdminConfig` (new — `src/app/admin/_components/useAdminConfig.ts`):

```ts
function useAdminConfig(scope: AdminScope) {
  const [values, setValues] = useState<Record<string, ConfigValue>>({});
  const [dirty, setDirty] = useState<Record<string, ConfigValue>>({});
  const [conflicts, setConflicts] = useState<Record<string, ConfigValue>>({});
  // Mount: GET /api/admin/config?scope=<scope>
  // Subscribe: useSSE('/api/admin/config/events') → on event with scope match:
  //   - if local dirty and incoming != local: set conflict
  //   - else: replace values[key]
  return { values, dirty, conflicts, set, save, saveAndDeploy, reset };
}
```

### 6.3 Permission gating

In `layout.tsx`, the tab nav only renders links the user has permission for. Each tab page guards with:

```tsx
const { hasPermission, loading } = useAuth();
if (loading) return <Spinner/>;
if (!hasPermission('manage_ai')) return <Forbidden/>;
```

### 6.4 Form patterns

| Type | Control |
|---|---|
| `bool` | toggle switch |
| `enum` | `<select>` |
| `int`/`float` | `<input type=number>` with min/max from validation |
| `string` | `<input>` + on-blur regex check if defined |
| `secret` | `<input type=password>` with `••••••` placeholder when value is set |
| `json` | `<textarea>` with JSON.parse on blur, inline error |

### 6.5 Conflict UX

If user edits while someone else saves the same key, SSE delivers the change → yellow banner: *"jrose changed this 2s ago. [Their value] [Your value]."*. Optimistic-concurrency, no locks.

### 6.6 Audit drawer

`HistoryDrawer.tsx` opens from a 📜 button next to any field. Last 20 changes of that key. Row click → diff modal + "Rollback to this".

### 6.7 Bundle impact

8 new route files, 200–400 LOC each. Heaviest: AI sandbox (streaming). Net ~60–80 KB gzipped.

## 7. Migration plan

Goal: every existing knob becomes a `config` row, every service reads it via `ConfigClient`, zero behaviour change at cutover.

### Step 1 — inventory & seed file

Sweep three sources into `admin-api/seeds/config_seed.json`:
- `~/uip/.env` lines
- `docker-compose.yml` env defaults (`${VAR:-default}`)
- Magic numbers in code

Each entry includes `env_legacy` — on first boot of admin-api, if a key has no DB row but the legacy env var is set, seed the DB with the env value (not the default).

### Step 2 — consumer rewrite, service by service

Canonical order (single source of truth; §8 slices reference this):

1. `health-checker` — smallest, lowest stakes; proves the client lib.
2. `runbook-api` — handful of keys.
3. `opensrs-health-api` — AI keys only.
4. `alert-state-api` — moderate.
5. `alert-enricher` — many keys; today's restart already proves env-driven changes work.
6. `auth-api` — sessions, timeouts.
7. `noc-escalation-bot` — most keys, shipped last when client lib is well-shaken.

Per service:
1. Add `from uip_config_client import ConfigClient`.
2. Replace `os.environ.get("X")` with `cfg.get("namespace.x")`.
3. Hot-reload keys: register `cfg.on_change(...)`.
4. Restart-only keys: read once at boot.
5. Ship + observe 1–2 days. Legacy env remains authoritative; revert by reverting code.

### Step 3 — UI cutover

`/admin/ai`, `/admin/pipeline`, etc. read from `/api/admin/config?scope=…` and `prompt_templates`. Existing `/portal/ai-manage` redirects to `/admin/ai`.

### Step 4 — env file shrink

Once each legacy env var has a confirmed DB row + working consumer:
- Comment out (keep for one release)
- Then remove
- Final `.env` ≤15 lines: secrets, boot-only

### Step 5 — Zabbix and runbook migrations

- Existing Zabbix instance config (currently scattered) → `zabbix_instances` table.
- `runbook.db` unchanged; admin UI reads the existing table.

### Step 6 — clean up old admin surfaces

- Delete `/portal/ai-manage` route (redirect one release, then remove).

## 8. Rollout strategy (within big bang)

Single project, sliced for shippability. Service-rewrite order **must match §7 Step 2** — each slice picks the next-in-list services.

### Slice 0 — Reconcile server↔local drift (prerequisite, not part of this spec)
Out of scope but required first.

### Slice 1 — Foundation (week 1)

- `admin-api` service + schema + seed loader + migration runner
- `ConfigClient` shared lib + tests
- `auth-api` extension: 8 new permissions added to `ALL_PERMISSIONS` + role-mapping seed
- Frontend constant `ALL_PERMISSIONS` in `src/lib/keep-api.ts:1786` updated
- `nginx-default.conf` adds `/api/admin/*` proxy locations
- Frontend: `admin/layout.tsx` + tab nav, no tab content yet

**Ship gate**: hit `/api/admin/config` from browser, see empty list, no breakage anywhere. Existing `/admin/users` + `/admin/roles` continue to work.

### Slice 2 — Services + Features tabs (week 1)

- `services/page.tsx`: list, status, mem/cpu, restart, logs
- `features/page.tsx`: grid of every `*_ENABLED` flag
- First consumer per §7: `health-checker` migrated to `ConfigClient`

**Ship gate** (three independent checks):
1. Restart `noc-escalation-bot` from the UI Services tab — proves docker.sock allowlist + RBAC.
2. Flip `ALERT_QA_ENABLED` in the Features tab — value appears in `admin.db.config`, audit row written, banner shows *"noc-escalation-bot not yet migrated — restart required to apply"* (noc-bot consumes this flag at boot until Slice 6).
3. Change `health-checker`'s probe interval via the Services tab's env editor — health-checker (the slice's migrated consumer) reflects the new interval within one cycle via SSE, no restart needed.

This separation makes it explicit that Slice 2 demonstrates **the admin plane** (DB+SSE+RBAC+docker.sock) and **one migrated consumer** (`health-checker`); the legacy unmigrated services pick up flag changes only on restart until their slice.

### Slice 3 — AI tab (week 2)

- Model registry + cluster endpoint editor + conflict modal
- Call-sites list, per-site editor
- Sandbox endpoint (chunked HTTP) + frontend streaming UI
- Version history + rollback
- Consumers per §7 order: `runbook-api` → `opensrs-health-api` for AI keys

**Ship gate**: change `ai.enricher.model` in UI; new model in use within 5s without restart; rollback works.

### Slice 4 — Pipeline tab (week 2–3)

- Intervals, thresholds, cluster-merge rules, severity overrides, suggested-merges queue
- Consumers per §7: `alert-state-api` → `alert-enricher` migrated

**Ship gate**: change poll interval, see new interval in enricher logs within one cycle.

### Slice 5 — Zabbix + Integrations + Runbooks (week 3–4)

- Zabbix instance CRUD + "Run setup" streaming output
- Integrations: Slack, Grafana IRM, Jira, n8n, Confluence
- Runbooks tab + Confluence bulk import + re-embed
- Consumer per §7: `auth-api` migrated (mostly session timeouts)
- **Confluence import is full re-sync each run** by default; an `?incremental=1` flag is reserved for a future enhancement.

**Ship gate**: add a new Zabbix instance via UI, click setup, see webhook configured.

### Slice 6 — Audit + RBAC polish (week 4)

- Audit log viewer + CSV export
- Per-tab permission UX in roles editor
- Conflict-detection banner
- Secret rotation timestamps + rotate endpoint
- **`audit` retention: 24 months by default**, configurable via `admin.audit.retention_days`. Older rows pruned by a nightly job (`admin-api/cron/prune_audit.py`).
- Final consumer per §7: `noc-escalation-bot` migrated

**Ship gate**: full RBAC matrix tested with Admin/SRE/Viewer roles.

### Slice 7 — Cleanup + env shrink (week 4–5)

- Drop legacy env vars
- Delete `/portal/ai-manage`
- One-page operator guide

**Ship gate**: `.env` ≤15 lines; new SRE onboards a Zabbix instance without SSH.

## 9. Risk register

| Risk | Mitigation |
|---|---|
| SSE flake | Consumers poll every 30s as belt-and-suspenders |
| admin-api down | Consumers serve last-known value; cold start uses env. No hard dependency. |
| Bad value pushed via SSE | Client validates against local schema; rejects, keeps old, logs + metric. Never crashes consumer. |
| Bad config saved | `Save` (stage) vs `Save & deploy` (push). One-click rollback. Audit log. High-stakes keys require typed confirmation (§4.4). |
| Permission misconfig locks out | `ADMIN_BYPASS_TOKEN` env escape hatch (§3.3) with audit tagging |
| Secrets leaked via API | `is_secret=1` returns `***SET***`; encrypted at rest with Fernet + HKDF(AUTH_SECRET) |
| Migration breaks a consumer | Per-service rollout with 1–2 day observation; legacy env remains until cutover |
| docker.sock RW exposure | Mounted read-only; restart endpoint uses an allowlist of container names |
| `AUTH_SECRET` rotation | Out of scope; explicit operational procedure required; separate future spec |
| Seed evolution breaks live config | Renames + deprecations supported per §3.2; validation tightening shows banner, doesn't auto-mutate |

## 10. Out of scope

- Multi-region / HA admin-api
- Config snapshot/restore across whole admin.db
- A/B testing of prompts
- External SSO (continues to use existing auth-api login)
- `AUTH_SECRET` master-key rotation (separate spec)
- Sandbox rate-limit accounting beyond what the cluster enforces upstream

## 11. Resolved decisions (previously open)

- **Sandbox rate limits**: passed through to cluster; admin-api does not add its own. If sandbox traffic harms prod, operators kill via `feature.admin.ai_sandbox` flag.
- **High-stakes key confirmation**: only `ai.cluster.endpoint` requires typed confirmation (§4.4). Other config writes are single-click on "Save & deploy".
- **Audit retention**: 24 months default, configurable.
- **Confluence import**: full re-sync each run; incremental reserved as future flag.

## 12. Open questions for implementation planning

(Items that don't block the spec but should be decided when writing the plan.)

- Exact list of every legacy env var to migrate — generated by sweeping the server and committed as part of seed file authoring during Slice 1.
- Estimated count of config keys (drives seed file size and UI density). Rough projection: 60–80 keys based on current env+compose+hardcoded sweep, but the planner should produce an exact count before estimating UI work.
- Test coverage targets per slice (the spec doesn't prescribe a percentage; the planner should set a bar consistent with the rest of UIP).
