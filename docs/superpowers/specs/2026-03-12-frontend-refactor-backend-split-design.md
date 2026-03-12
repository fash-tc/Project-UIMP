# UIP Frontend Refactor & Backend Split Design

**Date**: 2026-03-12
**Status**: Draft
**Scope**: Frontend page consolidation, backend service decomposition, Loki re-enablement, cleanup

## Overview

Five coordinated changes to the UIP platform:

1. **Merge Alerts page into Command Center** as a tabbed view
2. **Rename Registry Contacts to Registry** and add on-demand Loki trends
3. **Re-enable Logs page** with Loki integration
4. **Decompose runbook-api monolith** into focused services
5. **Remove Zabbix poller** (replaced by webhooks) and other cleanup

## Constraint: No Automatic Loki Queries

**All Loki/log queries must be user-initiated.** The Loki infrastructure is currently unstable. No automatic polling, no scheduled health checks, no periodic fetches against Loki. This applies to:

- Registry health polling — disabled
- Registry trends — on-demand only (already designed this way)
- Logs page — manual query only (already designed this way)
- Log context for alerts — fetched only when user opens alert detail

This constraint can be lifted once the Loki setup is stable.

## 1. Backend Decomposition

### Current State

`runbook-api.py` is a 1291-line monolith handling 7 unrelated domains: runbook entries, AI instructions, Loki/registry health, alert states, authentication, Jira integration, and the HTTP framework. All share a single SQLite database and process.

### Target Architecture

Split into 4 focused services. Each is a single-file Python HTTP server (same pattern as today), with its own container in docker-compose.

| Service | Port | Owns | Endpoints |
|---------|------|------|-----------|
| **runbook-api** (slimmed) | 8090 | Runbook entries, AI instructions, AI feedback, Jira integration | `/api/runbook/match`, `/api/runbook/entries`, `/api/runbook/ai-instructions`, `/api/runbook/ai-feedback-summary`, `/api/runbook/jira/*` |
| **loki-gateway** | 8091 | Loki queries, registry health polling, log-context, trends | `/api/loki/registry-health`, `/api/loki/log-context`, `/api/loki/logs/query`, `/api/loki/registry-trends` |
| **alert-state-api** | 8092 | Alert investigation, acknowledgment, state tracking | `/api/alert-states`, `/api/alert-states/investigate`, `/api/alert-states/acknowledge`, `/api/alert-states/unacknowledge`, `/api/alert-states/mark-updated` |
| **auth-api** | 8093 | Login, logout, password management, token verification | `/api/auth/login`, `/api/auth/logout`, `/api/auth/change-password`, `/api/auth/me`, `/api/auth/jira-config` |

### Design Decisions

- **Jira stays in runbook-api**: Incident creation is triggered from alert context alongside runbook data. Splitting it would require cross-service calls for no benefit.
- **Auth token verification**: Each service shares the `AUTH_SECRET` environment variable and validates tokens locally using the same HMAC-based logic currently in runbook-api. This avoids adding latency and a hard dependency on auth-api for every request. Auth-api owns user management (login, logout, password changes); other services only need the shared secret to verify tokens.
- **Shared SQLite considerations**: Today everything uses one `runbook.db`. After the split, each service gets its own DB file. The auth-api owns `auth.db` (users table), alert-state-api owns `alert-states.db`, runbook-api keeps `runbook.db` (entries, ai-instructions, feedback tables). Loki-gateway is stateless (queries Grafana/Loki directly).
- **API path migration**: Endpoints are moving from a single `/api/runbook/*` prefix to service-specific prefixes (`/api/loki/*`, `/api/alert-states/*`, `/api/auth/*`). This is a breaking change to frontend call paths. See the Path Migration Map and Updated Files sections below for the full list of files that need updating.

### New Endpoint: Registry Trends

Added to loki-gateway:

```
GET /api/loki/registry-trends?operator={id}&range={hours}
```

Returns hourly buckets for the requested operator:

```json
{
  "operator": "verisign",
  "range_hours": 24,
  "buckets": [
    {
      "timestamp": "2026-03-12T00:00:00Z",
      "avg_response_ms": 245,
      "error_rate": 0.02,
      "request_count": 1430
    }
  ]
}
```

This is **on-demand only** — no auto-polling, no caching. The frontend calls it when a user explicitly clicks "View Trends" in the registry detail modal. Range options: 6h, 24h, 7d.

### Path Migration Map

All current endpoints live under `/api/runbook/*`. The split moves them to service-specific prefixes:

| Old Path | New Path | Service |
|----------|----------|---------|
| `/api/runbook/match` | `/api/runbook/match` | runbook-api (unchanged) |
| `/api/runbook/entries` | `/api/runbook/entries` | runbook-api (unchanged) |
| `/api/runbook/ai-instructions` | `/api/runbook/ai-instructions` | runbook-api (unchanged) |
| `/api/runbook/ai-feedback-summary` | `/api/runbook/ai-feedback-summary` | runbook-api (unchanged) |
| `/api/runbook/jira/*` | `/api/runbook/jira/*` | runbook-api (unchanged) |
| `/api/runbook/registry-health` | `/api/loki/registry-health` | loki-gateway |
| `/api/runbook/log-context` | `/api/loki/log-context` | loki-gateway |
| `/api/runbook/logs/query` | `/api/loki/logs/query` | loki-gateway |
| (new) | `/api/loki/registry-trends` | loki-gateway |
| `/api/runbook/alert-states` | `/api/alert-states` | alert-state-api |
| `/api/runbook/alert-states/investigate` | `/api/alert-states/investigate` | alert-state-api |
| `/api/runbook/alert-states/acknowledge` | `/api/alert-states/acknowledge` | alert-state-api |
| `/api/runbook/alert-states/unacknowledge` | `/api/alert-states/unacknowledge` | alert-state-api |
| `/api/runbook/alert-states/mark-updated` | `/api/alert-states/mark-updated` | alert-state-api |
| `/api/runbook/auth/login` | `/api/auth/login` | auth-api |
| `/api/runbook/auth/logout` | `/api/auth/logout` | auth-api |
| `/api/runbook/auth/change-password` | `/api/auth/change-password` | auth-api |
| `/api/runbook/auth/me` | `/api/auth/me` | auth-api |
| `/api/runbook/auth/jira-config` | `/api/auth/jira-config` | auth-api |

### Nginx Routing

New location blocks in `nginx-default.conf`:

```
location /api/runbook/   → runbook-api:8090
location /api/loki/      → loki-gateway:8091
location /api/alert-states/ → alert-state-api:8092
location /api/auth/      → auth-api:8093
```

### Database Migration

Today all tables live in a single `runbook.db`. After the split:

1. **One-time migration script** (`migrate-db.sh`): Copies tables from `runbook.db` to per-service databases before starting new services. Specifically:
   - `users` table → `auth.db`
   - `alert_states` table → `alert-states.db`
   - `runbook_entries`, `ai_instructions`, `ai_feedback` tables stay in `runbook.db`
2. **Startup order**: auth-api and alert-state-api check for their DB files on startup and run `init_db()` if missing (same pattern as current runbook-api). Migration script runs first via docker-compose `depends_on` or an entrypoint wrapper.
3. **Rollback**: Keep the original `runbook.db` as a backup. The migration is additive (copies, not moves). If the split fails, revert to the monolith container with the original DB intact.

### Docker Compose Changes

- **Add**: `loki-gateway`, `alert-state-api`, `auth-api` containers (all `python:3.12-slim`)
- **Add**: Named volumes `auth_data:/data` for auth-api, `alert_state_data:/data` for alert-state-api
- **Add**: `AUTH_SECRET` env var shared across runbook-api, loki-gateway, alert-state-api, auth-api for token verification
- **Remove**: `zabbix-poller` service (webhooks replaced polling)
- **Update**: `runbook-api` volume/env to reflect slimmed scope
- **Update**: `alert-enricher` env — audit which endpoints it calls and update `RUNBOOK_API_URL` if any moved to new services

## 2. Command Center — Tabbed Dashboard + Alerts

### Current State

Two separate pages with overlapping data:
- **Command Center** (`/portal/command-center`): Stats, charts, 30 recent alerts. Fetches 100 alerts.
- **Alerts** (`/portal/alerts`): Full searchable/sortable table. Fetches 250 alerts.

### Design

Merge into a single page with a tab bar: **Dashboard | All Alerts**

#### Tab Bar

Styled consistently with existing Active/Acknowledged patterns in the codebase. Horizontal tabs below the page header, pill/underline style.

#### Dashboard Tab (default)

Current command center content, extracted into `DashboardView.tsx`:
- 5 stat cards (Active, Critical, High, Warning, Likely Noise)
- Severity breakdown chart (interactive filtering)
- Active alerts by source chart
- Recent alerts table (top 30 preview)

#### All Alerts Tab

Full alert explorer, extracted into `AlertsTableView.tsx`:
- Search input (name, host, AI summary)
- Severity dropdown filter
- Status dropdown filter (Active / Resolved / All)
- Sortable columns (severity, name, host, noise, time)
- Full result count
- All alerts displayed (up to 250)

#### Shared Data

Both tabs share a single `fetchAlerts(250)` call with 30-second auto-refresh. No duplicate API calls — data is fetched once in the parent `page.tsx` and passed to whichever view is active.

**Note**: The current Command Center fetches only 100 alerts. This increases to 250 to support the All Alerts tab. This is a deliberate tradeoff — the Dashboard tab only displays 30, but the shared fetch avoids a jarring re-fetch when switching tabs. The 30-second refresh interval remains unchanged.

#### File Structure

```
command-center/
  page.tsx              # Data fetching, tab state, renders active view
  DashboardView.tsx     # Stats, charts, recent alerts preview
  AlertsTableView.tsx   # Full searchable/sortable alert table
```

#### Removed

- `alerts/page.tsx` — deleted
- `alerts/[fingerprint]/page.tsx` — stays as-is, route `/portal/alerts/{fingerprint}` unchanged. All alert links in both DashboardView and AlertsTableView continue to point to this route.
- Nav link "Alerts" removed from `layout.tsx`

## 3. Registry Page (renamed from Registry Contacts)

### Route Change

`/portal/registry-contacts` → `/portal/registry`

### File Changes

- `src/app/registry-contacts/` → `src/app/registry/`
- `src/lib/registry-contacts.ts` → `src/lib/registry.ts`
- Page title: "Registry Contacts" → "Registry"
- Nav link updated in `layout.tsx`

### Registry Data Deduplication

**Problem**: Identity Digital has 3-4 separate operator entries with overlapping TLDs:
- `identity-digital` — .info, .asia, .bz, .in, .co.in, .mobi, .me (with per-TLD contacts)
- `identity-digital-me` — .me (duplicate)
- `identity-digital-mobi` — .mobi (duplicate)
- `afilias-au` — .au (may be separate ops team)

**Fix**:
1. Merge `identity-digital-me` and `identity-digital-mobi` into the main `identity-digital` entry. The main entry already has per-TLD contacts for .ME and .MOBI, so the dedicated entries are pure duplicates.
2. Keep `afilias-au` separate for now — .AU likely has a genuinely different operations team based in Australia. Can be merged later if confirmed otherwise.
3. Update `TLD_OPERATOR_MAP`: point `.me` → `identity-digital` and `.mobi` → `identity-digital`.
4. Audit remaining operators for similar consolidation opportunities (Rightside, Minds+Machines, CentralNic are all under CentralNic Group now but may have separate ops teams — leave as-is unless confirmed).

### On-Demand Trends

New "View Trends" button in the `OperatorDetailModal`:

- Appears below the existing EPP Health Metrics section
- When clicked, calls `GET /api/loki/registry-trends?operator={id}&range={hours}`
- User selects range: 6h | 24h | 7d (pill buttons, default 24h)
- Renders an inline chart showing hourly buckets of:
  - Average response time (ms) — line
  - Error rate (%) — line, different color
  - Request count — bar (background)
- Chart is a lightweight CSS/SVG implementation (no charting library) consistent with existing codebase patterns
- Shows loading state while query runs
- **No auto-refresh** — user clicks again to refresh

### Existing Features Preserved

- Operator cards with health status, TLD badges, quick contacts
- Registry-related alerts banner with auto-detection
- Search and TLD filter
- Detail modal with contacts, EPP codes, top operations
- ~~Health polling~~ — **DISABLED** until Loki infrastructure is stable. No automatic Loki queries of any kind. All Loki interactions (trends, logs, health) are strictly manual/on-demand.

## 4. Logs Page — Re-enable

### Current State

The page (`src/app/logs/page.tsx`) is fully built with:
- LogQL query input with presets (Registry Timing, EPP Result Codes, All Registry Logs, Errors & Failures)
- Time range selection (15m, 1h, 6h, 24h)
- Configurable result limits (100, 200, 500, 1000)
- Manual query execution only (Ctrl+Enter or "Run Query" button)
- Result filtering, row expansion, line classification (error/slow/normal)

### Changes Needed

1. **Ensure Logs is a top-level nav item** in `layout.tsx` — current layout uses a dropdown menu; the redesigned nav uses flat top-level links (see Section 5, Navigation). Logs must be included as a top-level item.
2. **Update API base URL** in `keep-api.ts` to point to loki-gateway instead of runbook-api (path changes from `/api/runbook/logs/query` to `/api/loki/logs/query`)
3. **Verify presets** work with current Loki label structure (`{app="ra"}`)

### Load Protection (already in place)

- No auto-run on page load — user must explicitly click "Run Query"
- Configurable limit caps (max 1000 entries per query)
- Time range caps (max 24h)
- No auto-refresh / polling

No functional changes to the page itself.

## 5. Cleanup

### Removed Files

| File | Reason |
|------|--------|
| `deploy/poller.py` | Replaced by Zabbix webhooks |
| `deploy/sre-frontend/src/app/alerts/page.tsx` | Merged into Command Center |

### Updated Files

| File | Changes |
|------|---------|
| `deploy/docker-compose.yml` | Add loki-gateway, alert-state-api, auth-api; remove poller service; add volumes |
| `deploy/nginx-default.conf` | Add routing for new services |
| `deploy/enricher.py` | Audit and update any runbook-api endpoint calls that moved to new services |
| `deploy/sre-frontend/src/app/layout.tsx` | Redesign nav from dropdown to flat top-level links; remove Alerts, add Logs, rename Registry Contacts → Registry |
| `deploy/sre-frontend/src/lib/keep-api.ts` | Update base URLs: replace single `RUNBOOK_BASE` with per-service base URLs (`RUNBOOK_BASE`, `LOKI_BASE`, `ALERT_STATE_BASE`, `AUTH_BASE`) |
| `deploy/sre-frontend/src/app/UserMenu.tsx` | Update hardcoded `/api/runbook/auth/logout` → `/api/auth/logout` |
| `deploy/sre-frontend/src/app/login/page.tsx` | Update hardcoded `/api/runbook/auth/login` → `/api/auth/login` |
| `deploy/sre-frontend/src/app/settings/page.tsx` | Update hardcoded `/api/runbook/auth/me`, `/api/runbook/auth/change-password`, `/api/runbook/auth/jira-config` → `/api/auth/*` |
| `deploy/sre-frontend/src/lib/registry.ts` | Merge Identity Digital duplicates, update TLD map, fix `.tv` mapping (currently maps to godaddy-registry but Verisign lists it) |
| `README.md` | Reflect new architecture |

### Navigation (layout.tsx) After Changes

The current dropdown-based navigation is replaced with flat top-level links:

```
Command Center  |  Logs  |  Registry  |  Maintenance  |  Health  |  AI Manage  |  Settings
```

## Testing Strategy

1. **Backend split**: Verify each new service starts independently and responds to its endpoints. Test nginx routing for all paths.
2. **Command Center tabs**: Verify tab switching preserves data, auto-refresh works across both views, alert detail links still work.
3. **Registry dedup**: Verify Identity Digital shows as one card with all TLDs. Verify TLD filter still works for .me, .mobi.
4. **Registry trends**: Verify on-demand query returns data, chart renders, no auto-polling.
5. **Logs page**: Verify presets query Loki successfully, results render, load limits enforced.
6. **Poller removal**: Verify webhook-based alert flow is unaffected.
