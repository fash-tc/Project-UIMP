# Real-Time SSE Events & Runbook Relevance Feedback

**Date:** 2026-03-17
**Status:** Draft
**Author:** fash + Claude

## Overview

Two features for the UIP dashboard:

1. **Server-Sent Events (SSE)** as the backbone for all real-time state updates across the platform — replacing polling for human-interaction state (investigation, acknowledgement, incidents, escalations).
2. **Runbook relevance feedback** — thumbs up/down on remediation entries attached to alert cards, feeding back into the enricher's prompt context as soft downranking.

## 1. SSE Infrastructure

### Transport

SSE (Server-Sent Events) via a new endpoint on `alert-state-api`. One-way server-to-client push. Clients continue using REST for mutations (investigate, ack, create incident, escalate, etc.). After each mutation, the API broadcasts an SSE event to all connected clients.

- **Endpoint:** `GET /api/alert-states/events`
- **Connection model:** Clients connect via `EventSource` (native browser API, auto-reconnects)
- **Server-side:** In-memory set of response objects. On disconnect, removed. On mutation, iterate and write event to all. SSE responses include `Cache-Control: no-store` and `X-Accel-Buffering: no` headers.
- **Fallback:** 60s polling as safety net in case SSE disconnects silently. The frontend `refreshInterval` default changes from 30s to 60s.
- **Keep alerts (new alerts from Zabbix):** Still polled every 30s from Keep API. SSE only covers human-interaction state.

### Server Threading Model

The current `alert-state-api` uses Python's `http.server.HTTPServer` which is single-threaded. SSE requires holding connections open indefinitely, which would block all other requests.

**Fix:** Switch to `ThreadingHTTPServer` (Python 3.7+ stdlib). This allows SSE connections to be held on separate threads while REST requests continue to be served concurrently.

Thread safety considerations:
- `_db_lock` (existing) already guards SQLite access — no changes needed.
- The SSE client set (in-memory set of response objects) requires its own `threading.Lock` for safe concurrent iteration/add/remove.
- Broadcast function acquires the SSE lock, iterates clients, writes events. Dead connections caught via try/except on write, removed from set.

### Nginx Configuration

The existing `location /api/alert-states` prefix block in nginx proxies to port 8092. A new more-specific block for the SSE path must be added. Because nginx matches by longest prefix, `/api/alert-states/events` will match before `/api/alert-states` regardless of block ordering. However, the SSE block needs different proxy settings (buffering off, long timeout):

```nginx
location /api/alert-states/events {
    proxy_pass http://alert-state-api:8092/api/alert-states/events;
    proxy_buffering off;
    proxy_set_header Connection '';
    proxy_http_version 1.1;
    chunked_transfer_encoding off;
    proxy_read_timeout 86400s;
}
```

### Event Format

All events include an `id:` field (monotonic counter) for reconnection support. On reconnect, `EventSource` sends `Last-Event-ID` header. The server maintains a small ring buffer (last 100 events) and replays missed events on reconnect. If the requested `Last-Event-ID` is not found in the buffer, the server sends `event: reset` with `data: {}` — the client responds by doing a full refetch of alert states. Max SSE client connections capped at 50 (returns 503 if exceeded).

```
id: 42
event: state_change
data: {"type": "<event_type>", "fingerprint": "abc123", ...fields, "timestamp": "ISO8601"}
```

**Event types and their payloads:**

| Type | Additional Fields |
|------|-------------------|
| `investigate` | `user`, `active` (bool) |
| `acknowledge` | `user`, `fingerprints` (array) |
| `unacknowledge` | `fingerprints` (array) |
| `mark_updated` | `fingerprints` (array) |
| `force_enrich` | `fingerprint` |
| `incident_created` | `user`, `jira_key`, `jira_url` |
| `escalated` | `user`, `escalated_to` |
| `runbook_feedback` | `user`, `entry_id`, `vote` ("up"/"down"/"none") |

**Batch operations:** When a mutation affects multiple alerts (e.g., acknowledging 20 alerts), a single SSE event is sent with a `fingerprints` array — not one event per alert.

### New API Endpoints

Added to `alert-state-api`:

- `GET /api/alert-states/events` — SSE stream (supports `Last-Event-ID` header for replay)
- `GET /api/alert-states/sse-status` — Returns `{"connected_clients": N}` for monitoring
- `POST /api/alert-states/incident` — Store Jira incident link on an alert
- `POST /api/alert-states/escalation` — Store escalation target on an alert
- `POST /api/alert-states/runbook-feedback` — Store thumbs up/down vote (vote `"none"` deletes the row)
- `GET /api/alert-states/runbook-feedback?entry_ids=1,2,3` — Fetch feedback for specific runbook entry IDs

Existing mutation endpoints (investigate, acknowledge, unacknowledge, mark-updated, force-enrich) are updated to broadcast SSE events after writing to the database.

## 2. Database Schema Changes

### Additions to `alert_states` table

```sql
-- New columns on existing table:
incident_jira_key TEXT,        -- e.g. "OCCIR-456"
incident_jira_url TEXT,        -- full Jira URL
incident_created_by TEXT,      -- username who created it
incident_created_at TEXT,      -- ISO timestamp
escalated_to TEXT,             -- team/schedule name from Grafana OnCall
escalated_by TEXT,             -- username who escalated
escalated_at TEXT              -- ISO timestamp
```

### New table: `runbook_feedback`

```sql
CREATE TABLE IF NOT EXISTS runbook_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_fingerprint TEXT NOT NULL,
    alert_name TEXT NOT NULL,
    runbook_entry_id INTEGER NOT NULL,
    vote TEXT NOT NULL,            -- "up" or "down"
    user TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(alert_fingerprint, runbook_entry_id, user)
);
CREATE INDEX IF NOT EXISTS idx_feedback_entry_id ON runbook_feedback(runbook_entry_id);
```

The UNIQUE constraint allows one vote per user per runbook entry per alert. Upsert on conflict to allow changing votes. Vote value `"none"` sent from frontend triggers a DELETE instead of upsert (removes the vote).

The `runbook_entry_id` references the `id` column in `runbook-api`'s `runbook_entries` table. No foreign key enforcement across databases — orphaned feedback rows from deleted runbook entries are harmless (they won't match any future entry IDs). The `alert_name` column is stored for debugging/inspection but is not queried — all feedback lookups use `runbook_entry_id`.

Feedback stored in `alert-state-api` (not `runbook-api`) because it's per-alert state and alert-state-api is the SSE hub — avoids cross-service event coordination.

## 3. Frontend Changes

### SSE Client Hook: `useSSE`

New React hook managing the EventSource lifecycle:

```typescript
function useSSE(url: string, onEvent: (event: SSEEvent) => void): { connected: boolean }
```

- Connects on mount, disconnects on unmount
- Auto-reconnects (native EventSource behavior, with `Last-Event-ID` for replay)
- Calls `onEvent` for each `state_change` event
- Returns connection status for optional UI indicator

### State Flow Change

**Before:**
```
setInterval(30s) → fetchAlerts() + fetchAlertStates() → setState
```

**After:**
```
Initial load → fetchAlerts() + fetchAlertStates() → setState
SSE events  → patch local alertStates incrementally (no full refetch)
Fallback    → 60s poll does full refetch as safety net (changed from 30s default)
Keep alerts → 30s poll for new alerts from Zabbix (unchanged)
```

User actions POST to REST as before. The API writes to DB, broadcasts SSE. All clients (including the actor) update via SSE.

### Frontend Orchestration: Incident & Escalation

Currently the alert detail page calls `createJiraIncident()` (via runbook-api) and `escalateAlert()` (via escalation-api) directly. These existing flows are preserved. After each succeeds, the frontend makes an additional call to store the reference in alert-state-api:

1. **Incident:** `createJiraIncident()` returns `{ key, url }` → frontend then calls `POST /api/alert-states/incident` with `{ fingerprint, jira_key, jira_url, user }` → API stores it and broadcasts SSE.
2. **Escalation:** `escalateAlert()` returns success → frontend then calls `POST /api/alert-states/escalation` with `{ fingerprint, escalated_to, user }` → API stores it and broadcasts SSE.

This is a sequential two-step from the frontend. If the first call succeeds but the second fails, the action still happened (Jira ticket exists / escalation sent) — the alert-state-api call is best-effort for visibility. No rollback needed.

### TypeScript Type Updates

The `AlertState` type in `deploy/sre-frontend/src/lib/types.ts` must be extended with the new fields:

```typescript
interface AlertState {
  // ... existing fields ...
  incident_jira_key?: string;
  incident_jira_url?: string;
  incident_created_by?: string;
  incident_created_at?: string;
  escalated_to?: string;
  escalated_by?: string;
  escalated_at?: string;
}
```

### UI Display: Alert Row

All new indicators are inline badges within the existing alert row. No new rows, no expanding sections, no layout shift.

**Visual ordering:**
```
[severity badge] Alert Name [investigating icon] [incident badge] [escalation badge]  |  host  |  time ago
```

**Incident badge:**
- Appears when `incident_jira_key` exists on the alert state
- Small inline linked icon with Jira key, e.g. a link icon + `OCCIR-456`
- Clickable — opens Jira URL
- Tooltip: "Created by fash, 2 min ago"
- Same visual weight as the existing investigation icon

**Escalation indicator:**
- Appears when `escalated_to` exists
- Small inline indicator after incident badge, e.g. arrow icon + `SRE-Primary`
- Tooltip: "Escalated by fash, 1 min ago"

**Badges use CSS transitions (200ms fade-in) for smooth appearance. No flash, no toast, no notification banner.**

Icons/badges only render when data exists — no empty space reserved.

### UI Display: Runbook Feedback (Alert Detail Page)

On the RunbookPanel where remediation entries are listed:

- Thumbs-up / thumbs-down icon pair inline with each runbook entry
- Clicking sends vote via `POST /api/alert-states/runbook-feedback` (with the entry's `id` from runbook-api as `runbook_entry_id`)
- Selected thumb highlighted, other dimmed
- Pre-highlighted on load if user already voted (fetched via `GET /api/alert-states/runbook-feedback?entry_ids=...`)
- Clicking same thumb again sends `vote: "none"` which removes the vote
- Downvoted entries get slightly muted styling (reduced opacity) but remain visible
- No confirmation dialogs

SSE broadcasts the vote so other users viewing the same alert detail page see feedback updates in real time.

## 4. Enricher Integration

### Runbook Feedback in Enrichment Prompt

During `build_enrichment_prompt()`, after fetching runbook matches from `/api/runbook/match`, the enricher collects the matched entry IDs and makes one additional call:

```
GET /api/alert-states/runbook-feedback?entry_ids=1,2,3
```

This queries by `runbook_entry_id` (not by alert name), which is the correct semantic — "has this runbook entry been rated?" rather than "has this alert name been rated?" This catches feedback from all alerts that matched the same runbook entry, regardless of alert name variations.

Returns all feedback rows for those entry IDs. The enricher aggregates votes per entry (sum of up=+1, down=-1) and partitions:

- **Net positive votes:** Included in prompt as high-confidence remediation (same as current behavior)
- **Net negative votes:** Included as negative context in prompt: *"Note: the following remediations were previously marked as irrelevant by SREs for similar alerts: [entry text]. Do not recommend these."*
- **No votes:** Included as-is (unrated, same as current behavior)

No changes to the Modelfile or system prompt. Feedback context injected into the user prompt alongside existing runbook matches — same pattern as SRE feedback corrections.

## 5. Files Modified

| File | Change |
|------|--------|
| `deploy/alert-state-api/alert-state-api.py` | Switch to `ThreadingHTTPServer`, SSE endpoint with event IDs + replay buffer, incident/escalation/feedback endpoints, SSE broadcast on all mutations, schema migration, SSE status endpoint |
| `deploy/sre-frontend/src/app/command-center/page.tsx` | Replace polling with useSSE, incremental state patching, fallback poll at 60s |
| `deploy/sre-frontend/src/app/command-center/DashboardView.tsx` | Incident badge, escalation badge in alert rows |
| `deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx` | Same badges in table rows |
| `deploy/sre-frontend/src/app/alerts/[fingerprint]/page.tsx` | Call `POST /api/alert-states/incident` after Jira creation, call `POST /api/alert-states/escalation` after escalation, pass state to RunbookPanel |
| `deploy/sre-frontend/src/components/RunbookPanel.tsx` (or equivalent) | Thumbs up/down UI, fetch/display vote state, send feedback via API |
| `deploy/sre-frontend/src/hooks/useSSE.ts` | New file — SSE client hook |
| `deploy/sre-frontend/src/lib/api.ts` (or equivalent) | New API functions for incident, escalation, feedback endpoints |
| `deploy/sre-frontend/src/lib/types.ts` | Extend `AlertState` type with incident/escalation fields |
| `deploy/enricher.py` | Fetch runbook feedback by entry IDs, partition runbooks by vote, include in prompt |
| `deploy/nginx/default.conf` (server config) | SSE proxy config for events endpoint |

## 6. Out of Scope

- WebSocket (SSE is sufficient for one-way push)
- Real-time push for new alerts from Zabbix/Keep (still polled)
- Hard-blocking runbook entries based on feedback (future enhancement)
- Incident lifecycle management (close/update from UIP — Jira is source of truth)
- Escalation status polling from Grafana OnCall (store at escalation time only)
- CORS headers (all traffic proxied through same-origin nginx, not needed)
