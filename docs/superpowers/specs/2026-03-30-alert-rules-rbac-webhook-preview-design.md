# UIP: Alert Rules Engine, RBAC, Time Sort, Webhook Preview

**Date:** 2026-03-30
**Author:** fash + Claude

## Context

UIP currently gives SREs limited control over alert flow and display. Silence rules exist but there's no way to auto-act on alerts based on payload content, no way to visually highlight critical alert sources, and no role-based access control. The webhook system was recently added but lacks end-to-end testing tooling. These features aim to give users maximum control over how alerts are displayed, routed, and acted upon.

---

## Feature 1: Alert Rules Engine (Routing + Highlighting)

### Overview

A unified rules system where users define conditions against alert payloads and attach either automated actions (routing) or visual treatments (highlighting). Managed from a single "Alert Rules" page with two tabs.

### Data Model

**`alert_rules` table** (alert-state-api SQLite):

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| name | TEXT | User-given rule name |
| rule_type | TEXT | `'routing'` or `'highlight'` |
| conditions_json | TEXT | JSON condition tree |
| expression_text | TEXT | Human-readable expression string |
| action | TEXT | Routing only: `'auto_ack'`, `'auto_resolve'`, `'auto_silence'`, `'auto_escalate'` |
| action_params | TEXT | JSON — e.g. `{"team": "sre-oncall"}` for escalate, `{"duration": "2h"}` for silence |
| color | TEXT | Highlight only: tailwind color or hex |
| label | TEXT | Highlight only: badge text |
| priority | INTEGER | Evaluation order (lower = first) |
| enabled | INTEGER | 0/1 |
| created_by | TEXT | Username |
| created_at | TEXT | ISO timestamp |

### Condition Format

The visual builder produces a JSON condition tree. Supported fields include all alert payload fields (`hostname`, `name`, `severity`, `source`, `description`, `tags`, `zabbixInstance`, `note`, `status`) **plus** a special `payload` pseudo-field that searches across all fields concatenated (entire payload text search).

```json
{
  "AND": [
    {"field": "hostname", "op": "contains", "value": "dns"},
    {"field": "payload", "op": "contains", "value": "radix"},
    {"field": "severity", "op": ">=", "value": "high"}
  ]
}
```

**Operators:** `equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`, `regex`, `>=`, `<=`, `>`, `<`
**Logical:** `AND`, `OR` (nestable)

**Severity ordinal mapping** (for comparison operators): `critical=5, high=4, warning=3, low=2, info=1, unknown=0`. Unknown/null field values evaluate to empty string for string ops, 0 for numeric ops.

**Regex validation:** Invalid regex patterns are rejected at rule creation time (400 error). During evaluation, regex errors are caught and treated as non-match.

**Priority tiebreaker:** Lower priority number evaluates first. On tie, lower `id` wins.

### Condition Evaluator

Recursive function `evaluate_condition(alert, condition)`:
- If condition has `AND` key: all children must match
- If condition has `OR` key: at least one child must match
- Leaf node `{"field", "op", "value"}`: extract field from alert (or concatenate all fields for `payload`), apply operator, return bool
- For `>=`/`<=`/`>`/`<` on `severity` field: map both sides to ordinal, compare numerically
- For string ops: case-insensitive by default

### Evaluation

- **Routing rules**: Evaluated in the enricher (`deploy/enricher.py`) after each poll cycle. Enricher fetches active routing rules from alert-state-api, evaluates each firing alert against them in priority order (first match wins), then calls the appropriate action endpoint (ack, resolve, silence, escalate).
- **Re-evaluation guard**: The enricher maintains an in-memory set of `(rule_id, fingerprint)` tuples for rules already acted on. Cleared when the alert resolves or when the rule is modified/disabled. If a user manually overrides a routing action (e.g. un-acks an auto-acked alert), the `(rule_id, fingerprint)` entry is NOT cleared — the manual override is respected until the alert resolves and re-fires.
- **Highlighting rules**: Fetched by the frontend on page load. Evaluated client-side against each alert. Applied as a colored left border + label badge on both DashboardView and AlertsTableView.

### Expression Builder UI

Visual builder with rows:
1. Each row: field dropdown (includes "Entire Payload") → operator dropdown → value input
2. AND/OR toggle between rows
3. Add/remove condition rows
4. Read-only text field below shows generated expression
5. Toggle to reveal raw text for direct editing by advanced users

### API Endpoints (alert-state-api)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/alert-states/rules` | List all rules (optional `?type=routing\|highlight`) |
| POST | `/api/alert-states/rules` | Create rule |
| PUT | `/api/alert-states/rules/:id` | Update rule |
| DELETE | `/api/alert-states/rules/:id` | Delete rule |

### Frontend

- **New page:** `/portal/alert-rules` (`deploy/sre-frontend/src/app/alert-rules/page.tsx`)
- **Nav link:** "Alert Rules" in Settings dropdown (`deploy/sre-frontend/src/app/layout.tsx`)
- **Two tabs:** Routing Rules, Highlighting Rules
- Each tab: table of rules (Name, Expression, Action/Color, Priority, Enabled toggle, Edit/Delete) + "Add Rule" button

### Files to modify/create

- `deploy/alert-state-api/alert-state-api.py` — new table, CRUD endpoints
- `deploy/enricher.py` — fetch rules, evaluate routing rules after each poll
- `deploy/sre-frontend/src/app/alert-rules/page.tsx` — new page
- `deploy/sre-frontend/src/lib/keep-api.ts` — API functions for rules CRUD
- `deploy/sre-frontend/src/lib/types.ts` — `AlertRule` interface
- `deploy/sre-frontend/src/app/layout.tsx` — nav link
- `deploy/sre-frontend/src/app/command-center/DashboardView.tsx` — apply highlight rules
- `deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx` — apply highlight rules

---

## Feature 2: User Management + RBAC

### Overview

Full role-based access control with custom roles. Admins can create named roles with granular permission sets, manage users, and assign roles. Frontend hides UI elements based on permissions; backend enforces on every endpoint.

### Data Model

**`roles` table** (auth-api SQLite):

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| name | TEXT UNIQUE | Role name |
| description | TEXT | Purpose of role |
| is_system | INTEGER | 1 = seeded (can't delete/rename), 0 = custom |
| created_by | TEXT | Username |
| created_at | TEXT | ISO timestamp |

**`role_permissions` table**:

| Column | Type | Description |
|--------|------|-------------|
| role_id | INTEGER FK | References roles.id |
| permission | TEXT | Permission key string |

**Seeded permissions:**

| Permission | Description | Admin | SRE | Viewer |
|------------|-------------|-------|-----|--------|
| `view_dashboard` | See Dashboard tab | yes | yes | yes |
| `view_alerts` | See All Alerts tab | yes | yes | yes |
| `view_knowledge_base` | See Knowledge Base tab | yes | yes | no |
| `ack_alerts` | Acknowledge/unacknowledge | yes | yes | no |
| `resolve_alerts` | Resolve/unresolve | yes | yes | no |
| `silence_alerts` | Create/cancel silence rules | yes | yes | no |
| `investigate_alerts` | Toggle investigating | yes | yes | no |
| `escalate_alerts` | Escalate to teams/users | yes | yes | no |
| `create_tickets` | Create Jira tickets | yes | yes | no |
| `create_incidents` | Use incident wizard | yes | yes | no |
| `override_severity` | Override severity | yes | yes | no |
| `manage_routing_rules` | CRUD routing rules | yes | yes | no |
| `manage_highlight_rules` | CRUD highlighting rules | yes | yes | no |
| `manage_webhooks` | Manage webhook subscribers | yes | yes | no |
| `manage_users` | CRUD users, assign roles | yes | no | no |
| `manage_roles` | CRUD roles, edit permissions | yes | no | no |
| `view_settings` | Access settings page | yes | yes | yes |
| `view_webhooks` | View webhook page (read-only) | yes | yes | no |
| `view_admin` | Access admin page | yes | no | no |

**`users` table changes:** Add `role_id INTEGER DEFAULT 2` (FK to roles). Migration: `fash` → role_id=1 (Admin), all others → role_id=2 (SRE).

### Auth Flow Changes

**Cross-service permission enforcement:** Permissions are embedded in the auth token. When auth-api issues a token (login or refresh), it includes the user's permission list in the signed payload: `{ username, permissions: [...], role_id, exp }`. All services already verify the HMAC signature — they now also read `permissions` from the decoded payload. When an admin changes a user's role, the affected user's token is invalidated (auth-api maintains an `invalidated_tokens` set checked on verification), forcing re-login with fresh permissions.

- `GET /api/auth/me` returns `{ ...user, role: { id, name }, permissions: ['view_dashboard', ...] }`
- Backend: each endpoint reads `permissions` from the verified token payload, returns 403 if the required permission is missing
- Frontend: `AuthProvider` context wraps the app in `layout.tsx`. On mount, calls `/api/auth/me` to load user profile + permissions. Exposes `useAuth()` hook returning `{ user, permissions, hasPermission(p) }`. Components use `hasPermission()` to conditionally render UI elements.

### API Endpoints (auth-api)

| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/auth/users` | `manage_users` |
| POST | `/api/auth/users` | `manage_users` |
| PUT | `/api/auth/users/:id` | `manage_users` |
| DELETE | `/api/auth/users/:id` | `manage_users` |
| GET | `/api/auth/roles` | `manage_roles` |
| POST | `/api/auth/roles` | `manage_roles` |
| PUT | `/api/auth/roles/:id` | `manage_roles` |
| DELETE | `/api/auth/roles/:id` | `manage_roles` (non-system only) |
| PUT | `/api/auth/roles/:id/permissions` | `manage_roles` |

### Frontend: Admin Page (`/portal/admin`)

Two tabs: **Users** and **Roles**.

**Users tab:** Table — Username, Display Name, Role (dropdown), Created At, Edit/Delete. "Add User" form: username, display name, password, role dropdown. Guards: can't delete yourself, can't delete last Admin.

**Roles tab:** Table — Name, Description, System badge, # Users, Edit/Delete. "Add Role" form: name, description, permission checklist grouped by category. System roles: permissions editable, can't delete/rename.

**Role deletion guard:** Cannot delete a role that has users assigned. UI shows user count per role; delete button is disabled with tooltip "Reassign N users before deleting" if count > 0. Backend returns 409 if attempted.

### Files to modify/create

- `deploy/auth-api/auth-api.py` — new tables, migration, CRUD endpoints, permission checks, token invalidation
- `deploy/alert-state-api/alert-state-api.py` — read permissions from token payload for endpoint enforcement
- `deploy/runbook-api/runbook-api.py` — read permissions from token payload for endpoint enforcement; upgrade to `ThreadingHTTPServer`
- `deploy/sre-frontend/src/app/admin/page.tsx` — new Admin page
- `deploy/sre-frontend/src/lib/keep-api.ts` — user/role management API functions
- `deploy/sre-frontend/src/lib/types.ts` — `Role`, `Permission`, updated `User` interface
- `deploy/sre-frontend/src/lib/auth.ts` — `AuthProvider` context + `useAuth()` hook
- `deploy/sre-frontend/src/app/layout.tsx` — wrap app in AuthProvider, conditional nav based on permissions
- `deploy/sre-frontend/src/app/command-center/page.tsx` — hide action buttons based on permissions
- `deploy/sre-frontend/src/app/command-center/DashboardView.tsx` — hide action buttons based on permissions

---

## Feature 3: Sort by Time Received

### Changes

- **AlertsTableView.tsx**: Add "Received" as a sortable column using `alert.lastReceived`. Sort by parsed ISO timestamp, default descending.
- **Alert detail panel** (page.tsx): Add "Received" field showing formatted `lastReceived` timestamp alongside existing "Started" time.

### Files to modify

- `deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx`
- `deploy/sre-frontend/src/app/command-center/page.tsx`

---

## Feature 4: Webhook Customer Preview + Test Receiver

### Overview

A real webhook receiver endpoint built into UIP for end-to-end testing. Combined with a "Customer Preview" tab in the Webhooks page that renders received payloads as a customer dashboard would display them, plus a raw payload inspector.

### Test Receiver Endpoint (runbook-api)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/runbook/webhook-test/receive` | Catches incoming webhooks, validates HMAC signature, stores in ring buffer (last 50) |
| GET | `/api/runbook/webhook-test/deliveries` | Returns all caught deliveries with full payload, headers, signature verification |
| DELETE | `/api/runbook/webhook-test/deliveries` | Clears the buffer |

**Stored per delivery:**
- Full request headers
- Raw JSON body
- `X-Webhook-Signature` header value
- Signature verification result (pass/fail)
- Timestamp received
- HTTP status returned

The test endpoint URL is available via nginx at `/api/runbook/webhook-test/receive`.

### Test Subscriber Auto-Registration

On the Customer Preview tab, a "Register Test Endpoint" button calls `createWebhookSubscriber("UIP Test Receiver", "/api/runbook/webhook-test/receive")` on the external maintenance dashboard API. This creates a real subscriber pointing at UIP's test receiver. The subscriber is created on-demand, not pre-seeded, since the subscriber registry lives on the external maintenance dashboard (10.177.154.174).

### Test Flow

1. User goes to Customer Preview tab → clicks "Register Test Endpoint" (one-time setup, button hidden once registered)
2. User clicks "Test" on the test subscriber in the Subscribers tab → webhook fires through the real pipeline (HMAC-signed, HTTP POST, retries)
3. User switches to **"Customer Preview"** tab → sees the result

### Customer Preview Tab (4th tab in Webhooks page)

Two panels side by side:

**Left — Customer View:** Rendered mock maintenance dashboard (light theme, clean layout) showing:
- Active incidents: title, description, started_at, status badge, last updated
- Active maintenance: scheduled windows, affected components, status
- Built from actual received webhook payloads

**Right — Raw Inspector:** Collapsible sections per delivery showing:
- Full headers received
- Raw JSON body
- Signature header value + verification result (pass/fail with checkmark/x)
- Timestamp received

"Clear" button to reset test buffer. "Send Test Incident" button to fire a sample through the pipeline directly from this tab. Auto-refreshes on new deliveries.

### Webhook Independence

UIP sends webhooks directly from runbook-api — Grafana is not involved. The `X-Grafana-Secret` header name is just a convention from the external maintenance dashboard system.

### Threading Prerequisite

runbook-api currently uses single-threaded `HTTPServer`. Since the test flow involves runbook-api receiving a webhook at its own endpoint (loopback via nginx), it must be upgraded to `ThreadingHTTPServer` to avoid deadlock. This is also done as part of Feature 2 (RBAC) since permission checks may call auth-api.

### Files to modify/create

- `deploy/runbook-api/runbook-api.py` — upgrade to ThreadingHTTPServer, test receiver endpoints + in-memory ring buffer
- `deploy/sre-frontend/src/app/webhooks/page.tsx` — add Customer Preview tab
- `deploy/sre-frontend/src/lib/keep-api.ts` — API functions for test receiver

---

## Verification

### Alert Rules Engine
1. Create a routing rule via UI (e.g. `hostname contains 'test' → auto_ack`)
2. Trigger/simulate an alert matching the condition
3. Confirm the enricher auto-acknowledges it
4. Create a highlighting rule (e.g. `payload contains 'radix' → red border + "RADIX" label`)
5. Confirm alerts matching show the colored border and label on dashboard

### RBAC
1. Log in as fash (Admin) → verify Admin page visible, all actions available
2. Create a custom role with limited permissions
3. Create a test user with Viewer role → log in as them → verify restricted UI
4. Edit role permissions → verify changes take effect on next page load
5. Verify backend returns 403 for unauthorized actions

### Time Sort
1. Go to All Alerts → click "Received" column header → verify sort order
2. Click an alert → verify "Received" timestamp shown in detail panel

### Webhook Preview
1. Go to Webhooks → confirm "UIP Test Receiver" subscriber exists
2. Click "Test" on it → switch to Customer Preview tab
3. Verify left panel shows rendered incident, right panel shows raw payload + signature verification
4. Click "Send Test Incident" from preview tab → confirm it appears
5. Click "Clear" → confirm buffer emptied
