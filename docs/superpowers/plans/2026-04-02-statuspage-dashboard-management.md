# Statuspage Dashboard Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dashboard Statuspage management tab that can create, view, update, and resolve Statuspage incidents from UIP, while also adding per-component degradation controls everywhere UIP posts Statuspage incidents.

**Architecture:** Extend `runbook-api` from create-only Statuspage support into a small Statuspage management surface with read and update endpoints. On the frontend, add a dedicated dashboard `Statuspage` tab and extract a shared component-status editor so both the dashboard and the existing incident wizard use the same create/update UI model.

**Tech Stack:** Python `http.server` service in `runbook-api`, Statuspage REST API via `urllib`, Next.js/React client components, TypeScript helper APIs, pytest, source-based frontend regression tests.

---

## File Structure

**Backend**

- Modify: `deploy/runbook-api/runbook-api.py`
  - add Statuspage incident listing/update helpers and HTTP routes
  - upgrade create payload mapping to support per-component statuses

**Frontend shared data**

- Modify: `deploy/sre-frontend/src/lib/types.ts`
  - expand Statuspage types for incidents, component statuses, and update payloads
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`
  - add fetch/create/update client helpers for Statuspage management

**Frontend UI**

- Create: `deploy/sre-frontend/src/app/command-center/StatuspageComponentStatusPicker.tsx`
  - shared per-component selection + degradation control
- Create: `deploy/sre-frontend/src/app/command-center/StatuspageIncidentEditor.tsx`
  - shared create/update/resolve form
- Create: `deploy/sre-frontend/src/app/command-center/StatuspageTab.tsx`
  - dashboard tab orchestration for active incidents and create flow
- Modify: `deploy/sre-frontend/src/app/command-center/IncidentWizard.tsx`
  - replace checkbox-only component picker with shared editor/picker
- Modify: `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`
  - add the new `Statuspage` dashboard tab and render the extracted tab component

**Tests**

- Create: `deploy/tests/test_statuspage_api.py`
  - backend unit coverage for incident list/create/update mapping
- Create: `deploy/tests/test_statuspage_ui_source.py`
  - regression checks for dashboard tab, component degradation controls, and resolve reminder

### Task 1: Add Backend Statuspage Management Endpoints

**Files:**
- Modify: `deploy/runbook-api/runbook-api.py`
- Test: `deploy/tests/test_statuspage_api.py`

- [ ] **Step 1: Write the failing test**

Create `deploy/tests/test_statuspage_api.py` with tests for:
- `create_statuspage_incident(...)` including both `component_ids` and Statuspage `components` status map in the outgoing payload
- `fetch_statuspage_active_incidents()` filtering out resolved incidents and returning normalized component state
- `update_statuspage_incident(...)` sending `PATCH` with resolved status plus operational component reset

Use monkeypatched `urlopen` and assert on `req.data.decode()`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_api.py -q`
Expected: three failing tests because the helper functions and update route do not exist yet.

- [ ] **Step 3: Write minimal implementation**

In `deploy/runbook-api/runbook-api.py`:
- change `create_statuspage_incident(name, body, component_ids, status, impact)` to `create_statuspage_incident(name, body, components, status, impact)`
- add `_normalize_statuspage_component_updates(components)`
- add `_build_statuspage_component_payload(components)` returning `(component_ids, component_statuses)`
- add `fetch_statuspage_active_incidents()` hitting `GET https://api.statuspage.io/v1/pages/{STATUSPAGE_PAGE_ID}/incidents`
- add `update_statuspage_incident(incident_id, name, body, status, impact, components)` hitting `PATCH .../incidents/{incident_id}`
- add `GET /api/runbook/statuspage/incidents`
- add `PATCH /api/runbook/statuspage/incidents/<id>`

Normalized incident response fields must include:
- `id`
- `name`
- `status`
- `impact`
- `shortlink`
- `updated_at`
- `components` with `id`, `name`, `status`, `description`

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_api.py -q`
Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add deploy/runbook-api/runbook-api.py deploy/tests/test_statuspage_api.py
git commit -m "feat: add statuspage incident management api"
```

### Task 2: Add Shared Frontend Statuspage Types And Client APIs

**Files:**
- Modify: `deploy/sre-frontend/src/lib/types.ts`
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`
- Test: `deploy/tests/test_statuspage_ui_source.py`

- [ ] **Step 1: Write the failing test**

Create `deploy/tests/test_statuspage_ui_source.py` with source assertions for:
- `export type StatuspageComponentStatus`
- `export interface StatuspageComponentUpdate`
- richer `StatuspageIncident` including `name`, `impact`, `updated_at`, and `components`
- `fetchStatuspageIncidents`
- `updateStatuspageIncident`
- `createStatuspageIncident` using `components: StatuspageComponentUpdate[]`

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_ui_source.py -q`
Expected: failing assertions because the new types and helpers do not exist yet.

- [ ] **Step 3: Write minimal implementation**

In `deploy/sre-frontend/src/lib/types.ts`, add:
- `StatuspageComponentStatus`
- `StatuspageComponentSummary`
- `StatuspageComponentUpdate`
- expanded `StatuspageIncident`

In `deploy/sre-frontend/src/lib/keep-api.ts`:
- change `createStatuspageIncident(...)` to accept `components: StatuspageComponentUpdate[]`
- add `fetchStatuspageIncidents()` calling `GET /api/runbook/statuspage/incidents`
- add `updateStatuspageIncident(id, data)` calling `PATCH /api/runbook/statuspage/incidents/${id}`

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_ui_source.py -q`
Expected: source assertions pass.

- [ ] **Step 5: Commit**

```bash
git add deploy/sre-frontend/src/lib/types.ts deploy/sre-frontend/src/lib/keep-api.ts deploy/tests/test_statuspage_ui_source.py
git commit -m "feat: add statuspage client types and helpers"
```

### Task 3: Extract Shared Statuspage Component And Editor UI

**Files:**
- Create: `deploy/sre-frontend/src/app/command-center/StatuspageComponentStatusPicker.tsx`
- Create: `deploy/sre-frontend/src/app/command-center/StatuspageIncidentEditor.tsx`
- Modify: `deploy/sre-frontend/src/app/command-center/IncidentWizard.tsx`
- Test: `deploy/tests/test_statuspage_ui_source.py`

- [ ] **Step 1: Extend the failing test**

Add source assertions that:
- `StatuspageComponentStatusPicker.tsx` exists
- `StatuspageIncidentEditor.tsx` exists
- `IncidentWizard.tsx` imports or references `StatuspageIncidentEditor`
- the reminder text `If service is restored, reset affected components to Operational as well.` exists in the shared editor

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_ui_source.py -q`
Expected: failing assertions for the new shared UI files.

- [ ] **Step 3: Write minimal implementation**

Create `deploy/sre-frontend/src/app/command-center/StatuspageComponentStatusPicker.tsx`:
- render component rows
- unchecked components are omitted
- checked components show a degradation dropdown with:
  - `Operational`
  - `Degraded Performance`
  - `Partial Outage`
  - `Major Outage`

Create `deploy/sre-frontend/src/app/command-center/StatuspageIncidentEditor.tsx`:
- render title, body, status, impact, and the shared picker
- support `resolving` mode
- render the inline reminder: `If service is restored, reset affected components to Operational as well.`
- accept a generic submit handler so the same editor works for create, update, and resolve

Update `IncidentWizard.tsx`:
- replace `selectedComponents: string[]` with `componentUpdates: StatuspageComponentUpdate[]`
- replace the checkbox grid with `StatuspageIncidentEditor`
- keep wizard flow the same
- call `createStatuspageIncident({ ..., components: componentUpdates })`

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_ui_source.py -q`
Expected: source assertions pass.

- [ ] **Step 5: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/StatuspageComponentStatusPicker.tsx deploy/sre-frontend/src/app/command-center/StatuspageIncidentEditor.tsx deploy/sre-frontend/src/app/command-center/IncidentWizard.tsx deploy/tests/test_statuspage_ui_source.py
git commit -m "feat: share statuspage component status editor"
```

### Task 4: Add Dashboard Statuspage Tab With Active Incident Controls

**Files:**
- Create: `deploy/sre-frontend/src/app/command-center/StatuspageTab.tsx`
- Modify: `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`
- Test: `deploy/tests/test_statuspage_ui_source.py`

- [ ] **Step 1: Extend the failing test**

Add source assertions that:
- `StatuspageTab.tsx` exists
- `DashboardView.tsx` includes a `Statuspage` tab button and `setDashboardTab('statuspage')`
- `StatuspageTab.tsx` contains `Active Incidents`
- `StatuspageTab.tsx` contains `Open in Statuspage`
- the resolve reminder text is reachable in the dashboard flow too

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_ui_source.py -q`
Expected: failing assertions because the dashboard tab does not exist yet.

- [ ] **Step 3: Write minimal implementation**

Create `deploy/sre-frontend/src/app/command-center/StatuspageTab.tsx`:
- load active incidents and components on mount
- refresh every 45 seconds while mounted
- expose manual refresh
- render `Active Incidents` cards
- render `Create Incident` using `StatuspageIncidentEditor`
- for each active incident render:
  - status
  - impact
  - updated time
  - component badges/statuses
  - `Post Update`
  - `Resolve`
  - `Open in Statuspage`
- use `updateStatuspageIncident(...)` for both normal updates and resolves
- prefill resolve action with `status = 'resolved'`, `impact = 'none'`, and component resets to `operational`

Update `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`:
- import `StatuspageTab`
- extend the dashboard tab union to include `'statuspage'`
- add the `Statuspage` tab button near the other dashboard tabs
- render `<StatuspageTab />` when `dashboardTab === 'statuspage'`
- hide the regular alerts table and global incident wizard while on that tab

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_ui_source.py -q`
Expected: all dashboard/statuspage source assertions pass.

- [ ] **Step 5: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/StatuspageTab.tsx deploy/sre-frontend/src/app/command-center/DashboardView.tsx deploy/tests/test_statuspage_ui_source.py
git commit -m "feat: add dashboard statuspage management tab"
```

### Task 5: Verify End-To-End Integration

**Files:**
- Modify: `deploy/runbook-api/runbook-api.py`
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`
- Modify: `deploy/sre-frontend/src/lib/types.ts`
- Modify: `deploy/sre-frontend/src/app/command-center/IncidentWizard.tsx`
- Modify: `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`
- Create: `deploy/sre-frontend/src/app/command-center/StatuspageComponentStatusPicker.tsx`
- Create: `deploy/sre-frontend/src/app/command-center/StatuspageIncidentEditor.tsx`
- Create: `deploy/sre-frontend/src/app/command-center/StatuspageTab.tsx`
- Test: `deploy/tests/test_statuspage_api.py`
- Test: `deploy/tests/test_statuspage_ui_source.py`

- [ ] **Step 1: Run the targeted automated verification**

Run: `python -m pytest C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_api.py C:\Users\fash\Documents\UIP\deploy\tests\test_statuspage_ui_source.py -q`
Expected: all targeted tests pass.

- [ ] **Step 2: Run Python syntax verification**

Run: `python -m py_compile C:\Users\fash\Documents\UIP\deploy\runbook-api\runbook-api.py`
Expected: no output.

- [ ] **Step 3: Run frontend build verification or nearest available source check**

Run: `Get-Command npm -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source`

If `npm` is available, run `npm run build` from `C:\Users\fash\Documents\UIP\deploy\sre-frontend` and expect a successful build.

If `npm` is unavailable, document that limitation and rely on source tests locally, then use server-side build verification during deployment.

- [ ] **Step 4: Commit**

```bash
git add deploy/runbook-api/runbook-api.py deploy/sre-frontend/src/lib/keep-api.ts deploy/sre-frontend/src/lib/types.ts deploy/sre-frontend/src/app/command-center/IncidentWizard.tsx deploy/sre-frontend/src/app/command-center/DashboardView.tsx deploy/sre-frontend/src/app/command-center/StatuspageComponentStatusPicker.tsx deploy/sre-frontend/src/app/command-center/StatuspageIncidentEditor.tsx deploy/sre-frontend/src/app/command-center/StatuspageTab.tsx deploy/tests/test_statuspage_api.py deploy/tests/test_statuspage_ui_source.py
git commit -m "feat: add statuspage dashboard management"
```
