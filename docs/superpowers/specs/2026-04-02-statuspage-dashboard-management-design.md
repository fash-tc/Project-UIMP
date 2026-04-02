# Statuspage Dashboard Management Design

**Date:** 2026-04-02

**Goal:** Add first-class Statuspage management into the command center dashboard so operators can create, monitor, update, and resolve Statuspage incidents from UIP, while also allowing per-component degradation selection when posting Statuspage incidents.

## Problem

UIP already has a partial Statuspage integration in the incident wizard:

- it can fetch components
- it can create a Statuspage incident
- it can set page-level incident status and impact

But it cannot currently:

- show active Statuspage incidents in the dashboard
- let users update or resolve existing Statuspage incidents from UIP
- let users set per-component degradation levels

This leads to two operator problems:

- active customer-facing incidents are managed outside the dashboard, which breaks workflow
- component state is too coarse because users can only check components, not set their degradation

## Scope

This design adds:

- a `Statuspage` tab inside the dashboard
- active incident management from UIP
- direct Statuspage incident creation from that tab
- per-component degradation controls for both dashboard creation and the existing incident wizard
- a resolve flow that reminds operators to reset affected components to `operational`

This design does not add:

- automatic Statuspage posting from alerts
- historical incident reporting
- background synchronization beyond modest polling/manual refresh
- role or permission model changes beyond the existing authenticated UIP flows

## Current System

### Existing frontend

The current Statuspage UX lives only in:

- `deploy/sre-frontend/src/app/command-center/IncidentWizard.tsx`

It supports:

- loading components from `/api/runbook/statuspage/components`
- creating an incident through `/api/runbook/statuspage/incident`

It currently sends:

- `name`
- `body`
- `component_ids`
- `status`
- `impact_override`

This means component membership is supported, but component degradation/status is not.

### Existing backend

The current backend support lives in:

- `deploy/runbook-api/runbook-api.py`

It supports:

- fetching components from Statuspage
- creating a Statuspage incident

It does not currently expose:

- active incident listing
- incident update
- incident resolution workflow
- component status updates tied to incidents

## Requirements

### Dashboard Statuspage tab

The command center dashboard gets a new `Statuspage` tab alongside the existing dashboard sub-tabs.

This tab contains two primary areas:

- `Active Incidents`
- `Create Incident`

### Active incidents

When active Statuspage incidents exist, users should be able to:

- view currently active incidents from UIP
- see each incident’s title, status, impact, link, updated time, and affected components
- post an update to an existing incident
- advance incident state such as `investigating`, `identified`, `monitoring`, or `resolved`
- resolve the incident directly from UIP

### Resolve reminder

When resolving a Statuspage incident, UIP should remind users that affected components typically need to be reset to `operational` too.

This reminder should appear inline in the resolve form, not as a hidden tooltip.

### Direct create from dashboard

The new dashboard Statuspage tab should also let users create a brand-new Statuspage incident directly from the tab, without needing to go through the incident wizard.

### Per-component degradation control

When creating or updating a Statuspage incident, users must be able to set degradation level for each affected component.

Supported values in UIP:

- `operational`
- `degraded_performance`
- `partial_outage`
- `major_outage`

The control should no longer be a plain checkbox-only picker.

## UX Design

### Statuspage tab layout

The `Statuspage` tab should be structured as a control surface, not a table-first admin screen.

Top controls:

- manual refresh button
- last refreshed time
- loading/error state

Main content:

- left or top section for `Active Incidents`
- secondary section for `Create Incident`

If there are no active incidents, the tab should still remain useful by keeping the create form visible.

### Active incident cards

Each active incident should render as a card with:

- incident name
- incident status
- impact override
- shortlink to open in external Statuspage
- updated timestamp
- current component states

Each card should expose:

- `Post Update`
- `Resolve`
- `Open in Statuspage`

`Post Update` opens an inline editor or modal with:

- incident title
- body/update text
- incident status
- impact override
- per-component degradation controls

`Resolve` opens the same update surface in resolved mode, preselecting:

- incident status = `resolved`

and displaying:

- a reminder to set any restored components back to `operational`

### Create form

The `Create Incident` area in the Statuspage tab should include:

- title
- body
- incident status
- impact override
- component status editor

The component editor should use row-based controls:

- unselected components are omitted from the incident payload
- selected components show a degradation dropdown

This keeps the operator intent explicit.

### Incident wizard parity

The component/degradation control used in the dashboard tab should also replace the existing component checkbox picker in `IncidentWizard.tsx`.

This avoids two inconsistent Statuspage experiences in UIP.

## API Design

### Existing endpoint to enhance

`POST /api/runbook/statuspage/incident`

Change the create payload to support component status updates, not just component IDs.

UIP request shape:

```json
{
  "name": "DNS Service Disruption",
  "body": "Customers may experience intermittent failures while we investigate.",
  "status": "investigating",
  "impact_override": "major",
  "components": [
    { "component_id": "abc123", "status": "partial_outage" },
    { "component_id": "def456", "status": "degraded_performance" }
  ]
}
```

The backend should translate this into the Statuspage incident create format.

### New endpoint: list active incidents

`GET /api/runbook/statuspage/incidents`

Returns unresolved/current incidents plus enough metadata for dashboard control.

Response should include:

- `id`
- `name`
- `status`
- `impact`
- `shortlink`
- `updated_at`
- current component states

### New endpoint: update incident

`PATCH /api/runbook/statuspage/incidents/<id>`

Accepts:

- `name`
- `body`
- `status`
- `impact_override`
- `components`

This powers both normal updates and resolve flow.

### Component update model

UIP should use a shared shape such as:

```json
{
  "component_id": "abc123",
  "status": "major_outage"
}
```

Components not included in the request are left untouched.

That makes it possible to:

- update only selected components
- explicitly reset selected components to `operational`
- avoid accidental component churn

## Frontend File Boundaries

### Modify

- `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`
  - add the new `Statuspage` dashboard tab hook-up
- `deploy/sre-frontend/src/app/command-center/IncidentWizard.tsx`
  - replace checkbox-only component picker with per-component degradation control
- `deploy/sre-frontend/src/lib/keep-api.ts`
  - add active incident fetch/update helpers and expand create payload shape
- `deploy/sre-frontend/src/lib/types.ts`
  - add richer Statuspage incident/component types

### Create

To keep `DashboardView.tsx` from growing further, create focused Statuspage UI units:

- `deploy/sre-frontend/src/app/command-center/StatuspageTab.tsx`
- `deploy/sre-frontend/src/app/command-center/StatuspageIncidentEditor.tsx`
- `deploy/sre-frontend/src/app/command-center/StatuspageComponentStatusPicker.tsx`

These units should separate:

- tab orchestration
- incident create/update form
- component status selection

## Backend File Boundaries

### Modify

- `deploy/runbook-api/runbook-api.py`
  - add active incident listing
  - add incident update support
  - enhance incident create payload handling for component statuses

No new service is needed. This should stay in `runbook-api`.

## Data Model Changes

### Frontend types

Add or expand types to represent:

- a Statuspage component with current status
- a Statuspage incident with full display metadata
- a UIP component update payload

Suggested shapes:

```ts
type StatuspageComponentStatus =
  | 'operational'
  | 'degraded_performance'
  | 'partial_outage'
  | 'major_outage';

interface StatuspageComponentUpdate {
  component_id: string;
  status: StatuspageComponentStatus;
}
```

## Rate Limiting And Refresh Strategy

Statuspage API is rate-limited to 1 request per second, so UIP should not poll aggressively.

Dashboard tab behavior:

- fetch incidents/components on first entry into the `Statuspage` tab
- allow manual refresh
- background refresh every 45 seconds while the tab is visible
- do not refresh if the tab is not active

Mutation behavior:

- after create/update/resolve, refresh immediately once
- avoid chained redundant fetches

## Error Handling

Frontend should show clear user-facing errors for:

- Statuspage API not configured
- failed component load
- failed incident creation
- failed incident update
- failed resolve

When active incidents cannot be loaded, the create form should still remain available.

Resolve flow should not silently assume components were reset. If a user resolves an incident without setting restored components back to `operational`, UIP should still allow the action, but the reminder must remain visible and explicit.

## Testing

### Backend

Add tests for:

- fetching active incidents
- mapping Statuspage incident payloads into UIP response shape
- creating incidents with component status payloads
- updating incidents with component status payloads
- resolving incidents with `resolved` status and component resets

### Frontend

Add tests or source-based regression checks for:

- `Statuspage` tab visible in dashboard
- active incident actions rendered
- per-component degradation control rendered
- resolve reminder text rendered
- incident wizard uses the same component-status control

## Rollout And Verification

Implementation is complete when:

- dashboard shows a working `Statuspage` tab
- users can create a Statuspage incident from the tab
- users can view active Statuspage incidents from UIP
- users can update and resolve those incidents from UIP
- users can set per-component degradation levels
- resolve flow reminds users to restore components to `operational`
- incident wizard also supports per-component degradation

Live smoke test after deploy:

1. Load Statuspage tab and confirm active incidents/components render.
2. Create a test incident from the dashboard tab with at least one affected component and explicit degradation.
3. Update that incident from UIP and confirm status/body change.
4. Resolve it from UIP and confirm the reminder to reset components to `operational` is shown.
5. Create a Statuspage incident through the incident wizard and confirm the same component-status control is used there.
