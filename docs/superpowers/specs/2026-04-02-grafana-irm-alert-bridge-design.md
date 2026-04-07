# Grafana IRM Alert Bridge Design

Date: 2026-04-02

## Goal

Use Grafana Cloud IRM as the upstream consolidation layer for alert sources that already flow there, starting with Domains Shared, so UIP can ingest active and resolved alert state from one normalized source instead of integrating each source directly.

The desired end state is:
- Grafana IRM sends alert-group lifecycle events to UIP by outgoing webhook.
- UIP keeps a low-frequency repair poller against Grafana IRM alert groups.
- After verification, the existing direct Domains Shared Zabbix ingress into UIP is disabled to avoid duplicate alerts.

## Why This Approach

The current direct-source model creates scaling and networking problems as more alerting systems are added. Grafana IRM already sits in front of those systems and tracks alert-group state transitions such as created, resolved, and unresolved. Using IRM as the aggregator reduces future integration cost and gives UIP a single external lifecycle model to reconcile against.

Pure polling would work, but would introduce avoidable delay and extra API reads. Pure webhook delivery would be lower-latency, but it leaves UIP vulnerable to missed events. A hybrid model gives fast updates from webhook delivery and correctness repair from periodic polling.

## Chosen Architecture

The implementation will use:
- `runbook-api` as the Grafana IRM webhook ingress
- a low-frequency UIP poller as the repair and backfill path
- Grafana IRM alert-group IDs as the stable upstream identity in UIP

This design intentionally does not add a separate new microservice for the first iteration.

## Grafana-Side Setup

Create three outgoing webhooks in Grafana IRM:
- `UIP Alert Group Created`
- `UIP Alert Group Resolved`
- `UIP Alert Group Unresolved`

Shared configuration:
- Enabled: on
- HTTP method: `POST`
- Payload mode: `Forward whole payload data`
- Webhook URL:
  - `https://10-177-154-196.sslip.io/api/runbook/grafana-irm/alert-group-event`
- Webhook headers:

```json
{
  "Content-Type": "application/json",
  "X-UIP-Webhook-Source": "grafana-irm",
  "X-UIP-Webhook-Secret": "replace-with-a-long-random-secret"
}
```

Other fields:
- Username: blank
- Password: blank
- Authorization Header: blank
- Trigger Template: blank

Trigger type per webhook:
- one webhook for `Alert group created`
- one webhook for `Resolved`
- one webhook for `Unresolved`

The `Integrations` selector may be left empty for all IRM integrations, or restricted during rollout if only Domains Shared should flow through first.

## UIP Webhook Ingress

Add a new endpoint in `runbook-api`:
- `POST /api/runbook/grafana-irm/alert-group-event`

Responsibilities:
- validate request origin using:
  - `X-UIP-Webhook-Source`
  - `X-UIP-Webhook-Secret`
- parse the forwarded Grafana IRM payload
- normalize it into a UIP-internal event shape
- apply a create, resolve, or reopen transition to the corresponding UIP alert
- return `200` quickly

The webhook handler must be lightweight and avoid long-running processing. Any expensive enrichment or secondary lookups should remain asynchronous or be handled by existing downstream logic.

### Required server configuration

Add a new environment variable:
- `GRAFANA_IRM_WEBHOOK_SECRET`

This secret is compared against `X-UIP-Webhook-Secret`. The endpoint will reject missing or incorrect values with `401`.

## UIP Internal Data Model

Grafana IRM alert groups become the external source-of-truth object. UIP must store enough metadata to update the same alert across webhook and poller flows.

Required persisted metadata per IRM-backed alert:
- `upstream_source = grafana-irm`
- `upstream_id = <alert_group_id>`
- `upstream_integration = <integration name or id if present>`

The normalized UIP alert should also preserve:
- title / summary
- current state
- timestamps such as created and resolved
- raw payload or selected fields needed for enrichment, dedupe, and operator context

For the first iteration, one Grafana IRM alert group should map to one UIP alert object. UIP should not fan an IRM group back out into multiple child alerts yet.

## State Transitions

Webhook event handling:
- `Alert group created`:
  - create the UIP alert if it does not exist
  - reopen/update it if it already exists
- `Resolved`:
  - mark the UIP alert resolved
- `Unresolved`:
  - reopen the UIP alert

Poller behavior:
- fetch active or otherwise unresolved IRM alert groups on a modest interval
- create missing UIP alerts for open IRM groups
- refresh metadata on known open IRM groups
- close UIP alerts that are still open locally but are no longer active in IRM

Polling is a repair loop, not the primary delivery mechanism.

## Poller Design

The poller should run at a conservative interval such as every `1-5` minutes.

Responsibilities:
- startup backfill
- missed webhook recovery
- drift correction

Recommended API usage:
- list alert groups in active/open states
- optionally fetch per-group alert detail only when needed for enrichment or normalization

Rate limits and cost should be respected by:
- paging through results
- caching the last seen IRM group state hash or update timestamp
- avoiding repeated detail fetches when nothing changed

## Cutover Strategy For Domains Shared

This migration must be staged to avoid duplicate board entries.

### Stage 1: Shadow ingest

Enable Grafana IRM outgoing webhooks to UIP while keeping the current direct Domains Shared Zabbix path active.

IRM-backed UIP alerts must be explicitly marked with:
- `providerType = grafana-irm`
- `upstream_source = grafana-irm`
- `upstream_id = <alert_group_id>`

### Stage 2: Overlap verification

Verify that:
- create events arrive in UIP
- resolved events arrive in UIP
- unresolved events reopen alerts in UIP
- the repair poller can backfill active IRM state

During the overlap window, UIP should suppress duplicate display between:
- direct Domains Shared Zabbix alerts
- IRM-backed alerts for the same operational issue

Initial duplicate suppression rule:
- if an active IRM-backed alert matches the same normalized target/title as a direct Domains Shared alert, prefer the IRM-backed alert in the operator view

This suppression is transitional and only needed during migration overlap.

### Stage 3: Disable direct Domains Shared ingress

Once webhook delivery and repair polling are verified, disable the existing direct Domains Shared Zabbix flow into UIP at the source.

After this cutover:
- Domains Shared alerts should arrive only through Grafana IRM
- other existing direct integrations remain unchanged

## Error Handling

Webhook ingress should:
- reject invalid secrets with `401`
- reject malformed payloads with `400`
- log normalization failures with enough context to replay/debug safely
- avoid partial silent success

Poller behavior should:
- log and continue on transient Grafana API failures
- avoid mass-closing alerts on one failed poll cycle
- require a positive IRM absence signal before resolving via polling

## Security

Security expectations:
- use a dedicated shared secret for Grafana IRM webhook auth
- do not allow anonymous lifecycle mutation without the secret
- keep poller credentials server-side only
- use a scoped Grafana service account/token for IRM reads

The webhook secret should be long random text, not a placeholder.

## Testing

### Backend tests

Add tests for:
- valid webhook create event creates or opens a UIP alert
- valid resolved event marks the alert resolved
- valid unresolved event reopens the alert
- invalid secret returns `401`
- malformed payload returns `400`
- poller backfills an active IRM group into UIP
- poller resolves drift when UIP shows an alert open but IRM no longer does

### Integration verification

Before disabling the direct Domains Shared path, verify live:
- new alert group in IRM creates one UIP alert
- resolving that IRM alert group resolves the UIP alert
- reopening it in IRM reopens the UIP alert
- disabling webhook delivery temporarily is repaired by the poller
- no duplicate operator-visible alert remains during overlap

## Out Of Scope

This iteration does not include:
- exploding one IRM alert group back into multiple UIP child alerts
- migrating every current direct source into IRM at once
- replacing the maintenance webhook or incident-notification subsystems
- UI for configuring Grafana IRM credentials

## Success Criteria

This work is successful when:
- UIP can ingest Grafana IRM alert-group lifecycle events reliably
- UIP can reconcile against IRM open-state via polling
- Domains Shared can be cut over from direct Zabbix ingress to IRM-backed ingest without duplicate board entries
- resolved and reopened alert lifecycle remains accurate in UIP after cutover
