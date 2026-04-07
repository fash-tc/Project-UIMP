# UIP Operations Guide

This guide is the main operator handbook for the Unified Incident Platform (UIP). It is written for the teams who use, support, troubleshoot, and maintain the platform.

The goal is to make this document useful both:

- in GitHub as the primary operational reference
- in Confluence later as a full team handbook

---

## Table of Contents

1. [Purpose](#purpose)
2. [Audience](#audience)
3. [What UIP Is](#what-uip-is)
4. [Access and URLs](#access-and-urls)
5. [High-Level Architecture](#high-level-architecture)
6. [Service and Container Inventory](#service-and-container-inventory)
7. [UIP Interface Guide](#uip-interface-guide)
8. [Integrations and External Systems](#integrations-and-external-systems)
9. [Normal Operations](#normal-operations)
10. [Troubleshooting](#troubleshooting)
11. [Logs and Diagnostics](#logs-and-diagnostics)
12. [Restart and Recovery Procedures](#restart-and-recovery-procedures)
13. [Deployment and Change Workflow](#deployment-and-change-workflow)
14. [Data and Persistence Notes](#data-and-persistence-notes)
15. [Known Risks and Cautions](#known-risks-and-cautions)

---

## Purpose

UIP is the SRE-facing incident and alert operations platform used to:

- view and work active alerts
- track alert state such as acknowledge, resolve, incident linkage, and custom grouping
- generate AI-assisted summaries and assessments
- create and manage Jira incidents
- manage customer-facing webhook previews and deliveries
- manage customer-facing Statuspage incidents
- provide admin, role, and integration control surfaces

This guide is intended to answer four practical questions:

1. What is this system and how does it fit together?
2. Where do teams go in the UI to do their work?
3. How do teams troubleshoot something that is broken?
4. How do teams safely restart, recover, and validate the platform?

---

## Audience

This guide is for:

- SRE operators using the Command Center during incidents
- administrators managing users, roles, webhooks, and integration settings
- platform owners maintaining the UIP stack
- engineers on support duty who need to diagnose or recover the system

This guide assumes the reader may not know the UIP internals already.

---

## What UIP Is

UIP is a Docker Compose-based operational platform that combines:

- a custom SRE portal built in Next.js
- Keep as the alert storage and aggregation backend
- supporting Python APIs for auth, runbooks, alert state, health, logs, and escalation
- reverse proxy and routing through nginx
- external integrations such as Jira, Statuspage, webhook receivers, maintenance tracking, and Grafana/Loki-related services

UIP should be thought of as two operator-facing layers:

- the **SRE Portal** at `/portal/...`
- the **Keep Admin UI** at `/incidents` and related Keep pages

The SRE Portal is the primary interface for most teams. The Keep Admin UI is mainly for platform administration and lower-level integration management.

Important note on alert ingress:

- upstream alert-routing architecture may evolve over time
- operators should not rely on one fixed ingestion topology when troubleshooting
- instead, they should verify platform health, upstream connectivity, and the current behavior of the active integrations

---

## Access and URLs

### Primary URLs

- Root landing page: `https://10-177-154-196.sslip.io/`
- SRE Portal: `https://10-177-154-196.sslip.io/portal/`
- Command Center: `https://10-177-154-196.sslip.io/portal/command-center/`
- Keep Admin UI: `https://10-177-154-196.sslip.io/incidents`
- n8n: `https://10-177-154-196.sslip.io/n8n/`

### Internal / proxied API paths exposed through nginx

- Auth API: `/api/auth/`
- Alert State API: `/api/alert-states`
- Health API: `/api/health/`
- Runbook API: `/api/runbook/`
- Keep API proxy: `/api/keep/`
- Maintenance API proxy: `/api/maintenance/`
- Loki Gateway API: `/api/loki/`
- Escalation API: `/api/escalation/`

### Deployment server

- Host: `10.177.154.196`
- Working directory on server: `/home/fash/uip`

### SSH access

Teams with operational access connect to the deployment host over SSH, then manage the stack from `/home/fash/uip`.

Example:

```bash
ssh <authorized-user>@10.177.154.196
cd /home/fash/uip
```

If you do not already have server access, do not guess credentials or bypass established access controls. Use your team’s normal access process.

---

## High-Level Architecture

At a high level, UIP works like this:

1. Alerts arrive from upstream monitoring and incident sources.
2. UIP normalizes and stores alert data through Keep and the supporting UIP APIs.
3. Alert state, incident linkage, runbook logic, AI summaries, webhook behavior, and Statuspage/Jira workflows are handled by the custom services in the stack.
4. nginx exposes the system under a single host and routes traffic to the correct backend service.
5. Teams interact primarily through the SRE Portal, with Keep Admin available for lower-level administration.

### Architecture principles

- nginx is the main edge and reverse proxy
- Keep is the core alert data plane
- the SRE frontend is the operator experience
- Python sidecar services provide platform behavior not handled natively by Keep
- persistence is split across PostgreSQL and several local SQLite-backed service data volumes

### Important architectural caution

Do not treat upstream alert flow as permanently fixed. The stable operational model is:

- alerts arrive from upstream systems
- UIP processes, stores, enriches, and displays them

The exact upstream source path may change over time as integrations are consolidated.

---

## Service and Container Inventory

The stack is defined in [`deploy/docker-compose.yml`](../deploy/docker-compose.yml).

### Core containers

| Container | Service | Purpose |
| --- | --- | --- |
| `uip-nginx` | nginx | Entry point, reverse proxy, TLS termination, path routing |
| `uip-sre-frontend` | `sre-frontend` | Main SRE Portal |
| `uip-keep-api` | `keep-api` | Core alert backend |
| `uip-keep-ui` | `keep-frontend` | Keep Admin UI |
| `uip-postgres` | `postgres` | Shared PostgreSQL database |

### UIP support services

| Container | Service | Purpose |
| --- | --- | --- |
| `uip-runbook-api` | `runbook-api` | Runbooks, Jira incident workflows, webhook preview/test, Statuspage operations |
| `uip-auth-api` | `auth-api` | Platform auth, user roles, Jira OAuth, shared integration auth bootstrap |
| `uip-alert-state-api` | `alert-state-api` | Acknowledgements, resolves, severity overrides, incident linkage, custom alert groups |
| `uip-alert-enricher` | `alert-enricher` | AI enrichment, situation summaries, rule execution, reconciliation logic |
| `uip-health-checker` | `health-checker` | Health API and service/container monitoring |
| `uip-loki-gateway` | `loki-gateway` | Log query proxy and registry/log workflows |
| `uip-escalation-api` | `escalation-api` | Grafana IRM / escalation-related integration logic |
| `uip-n8n` | `n8n` | Workflow automation |
| `uip-ollama` | `ollama` | Local model runtime, currently not intended for primary production AI path |

### Service routing

nginx routing is defined in [`deploy/nginx-default.conf`](../deploy/nginx-default.conf).

Important routes:

- `/portal/` -> `sre-frontend`
- `/api/auth/` -> `auth-api`
- `/api/alert-states` -> `alert-state-api`
- `/api/runbook/` -> `runbook-api`
- `/api/health/` -> `health-checker`
- `/api/loki/` -> `loki-gateway`
- `/api/escalation/` -> `escalation-api`
- `/api/maintenance/` -> external maintenance tracker
- `/backend/`, `/alerts/`, `/providers/`, `/workflows/` -> Keep

### What is external to UIP

Some functionality depends on systems outside this Compose stack:

- Jira Cloud
- Atlassian OAuth
- Statuspage
- maintenance tracker at `10.177.154.174`
- external Grafana / Loki related endpoints
- upstream alerting systems

This matters during troubleshooting, because sometimes UIP is healthy and the dependency is not.

---

## UIP Interface Guide

The SRE Portal application lives under [`deploy/sre-frontend/src/app`](../deploy/sre-frontend/src/app).

### 1. Landing and login

- `/portal/login`
- used for UIP session-based login
- auth behavior is backed by `auth-api`

If login breaks:

- check `uip-auth-api`
- check `uip-sre-frontend`
- check nginx routing for `/portal/` and `/api/auth/`

### 2. Command Center

Primary file area:

- [`deploy/sre-frontend/src/app/command-center/page.tsx`](../deploy/sre-frontend/src/app/command-center/page.tsx)
- [`deploy/sre-frontend/src/app/command-center/DashboardView.tsx`](../deploy/sre-frontend/src/app/command-center/DashboardView.tsx)
- [`deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx`](../deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx)

This is the main operations surface.

What teams do here:

- review current active alerts
- filter by severity and state
- acknowledge or resolve alerts
- inspect alert details
- create or manage incidents
- use bulk alert actions
- manage custom alert groups
- review AI summary content
- access embedded Statuspage controls
- access alert rules

Key embedded tabs/views:

- firing alerts
- acknowledged alerts
- suppressed or silenced alerts
- Statuspage tab
- alert rules tab
- knowledge base related flows

### 3. Alert detail pages

Path:

- `/portal/alerts/[fingerprint]`

Purpose:

- deep drill into one alert
- inspect AI enrichment
- view linked incident data
- review history and feedback details

### 4. Admin

Path:

- `/portal/admin`

Primary use:

- user and role management
- shared integration auth settings

If admin data is missing:

- check `auth-api`
- confirm user role and auth state
- confirm `/api/auth/users` and `/api/auth/roles` are responding

### 5. Webhooks

Path:

- `/portal/webhooks`

Primary use:

- manage subscriber records
- view delivery history
- inspect delivery payloads and errors
- test customer preview receiver flows

Backed mostly by:

- maintenance API proxy
- `runbook-api` preview/test endpoints

### 6. Settings

Path:

- `/portal/settings`

Primary use:

- user-level settings
- Jira OAuth connect/reconnect
- profile-specific integration state

### 7. Health

Path:

- `/portal/health`

Primary use:

- service visibility
- quick health summary of platform services

This page is useful for checking the platform state, but it is not a substitute for service logs.

### 8. Logs

Path:

- `/portal/logs`

Primary use:

- centralized log access through the platform
- operator-facing log search workflows

### 9. Maintenance

Path:

- `/portal/maintenance`

Primary use:

- maintenance tracking and related workflows

### 10. Registry

Path:

- `/portal/registry`

Primary use:

- registry-oriented data and supporting workflows

### 11. AI management

Path:

- `/portal/ai-manage`

Primary use:

- AI-related configuration and visibility

### 12. Keep Admin UI

Path:

- `/incidents`

This is not the main SRE dashboard. Use it when lower-level Keep administration is required, such as provider or integration visibility and direct Keep-side administrative tasks.

---

## Integrations and External Systems

### Jira

Used for:

- incident ticket creation
- user-specific OAuth-based ticket creation

Important behavior:

- users should create Jira tickets as themselves when OAuth is configured
- shared/global fallback behavior should not be relied on for normal user-created incidents

Related backend:

- [`deploy/runbook-api/runbook-api.py`](../deploy/runbook-api/runbook-api.py)
- [`deploy/auth-api/auth-api.py`](../deploy/auth-api/auth-api.py)

### Statuspage

Used for:

- creating customer-facing status incidents
- viewing active incidents
- updating and resolving incidents
- managing affected component degradation states

Primary UI:

- Statuspage tab inside the Command Center

### Webhooks

Used for:

- maintenance and incident delivery
- customer preview testing
- inspecting payloads and delivery errors

Important note:

- webhook management and preview involve both UIP and the external maintenance system
- a symptom in the UI may be caused by either side

### Maintenance tracker

The maintenance API is proxied through nginx but is external to the main UIP Compose stack.

Current proxy target:

- `http://10.177.154.174/api/`

If maintenance-related UI features fail while core UIP is healthy, this dependency is a strong suspect.

### Grafana / Loki / escalation-related services

Used for:

- log querying
- registry health related views
- escalation and IRM related platform integrations

Because this area is evolving, operators should focus on:

- whether the UI/API path is healthy
- whether credentials and upstream reachability are healthy
- whether returned data is current

---

## Normal Operations

### Daily operator checks

For routine platform confidence, verify:

1. the portal loads
2. login works
3. the Command Center shows data
4. `/api/health/` is responding
5. key integrations used that day are healthy

### Basic health commands

Run from the server:

```bash
cd /home/fash/uip
docker compose ps
docker compose logs --tail=100 nginx
docker compose logs --tail=100 sre-frontend
docker compose logs --tail=100 auth-api
docker compose logs --tail=100 runbook-api
```

### Quick UI/API sanity checks

Examples:

```bash
curl -k -I https://10-177-154-196.sslip.io/
curl -k -I https://10-177-154-196.sslip.io/portal/command-center/
curl -s http://10.177.154.196/api/health/
curl -s http://10.177.154.196/api/runbook/statuspage/incidents
```

Use these to distinguish:

- total edge outage
- frontend-only issue
- backend API issue
- feature-specific issue

---

## Troubleshooting

This section is symptom-driven. Start with the symptom, then work inward.

### Portal returns 502

Likely causes:

- nginx is up but upstream container is down
- nginx config is pinning or routing incorrectly
- frontend container failed to start or rebuild

Check:

```bash
cd /home/fash/uip
docker compose ps
docker compose logs --tail=200 nginx
docker compose logs --tail=200 sre-frontend
```

Common fix:

- rebuild and restart `sre-frontend`
- if needed, restart `nginx`

### Login or user/session behavior is broken

Likely causes:

- `auth-api` is down
- auth secret mismatch
- frontend/auth routing issue

Check:

```bash
docker compose logs --tail=200 auth-api
docker compose logs --tail=200 sre-frontend
curl -s http://10.177.154.196/api/auth/health
```

If the auth API does not expose a health endpoint in a given version, use logs and a direct auth route check instead.

### Users or roles missing in Admin

Check:

```bash
docker compose logs --tail=200 auth-api
curl -s http://10.177.154.196/api/auth/users
curl -s http://10.177.154.196/api/auth/roles
```

Look for:

- auth failures
- DB read/write issues
- role permission mismatches

### Command Center loads but data is wrong or stale

Likely causes:

- `keep-api` issue
- `alert-state-api` issue
- `alert-enricher` lag or failure
- upstream alert state drift

Check:

```bash
docker compose logs --tail=200 keep-api
docker compose logs --tail=200 alert-state-api
docker compose logs --tail=200 alert-enricher
```

Also verify whether the issue is:

- UI-only
- alert state-only
- enrichment-only
- upstream source mismatch

### Statuspage tab shows no incidents when one exists

Check:

```bash
docker compose logs --tail=200 runbook-api
curl -s http://10.177.154.196/api/runbook/statuspage/incidents
```

If the API returns data but the tab is blank:

- inspect `sre-frontend` build/version
- confirm the deployed frontend contains the current Statuspage code

### Jira connect or ticket creation is broken

Likely causes:

- missing OAuth env vars
- bad redirect URI
- auth-api issue
- runbook-api issue
- user has not connected Jira properly

Check:

```bash
docker compose logs --tail=200 auth-api
docker compose logs --tail=200 runbook-api
curl -k -i https://10-177-154-196.sslip.io/api/auth/jira/connect
```

Look for:

- missing `JIRA_OAUTH_*` env vars
- redirecting to wrong path
- fallback usage that should not occur

### Webhook sends fail or preview is wrong

Check both:

- `runbook-api`
- external maintenance API connectivity and auth

Commands:

```bash
docker compose logs --tail=200 runbook-api
curl -s http://10.177.154.196/api/runbook/webhook-test/deliveries
curl -s http://10.177.154.196/api/maintenance/webhooks/subscribers
```

Questions to answer:

- is the preview receiver capturing payloads?
- is the subscriber active?
- is the maintenance API reachable?
- is the signature present or missing?
- did UIP fall back to preview-only behavior?

### AI summary or AI assess is broken or slow

Check:

```bash
docker compose logs --tail=200 alert-enricher
docker compose logs --tail=200 runbook-api
```

Look for:

- upstream model endpoint timeout
- wrong model selection
- fallback path behavior
- prompt path errors

### Logs page or log-backed features are failing

Check:

```bash
docker compose logs --tail=200 loki-gateway
```

Also verify:

- upstream Grafana reachability
- datasource configuration
- auth credentials

### Maintenance features are failing

Check:

```bash
curl -s http://10.177.154.196/api/maintenance/
docker compose logs --tail=200 nginx
docker compose logs --tail=200 runbook-api
```

Remember:

- the maintenance API is proxied but external
- UIP may be fine while maintenance is not

---

## Logs and Diagnostics

### Where to read logs

Primary log access is through Docker Compose on the server.

From `/home/fash/uip`:

```bash
docker compose logs --tail=200 nginx
docker compose logs --tail=200 sre-frontend
docker compose logs --tail=200 keep-api
docker compose logs --tail=200 auth-api
docker compose logs --tail=200 runbook-api
docker compose logs --tail=200 alert-state-api
docker compose logs --tail=200 alert-enricher
docker compose logs --tail=200 health-checker
docker compose logs --tail=200 loki-gateway
docker compose logs --tail=200 escalation-api
docker compose logs --tail=200 n8n
```

For live follow:

```bash
docker compose logs -f runbook-api
docker compose logs -f sre-frontend
docker compose logs -f auth-api
```

### Useful inspection commands

```bash
docker compose ps
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
docker inspect uip-sre-frontend
docker inspect uip-nginx
```

### When to use UI diagnostics vs server logs

Use UI/API checks when you need to know:

- whether the user-facing route is up
- whether a feature endpoint is returning data

Use server logs when you need to know:

- why a route failed
- whether a container crashed
- whether an upstream dependency timed out
- whether a secret/config value is missing

---

## Restart and Recovery Procedures

Always run restart actions from:

```bash
cd /home/fash/uip
```

### Restart one service

```bash
docker compose restart runbook-api
docker compose restart auth-api
docker compose restart alert-state-api
docker compose restart alert-enricher
docker compose restart nginx
docker compose restart sre-frontend
```

Use this when:

- the configuration did not change
- the container is healthy enough to restart cleanly
- you only need to bounce the process

### Recreate one service after code or env change

```bash
docker compose up -d --force-recreate runbook-api
docker compose up -d --force-recreate auth-api
docker compose up -d --force-recreate alert-state-api
docker compose up -d --force-recreate alert-enricher
```

### Rebuild and restart the frontend

```bash
docker compose up -d --build sre-frontend
```

Use this when:

- frontend source changed
- a page fix was copied to the server
- a build-time mismatch is suspected

### Rebuild and restart nginx-backed routing change

If nginx config changes:

```bash
docker compose up -d --force-recreate nginx
```

If a route issue persists:

- also confirm the upstream container is healthy
- check nginx logs immediately after restart

### Restart the full stack

Use only when a broad recovery is necessary:

```bash
docker compose up -d
```

If a clean rolling recovery is needed:

```bash
docker compose down
docker compose up -d
```

Avoid full-stack restarts during active incidents unless the failure is clearly platform-wide and coordination has already happened.

### Validation after any restart

After restarting anything, validate:

1. the container is `Up`
2. logs do not show immediate crash loops
3. the relevant route responds
4. the affected feature works again

Example:

```bash
docker compose ps
docker compose logs --tail=100 runbook-api
curl -s http://10.177.154.196/api/runbook/statuspage/incidents
```

---

## Deployment and Change Workflow

### Repo location

Main repo:

- [`README.md`](../README.md)
- [`deploy/`](../deploy)

### Typical deployment pattern

The common operational flow is:

1. update files in the repo
2. copy changed files to the deployment server
3. rebuild or recreate only the affected service
4. verify with logs and a live route check

### Examples

Frontend change:

1. update files under `deploy/sre-frontend/...`
2. copy changed files to `/home/fash/uip/sre-frontend/...`
3. run:

```bash
docker compose up -d --build sre-frontend
```

Python service change:

1. update the service file
2. copy it to `/home/fash/uip/<service-dir>/...`
3. run:

```bash
docker compose up -d --force-recreate <service-name>
```

nginx change:

1. update [`deploy/nginx-default.conf`](../deploy/nginx-default.conf)
2. copy it to `/home/fash/uip/nginx-default.conf`
3. restart or recreate nginx

### Safe change guidance

Before deployment:

- know which container owns the changed file
- know whether the change needs rebuild vs recreate vs simple restart
- know which route or UI action will prove success

After deployment:

- inspect logs
- test the feature directly
- do not assume success just because the container started

---

## Data and Persistence Notes

UIP persistence is split across several stores.

### PostgreSQL

Used by:

- Keep
- n8n

Volume:

- `postgres_data`

### Runbook API local data

Used by:

- runbook entries
- local runbook DB-backed state

Volume:

- `runbook_data`

Path in container:

- `/data/runbook.db`

### Auth API local data

Used by:

- user auth and role-related service state

Volume:

- `auth_data`

Path in container:

- `/data/auth.db`

### Alert state local data

Used by:

- acknowledgements
- resolves
- severity overrides
- custom group data
- incident linkage state

Volume:

- `alert_state_data`

Path in container:

- `/data/alert-states.db`

### Important caution

If you remove containers but preserve volumes, data remains.

If you destroy volumes, service state may be lost.

Do not remove volumes casually during troubleshooting.

---

## Known Risks and Cautions

### 1. Upstream integrations may fail independently of UIP

Examples:

- Jira OAuth/provider problems
- Statuspage API issues
- maintenance tracker issues
- Grafana/Loki connectivity issues

Do not restart UIP blindly if the true problem is upstream.

### 2. nginx route issues can look like app issues

Because nginx fronts almost everything, stale or incorrect routing can look like:

- frontend outage
- auth outage
- runbook outage
- API outage

Always include nginx in first-pass checks for edge symptoms.

### 3. Frontend drift and source drift are possible

If the UI behavior does not match the repo:

- confirm the changed file was actually copied to the server
- confirm the correct container was rebuilt
- confirm the route is serving the new build

### 4. Maintenance features involve an external system

Maintenance subscriber create/delete/test problems may be caused by the external maintenance service rather than UIP itself.

### 5. Do not assume hidden/archived means deleted

Especially with webhook subscribers and delivery logs, archived records can still matter during troubleshooting.

### 6. Avoid broad restarts during live incidents

Prefer:

- restart one service
- verify
- expand only if necessary

Broad restarts increase risk and make diagnosis harder.

### 7. Treat secrets and credentials as external operational data

This repo and this guide should describe where secrets are used, not include their values.

---

## Quick Reference

### Most common URLs

- Portal: `https://10-177-154-196.sslip.io/portal/`
- Command Center: `https://10-177-154-196.sslip.io/portal/command-center/`
- Keep Admin: `https://10-177-154-196.sslip.io/incidents`

### Most common server commands

```bash
cd /home/fash/uip
docker compose ps
docker compose logs --tail=200 nginx
docker compose logs --tail=200 sre-frontend
docker compose logs --tail=200 runbook-api
docker compose logs --tail=200 auth-api
docker compose restart <service>
docker compose up -d --force-recreate <service>
docker compose up -d --build sre-frontend
```

### Most common containers

- `uip-nginx`
- `uip-sre-frontend`
- `uip-keep-api`
- `uip-runbook-api`
- `uip-auth-api`
- `uip-alert-state-api`
- `uip-alert-enricher`
- `uip-health-checker`
- `uip-loki-gateway`
- `uip-escalation-api`

---

## Source References

This guide is based on the current repo structure and stack definitions in:

- [`README.md`](../README.md)
- [`deploy/docker-compose.yml`](../deploy/docker-compose.yml)
- [`deploy/nginx-default.conf`](../deploy/nginx-default.conf)
- [`deploy/runbook-api/runbook-api.py`](../deploy/runbook-api/runbook-api.py)
- [`deploy/auth-api/auth-api.py`](../deploy/auth-api/auth-api.py)
- [`deploy/alert-state-api/alert-state-api.py`](../deploy/alert-state-api/alert-state-api.py)
- [`deploy/health-checker.py`](../deploy/health-checker.py)
- [`deploy/loki-gateway/loki-gateway.py`](../deploy/loki-gateway/loki-gateway.py)
- [`deploy/maint-sync/maint-sync.py`](../deploy/maint-sync/maint-sync.py)
- [`deploy/sre-frontend/src/app`](../deploy/sre-frontend/src/app)
