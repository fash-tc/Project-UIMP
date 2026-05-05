# OpenSRS E2E Health Report - Design Spec

**Date:** 2026-05-05
**Author:** fash + Codex
**Status:** Approved for implementation planning

---

## Goal

Add an SRE-triggered OpenSRS end-to-end health report to UIP. The report must read existing log, metric, and event evidence only, then present a clear dashboard-style assessment of OpenSRS platform health.

This feature gives SREs a manual "what is OpenSRS doing right now?" report without causing customer-like actions, lookups, writes, or any platform mutation.

## Non-Goals

- Do not perform OpenSRS lookups, API calls, endpoint probes, or synthetic transactions from UIP.
- Do not schedule automatic runs in the MVP.
- Do not let the LLM generate arbitrary LogQL.
- Do not send Slack messages in the MVP. Reports should be Slack-ready for a later NOC Slack Bot or n8n integration.
- Do not replace the existing manual Logs Explorer.

---

## Current Context

UIP already includes:

- A Loki Gateway service at `deploy/loki-gateway/loki-gateway.py`.
- A manual Logs Explorer at `/portal/logs`.
- Local LLM inference through Ollama.
- Existing registry/EPP health aggregation from Loki logs.
- n8n and escalation plumbing that can support later Slack workflows.

The new feature should follow the existing lightweight service pattern: single-file Python API, SQLite where persistence is needed, and a Next.js dashboard page.

---

## User Workflow

1. SRE opens `/portal/opensrs-health`.
2. SRE clicks one primary button: **Run OpenSRS E2E Health Report**.
3. UIP starts one log-only analysis run.
4. UI shows progress while evidence lanes run.
5. UI renders a readable report with separate dashboard sections.
6. SRE can view report history and open previous reports.

The SRE should not need to write LogQL or know which logs matter. The report should separate raw evidence from interpretation.

---

## Architecture

Add a new `opensrs-health-api` service. It owns report orchestration, Loki evidence collection, LLM analysis, and report persistence.

```
SRE Browser
    |
    v
UIP Next.js Page (/portal/opensrs-health)
    |
    v
Nginx /api/opensrs-health/*
    |
    v
opensrs-health-api
    |                 |
    v                 v
Grafana Loki      Ollama
    |
    v
OpenSRS logs, metrics, events
```

The service queries Loki using fixed, allowlisted query templates. Each template has a bounded time window, result limit, and parsing logic. It then compacts the results into evidence summaries and sends one prompt to Ollama to produce the human-readable analysis.

---

## Evidence Lanes

Each report is built from several evidence lanes. Lanes can fail independently; one failed lane should not fail the whole report unless no evidence can be collected.

### 1. Customer-Like Synthetic Evidence

Purpose: Capture blackbox/customer-like tests that already run outside UIP.

Primary signal:

- Reseller name `srsopsmonitoring`.

Expected extraction:

- pass/fail markers
- latency or duration fields
- timeout text
- operation or flow name if present
- target service or registry if present
- representative error samples

This lane is important but not the whole report. It is an anchor signal for customer-like behavior.

### 2. OpenSRS API and Request Health

Purpose: Detect broad request-level problems.

Expected extraction:

- HTTP 5xx and 4xx counts where present
- timeout and connection error counts
- slow request samples
- top error messages
- affected route, service, or component labels where present

This lane should prefer structured labels when available and fall back to message parsing when needed.

### 3. Registry and EPP Health

Purpose: Reuse and extend existing registry/EPP timing and result-code analysis.

Signals:

- `registry_agent` timing logs
- EPP result codes
- response codes
- slow registry operations
- degraded/down operator summaries

The existing Loki Gateway registry aggregation is a useful model, but the OpenSRS report should package this evidence into the new report format rather than forcing the frontend to correlate separate APIs.

### 4. Platform Event and Error Trend Evidence

Purpose: Surface notable event spikes that may explain end-to-end symptoms.

Expected extraction:

- restart/deploy/error-spike messages if visible in logs
- repeated exception signatures
- dependency failures
- database/cache/queue timeout messages if present
- notable event counts bucketed by time

This lane should be conservative. It should show evidence, not invent causality.

### 5. Correlation Evidence

Purpose: Explain whether customer-like failures align with platform or registry symptoms.

The API should bucket lane evidence by time, then report correlations such as:

- `srsopsmonitoring` failures increased during the same bucket as API timeout spikes.
- EPP error codes increased without customer-like failures.
- Customer-like checks failed while API and registry lanes looked healthy.

Correlation output should include confidence and evidence references.

---

## Loki Load Controls

The feature must be lightweight on Loki.

Controls:

- Manual runs only.
- Default report window: 1 hour.
- Optional UI windows may be `15m`, `1h`, `6h`, and `24h`, with `1h` default.
- Each lane has fixed query templates and max result limits.
- Total report run has a max query count.
- User cannot submit raw LogQL to the report runner.
- LLM cannot write or modify queries.
- Representative samples are capped before storage and before LLM prompting.
- Cooldown per user or global run type prevents repeated button clicks from hammering Loki.
- If cached report is very recent, UI can suggest viewing it before starting another run.

Suggested MVP limits:

- Max 5 evidence lanes per run.
- Max 2 Loki queries per lane.
- Max 500 raw log entries per lane before parsing.
- Max 20 stored evidence samples per lane.
- Max 60 seconds backend timeout per report.
- Minimum 60 second cooldown between started runs.

These values can be environment variables.

---

## API Design

### `POST /api/opensrs-health/runs`

Starts a manual report run.

Request:

```json
{
  "window_seconds": 3600
}
```

Response:

```json
{
  "id": "run_20260505_184200_ab12",
  "status": "running",
  "started_at": "2026-05-05T18:42:00Z"
}
```

If the service chooses to run synchronously for MVP, it may return a completed report object directly. The UI should still be written to handle `running`, `completed`, and `failed`.

### `GET /api/opensrs-health/runs`

Lists recent reports.

Response:

```json
[
  {
    "id": "run_20260505_184200_ab12",
    "status": "completed",
    "started_at": "2026-05-05T18:42:00Z",
    "completed_at": "2026-05-05T18:42:31Z",
    "window_seconds": 3600,
    "overall_status": "degraded",
    "headline": "Customer-like checks show intermittent failures correlated with registry latency."
  }
]
```

### `GET /api/opensrs-health/runs/{id}`

Returns full report JSON.

### Report Schema

```json
{
  "id": "run_20260505_184200_ab12",
  "status": "completed",
  "started_at": "2026-05-05T18:42:00Z",
  "completed_at": "2026-05-05T18:42:31Z",
  "window_seconds": 3600,
  "overall": {
    "status": "degraded",
    "confidence": "medium",
    "headline": "Customer-like checks show intermittent failures correlated with registry latency.",
    "summary": "OpenSRS appears degraded for a subset of flows. Evidence points to registry latency rather than a full API outage."
  },
  "lanes": [
    {
      "id": "synthetic",
      "label": "Customer-like checks",
      "status": "degraded",
      "metrics": {
        "events": 128,
        "failures": 7,
        "timeouts": 3,
        "avg_latency_ms": 642,
        "p95_latency_ms": 1840
      },
      "findings": [
        "7 failures found for reseller srsopsmonitoring."
      ],
      "samples": [
        {
          "timestamp": "2026-05-05T18:20:12Z",
          "message": "bounded sample text",
          "labels": {
            "app": "opensrs"
          }
        }
      ],
      "errors": []
    }
  ],
  "timeline": [
    {
      "bucket_start": "2026-05-05T18:20:00Z",
      "synthetic_failures": 3,
      "api_errors": 12,
      "registry_errors": 4,
      "notes": ["Synthetic failures and registry errors overlap."]
    }
  ],
  "correlations": [
    {
      "title": "Synthetic failures overlap with registry latency",
      "confidence": "medium",
      "evidence": "Failures and slow registry operations occurred in the 18:20 UTC bucket."
    }
  ],
  "ai_analysis": {
    "impact": "Possible intermittent customer-visible degradation for lookup-like flows.",
    "likely_causes": ["Registry latency or EPP-side degradation"],
    "recommended_next_steps": [
      "Inspect registry agents with elevated latency.",
      "Compare blackbox failures against affected operation names."
    ],
    "slack_markdown": "*OpenSRS E2E Health:* degraded..."
  }
}
```

---

## Persistence

Use SQLite in an `opensrs_health_data` Docker volume.

Tables:

```sql
CREATE TABLE IF NOT EXISTS health_runs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    window_seconds INTEGER NOT NULL,
    requested_by TEXT,
    overall_status TEXT,
    headline TEXT,
    report_json TEXT NOT NULL,
    error TEXT
);
```

Keep the schema intentionally small. The full report lives in JSON so lane fields can evolve without migrations during early development.

Retention:

- Keep latest 100 reports by default.
- Delete older reports after each completed run.

---

## LLM Analysis

The LLM should only analyze compact evidence prepared by code.

Prompt input:

- report window
- lane metrics
- lane findings
- timeline buckets
- capped representative samples
- parser warnings or failed lanes

Prompt output:

- overall status recommendation
- concise summary
- likely impact
- likely causes
- next SRE checks
- Slack-ready markdown

Rules:

- LLM must not claim certainty beyond evidence.
- LLM must mention missing/failed evidence lanes.
- LLM must not request new live OpenSRS actions.
- LLM must distinguish observed symptoms from inferred causes.

If Ollama fails, the report still completes with deterministic lane summaries and `ai_analysis.error`.

---

## Frontend Design

Add `/portal/opensrs-health` with one primary button and a dashboard report layout.

### Header

- Title: `OpenSRS E2E Health`
- Subtitle: `Manual log-derived health report for OpenSRS platform signals.`
- Primary button: `Run OpenSRS E2E Health Report`
- Window selector: `15m`, `1h`, `6h`, `24h`

### Latest Report

Show:

- status badge
- confidence
- time window
- generated time
- headline
- short summary

### Dashboard Sections

Sections should be visually separate and easy to scan:

- Customer-like checks
- API/request health
- Registry/EPP health
- Platform events
- Timeline
- Correlation
- AI analysis
- Evidence samples

Each lane section should show:

- status
- key metrics
- top findings
- sample count
- lane errors if any

Evidence samples should be collapsed by default to keep the report readable.

### Report History

Show a compact list of recent reports:

- time
- status
- headline
- window

Selecting a report loads full detail.

---

## Nginx and Docker Compose

Add service:

- `opensrs-health-api`
- Python 3.12 slim
- command `python3 -u /app/opensrs-health-api.py`
- volume for script
- volume for SQLite data
- environment:
  - `API_PORT=8095`
  - `AUTH_SECRET`
  - `GRAFANA_URL`
  - `GRAFANA_USER`
  - `GRAFANA_PASS`
  - `LOKI_DATASOURCE_ID`
  - `OLLAMA_URL=http://ollama:11434`
  - `OLLAMA_MODEL=${OLLAMA_MODEL:-qwen2.5:3b}`
  - query limit settings

Add nginx route:

- `/api/opensrs-health/` proxies to `opensrs-health-api:8095`.

Add frontend nav link:

- `OpenSRS Health`

---

## Error Handling

Expected behavior:

- Loki unavailable: report fails with clear error if no lanes can run.
- Single lane query fails: report completes with that lane marked `unknown` and error shown.
- Ollama unavailable: report completes without AI narrative.
- Cooldown active: API returns 429 with last report metadata.
- User unauthenticated: API returns 401.
- Invalid window: API returns 400.

The UI should preserve the previous completed report if a new run fails.

---

## Testing

Backend tests should cover:

- auth requirement
- invalid window validation
- cooldown behavior
- report persistence and list/detail endpoints
- lane parser behavior with synthetic log fixtures
- `srsopsmonitoring` extraction from message text
- failed lane does not fail whole report
- Ollama failure still returns deterministic report
- retention keeps newest reports

Frontend/source tests should cover:

- nav link exists
- page has one primary run button
- report sections render from fixture data
- evidence samples collapsed by default
- error state preserves readable message

Nginx test should cover:

- `/api/opensrs-health/` route exists.

---

## Implementation Boundaries

The first implementation should favor simple, explicit code:

- No background workers unless synchronous request runtime is unacceptable.
- No generalized query builder.
- No free-form report configuration.
- No frontend charting library unless simple table/timeline UI is insufficient.
- No Slack integration until report format has settled.

The MVP is useful when an SRE can click one button and quickly answer:

- Are customer-like OpenSRS flows showing failures?
- Are API/request logs showing broad errors or latency?
- Are registry/EPP dependencies degraded?
- Do symptoms correlate in time?
- What should I inspect next?

---

## Open Questions for Implementation Planning

Implementation planning should inspect production-like log examples if available. The approved design can proceed without exact examples by writing parsers around fixtures and keeping query templates configurable through code constants.

Areas to confirm during planning:

- Exact Loki labels for OpenSRS API/app logs.
- Exact message patterns for `srsopsmonitoring`.
- Best registry/EPP query reuse point: call Loki directly from `opensrs-health-api` or share helper logic with `loki-gateway`.
- Whether report run should be synchronous in MVP or async with polling.
