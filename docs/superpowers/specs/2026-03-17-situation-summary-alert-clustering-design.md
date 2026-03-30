# Situation Summary & Alert Clustering — Design Spec

**Date:** 2026-03-17
**Author:** fash + Claude
**Status:** Draft

---

## Goal

Add an AI-generated situation summary and smart alert clustering to the UIP Command Center dashboard. The enricher generates a real-time "situation report" each cycle that gives on-call SREs an instant understanding of what's happening, what's related, and what to do first.

## Architecture

The enricher (already running every poll cycle with full alert context) gains three new responsibilities after individual alert enrichment:

1. **Rule-based clustering** — deterministic grouping of related alerts
2. **LLM situation summary** — AI-generated narrative, cluster assessments, shift context, and recommended actions
3. **Summary storage** — writes to alert-state-api, broadcast via SSE to all dashboards

The frontend adds a collapsible Situation Card at the top of the Dashboard tab.

## Non-Goals

- Interactive AI chat (sub-project #2)
- Proactive trend detection / shift-handoff (sub-project #3)
- Changes to individual alert enrichment logic

---

## Component 1: Enricher — Poll Interval Reduction

**Change:** Reduce `POLL_INTERVAL` default from 60s to 15s.

The GH200 GPU completes enrichments in ~3 seconds. Most 15s cycles will have 0 new alerts and complete in <1s (fetch → filter → skip cached → done). This makes new alerts visible within 15 seconds of arriving in Keep.

No other changes needed — the enricher already skips cached/enriched alerts.

---

## Component 2: Enricher — Rule-Based Clustering

**New function: `cluster_alerts(active_alerts) -> list[Cluster]`**

Runs after enrichment, before summary generation. Groups active alerts deterministically using three rules applied in order:

### Rule 1: Same Host
Alerts sharing a `hostname` value are grouped into a cluster.

### Rule 2: Same Service Prefix
Alerts with matching service/alert-name prefix (e.g., all "MySQL:" alerts, all "PostgreSQL:" alerts) across different hosts are grouped. Prefix is extracted as the text before the first `:` in the alert name.

### Rule 3: Temporal Correlation
Alerts on related infrastructure (same domain suffix, e.g., `*.dns1.tucows.net`) that first fired within 5 minutes of each other are merged into the same cluster.

### Cluster Structure

```python
{
    "cluster_id": "c_<hash>",          # deterministic ID from sorted fingerprints
    "label": "cdg01.dns1.tucows.net",  # host, service prefix, or generated label
    "fingerprints": ["abc...", "def..."],
    "alert_names": ["NTP Sync Down", "TRS DNS Tapper not running"],
    "top_severity": "critical",         # highest severity in the cluster
    "count": 2,
    "hosts": ["cdg01.dns1.tucows.net"],
}
```

Unclustered alerts remain as single-alert clusters (count=1). Clustering is purely deterministic — no LLM calls.

---

## Component 3: Enricher — LLM Situation Summary

**New function: `generate_situation_summary(clusters, active_alerts, resolved_count) -> dict`**

Called at the end of each poll cycle, but **only when**:
- Active alerts exist, AND
- Either the active alert set changed (detected via hash of sorted fingerprints) OR 5 minutes elapsed since last summary

This avoids redundant LLM calls when nothing has changed.

### Prompt

Sends to `qwen-tooling` model:
- Cluster list with labels, severities, alert names, and hosts
- Total active count, noise count (noise_score >= 8), recently resolved count
- Delta since last summary (new alerts, resolved alerts)
- Existing enrichment summaries for each alert (already available from the enrichment step)

### Response Format (JSON)

```json
{
    "one_liner": "3 active incidents across 2 hosts; 24 noise alerts suppressed. Priority: cdg01 DNS cluster.",
    "clusters": [
        {
            "cluster_id": "c_abc123",
            "assessment": "DNS node cdg01 has NTP sync failure and Tapper process down — likely a node-level issue affecting DNS resolution.",
            "priority": 1
        },
        {
            "cluster_id": "c_def456",
            "assessment": "PostgreSQL service down on db-primary — active incident, failover in progress.",
            "priority": 2
        }
    ],
    "shift_context": {
        "new_since_last": 4,
        "resolved_since_last": 2,
        "trend": "stable",
        "recurring": ["High Memory on dns nodes (fired 12 times today)"]
    },
    "recommended_actions": [
        "Investigate cdg01 DNS cluster first — 2 critical alerts, DNS resolution at risk",
        "PostgreSQL is stable-degraded — monitor, no immediate action needed"
    ]
}
```

### Error Handling

If LLM fails or times out, the summary is not updated — the previous summary remains displayed. A warning is logged but the enricher continues normally. The situation summary is enhancement-only; its failure must never block alert enrichment.

---

## Component 4: Alert-State-API — Summary Storage

### New Table

```sql
CREATE TABLE IF NOT EXISTS situation_summary (
    id INTEGER PRIMARY KEY DEFAULT 1,
    one_liner TEXT,
    clusters_json TEXT,
    shift_context_json TEXT,
    actions_json TEXT,
    generated_at TEXT,
    alert_hash TEXT
);
```

Single-row table — always overwritten (upsert on id=1). The `alert_hash` is stored so the enricher can compare on next cycle and skip regeneration if unchanged.

### New Endpoints

**`POST /api/alert-states/situation-summary`** — Enricher writes the summary. Body:
```json
{
    "one_liner": "...",
    "clusters": [...],
    "shift_context": {...},
    "recommended_actions": [...],
    "alert_hash": "sha256..."
}
```

**`GET /api/alert-states/situation-summary`** — Frontend fetches current summary. Returns the stored JSON. Returns `{"one_liner": null}` if no summary exists yet.

### SSE Broadcast

When summary is written, broadcast:
```
event: state_change
data: {"type": "situation_update", "generated_at": "2026-03-17T17:30:00Z"}
```

Frontend receives this event and re-fetches the full summary via GET (rather than embedding the full summary in the SSE payload).

---

## Component 5: Frontend — Situation Card

### Collapsed State (always visible)

A single-line bar at the top of the Dashboard tab, above stat cards:

```
[●] 3 active incidents across 2 hosts; 24 noise alerts suppressed. Priority: investigate cdg01 DNS cluster.  [▼]
```

- Left dot colored by worst active severity (red = critical, orange = high, yellow = warning, green = all clear)
- Text is the `one_liner` from the summary
- Chevron on right toggles expansion
- Live-updates via SSE: on `situation_update` event, re-fetch summary and fade-transition the text
- If no active alerts: "All clear — no active incidents" in green

### Expanded State

Three sections inside the card:

**1. Clusters** — Horizontal scrollable row of mini-cards:
- Cluster label (host or service name)
- Alert count badge
- Top severity colored dot
- One-line AI assessment from the `clusters[].assessment` field
- Clicking a cluster filters the dashboard table to show only those alerts
- Ordered by priority (from LLM response)

**2. Shift Context** — Single compact line:
```
↑4 new  ↓2 resolved  → stable  ⟳ "High Memory on dns nodes" (12× today)
```
- Trend arrow colored: green (improving), yellow (stable), red (worsening)
- Recurring patterns listed inline

**3. Recommended Actions** — Numbered list, one line each:
1. *Investigate cdg01 DNS cluster first — 2 critical alerts, DNS resolution at risk*
2. *PostgreSQL is stable-degraded — monitor, no immediate action needed*

Clicking an action scrolls to and highlights the relevant cluster's alerts in the dashboard table.

### Behavior

- Expanded/collapsed state persisted in `localStorage`
- Subtle "Updated 30s ago" timestamp in the corner
- No layout shift — collapsed bar is a fixed-height single line; expanded card pushes content down with a smooth CSS transition
- Summary fetched on initial load + on each SSE `situation_update` event

---

## Data Flow

```
Every 15 seconds:
  Enricher polls Keep
  → Enriches new/un-enriched alerts (3s each on GH200)
  → cluster_alerts() groups active alerts deterministically
  → If alert set changed or 5min elapsed:
      generate_situation_summary() calls qwen-tooling LLM (~3-5s)
      → POST summary to alert-state-api
      → alert-state-api stores + broadcasts SSE event
      → All connected dashboards re-fetch summary
      → Situation Card updates with fade transition
```

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Summary generation adds latency to enrichment cycle | Summary runs *after* all enrichments complete; skipped if alert set unchanged |
| LLM timeout delays next poll cycle | 15s timeout on summary generation; failure is non-blocking |
| Overlapping cycles if enrichment + summary > 15s | Track cycle duration; skip summary if previous cycle took > 12s |
| Cluster heuristics group unrelated alerts | LLM summary can note when grouping seems wrong; users can click through to verify |
| SSE summary payload too large | SSE sends only a notification; frontend does a GET for full payload |
