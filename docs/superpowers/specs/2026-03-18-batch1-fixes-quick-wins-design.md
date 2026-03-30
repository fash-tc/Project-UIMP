# Batch 1: Fixes & Quick Wins — Design Spec

**Date:** 2026-03-18
**Scope:** 7 items — 4 fixes, 3 new features

---

## 1. Fix Unenriched Alerts

**Root cause:** `enriched_cache` is a permanent in-memory set. Once a fingerprint is added — even if the enrichment POST to Keep fails — it's never retried.

**Changes:**

### enricher.py
- Replace `enriched_cache = set()` with `enriched_cache = {}` (dict mapping fingerprint → timestamp)
- Only add to cache after confirmed successful write: move `enriched_cache[fingerprint] = time.time()` inside the success branch of `post_enrichment_to_keep`
- Each cycle, prune cache entries older than 600s (10 min) whose alerts still have no enrichment note — this forces a retry
- Same fix for suppression writes: only cache after successful suppression note write

### Frontend (DashboardView, AlertsTableView)
- Alerts with no enrichment note and no `ENRICHMENT_PENDING` marker: show "Enriching..." text with a subtle pulse animation
- Clicking "Enriching..." calls the existing `forceEnrich(fingerprint)` endpoint to trigger immediate enrichment
- After force-enrich, show "Enriching..." until the next SSE event confirms the enrichment landed

---

## 2. Fix Situation Card Display

**Changes to SituationCard.tsx:**

### Collapsed bar
- Prepend `✦ AI Summary` label (with sparkle icon) before the one-liner text, left-aligned
- Keep severity dot, one-liner, timestamp, and expand chevron

### Cluster cards
- Each card shows: severity dot + label + count badge (top line), then assessment text (second line)
- Fix current issue where only assessment text is visible with no header

### Cluster detail expansion
- Clicking a cluster card expands an inline detail panel below the cluster row showing:
  - Alert names in the cluster (bulleted list)
  - AI assessment (full text)
  - Hosts involved
  - "Filter alerts" button that applies the existing cluster filter to the table below
- Only one cluster can be expanded at a time (accordion behavior)

### Recommended actions
- Style numbered list with accent-colored numbers and proportional font
- Match dashboard text styling

---

## 3. Fix AI Chat

**Problem:** AI Chat redirects to port 9001 which is blocked by OpenStack security group.

**Solution:** Embed Open WebUI via iframe through port 80 proxy.

### nginx/default.conf
- Add location block `/ai-chat-api/` that proxies to `http://open-webui:8080/`
- Include WebSocket upgrade headers (`Upgrade`, `Connection`)
- Set `proxy_buffering off` for streaming responses
- Remove the port 9001 server block (no longer needed)

### docker-compose.yml
- Remove port 9001 mapping from nginx service

### sre-frontend AI Chat page
- Replace redirect with full-height iframe: `<iframe src="/ai-chat-api/" />`
- Style: `w-full h-[calc(100vh-4rem)] border-0` to fill available space

---

## 4. Improved Alert Clustering

### enricher.py — Rule 1.5: Domain pattern merge

After same-host clustering (Rule 1) and before same-prefix clustering (Rule 2), add a merge pass:

1. For each cluster label, normalize by stripping trailing digits from each hostname segment: `dns1` → `dns`, `phx01` → `phx`
2. Clusters with matching normalized patterns get merged into super-clusters
3. Super-cluster label uses wildcard: `dns*.tucows.net`
4. Fingerprints, alert names, and hosts are combined; top severity is worst across merged clusters

**Pattern extraction:**
```
phx01.dns1.tucows.net → phx.dns.tucows.net
sea01.dns1.tucows.net → sea.dns.tucows.net  (same cluster already — same host)
dns1.tucows.net cluster + dns2.tucows.net cluster → dns*.tucows.net
```

### enricher.py — LLM merge suggestions

Add to situation summary prompt:
- "If any clusters appear related but were not grouped together, suggest merges."
- New field in summary JSON: `"suggested_merges": [{"clusters": ["c_id1", "c_id2"], "reason": "..."}]`

### SituationCard.tsx
- Render suggested merges as a subtle hint in the expanded card: "AI suggests these clusters may be related: ..."
- No auto-merge — informational only

---

## 5. Auto-Investigate on Ticket Creation

### Frontend (IncidentForm in page.tsx and alert detail page)

After `storeIncidentState()` succeeds, immediately call the existing investigate endpoint:
```typescript
await fetch(`${ALERT_STATE_BASE}/investigate`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ fingerprint: alert.fingerprint }),
});
```

This triggers both `incident_created` and `investigate` SSE events — all open dashboards update in real-time.

---

## 6. Zabbix Follow-Back Link

### Frontend — Zabbix URL mapping

Config object mapping `zabbixInstance` to base URL:
```typescript
const ZABBIX_URLS: Record<string, string> = {
  'domains-shared': 'https://zabbix.bra2.tucows.cloud',
  'ascio': 'https://zabbix.ascio.net',
  'hostedemail': 'https://zabbix.hostedemail.com',
  'enom': 'https://zabbix.enom.net',
};
```

### Link construction
```
https://<zabbix-url>/zabbix.php?action=problem.view&filter_triggerids[]=<triggerId>
```

### Display (DashboardView, AlertsTableView)
- Small external-link icon on alert row, inline with existing badges
- Only visible when `triggerId` is present on the alert
- Tooltip: "View in Zabbix"
- Opens in new tab

---

## 7. Severity Override

### alert-state-api — New column and endpoint

Add to `alert_states` table:
```sql
severity_override TEXT,        -- e.g. "critical"
severity_override_by TEXT,     -- username
severity_override_at TEXT      -- ISO timestamp
```

New endpoint: `POST /api/alert-states/severity-override`
```json
{"fingerprint": "...", "severity": "critical"}
```

Stores override, broadcasts SSE `severity_override` event, and invalidates the situation summary cache by calling a new internal function that resets `_last_summary_hash`.

### alert-state-api — Summary invalidation

New endpoint: `POST /api/alert-states/invalidate-summary`
- Sets a flag that the enricher checks each cycle
- When flag is set, enricher clears `_last_summary_hash` to force summary regeneration

### Frontend — Severity dropdown

On the alert row, clicking the severity badge opens a small dropdown:
- Options: critical, high, warning, info
- Selecting one sends POST to severity-override endpoint
- Badge shows overridden severity with a small "manual" indicator (e.g., italic text or small dot)
- Original AI-assessed severity shown in tooltip: "AI assessed: warning, overridden to: critical by fash"

### Enricher — Respect overrides

When building the situation summary, fetch alert states including severity overrides. Use overridden severity instead of AI-assessed severity for clustering priority and recommended actions.
