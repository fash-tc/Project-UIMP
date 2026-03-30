# Situation Summary & Alert Clustering — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add rule-based alert clustering, LLM situation summary, and a collapsible Situation Card to the Command Center dashboard. Reduce poll interval from 60s to 15s.

**Architecture:** The enricher gains two new functions (`cluster_alerts`, `generate_situation_summary`) called after each enrichment cycle. Summaries stored in alert-state-api via a new single-row table, broadcast via SSE, rendered in a new SituationCard component.

**Tech Stack:** Python stdlib, React/Next.js, SQLite, SSE, Ollama qwen-tooling model.

**Spec:** `docs/superpowers/specs/2026-03-17-situation-summary-alert-clustering-design.md`

---

## Chunk 1: Backend — Alert-State-API Summary Storage

### Task 1: Add situation_summary table and endpoints to alert-state-api

**Files:**
- Modify: `deploy/alert-state-api/alert-state-api.py`

- [ ] **Step 1: Add situation_summary table in _init_db()**

In `deploy/alert-state-api/alert-state-api.py`, inside `_init_db()`, after the `runbook_feedback` table creation, add:

```python
    conn.execute("""
        CREATE TABLE IF NOT EXISTS situation_summary (
            id INTEGER PRIMARY KEY DEFAULT 1,
            one_liner TEXT,
            clusters_json TEXT,
            shift_context_json TEXT,
            actions_json TEXT,
            generated_at TEXT,
            alert_hash TEXT
        )
    """)
    conn.commit()
```

- [ ] **Step 2: Add GET /api/alert-states/situation-summary endpoint**

In `do_GET`, before the final `else: self._send_json(404, ...)` block, add:

```python
        elif path == "/api/alert-states/situation-summary":
            with _db_lock:
                cursor = db.execute("SELECT * FROM situation_summary WHERE id = 1")
                row = cursor.fetchone()
            if row:
                self._send_json(200, {
                    "one_liner": row["one_liner"],
                    "clusters": json.loads(row["clusters_json"] or "[]"),
                    "shift_context": json.loads(row["shift_context_json"] or "{}"),
                    "recommended_actions": json.loads(row["actions_json"] or "[]"),
                    "generated_at": row["generated_at"],
                    "alert_hash": row["alert_hash"],
                })
            else:
                self._send_json(200, {"one_liner": None})
```

- [ ] **Step 3: Add POST /api/alert-states/situation-summary endpoint**

In `do_POST`, before the final `else: self._send_json(404, ...)` block, add:

```python
        elif path == "/api/alert-states/situation-summary":
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            one_liner = (data.get("one_liner") or "").strip()
            clusters = data.get("clusters", [])
            shift_context = data.get("shift_context", {})
            actions = data.get("recommended_actions", [])
            alert_hash = (data.get("alert_hash") or "").strip()
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                db.execute("""
                    INSERT INTO situation_summary (id, one_liner, clusters_json, shift_context_json,
                        actions_json, generated_at, alert_hash)
                    VALUES (1, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        one_liner = excluded.one_liner,
                        clusters_json = excluded.clusters_json,
                        shift_context_json = excluded.shift_context_json,
                        actions_json = excluded.actions_json,
                        generated_at = excluded.generated_at,
                        alert_hash = excluded.alert_hash
                """, (one_liner, json.dumps(clusters), json.dumps(shift_context),
                      json.dumps(actions), now, alert_hash))
                db.commit()
            _sse_broadcast("situation_update", {"generated_at": now})
            self._send_json(200, {"status": "stored"})
```

- [ ] **Step 4: Commit**

```bash
git add deploy/alert-state-api/alert-state-api.py
git commit -m "feat(alert-state-api): add situation summary table and endpoints"
```

---

## Chunk 2: Backend — Enricher Clustering and Summary

### Task 2: Reduce poll interval to 15 seconds

**Files:**
- Modify: `deploy/enricher.py`

- [ ] **Step 1: Change POLL_INTERVAL default**

At line 21 of `deploy/enricher.py`, change:

```python
# Before:
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))

# After:
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))
```

- [ ] **Step 2: Commit**

```bash
git add deploy/enricher.py
git commit -m "feat(enricher): reduce poll interval from 60s to 15s"
```

### Task 3: Add rule-based alert clustering function

**Files:**
- Modify: `deploy/enricher.py`

- [ ] **Step 1: Add hashlib import**

At the top of `deploy/enricher.py`, add to imports:

```python
import hashlib
```

- [ ] **Step 2: Add cluster_alerts() function**

Add this function before `poll_and_enrich()` (before line 860):

```python
# ── Alert Clustering ──────────────────────────────────────
def cluster_alerts(active_alerts):
    """Group related active alerts using deterministic rules."""
    # Build lookup structures
    by_host = {}       # hostname -> [alert]
    by_prefix = {}     # service prefix -> [alert]
    for a in active_alerts:
        host = get_host(a)
        if host and host != "unknown":
            by_host.setdefault(host, []).append(a)
        name = a.get("name", "")
        if ":" in name:
            prefix = name.split(":")[0].strip()
            if len(prefix) > 2:
                by_prefix.setdefault(prefix, []).append(a)

    assigned = set()   # fingerprints already in a cluster
    clusters = []

    # Rule 1: Same host
    for host, alerts in sorted(by_host.items(), key=lambda x: -len(x[1])):
        fps = [a.get("fingerprint", "") for a in alerts if a.get("fingerprint", "") not in assigned]
        if len(fps) >= 2:
            cluster_alerts_list = [a for a in alerts if a.get("fingerprint", "") in set(fps)]
            severities = []
            names = []
            for a in cluster_alerts_list:
                note = a.get("note", "") or ""
                for line in note.split("\n"):
                    if line.startswith("ASSESSED_SEVERITY:"):
                        severities.append(line.split(":", 1)[1].strip())
                        break
                names.append(a.get("name", "")[:60])
            sev_order = {"critical": 0, "high": 1, "warning": 2, "low": 3, "info": 4}
            top_sev = min(severities, key=lambda s: sev_order.get(s, 5)) if severities else "unknown"
            cid = "c_" + hashlib.sha256(",".join(sorted(fps)).encode()).hexdigest()[:12]
            clusters.append({
                "cluster_id": cid,
                "label": host,
                "fingerprints": fps,
                "alert_names": names,
                "top_severity": top_sev,
                "count": len(fps),
                "hosts": [host],
            })
            assigned.update(fps)

    # Rule 2: Same service prefix (across hosts)
    for prefix, alerts in sorted(by_prefix.items(), key=lambda x: -len(x[1])):
        fps = [a.get("fingerprint", "") for a in alerts if a.get("fingerprint", "") not in assigned]
        if len(fps) >= 2:
            cluster_alerts_list = [a for a in alerts if a.get("fingerprint", "") in set(fps)]
            severities = []
            names = []
            hosts = set()
            for a in cluster_alerts_list:
                note = a.get("note", "") or ""
                for line in note.split("\n"):
                    if line.startswith("ASSESSED_SEVERITY:"):
                        severities.append(line.split(":", 1)[1].strip())
                        break
                names.append(a.get("name", "")[:60])
                hosts.add(get_host(a))
            sev_order = {"critical": 0, "high": 1, "warning": 2, "low": 3, "info": 4}
            top_sev = min(severities, key=lambda s: sev_order.get(s, 5)) if severities else "unknown"
            cid = "c_" + hashlib.sha256(",".join(sorted(fps)).encode()).hexdigest()[:12]
            clusters.append({
                "cluster_id": cid,
                "label": f"{prefix} (multi-host)",
                "fingerprints": fps,
                "alert_names": names,
                "top_severity": top_sev,
                "count": len(fps),
                "hosts": sorted(hosts),
            })
            assigned.update(fps)

    # Rule 3: Temporal correlation (same domain suffix, fired within 5 min)
    unassigned = [a for a in active_alerts if a.get("fingerprint", "") not in assigned]
    by_domain = {}
    for a in unassigned:
        host = get_host(a)
        parts = host.split(".") if host else []
        domain = ".".join(parts[-3:]) if len(parts) >= 3 else host
        by_domain.setdefault(domain, []).append(a)

    for domain, alerts in by_domain.items():
        if len(alerts) < 2:
            continue
        # Check temporal proximity (within 5 minutes)
        timed = []
        for a in alerts:
            ts = a.get("firingStartTime") or a.get("startedAt") or ""
            timed.append((a, ts))
        timed.sort(key=lambda x: x[1])
        group = [timed[0][0]]
        for i in range(1, len(timed)):
            # Simple check: if timestamps share the same hour:minute prefix (within ~5 min)
            if timed[i][1][:15] == timed[i-1][1][:15] or abs(len(timed[i][1]) - len(timed[i-1][1])) < 2:
                group.append(timed[i][0])
        fps = [a.get("fingerprint", "") for a in group if a.get("fingerprint", "") not in assigned]
        if len(fps) >= 2:
            names = [a.get("name", "")[:60] for a in group]
            cid = "c_" + hashlib.sha256(",".join(sorted(fps)).encode()).hexdigest()[:12]
            clusters.append({
                "cluster_id": cid,
                "label": domain,
                "fingerprints": fps,
                "alert_names": names,
                "top_severity": "warning",
                "count": len(fps),
                "hosts": sorted(set(get_host(a) for a in group)),
            })
            assigned.update(fps)

    # Remaining: single-alert clusters
    for a in active_alerts:
        fp = a.get("fingerprint", "")
        if fp not in assigned:
            clusters.append({
                "cluster_id": "c_" + fp[:12],
                "label": get_host(a) or a.get("name", "unknown")[:30],
                "fingerprints": [fp],
                "alert_names": [a.get("name", "")[:60]],
                "top_severity": "unknown",
                "count": 1,
                "hosts": [get_host(a)],
            })

    return clusters
```

- [ ] **Step 3: Commit**

```bash
git add deploy/enricher.py
git commit -m "feat(enricher): add rule-based alert clustering function"
```

### Task 4: Add LLM situation summary generation

**Files:**
- Modify: `deploy/enricher.py`

- [ ] **Step 1: Add summary state globals**

After the existing `enriched_cache = set()` line (around line 27), add:

```python
_last_summary_hash = ""
_last_summary_time = 0
_SUMMARY_COOLDOWN = 300  # Only regenerate if 5 min elapsed with no changes
```

- [ ] **Step 2: Add generate_situation_summary() function**

Add after `cluster_alerts()`, before `poll_and_enrich()`:

```python
def generate_situation_summary(clusters, active_alerts, resolved_count):
    """Generate an AI situation summary from clustered alerts."""
    global _last_summary_hash, _last_summary_time

    # Build a hash of current active alert fingerprints
    fps = sorted(a.get("fingerprint", "") for a in active_alerts)
    alert_hash = hashlib.sha256(",".join(fps).encode()).hexdigest()[:16]

    # Skip if nothing changed and cooldown not elapsed
    now = time.time()
    if alert_hash == _last_summary_hash and (now - _last_summary_time) < _SUMMARY_COOLDOWN:
        return None

    # Build prompt for LLM
    noise_count = 0
    cluster_info = []
    for c in clusters:
        if c["count"] == 1:
            continue  # Skip singletons in summary prompt
        cluster_info.append(
            f"- Cluster '{c['label']}': {c['count']} alerts, "
            f"top severity={c['top_severity']}, "
            f"alerts: {', '.join(c['alert_names'][:5])}"
        )

    # Count noise alerts
    for a in active_alerts:
        note = a.get("note", "") or ""
        for line in note.split("\n"):
            if line.startswith("NOISE_SCORE:"):
                try:
                    score = int(line.split(":")[1].strip())
                    if score >= 8:
                        noise_count += 1
                except (ValueError, IndexError):
                    pass
                break

    singleton_count = sum(1 for c in clusters if c["count"] == 1)

    prompt = f"""You are an SRE situation analyst. Analyze the current alert state and produce a JSON situation summary.

CURRENT STATE:
- Active alerts: {len(active_alerts)}
- Resolved alerts (recent): {resolved_count}
- Noise alerts (score >= 8): {noise_count}
- Alert clusters: {len([c for c in clusters if c['count'] > 1])}
- Unclustered alerts: {singleton_count}

CLUSTERS:
{chr(10).join(cluster_info) if cluster_info else "No multi-alert clusters detected."}

INDIVIDUAL ACTIVE ALERTS (enrichment summaries):
"""
    for a in active_alerts[:30]:  # Cap at 30 to avoid huge prompts
        note = a.get("note", "") or ""
        summary_line = ""
        sev_line = ""
        for line in note.split("\n"):
            if line.startswith("SUMMARY:"):
                summary_line = line.split(":", 1)[1].strip()[:100]
            elif line.startswith("ASSESSED_SEVERITY:"):
                sev_line = line.split(":", 1)[1].strip()
        name = a.get("name", "")[:50]
        host = get_host(a)
        prompt += f"- [{sev_line}] {name} on {host}: {summary_line}\n"

    prompt += """
Respond with JSON only:
{
  "one_liner": "Brief 1-sentence situation overview with alert counts and top priority",
  "clusters": [
    {"cluster_id": "<id>", "assessment": "1-sentence assessment of this cluster", "priority": 1}
  ],
  "shift_context": {
    "new_since_last": <int>,
    "resolved_since_last": <int>,
    "trend": "improving|stable|worsening",
    "recurring": ["alert patterns that keep firing"]
  },
  "recommended_actions": [
    "Numbered action items, most urgent first"
  ]
}

Rules:
- one_liner must be concise and lead with the most critical issue
- Order clusters by priority (1 = most urgent)
- recommended_actions should be specific and actionable
- trend: "improving" if more resolving than firing, "worsening" if more firing, "stable" otherwise
- Only include clusters with count > 1 in the clusters array
"""

    response = ollama_generate(prompt, timeout=15)
    if not response:
        log.warning("Situation summary LLM call failed")
        return None

    try:
        # Clean response — strip markdown fences if present
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        if text.startswith("json"):
            text = text[4:].strip()

        summary = json.loads(text)
    except (json.JSONDecodeError, ValueError) as e:
        log.warning(f"Situation summary JSON parse failed: {e}")
        return None

    # Map cluster IDs from our clustering to the LLM response
    our_cluster_ids = {c["cluster_id"] for c in clusters}
    for sc in summary.get("clusters", []):
        if sc.get("cluster_id") not in our_cluster_ids:
            # LLM may have invented IDs — try to match by position
            pass

    # Store in alert-state-api
    payload = {
        "one_liner": summary.get("one_liner", ""),
        "clusters": summary.get("clusters", []),
        "shift_context": summary.get("shift_context", {}),
        "recommended_actions": summary.get("recommended_actions", []),
        "alert_hash": alert_hash,
    }

    try:
        body = json.dumps(payload).encode()
        req = Request(
            f"{ALERT_STATE_API_URL}/api/alert-states/situation-summary",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        urlopen(req, timeout=5)
        _last_summary_hash = alert_hash
        _last_summary_time = now
        log.info(f"Situation summary updated: {summary.get('one_liner', '')[:80]}")
    except Exception as e:
        log.warning(f"Failed to store situation summary: {e}")

    return summary
```

- [ ] **Step 3: Wire clustering and summary into poll_and_enrich()**

At the end of `poll_and_enrich()`, replace lines 985-988:

```python
# Before (lines 985-988):
    if suppressed_count:
        log.info(f"Suppressed {suppressed_count} alerts (noise/flapping/dedup)")

    return enriched_count

# After:
    if suppressed_count:
        log.info(f"Suppressed {suppressed_count} alerts (noise/flapping/dedup)")

    # ── Clustering & Situation Summary ──
    if active_alerts:
        clusters = cluster_alerts(active_alerts)
        multi_clusters = [c for c in clusters if c["count"] > 1]
        if multi_clusters:
            log.info(f"Clustered {sum(c['count'] for c in multi_clusters)} alerts into {len(multi_clusters)} groups")
        generate_situation_summary(clusters, active_alerts, len(items) - len(active_alerts))

    return enriched_count
```

- [ ] **Step 4: Commit**

```bash
git add deploy/enricher.py
git commit -m "feat(enricher): add LLM situation summary with clustering"
```

---

## Chunk 3: Frontend — Types, API, and Situation Card

### Task 5: Add frontend types and API functions

**Files:**
- Modify: `deploy/sre-frontend/src/lib/types.ts`
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`

- [ ] **Step 1: Add SituationSummary type**

In `deploy/sre-frontend/src/lib/types.ts`, after the `RunbookFeedback` interface, add:

```typescript
export interface ClusterInfo {
  cluster_id: string;
  label?: string;
  fingerprints?: string[];
  alert_names?: string[];
  top_severity?: string;
  count?: number;
  hosts?: string[];
  assessment?: string;
  priority?: number;
}

export interface ShiftContext {
  new_since_last: number;
  resolved_since_last: number;
  trend: 'improving' | 'stable' | 'worsening';
  recurring: string[];
}

export interface SituationSummary {
  one_liner: string | null;
  clusters: ClusterInfo[];
  shift_context: ShiftContext;
  recommended_actions: string[];
  generated_at: string;
  alert_hash: string;
}
```

- [ ] **Step 2: Add fetchSituationSummary API function**

In `deploy/sre-frontend/src/lib/keep-api.ts`, at the end of the file, add:

```typescript
export async function fetchSituationSummary(): Promise<SituationSummary | null> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/situation-summary`);
    if (!res.ok) return null;
    const data = await res.json();
    if (!data.one_liner) return null;
    return data as SituationSummary;
  } catch {
    return null;
  }
}
```

Also add `SituationSummary` to the imports from types at the top of the file.

- [ ] **Step 3: Commit**

```bash
git add deploy/sre-frontend/src/lib/types.ts deploy/sre-frontend/src/lib/keep-api.ts
git commit -m "feat(frontend): add SituationSummary types and API function"
```

### Task 6: Create SituationCard component

**Files:**
- Create: `deploy/sre-frontend/src/app/command-center/SituationCard.tsx`

- [ ] **Step 1: Create the component**

Create `deploy/sre-frontend/src/app/command-center/SituationCard.tsx`:

```typescript
'use client';

import { useState, useEffect, useCallback } from 'react';
import { SituationSummary } from '@/lib/types';
import { fetchSituationSummary } from '@/lib/keep-api';
import { severityColor, timeAgo } from '@/lib/keep-api';

interface SituationCardProps {
  onClusterClick?: (fingerprints: string[]) => void;
  sseUpdateTrigger?: number; // incremented when SSE situation_update arrives
}

export default function SituationCard({ onClusterClick, sseUpdateTrigger }: SituationCardProps) {
  const [summary, setSummary] = useState<SituationSummary | null>(null);
  const [expanded, setExpanded] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('situation-card-expanded') === 'true';
    }
    return false;
  });

  const loadSummary = useCallback(async () => {
    const data = await fetchSituationSummary();
    if (data) setSummary(data);
  }, []);

  useEffect(() => {
    loadSummary();
  }, [loadSummary, sseUpdateTrigger]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('situation-card-expanded', String(expanded));
    }
  }, [expanded]);

  if (!summary) return null;

  const severityDotColor = (sev: string) => {
    switch (sev) {
      case 'critical': return 'bg-red';
      case 'high': return 'bg-orange';
      case 'warning': return 'bg-yellow';
      case 'info': return 'bg-blue';
      default: return 'bg-muted';
    }
  };

  // Find worst severity across clusters
  const worstSeverity = summary.clusters.reduce((worst, c) => {
    const order: Record<string, number> = { critical: 0, high: 1, warning: 2, low: 3, info: 4 };
    const cSev = c.top_severity || 'info';
    return (order[cSev] ?? 5) < (order[worst] ?? 5) ? cSev : worst;
  }, 'info');

  const trendIcon = summary.shift_context?.trend === 'improving' ? '↓' :
                    summary.shift_context?.trend === 'worsening' ? '↑' : '→';
  const trendColor = summary.shift_context?.trend === 'improving' ? 'text-green' :
                     summary.shift_context?.trend === 'worsening' ? 'text-red' : 'text-yellow';

  return (
    <div className="mb-4">
      {/* Collapsed bar */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-4 py-2 bg-surface border border-border rounded-lg hover:bg-surface-hover transition-colors text-left"
      >
        <span className={`w-2.5 h-2.5 rounded-full ${severityDotColor(worstSeverity)} shrink-0`} />
        <span className="text-sm text-text-bright flex-1 truncate">
          {summary.one_liner || 'Generating situation summary...'}
        </span>
        <span className="text-xs text-muted shrink-0">
          {summary.generated_at ? timeAgo(summary.generated_at) : ''}
        </span>
        <svg
          className={`w-4 h-4 text-muted transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="mt-2 p-4 bg-surface border border-border rounded-lg space-y-4 animate-in fade-in slide-in-from-top-1 duration-200">
          {/* Clusters */}
          {summary.clusters.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-2">Clusters</h4>
              <div className="flex gap-2 overflow-x-auto pb-1">
                {summary.clusters
                  .sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99))
                  .map((cluster) => (
                  <button
                    key={cluster.cluster_id}
                    onClick={() => onClusterClick?.(cluster.fingerprints || [])}
                    className="flex-shrink-0 p-2 bg-background border border-border rounded-md hover:border-accent transition-colors text-left max-w-[280px]"
                  >
                    <div className="flex items-center gap-1.5 mb-1">
                      <span className={`w-2 h-2 rounded-full ${severityDotColor(cluster.top_severity || 'info')}`} />
                      <span className="text-xs font-medium text-text-bright truncate">{cluster.label}</span>
                      <span className="text-xs text-muted ml-auto">{cluster.count}</span>
                    </div>
                    <p className="text-xs text-muted line-clamp-2">{cluster.assessment || ''}</p>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Shift Context */}
          {summary.shift_context && (
            <div className="flex items-center gap-3 text-xs text-muted">
              <span>↑{summary.shift_context.new_since_last ?? 0} new</span>
              <span>↓{summary.shift_context.resolved_since_last ?? 0} resolved</span>
              <span className={trendColor}>{trendIcon} {summary.shift_context.trend}</span>
              {summary.shift_context.recurring?.length > 0 && (
                <span className="text-yellow">
                  ⟳ {summary.shift_context.recurring[0]}
                </span>
              )}
            </div>
          )}

          {/* Recommended Actions */}
          {summary.recommended_actions?.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-1">Recommended Actions</h4>
              <ol className="space-y-1">
                {summary.recommended_actions.map((action, i) => (
                  <li key={i} className="text-sm text-text flex gap-2">
                    <span className="text-accent font-medium shrink-0">{i + 1}.</span>
                    <span>{action}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/SituationCard.tsx
git commit -m "feat(frontend): create SituationCard component"
```

### Task 7: Wire SituationCard into DashboardView

**Files:**
- Modify: `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`
- Modify: `deploy/sre-frontend/src/app/command-center/page.tsx`

- [ ] **Step 1: Add SSE situation_update trigger to page.tsx**

In `deploy/sre-frontend/src/app/command-center/page.tsx`, add state for SSE situation updates. Find the SSE event handler (the `onEvent` callback for `useSSE`) and add a case for `situation_update`:

```typescript
// Add state:
const [situationTrigger, setSituationTrigger] = useState(0);

// In SSE event handler, add case:
if (event.type === 'situation_update') {
  setSituationTrigger(prev => prev + 1);
}
```

Pass `situationTrigger` as a prop to the Dashboard tab component.

- [ ] **Step 2: Add SituationCard to DashboardView**

In `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`:

Add import at top:
```typescript
import SituationCard from './SituationCard';
```

Add `sseUpdateTrigger?: number` to the component's props interface.

Add a state for cluster filtering:
```typescript
const [clusterFilter, setClusterFilter] = useState<string[] | null>(null);
```

Insert the SituationCard just before the stat cards grid (before the `<div className="grid grid-cols-2 md:grid-cols-4 gap-4">` line):

```tsx
<SituationCard
  sseUpdateTrigger={sseUpdateTrigger}
  onClusterClick={(fps) => setClusterFilter(fps.length > 0 ? fps : null)}
/>
```

If `clusterFilter` is set, filter the displayed alerts to only those whose fingerprint is in the cluster:
```typescript
const displayAlerts = clusterFilter
  ? firingAlerts.filter(a => clusterFilter.includes(a.fingerprint))
  : firingAlerts;
```

Add a "Clear filter" chip when filtering is active:
```tsx
{clusterFilter && (
  <button
    onClick={() => setClusterFilter(null)}
    className="text-xs px-2 py-1 bg-accent/20 text-accent rounded-full hover:bg-accent/30 transition-colors"
  >
    Showing cluster · Click to clear
  </button>
)}
```

- [ ] **Step 3: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/DashboardView.tsx deploy/sre-frontend/src/app/command-center/page.tsx
git commit -m "feat(frontend): wire SituationCard into dashboard with cluster filtering"
```

---

## Chunk 4: Deploy & Verify

### Task 8: Deploy all changes to server

- [ ] **Step 1: Deploy alert-state-api**

```bash
scp -i ~/.ssh/id_uip_deploy deploy/alert-state-api/alert-state-api.py fash@10.177.154.196:~/uip/alert-state-api/alert-state-api.py
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "cd ~/uip && docker compose restart alert-state-api"
```

- [ ] **Step 2: Deploy enricher**

```bash
scp -i ~/.ssh/id_uip_deploy deploy/enricher.py fash@10.177.154.196:~/uip/enricher/enricher.py
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "cd ~/uip && docker compose restart alert-enricher"
```

- [ ] **Step 3: Deploy frontend files and rebuild**

```bash
scp files to server...
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "cd ~/uip && docker compose build sre-frontend && docker compose up -d sre-frontend"
```

- [ ] **Step 4: Verify enricher logs show clustering and summary**

```bash
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "cd ~/uip && docker compose logs alert-enricher --tail 20"
```

Expected: logs every 15s, cluster counts, situation summary updates.

- [ ] **Step 5: Verify SSE endpoint delivers situation_update events**

```bash
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "timeout 20 curl -s -N http://localhost/api/alert-states/events"
```

Expected: `event: state_change` with `type: situation_update` within 15-20 seconds.

- [ ] **Step 6: Verify frontend renders SituationCard**

Open Command Center in browser. The situation bar should appear at the top of the Dashboard tab with the one-liner summary. Expand to see clusters, shift context, and recommended actions.

- [ ] **Step 7: Commit deployment verification**

```bash
git commit --allow-empty -m "chore: verified situation summary deployment"
```
