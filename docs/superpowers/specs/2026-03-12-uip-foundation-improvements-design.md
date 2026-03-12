# UIP Foundation Improvements — Design Spec

**Date:** 2026-03-12
**Author:** fash + Claude
**Status:** Draft
**Scope:** Fix the foundation — LLM performance, feedback quality, noise suppression, Grafana IRM escalation, UI fixes

---

## 1. Context

UIP is the Unified Incident Management Platform used by the Tucows Domains SRE team. It ingests Zabbix alerts via Keep, enriches them with a local LLM (Ollama), and provides a command center for triage, investigation, and incident response.

**Current pain points:**
- LLM enrichment is slow (Qwen 2.5 7B running on CPU-only, 8 vCPUs, no GPU)
- SRE feedback corrections don't reliably improve future enrichments
- Alert noise is scored but not acted on — flapping alerts waste LLM cycles
- No escalation path from UIP to Grafana IRM (SREs must leave UIP to page someone)
- Health page references removed Zabbix Poller service
- Enricher still has code paths that could auto-query Loki (resource-heavy)
- Navigation is overcrowded, registry trends are hard to read, Keep UI throws 401

**Server hardware:** AMD EPYC 8 vCPUs, 24GB RAM, no GPU. Ollama currently consumes 7.5GB.

---

## 2. LLM Model Swap & Performance

### Change
Replace `qwen2.5:7b` (4.6GB) with `qwen2.5:3b` (~2GB loaded).

### Why
Same model family, identical prompt format. 3B runs 2-3x faster on CPU for structured extraction tasks (severity assessment, cause hypothesis, remediation steps). The enrichment prompt is highly structured with explicit field names — this is where smaller models perform closest to their larger siblings.

### Implementation
- **docker-compose.yml:** Change `OLLAMA_MODEL` from `qwen2.5:7b` to `qwen2.5:3b`
- **docker-compose.yml:** Reduce Ollama memory limit from `8g` to `4g`
- **enricher.py:** Reduce the existing 120-second Ollama timeout to 45 seconds (3B model should complete in 15-30s on this hardware). If Ollama doesn't respond within 45s, retry once. If second attempt fails, tag alert note with `ENRICHMENT_PENDING: LLM timeout — will retry next cycle` and move on.
- **enricher.py:** Trim prompt context — only include service dependencies relevant to the alert's service/host, not the full dependency map.

### Rollback
Single env var change: `OLLAMA_MODEL=qwen2.5:7b`, Ollama memory limit back to `8g`.

### Validation
- Compare enrichment quality on 10 recent alerts: run both models, diff outputs
- Measure tokens/sec before and after
- Confirm memory usage drops by ~3GB

---

## 3. Structured Feedback Store

### Problem
Enricher fetches the last N feedback entries regardless of relevance. An EPP timeout correction gets included when enriching a DNS alert, wasting context tokens and confusing the model.

### Change
Add similarity-matched feedback retrieval so the enricher only sees corrections relevant to the alert it's currently processing.

### Schema
New table `feedback` in runbook.db:

```sql
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_pattern TEXT NOT NULL,        -- normalized alert name (lowercase, host stripped)
    service TEXT DEFAULT '',            -- service category (dns, epp, whois, etc.)
    severity_correction TEXT DEFAULT '',
    cause_correction TEXT DEFAULT '',
    remediation_correction TEXT DEFAULT '',
    full_text TEXT DEFAULT '',          -- free-form SRE notes
    sre_user TEXT NOT NULL,
    usefulness_score REAL DEFAULT 1.0,  -- decays over time
    created_at TEXT DEFAULT (datetime('now')),
    reinforced_at TEXT DEFAULT (datetime('now'))
);
```

### New runbook-api endpoints

**POST /api/runbook/feedback**
Store a structured correction. Body: `{ alert_name, hostname, service, severity_correction, cause_correction, remediation_correction, full_text, sre_user }`. Server normalizes `alert_name` into `alert_pattern` (lowercase, strip hostname suffix, remove timestamps).

**GET /api/runbook/feedback/match?alert_name=X&service=Y**
Retrieve top 5 feedback entries matching the alert. Scoring uses the same token-overlap fuzzy matching as runbook entry search, plus exact service match bonus. Results sorted by `(relevance_score * usefulness_score)`, most recent first for ties.

### Decay
On each retrieval query, apply a one-time halving: if `reinforced_at` is older than 90 days, set `usefulness_score = usefulness_score * 0.5` (applied once, not repeatedly). Entries below 0.1 score are excluded from retrieval (not deleted — kept for audit). The halving is a step function, not exponential — an entry is either "fresh" (score 1.0) or "stale" (score 0.5), and only drops further if manually scored down.

When a new feedback entry matches an existing pattern+service, update `reinforced_at` on the older entry to reset its decay clock (score returns to 1.0).

### Enricher change
Replace current feedback fetch with:
```
GET /api/runbook/feedback/match?alert_name={alert_name}&service={service}
```
Include results in prompt under heading: `SRE corrections for similar alerts:` with each entry showing the correction fields and the SRE who submitted it.

### Frontend change
Update the feedback form in the alert detail modal to submit structured fields directly. The enrichment display already shows separate severity/cause/remediation sections — add corresponding correction fields to the feedback form:
- **Severity correction** (dropdown: critical/high/warning/low/info, or "no change")
- **Cause correction** (text field)
- **Remediation correction** (text field)
- **Additional notes** (text field → stored as `full_text`)

This avoids ambiguous NLP parsing on the backend — the SRE tells us exactly which field they're correcting.

---

## 4. Noise Suppression Layer

### Problem
Flapping alerts generate dozens of enrichment requests. The enricher scores noise (1-10) but doesn't act on the score. Each instance gets a full Ollama inference cycle.

### Change
Add a pre-enrichment filter in the enricher's poll loop.

### Rules (evaluated in order)

1. **Flapping detection:** Same fingerprint resolved then re-fired within `FLAP_WINDOW` (default 10 min, env var). Tag alert note: `NOISE: FLAPPING — same alert resolved and re-fired {N} times in last hour. Enrichment suppressed.` Skip enrichment.

2. **Recent duplicate:** Same `alert_name` + same `host`, already enriched within `DEDUP_WINDOW` (default 30 min, env var). Copy the existing enrichment to the new alert's note with prefix: `ENRICHMENT (copied from {fingerprint} at {time}):`. Skip Ollama call.

3. **High noise pattern:** Previous enrichment of the same alert pattern had `NOISE_SCORE >= NOISE_THRESHOLD` (default 8, env var). Reuse previous enrichment with note: `NOISE: Score {score} from previous instance. Enrichment reused.` Skip Ollama call.

### Tracking
Enricher maintains an in-memory dict:
```python
recent_enrichments: dict[str, {
    fingerprint: str,
    alert_name: str,
    host: str,
    enrichment_text: str,
    noise_score: int,
    enriched_at: datetime,
    resolve_count: int,      # times resolved in last hour
    last_resolved_at: datetime
}]
```
Keyed by fingerprint. Evicted after 2 hours. On startup, the dict is empty — it populates naturally as the enricher processes alerts in its first few poll cycles. No need to backfill from existing alert notes (cold start means a few alerts may get redundantly enriched on restart, which is acceptable).

### Frontend
- Add "Suppressed" count to the dashboard tab bar: `Firing (12) | Acknowledged (3) | Suppressed (8)`
- Suppressed tab shows alerts with suppression reason
- Each suppressed alert has a "Force Enrich" button that calls `POST /api/alert-states/force-enrich` with the alert fingerprint

### Force-enrich mechanism
Uses alert-state-api (no HTTP listener needed in the enricher):
- **alert-state-api:** Add `force_enrich` boolean column to `alert_states` table. New endpoint `POST /api/alert-states/force-enrich` sets the flag for a given fingerprint.
- **enricher:** During each poll cycle, also fetches `GET /api/alert-states?force_enrich=true`. Any alerts returned are enriched immediately regardless of suppression rules. After enrichment, enricher calls `POST /api/alert-states/clear-force-enrich` to reset the flag.

### Env vars (on enricher service)
- `FLAP_WINDOW_SECONDS=600`
- `DEDUP_WINDOW_SECONDS=1800`
- `NOISE_THRESHOLD=8`

---

## 5. Grafana IRM Escalation

### Problem
SREs must leave UIP and manually create incidents in Grafana OnCall to page someone.

### New service: escalation-api (port 8094)

Lightweight Python HTTP service. Same stdlib pattern as auth-api, alert-state-api.

### Grafana OnCall API
Base URL: configurable via `GRAFANA_ONCALL_URL` env var (e.g. `https://oncall-prod-us-central-0.grafana.net/oncall/api/v1`)
Auth: `GRAFANA_ONCALL_API_KEY` env var, sent as `Authorization: {api_key}` header (no "Bearer" prefix — OnCall expects the raw token).
Required permission: `grafana-oncall-app.alert-groups:direct-paging`.

### Endpoints

**GET /api/escalation/teams**
Proxies `GET /api/v1/teams/` from Grafana OnCall. Returns list of `{ id, name }`. Cached in-memory for 5 minutes.

**GET /api/escalation/users**
Proxies `GET /api/v1/users/` from Grafana OnCall. Returns list of `{ id, name, email, is_currently_oncall }`. Cached 5 minutes.

**POST /api/escalation/escalate**
Body:
```json
{
    "team_id": "abc123",               // Grafana OnCall team ID — OR
    "user_ids": ["def456"],            // list of OnCall user IDs (with important flag)
    "alert_name": "...",
    "severity": "critical",
    "summary": "...",                  // from enrichment
    "message": "...",                  // optional SRE note
    "uip_link": "https://..."         // link back to alert in UIP
}
```
Uses the Grafana OnCall **Direct Paging API** (`POST /api/v1/escalation/`). Maps UIP fields to OnCall payload:
- `team_id` → `team` (routes through team's escalation chain)
- `user_ids` → `users` (array of `{id, important: true}`)
- `alert_name` + `severity` → `title`
- `summary` + `message` → `message`
- `uip_link` → `source_url`

Returns `{ success: true, incident_url: "https://..." }`.

Auth: Requires valid `uip_auth` cookie (verified same as other services).

### Docker compose
```yaml
escalation-api:
    image: python:3.12-slim
    container_name: uip-escalation-api
    volumes:
      - ./escalation-api/escalation-api.py:/app/escalation-api.py:ro
    command: ["python", "/app/escalation-api.py"]
    environment:
      - GRAFANA_ONCALL_URL=${GRAFANA_ONCALL_URL}
      - GRAFANA_ONCALL_API_KEY=${GRAFANA_ONCALL_API_KEY}
      - AUTH_SECRET=${AUTH_SECRET}
    networks:
      - uip-net
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: "0.25"
    restart: unless-stopped
```

### Nginx
```nginx
location /api/escalation/ {
    proxy_pass http://escalation-api:8094/api/escalation/;
}
```

### Frontend: Alert detail modal
Add "Escalate" button in the action bar (next to Resolve, Silence, Create Jira Incident):
- Click opens a popover with:
  - Radio: "Team" or "User"
  - Dropdown: populated from `/api/escalation/teams` or `/api/escalation/users`
  - Text field: "Additional context" (optional)
  - "Send Escalation" button
- On success: button changes to "Escalated" with link to Grafana OnCall incident
- On failure: show error message inline

### Health endpoint
Escalation-api exposes `GET /api/escalation/health` returning `{"status": "ok"}` for health-checker HTTP checks.

### Health checker
Add `escalation-api` (port 8094, HTTP check on `/api/escalation/health`) to monitored services list.

---

## 6. Enricher & Health Page Fixes

### Enricher: Verify Loki auto-query is fully removed
Previous session already removed `LOKI_GATEWAY_URL` from the enricher's docker-compose env and the `fetch_log_context()` function. **Verify** this is complete on the deployed server — no Loki env vars in the enricher container, no code paths that could auto-query Loki. If any remnants exist, remove them.

### Health checker: Update service list
- **health-checker.py:** Remove `zabbix-poller` / `uip-zabbix-poller` from the monitored services list
- **health-checker.py:** Add `auth-api` (8093), `alert-state-api` (8092), `loki-gateway` (8091), `escalation-api` (8094) to monitored services
- The health page frontend reads from the health-checker API dynamically — no frontend changes needed unless service names are hardcoded (verify)

---

## 7. UI Fixes

### Navigation restructure
Deliberately reverting the recent flat-links change (commit 206e829) — user feedback is that the top bar is too crowded. Change `layout.tsx` back to two dropdowns:

```
Command Center ▾          Settings ▾
├─ Dashboard              ├─ Settings
├─ Logs                   ├─ Health
├─ Registry               └─ AI Manage
└─ Maintenance
```

"Command Center" link itself navigates to `/portal/command-center`. Dropdown items are sub-pages. "Settings" link navigates to `/portal/settings`.

### Registry performance trends
- Add time range options: **5m, 15m, 30m, 1h** alongside existing 6h, 24h, 7d
- Change display from SVG TrendsChart to a **table** matching the "Load Health Data" display style:
  - Rows: one per operator
  - Columns: Operator name, Avg Response (ms), P95 (ms), Error Rate (%), Status indicator
  - Color-code status: green (healthy), yellow (degraded), red (down)
- Loki query optimization for small ranges:
  - Filter by specific operator agent regex (not `{app="ra"}` broadly)
  - Limit to 1000 entries max
  - Use step intervals proportional to range (5m range = 10s steps, 1h range = 60s steps)

### Keep API 401 fix
The Keep frontend calls `/alerts/query` directly (not through `/api/keep/`). Nginx needs to inject the `X-API-KEY` header on these paths too.

Add to nginx config:
```nginx
location /alerts/ {
    proxy_pass http://keep-api:8080/alerts/;
    proxy_set_header X-API-KEY $keep_api_key;
    # ... standard proxy headers
}
```

Verify other Keep frontend paths (`/preset/`, `/topology/`, `/workflows/`) also get the API key injected.

---

## 8. Deployment Order

1. **Health page & enricher fixes** (low risk, immediate value)
2. **LLM model swap** (low risk, easy rollback, immediate performance gain)
3. **Navigation & UI fixes** (frontend-only, no backend risk)
4. **Keep 401 fix** (nginx config change)
5. **Registry trends rework** (frontend + loki-gateway query changes)
6. **Structured feedback store** (new DB table + endpoints + enricher change)
7. **Noise suppression layer** (enricher logic change, new frontend tab)
8. **Grafana IRM escalation** (new service, new UI, requires Grafana API key)

---

## 9. Files Affected

### New files
- `deploy/escalation-api/escalation-api.py` — Grafana IRM escalation service

### Modified files
- `deploy/docker-compose.yml` — new escalation-api service, model swap, Ollama memory, remove enricher Loki env
- `deploy/enricher/enricher.py` — verify Loki removal, add noise suppression, reduce timeout, use feedback/match, trim context
- `deploy/health-checker.py` — remove zabbix-poller, add new services
- `deploy/nginx-default.conf` — add escalation-api route, fix Keep API key injection
- `deploy/runbook-api/runbook-api.py` — add feedback table, feedback endpoints
- `deploy/loki-gateway/loki-gateway.py` — optimize registry trends queries for small ranges
- `deploy/sre-frontend/src/app/layout.tsx` — dropdown navigation
- `deploy/sre-frontend/src/app/command-center/page.tsx` — escalation UI, suppressed tab
- `deploy/sre-frontend/src/app/command-center/DashboardView.tsx` — suppressed count badge
- `deploy/sre-frontend/src/app/registry/page.tsx` — trends table, small time ranges
- `deploy/alert-state-api/alert-state-api.py` — add force_enrich column and endpoints
- `deploy/sre-frontend/src/lib/keep-api.ts` — escalation API functions, feedback API functions

---

## 10. Out of Scope

- Cloud LLM fallback (Approach B — deferred)
- Shift handoff system (Approach C — future)
- SLA/error budget tracking (Approach C — future)
- Correlation engine (Approach C — future)
- Predictive alerting (Approach C — future)
- Multi-instance Zabbix webhook setup (separate task)
- n8n Slack routing workflows (separate task)
