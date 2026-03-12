# UIP Foundation Improvements — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve UIP performance, enrichment quality, noise handling, and add Grafana IRM escalation.

**Architecture:** 4 backend Python services modified (enricher, runbook-api, alert-state-api, health-checker), 1 new service created (escalation-api), nginx config updated, Next.js frontend updated. All services use Python 3.12 stdlib `http.server` pattern with SQLite/WAL. Deployment via SCP to 10.177.154.196.

**Tech Stack:** Python 3.12 stdlib, SQLite, Next.js 14, Tailwind CSS, Docker Compose, Ollama, Grafana OnCall API

**Spec:** `docs/superpowers/specs/2026-03-12-uip-foundation-improvements-design.md`

**Deployment:** SCP via `ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196`. Server path: `~/uip/`. No git on server. The full `sre-frontend/` tree already exists on the server from previous deployments — we SCP individual changed files then `docker compose up -d --build sre-frontend`.

**Path note:** The enricher source is at `deploy/enricher.py` locally but is mounted from `./enricher/enricher.py` on the server. SCP to `~/uip/enricher/enricher.py`.

**Important codebase conventions:**
- All Python services use `http.server.BaseHTTPRequestHandler` (no frameworks)
- Auth uses HMAC-SHA256 signed cookies (`uip_auth`), verified via `AUTH_SECRET` env var
- Frontend API calls go through `src/lib/keep-api.ts` helper functions
- Docker containers named `uip-{service-name}`, on `uip-net` bridge network
- Health checker monitors containers via Docker socket + HTTP checks

---

## Chunk 1: Health Page Fixes, LLM Model Swap & Enricher Performance

Low-risk changes with immediate impact. No new services, no schema changes.

### Task 1: Update health checker — add HTTP checks for new services, prep escalation-api

**Files:**
- Modify: `deploy/health-checker.py:19-41`

**Note:** The `DOCKER_CONTAINERS` dict already includes `auth-api`, `alert-state-api`, and `loki-gateway` (no `zabbix-poller` — already removed). But these three don't have HTTP health checks yet.

- [ ] **Step 1: Add escalation-api to DOCKER_CONTAINERS dict**

In `deploy/health-checker.py`, add to the `DOCKER_CONTAINERS` dict (after the `runbook-api` entry):

```python
    "escalation-api": {"display": "Escalation API",  "role": "IRM Escalation"},
```

- [ ] **Step 2: Add HTTP checks for all new services**

In the same file, add to the `HTTP_CHECKS` dict (after the `runbook-api` entry):

```python
    "auth-api":        "http://auth-api:8093/api/auth/login",
    "alert-state-api": "http://alert-state-api:8092/api/alert-states",
    "loki-gateway":    "http://loki-gateway:8091/api/loki/registry-health",
    "escalation-api":  "http://escalation-api:8094/api/escalation/health",
```

- [ ] **Step 3: Commit**

```bash
git add deploy/health-checker.py
git commit -m "feat(health): add HTTP checks for auth-api, alert-state-api, loki-gateway, escalation-api"
```

### Task 2: LLM model swap — docker-compose changes

**Files:**
- Modify: `deploy/docker-compose.yml:99-111` (ollama service)
- Modify: `deploy/docker-compose.yml:116-139` (enricher service)

- [ ] **Step 1: Change Ollama memory limit**

In `deploy/docker-compose.yml`, in the `ollama` service block, change:
```yaml
          memory: 8192M
```
to:
```yaml
          memory: 4096M
```

- [ ] **Step 2: Change default model**

In the `alert-enricher` service `environment` section, change:
```yaml
      OLLAMA_MODEL: ${OLLAMA_MODEL:-qwen2.5:7b}
```
to:
```yaml
      OLLAMA_MODEL: ${OLLAMA_MODEL:-qwen2.5:3b}
```

- [ ] **Step 3: Add noise suppression env vars to enricher**

In the `alert-enricher` service `environment` section, add after `RUNBOOK_API_URL`:
```yaml
      FLAP_WINDOW_SECONDS: "${FLAP_WINDOW_SECONDS:-600}"
      DEDUP_WINDOW_SECONDS: "${DEDUP_WINDOW_SECONDS:-1800}"
      NOISE_THRESHOLD: "${NOISE_THRESHOLD:-8}"
      ALERT_STATE_API_URL: "http://alert-state-api:8092"
```

- [ ] **Step 4: Commit**

```bash
git add deploy/docker-compose.yml
git commit -m "feat(docker): swap to qwen2.5:3b, reduce ollama memory, add noise suppression env vars"
```

### Task 3: Enricher — reduce timeout, add retry logic

**Files:**
- Modify: `deploy/enricher.py:326-347` (ollama_generate function)

- [ ] **Step 1: Update ollama_generate with 45s timeout and retry**

Replace the `ollama_generate` function at line 326 with:

```python
def ollama_generate(prompt, timeout=45):
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 768,
        },
    }).encode()
    req = Request(
        f"{OLLAMA_URL}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    for attempt in range(2):
        try:
            resp = urlopen(req, timeout=timeout)
            data = json.loads(resp.read())
            return data.get("response", "").strip()
        except Exception as e:
            if attempt == 0:
                log.warning(f"Ollama timeout/error (attempt 1), retrying: {e}")
                time.sleep(2)
            else:
                log.error(f"Ollama failed after 2 attempts: {e}")
    return None
```

- [ ] **Step 2: Update enrich_alert to handle ENRICHMENT_PENDING**

After the `ollama_generate` call in `enrich_alert` (line 620-628), update to tag pending alerts:

Replace:
```python
def enrich_alert(alert, similar_alerts):
    prompt = build_enrichment_prompt(alert, similar_alerts)
    response = ollama_generate(prompt)
    if not response:
        return None
```

With:
```python
def enrich_alert(alert, similar_alerts):
    prompt = build_enrichment_prompt(alert, similar_alerts)
    response = ollama_generate(prompt)
    if not response:
        # Tag alert as pending so it gets retried next cycle
        fingerprint = alert.get("fingerprint", "")
        if fingerprint:
            pending_note = "ENRICHMENT_PENDING: LLM timeout — will retry next cycle"
            keep_request("/alerts/enrich", method="POST", data={
                "fingerprint": fingerprint,
                "enrichments": {"note": pending_note},
            })
        return None
```

- [ ] **Step 3: Update poll_and_enrich to retry ENRICHMENT_PENDING alerts**

In `poll_and_enrich` (line 724-727), update the skip check to allow retrying pending alerts:

Replace:
```python
        note = alert.get("note", "") or ""
        if "---AI-ENRICHMENT-V2---" in note or note.startswith("AI Summary:"):
            enriched_cache.add(fingerprint)
            continue
```

With:
```python
        note = alert.get("note", "") or ""
        if "---AI-ENRICHMENT-V2---" in note or note.startswith("AI Summary:"):
            enriched_cache.add(fingerprint)
            continue
        # Allow retry of pending alerts (don't cache them)
        if note.startswith("ENRICHMENT_PENDING:"):
            log.info(f"Retrying pending enrichment: {alert.get('name', '')[:60]}")
        elif fingerprint in enriched_cache:
            continue
```

- [ ] **Step 4: Commit**

```bash
git add deploy/enricher.py
git commit -m "feat(enricher): reduce timeout to 45s, add retry logic, tag pending alerts"
```

### Task 4: Enricher — trim prompt context to relevant services only

**Files:**
- Modify: `deploy/enricher.py:402-500` (build_enrichment_prompt function)

The current `find_service_context` function (around line 82-95) builds context from the full SERVICE_DEPS map. It already filters by matching service name from the alert. Verify this works correctly and ensure only matched services are included.

- [ ] **Step 1: Verify find_service_context only returns relevant deps**

Read `deploy/enricher.py` lines 82-95 to confirm `find_service_context` filters properly. If it returns ALL services, modify it to only return the matched service and its immediate upstream/downstream.

- [ ] **Step 2: Limit service context in the prompt**

In `build_enrichment_prompt`, the `service_context` variable is already filtered. Ensure the prompt doesn't also include the full dependency map elsewhere. If it does, remove the full map and keep only the filtered context.

- [ ] **Step 3: Commit if changes were needed**

```bash
git add deploy/enricher.py
git commit -m "refactor(enricher): trim prompt context to relevant services only"
```

### Task 5: Deploy Chunk 1 to server

**Files:** All modified files from Tasks 1-4

- [ ] **Step 1: Upload modified files**

```bash
SSH_KEY=~/.ssh/id_uip_deploy
SERVER=fash@10.177.154.196

scp -i $SSH_KEY deploy/health-checker.py $SERVER:~/uip/health-checker/health-checker.py
scp -i $SSH_KEY deploy/docker-compose.yml $SERVER:~/uip/docker-compose.yml
scp -i $SSH_KEY deploy/enricher.py $SERVER:~/uip/enricher/enricher.py
```

- [ ] **Step 2: Pull the new model and restart affected services**

```bash
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker exec uip-ollama ollama pull qwen2.5:3b"
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker compose up -d ollama alert-enricher health-checker"
```

- [ ] **Step 3: Verify model swap worked**

```bash
ssh -i $SSH_KEY $SERVER "docker exec uip-ollama ollama ps"
# Expected: qwen2.5:3b loaded, ~2GB size
ssh -i $SSH_KEY $SERVER "docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}' uip-ollama"
# Expected: ~2-3GB instead of 7.5GB
```

- [ ] **Step 4: Verify enrichment still works**

```bash
ssh -i $SSH_KEY $SERVER "docker logs uip-alert-enricher --tail 20 2>&1"
# Expected: successful enrichment cycle, no errors
```

- [ ] **Step 5: Verify no Loki env vars on enricher (spec section 6)**

```bash
ssh -i $SSH_KEY $SERVER "docker exec uip-alert-enricher env | grep -i loki"
# Expected: no output (LOKI_GATEWAY_URL should not be present)
```

---

## Chunk 2: Nginx Fix (Keep 401) & Navigation

### Task 6: Fix Keep API 401 — inject API key on /alerts/ paths

**Files:**
- Modify: `deploy/nginx-default.conf:120-136`

- [ ] **Step 1: Add /alerts/ location with API key injection**

In `deploy/nginx-default.conf`, replace the existing `/alerts/event/` block (lines 121-128) and add a broader `/alerts/` block before it:

Insert after line 119 (after the maintenance location block closing `}`):

```nginx
    # -- Keep alerts API (for Keep UI — needs API key) --
    location /alerts/ {
        proxy_pass http://keep-api:8080/alerts/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-API-KEY "ca5ee58d-1a50-4817-aac5-9a538e40590d";
    }

    # -- Keep preset/topology/workflows (for Keep UI — needs API key) --
    location /preset/ {
        proxy_pass http://keep-api:8080/preset/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-API-KEY "ca5ee58d-1a50-4817-aac5-9a538e40590d";
    }

    location /topology/ {
        proxy_pass http://keep-api:8080/topology/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-API-KEY "ca5ee58d-1a50-4817-aac5-9a538e40590d";
    }

    location /workflows/ {
        proxy_pass http://keep-api:8080/workflows/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-API-KEY "ca5ee58d-1a50-4817-aac5-9a538e40590d";
    }
```

Remove the old `/alerts/event/` block (lines 121-128) since `/alerts/` now covers it.

- [ ] **Step 2: Commit**

```bash
git add deploy/nginx-default.conf
git commit -m "fix(nginx): inject Keep API key on /alerts/ and other Keep UI paths"
```

### Task 7: Navigation is already correct — verify

The `layout.tsx` already has the dropdown structure per the spec (Command Center dropdown with Dashboard/Logs/Registry/Maintenance, Settings dropdown with Settings/Health/AI Manage). This was updated by the user between sessions.

- [ ] **Step 1: Verify layout.tsx matches spec**

Read `deploy/sre-frontend/src/app/layout.tsx` and confirm it matches the spec's navigation structure. No changes needed if it already has the two NavDropdown components.

- [ ] **Step 2: Skip or commit if changes needed**

### Task 8: Deploy Chunk 2 to server

- [ ] **Step 1: Upload nginx config**

```bash
scp -i $SSH_KEY deploy/nginx-default.conf $SERVER:~/uip/nginx/default.conf
```

- [ ] **Step 2: Reload nginx**

```bash
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker compose restart nginx"
```

- [ ] **Step 3: Verify Keep UI no longer shows 401**

```bash
ssh -i $SSH_KEY $SERVER "curl -s -o /dev/null -w '%{http_code}' http://localhost/alerts/query"
# Expected: 200 (or valid JSON response), NOT 401
```

---

## Chunk 3: Registry Trends Rework

### Task 9: Add small time ranges to loki-gateway trends endpoint

**Files:**
- Modify: `deploy/loki-gateway/loki-gateway.py`

- [ ] **Step 1: Read the registry-trends endpoint handler**

Read `deploy/loki-gateway/loki-gateway.py` and find the `/api/loki/registry-trends` handler. Understand how it currently accepts range parameters and what step intervals it uses.

- [ ] **Step 2: Add support for small ranges with proportional steps**

Update the trends handler to:
- Accept range values: `5m`, `15m`, `30m`, `1h`, `6h`, `24h`, `7d`
- Map ranges to seconds: `{5m: 300, 15m: 900, 30m: 1800, 1h: 3600, 6h: 21600, 24h: 86400, 7d: 604800}`
- Set step intervals proportional to range:
  - 5m → 10s steps
  - 15m → 30s steps
  - 30m → 60s steps
  - 1h → 120s steps
  - 6h → 600s steps (existing)
  - 24h → 1800s steps (existing)
  - 7d → 21600s steps (existing)
- Limit results to 1000 entries max per query
- Filter by specific operator agent regex when an operator is specified (not broad `{app="ra"}`)

- [ ] **Step 3: Commit**

```bash
git add deploy/loki-gateway/loki-gateway.py
git commit -m "feat(loki-gateway): support small time ranges (5m-1h) with proportional step intervals"
```

### Task 10: Registry page — trends as table, small time ranges

**Files:**
- Modify: `deploy/sre-frontend/src/app/registry/page.tsx`
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`

- [ ] **Step 1: Read registry page to understand current trends UI**

Read `deploy/sre-frontend/src/app/registry/page.tsx` to find the TrendsChart component and range selector.

- [ ] **Step 2: Update fetchRegistryTrends in keep-api.ts**

Ensure `fetchRegistryTrends` accepts the new range values (`5m`, `15m`, `30m`, `1h`, `6h`, `24h`, `7d`) and passes them to the loki-gateway endpoint.

- [ ] **Step 3: Replace TrendsChart with TrendsTable**

In `registry/page.tsx`:
- Replace the SVG chart component with a table
- Table structure:
  - Header row: Operator | Avg Response (ms) | P95 (ms) | Error Rate (%) | Status
  - One row per operator
  - Status cell: colored dot — green (healthy: avg < 500ms, errors < 5%), yellow (degraded: avg < 2000ms, errors < 15%), red (down: above thresholds)
- Add time range pill buttons: `5m | 15m | 30m | 1h | 6h | 24h | 7d`
- Style to match the existing "Load Health Data" section's table style

- [ ] **Step 4: Commit**

```bash
git add deploy/sre-frontend/src/app/registry/page.tsx deploy/sre-frontend/src/lib/keep-api.ts
git commit -m "feat(registry): replace trends chart with table, add 5m-1h time ranges"
```

### Task 11: Deploy Chunk 3 to server

- [ ] **Step 1: Upload files**

```bash
scp -i $SSH_KEY deploy/loki-gateway/loki-gateway.py $SERVER:~/uip/loki-gateway/loki-gateway.py
scp -i $SSH_KEY deploy/sre-frontend/src/app/registry/page.tsx $SERVER:~/uip/sre-frontend/src/app/registry/page.tsx
scp -i $SSH_KEY deploy/sre-frontend/src/lib/keep-api.ts $SERVER:~/uip/sre-frontend/src/lib/keep-api.ts
```

- [ ] **Step 2: Rebuild frontend and restart loki-gateway**

```bash
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker compose up -d --build sre-frontend && docker compose restart loki-gateway"
```

- [ ] **Step 3: Verify trends load with small ranges**

Open the Registry page in browser, select "5m" range, click "Load Trends". Verify table displays with operator rows and no 400 errors.

---

## Chunk 4: Structured Feedback Store

### Task 12: Add feedback table and endpoints to runbook-api

**Files:**
- Modify: `deploy/runbook-api/runbook-api.py`

- [ ] **Step 1: Read runbook-api.py to understand current structure**

Read `deploy/runbook-api/runbook-api.py` fully. Note:
- `_init_db()` function and existing table creation
- `do_GET` / `do_POST` routing pattern
- Existing fuzzy match logic in the `/api/runbook/match` handler
- Auth verification pattern

- [ ] **Step 2: Add feedback table to _init_db**

In the `_init_db()` function, add after the existing table creation statements:

```python
    db.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_pattern TEXT NOT NULL,
            service TEXT DEFAULT '',
            severity_correction TEXT DEFAULT '',
            cause_correction TEXT DEFAULT '',
            remediation_correction TEXT DEFAULT '',
            full_text TEXT DEFAULT '',
            sre_user TEXT NOT NULL,
            usefulness_score REAL DEFAULT 1.0,
            created_at TEXT DEFAULT (datetime('now')),
            reinforced_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_feedback_pattern ON feedback(alert_pattern)")
```

- [ ] **Step 3: Add normalize_alert_pattern helper**

Add a helper function near the top of the file (after imports):

```python
def normalize_alert_pattern(alert_name, hostname=""):
    """Normalize alert name for feedback matching: lowercase, strip hostname suffix."""
    pattern = (alert_name or "").lower().strip()
    if hostname:
        host_lower = hostname.lower()
        for sep in [" on ", " for ", " at ", " - ", ": "]:
            idx = pattern.find(sep + host_lower)
            if idx != -1:
                pattern = pattern[:idx].strip()
                break
        if pattern.endswith(host_lower):
            pattern = pattern[:len(pattern) - len(host_lower)].rstrip(" -:")
    # Strip timestamps (common patterns like "2026-03-12" or "12:34:56")
    import re
    pattern = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?', '', pattern).strip()
    return pattern
```

- [ ] **Step 4: Add POST /api/runbook/feedback handler**

Add to the `do_POST` routing in the request handler:

```python
        elif path == "/api/runbook/feedback":
            username = self._get_username()
            if not username:
                return self._json_response({"error": "auth required"}, 401)

            alert_pattern = normalize_alert_pattern(
                body.get("alert_name", ""),
                body.get("hostname", "")
            )
            if not alert_pattern:
                return self._json_response({"error": "alert_name required"}, 400)

            service = (body.get("service") or "").lower().strip()
            sev = (body.get("severity_correction") or "").strip()
            cause = (body.get("cause_correction") or "").strip()
            remed = (body.get("remediation_correction") or "").strip()
            full = (body.get("full_text") or "").strip()

            # Check for existing matching entry — reinforce if found
            with _db_lock:
                existing = db.execute(
                    "SELECT id FROM feedback WHERE alert_pattern = ? AND service = ? AND sre_user = ?",
                    (alert_pattern, service, username)
                ).fetchone()
                if existing:
                    db.execute(
                        "UPDATE feedback SET reinforced_at = datetime('now'), usefulness_score = 1.0, "
                        "severity_correction = ?, cause_correction = ?, remediation_correction = ?, full_text = ? "
                        "WHERE id = ?",
                        (sev, cause, remed, full, existing["id"])
                    )
                    db.commit()
                    return self._json_response({"status": "reinforced", "id": existing["id"]})
                else:
                    cursor = db.execute(
                        "INSERT INTO feedback (alert_pattern, service, severity_correction, cause_correction, "
                        "remediation_correction, full_text, sre_user) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (alert_pattern, service, sev, cause, remed, full, username)
                    )
                    db.commit()
                    return self._json_response({"status": "created", "id": cursor.lastrowid})
```

- [ ] **Step 5: Add GET /api/runbook/feedback/match handler**

Add to the `do_GET` routing:

```python
        elif path == "/api/runbook/feedback/match":
            alert_name = params.get("alert_name", [""])[0]
            service = params.get("service", [""])[0].lower()
            if not alert_name:
                return self._json_response({"error": "alert_name required"}, 400)

            pattern = normalize_alert_pattern(alert_name)
            pattern_tokens = set(pattern.lower().split())
            stop_words = {"the", "a", "an", "is", "on", "for", "at", "in", "to", "of", "and", "or"}
            pattern_tokens -= stop_words

            with _db_lock:
                # Apply decay: one-time halve for entries not reinforced in 90 days (step function)
                db.execute(
                    "UPDATE feedback SET usefulness_score = 0.5 "
                    "WHERE reinforced_at < datetime('now', '-90 days') AND usefulness_score >= 1.0"
                )
                db.commit()

                rows = db.execute(
                    "SELECT * FROM feedback WHERE usefulness_score >= 0.1 ORDER BY created_at DESC LIMIT 100"
                ).fetchall()

            results = []
            for row in rows:
                row_tokens = set(row["alert_pattern"].lower().split()) - stop_words
                if not row_tokens:
                    continue
                overlap = len(pattern_tokens & row_tokens)
                if overlap == 0:
                    continue
                score = overlap / max(len(pattern_tokens), 1)
                # Bonus for exact service match
                if service and row["service"] == service:
                    score += 0.3
                results.append({
                    "id": row["id"],
                    "alert_pattern": row["alert_pattern"],
                    "service": row["service"],
                    "severity_correction": row["severity_correction"],
                    "cause_correction": row["cause_correction"],
                    "remediation_correction": row["remediation_correction"],
                    "full_text": row["full_text"],
                    "sre_user": row["sre_user"],
                    "score": round(score * row["usefulness_score"], 3),
                    "created_at": row["created_at"],
                })

            results.sort(key=lambda x: (-x["score"], x["created_at"]))
            return self._json_response(results[:5])
```

- [ ] **Step 6: Commit**

```bash
git add deploy/runbook-api/runbook-api.py
git commit -m "feat(runbook-api): add structured feedback table with similarity matching and decay"
```

### Task 13: Update enricher to use feedback/match endpoint

**Files:**
- Modify: `deploy/enricher.py:210-250` (feedback fetching)
- Modify: `deploy/enricher.py:441-453` (feedback context in prompt)

- [ ] **Step 1: Add fetch_feedback_matches function**

Add after the existing `fetch_runbook_entries` function (around line 230):

```python
def fetch_feedback_matches(alert_name, service=""):
    """Fetch structured SRE feedback corrections for similar alerts."""
    params = f"alert_name={quote(alert_name)}"
    if service:
        params += f"&service={quote(service)}"
    url = f"{RUNBOOK_API_URL}/api/runbook/feedback/match?{params}"
    req = Request(url, headers={"Content-Type": "application/json"})
    try:
        resp = urlopen(req, timeout=5)
        return json.loads(resp.read())
    except Exception as e:
        log.warning(f"Feedback match fetch failed: {e}")
        return []
```

Also add `from urllib.parse import quote` to the imports at the top if not already present.

- [ ] **Step 2: Replace feedback context in build_enrichment_prompt**

In `build_enrichment_prompt` (around lines 441-453), replace the existing SRE feedback context section with:

```python
    # Structured SRE feedback from similar alerts
    service = infer_service(alert)
    feedback_matches = fetch_feedback_matches(name, service)
    feedback_context = ""
    if feedback_matches:
        lines = ["\nSRE CORRECTIONS FOR SIMILAR ALERTS (apply these corrections to your analysis):"]
        for fb in feedback_matches:
            lines.append(f'  - Pattern: "{fb["alert_pattern"]}" (by {fb["sre_user"]})')
            if fb.get("severity_correction"):
                lines.append(f'    Severity should be: {fb["severity_correction"]}')
            if fb.get("cause_correction"):
                lines.append(f'    Cause correction: {fb["cause_correction"]}')
            if fb.get("remediation_correction"):
                lines.append(f'    Remediation: {fb["remediation_correction"]}')
            if fb.get("full_text"):
                lines.append(f'    Notes: {fb["full_text"][:200]}')
        lines.append("  IMPORTANT: Apply these SRE corrections to your assessment.\n")
        feedback_context = "\n".join(lines)
```

Keep `direct_feedback` (from alert note) as-is — it's still useful for per-alert corrections. But the `lessons_context` from FeedbackTracker can be removed or kept as a secondary signal (the structured feedback is now the primary source).

- [ ] **Step 3: Update the prompt string to include feedback_context**

In the final prompt assembly (around line 483), ensure `feedback_context` replaces or supplements `lessons_context` in the prompt string.

- [ ] **Step 4: Commit**

```bash
git add deploy/enricher.py
git commit -m "feat(enricher): use structured feedback matching instead of raw feedback ingestion"
```

### Task 14: Frontend — structured feedback form in alert detail modal

**Files:**
- Modify: `deploy/sre-frontend/src/app/command-center/page.tsx`
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`

- [ ] **Step 1: Add submitStructuredFeedback function to keep-api.ts**

**Note:** There is an existing `submitFeedback` function in keep-api.ts that writes to the alert note field. Keep it for backward compatibility. This new function calls the structured feedback endpoint.

Add to `deploy/sre-frontend/src/lib/keep-api.ts`:

```typescript
export async function submitStructuredFeedback(data: {
  alert_name: string;
  hostname: string;
  service: string;
  severity_correction: string;
  cause_correction: string;
  remediation_correction: string;
  full_text: string;
}): Promise<boolean> {
  try {
    const res = await fetch('/api/runbook/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return res.ok;
  } catch {
    return false;
  }
}
```

- [ ] **Step 2: Add structured feedback form to alert detail modal**

In `page.tsx`, find the existing SRE feedback section in the alert detail modal. Replace the free-text feedback form with structured fields:

- Severity correction dropdown: `no change | critical | high | warning | low | info`
- Cause correction textarea (2 rows)
- Remediation correction textarea (2 rows)
- Additional notes textarea (2 rows)
- Submit button that calls `submitFeedback()` with the alert's name, host, inferred service, and the correction fields

- [ ] **Step 3: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/page.tsx deploy/sre-frontend/src/lib/keep-api.ts
git commit -m "feat(frontend): add structured feedback form with severity/cause/remediation fields"
```

### Task 15: Deploy Chunk 4 to server

- [ ] **Step 1: Upload files**

```bash
scp -i $SSH_KEY deploy/runbook-api/runbook-api.py $SERVER:~/uip/runbook-api/runbook-api.py
scp -i $SSH_KEY deploy/enricher.py $SERVER:~/uip/enricher/enricher.py
scp -i $SSH_KEY deploy/sre-frontend/src/app/command-center/page.tsx $SERVER:~/uip/sre-frontend/src/app/command-center/page.tsx
scp -i $SSH_KEY deploy/sre-frontend/src/lib/keep-api.ts $SERVER:~/uip/sre-frontend/src/lib/keep-api.ts
```

- [ ] **Step 2: Restart backend services and rebuild frontend**

```bash
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker compose restart runbook-api alert-enricher && docker compose up -d --build sre-frontend"
```

- [ ] **Step 3: Verify feedback table was created**

```bash
ssh -i $SSH_KEY $SERVER "docker exec uip-runbook-api python3 -c \"
import sqlite3; db = sqlite3.connect('/data/runbook.db')
print(db.execute('SELECT name FROM sqlite_master WHERE type=\"table\"').fetchall())
\""
# Expected: includes ('feedback',)
```

---

## Chunk 5: Noise Suppression Layer

### Task 16: Add force_enrich to alert-state-api

**Files:**
- Modify: `deploy/alert-state-api/alert-state-api.py`

- [ ] **Step 1: Add force_enrich column to schema**

In `_init_db()`, add after the existing CREATE TABLE statement (around line 47):

```python
    # Add force_enrich column if it doesn't exist
    try:
        db.execute("ALTER TABLE alert_states ADD COLUMN force_enrich INTEGER DEFAULT 0")
        db.commit()
    except sqlite3.OperationalError:
        pass  # Column already exists
```

- [ ] **Step 2: Add POST /api/alert-states/force-enrich endpoint**

Add to the `do_POST` handler:

```python
        elif path == "/api/alert-states/force-enrich":
            fp = body.get("fingerprint", "")
            if not fp:
                return self._json({"error": "fingerprint required"}, 400)
            with _db_lock:
                db.execute(
                    "INSERT INTO alert_states (alert_fingerprint, force_enrich) VALUES (?, 1) "
                    "ON CONFLICT(alert_fingerprint) DO UPDATE SET force_enrich = 1, updated_at = CURRENT_TIMESTAMP",
                    (fp,)
                )
                db.commit()
            return self._json({"status": "queued"})
```

- [ ] **Step 3: Add POST /api/alert-states/clear-force-enrich endpoint**

```python
        elif path == "/api/alert-states/clear-force-enrich":
            fp = body.get("fingerprint", "")
            if not fp:
                return self._json({"error": "fingerprint required"}, 400)
            with _db_lock:
                db.execute(
                    "UPDATE alert_states SET force_enrich = 0, updated_at = CURRENT_TIMESTAMP "
                    "WHERE alert_fingerprint = ?", (fp,)
                )
                db.commit()
            return self._json({"status": "cleared"})
```

- [ ] **Step 4: Update GET /api/alert-states to support force_enrich filter**

In the `do_GET` handler for `/api/alert-states`, add support for `?force_enrich=true` query parameter that returns only rows where `force_enrich = 1`.

- [ ] **Step 5: Commit**

```bash
git add deploy/alert-state-api/alert-state-api.py
git commit -m "feat(alert-state-api): add force_enrich column and endpoints"
```

### Task 17: Add noise suppression logic to enricher

**Files:**
- Modify: `deploy/enricher.py`

- [ ] **Step 1: Add env var reads and tracking dict**

At the top of `enricher.py`, after the existing env var reads (around line 22):

```python
FLAP_WINDOW = int(os.environ.get("FLAP_WINDOW_SECONDS", "600"))
DEDUP_WINDOW = int(os.environ.get("DEDUP_WINDOW_SECONDS", "1800"))
NOISE_THRESHOLD = int(os.environ.get("NOISE_THRESHOLD", "8"))
ALERT_STATE_API_URL = os.environ.get("ALERT_STATE_API_URL", "http://alert-state-api:8092")

# In-memory tracking for noise suppression
recent_enrichments = {}  # fingerprint -> {alert_name, host, enrichment_text, noise_score, enriched_at, resolve_count, last_resolved_at}
```

- [ ] **Step 2: Add suppression check function**

Add a new function before `poll_and_enrich`:

```python
def check_suppression(alert):
    """Check if alert should be suppressed from enrichment. Returns (suppress: bool, reason: str, copied_enrichment: str|None)."""
    fp = alert.get("fingerprint", "")
    name = alert.get("name", "")
    host = get_host(alert)
    now = time.time()

    # Evict stale entries (older than 2 hours)
    stale = [k for k, v in recent_enrichments.items() if now - v["enriched_at"] > 7200]
    for k in stale:
        del recent_enrichments[k]

    # Rule 1: Flapping detection
    if fp in recent_enrichments:
        entry = recent_enrichments[fp]
        if entry.get("last_resolved_at") and (now - entry["last_resolved_at"]) < FLAP_WINDOW:
            count = entry.get("resolve_count", 0)
            return True, f"NOISE: FLAPPING — same alert resolved and re-fired {count} times in last hour. Enrichment suppressed.", None

    # Rule 2: Recent duplicate (same name+host already enriched)
    for efp, entry in recent_enrichments.items():
        if efp == fp:
            continue
        if entry["alert_name"] == name and entry["host"] == host:
            if (now - entry["enriched_at"]) < DEDUP_WINDOW:
                return True, f"ENRICHMENT (copied from {efp[:16]} at {time.strftime('%H:%M', time.localtime(entry['enriched_at']))}): duplicate suppressed.", entry["enrichment_text"]

    # Rule 3: High noise pattern
    for efp, entry in recent_enrichments.items():
        if entry["alert_name"] == name and entry.get("noise_score", 0) >= NOISE_THRESHOLD:
            return True, f"NOISE: Score {entry['noise_score']}/10 from previous instance. Enrichment reused.", entry["enrichment_text"]

    return False, "", None
```

- [ ] **Step 3: Add force-enrich check function**

```python
def fetch_force_enrich_fingerprints():
    """Get fingerprints that SREs have manually requested enrichment for."""
    try:
        req = Request(f"{ALERT_STATE_API_URL}/api/alert-states?force_enrich=true")
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return {item["alert_fingerprint"] for item in data}
    except Exception:
        return set()

def clear_force_enrich(fingerprint):
    """Clear the force_enrich flag after enrichment."""
    try:
        body = json.dumps({"fingerprint": fingerprint}).encode()
        req = Request(f"{ALERT_STATE_API_URL}/api/alert-states/clear-force-enrich",
                      data=body, headers={"Content-Type": "application/json"})
        urlopen(req, timeout=5)
    except Exception:
        pass
```

- [ ] **Step 4: Integrate suppression into poll_and_enrich**

In `poll_and_enrich`, after the resolved-alerts filter loop and before the enrichment loop (around line 718), add:

```python
    # Fetch force-enrich requests from SREs
    force_enrich_fps = fetch_force_enrich_fingerprints()
    suppressed_count = 0
```

Then in the enrichment loop, before calling `enrich_alert`, add the suppression check:

```python
        # Check noise suppression (skip if force-enriched)
        if fingerprint not in force_enrich_fps:
            suppress, reason, copied = check_suppression(alert)
            if suppress:
                # Write suppression note to Keep
                note_text = reason
                if copied:
                    note_text = copied  # Use the copied enrichment
                keep_request("/alerts/enrich", method="POST", data={
                    "fingerprint": fingerprint,
                    "enrichments": {"note": note_text},
                })
                enriched_cache.add(fingerprint)
                suppressed_count += 1
                log.info(f"  Suppressed: {name[:40]} — {reason[:60]}")
                continue
        else:
            log.info(f"  Force-enriching: {name[:40]} (requested by SRE)")
            clear_force_enrich(fingerprint)
```

After the enrichment loop, add:
```python
    if suppressed_count:
        log.info(f"Suppressed {suppressed_count} alerts (noise/flapping/dedup)")
```

- [ ] **Step 5: Track enrichment results in recent_enrichments dict**

After successful enrichment (where `enriched_cache.add(fingerprint)` is called), add:

```python
                recent_enrichments[fingerprint] = {
                    "alert_name": name,
                    "host": get_host(alert),
                    "enrichment_text": enrichment_note,  # the full note
                    "noise_score": int(enrichment.get("noise_score", 0)),
                    "enriched_at": time.time(),
                    "resolve_count": 0,
                    "last_resolved_at": None,
                }
```

And in the resolved alerts section (where status is "resolved"), track resolve counts:

```python
            if fp and fp in recent_enrichments:
                recent_enrichments[fp]["resolve_count"] = recent_enrichments[fp].get("resolve_count", 0) + 1
                recent_enrichments[fp]["last_resolved_at"] = time.time()
```

- [ ] **Step 6: Commit**

```bash
git add deploy/enricher.py
git commit -m "feat(enricher): add noise suppression layer (flapping, dedup, high-noise detection)"
```

### Task 18: Frontend — suppressed alerts tab

**Files:**
- Modify: `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`

- [ ] **Step 1: Add forceEnrich function to keep-api.ts**

```typescript
export async function forceEnrich(fingerprint: string): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/force-enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint }),
    });
    return res.ok;
  } catch {
    return false;
  }
}
```

- [ ] **Step 2: Add Suppressed tab to DashboardView**

In `DashboardView.tsx`, add a "Suppressed" tab alongside Firing and Acknowledged:

- Filter suppressed alerts: alerts whose note starts with `NOISE:` or `ENRICHMENT (copied`
- Add suppressed count badge to tab bar
- Each row shows alert name, host, and suppression reason (parsed from note)
- "Force Enrich" button per row that calls `forceEnrich(fingerprint)` then refreshes

- [ ] **Step 3: Add onForceEnrich prop and handler**

Add `onForceEnrich: (fingerprint: string) => Promise<void>` to DashboardViewProps. Wire it from page.tsx.

- [ ] **Step 4: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/DashboardView.tsx deploy/sre-frontend/src/lib/keep-api.ts
git commit -m "feat(frontend): add suppressed alerts tab with force-enrich button"
```

### Task 19: Deploy Chunk 5 to server

- [ ] **Step 1: Upload all modified files**

```bash
scp -i $SSH_KEY deploy/alert-state-api/alert-state-api.py $SERVER:~/uip/alert-state-api/alert-state-api.py
scp -i $SSH_KEY deploy/enricher.py $SERVER:~/uip/enricher/enricher.py
scp -i $SSH_KEY deploy/sre-frontend/src/app/command-center/DashboardView.tsx $SERVER:~/uip/sre-frontend/src/app/command-center/DashboardView.tsx
scp -i $SSH_KEY deploy/sre-frontend/src/lib/keep-api.ts $SERVER:~/uip/sre-frontend/src/lib/keep-api.ts
```

- [ ] **Step 2: Restart services and rebuild frontend**

```bash
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker compose restart alert-state-api alert-enricher && docker compose up -d --build sre-frontend"
```

- [ ] **Step 3: Verify suppression is working**

```bash
ssh -i $SSH_KEY $SERVER "docker logs uip-alert-enricher --tail 30 2>&1 | grep -i suppress"
# Expected: suppression log entries if any flapping/dedup alerts exist
```

---

## Chunk 6: Grafana IRM Escalation

### Task 20: Create escalation-api service

**Files:**
- Create: `deploy/escalation-api/escalation-api.py`

- [ ] **Step 1: Create directory**

```bash
mkdir -p deploy/escalation-api
```

- [ ] **Step 2: Write escalation-api.py**

Create `deploy/escalation-api/escalation-api.py` following the same stdlib pattern as auth-api and alert-state-api. The service:

- Runs on port 8094 (from `API_PORT` env var)
- Reads `GRAFANA_ONCALL_URL`, `GRAFANA_ONCALL_API_KEY`, `AUTH_SECRET` from env
- Uses `http.server.BaseHTTPRequestHandler`
- Auth verification: same HMAC-SHA256 cookie check pattern as other services

Endpoints:

**GET /api/escalation/health**
Returns `{"status": "ok"}`.

**GET /api/escalation/teams**
Proxies to `GET {GRAFANA_ONCALL_URL}/teams/` with `Authorization: {GRAFANA_ONCALL_API_KEY}` header. Caches result in-memory for 5 minutes. Returns `[{id, name}]`.

**GET /api/escalation/users**
Proxies to `GET {GRAFANA_ONCALL_URL}/users/` with auth header. Caches 5 min. Returns `[{id, name, email}]`.

**POST /api/escalation/escalate**
Requires auth cookie. Accepts body with `team_id` OR `user_ids`, plus `alert_name`, `severity`, `summary`, `message`, `uip_link`.
Makes `POST {GRAFANA_ONCALL_URL}/escalation/` with payload mapped per spec:
- `team_id` → `{"team": team_id, "title": f"[{severity}] {alert_name}", "message": summary + message, "source_url": uip_link}`
- `user_ids` → `{"users": [{"id": uid, "important": True} for uid in user_ids], "title": ..., "message": ..., "source_url": ...}`

Returns `{"success": true}` on 200/201 from OnCall, or `{"error": "..."}` with status from OnCall.

Full implementation should be ~200-250 lines.

- [ ] **Step 3: Add escalation-api to docker-compose.yml**

In `deploy/docker-compose.yml`, add before the nginx service block:

```yaml
  # ============================================
  # Escalation API — Grafana IRM Integration
  # ============================================
  escalation-api:
    image: python:3.12-slim
    container_name: uip-escalation-api
    restart: unless-stopped
    command: python3 -u /app/escalation-api.py
    volumes:
      - ./escalation-api/escalation-api.py:/app/escalation-api.py:ro
    environment:
      API_PORT: "8094"
      AUTH_SECRET: "${AUTH_SECRET}"
      GRAFANA_ONCALL_URL: "${GRAFANA_ONCALL_URL}"
      GRAFANA_ONCALL_API_KEY: "${GRAFANA_ONCALL_API_KEY}"
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: "0.25"
    networks:
      - uip-net
```

Also add `escalation-api` to nginx's `depends_on` list.

- [ ] **Step 4: Add escalation-api nginx route**

In `deploy/nginx-default.conf`, add after the loki-gateway location block:

```nginx
    # Escalation API — Grafana IRM integration
    location /api/escalation/ {
        proxy_pass http://escalation-api:8094/api/escalation/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
```

- [ ] **Step 5: Commit**

```bash
git add deploy/escalation-api/escalation-api.py deploy/docker-compose.yml deploy/nginx-default.conf
git commit -m "feat(escalation-api): create Grafana IRM escalation service with direct paging API"
```

### Task 21: Frontend — escalation UI in alert detail modal

**Files:**
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`
- Modify: `deploy/sre-frontend/src/app/command-center/page.tsx`

- [ ] **Step 1: Add escalation API functions to keep-api.ts**

```typescript
const ESCALATION_BASE = '/api/escalation';

export async function fetchEscalationTeams(): Promise<{id: string; name: string}[]> {
  try {
    const res = await fetch(`${ESCALATION_BASE}/teams`);
    if (!res.ok) return [];
    return await res.json();
  } catch { return []; }
}

export async function fetchEscalationUsers(): Promise<{id: string; name: string; email: string}[]> {
  try {
    const res = await fetch(`${ESCALATION_BASE}/users`);
    if (!res.ok) return [];
    return await res.json();
  } catch { return []; }
}

export async function escalateAlert(data: {
  team_id?: string;
  user_ids?: string[];
  alert_name: string;
  severity: string;
  summary: string;
  message: string;
  uip_link: string;
}): Promise<{success: boolean; error?: string}> {
  try {
    const res = await fetch(`${ESCALATION_BASE}/escalate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return await res.json();
  } catch {
    return { success: false, error: 'Network error' };
  }
}
```

- [ ] **Step 2: Add Escalate button and popover to alert detail modal**

In `page.tsx`, in the alert detail modal's action bar (near the Resolve and Silence buttons):

Add an "Escalate" button that:
- On click, toggles an escalation popover open/closed
- Popover contains:
  - Radio toggle: "Team" | "User"
  - Dropdown select populated by `fetchEscalationTeams()` or `fetchEscalationUsers()`
  - Textarea: "Additional context" (optional)
  - "Send Escalation" button
- On submit: calls `escalateAlert()` with the selected target and alert context
- On success: shows "✓ Escalated" state on the button
- On error: shows error message inline

State variables needed:
```typescript
const [showEscalation, setShowEscalation] = useState(false);
const [escalationType, setEscalationType] = useState<'team' | 'user'>('team');
const [escalationTarget, setEscalationTarget] = useState('');
const [escalationMessage, setEscalationMessage] = useState('');
const [escalating, setEscalating] = useState(false);
const [escalated, setEscalated] = useState(false);
const [teams, setTeams] = useState<{id: string; name: string}[]>([]);
const [users, setUsers] = useState<{id: string; name: string; email: string}[]>([]);
```

Fetch teams/users when popover opens:
```typescript
useEffect(() => {
  if (showEscalation) {
    fetchEscalationTeams().then(setTeams);
    fetchEscalationUsers().then(setUsers);
  }
}, [showEscalation]);
```

- [ ] **Step 3: Commit**

```bash
git add deploy/sre-frontend/src/lib/keep-api.ts deploy/sre-frontend/src/app/command-center/page.tsx
git commit -m "feat(frontend): add escalation button with team/user selection in alert detail modal"
```

### Task 22: Deploy Chunk 6 to server

**Prerequisites:** User must provide `GRAFANA_ONCALL_URL` and `GRAFANA_ONCALL_API_KEY` values to add to the server's `.env` file.

- [ ] **Step 1: Create escalation-api directory on server**

```bash
ssh -i $SSH_KEY $SERVER "mkdir -p ~/uip/escalation-api"
```

- [ ] **Step 2: Upload all files**

```bash
scp -i $SSH_KEY deploy/escalation-api/escalation-api.py $SERVER:~/uip/escalation-api/escalation-api.py
scp -i $SSH_KEY deploy/docker-compose.yml $SERVER:~/uip/docker-compose.yml
scp -i $SSH_KEY deploy/nginx-default.conf $SERVER:~/uip/nginx/default.conf
scp -i $SSH_KEY deploy/sre-frontend/src/lib/keep-api.ts $SERVER:~/uip/sre-frontend/src/lib/keep-api.ts
scp -i $SSH_KEY deploy/sre-frontend/src/app/command-center/page.tsx $SERVER:~/uip/sre-frontend/src/app/command-center/page.tsx
```

- [ ] **Step 3: Add Grafana OnCall env vars to server .env**

```bash
ssh -i $SSH_KEY $SERVER "cat >> ~/uip/.env << 'EOF'
GRAFANA_ONCALL_URL=<user-provides-this>
GRAFANA_ONCALL_API_KEY=<user-provides-this>
EOF"
```

- [ ] **Step 4: Start escalation-api, restart nginx, rebuild frontend**

```bash
ssh -i $SSH_KEY $SERVER "cd ~/uip && docker compose up -d escalation-api nginx && docker compose up -d --build sre-frontend"
```

- [ ] **Step 5: Verify escalation-api is running**

```bash
ssh -i $SSH_KEY $SERVER "curl -s http://localhost:8094/api/escalation/health"
# Expected: {"status": "ok"}
```

- [ ] **Step 6: Verify teams endpoint works (requires valid API key)**

```bash
ssh -i $SSH_KEY $SERVER "docker exec uip-nginx curl -s http://escalation-api:8094/api/escalation/teams"
# Expected: JSON array of teams from Grafana OnCall
```

---

## Post-Deployment Verification

### Task 23: End-to-end verification

- [ ] **Step 1: Verify Ollama model swap**

```bash
ssh -i $SSH_KEY $SERVER "docker exec uip-ollama ollama ps"
# Expected: qwen2.5:3b loaded
ssh -i $SSH_KEY $SERVER "docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}' uip-ollama"
# Expected: ~2-3GB instead of 7.5GB
```

- [ ] **Step 2: Verify Keep UI no longer shows 401**

Navigate to Keep admin UI at `http://10.177.154.196/incidents` — should load without 401 errors.

- [ ] **Step 3: Verify enrichment works with new model**

```bash
ssh -i $SSH_KEY $SERVER "docker logs uip-alert-enricher --tail 30 2>&1"
# Expected: successful enrichment cycles, no LLM errors
```

- [ ] **Step 4: Verify health page shows all services**

Navigate to `http://10.177.154.196/portal/health` — should show all services including escalation-api, no Zabbix Poller.

- [ ] **Step 5: Verify registry trends with small ranges**

Navigate to Registry page, select "5m" or "15m" range, load trends. Should show table with operators.

- [ ] **Step 6: Test feedback submission**

Open an alert in Command Center, submit a structured correction (severity + cause + remediation). Verify it returns success.

- [ ] **Step 7: Test escalation (if API key configured)**

Open an alert, click Escalate, select a team, send. Verify Grafana OnCall receives the page.
