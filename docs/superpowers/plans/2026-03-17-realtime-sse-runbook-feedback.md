# Real-Time SSE Events & Runbook Relevance Feedback — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SSE-based real-time state broadcasting to alert-state-api and thumbs up/down runbook feedback, with compact inline badges in the dashboard.

**Architecture:** alert-state-api becomes the SSE hub — every mutation broadcasts an event to all connected EventSource clients. Frontend replaces polling with SSE for alert state, keeps 30s poll for Keep alerts. Runbook feedback stored in alert-state-api, queried by enricher during prompt construction.

**Tech Stack:** Python stdlib (ThreadingHTTPServer, threading), React hooks (EventSource), Next.js App Router, SQLite, nginx SSE proxy config.

**Spec:** `docs/superpowers/specs/2026-03-17-realtime-sse-runbook-feedback-design.md`

---

## Chunk 1: Backend — SSE Infrastructure & New Endpoints

### Task 1: Switch alert-state-api to ThreadingHTTPServer and add SSE infrastructure

**Files:**
- Modify: `deploy/alert-state-api/alert-state-api.py`

- [ ] **Step 1: Update imports and server class**

In `deploy/alert-state-api/alert-state-api.py`, change line 13:

```python
# Before:
from http.server import HTTPServer, BaseHTTPRequestHandler

# After:
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
```

And change line 331:

```python
# Before:
server = HTTPServer(("0.0.0.0", API_PORT), AlertStateHandler)

# After:
server = ThreadingHTTPServer(("0.0.0.0", API_PORT), AlertStateHandler)
```

- [ ] **Step 2: Add SSE client management globals**

After the existing `_db_lock = threading.Lock()` line (~line 22), add the SSE infrastructure:

```python
from collections import deque

# ── SSE Infrastructure ────────────────────────────────────
_sse_lock = threading.Lock()
_sse_clients = set()          # Set of wfile objects
_sse_event_counter = 0
_sse_ring_buffer = deque(maxlen=100)  # Ring buffer for replay
_SSE_MAX_CLIENTS = 50


def _sse_broadcast(event_type, payload):
    """Broadcast an SSE event to all connected clients."""
    global _sse_event_counter
    with _sse_lock:
        _sse_event_counter += 1
        event_id = _sse_event_counter
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        payload["type"] = event_type
        msg = f"id: {event_id}\nevent: state_change\ndata: {json.dumps(payload, default=str)}\n\n"
        _sse_ring_buffer.append((event_id, msg))
        dead = set()
        for client in _sse_clients:
            try:
                client.write(msg.encode())
                client.flush()
            except Exception:
                dead.add(client)
        _sse_clients -= dead
        if dead:
            log.info(f"Removed {len(dead)} dead SSE client(s), {len(_sse_clients)} remaining")
```

- [ ] **Step 3: Add SSE endpoint handler in do_GET**

In `do_GET`, after the existing `/api/alert-states` block (before the `else: 404`), add two new endpoints:

```python
        elif path == "/api/alert-states/events":
            # SSE stream endpoint
            with _sse_lock:
                if len(_sse_clients) >= _SSE_MAX_CLIENTS:
                    self._send_json(503, {"error": "too many SSE connections"})
                    return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            # Register client and replay missed events atomically to avoid gaps
            last_id_str = self.headers.get("Last-Event-ID", "")
            with _sse_lock:
                _sse_clients.add(self.wfile)
                if last_id_str:
                    try:
                        last_id = int(last_id_str)
                        # Find events after last_id
                        found = False
                        for eid, msg in _sse_ring_buffer:
                            if eid == last_id:
                                found = True
                                continue
                            if found:
                                self.wfile.write(msg.encode())
                        if not found and _sse_ring_buffer:
                            # Gap too large — tell client to refetch
                            reset_msg = f"id: {_sse_ring_buffer[-1][0]}\nevent: reset\ndata: {{}}\n\n"
                            self.wfile.write(reset_msg.encode())
                    except (ValueError, TypeError):
                        pass
            self.wfile.flush()
            log.info(f"SSE client connected ({len(_sse_clients)} total)")
            try:
                # Keep connection alive — block until client disconnects
                while True:
                    time.sleep(30)
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except Exception:
                        break
            finally:
                with _sse_lock:
                    _sse_clients.discard(self.wfile)
                log.info(f"SSE client disconnected ({len(_sse_clients)} remaining)")

        elif path == "/api/alert-states/sse-status":
            with _sse_lock:
                count = len(_sse_clients)
            self._send_json(200, {"connected_clients": count})
```

- [ ] **Step 4: Verify server starts with threading**

Deploy to server and verify the service starts without errors:

```bash
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "cd ~/uip && docker compose restart alert-state-api && sleep 2 && docker compose logs alert-state-api --tail 5"
```

Expected: `alert-state-api listening on port 8092`

- [ ] **Step 5: Commit**

```bash
git add deploy/alert-state-api/alert-state-api.py
git commit -m "feat(alert-state-api): add SSE infrastructure with ThreadingHTTPServer"
```

---

### Task 2: Add SSE broadcast calls to all existing mutation endpoints

**Files:**
- Modify: `deploy/alert-state-api/alert-state-api.py`

- [ ] **Step 1: Add broadcast to investigate endpoint**

After line 194 (`self._send_json(200, {"status": "investigating", ...})`), and after line 181 (`self._send_json(200, {"status": "stopped", ...})`), add broadcasts.

In the investigate handler, after the `if row and row["investigating_user"] == username:` branch (stop investigating), after `db.commit()` but before `self._send_json`:

```python
                    _sse_broadcast("investigate", {"fingerprint": fingerprint, "user": username, "active": False})
```

And in the `else` branch (start investigating), after `db.commit()` but before `self._send_json`:

```python
                    _sse_broadcast("investigate", {"fingerprint": fingerprint, "user": username, "active": True})
```

- [ ] **Step 2: Add broadcast to acknowledge endpoint**

After line 226 (`db.commit()`) in the acknowledge handler, before `log.info`:

```python
            _sse_broadcast("acknowledge", {"fingerprints": fingerprints, "user": username})
```

- [ ] **Step 3: Add broadcast to unacknowledge endpoint**

After line 252 (`db.commit()`) in the unacknowledge handler, before `self._send_json`:

```python
            _sse_broadcast("unacknowledge", {"fingerprints": fingerprints})
```

- [ ] **Step 4: Add broadcast to mark-updated endpoint**

After line 276 (`db.commit()`) in the mark-updated handler, before the `if fingerprints:` log:

```python
            _sse_broadcast("mark_updated", {"fingerprints": fingerprints})
```

- [ ] **Step 5: Add broadcast to force-enrich endpoint**

After line 298 (`db.commit()`) in the force-enrich handler, before `log.info`:

```python
            _sse_broadcast("force_enrich", {"fingerprint": fingerprint})
```

- [ ] **Step 6: Commit**

```bash
git add deploy/alert-state-api/alert-state-api.py
git commit -m "feat(alert-state-api): broadcast SSE events on all state mutations"
```

---

### Task 3: Add database schema for incidents, escalations, and runbook feedback

**Files:**
- Modify: `deploy/alert-state-api/alert-state-api.py`

- [ ] **Step 1: Add schema migration for new alert_states columns**

In `_init_db()`, after the existing `force_enrich` migration block (~line 49-55), add:

```python
    # Migration: add incident and escalation columns
    existing = {row[1] for row in conn.execute("PRAGMA table_info(alert_states)").fetchall()}
    for col, default in [
        ("incident_jira_key", "NULL"),
        ("incident_jira_url", "NULL"),
        ("incident_created_by", "NULL"),
        ("incident_created_at", "NULL"),
        ("escalated_to", "NULL"),
        ("escalated_by", "NULL"),
        ("escalated_at", "NULL"),
    ]:
        if col not in existing:
            conn.execute(f"ALTER TABLE alert_states ADD COLUMN {col} TEXT DEFAULT {default}")
            log.info(f"Migrated: added '{col}' column to alert_states")
    conn.commit()
```

- [ ] **Step 2: Add runbook_feedback table creation**

In `_init_db()`, after the alert_states table creation, add:

```python
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runbook_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_fingerprint TEXT NOT NULL,
            alert_name TEXT NOT NULL,
            runbook_entry_id INTEGER NOT NULL,
            vote TEXT NOT NULL,
            user TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(alert_fingerprint, runbook_entry_id, user)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_entry_id ON runbook_feedback(runbook_entry_id)")
    conn.commit()
```

- [ ] **Step 3: Commit**

```bash
git add deploy/alert-state-api/alert-state-api.py
git commit -m "feat(alert-state-api): add schema for incidents, escalations, runbook feedback"
```

---

### Task 4: Add incident, escalation, and runbook feedback endpoints

**Files:**
- Modify: `deploy/alert-state-api/alert-state-api.py`

- [ ] **Step 1: Add incident endpoint**

In `do_POST`, before the final `else: 404` block, add:

```python
        elif path == "/api/alert-states/incident":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            fingerprint = (data.get("fingerprint") or "").strip()
            jira_key = (data.get("jira_key") or "").strip()
            jira_url = (data.get("jira_url") or "").strip()
            if not fingerprint or not jira_key:
                self._send_json(400, {"error": "fingerprint and jira_key are required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                db.execute("""
                    INSERT INTO alert_states (alert_fingerprint, incident_jira_key, incident_jira_url,
                        incident_created_by, incident_created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(alert_fingerprint) DO UPDATE SET
                        incident_jira_key = excluded.incident_jira_key,
                        incident_jira_url = excluded.incident_jira_url,
                        incident_created_by = excluded.incident_created_by,
                        incident_created_at = excluded.incident_created_at,
                        updated_at = datetime('now')
                """, (fingerprint, jira_key, jira_url, username, now))
                db.commit()
            _sse_broadcast("incident_created", {
                "fingerprint": fingerprint, "user": username,
                "jira_key": jira_key, "jira_url": jira_url,
            })
            log.info(f"{username} created incident {jira_key} for {fingerprint[:16]}")
            self._send_json(200, {"status": "stored", "jira_key": jira_key})
```

- [ ] **Step 2: Add escalation endpoint**

```python
        elif path == "/api/alert-states/escalation":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            fingerprint = (data.get("fingerprint") or "").strip()
            escalated_to = (data.get("escalated_to") or "").strip()
            if not fingerprint or not escalated_to:
                self._send_json(400, {"error": "fingerprint and escalated_to are required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                db.execute("""
                    INSERT INTO alert_states (alert_fingerprint, escalated_to, escalated_by, escalated_at, updated_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(alert_fingerprint) DO UPDATE SET
                        escalated_to = excluded.escalated_to,
                        escalated_by = excluded.escalated_by,
                        escalated_at = excluded.escalated_at,
                        updated_at = datetime('now')
                """, (fingerprint, escalated_to, username, now))
                db.commit()
            _sse_broadcast("escalated", {
                "fingerprint": fingerprint, "user": username, "escalated_to": escalated_to,
            })
            log.info(f"{username} escalated {fingerprint[:16]} to {escalated_to}")
            self._send_json(200, {"status": "stored", "escalated_to": escalated_to})
```

- [ ] **Step 3: Add runbook feedback POST endpoint**

```python
        elif path == "/api/alert-states/runbook-feedback":
            username = _get_username_from_request(self)
            if not username:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return
            fingerprint = (data.get("fingerprint") or "").strip()
            alert_name = (data.get("alert_name") or "").strip()
            entry_id = data.get("entry_id")
            vote = (data.get("vote") or "").strip()
            if not fingerprint or not entry_id or vote not in ("up", "down", "none"):
                self._send_json(400, {"error": "fingerprint, entry_id, and vote (up/down/none) required"})
                return
            now = datetime.now(timezone.utc).isoformat()
            with _db_lock:
                if vote == "none":
                    db.execute("""
                        DELETE FROM runbook_feedback
                        WHERE alert_fingerprint = ? AND runbook_entry_id = ? AND user = ?
                    """, (fingerprint, entry_id, username))
                else:
                    db.execute("""
                        INSERT INTO runbook_feedback (alert_fingerprint, alert_name, runbook_entry_id, vote, user, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(alert_fingerprint, runbook_entry_id, user) DO UPDATE SET
                            vote = excluded.vote, created_at = excluded.created_at
                    """, (fingerprint, alert_name, entry_id, vote, username, now))
                db.commit()
            _sse_broadcast("runbook_feedback", {
                "fingerprint": fingerprint, "entry_id": entry_id,
                "vote": vote, "user": username,
            })
            self._send_json(200, {"status": "stored", "vote": vote})
```

- [ ] **Step 4: Add runbook feedback GET endpoint**

In `do_GET`, add a new path before the `else: 404`:

```python
        elif path == "/api/alert-states/runbook-feedback":
            qs = parse_qs(parsed.query)
            entry_ids_str = qs.get("entry_ids", [""])[0]
            if not entry_ids_str:
                self._send_json(400, {"error": "entry_ids query param required"})
                return
            try:
                entry_ids = [int(x.strip()) for x in entry_ids_str.split(",") if x.strip()]
            except ValueError:
                self._send_json(400, {"error": "entry_ids must be comma-separated integers"})
                return
            with _db_lock:
                placeholders = ",".join("?" * len(entry_ids))
                cursor = db.execute(f"""
                    SELECT * FROM runbook_feedback
                    WHERE runbook_entry_id IN ({placeholders})
                    ORDER BY created_at DESC
                """, entry_ids)
                rows = [dict(r) for r in cursor.fetchall()]
            self._send_json(200, rows)
```

- [ ] **Step 5: Update the existing GET /api/alert-states to include new columns**

The existing GET query uses `SELECT *` so the new columns are already returned. However, the WHERE clause filters rows that have investigating_user OR acknowledged_by OR is_updated. We need to also return rows that have incident or escalation data. Update the query at line 137:

```python
                    cursor = db.execute("""
                        SELECT * FROM alert_states
                        WHERE investigating_user IS NOT NULL
                           OR acknowledged_by IS NOT NULL
                           OR is_updated = 1
                           OR incident_jira_key IS NOT NULL
                           OR escalated_to IS NOT NULL
                        ORDER BY updated_at DESC
                    """)
```

- [ ] **Step 6: Commit**

```bash
git add deploy/alert-state-api/alert-state-api.py
git commit -m "feat(alert-state-api): add incident, escalation, and runbook feedback endpoints"
```

---

### Task 5: Update nginx config for SSE proxy

**Files:**
- Modify: Server-only file at `~/uip/nginx/default.conf` (not in git repo — tracked via `deploy/nginx-default.conf` which is a local copy)

- [ ] **Step 1: Add SSE-specific location block via SSH**

SSH into the server and insert the SSE block before the existing `/api/alert-states` block. The nginx config lives at `~/uip/nginx/default.conf` on the server. Insert the following block before the line `location /api/alert-states {`:

```nginx
    # Alert State API — SSE event stream (longer prefix match takes priority)
    location /api/alert-states/events {
        proxy_pass http://alert-state-api:8092;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
        chunked_transfer_encoding off;
        proxy_read_timeout 86400s;
    }
```

Use a Python script or sed on the server to insert the block:

```bash
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "cd ~/uip && python3 -c \"
content = open('nginx/default.conf').read()
sse_block = '''    # Alert State API — SSE event stream (longer prefix match takes priority)
    location /api/alert-states/events {
        proxy_pass http://alert-state-api:8092;
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
        proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
        chunked_transfer_encoding off;
        proxy_read_timeout 86400s;
    }

'''
content = content.replace('    # Alert State API — investigation', sse_block + '    # Alert State API — investigation')
open('nginx/default.conf', 'w').write(content)
print('SSE block inserted')
\""
```

- [ ] **Step 2: Reload nginx**

```bash
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "cd ~/uip && docker compose exec nginx nginx -t && docker compose exec nginx nginx -s reload"
```

Expected: `nginx: configuration file /etc/nginx/nginx.conf test is successful`

- [ ] **Step 3: Test SSE endpoint**

```bash
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "timeout 5 curl -s -N -H 'Accept: text/event-stream' http://localhost/api/alert-states/events 2>&1 || true"
```

Expected: Connection stays open, receives keepalive comments or hangs until timeout.

- [ ] **Step 4: Pull updated nginx config back to local repo**

```bash
scp -i ~/.ssh/id_uip_deploy fash@10.177.154.196:~/uip/nginx/default.conf deploy/nginx-default.conf
git add deploy/nginx-default.conf
git commit -m "feat(nginx): add SSE proxy config for alert-state-api events endpoint"
```

---

## Chunk 2: Frontend — SSE Hook, Types, and API Functions

### Task 6: Update TypeScript types

**Files:**
- Modify: `deploy/sre-frontend/src/lib/types.ts`

- [ ] **Step 1: Extend AlertState interface**

Add the new fields to the existing `AlertState` interface (after line 94, before the closing `}`):

```typescript
export interface AlertState {
  alert_fingerprint: string;
  alert_name: string;
  investigating_user: string | null;
  investigating_since: string | null;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  ack_firing_start: string | null;
  is_updated: number;
  // Incident tracking
  incident_jira_key?: string | null;
  incident_jira_url?: string | null;
  incident_created_by?: string | null;
  incident_created_at?: string | null;
  // Escalation tracking
  escalated_to?: string | null;
  escalated_by?: string | null;
  escalated_at?: string | null;
}
```

- [ ] **Step 2: Add SSE event type**

Append to the file:

```typescript
export interface SSEEvent {
  type: string;
  fingerprint?: string;
  fingerprints?: string[];
  user?: string;
  active?: boolean;
  jira_key?: string;
  jira_url?: string;
  escalated_to?: string;
  entry_id?: number;
  vote?: string;
  timestamp: string;
}

export interface RunbookFeedback {
  id: number;
  alert_fingerprint: string;
  alert_name: string;
  runbook_entry_id: number;
  vote: 'up' | 'down';
  user: string;
  created_at: string;
}
```

- [ ] **Step 3: Commit**

```bash
git add deploy/sre-frontend/src/lib/types.ts
git commit -m "feat(frontend): extend types for SSE events, incidents, escalations, runbook feedback"
```

---

### Task 7: Create useSSE React hook

**Files:**
- Create: `deploy/sre-frontend/src/hooks/useSSE.ts`

- [ ] **Step 1: Write the hook**

```typescript
'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { SSEEvent } from '@/lib/types';

export function useSSE(
  url: string,
  onEvent: (event: SSEEvent) => void,
): { connected: boolean } {
  const [connected, setConnected] = useState(false);
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    es.addEventListener('state_change', (e: MessageEvent) => {
      try {
        const data: SSEEvent = JSON.parse(e.data);
        onEventRef.current(data);
      } catch {
        // Ignore malformed events
      }
    });

    es.addEventListener('reset', () => {
      // Server says gap is too large — trigger full refetch
      onEventRef.current({ type: '_reset', timestamp: new Date().toISOString() });
    });

    return () => {
      es.close();
      esRef.current = null;
      setConnected(false);
    };
  }, [url]);

  return { connected };
}
```

- [ ] **Step 2: Commit**

```bash
git add deploy/sre-frontend/src/hooks/useSSE.ts
git commit -m "feat(frontend): add useSSE hook for real-time event streaming"
```

---

### Task 8: Add new API functions for incident, escalation, and runbook feedback

**Files:**
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`

- [ ] **Step 1: Add incident storage function**

Append near the other alert-state API functions (after `markAlertsUpdated`):

```typescript
export async function storeIncidentState(
  fingerprint: string,
  jiraKey: string,
  jiraUrl: string,
): Promise<void> {
  await fetch('/api/alert-states/incident', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ fingerprint, jira_key: jiraKey, jira_url: jiraUrl }),
  });
}
```

- [ ] **Step 2: Add escalation storage function**

```typescript
export async function storeEscalationState(
  fingerprint: string,
  escalatedTo: string,
): Promise<void> {
  await fetch('/api/alert-states/escalation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ fingerprint, escalated_to: escalatedTo }),
  });
}
```

- [ ] **Step 3: Add runbook feedback functions**

```typescript
export async function submitRunbookFeedback(
  fingerprint: string,
  alertName: string,
  entryId: number,
  vote: 'up' | 'down' | 'none',
): Promise<void> {
  await fetch('/api/alert-states/runbook-feedback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ fingerprint, alert_name: alertName, entry_id: entryId, vote }),
  });
}

export async function fetchRunbookFeedback(
  entryIds: number[],
): Promise<RunbookFeedback[]> {
  if (entryIds.length === 0) return [];
  const res = await fetch(`/api/alert-states/runbook-feedback?entry_ids=${entryIds.join(',')}`, {
    credentials: 'include',
  });
  if (!res.ok) return [];
  return res.json();
}
```

- [ ] **Step 4: Add the RunbookFeedback import to the imports line**

At the top of `keep-api.ts`, update the import from types:

```typescript
import { Alert, AIEnrichment, AlertStats, SREFeedback, RunbookEntry, AIInstruction, AIFeedbackSummary, AlertState, RunbookFeedback } from './types';
```

- [ ] **Step 5: Commit**

```bash
git add deploy/sre-frontend/src/lib/keep-api.ts
git commit -m "feat(frontend): add API functions for incident, escalation, and runbook feedback"
```

---

## Chunk 3: Frontend — SSE Integration in Command Center

### Task 9: Replace polling with SSE in command-center page

**Files:**
- Modify: `deploy/sre-frontend/src/app/command-center/page.tsx`

- [ ] **Step 1: Add SSE hook import and connection**

Add to imports at the top of the file:

```typescript
import { useSSE } from '@/hooks/useSSE';
```

- [ ] **Step 2: Create SSE event handler**

Inside the component, add an SSE event handler that patches local alertStates. This replaces the need to refetch on every change:

```typescript
  const handleSSEEvent = useCallback((event: SSEEvent) => {
    if (event.type === '_reset') {
      // Full refetch needed — gap in SSE stream
      load();
      return;
    }

    setAlertStates(prev => {
      const next = new Map(prev);

      if (event.fingerprint) {
        const fp = event.fingerprint;
        const existing = next.get(fp) || { alert_fingerprint: fp, alert_name: '', investigating_user: null, investigating_since: null, acknowledged_by: null, acknowledged_at: null, ack_firing_start: null, is_updated: 0 } as AlertState;

        switch (event.type) {
          case 'investigate':
            next.set(fp, {
              ...existing,
              investigating_user: event.active ? (event.user || null) : null,
              investigating_since: event.active ? event.timestamp : null,
            });
            break;
          case 'incident_created':
            next.set(fp, {
              ...existing,
              incident_jira_key: event.jira_key || null,
              incident_jira_url: event.jira_url || null,
              incident_created_by: event.user || null,
              incident_created_at: event.timestamp || null,
            });
            break;
          case 'escalated':
            next.set(fp, {
              ...existing,
              escalated_to: event.escalated_to || null,
              escalated_by: event.user || null,
              escalated_at: event.timestamp || null,
            });
            break;
          case 'force_enrich':
            // No visible state change needed
            break;
        }
      }

      // Batch events (acknowledge, unacknowledge, mark_updated)
      if (event.fingerprints) {
        for (const fp of event.fingerprints) {
          const existing = next.get(fp) || { alert_fingerprint: fp, alert_name: '', investigating_user: null, investigating_since: null, acknowledged_by: null, acknowledged_at: null, ack_firing_start: null, is_updated: 0 } as AlertState;
          switch (event.type) {
            case 'acknowledge':
              next.set(fp, { ...existing, acknowledged_by: event.user || null, acknowledged_at: event.timestamp, is_updated: 0 });
              break;
            case 'unacknowledge':
              next.set(fp, { ...existing, acknowledged_by: null, acknowledged_at: null, ack_firing_start: null, is_updated: 0 });
              break;
            case 'mark_updated':
              next.set(fp, { ...existing, acknowledged_by: null, acknowledged_at: null, is_updated: 1 });
              break;
          }
        }
      }

      return next;
    });
  }, []);

  const { connected } = useSSE('/api/alert-states/events', handleSSEEvent);
```

- [ ] **Step 3: Change polling interval default from 30s to 60s**

Find the `refreshInterval` state initialization and change:

```typescript
// Before:
const [refreshInterval, setRefreshInterval] = useState(30);

// After:
const [refreshInterval, setRefreshInterval] = useState(60);
```

- [ ] **Step 4: Optionally show SSE connection status**

Near the existing refresh interval selector, add a small connection indicator:

```typescript
<span className={`inline-block w-2 h-2 rounded-full ${connected ? 'bg-green' : 'bg-red/50'}`} title={connected ? 'Live updates connected' : 'Live updates disconnected'} />
```

- [ ] **Step 5: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/page.tsx
git commit -m "feat(frontend): integrate SSE for real-time alert state updates"
```

---

### Task 10: Add incident and escalation badges to DashboardView

**Files:**
- Modify: `deploy/sre-frontend/src/app/command-center/DashboardView.tsx`

- [ ] **Step 1: Add incident badge inline after existing state badges**

Find the section where the investigation badge and Updated badge are rendered (after `alertState?.is_updated === 1` block, around line 206). Add incident and escalation badges:

```tsx
          {alertState?.incident_jira_key && (
            <a
              href={alertState.incident_jira_url || '#'}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              title={`Incident created by ${alertState.incident_created_by || 'unknown'}${alertState.incident_created_at ? ', ' + timeAgo(alertState.incident_created_at) : ''}`}
              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-purple/10 border border-purple/30 text-purple whitespace-nowrap hover:bg-purple/20 transition-colors"
            >
              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M10.172 13.828a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.102 1.101" />
              </svg>
              {alertState.incident_jira_key}
            </a>
          )}
          {alertState?.escalated_to && (
            <span
              title={`Escalated by ${alertState.escalated_by || 'unknown'}${alertState.escalated_at ? ', ' + timeAgo(alertState.escalated_at) : ''}`}
              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-amber/10 border border-amber/30 text-amber whitespace-nowrap"
            >
              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 10l7-7m0 0l7 7m-7-7v18" />
              </svg>
              {alertState.escalated_to}
            </span>
          )}
```

- [ ] **Step 2: Ensure `timeAgo` is imported**

Verify `timeAgo` is imported from `keep-api.ts` in DashboardView. It should already be — check the existing import line and add if missing:

```typescript
import { ..., timeAgo } from '@/lib/keep-api';
```

- [ ] **Step 3: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/DashboardView.tsx
git commit -m "feat(frontend): add inline incident and escalation badges to dashboard"
```

---

### Task 11: Add incident and escalation badges to AlertsTableView

**Files:**
- Modify: `deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx`

- [ ] **Step 1: Add same badge pattern to table rows**

Find where alert names are rendered in the table. Add the same incident/escalation badge JSX after the alert name and any existing badges (same code as Task 10, Step 1). The badges are inline `<span>` elements so they work in both grid and table layouts.

- [ ] **Step 2: Commit**

```bash
git add deploy/sre-frontend/src/app/command-center/AlertsTableView.tsx
git commit -m "feat(frontend): add inline incident and escalation badges to alerts table"
```

---

## Chunk 4: Frontend — Incident/Escalation State Storage & Runbook Feedback UI

### Task 12: Wire incident creation to store state in alert-state-api

**Files:**
- Modify: `deploy/sre-frontend/src/app/alerts/[fingerprint]/page.tsx`
- Modify: `deploy/sre-frontend/src/app/command-center/page.tsx` (if incident form also exists here)

- [ ] **Step 1: Update incident form submission**

Find the incident creation success handler (where `createJiraIncident()` returns successfully with `issueKey` and `issueUrl`). After the success state is set, add:

```typescript
import { storeIncidentState } from '@/lib/keep-api';

// After createJiraIncident succeeds:
try {
  await storeIncidentState(alert.fingerprint, result.issueKey, result.issueUrl);
} catch {
  // Best-effort — incident was already created in Jira
}
```

- [ ] **Step 2: Update escalation success handler**

Find where `escalateAlert()` succeeds. After the success state, add:

```typescript
import { storeEscalationState } from '@/lib/keep-api';

// After escalateAlert succeeds — extract team/user name from the selected option:
try {
  await storeEscalationState(alert.fingerprint, selectedTeamName || selectedUserName);
} catch {
  // Best-effort — escalation was already sent
}
```

- [ ] **Step 3: Commit**

```bash
git add deploy/sre-frontend/src/app/alerts/[fingerprint]/page.tsx deploy/sre-frontend/src/app/command-center/page.tsx
git commit -m "feat(frontend): store incident and escalation state in alert-state-api"
```

---

### Task 13: Add thumbs up/down to RunbookPanel

**Files:**
- Modify: The RunbookPanel component (in `deploy/sre-frontend/src/app/alerts/[fingerprint]/page.tsx` or `deploy/sre-frontend/src/app/command-center/page.tsx` — wherever the RunbookPanel is defined)

- [ ] **Step 1: Add feedback state and fetch**

At the top of the RunbookPanel (or wherever runbook entries are rendered), add state for votes:

```typescript
import { submitRunbookFeedback, fetchRunbookFeedback } from '@/lib/keep-api';
import { RunbookFeedback } from '@/lib/types';

const [votes, setVotes] = useState<Map<string, 'up' | 'down'>>(new Map()); // key: `${entryId}`
```

After runbook entries are fetched, fetch existing feedback:

```typescript
useEffect(() => {
  if (entries.length === 0) return;
  const entryIds = entries.map(e => e.id).filter(Boolean);
  if (entryIds.length === 0) return;
  fetchRunbookFeedback(entryIds).then(feedback => {
    const voteMap = new Map<string, 'up' | 'down'>();
    // Only show current user's votes
    for (const fb of feedback) {
      // We'll show all votes but highlight the user's own
      voteMap.set(`${fb.runbook_entry_id}`, fb.vote as 'up' | 'down');
    }
    setVotes(voteMap);
  });
}, [entries]);
```

- [ ] **Step 2: Add vote handler**

```typescript
const handleVote = async (entryId: number, vote: 'up' | 'down') => {
  const key = `${entryId}`;
  const currentVote = votes.get(key);
  const newVote = currentVote === vote ? 'none' : vote;

  // Optimistic update
  setVotes(prev => {
    const next = new Map(prev);
    if (newVote === 'none') next.delete(key);
    else next.set(key, newVote as 'up' | 'down');
    return next;
  });

  try {
    await submitRunbookFeedback(alert.fingerprint, alert.name, entryId, newVote as 'up' | 'down' | 'none');
  } catch {
    // Revert on failure
    setVotes(prev => {
      const next = new Map(prev);
      if (currentVote) next.set(key, currentVote);
      else next.delete(key);
      return next;
    });
  }
};
```

- [ ] **Step 3: Render thumbs inline with each runbook entry**

For each runbook entry in the list, add after the entry's metadata line:

```tsx
<div className="inline-flex items-center gap-1 ml-2">
  <button
    onClick={() => handleVote(entry.id, 'up')}
    className={`p-0.5 rounded transition-colors ${
      votes.get(`${entry.id}`) === 'up'
        ? 'text-green'
        : 'text-muted/30 hover:text-green/70'
    }`}
    title="Useful remediation"
  >
    <svg className="w-3.5 h-3.5" fill={votes.get(`${entry.id}`) === 'up' ? 'currentColor' : 'none'} viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M14 9V5a3 3 0 00-3-3l-4 9v11h11.28a2 2 0 002-1.7l1.38-9a2 2 0 00-2-2.3H14z" />
    </svg>
  </button>
  <button
    onClick={() => handleVote(entry.id, 'down')}
    className={`p-0.5 rounded transition-colors ${
      votes.get(`${entry.id}`) === 'down'
        ? 'text-red'
        : 'text-muted/30 hover:text-red/70'
    }`}
    title="Irrelevant remediation"
  >
    <svg className="w-3.5 h-3.5" fill={votes.get(`${entry.id}`) === 'down' ? 'currentColor' : 'none'} viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M10 15v4a3 3 0 003 3l4-9V2H5.72a2 2 0 00-2 1.7l-1.38 9a2 2 0 002 2.3H10z" />
    </svg>
  </button>
</div>
```

- [ ] **Step 4: Add muted styling for downvoted entries**

Wrap each runbook entry container with conditional opacity:

```tsx
<div className={`${votes.get(`${entry.id}`) === 'down' ? 'opacity-50' : ''} transition-opacity`}>
  {/* existing entry content */}
</div>
```

- [ ] **Step 5: Commit**

```bash
git add deploy/sre-frontend/src/app/alerts/[fingerprint]/page.tsx deploy/sre-frontend/src/app/command-center/page.tsx
git commit -m "feat(frontend): add thumbs up/down feedback for runbook entries"
```

---

## Chunk 5: Enricher Integration & Deployment

### Task 14: Add runbook feedback to enricher prompt

**Files:**
- Modify: `deploy/enricher.py`

- [ ] **Step 1: Add fetch function for runbook feedback**

After the existing `fetch_runbook_entries()` function (~line 237), add:

```python
def fetch_runbook_feedback(entry_ids):
    """Fetch SRE feedback on runbook entries from alert-state-api."""
    if not entry_ids:
        return []
    ids_str = ",".join(str(i) for i in entry_ids)
    url = f"{ALERT_STATE_API_URL}/api/alert-states/runbook-feedback?entry_ids={ids_str}"
    try:
        req = Request(url, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data if isinstance(data, list) else []
    except Exception as e:
        log.debug(f"Runbook feedback fetch failed (non-fatal): {e}")
        return []
```

`ALERT_STATE_API_URL` already exists at line 25 of `enricher.py` — do not add it again.

- [ ] **Step 2: Update build_enrichment_prompt to use feedback**

In `build_enrichment_prompt()`, after the runbook entries are fetched (~line 506), add feedback integration:

```python
    # Fetch SRE feedback on runbook entries
    entry_ids = [e.get("id") for e in runbook_entries if e.get("id")]
    feedback_rows = fetch_runbook_feedback(entry_ids)

    # Aggregate votes per entry_id: net score (up=+1, down=-1)
    vote_scores = {}
    for fb in feedback_rows:
        eid = fb.get("runbook_entry_id")
        v = 1 if fb.get("vote") == "up" else -1
        vote_scores[eid] = vote_scores.get(eid, 0) + v
```

Then modify the runbook context building block. Replace the existing block (lines 508-519) with:

```python
    runbook_context = ""
    if runbook_entries:
        good_lines = ["\nRUNBOOK ENTRIES (real SRE remediation experience for similar alerts — use as authoritative reference):"]
        bad_lines = ["\nDOWNVOTED REMEDIATION (marked irrelevant by SREs — do NOT recommend these):"]
        has_good = False
        has_bad = False
        for entry in runbook_entries[:5]:
            date = (entry.get("created_at") or "unknown")[:10]
            user = entry.get("sre_user") or "unknown"
            e_name = (entry.get("alert_name") or "")[:60]
            e_host = entry.get("hostname") or "N/A"
            rem = (entry.get("remediation") or "")[:300]
            eid = entry.get("id")
            score = vote_scores.get(eid, 0)
            line1 = f'  - [{date}, {user}] Alert: "{e_name}" | Host: {e_host}'
            line2 = f'    Remediation: "{rem}"'
            if score < 0:
                bad_lines.append(line1)
                bad_lines.append(line2)
                has_bad = True
            else:
                good_lines.append(line1)
                good_lines.append(line2)
                has_good = True
        if has_good:
            good_lines.append("  Apply these SRE-validated remediation steps to your REMEDIATION field when relevant.\n")
            runbook_context += "\n".join(good_lines)
        if has_bad:
            bad_lines.append("  These have been flagged as unhelpful. Do not use them.\n")
            runbook_context += "\n".join(bad_lines)
```

- [ ] **Step 3: Commit**

```bash
git add deploy/enricher.py
git commit -m "feat(enricher): integrate runbook feedback for soft downranking in prompts"
```

---

### Task 15: Deploy and verify end-to-end

**Files:**
- All modified files deployed to server

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

- [ ] **Step 3: Deploy nginx config (if not already done in Task 5)**

Nginx config was already deployed directly on the server in Task 5. Just verify it's still correct:

```bash
ssh -i ~/.ssh/id_uip_deploy fash@10.177.154.196 "cd ~/uip && docker compose exec nginx nginx -t"
```

- [ ] **Step 4: Build and deploy frontend**

```bash
cd deploy/sre-frontend && npm run build
# Then deploy built output to server (follow existing deployment pattern)
```

- [ ] **Step 5: Verify SSE connection**

Open browser dev tools → Network tab → filter EventStream. Navigate to Command Center. Should see an SSE connection to `/api/alert-states/events` staying open.

- [ ] **Step 6: Verify real-time updates**

Open Command Center in two browser windows. In window A, click investigate on an alert. Window B should show the investigation badge within 1-2 seconds without manual refresh.

- [ ] **Step 7: Verify runbook feedback**

Open an alert detail page. Navigate to the runbook section. Click thumbs-down on an irrelevant entry. Verify the entry becomes muted. Refresh page — vote should persist.

- [ ] **Step 8: Commit any final adjustments**

```bash
git add -A
git commit -m "chore: final adjustments from end-to-end verification"
```
