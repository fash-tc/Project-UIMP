# Shared Maintenance Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `Admin` and `SRE` users use maintenance-protected webhook actions without signing into the Maintenance API every browser session, while keeping manual per-session sign-in for all other roles.

**Architecture:** Store one shared maintenance username/password in `auth-api`, encrypted at rest and managed from the Admin roles surface. Add an auth-api bootstrap endpoint that logs into the Maintenance API server-side for eligible users, then keep the existing browser-session token flow in the webhooks page so the rest of the webhook write path changes minimally.

**Tech Stack:** Python `http.server` auth service, SQLite, HMAC/cookie auth, `urllib.request`, React/Next.js client components, TypeScript fetch helpers, pytest.

---

## File Structure

### Existing files to modify

- `deploy/auth-api/auth-api.py`
  - add shared integration table creation
  - add encryption helpers and maintenance-login helper
  - add maintenance shared-config CRUD endpoints
  - add maintenance bootstrap endpoint for `Admin` and `SRE`
- `deploy/sre-frontend/src/lib/types.ts`
  - add shared maintenance auth metadata types
- `deploy/sre-frontend/src/lib/keep-api.ts`
  - add auth-api client helpers for shared maintenance auth management and bootstrap
  - keep existing manual maintenance login helpers intact
- `deploy/sre-frontend/src/app/admin/page.tsx`
  - add `Shared Maintenance Auth` card on the Roles tab
- `deploy/sre-frontend/src/app/webhooks/page.tsx`
  - auto-bootstrap maintenance auth for `Admin` and `SRE`
  - retain manual sign-in for all other roles and as fallback

### New files to create

- `deploy/tests/test_auth_shared_maintenance.py`
  - backend TDD coverage for storage, encryption, permissions, maintenance login bootstrap
- `deploy/tests/test_shared_maintenance_ui.py`
  - lightweight source-level regression checks for admin/webhooks UI wiring

### Optional config touch

- `deploy/docker-compose.yml`
  - only if `auth-api` does not already have a suitable encryption secret environment variable source

## Task 1: Add Shared Maintenance Storage And Crypto In Auth API

**Files:**
- Modify: `deploy/auth-api/auth-api.py`
- Test: `deploy/tests/test_auth_shared_maintenance.py`

- [ ] **Step 1: Write the failing backend storage/encryption tests**

```python
import importlib.util
from pathlib import Path


AUTH_API_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\auth-api\auth-api.py")


def load_auth_api():
    spec = importlib.util.spec_from_file_location("auth_api_under_test", AUTH_API_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_init_db_creates_shared_integrations_table(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()

    db = auth_api._init_db()
    row = db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'shared_integrations'"
    ).fetchone()

    assert row["name"] == "shared_integrations"


def test_shared_maintenance_password_round_trip_is_encrypted(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()
    db = auth_api._init_db()

    auth_api._set_shared_integration_secret(
        db,
        "maintenance_api",
        username="maint-user",
        password="maint-pass",
        updated_by="fash",
    )

    stored = db.execute(
        "SELECT username, password_ciphertext, updated_by FROM shared_integrations WHERE key = ?",
        ("maintenance_api",),
    ).fetchone()

    assert stored["username"] == "maint-user"
    assert stored["updated_by"] == "fash"
    assert stored["password_ciphertext"] != "maint-pass"
    assert auth_api._get_shared_integration_secret(db, "maintenance_api")["password"] == "maint-pass"
```

- [ ] **Step 2: Run the tests to verify they fail for the right reason**

Run: `python -m pytest deploy\tests\test_auth_shared_maintenance.py -k "shared_integrations or round_trip" -v`

Expected: FAIL with missing `shared_integrations` table and missing helper functions such as `_set_shared_integration_secret`.

- [ ] **Step 3: Add minimal shared-integration table and crypto helpers in `auth-api.py`**

```python
SHARED_INTEGRATIONS_SECRET = os.environ.get("SHARED_INTEGRATIONS_SECRET", "")


def _require_shared_integrations_secret():
    if not SHARED_INTEGRATIONS_SECRET:
        raise RuntimeError("SHARED_INTEGRATIONS_SECRET is required")
    return SHARED_INTEGRATIONS_SECRET.encode("utf-8")


def _encrypt_shared_secret(raw_password):
    key = hashlib.sha256(_require_shared_integrations_secret()).digest()
    raw = raw_password.encode("utf-8")
    return base64.urlsafe_b64encode(bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))).decode("ascii")


def _decrypt_shared_secret(ciphertext):
    key = hashlib.sha256(_require_shared_integrations_secret()).digest()
    raw = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)).decode("utf-8")


def _set_shared_integration_secret(db_conn, key, username, password, updated_by):
    db_conn.execute(
        """
        INSERT INTO shared_integrations (key, username, password_ciphertext, updated_by, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
            username = excluded.username,
            password_ciphertext = excluded.password_ciphertext,
            updated_by = excluded.updated_by,
            updated_at = CURRENT_TIMESTAMP
        """,
        (key, username, _encrypt_shared_secret(password), updated_by),
    )
    db_conn.commit()


def _get_shared_integration_secret(db_conn, key):
    row = db_conn.execute(
        "SELECT key, username, password_ciphertext, updated_by, updated_at FROM shared_integrations WHERE key = ?",
        (key,),
    ).fetchone()
    if not row or not row["password_ciphertext"]:
        return None
    return {
        "key": row["key"],
        "username": row["username"],
        "password": _decrypt_shared_secret(row["password_ciphertext"]),
        "updated_by": row["updated_by"],
        "updated_at": row["updated_at"],
    }
```

Also add this table in `_init_db()`:

```python
db.execute("""
    CREATE TABLE IF NOT EXISTS shared_integrations (
        key TEXT PRIMARY KEY,
        username TEXT NOT NULL DEFAULT '',
        password_ciphertext TEXT NOT NULL DEFAULT '',
        updated_by TEXT DEFAULT '',
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
""")
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `python -m pytest deploy\tests\test_auth_shared_maintenance.py -k "shared_integrations or round_trip" -v`

Expected: PASS for table creation and encrypted round-trip storage.

- [ ] **Step 5: Commit**

```bash
git add deploy/auth-api/auth-api.py deploy/tests/test_auth_shared_maintenance.py
git commit -m "feat: add shared maintenance auth storage"
```

## Task 2: Add Shared Maintenance Auth Endpoints And Bootstrap

**Files:**
- Modify: `deploy/auth-api/auth-api.py`
- Test: `deploy/tests/test_auth_shared_maintenance.py`

- [ ] **Step 1: Write failing endpoint and eligibility tests**

```python
def test_bootstrap_requires_admin_or_sre_role(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()
    db = auth_api._init_db()

    db.execute("UPDATE users SET role_id = 3 WHERE username = 'jpratt'")
    db.commit()

    token = auth_api._create_auth_token("jpratt", permissions=["view_webhooks"], role_id=3)
    allowed, reason = auth_api._can_bootstrap_maintenance(db, token)

    assert allowed is False
    assert reason == "forbidden"


def test_bootstrap_uses_shared_maintenance_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()
    db = auth_api._init_db()
    auth_api._set_shared_integration_secret(db, "maintenance_api", "maint-user", "maint-pass", "fash")

    calls = []

    def fake_login(username, password):
        calls.append((username, password))
        return {"token": "maint-token"}

    monkeypatch.setattr(auth_api, "_login_to_maintenance_api", fake_login)

    token = auth_api._create_auth_token("fash", permissions=["manage_roles"], role_id=1)
    body = auth_api._bootstrap_maintenance_token(db, token)

    assert body["token"] == "maint-token"
    assert calls == [("maint-user", "maint-pass")]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest deploy\tests\test_auth_shared_maintenance.py -k "bootstrap_requires or bootstrap_uses" -v`

Expected: FAIL with missing helper functions such as `_can_bootstrap_maintenance`, `_login_to_maintenance_api`, or `_bootstrap_maintenance_token`.

- [ ] **Step 3: Add minimal backend helpers and HTTP handlers**

```python
def _login_to_maintenance_api(username, password):
    req = Request(
        "http://maintenance-api:8000/api/auth/login",
        data=json.dumps({"username": username, "password": password}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _can_bootstrap_maintenance(db_conn, auth_payload):
    if not auth_payload:
        return False, "unauthorized"
    role = _get_user_role(db_conn, auth_payload["u"])
    if role["name"] not in {"Admin", "SRE"}:
        return False, "forbidden"
    return True, None


def _bootstrap_maintenance_token(db_conn, auth_payload):
    allowed, reason = _can_bootstrap_maintenance(db_conn, auth_payload)
    if not allowed:
        raise PermissionError(reason)
    secret = _get_shared_integration_secret(db_conn, "maintenance_api")
    if not secret:
        raise LookupError("Shared maintenance auth is not configured.")
    return _login_to_maintenance_api(secret["username"], secret["password"])
```

Add request handling branches for:

```python
elif path == "/api/auth/shared-integrations/maintenance":
    caller = _require_permission(self, "manage_roles")
    if not caller:
        return
    # GET returns configured metadata only

elif path == "/api/auth/shared-integrations/maintenance/test":
    caller = _require_permission(self, "manage_roles")
    if not caller:
        return
    # POST attempts server-side maintenance login with stored secret

elif path == "/api/auth/maintenance/bootstrap":
    auth_payload = _get_token_from_request(self)
    try:
        result = _bootstrap_maintenance_token(db, auth_payload)
        self._send_json(200, {"ok": True, "token": result["token"]})
    except PermissionError as exc:
        status = 401 if str(exc) == "unauthorized" else 403
        self._send_json(status, {"error": "Not eligible for shared maintenance bootstrap"})
    except LookupError:
        self._send_json(409, {"error": "Shared maintenance auth is not configured."})
    except Exception:
        self._send_json(502, {"error": "Maintenance API is unavailable."})
```

For PUT/DELETE shared-config handlers, use the existing `manage_roles` pattern from role updates so they fit the file’s style.

- [ ] **Step 4: Expand tests for CRUD and sanitized failures, then run them**

Add these assertions to `deploy/tests/test_auth_shared_maintenance.py`:

```python
def test_shared_maintenance_metadata_excludes_password(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()
    db = auth_api._init_db()
    auth_api._set_shared_integration_secret(db, "maintenance_api", "maint-user", "maint-pass", "fash")

    metadata = auth_api._get_shared_integration_metadata(db, "maintenance_api")

    assert metadata["configured"] is True
    assert metadata["username"] == "maint-user"
    assert "password" not in metadata
```

Run: `python -m pytest deploy\tests\test_auth_shared_maintenance.py -v`

Expected: PASS, including eligibility, round-trip storage, metadata, and bootstrap behavior.

- [ ] **Step 5: Commit**

```bash
git add deploy/auth-api/auth-api.py deploy/tests/test_auth_shared_maintenance.py
git commit -m "feat: add shared maintenance auth endpoints"
```

## Task 3: Add Frontend Types And Keep API Helpers

**Files:**
- Modify: `deploy/sre-frontend/src/lib/types.ts`
- Modify: `deploy/sre-frontend/src/lib/keep-api.ts`
- Test: `deploy/tests/test_shared_maintenance_ui.py`

- [ ] **Step 1: Write failing source-level tests for the new frontend helpers**

```python
from pathlib import Path


KEEP_API_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\lib\keep-api.ts")
TYPES_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\lib\types.ts")


def test_keep_api_exposes_shared_maintenance_bootstrap_helpers():
    keep_api = KEEP_API_PATH.read_text(encoding="utf-8")
    assert "export async function bootstrapSharedMaintenanceAuth" in keep_api
    assert "export async function fetchSharedMaintenanceAuth" in keep_api
    assert "export async function saveSharedMaintenanceAuth" in keep_api
    assert "export async function testSharedMaintenanceAuth" in keep_api


def test_types_include_shared_maintenance_auth_metadata():
    types_text = TYPES_PATH.read_text(encoding="utf-8")
    assert "export interface SharedMaintenanceAuthConfig" in types_text
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest deploy\tests\test_shared_maintenance_ui.py -k "keep_api_exposes or types_include" -v`

Expected: FAIL because the new helpers and type do not exist yet.

- [ ] **Step 3: Add the new types and API helpers**

In `types.ts`:

```ts
export interface SharedMaintenanceAuthConfig {
  configured: boolean;
  username: string;
  updated_by?: string;
  updated_at?: string;
}
```

In `keep-api.ts`:

```ts
export async function fetchSharedMaintenanceAuth(): Promise<SharedMaintenanceAuthConfig> {
  const res = await fetch('/api/auth/shared-integrations/maintenance', { credentials: 'include' });
  const body = await readResponseBody(res);
  if (!res.ok) throw new Error(extractResponseError(body, 'Failed to load shared maintenance auth'));
  return body as SharedMaintenanceAuthConfig;
}

export async function saveSharedMaintenanceAuth(username: string, password: string) {
  const res = await fetch('/api/auth/shared-integrations/maintenance', {
    method: 'PUT',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const body = await readResponseBody(res);
  return { ok: res.ok, error: res.ok ? undefined : extractResponseError(body, 'Failed to save shared maintenance auth') };
}

export async function testSharedMaintenanceAuth() {
  const res = await fetch('/api/auth/shared-integrations/maintenance/test', {
    method: 'POST',
    credentials: 'include',
  });
  const body = await readResponseBody(res);
  return { ok: res.ok, error: res.ok ? undefined : extractResponseError(body, 'Failed to test shared maintenance auth') };
}

export async function bootstrapSharedMaintenanceAuth(): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch('/api/auth/maintenance/bootstrap', {
    method: 'POST',
    credentials: 'include',
  });
  const body = await readResponseBody(res);
  if (!res.ok) return { ok: false, error: extractResponseError(body, 'Failed to bootstrap maintenance auth') };
  if (!body?.token) return { ok: false, error: 'Maintenance bootstrap succeeded but no token was returned.' };
  setMaintenanceAuthToken(body.token);
  return { ok: true };
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `python -m pytest deploy\tests\test_shared_maintenance_ui.py -k "keep_api_exposes or types_include" -v`

Expected: PASS for helper exports and shared auth type presence.

- [ ] **Step 5: Commit**

```bash
git add deploy/sre-frontend/src/lib/types.ts deploy/sre-frontend/src/lib/keep-api.ts deploy/tests/test_shared_maintenance_ui.py
git commit -m "feat: add shared maintenance auth frontend helpers"
```

## Task 4: Wire Admin Roles UI And Webhooks Auto-Bootstrap

**Files:**
- Modify: `deploy/sre-frontend/src/app/admin/page.tsx`
- Modify: `deploy/sre-frontend/src/app/webhooks/page.tsx`
- Modify: `deploy/sre-frontend/src/lib/auth.ts`
- Test: `deploy/tests/test_shared_maintenance_ui.py`

- [ ] **Step 1: Write failing UI regression tests**

```python
ADMIN_PAGE_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\admin\page.tsx")
WEBHOOKS_PAGE_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\webhooks\page.tsx")


def test_admin_page_contains_shared_maintenance_auth_card():
    page = ADMIN_PAGE_PATH.read_text(encoding="utf-8")
    assert "Shared Maintenance Auth" in page
    assert "fetchSharedMaintenanceAuth" in page
    assert "saveSharedMaintenanceAuth" in page
    assert "testSharedMaintenanceAuth" in page


def test_webhooks_page_bootstraps_for_admin_and_sre():
    page = WEBHOOKS_PAGE_PATH.read_text(encoding="utf-8")
    assert "bootstrapSharedMaintenanceAuth" in page
    assert "user?.role?.name === 'Admin' || user?.role?.name === 'SRE'" in page
    assert "Shared maintenance auth is not configured." in page
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest deploy\tests\test_shared_maintenance_ui.py -k "admin_page_contains or webhooks_page_bootstraps" -v`

Expected: FAIL because the admin card and bootstrap logic are not present yet.

- [ ] **Step 3: Add the admin Roles-tab card**

In `admin/page.tsx`, extend the imports and state:

```ts
import {
  fetchSharedMaintenanceAuth,
  saveSharedMaintenanceAuth,
  testSharedMaintenanceAuth,
  clearSharedMaintenanceAuth,
} from '@/lib/keep-api';

const [sharedMaint, setSharedMaint] = useState<SharedMaintenanceAuthConfig | null>(null);
const [sharedMaintUser, setSharedMaintUser] = useState('');
const [sharedMaintPassword, setSharedMaintPassword] = useState('');
const [sharedMaintSaving, setSharedMaintSaving] = useState(false);
const [sharedMaintTesting, setSharedMaintTesting] = useState(false);
```

Add to `loadData()`:

```ts
const [u, r, maintenance] = await Promise.all([
  fetchUsers(),
  fetchRoles(),
  fetchSharedMaintenanceAuth(),
]);
setSharedMaint(maintenance);
setSharedMaintUser(maintenance.username || '');
```

Render a card above the role list:

```tsx
<div className="bg-surface border border-border rounded-lg p-4 space-y-3">
  <div className="flex items-center justify-between gap-4">
    <div>
      <h3 className="text-sm font-medium text-text-bright">Shared Maintenance Auth</h3>
      <p className="text-xs text-muted mt-1">
        Admin and SRE users auto-connect to maintenance webhook actions using this shared credential.
      </p>
    </div>
    <span className={`text-xs font-medium ${sharedMaint?.configured ? 'text-green' : 'text-yellow'}`}>
      {sharedMaint?.configured ? 'Configured' : 'Not Configured'}
    </span>
  </div>
  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
    <input value={sharedMaintUser} onChange={(e) => setSharedMaintUser(e.target.value)} />
    <input type="password" value={sharedMaintPassword} onChange={(e) => setSharedMaintPassword(e.target.value)} placeholder="Enter new maintenance password" />
  </div>
</div>
```

- [ ] **Step 4: Add webhooks-page bootstrap flow with manual fallback**

In `webhooks/page.tsx`, use auth context:

```ts
import { useAuth } from '@/lib/auth';
import { bootstrapSharedMaintenanceAuth } from '@/lib/keep-api';
```

Inside `MaintenanceAuthCard()`:

```ts
const { user, loading: authLoading } = useAuth();
const eligibleForSharedBootstrap = user?.role?.name === 'Admin' || user?.role?.name === 'SRE';

useEffect(() => {
  if (authLoading) return;
  if (hasMaintenanceAuthToken()) {
    setConnected(true);
    return;
  }
  if (!eligibleForSharedBootstrap) {
    setConnected(false);
    return;
  }
  let cancelled = false;
  setLoading(true);
  bootstrapSharedMaintenanceAuth()
    .then((result) => {
      if (cancelled) return;
      if (result.ok) {
        setConnected(true);
        setError('');
      } else {
        setConnected(false);
        setError(result.error || 'Shared maintenance auth is not configured.');
      }
    })
    .finally(() => {
      if (!cancelled) setLoading(false);
    });
  return () => {
    cancelled = true;
  };
}, [authLoading, eligibleForSharedBootstrap]);
```

Adjust the helper text:

```tsx
<p className="text-xs text-muted mt-1">
  Admin and SRE users auto-connect using the shared maintenance credential. Other roles sign in here per session.
</p>
```

Keep the manual form visible when `!connected`, regardless of bootstrap failure.

- [ ] **Step 5: Run frontend regression tests and backend auth tests**

Run: `python -m pytest deploy\tests\test_shared_maintenance_ui.py deploy\tests\test_auth_shared_maintenance.py -v`

Expected: PASS, including admin-card presence and auto-bootstrap wiring.

- [ ] **Step 6: Commit**

```bash
git add deploy/sre-frontend/src/app/admin/page.tsx deploy/sre-frontend/src/app/webhooks/page.tsx deploy/sre-frontend/src/lib/auth.ts deploy/tests/test_shared_maintenance_ui.py
git commit -m "feat: auto-bootstrap shared maintenance auth"
```

## Task 5: Environment Wiring And Live Verification

**Files:**
- Modify: `deploy/docker-compose.yml` (only if needed for `SHARED_INTEGRATIONS_SECRET`)
- Modify: `deploy/auth-api/auth-api.py` (only if startup validation needs a clearer operator log)
- Test: existing pytest files plus live smoke checks

- [ ] **Step 1: Write the failing env/config regression test if new env wiring is needed**

If `auth-api` relies on `docker-compose.yml` to inject the new secret, add a source-level test in `deploy/tests/test_auth_shared_maintenance.py`:

```python
def test_auth_api_compose_includes_shared_integrations_secret():
    compose = Path(r"C:\Users\fash\Documents\UIP\deploy\docker-compose.yml").read_text(encoding="utf-8")
    assert "SHARED_INTEGRATIONS_SECRET" in compose
```

- [ ] **Step 2: Run the regression test to verify it fails**

Run: `python -m pytest deploy\tests\test_auth_shared_maintenance.py -k "compose_includes_shared_integrations_secret" -v`

Expected: FAIL only if compose wiring is missing.

- [ ] **Step 3: Add minimal env wiring**

In `docker-compose.yml`, add the new env var alongside `AUTH_SECRET` for `auth-api`:

```yaml
      AUTH_SECRET: ${AUTH_SECRET}
      SHARED_INTEGRATIONS_SECRET: ${SHARED_INTEGRATIONS_SECRET}
```

If the stack already injects a compatible secret via another shared env source, skip this file change and document that verification instead.

- [ ] **Step 4: Run full verification**

Run:

```bash
python -m pytest deploy\tests\test_auth_shared_maintenance.py deploy\tests\test_shared_maintenance_ui.py -v
python -m py_compile deploy\auth-api\auth-api.py
```

Expected:
- pytest: all PASS
- py_compile: clean exit, no output

Live verification checklist after deploy:

```text
1. Save shared maintenance username/password from Admin -> Roles -> Shared Maintenance Auth.
2. Click Test and confirm success.
3. Sign in as Admin, open Webhooks, confirm Connected without manual sign-in.
4. Sign in as SRE, open Webhooks, confirm Connected without manual sign-in.
5. Sign in as Viewer, open Webhooks, confirm manual maintenance sign-in is still required.
6. Perform one protected webhook action as Admin or SRE, such as rotate secret or create subscriber.
7. Clear the shared maintenance config and confirm Admin/SRE now receive the explicit unconfigured message.
```

- [ ] **Step 5: Commit**

```bash
git add deploy/docker-compose.yml deploy/auth-api/auth-api.py deploy/tests/test_auth_shared_maintenance.py
git commit -m "chore: wire shared maintenance auth config"
```

## Self-Review

### Spec coverage

- Shared credential storage: Task 1
- Shared credential admin management: Task 2 and Task 4
- Auto-bootstrap for `Admin`/`SRE`: Task 2 and Task 4
- Manual per-session login for other roles: Task 4
- Clear error states: Task 2 and Task 4
- Environment/config rollout: Task 5

No spec gaps remain.

### Placeholder scan

- No `TODO`, `TBD`, or “implement later” placeholders remain.
- Each task includes exact files, commands, and code snippets.
- The only conditional is `docker-compose.yml` wiring, which is explicitly gated on whether the env var is already supplied elsewhere.

### Type consistency

- Shared metadata type is `SharedMaintenanceAuthConfig` across the plan.
- Bootstrap helper is consistently named `bootstrapSharedMaintenanceAuth`.
- Server storage key is consistently `maintenance_api`.

