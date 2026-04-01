# Shared Maintenance Auth Design

## Goal

Allow `Admin` and `SRE` users to use Maintenance API protected webhook actions without manually signing in on every browser session, while keeping all other roles on the current per-session username/password sign-in flow.

The shared maintenance credential should be configured once centrally by an authorized admin and reused only for `Admin` and `SRE`.

## Scope

In scope:
- shared maintenance credential storage in UIP
- admin UI for managing the shared maintenance credential
- automatic maintenance token bootstrap for `Admin` and `SRE`
- preservation of manual maintenance sign-in for all other roles
- clear error states when shared credentials are missing or invalid

Out of scope:
- changing Maintenance API behavior
- changing webhook subscriber authorization rules
- persisting per-user maintenance credentials
- assigning saved maintenance credentials to non-`Admin`/`SRE` roles

## Current State

Today, protected maintenance webhook actions rely on a Maintenance API bearer token stored in browser session storage by the Webhooks page. Users must manually sign in through the page every session. UIP role and permission data already lives in `auth-api`, and the existing admin UI already manages users and roles, but there is no storage or UI for shared maintenance credentials.

## Requirements

### Functional

- `Admin` and `SRE` users should not need to manually sign in on the Webhooks page when shared maintenance credentials are configured and valid.
- Shared maintenance credentials should be configured once in the admin experience and reused across all `Admin` and `SRE` users.
- Users outside `Admin` and `SRE` should continue to sign in manually on the Webhooks page with their assigned maintenance username/password.
- Existing webhook write actions should keep using the current maintenance bearer-token flow after bootstrap, so the rest of the page behavior changes as little as possible.
- Admin users with `manage_roles` should be able to create, update, clear, and validate the shared maintenance credential.

### Security

- The shared maintenance password must remain server-side and must never be returned to the browser after save.
- Only users with `manage_roles` may manage the shared maintenance credential.
- Automatic bootstrap must verify the currently signed-in UIP user role or permissions before performing a server-side maintenance login.
- Error responses should not leak the stored password or raw secrets.

### UX

- The Admin UI should show whether shared maintenance auth is configured and when it was last updated.
- The Webhooks page should show `Connected` automatically for eligible users when bootstrap succeeds.
- If automatic bootstrap fails for an eligible user, the page should show a clear reason:
  - shared maintenance auth is not configured
  - shared maintenance auth is invalid
  - maintenance API unavailable
- Manual sign-in should remain available as a fallback path.

## Proposed Approach

Use a server-side shared maintenance-auth configuration stored in `auth-api`, plus a bootstrap endpoint that exchanges the stored maintenance username/password for a maintenance bearer token only for eligible users.

This keeps the shared credential server-side, avoids a large proxy rewrite of the existing webhooks write path, and preserves the current frontend write calls once a token has been obtained.

## Architecture

### Data Model

Add a new single-row configuration table in `auth-api`:

- `shared_integrations`
  - `key` text primary key
  - `username` text not null default `''`
  - `password_ciphertext` text not null default `''`
  - `updated_by` text default `''`
  - `updated_at` text default current timestamp

The first and only planned `key` is `maintenance_api`.

Password storage should be encrypted at rest using a UIP-side symmetric secret from environment configuration. If a secure existing encryption helper already exists in the project, reuse it. If not, add one in `auth-api` with a required environment key and fail closed when the key is missing.

### Backend API

Add auth-api endpoints:

- `GET /api/auth/shared-integrations/maintenance`
  - permission: `manage_roles`
  - returns configured status, username, updated_by, updated_at
  - never returns the password

- `PUT /api/auth/shared-integrations/maintenance`
  - permission: `manage_roles`
  - accepts `username` and `password`
  - encrypts and stores the password
  - supports replacing the current credential

- `DELETE /api/auth/shared-integrations/maintenance`
  - permission: `manage_roles`
  - clears the stored shared maintenance credential

- `POST /api/auth/shared-integrations/maintenance/test`
  - permission: `manage_roles`
  - attempts a server-side login against `/api/maintenance/auth/login`
  - returns success or a sanitized error

- `POST /api/auth/maintenance/bootstrap`
  - permission gate: current UIP user must have role name `Admin` or `SRE`
  - reads the stored shared maintenance credential
  - performs a server-side login to the Maintenance API
  - returns only the maintenance bearer token and optional expiry metadata
  - returns explicit errors for unconfigured, invalid, or unavailable upstream auth

### Frontend

#### Admin Page

Extend the Roles tab in the existing admin page with a `Shared Maintenance Auth` card that includes:
- current configured username
- configured/not configured status
- last updated timestamp and actor
- password input for rotation
- `Save`, `Test`, and `Clear` actions

The password field should always render blank on load and only send a new value when the admin explicitly updates it.

#### Webhooks Page

Adjust `MaintenanceAuthCard` behavior:
- on load, inspect the signed-in UIP user
- if role is `Admin` or `SRE`, attempt automatic bootstrap through `/api/auth/maintenance/bootstrap`
- if bootstrap succeeds, store the returned maintenance token in the same session storage key currently used by webhook write calls
- if bootstrap fails, show the reason and keep the manual sign-in controls available
- if role is not `Admin` or `SRE`, keep the current manual sign-in flow unchanged

This keeps existing `create/edit/delete/rotate-secret` client code largely intact.

## Data Flow

### Admin/SRE Automatic Flow

1. User signs into UIP.
2. Webhooks page loads.
3. Frontend detects user role is `Admin` or `SRE`.
4. Frontend calls `/api/auth/maintenance/bootstrap`.
5. `auth-api` validates UIP auth, reads shared maintenance credentials, and logs into the Maintenance API server-side.
6. `auth-api` returns a maintenance bearer token.
7. Frontend stores the token in existing session storage and uses the existing webhook write flow.

### Non-Admin/SRE Manual Flow

1. User opens Webhooks page.
2. No automatic bootstrap is attempted, or the user is marked ineligible.
3. User signs in manually with maintenance username/password.
4. Frontend stores that returned token in session storage and uses existing webhook write calls.

## Error Handling

- Missing shared credential:
  - bootstrap returns `409` or `400` with `Shared maintenance auth is not configured.`
- Invalid stored credential:
  - bootstrap returns `502` with a sanitized error such as `Stored shared maintenance auth is invalid.`
- Maintenance API unavailable:
  - bootstrap returns `502` with `Maintenance API is unavailable.`
- Ineligible user:
  - bootstrap returns `403`
- Encryption key missing:
  - admin save/test/bootstrap should fail closed with a clear operator-facing error and a server log entry

The Webhooks page should never silently fail back to `Not Connected` without explanation for eligible users.

## Testing

### Backend

- migration/initialization test for new shared-integrations table
- round-trip test for save/read metadata without exposing stored password
- encryption/decryption test for shared maintenance credential
- permission tests for get/put/delete/test endpoints
- bootstrap tests for:
  - eligible admin/sre success
  - ineligible role rejection
  - missing configuration
  - invalid stored credentials
  - upstream unavailable

### Frontend

- admin page renders shared maintenance auth card only for authorized users
- save/test/clear UI states
- webhooks page auto-bootstrap for `Admin`
- webhooks page auto-bootstrap for `SRE`
- manual sign-in path remains for non-eligible roles
- bootstrap failure leaves manual sign-in available and surfaces message

### Live Verification

- configure shared maintenance auth once as admin
- verify `Admin` user opens Webhooks and is auto-connected without manual sign-in
- verify `SRE` user gets the same auto-connect behavior
- verify a non-`Admin`/`SRE` user still sees manual sign-in and cannot auto-bootstrap
- verify at least one protected webhook write action succeeds after auto-bootstrap
- clear the shared credential and verify eligible users get the expected unconfigured error

## Rollout Notes

- This should be deployed behind the existing UIP auth boundary; no public unauthenticated endpoints are added.
- Because the worktree is already active with unrelated changes, implementation should avoid touching unrelated auth or webhook behaviors beyond the shared-auth flow.
- If maintenance token lifetime proves short in practice, the current design still works because bootstrap is cheap and can be retried on page load or after token expiry.
