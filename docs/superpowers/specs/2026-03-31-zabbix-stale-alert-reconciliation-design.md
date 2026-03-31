# Zabbix Stale Alert Reconciliation - Design Spec

**Date:** 2026-03-31
**Author:** fash + Codex
**Status:** Draft

---

## Goal

Resolve stale Node/Kubernetes alerts from the Command Center much faster when Zabbix deletes and recreates the underlying problem instead of sending a clean recovery event.

The design should aggressively remove stale board entries without turning the enricher into a heavy Zabbix poller or causing load issues for Zabbix.

## Architecture

The alert enricher keeps ownership of stale-alert reconciliation. It already polls Keep and has the Zabbix credentials needed for verification, so the new behavior stays in one service.

The new logic adds a lightweight, bounded reconciliation pass for Zabbix-origin alerts:

1. Build a stable alert signature that survives Zabbix event/trigger recreation
2. Track short-lived suspicion state in memory per signature
3. Batch-check only a capped set of suspicious alerts against Zabbix
4. Resolve alerts after two consecutive misses, or immediately when a newer alert with the same stable signature appears

The frontend should not need special handling for this change. The board gets better because the underlying Keep alert state is corrected faster.

## Non-Goals

- Rebuilding the Keep alert lifecycle model
- Adding a new persistent database for reconciliation state
- Polling all Zabbix active problems every cycle
- Changing non-Zabbix providers
- Reworking Command Center grouping or visualization

---

## Problem Summary

Today stale cleanup in [enricher.py](C:/Users/fash/Documents/UIP/deploy/enricher.py) is based on `triggerId`, `zabbixInstance`, and a long stale timeout (`STALE_RESOLVE_SECONDS`, currently 7200 seconds). That works for some deleted triggers, but it is too conservative for Node/Kubernetes alerts where Zabbix often deletes one problem object and recreates a new one for the same real-world issue.

This creates two failure modes:

1. The old alert remains visible much longer than operators expect because it must age past the stale timeout before verification starts.
2. The recreated alert has a new trigger/event identity, so the system cannot easily tell that the older board entry has been superseded by a newer Zabbix object.

The result is a firing board that can feel stale even though Keep and Zabbix eventually converge.

---

## Component 1: Stable Zabbix Alert Signature

### New function

**`build_stable_zabbix_signature(alert) -> str | None`**

This function derives a normalized identity for a Zabbix alert that stays stable across event recreation.

### Required fields

Base prefix:

```python
f"{zabbix_instance}|{target_family}|{alert_family}|{scope_key}"
```

Where:

- `zabbix_instance` comes from `alert["zabbixInstance"]`
- `target_family` is inferred from tags and alert naming, prioritizing:
  - `kubernetes`
  - `nodes`
  - fallback `generic`
- `alert_family` is a normalized version of the alert name with volatile values removed
- `scope_key` comes from the strongest available Zabbix tags

### Scope-key rules

For Kubernetes-style alerts, build the scope key from tags in this order:

1. `namespace + pod`
2. `namespace + replicaset`
3. `namespace + deployment` if present
4. `namespace + node`
5. fallback host/service name

For Node-style alerts, prefer:

1. `node`
2. host extracted from name
3. `hostName` / `hostname`

### Name normalization

Normalize alert names by removing volatile identifiers that should not create a new logical issue, such as:

- replica hashes like `-6f5c8f6d75`
- dynamic pod suffixes like `-7mg5f`
- repeated whitespace

Examples:

- `Kubernetes: Namespace [default] RS [ryinterface-nominet-cymru-enom-tdp-6f5c8f6d75]: ReplicaSet mismatch`
  becomes a stable family like
  `kubernetes|replicaset_mismatch|default|ryinterface-nominet-cymru-enom-tdp`

- `Node [ip-10-108-24-11.ec2.internal] Pod [order-api-tdp-865488c957-nhh2l]: Pod is crash looping`
  becomes
  `nodes|pod_crash_looping|default|order-api-tdp`

If the alert does not have enough signal to build a trustworthy signature, return `None` and let the legacy stale path handle it.

---

## Component 2: In-Memory Suspicion Tracker

### New structure

Add an in-memory tracker in [enricher.py](C:/Users/fash/Documents/UIP/deploy/enricher.py):

```python
stale_reconcile_tracker = {
    "<instance>|<signature>": {
        "fingerprint": "...",
        "trigger_id": "...",
        "first_seen_at": 0.0,
        "last_seen_in_keep_at": 0.0,
        "last_checked_at": 0.0,
        "consecutive_missing_checks": 0,
    }
}
```

### Lifecycle

- Updated every poll cycle from current active alerts
- Cleared when the alert disappears from Keep or is confirmed active in Zabbix
- Replaced when a newer Keep alert with the same signature appears
- Best-effort only; loss on restart is acceptable

Persistence is intentionally out of scope because this is reconciliation state, not operator state.

---

## Component 3: Candidate Selection And Rate Limits

### New function

**`collect_reconcile_candidates(active_alerts) -> dict[instance, list[candidate]]`**

This function produces a bounded candidate set for Zabbix verification.

### Candidate eligibility

A candidate must:

- have `providerType == "zabbix"` or `source` containing `zabbix`
- include a recognized `zabbixInstance`
- include a `triggerId`
- be in a firing-like state in Keep
- be older than a short grace period, default `STALE_RECONCILE_GRACE_SECONDS = 300`

Priority order:

1. alerts with a stable Kubernetes/Node signature
2. alerts that already have `consecutive_missing_checks > 0`
3. legacy stale-trigger candidates

### Rate-limiting rules

Add new configuration values in [docker-compose.yml](C:/Users/fash/Documents/UIP/deploy/docker-compose.yml):

- `STALE_RECONCILE_INTERVAL_SECONDS=60`
- `STALE_RECONCILE_GRACE_SECONDS=300`
- `STALE_RECONCILE_MAX_PER_INSTANCE=25`
- `STALE_RECONCILE_MISSES_REQUIRED=2`

Behavior:

- run reconciliation at most once per 60 seconds
- batch by Zabbix instance
- never exceed 25 candidates per instance per run
- reuse the cached Zabbix auth token already present in the enricher

This keeps the design aggressive for operators but lightweight for Zabbix.

---

## Component 4: Superseded-By-Newer Detection

### New function

**`resolve_superseded_alerts(active_alerts)`**

Before doing Zabbix miss-based resolution, compare active alerts by stable signature.

If two or more active alerts share the same stable signature:

- keep the newest alert active
- immediately resolve the older alert(s)
- log the reason as `superseded_by_newer_signature_match`

"Newest" should be chosen by:

1. latest `lastReceived`
2. then latest `startedAt` / `firingStartTime`

This is the main fix for deleted-and-recreated Node/Kubernetes alerts. It avoids waiting for the older object to age out before the board cleans up.

### Safety rule

Only apply immediate supersede resolution when:

- both alerts come from the same `zabbixInstance`, and
- both produce the same non-`None` stable signature

Do not supersede generic alerts that do not have a trustworthy signature.

---

## Component 5: Consecutive-Miss Verification

### New function

**`reconcile_stale_zabbix_alerts(active_alerts)`**

This replaces the current "2-hour stale then check trigger" behavior for Node/Kubernetes-style alerts, while preserving a conservative fallback for everything else.

### Verification flow

For each instance batch:

1. Build the candidate list
2. Query Zabbix once with `trigger.get` for the candidate trigger IDs
3. Compare the returned active trigger set against the candidate set

Per candidate:

- trigger present and active in Zabbix:
  - set `consecutive_missing_checks = 0`
- trigger missing from Zabbix:
  - increment `consecutive_missing_checks`
- when misses reach `STALE_RECONCILE_MISSES_REQUIRED`:
  - resolve the alert in Keep
  - log `resolved_after_consecutive_zabbix_misses`

### Why two misses

Two misses provide a fast but safe guardrail:

- a single bad check or transient Zabbix gap does not immediately resolve the alert
- two consecutive misses at 60-second intervals clear the board in about 2 minutes after grace time

This is much more aggressive than today without being reckless.

---

## Component 6: Legacy Fallback Path

Keep the existing long-tail trigger verification for non-Node/Kubernetes alerts that do not produce a stable signature.

Changes:

- retain existing trigger-based verification helpers
- reduce dependence on `STALE_RESOLVE_SECONDS` for signed Kubernetes/Node candidates
- preserve the old path for generic Zabbix alerts where aggressive reconciliation could be ambiguous

This splits the behavior:

- **aggressive path** for trusted Node/Kubernetes signatures
- **conservative path** for everything else

---

## Resolution Payload And Audit Trail

When auto-resolving through this reconciler, continue posting a synthetic Zabbix OK event into Keep using the existing `/alerts/event/zabbix` path.

Update the description or note reason to make the source of the resolution explicit:

- `Auto-resolved: superseded by newer Zabbix alert with same stable signature`
- `Auto-resolved: missing from Zabbix for 2 consecutive reconciliation checks`

Required log lines:

- candidate counts per instance
- rate-limit skips
- supersede decisions
- miss counts
- final resolution reason

This makes live debugging much easier when operators question why something disappeared from the board.

---

## Failure Handling

If Zabbix is unavailable, do nothing destructive.

Rules:

- failed login or failed `trigger.get` call must not resolve alerts
- on API failure, keep suspicion state but do not increment miss counts
- if the candidate cap is exceeded, defer the oldest low-priority candidates to the next run

This ensures that Zabbix instability cannot create false resolves.

---

## Testing

### Local verification

Add focused tests or a small deterministic harness for:

1. stable signature generation for:
   - Kubernetes pod crash-loop alerts
   - Kubernetes ReplicaSet mismatch alerts
   - Node pod crash-loop alerts
2. superseded-by-newer behavior
3. consecutive miss counting
4. candidate capping and per-instance batching

### Live verification

After deploy:

1. identify a live stale Node/Kubernetes alert family
2. confirm multiple recreated alerts map to the same stable signature
3. confirm the older alert resolves within the grace + two-check window
4. confirm logs show one bounded batched check per instance, not a full Zabbix sweep
5. confirm non-Kubernetes Zabbix alerts still follow the conservative fallback path

---

## Success Criteria

- stale Node/Kubernetes alerts disappear from the firing board within a few minutes, not hours
- recreated Zabbix alerts do not leave older board entries behind
- reconciliation performs at most one bounded batch check per instance per interval
- Zabbix outages do not create false resolves
- generic Zabbix alerts continue to work under the fallback logic
