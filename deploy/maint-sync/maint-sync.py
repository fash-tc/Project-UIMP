"""
Maintenance Tracker -> Keep Maintenance Window Sync Service.
Polls the maintenance tracker for active events, builds CEL queries
via keyword matching, and creates/deletes Keep maintenance rules.
"""

import json
import time
import os
import re
import logging
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("maint-sync")

MAINT_TRACKER_URL = os.environ.get("MAINT_TRACKER_URL", "http://10.177.154.174/api/active-now")
KEEP_URL = os.environ.get("KEEP_URL", "http://keep-api:8080")
KEEP_API_KEY = os.environ.get("KEEP_API_KEY", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "300"))
DEFAULT_DURATION_HOURS = int(os.environ.get("DEFAULT_DURATION_HOURS", "8"))

# ── Keyword Mapping ──────────────────────────────────────────────

# Static map: keyword found in event text -> hostname/service patterns for CEL
VENDOR_KEYWORD_MAP = {
    # Registrar platforms
    "opensrs":    ["opensrs", "prod-opensrs"],
    "enom":       ["enom", "prod-enom"],
    "ascio":      ["ascio", "prod-ascio"],
    # Infrastructure services
    "dns":        ["dns"],
    "epp":        ["epp"],
    "whois":      ["whois"],
    # Registries
    "red.es":     ["red.es"],
    "cira":       ["cira"],
    "verisign":   ["verisign"],
    "centralnic": ["centralnic"],
    "afilias":    ["afilias"],
    "neustar":    ["neustar"],
    # Database / infra
    "mysql":      ["mysql"],
    "postgres":   ["postgres"],
}

# Extract hostname-like patterns from event text
HOSTNAME_PATTERN = re.compile(r"\b(prod-[a-z0-9][\w-]*)\b", re.IGNORECASE)
FQDN_PATTERN = re.compile(r"\b([a-z][\w-]*\d+\.[\w.-]+\.[a-z]{2,})\b", re.IGNORECASE)

# ── State ────────────────────────────────────────────────────────

# Maps maintenance tracker event ID -> Keep rule info
synced_rules = {}  # {event_id: {"keep_rule_id": int, "name": str, "cel_query": str}}

# ── Keep API ─────────────────────────────────────────────────────

def keep_request(path, method="GET", data=None):
    """Make a request to the Keep API."""
    url = f"{KEEP_URL}{path}"
    body = json.dumps(data).encode() if data else None
    headers = {"Content-Type": "application/json"}
    if KEEP_API_KEY:
        headers["X-API-KEY"] = KEEP_API_KEY
    req = Request(url, data=body, method=method, headers=headers)
    try:
        resp = urlopen(req, timeout=30)
        raw = resp.read()
        return json.loads(raw) if raw else {}
    except HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode()[:200]
        except Exception:
            pass
        log.error(f"Keep API {e.code} on {method} {path}: {body_text}")
        return None
    except Exception as e:
        log.error(f"Keep request failed: {e}")
        return None

# ── Maintenance Tracker ──────────────────────────────────────────

def fetch_maintenance_events():
    """Fetch currently active maintenance events. Returns None on failure."""
    try:
        req = Request(MAINT_TRACKER_URL, headers={"Accept": "application/json"})
        resp = urlopen(req, timeout=15)
        data = json.loads(resp.read())
        if isinstance(data, dict):
            return data.get("results", [])
        return data if isinstance(data, list) else []
    except Exception as e:
        log.error(f"Failed to fetch maintenance events: {e}")
        return None  # None = fetch failed, don't delete rules

# ── CEL Query Building ───────────────────────────────────────────

def build_cel_query(event):
    """Build a CEL query matching alerts related to this maintenance event.
    Returns a CEL string, or None if no meaningful match can be built."""
    title = event.get("title", "")
    vendor = event.get("vendor", "")
    summary = event.get("summary", "") or ""
    impact = event.get("impact", "") or ""
    combined = f"{title} {vendor} {summary} {impact}".lower()

    match_terms = set()

    # 1. Static keyword map
    for keyword, patterns in VENDOR_KEYWORD_MAP.items():
        if keyword in combined:
            match_terms.update(patterns)

    # 2. Extract "prod-xxx" patterns from title
    for m in HOSTNAME_PATTERN.finditer(title):
        match_terms.add(m.group(1).lower())

    # 3. Extract FQDNs from all text
    for m in FQDN_PATTERN.finditer(combined):
        match_terms.add(m.group(1).lower())

    # 4. Fallback: use vendor name if specific enough
    if not match_terms:
        vendor_clean = vendor.strip().lower()
        if vendor_clean and len(vendor_clean) > 3 and vendor_clean not in ("n/a", "none", "internal", "null"):
            match_terms.add(vendor_clean)

    if not match_terms:
        return None

    # Build CEL: OR across name/hostname/service contains checks
    conditions = []
    for term in sorted(match_terms):
        safe = term.replace('"', '\\"')
        conditions.append(
            f'(name.contains("{safe}") || hostname.contains("{safe}") || service.contains("{safe}"))'
        )

    return " || ".join(conditions)

# ── Rule Management ──────────────────────────────────────────────

def create_keep_rule(event, cel_query):
    """Create a maintenance rule in Keep. Returns rule ID or None."""
    event_type = event.get("event_type", "change")
    suppress = event_type == "maintenance"

    start_time = event.get("start_time", "")
    end_time = event.get("end_time")

    # Calculate duration
    duration_seconds = None
    if start_time and end_time:
        try:
            st = datetime.fromisoformat(start_time)
            et = datetime.fromisoformat(end_time)
            duration_seconds = max(int((et - st).total_seconds()), 0)
        except (ValueError, TypeError):
            pass

    if not duration_seconds or duration_seconds <= 0:
        duration_seconds = DEFAULT_DURATION_HOURS * 3600

    # Add 1hr buffer (30min before + 30min after)
    duration_seconds += 3600

    # Shift start 30min earlier
    try:
        st = datetime.fromisoformat(start_time)
        adjusted_start = st - timedelta(minutes=30)
        start_iso = adjusted_start.isoformat()
    except (ValueError, TypeError):
        start_iso = start_time

    name = f"[auto-sync] {event.get('title', 'Unknown')[:80]}"
    description = (
        f"Auto-synced from Maintenance Tracker (event #{event.get('id')}). "
        f"Vendor: {event.get('vendor', 'N/A')}. "
        f"Type: {event_type}. "
        f"{'SUPPRESSING alerts' if suppress else 'Tracking only (no suppression)'}."
    )

    payload = {
        "name": name,
        "description": description,
        "cel_query": cel_query,
        "start_time": start_iso,
        "duration_seconds": duration_seconds,
        "suppress": suppress,
        "enabled": True,
    }

    result = keep_request("/maintenance", method="POST", data=payload)
    if result and "id" in result:
        return result["id"]
    return None


def delete_keep_rule(rule_id):
    """Delete a maintenance rule from Keep."""
    result = keep_request(f"/maintenance/{rule_id}", method="DELETE")
    return result is not None

# ── Reconciliation ───────────────────────────────────────────────

def reconcile_on_startup():
    """Read existing auto-synced rules from Keep to rebuild state after restart."""
    rules = keep_request("/maintenance")
    if not rules or not isinstance(rules, list):
        log.info("No existing maintenance rules in Keep")
        return

    for rule in rules:
        name = rule.get("name", "")
        if not name.startswith("[auto-sync]"):
            continue
        desc = rule.get("description", "")
        match = re.search(r"event #(\d+)", desc)
        if match:
            event_id = int(match.group(1))
            synced_rules[event_id] = {
                "keep_rule_id": rule["id"],
                "name": name,
                "cel_query": rule.get("cel_query", ""),
            }

    log.info(f"Reconciled {len(synced_rules)} existing auto-synced rules from Keep")

# ── Main Loop ────────────────────────────────────────────────────

def sync_once():
    """One sync cycle."""
    events = fetch_maintenance_events()
    if events is None:
        log.warning("Skipping sync cycle — maintenance tracker unreachable")
        return

    active_event_ids = set()
    created = 0
    skipped = 0

    for event in events:
        event_id = event.get("id")
        if event_id is None:
            continue
        active_event_ids.add(event_id)

        if event_id in synced_rules:
            continue

        cel_query = build_cel_query(event)
        if not cel_query:
            skipped += 1
            log.debug(f"Skipping event #{event_id} ({event.get('title', '')[:50]}): no CEL keywords")
            continue

        event_type = event.get("event_type", "change")
        suppress = event_type == "maintenance"
        log.info(
            f"Creating rule: event #{event_id} \"{event.get('title', '')[:60]}\" "
            f"[type={event_type}, suppress={suppress}]"
        )
        log.info(f"  CEL: {cel_query[:150]}")

        rule_id = create_keep_rule(event, cel_query)
        if rule_id:
            synced_rules[event_id] = {
                "keep_rule_id": rule_id,
                "name": event.get("title", "")[:80],
                "cel_query": cel_query,
            }
            created += 1
            log.info(f"  -> Created Keep rule #{rule_id}")
        else:
            log.warning(f"  -> Failed to create rule for event #{event_id}")

    # Clean up expired rules
    expired_ids = set(synced_rules.keys()) - active_event_ids
    deleted = 0
    for event_id in expired_ids:
        rule_info = synced_rules[event_id]
        rule_id = rule_info["keep_rule_id"]
        log.info(f"Deleting expired rule #{rule_id} for event #{event_id} ({rule_info['name'][:50]})")
        if delete_keep_rule(rule_id):
            del synced_rules[event_id]
            deleted += 1
        else:
            log.warning(f"  -> Failed to delete rule #{rule_id}, will retry")

    log.info(
        f"Sync: {len(events)} events, {len(synced_rules)} active rules, "
        f"+{created} created, -{deleted} deleted, {skipped} skipped (no keywords)"
    )


def main():
    log.info("Maintenance Sync Service starting")
    log.info(f"  Tracker: {MAINT_TRACKER_URL}")
    log.info(f"  Keep: {KEEP_URL}")
    log.info(f"  Poll interval: {POLL_INTERVAL}s")

    reconcile_on_startup()

    while True:
        try:
            sync_once()
        except Exception as e:
            log.error(f"Sync cycle failed: {e}", exc_info=True)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
