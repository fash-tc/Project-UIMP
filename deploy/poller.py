#!/usr/bin/env python3
"""Zabbix -> Keep poller. Polls Zabbix API for active problems and forwards them to Keep.

Replicates the Grafana-Alerts action filters:
  - Host group 30 (Alerta) only
  - Severity >= Warning (2)
  - Not in maintenance (suppressed=False)
  - Exclude trigger 3034311

Only fetches problems from the last 24 hours.
Tracks previously-sent alerts so that when a problem clears in Zabbix,
a resolved ('ok') event is sent to Keep to auto-resolve it.
On startup, resolves any stale alerts in Keep that are no longer active in Zabbix.
"""

import json
import time
import ssl
import os
import logging
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('zabbix-poller')

ZABBIX_URL = os.environ.get('ZABBIX_URL')
ZABBIX_USER = os.environ.get('ZABBIX_USER')
ZABBIX_PASS = os.environ.get('ZABBIX_PASS')
KEEP_URL = os.environ.get('KEEP_URL')
KEEP_API_KEY = os.environ.get('KEEP_API_KEY')
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '120'))
MAX_AGE_HOURS = int(os.environ.get('MAX_AGE_HOURS', '24'))

if not all([ZABBIX_URL, ZABBIX_USER, ZABBIX_PASS, KEEP_URL, KEEP_API_KEY]):
    raise RuntimeError("Missing required env vars: ZABBIX_URL, ZABBIX_USER, ZABBIX_PASS, KEEP_URL, KEEP_API_KEY")

# Derive Keep base URL from the webhook URL (strip /alerts/event/zabbix)
KEEP_BASE_URL = KEEP_URL.rsplit('/alerts/event/', 1)[0] if '/alerts/event/' in KEEP_URL else KEEP_URL.rsplit('/', 1)[0]

ALERT_GROUP_IDS = [30]
MIN_SEVERITY = 2
EXCLUDED_TRIGGER_IDS = ['3034311']

# Track active problems between polls so we can detect resolved ones
# Key: eventid, Value: alert dict (for sending resolved event)
previous_active = {}

# Allow self-signed certs
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def format_metric_values(items):
    """Format Zabbix item values into a readable metrics string."""
    if not items:
        return ''
    parts = []
    for item in items[:5]:
        name = item.get('name', '')
        val = item.get('lastvalue', '')
        units = item.get('units', '')
        if not name or val == '':
            continue
        try:
            num = float(val)
            val = str(int(num)) if num == int(num) else f"{num:.1f}"
        except (ValueError, TypeError):
            pass
        parts.append(f"{name}: {val}{units}" if units else f"{name}: {val}")
    return ' | '.join(parts)


def zabbix_api(method, params, auth=None):
    body = json.dumps({
        'jsonrpc': '2.0',
        'method': method,
        'params': params,
        'auth': auth,
        'id': 1
    }).encode()
    req = Request(ZABBIX_URL, data=body, headers={'Content-Type': 'application/json'})
    resp = urlopen(req, context=ctx, timeout=30)
    data = json.loads(resp.read())
    if 'error' in data:
        raise Exception(f"Zabbix API error: {data['error']}")
    return data['result']


def send_to_keep(alert):
    body = json.dumps(alert).encode()
    req = Request(KEEP_URL, data=body, headers={
        'Content-Type': 'application/json',
        'X-API-KEY': KEEP_API_KEY
    })
    try:
        resp = urlopen(req, timeout=10)
        return resp.status
    except URLError as e:
        log.error(f"Failed to send alert to Keep: {e}")
        return None


def get_keep_alerts():
    """Fetch current alerts from Keep to find stale ones."""
    url = f"{KEEP_BASE_URL}/alerts?limit=500"
    req = Request(url, headers={
        'X-API-KEY': KEEP_API_KEY,
        'Content-Type': 'application/json',
    })
    try:
        resp = urlopen(req, timeout=30)
        data = json.loads(resp.read())
        items = data if isinstance(data, list) else data.get('items', [])
        return items
    except Exception as e:
        log.error(f"Failed to fetch Keep alerts: {e}")
        return []


def resolve_keep_alert(fingerprint):
    """Resolve a specific alert in Keep by fingerprint using the enrich API."""
    url = f"{KEEP_BASE_URL}/alerts/enrich"
    body = json.dumps({
        'fingerprint': fingerprint,
        'enrichments': {'status': 'resolved'},
    }).encode()
    req = Request(url, data=body, method='POST', headers={
        'Content-Type': 'application/json',
        'X-API-KEY': KEEP_API_KEY,
    })
    try:
        resp = urlopen(req, timeout=10)
        return resp.status
    except Exception as e:
        log.error(f"Failed to resolve alert {fingerprint[:16]}: {e}")
        return None


def cleanup_stale_keep_alerts(current_event_ids):
    """Resolve alerts in Keep that are no longer active in Zabbix."""
    keep_alerts = get_keep_alerts()
    if not keep_alerts:
        return 0

    resolved_count = 0
    for alert in keep_alerts:
        # Skip already resolved alerts
        status = alert.get('status', '')
        if status in ('resolved', 'ok'):
            continue

        # Only touch alerts from zabbix source
        source = alert.get('source', [])
        if isinstance(source, list) and 'zabbix' not in source:
            continue

        # Check if this alert's event ID is still active
        alert_id = str(alert.get('id', ''))
        if not alert_id:
            continue

        if alert_id not in current_event_ids:
            fingerprint = alert.get('fingerprint', '')
            if fingerprint:
                code = resolve_keep_alert(fingerprint)
                if code and 200 <= code < 300:
                    resolved_count += 1
                    log.info(f"Resolved stale: {alert.get('name', '')[:50]} ({fingerprint[:16]})")

    return resolved_count


def poll_once(first_run=False):
    global previous_active

    # Login
    auth = zabbix_api('user.login', {'user': ZABBIX_USER, 'password': ZABBIX_PASS})
    log.info("Logged into Zabbix API")

    try:
        # Only fetch problems from the last MAX_AGE_HOURS
        time_from = int(time.time()) - (MAX_AGE_HOURS * 3600)

        # Get active problems — filtered to match Grafana-Alerts action
        problems = zabbix_api('problem.get', {
            'output': 'extend',
            'selectTags': 'extend',
            'recent': True,
            'sortfield': 'eventid',
            'sortorder': 'DESC',
            'groupids': ALERT_GROUP_IDS,
            'severities': list(range(MIN_SEVERITY, 6)),  # [2,3,4,5]
            'suppressed': False,  # excludes maintenance-suppressed
            'time_from': time_from,
            'limit': 200
        }, auth)
        log.info(f"Fetched {len(problems)} active problems from Zabbix (last {MAX_AGE_HOURS}h, group=Alerta, severity>=Warning)")

        # Filter out excluded triggers
        problems = [p for p in problems if p['objectid'] not in EXCLUDED_TRIGGER_IDS]

        # Get trigger+host details
        trigger_ids = list(set(p['objectid'] for p in problems)) if problems else []
        trigger_map = {}
        if trigger_ids:
            triggers = zabbix_api('trigger.get', {
                'output': ['triggerid', 'description', 'url', 'priority'],
                'triggerids': trigger_ids,
                'selectHosts': ['hostid', 'host', 'name'],
                'selectItems': ['itemid', 'name', 'lastvalue', 'units', 'lastclock'],
            }, auth)
            trigger_map = {t['triggerid']: t for t in triggers}

        # Build current active set and send active alerts
        current_active = {}
        sent = 0
        now_zabbix_fmt = time.strftime('%Y.%m.%d %H:%M:%S', time.gmtime())
        for p in problems:
            trig = trigger_map.get(p['objectid'], {})
            host = (trig.get('hosts') or [{}])[0] if trig.get('hosts') else {}
            started_at = time.strftime('%Y.%m.%d %H:%M:%S', time.gmtime(int(p['clock'])))
            tags = json.dumps([{'tag': t['tag'], 'value': t['value']} for t in p.get('tags', [])])
            metrics = format_metric_values(trig.get('items', []))

            status = 'problem'
            if p.get('acknowledged', '0') == '1':
                status = 'acknowledged'

            alert = {
                'id': p['eventid'],
                'triggerId': p['objectid'],
                'name': p['name'],
                'status': status,
                'severity': p.get('severity', '0'),
                'url': trig.get('url', ''),
                'hostName': host.get('name', host.get('host', '')),
                'hostIp': '',
                'lastReceived': now_zabbix_fmt,
                'description': f"{p['name']} [{metrics}] (since {started_at})" if metrics else f"{p['name']} (since {started_at})",
                'tags': tags
            }

            current_active[p['eventid']] = alert

            code = send_to_keep(alert)
            if code and 200 <= code < 300:
                sent += 1

        log.info(f"Sent {sent}/{len(problems)} active alerts to Keep")

        # On first run, clean up stale alerts already in Keep
        if first_run:
            current_event_ids = set(str(eid) for eid in current_active.keys())
            stale_count = cleanup_stale_keep_alerts(current_event_ids)
            if stale_count:
                log.info(f"Cleaned up {stale_count} stale alerts from Keep on startup")

        # Detect resolved: problems that were active last cycle but are gone now
        resolved_ids = set(previous_active.keys()) - set(current_active.keys())
        resolved_count = 0
        for eid in resolved_ids:
            old_alert = previous_active[eid]
            old_alert['status'] = 'ok'
            old_alert['lastReceived'] = time.strftime('%Y.%m.%d %H:%M:%S', time.gmtime())
            code = send_to_keep(old_alert)
            if code and 200 <= code < 300:
                resolved_count += 1
                log.info(f"Resolved in Keep: {old_alert['name'][:60]} (host: {old_alert['hostName']})")

        if resolved_count:
            log.info(f"Sent {resolved_count} resolved alerts to Keep")

        # Update tracking state
        previous_active = current_active
        return sent

    finally:
        try:
            zabbix_api('user.logout', {}, auth)
        except:
            pass


def main():
    log.info(f"Starting Zabbix->Keep poller (interval={POLL_INTERVAL}s, max_age={MAX_AGE_HOURS}h)")
    log.info(f"Zabbix: {ZABBIX_URL}")
    log.info(f"Keep: {KEEP_URL}")
    log.info(f"Filters: groupids={ALERT_GROUP_IDS}, min_severity={MIN_SEVERITY}, excluded_triggers={EXCLUDED_TRIGGER_IDS}")

    first_run = True
    while True:
        try:
            poll_once(first_run=first_run)
            first_run = False
        except Exception as e:
            log.error(f"Poll failed: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
