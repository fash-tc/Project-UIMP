#!/usr/bin/env python3
"""Zabbix -> Keep poller. Polls Zabbix API for active problems and forwards them to Keep.

Replicates the Grafana-Alerts action filters:
  - Host group 30 (Alerta) only
  - Severity >= Warning (2)
  - Not in maintenance (suppressed=False)
  - Exclude trigger 3034311

Tracks previously-sent alerts so that when a problem clears in Zabbix,
a resolved ('ok') event is sent to Keep to auto-resolve it.
"""

import json
import time
import ssl
import os
import logging
from urllib.request import Request, urlopen
from urllib.error import URLError

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('zabbix-poller')

ZABBIX_URL = os.environ.get('ZABBIX_URL', 'https://zabbix.prod-domains-shared.bra2.tucows.systems/api_jsonrpc.php')
ZABBIX_USER = os.environ.get('ZABBIX_USER', 'uip-poller')
ZABBIX_PASS = os.environ.get('ZABBIX_PASS', 'UipPoller2026!')
KEEP_URL = os.environ.get('KEEP_URL', 'http://keep-api:8080/alerts/event/zabbix')
KEEP_API_KEY = os.environ.get('KEEP_API_KEY', '412ff98a-5ea6-450d-8531-4a4940cdc3b4')
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '120'))

# Grafana-Alerts action filters
ALERT_GROUP_IDS = [30]           # "Alerta" host group
MIN_SEVERITY = 2                 # Warning(2), Average(3), High(4), Disaster(5)
EXCLUDED_TRIGGER_IDS = ['3034311']

# Track active problems between polls so we can detect resolved ones
# Key: eventid, Value: alert dict (for sending resolved event)
previous_active = {}

# Allow self-signed certs
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

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

def poll_once():
    global previous_active

    # Login
    auth = zabbix_api('user.login', {'user': ZABBIX_USER, 'password': ZABBIX_PASS})
    log.info("Logged into Zabbix API")

    try:
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
            'limit': 200
        }, auth)
        log.info(f"Fetched {len(problems)} active problems from Zabbix (group=Alerta, severity>=Warning, not suppressed)")

        # Filter out excluded triggers
        problems = [p for p in problems if p['objectid'] not in EXCLUDED_TRIGGER_IDS]

        # Get trigger+host details
        trigger_ids = list(set(p['objectid'] for p in problems)) if problems else []
        trigger_map = {}
        if trigger_ids:
            triggers = zabbix_api('trigger.get', {
                'output': ['triggerid', 'description', 'url', 'priority'],
                'triggerids': trigger_ids,
                'selectHosts': ['hostid', 'host', 'name']
            }, auth)
            trigger_map = {t['triggerid']: t for t in triggers}

        # Build current active set and send active alerts
        current_active = {}
        sent = 0
        for p in problems:
            trig = trigger_map.get(p['objectid'], {})
            host = (trig.get('hosts') or [{}])[0] if trig.get('hosts') else {}
            ts = time.gmtime(int(p['clock']))
            last_received = time.strftime('%Y.%m.%d %H:%M:%S', ts)
            tags = json.dumps([{'tag': t['tag'], 'value': t['value']} for t in p.get('tags', [])])

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
                'lastReceived': last_received,
                'description': p['name'],
                'tags': tags
            }

            current_active[p['eventid']] = alert

            code = send_to_keep(alert)
            if code and 200 <= code < 300:
                sent += 1

        log.info(f"Sent {sent}/{len(problems)} active alerts to Keep")

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
    log.info(f"Starting Zabbix->Keep poller (interval={POLL_INTERVAL}s)")
    log.info(f"Zabbix: {ZABBIX_URL}")
    log.info(f"Keep: {KEEP_URL}")
    log.info(f"Filters: groupids={ALERT_GROUP_IDS}, min_severity={MIN_SEVERITY}, excluded_triggers={EXCLUDED_TRIGGER_IDS}")

    while True:
        try:
            poll_once()
        except Exception as e:
            log.error(f"Poll failed: {e}")
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main()
