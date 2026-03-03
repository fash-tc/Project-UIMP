#!/usr/bin/env python3
"""One-shot cleanup: resolve Keep alerts that are no longer active in Zabbix."""
import json
import ssl
import time
from urllib.request import Request, urlopen

ZABBIX_URL = "https://zabbix.prod-domains-shared.bra2.tucows.systems/api_jsonrpc.php"
KEEP_API = "http://keep-api:8080"
KEEP_API_KEY = "412ff98a-5ea6-450d-8531-4a4940cdc3b4"
KEEP_WEBHOOK = "http://keep-api:8080/alerts/event/zabbix"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def zabbix_call(method, params, auth=None):
    body = json.dumps({"jsonrpc":"2.0","method":method,"params":params,"auth":auth,"id":1}).encode()
    req = Request(ZABBIX_URL, data=body, headers={"Content-Type":"application/json"})
    resp = urlopen(req, context=ctx, timeout=30)
    return json.loads(resp.read()).get("result")

def keep_get(path):
    req = Request(f"{KEEP_API}{path}", headers={"X-API-KEY": KEEP_API_KEY, "Content-Type": "application/json"})
    resp = urlopen(req, timeout=10)
    return json.loads(resp.read())

def keep_send_resolved(alert_data):
    body = json.dumps(alert_data).encode()
    req = Request(KEEP_WEBHOOK, data=body, headers={"Content-Type": "application/json", "X-API-KEY": KEEP_API_KEY})
    resp = urlopen(req, timeout=10)
    return resp.status

# Get active Zabbix problems (same filters as poller)
auth = zabbix_call("user.login", {"user": "uip-poller", "password": "UipPoller2026!"})
problems = zabbix_call("problem.get", {
    "output": ["eventid", "objectid", "name"],
    "selectTags": "extend",
    "recent": True,
    "groupids": [30],
    "severities": [2, 3, 4, 5],
    "suppressed": False,
    "limit": 500
}, auth)
zabbix_call("user.logout", {}, auth)

active_event_ids = set(p["eventid"] for p in problems)
active_trigger_ids = set(p["objectid"] for p in problems)
print(f"Zabbix: {len(problems)} active problems, {len(active_trigger_ids)} unique triggers")

# Get all firing alerts from Keep
all_keep = []
for offset in range(0, 500, 50):
    data = keep_get(f"/alerts?limit=50&offset={offset}")
    items = data.get("items", data) if isinstance(data, dict) else data
    if not items:
        break
    all_keep.extend(items)

firing = [a for a in all_keep if a.get("status") == "firing"]
print(f"Keep: {len(all_keep)} total alerts, {len(firing)} firing")

# Find Keep alerts that are firing but not active in Zabbix
resolved_count = 0
for alert in firing:
    trigger_id = alert.get("triggerId", "")
    event_id = alert.get("id", "")
    name = alert.get("name", "?")
    host = alert.get("hostName", alert.get("hostname", ""))

    # Check if this trigger is still active in Zabbix
    if str(trigger_id) not in active_trigger_ids and str(event_id) not in active_event_ids:
        # Send resolved event to Keep
        resolved_alert = {
            "id": event_id,
            "triggerId": trigger_id,
            "name": name,
            "status": "ok",
            "severity": alert.get("severity", "0"),
            "hostName": host,
            "hostIp": "",
            "lastReceived": time.strftime('%Y.%m.%d %H:%M:%S', time.gmtime()),
            "description": name,
            "tags": "[]"
        }
        code = keep_send_resolved(resolved_alert)
        if code and 200 <= code < 300:
            resolved_count += 1
            print(f"  Resolved: {name[:55]} ({host})")

print(f"\nResolved {resolved_count} stale alerts in Keep")
