#!/usr/bin/env python3
"""Debug: find Keep alerts that are firing but resolved in Zabbix."""
import json, ssl, time
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

# Get ALL active Zabbix problems (no group/severity filter)
auth = zabbix_call("user.login", {"user": "uip-poller", "password": "UipPoller2026!"})
problems = zabbix_call("problem.get", {
    "output": ["eventid", "objectid", "name"],
    "recent": True,
    "limit": 1000
}, auth)
zabbix_call("user.logout", {}, auth)

all_active_triggers = set(p["objectid"] for p in problems)
print(f"Zabbix: {len(problems)} total active problems, {len(all_active_triggers)} unique triggers")

# Get all firing alerts from Keep
firing = []
for offset in range(0, 500, 50):
    data = keep_get(f"/alerts?limit=50&offset={offset}")
    items = data.get("items", data) if isinstance(data, dict) else data
    if not items:
        break
    for a in items:
        if a.get("status") == "firing":
            firing.append(a)

print(f"Keep: {len(firing)} firing alerts")

# Find and resolve stale alerts
resolved = 0
for a in firing:
    tid = str(a.get("triggerId", ""))
    name = a.get("name", "?")
    host = a.get("hostName", a.get("hostname", ""))

    if tid and tid not in all_active_triggers:
        print(f"  STALE: {name[:55]} | {host} | trigger {tid}")
        # Send resolved
        code = keep_send_resolved({
            "id": a.get("id", ""),
            "triggerId": tid,
            "name": name,
            "status": "ok",
            "severity": a.get("severity", "0"),
            "hostName": host,
            "hostIp": "",
            "lastReceived": time.strftime('%Y.%m.%d %H:%M:%S', time.gmtime()),
            "description": name,
            "tags": "[]"
        })
        if code and 200 <= code < 300:
            resolved += 1

print(f"\nResolved {resolved} stale alerts in Keep")
