#!/usr/bin/env python3
import json, urllib.request, ssl, time, datetime
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def zc(method, params, token=None):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    if token:
        payload["auth"] = token
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        "https://zabbix.prod-domains-shared.bra2.tucows.systems/api_jsonrpc.php",
        data=body, headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req, context=ctx, timeout=15)
    return json.loads(resp.read())["result"]

token = zc("user.login", {"username": "uip-poller", "password": "UipPoller2026!"})

actions = zc("action.get", {
    "output": "extend",
    "selectOperations": "extend",
    "selectRecoveryOperations": "extend",
    "filter": {"eventsource": "0", "status": "0"}
}, token)

for a in actions:
    aid = a.get("actionid")
    print(f"{aid}: {a['name']} (esc_period: {a['esc_period']})")
    for op in a.get("operations", []):
        print(f"  Step {op['esc_step_from']}-{op['esc_step_to']} | type={op['operationtype']} | period={op['esc_period']}")
    for rop in a.get("recoveryOperations", []):
        print(f"  Recovery | type={rop['operationtype']}")

since = str(int(time.time()) - 7200)
alerts = zc("alert.get", {
    "output": ["alertid", "status", "error", "subject", "clock"],
    "time_from": since,
    "sortfield": "alertid",
    "sortorder": "DESC",
    "limit": 30
}, token)
print(f"\nRecent alerts: {len(alerts)}")
for al in alerts:
    t = datetime.datetime.fromtimestamp(int(al["clock"]))
    st = {"0": "pending", "1": "sent", "2": "failed"}.get(al["status"], al["status"])
    print(f"  [{t}] {st} | {al.get('subject', '')[:80]}")
