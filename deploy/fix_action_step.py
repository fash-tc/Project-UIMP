#!/usr/bin/env python3
"""Fix UIP Keep Webhook action to fire at step 1 instead of step 2."""
import json, urllib.request, ssl
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
    data = json.loads(resp.read())
    if "error" in data:
        print("ERROR:", data["error"])
        return None
    return data["result"]

token = zc("user.login", {"username": "uip-poller", "password": "UipPoller2026!"})

# Get action 47 full details
actions = zc("action.get", {
    "output": "extend",
    "actionids": ["47"],
    "selectOperations": "extend",
}, token)

a = actions[0]
print(f"Action: {a['name']}")
print(f"Current esc_period: {a['esc_period']}")
for op in a["operations"]:
    print(f"  Operation {op['operationid']}: step {op['esc_step_from']}-{op['esc_step_to']}")

# Update: change step from 2-2 to 1-1 and reduce esc_period to 1m
ops = a["operations"]
for op in ops:
    op["esc_step_from"] = "1"
    op["esc_step_to"] = "1"
    # Remove read-only fields that Zabbix rejects on update
    for key in ["actionid", "operationid"]:
        op.pop(key, None)
    # Clean opmessage sub-object too
    if "opmessage" in op:
        for mkey in ["subject", "message"]:
            op["opmessage"].pop(mkey, None)

result = zc("action.update", {
    "actionid": "47",
    "esc_period": "1m",
    "operations": ops,
}, token)
print(f"\nUpdate result: {result}")
print("Action now fires at step 1 (immediate) with 1m escalation period")
