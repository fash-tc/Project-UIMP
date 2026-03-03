#!/usr/bin/env python3
"""Check Zabbix actions/filters for Grafana user."""
import json, ssl, urllib.request

ZABBIX_URL = "https://zabbix.prod-domains-shared.bra2.tucows.systems/api_jsonrpc.php"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def zc(method, params, auth=None):
    body = json.dumps({"jsonrpc":"2.0","method":method,"params":params,"auth":auth,"id":1}).encode()
    req = urllib.request.Request(ZABBIX_URL, data=body, headers={"Content-Type":"application/json"})
    resp = urllib.request.urlopen(req, context=ctx, timeout=30)
    return json.loads(resp.read()).get("result")

auth = zc("user.login", {"user": "uip-poller", "password": "UipPoller2026!"})

# List all users
print("=== ALL USERS ===")
users = zc("user.get", {"output": "extend"}, auth)
for u in (users or []):
    uname = u.get("alias", u.get("username", "?"))
    print(f"  {uname} | {u.get('name','')} {u.get('surname','')} | uid:{u.get('userid')}")

# Find actions with filters
print("\n=== ACTIONS (trigger-based) ===")
actions = zc("action.get", {
    "output": "extend",
    "selectOperations": "extend",
    "selectFilter": "extend",
    "eventsource": 0,
}, auth)

for a in (actions or []):
    name = a.get("name", "?")
    status = a.get("status", "?")
    filt = a.get("filter", {})
    conditions = filt.get("conditions", [])
    ops = a.get("operations", [])

    user_ids = []
    grp_ids = []
    for op in ops:
        for opmsg in op.get("opmessage_usr", []):
            user_ids.append(opmsg.get("userid"))
        for opgrp in op.get("opmessage_grp", []):
            grp_ids.append(opgrp.get("usrgrpid", ""))

    print(f"\nAction: {name} (status: {'enabled' if status == '0' else 'disabled'})")
    print(f"  Sends to users: {user_ids}, groups: {grp_ids}")
    if conditions:
        print(f"  Filter evaltype: {filt.get('evaltype','')}")
        for c in conditions:
            ctype = c.get("conditiontype")
            op = c.get("operator")
            val = c.get("value")
            # Decode condition types
            type_map = {
                "0": "host_group", "1": "host", "2": "trigger",
                "3": "trigger_name", "4": "trigger_severity",
                "5": "time_period", "6": "host_ip", "13": "host_template",
                "16": "maintenance", "24": "host_name", "25": "event_type",
                "26": "host_metadata",
            }
            op_map = {
                "0": "=", "1": "!=", "2": "like", "3": "not_like",
                "4": ">=", "5": "<=", "6": "not_in", "7": "in",
                "8": "matches", "9": "not_matches",
            }
            tname = type_map.get(str(ctype), f"type_{ctype}")
            oname = op_map.get(str(op), f"op_{op}")
            print(f"    {tname} {oname} {val}")

# Also get host groups for reference
print("\n=== HOST GROUPS ===")
groups = zc("hostgroup.get", {"output": ["groupid", "name"]}, auth)
for g in (groups or []):
    print(f"  {g['groupid']}: {g['name']}")
