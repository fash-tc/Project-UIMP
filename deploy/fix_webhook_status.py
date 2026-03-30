#!/usr/bin/env python3
"""Fix webhook status mapping: problem->firing, ok->resolved."""
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
        data=body,
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req, context=ctx, timeout=15)
    data = json.loads(resp.read())
    if "error" in data:
        print("ERROR:", data["error"])
        return None
    return data["result"]

token = zc("user.login", {"username": "uip-poller", "password": "UipPoller2026!"})

# Get current script
mt = zc("mediatype.get", {"output": "extend", "mediatypeids": ["47"]}, token)
old_script = mt[0]["script"]

# Replace status values
new_script = old_script.replace("var status = 'problem'", "var status = 'firing'")
new_script = new_script.replace("status = 'ok'", "status = 'resolved'")

print("problem->firing:", "var status = 'firing'" in new_script)
print("ok->resolved:", "status = 'resolved'" in new_script)
print("Script changed:", old_script != new_script)

if old_script != new_script:
    result = zc("mediatype.update", {"mediatypeid": "47", "script": new_script}, token)
    print("Update result:", result)
else:
    print("No changes needed or pattern not found")
    # Debug: show the actual status lines
    for line in old_script.split("\n"):
        if "status" in line.lower() and ("problem" in line or "ok" in line):
            print("  Found line:", repr(line))
