#!/usr/bin/env python3
"""Zabbix Webhook Setup for Keep Integration — Multi-Instance.

Automates creation of webhook media type, user, and action on multiple
Zabbix instances to forward alerts to the UIP Keep platform.

Usage:
  python3 zabbix_webhook_setup.py discover <instance>   # List host groups, actions, users
  python3 zabbix_webhook_setup.py setup <instance>       # Create media type + user + action
  python3 zabbix_webhook_setup.py test <instance>        # Test connectivity
  python3 zabbix_webhook_setup.py status <instance>      # Show current config
  python3 zabbix_webhook_setup.py teardown <instance>    # Remove config
  python3 zabbix_webhook_setup.py dry-run <instance>     # Show what setup would do (no changes)

Instances: domains-shared, ascio, hostedemail, enom, iaas
"""

import json
import os
import ssl
import sys
import urllib.request
from urllib.error import URLError, HTTPError

# ── Instance Configuration ────────────────────────────────────────────────

KEEP_API_KEY = os.environ.get("KEEP_API_KEY", "ca5ee58d-1a50-4817-aac5-9a538e40590d")
KEEP_WEBHOOK_URL = os.environ.get("KEEP_WEBHOOK_URL", "http://10.177.154.196/alerts/event/zabbix")

INSTANCES = {
    "domains-shared": {
        "zabbix_url": "https://zabbix.prod-domains-shared.bra2.tucows.systems/api_jsonrpc.php",
        "display_name": "Domains Shared Zabbix",
        "zabbix_user": "uip-poller",
        "zabbix_pass": "UipPoller2026!",
        "alert_group_ids": ["30"],
        "min_severity": "2",
        "excluded_trigger_ids": ["3034311"],
    },
    "ascio": {
        "zabbix_url": "https://zabbix.ascio.com/api_jsonrpc.php",
        "display_name": "Ascio Zabbix",
        "zabbix_user": None,
        "zabbix_pass": None,
        "alert_group_ids": None,
        "min_severity": "2",
        "excluded_trigger_ids": [],
    },
    "hostedemail": {
        "zabbix_url": "https://zabbix.a.tucows.com/api_jsonrpc.php",
        "display_name": "HostedEmail Zabbix",
        "zabbix_user": None,
        "zabbix_pass": None,
        "alert_group_ids": None,
        "min_severity": "2",
        "excluded_trigger_ids": [],
    },
    "enom": {
        "zabbix_url": "https://zabbix.enom.net/api_jsonrpc.php",
        "display_name": "Enom Zabbix",
        "zabbix_user": "fash",
        "zabbix_pass": "Nbpt6wev8rahsrafham@@",
        "alert_group_ids": [],  # No host group filter — matches all groups (like Grafana action)
        "min_severity": "2",
        "excluded_trigger_ids": [],
        "excluded_tag_names": ["dev"],  # Exclude events tagged with "dev"
    },
    "iaas": {
        "zabbix_url": "https://zabbix.tucows.cloud/api_jsonrpc.php",
        "display_name": "IAAS Zabbix",
        "zabbix_user": None,
        "zabbix_pass": None,
        "alert_group_ids": None,
        "min_severity": "2",
        "excluded_trigger_ids": [],
    },
}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# ── Zabbix API helper ────────────────────────────────────────────────────

_req_id = 0
_zabbix_url = None  # Set per-instance
_zabbix_version = None  # Detected at login


def _is_legacy_zabbix():
    """Return True if Zabbix < 5.4 (uses 'alias'/'user' instead of 'username')."""
    if not _zabbix_version:
        return False
    parts = _zabbix_version.split(".")
    try:
        return int(parts[0]) < 5 or (int(parts[0]) == 5 and int(parts[1]) < 4)
    except (ValueError, IndexError):
        return False


def _user_field():
    """Return the correct user identifier field for this Zabbix version."""
    return "alias" if _is_legacy_zabbix() else "username"


def zapi(method, params, auth=None):
    global _req_id
    _req_id += 1
    body = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "auth": auth, "id": _req_id}
    ).encode()
    req = urllib.request.Request(
        _zabbix_url, data=body, headers={"Content-Type": "application/json"}
    )
    resp = urllib.request.urlopen(req, context=ctx, timeout=30)
    data = json.loads(resp.read())
    if "error" in data:
        raise RuntimeError(f"Zabbix API error: {data['error']}")
    return data.get("result")


def load_instance(name):
    """Load instance config and set up globals. Returns config dict."""
    global _zabbix_url
    if name not in INSTANCES:
        print(f"Unknown instance '{name}'. Available: {', '.join(INSTANCES.keys())}")
        sys.exit(1)
    cfg = INSTANCES[name].copy()
    cfg["instance_key"] = name

    # Allow env var overrides: ZABBIX_USER_ASCIO / ZABBIX_PASS_ASCIO
    env_suffix = name.upper().replace("-", "_")
    cfg["zabbix_user"] = os.environ.get(f"ZABBIX_USER_{env_suffix}", cfg["zabbix_user"])
    cfg["zabbix_pass"] = os.environ.get(f"ZABBIX_PASS_{env_suffix}", cfg["zabbix_pass"])
    # Also check generic env vars as fallback
    if not cfg["zabbix_user"]:
        cfg["zabbix_user"] = os.environ.get("ZABBIX_USER")
    if not cfg["zabbix_pass"]:
        cfg["zabbix_pass"] = os.environ.get("ZABBIX_PASS")

    if not cfg["zabbix_user"] or not cfg["zabbix_pass"]:
        print(f"No credentials for '{name}'. Set ZABBIX_USER_{env_suffix} and ZABBIX_PASS_{env_suffix}")
        sys.exit(1)

    _zabbix_url = cfg["zabbix_url"]

    # Instance-specific names
    cfg["media_type_name"] = f"Keep UIP Webhook ({name})"
    cfg["action_name"] = f"UIP Keep Webhook ({name})"
    cfg["webhook_username"] = "uip-webhook"

    return cfg


def zlogin(cfg):
    global _zabbix_version
    # Detect version first (no auth needed)
    _zabbix_version = zapi("apiinfo.version", {})
    print(f"  Zabbix version: {_zabbix_version} ({'legacy alias mode' if _is_legacy_zabbix() else 'modern username mode'})")

    # Zabbix < 5.4 uses 'user', >= 5.4 uses 'username' for login
    login_field = "user" if _is_legacy_zabbix() else "username"
    auth = zapi("user.login", {login_field: cfg["zabbix_user"], "password": cfg["zabbix_pass"]})
    if not auth:
        raise RuntimeError("Zabbix login failed")
    return auth


def zlogout(auth):
    try:
        zapi("user.logout", [], auth)
    except Exception:
        pass


# ── Webhook JavaScript ────────────────────────────────────────────────────

WEBHOOK_SCRIPT = r"""
var params = JSON.parse(value);

var status = 'problem';
if (params.eventValue === '0') {
    status = 'ok';
} else if (params.eventUpdateStatus === '1' || params.eventAckStatus === 'Yes') {
    status = 'acknowledged';
}

// Generate UTC timestamp (Zabbix macros use server-local time which may not be UTC)
var now = new Date();
function pad(n) { return n < 10 ? '0' + n : '' + n; }
var lastReceived = now.getUTCFullYear() + '.' + pad(now.getUTCMonth() + 1) + '.' + pad(now.getUTCDate())
    + ' ' + pad(now.getUTCHours()) + ':' + pad(now.getUTCMinutes()) + ':' + pad(now.getUTCSeconds());

var metricParts = [];
var items = [
    {name: params.itemName1, value: params.itemValue1},
    {name: params.itemName2, value: params.itemValue2},
    {name: params.itemName3, value: params.itemValue3}
];
for (var i = 0; i < items.length; i++) {
    if (!items[i].name || items[i].name.indexOf('{ITEM.') === 0 || items[i].name === '*UNKNOWN*') continue;
    if (!items[i].value || items[i].value.indexOf('{ITEM.') === 0 || items[i].value === '*UNKNOWN*') continue;
    metricParts.push(items[i].name + ': ' + items[i].value);
}
var metrics = metricParts.join(' | ');

// Use UTC timestamp for "since" (Zabbix event macros use server-local time)
var description = metrics
    ? params.triggerName + ' [' + metrics + '] (since ' + lastReceived + ')'
    : params.triggerName + ' (since ' + lastReceived + ')';

var tags;
try { tags = JSON.stringify(JSON.parse(params.eventTagsJson)); }
catch(e) { tags = '[]'; }

var req = new HttpRequest();
req.addHeader('Content-Type: application/json');
req.addHeader('X-API-KEY: ' + params.keepApiKey);

var payload = JSON.stringify({
    id: params.eventId,
    triggerId: params.triggerId,
    name: params.triggerName,
    status: status,
    severity: params.triggerSeverity,
    url: params.triggerUrl,
    hostName: params.hostName,
    hostIp: params.hostIp || '',
    lastReceived: lastReceived,
    description: description,
    tags: tags,
    zabbixInstance: params.zabbixInstance
});

var resp = req.post(params.keepUrl, payload);
if (req.getStatus() < 200 || req.getStatus() >= 300) {
    throw 'Keep HTTP ' + req.getStatus() + ': ' + resp;
}
return 'OK: event ' + params.eventId + ' status=' + status + ' HTTP ' + req.getStatus();
""".strip()


def build_webhook_params(instance_key):
    """Build media type parameters with instance-specific zabbixInstance value."""
    return [
        {"name": "keepUrl", "value": KEEP_WEBHOOK_URL},
        {"name": "keepApiKey", "value": KEEP_API_KEY},
        {"name": "zabbixInstance", "value": instance_key},
        {"name": "eventId", "value": "{EVENT.ID}"},
        {"name": "triggerId", "value": "{TRIGGER.ID}"},
        {"name": "triggerName", "value": "{TRIGGER.NAME}"},
        {"name": "triggerSeverity", "value": "{TRIGGER.SEVERITY}"},
        {"name": "triggerUrl", "value": "{TRIGGER.URL}"},
        {"name": "triggerDescription", "value": "{TRIGGER.DESCRIPTION}"},
        {"name": "hostName", "value": "{HOST.NAME}"},
        {"name": "hostIp", "value": "{HOST.IP}"},
        {"name": "eventValue", "value": "{EVENT.VALUE}"},
        {"name": "eventUpdateStatus", "value": "{EVENT.UPDATE.STATUS}"},
        {"name": "eventAckStatus", "value": "{EVENT.ACK.STATUS}"},
        {"name": "eventDate", "value": "{EVENT.DATE}"},
        {"name": "eventTime", "value": "{EVENT.TIME}"},
        {"name": "eventRecoveryDate", "value": "{EVENT.RECOVERY.DATE}"},
        {"name": "eventRecoveryTime", "value": "{EVENT.RECOVERY.TIME}"},
        {"name": "eventTagsJson", "value": "{EVENT.TAGSJSON}"},
        {"name": "itemName1", "value": "{ITEM.NAME1}"},
        {"name": "itemValue1", "value": "{ITEM.VALUE1}"},
        {"name": "itemName2", "value": "{ITEM.NAME2}"},
        {"name": "itemValue2", "value": "{ITEM.VALUE2}"},
        {"name": "itemName3", "value": "{ITEM.NAME3}"},
        {"name": "itemValue3", "value": "{ITEM.VALUE3}"},
    ]


# ── Discover command ──────────────────────────────────────────────────────


def cmd_discover(cfg):
    print(f"=== Discover: {cfg['display_name']} ===")
    print(f"URL: {cfg['zabbix_url']}\n")

    auth = zlogin(cfg)
    try:
        # Host groups with host counts
        print("=== Host Groups ===")
        groups = zapi("hostgroup.get", {
            "output": ["groupid", "name"],
            "selectHosts": "count",
            "sortfield": "name",
        }, auth)
        for g in (groups or []):
            hosts = g.get("hosts", "?")
            print(f"  [{g['groupid']:>4}] {g['name']} ({hosts} hosts)")

        # User groups
        print("\n=== User Groups ===")
        ugroups = zapi("usergroup.get", {
            "output": ["usrgrpid", "name"],
            "sortfield": "name",
        }, auth)
        for ug in (ugroups or []):
            print(f"  [{ug['usrgrpid']:>4}] {ug['name']}")

        # Existing trigger-based actions
        print("\n=== Trigger Actions ===")
        actions = zapi("action.get", {
            "output": ["actionid", "name", "status"],
            "selectFilter": "extend",
            "selectOperations": ["operationtype", "opmessage"],
            "eventsource": "0",
        }, auth)

        type_map = {"0": "host_group", "1": "host", "2": "trigger", "3": "trigger_name",
                     "4": "severity", "16": "maintenance", "26": "event_tag"}
        op_map = {"0": "=", "1": "!=", "2": "like", "5": ">=", "11": "not"}

        for a in (actions or []):
            status = "enabled" if a.get("status") == "0" else "disabled"
            print(f"\n  Action: {a['name']} (id: {a['actionid']}, {status})")
            filt = a.get("filter", {})
            for c in filt.get("conditions", []):
                ct = type_map.get(str(c.get("conditiontype", "")), f"type_{c.get('conditiontype')}")
                op = op_map.get(str(c.get("operator", "")), f"op_{c.get('operator')}")
                val = c.get("value", "")
                print(f"    {ct} {op} {val}")

        # Active problem count by severity
        print("\n=== Active Problems by Severity ===")
        sev_names = {0: "Not classified", 1: "Information", 2: "Warning",
                     3: "Average", 4: "High", 5: "Disaster"}
        for sev in range(0, 6):
            problems = zapi("problem.get", {
                "output": ["eventid"],
                "severities": [sev],
                "recent": True,
                "limit": 1,
                "countOutput": True,
            }, auth)
            count = problems if isinstance(problems, (int, str)) else 0
            print(f"  {sev_names[sev]:>16}: {count}")

    finally:
        zlogout(auth)


# ── Setup helpers ─────────────────────────────────────────────────────────


def find_media_type(auth, name):
    result = zapi("mediatype.get", {"output": "extend", "filter": {"name": name}}, auth)
    return result[0] if result else None


def create_or_update_media_type(auth, cfg):
    name = cfg["media_type_name"]
    existing = find_media_type(auth, name)
    params = build_webhook_params(cfg["instance_key"])

    media_def = {
        "name": name,
        "type": "4",
        "description": f"Sends alerts from {cfg['display_name']} to Keep UIP platform",
        "parameters": params,
        "script": WEBHOOK_SCRIPT,
        "process_tags": "0",
        "maxsessions": "5",
        "maxattempts": "3",
        "attempt_interval": "10s",
        "status": "0",
    }

    if existing:
        media_def["mediatypeid"] = existing["mediatypeid"]
        zapi("mediatype.update", media_def, auth)
        print(f"  Updated media type '{name}' (id: {existing['mediatypeid']})")
        return existing["mediatypeid"]
    else:
        result = zapi("mediatype.create", media_def, auth)
        mtid = result["mediatypeids"][0]
        print(f"  Created media type '{name}' (id: {mtid})")
        return mtid


def find_user(auth, username):
    result = zapi(
        "user.get",
        {"output": "extend", "selectMedias": "extend", "selectUsrgrps": ["usrgrpid"],
         "filter": {_user_field(): username}},
        auth,
    )
    return result[0] if result else None


def get_user_groups_for_instance(auth, cfg):
    """Get suitable user groups — try the poller user first, then fall back."""
    poller = find_user(auth, cfg["zabbix_user"])
    if poller:
        usrgrps = poller.get("usrgrps", [])
        if usrgrps:
            print(f"  Found {cfg['zabbix_user']} user groups: {[g['usrgrpid'] for g in usrgrps]}")
            return usrgrps

    # Fall back to any available group
    groups = zapi("usergroup.get", {"output": ["usrgrpid", "name"], "limit": 5}, auth)
    if groups:
        print(f"  Using user group: {groups[0]['name']} (id: {groups[0]['usrgrpid']})")
        return [{"usrgrpid": groups[0]["usrgrpid"]}]
    raise RuntimeError("No user groups found in Zabbix")


def create_or_update_user(auth, cfg, mediatypeid):
    username = cfg["webhook_username"]
    existing = find_user(auth, username)
    usrgrps = get_user_groups_for_instance(auth, cfg)

    media_entry = {
        "mediatypeid": mediatypeid,
        "sendto": "keep",
        "active": "0",
        "severity": "60",
        "period": "1-7,00:00-24:00",
    }

    if existing:
        # Preserve ALL existing medias except our Keep webhook entry (sendto="keep")
        existing_medias = existing.get("medias", [])
        other_medias = []
        for m in existing_medias:
            if m.get("sendto") == "keep":
                continue
            clean = {k: v for k, v in m.items() if k != "mediaid" and k != "userid"}
            other_medias.append(clean)
        all_medias = other_medias + [media_entry]

        zapi("user.update", {
            "userid": existing["userid"],
            "medias": all_medias,
            "usrgrps": usrgrps,
        }, auth)
        print(f"  Updated user '{username}' (id: {existing['userid']}, {len(all_medias)} media entries)")
        return existing["userid"]
    else:
        user_def = {
            _user_field(): username,
            "name": "UIP",
            "surname": "Alert Relay",
            "passwd": "Xk9#mPq4vL2nR7!jF5",
            "usrgrps": usrgrps,
        }
        # roleid only exists in Zabbix >= 5.2; legacy uses type
        if not _is_legacy_zabbix():
            user_def["roleid"] = "1"
            user_def["medias"] = [media_entry]  # Modern Zabbix supports medias in create
        else:
            user_def["type"] = "3"  # Super admin on legacy Zabbix
            # Zabbix < 5.2 doesn't support medias in user.create — add separately
        result = zapi("user.create", user_def, auth)
        uid = result["userids"][0]
        print(f"  Created user '{username}' (id: {uid})")

        # On legacy Zabbix, add media via user.update (supported since 3.0)
        if _is_legacy_zabbix():
            zapi("user.update", {"userid": uid, "user_medias": [media_entry]}, auth)
            print(f"  Added media entry to user (legacy mode)")

        return uid


def find_action(auth, name):
    result = zapi("action.get", {
        "output": "extend",
        "selectOperations": "extend",
        "selectRecoveryOperations": "extend",
        "selectUpdateOperations": "extend",
        "selectFilter": "extend",
        "filter": {"name": name},
    }, auth)
    return result[0] if result else None


def create_or_update_action(auth, cfg, mediatypeid, userid):
    name = cfg["action_name"]
    existing = find_action(auth, name)

    msg_op = {
        "operationtype": "0",
        "opmessage": {
            "mediatypeid": mediatypeid,
            "default_msg": "1",
        },
        "opmessage_usr": [{"userid": userid}],
        "opmessage_grp": [],
    }

    # Build filter conditions
    conditions = []

    # Host group filter(s)
    group_ids = cfg.get("alert_group_ids") or []
    for gid in group_ids:
        conditions.append({
            "conditiontype": "0",
            "operator": "0",
            "value": str(gid),
        })

    # Severity filter
    conditions.append({
        "conditiontype": "4",
        "operator": "5",
        "value": cfg["min_severity"],
    })

    # Not in maintenance (value="" required by Zabbix 5.0)
    conditions.append({
        "conditiontype": "16",
        "operator": "11",
        "value": "",
    })

    # Excluded triggers
    for tid in cfg.get("excluded_trigger_ids", []):
        conditions.append({
            "conditiontype": "2",
            "operator": "1",
            "value": str(tid),
        })

    # Excluded event tag names (conditiontype 25 = event tag name, operator 3 = does not contain)
    for tag_name in cfg.get("excluded_tag_names", []):
        conditions.append({
            "conditiontype": "25",
            "operator": "3",
            "value": tag_name,
        })

    # Use AND-OR based on whether we have host groups
    # evaltype 0 = AND/OR, evaltype 1 = AND
    action_filter = {"evaltype": "1" if conditions else "0", "conditions": conditions}

    action_def = {
        "name": name,
        "eventsource": "0",
        "status": "0",
        "esc_period": "60",
        "filter": action_filter,
        "operations": [msg_op],
        "recovery_operations": [dict(msg_op)],
        "update_operations": [dict(msg_op)],
    }

    if existing:
        action_def["actionid"] = existing["actionid"]
        zapi("action.update", action_def, auth)
        print(f"  Updated action '{name}' (id: {existing['actionid']})")
        return existing["actionid"]
    else:
        result = zapi("action.create", action_def, auth)
        aid = result["actionids"][0]
        print(f"  Created action '{name}' (id: {aid})")
        return aid


# ── Commands ──────────────────────────────────────────────────────────────


def cmd_setup(cfg):
    print(f"=== Setup: {cfg['display_name']} ===")
    print(f"Zabbix URL:    {cfg['zabbix_url']}")
    print(f"Keep Webhook:  {KEEP_WEBHOOK_URL}")
    print(f"Instance key:  {cfg['instance_key']}")
    print()

    if not cfg.get("alert_group_ids") and not cfg.get("excluded_tag_names"):
        print("ERROR: No alert_group_ids or excluded_tag_names configured for this instance.")
        print(f"Run: python3 {sys.argv[0]} discover {cfg['instance_key']}")
        print("Then update the INSTANCES config with the correct filters.")
        sys.exit(1)

    auth = zlogin(cfg)
    try:
        print("Step 1: Create/update webhook media type")
        mtid = create_or_update_media_type(auth, cfg)
        print()

        print("Step 2: Create/update webhook user")
        uid = create_or_update_user(auth, cfg, mtid)
        print()

        print("Step 3: Create/update action")
        aid = create_or_update_action(auth, cfg, mtid, uid)
        print()

        print("=" * 50)
        print(f"Setup complete for {cfg['display_name']}!")
        print(f"  Media type ID: {mtid}")
        print(f"  User ID:       {uid}")
        print(f"  Action ID:     {aid}")
        print(f"  Instance key:  {cfg['instance_key']}")
        print()
        print("Next steps:")
        print(f"  1. Run: python3 {sys.argv[0]} test {cfg['instance_key']}")
        print(f"  2. Test in Zabbix UI -> Administration -> Media types -> Test")
        print(f"  3. Monitor Zabbix Reports -> Action log")
    finally:
        zlogout(auth)


def cmd_test(cfg):
    print(f"=== Connectivity Test: {cfg['display_name']} ===\n")

    # Test 1: Can we reach Keep?
    print(f"Test 1: HTTP POST to {KEEP_WEBHOOK_URL}")
    test_payload = json.dumps({
        "id": f"test_{cfg['instance_key']}",
        "triggerId": "0",
        "name": f"Webhook Test ({cfg['display_name']})",
        "status": "ok",
        "severity": "0",
        "url": "",
        "hostName": "test",
        "hostIp": "",
        "lastReceived": "2026.01.01 00:00:00",
        "description": "Connectivity test - safe to ignore",
        "tags": "[]",
        "zabbixInstance": cfg["instance_key"],
    }).encode()

    req = urllib.request.Request(
        KEEP_WEBHOOK_URL, data=test_payload,
        headers={"Content-Type": "application/json", "X-API-KEY": KEEP_API_KEY},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        print(f"  SUCCESS: HTTP {resp.status}")
    except HTTPError as e:
        print(f"  HTTP {e.code}: {e.reason}")
        if e.code < 500:
            print(f"  Connectivity OK")
    except URLError as e:
        print(f"  FAILED: {e.reason}")

    # Test 2: Can we reach Zabbix?
    print(f"\nTest 2: Zabbix API at {cfg['zabbix_url']}")
    try:
        auth = zlogin(cfg)
        print(f"  SUCCESS: Authenticated as {cfg['zabbix_user']}")
        version = zapi("apiinfo.version", {})
        print(f"  Zabbix version: {version}")
        zlogout(auth)
    except Exception as e:
        print(f"  FAILED: {e}")

    print(f"\nNote: Test from Zabbix UI -> Media types -> '{cfg['media_type_name']}' -> Test")
    print("to verify the Zabbix server can reach Keep.")


def cmd_status(cfg):
    print(f"=== Status: {cfg['display_name']} ===\n")

    auth = zlogin(cfg)
    try:
        mt = find_media_type(auth, cfg["media_type_name"])
        if mt:
            print(f"Media Type: '{mt['name']}' (id: {mt['mediatypeid']})")
            print(f"  Status: {'enabled' if mt.get('status') == '0' else 'DISABLED'}")
            print(f"  Max sessions: {mt.get('maxsessions', '?')}")
            print(f"  Max attempts: {mt.get('maxattempts', '?')}")
        else:
            print(f"Media Type: NOT FOUND ('{cfg['media_type_name']}')")

        print()
        user = find_user(auth, cfg["webhook_username"])
        if user:
            uname = user.get("username", user.get("alias", "?"))
            print(f"User: '{uname}' (id: {user['userid']})")
            for m in user.get("medias", []):
                print(f"  Media: type={m.get('mediatypeid')}, sendto={m.get('sendto')}, "
                      f"active={'yes' if m.get('active') == '0' else 'no'}")
        else:
            print(f"User: NOT FOUND ('{cfg['webhook_username']}')")

        print()
        action = find_action(auth, cfg["action_name"])
        if action:
            print(f"Action: '{action['name']}' (id: {action['actionid']})")
            print(f"  Status: {'enabled' if action.get('status') == '0' else 'DISABLED'}")
            filt = action.get("filter", {})
            conds = filt.get("conditions", [])
            print(f"  Filter conditions: {len(conds)}")
            type_map = {"0": "host_group", "2": "trigger", "4": "severity", "16": "maintenance"}
            op_map = {"0": "=", "1": "!=", "5": ">=", "11": "not"}
            for c in conds:
                ct = type_map.get(str(c.get("conditiontype")), f"type_{c.get('conditiontype')}")
                op = op_map.get(str(c.get("operator")), f"op_{c.get('operator')}")
                print(f"    {ct} {op} {c.get('value')}")
            ops = action.get("operations", [])
            rec_ops = action.get("recovery_operations", [])
            upd_ops = action.get("update_operations", [])
            print(f"  Operations: {len(ops)} problem, {len(rec_ops)} recovery, {len(upd_ops)} update")
        else:
            print(f"Action: NOT FOUND ('{cfg['action_name']}')")
    finally:
        zlogout(auth)


def cmd_teardown(cfg):
    print(f"=== Teardown: {cfg['display_name']} ===\n")

    auth = zlogin(cfg)
    try:
        action = find_action(auth, cfg["action_name"])
        if action:
            zapi("action.delete", [action["actionid"]], auth)
            print(f"  Deleted action (id: {action['actionid']})")
        else:
            print(f"  Action not found, skipping")

        # Don't delete user — shared across instances on the same Zabbix
        # Just remove the media entry for this media type
        mt = find_media_type(auth, cfg["media_type_name"])
        if mt:
            user = find_user(auth, cfg["webhook_username"])
            if user:
                remaining = [m for m in user.get("medias", [])
                             if m.get("mediatypeid") != mt["mediatypeid"]]
                zapi("user.update", {"userid": user["userid"], "medias": remaining}, auth)
                print(f"  Removed media entry from user")

            zapi("mediatype.delete", [mt["mediatypeid"]], auth)
            print(f"  Deleted media type (id: {mt['mediatypeid']})")
        else:
            print(f"  Media type not found, skipping")

        print("\nTeardown complete.")
    finally:
        zlogout(auth)


def cmd_dryrun(cfg):
    """Show exactly what setup would create — no changes made."""
    print(f"=== DRY RUN: {cfg['display_name']} ===")
    print(f"Zabbix URL:    {cfg['zabbix_url']}")
    print(f"Keep Webhook:  {KEEP_WEBHOOK_URL}")
    print(f"Instance key:  {cfg['instance_key']}")
    print()

    auth = zlogin(cfg)
    try:
        # --- Media Type ---
        mt_name = cfg["media_type_name"]
        existing_mt = find_media_type(auth, mt_name)
        if existing_mt:
            print(f"[MEDIA TYPE] WOULD UPDATE existing '{mt_name}' (id: {existing_mt['mediatypeid']})")
        else:
            print(f"[MEDIA TYPE] WOULD CREATE '{mt_name}'")
        print(f"  Type: webhook (4)")
        print(f"  Script: {len(WEBHOOK_SCRIPT)} chars, POSTs to {KEEP_WEBHOOK_URL}")
        print(f"  Parameters: {len(build_webhook_params(cfg['instance_key']))} fields")
        print(f"  zabbixInstance: {cfg['instance_key']}")
        print()

        # --- Check for name collisions ---
        print("[COLLISION CHECK] Searching for existing resources with similar names...")
        all_mt = zapi("mediatype.get", {"output": ["name", "mediatypeid"]}, auth)
        for m in all_mt:
            if "keep" in m["name"].lower() or "uip" in m["name"].lower():
                print(f"  Found media type: '{m['name']}' (id: {m['mediatypeid']})")
        all_users = zapi("user.get", {"output": ["userid", _user_field()], "filter": {_user_field(): cfg["webhook_username"]}}, auth)
        if all_users:
            for u in all_users:
                uname = u.get(_user_field(), u.get("alias", u.get("username", "?")))
                print(f"  Found existing user: '{uname}' (id: {u['userid']})")
        else:
            print(f"  No existing user '{cfg['webhook_username']}' found")
        all_actions = zapi("action.get", {"output": ["name", "actionid"], "eventsource": "0"}, auth)
        for a in all_actions:
            if "keep" in a["name"].lower() or "uip" in a["name"].lower():
                print(f"  Found action: '{a['name']}' (id: {a['actionid']})")
        print()

        # --- User ---
        username = cfg["webhook_username"]
        existing_user = find_user(auth, username)
        if existing_user:
            uid = existing_user["userid"]
            existing_medias = existing_user.get("medias", [])
            print(f"[USER] WOULD UPDATE existing '{username}' (id: {uid})")
            print(f"  Current media entries: {len(existing_medias)}")
            for m in existing_medias:
                mt_info = zapi("mediatype.get", {"output": ["name"], "mediatypeids": [m["mediatypeid"]]}, auth)
                mt_label = mt_info[0]["name"] if mt_info else f"id={m['mediatypeid']}"
                print(f"    - {mt_label} → sendto={m.get('sendto')}")
            print(f"  WOULD ADD media entry: sendto='keep', severity=60 (Warning+), 24/7")
            print(f"  ⚠ Would preserve {len(existing_medias)} existing media entries (filtering out sendto='keep' dupes)")
        else:
            print(f"[USER] WOULD CREATE '{username}'")
            print(f"  Name: UIP Alert Relay")
            print(f"  Type: {'type=3 (Super admin)' if _is_legacy_zabbix() else 'roleid=1'}")
            usrgrps = get_user_groups_for_instance(auth, cfg)
            grp_names = []
            for g in usrgrps:
                gi = zapi("usergroup.get", {"output": ["name"], "usrgrpids": [g["usrgrpid"]]}, auth)
                grp_names.append(gi[0]["name"] if gi else g["usrgrpid"])
            print(f"  Groups: {', '.join(grp_names)}")
            print(f"  Media: sendto='keep', severity=60 (Warning+), 24/7")
        print()

        # --- Action ---
        action_name = cfg["action_name"]
        existing_action = find_action(auth, action_name)
        if existing_action:
            print(f"[ACTION] WOULD UPDATE existing '{action_name}' (id: {existing_action['actionid']})")
        else:
            print(f"[ACTION] WOULD CREATE '{action_name}'")

        print(f"  Event source: triggers (0)")
        print(f"  Filter conditions (AND):")

        group_ids = cfg.get("alert_group_ids") or []
        if group_ids:
            for gid in group_ids:
                gi = zapi("hostgroup.get", {"output": ["name"], "groupids": [gid]}, auth)
                gname = gi[0]["name"] if gi else f"id={gid}"
                print(f"    - Host group = {gname} (id: {gid})")
        else:
            print(f"    - (no host group filter — all groups)")

        print(f"    - Severity >= {cfg['min_severity']} ({'Warning' if cfg['min_severity'] == '2' else cfg['min_severity']})")
        print(f"    - Not in maintenance")

        for tid in cfg.get("excluded_trigger_ids", []):
            print(f"    - Trigger != {tid}")

        for tag in cfg.get("excluded_tag_names", []):
            print(f"    - Event tag name does not contain '{tag}'")

        print(f"  Operations: send to '{username}' on problem, recovery, and update")
        print()

        # --- Summary ---
        creates = sum([
            existing_mt is None,
            existing_user is None,
            existing_action is None,
        ])
        updates = 3 - creates
        print(f"=== SUMMARY: {creates} create(s), {updates} update(s), 0 deletes ===")
        print(f"Resources that WILL NOT be touched:")
        untouched_actions = [a for a in all_actions if "keep" not in a["name"].lower() and "uip" not in a["name"].lower()]
        print(f"  {len(untouched_actions)} existing trigger actions (including ZabbixToGrafana, zabbixToAlerta)")
        print(f"  {len(all_mt) - (1 if existing_mt else 0)} existing media types (including GrafanaWebhook)")
        print(f"  All existing users except '{username}' (if it exists)")

    finally:
        zlogout(auth)


# ── Main ──────────────────────────────────────────────────────────────────

COMMANDS = ["discover", "setup", "test", "status", "teardown", "dry-run"]


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in COMMANDS:
        print(f"Usage: {sys.argv[0]} <command> <instance>")
        print()
        print("Commands:")
        print("  discover   List host groups, actions, users on the Zabbix instance")
        print("  setup      Create webhook media type, user, and action")
        print("  test       Test connectivity to Keep and Zabbix API")
        print("  status     Show current webhook configuration")
        print("  teardown   Remove webhook configuration")
        print("  dry-run    Show what setup would do without making changes")
        print()
        print("Instances:")
        for key, inst in INSTANCES.items():
            print(f"  {key:20s} {inst['display_name']}")
        sys.exit(1)

    command = sys.argv[1]
    instance = sys.argv[2]
    cfg = load_instance(instance)

    cmd_map = {
        "discover": cmd_discover,
        "setup": cmd_setup,
        "test": cmd_test,
        "status": cmd_status,
        "teardown": cmd_teardown,
        "dry-run": cmd_dryrun,
    }

    try:
        cmd_map[command](cfg)
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
