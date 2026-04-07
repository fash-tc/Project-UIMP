from pathlib import Path
import sys
import io
from contextlib import redirect_stdout


REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_ROOT = REPO_ROOT / "deploy"
sys.path.insert(0, str(DEPLOY_ROOT))

import zabbix_webhook_setup as zws  # noqa: E402


def test_load_instance_accepts_runtime_style_enom_env_names(monkeypatch):
    monkeypatch.setenv("ZABBIX_ENOM_USER", "UIPZabbix")
    monkeypatch.setenv("ZABBIX_ENOM_PASS", "srepass1")

    cfg = zws.load_instance("enom")

    assert cfg["zabbix_user"] == "UIPZabbix"
    assert cfg["zabbix_pass"] == "srepass1"


def test_load_instance_accepts_setup_script_style_enom_env_names(monkeypatch):
    monkeypatch.delenv("ZABBIX_ENOM_USER", raising=False)
    monkeypatch.delenv("ZABBIX_ENOM_PASS", raising=False)
    monkeypatch.setenv("ZABBIX_USER_ENOM", "UIPZabbix")
    monkeypatch.setenv("ZABBIX_PASS_ENOM", "srepass1")

    cfg = zws.load_instance("enom")

    assert cfg["zabbix_user"] == "UIPZabbix"
    assert cfg["zabbix_pass"] == "srepass1"


def test_alert_enricher_exposes_enom_runtime_credentials():
    compose = (DEPLOY_ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert 'ZABBIX_ENOM_USER: "${ZABBIX_ENOM_USER:-}"' in compose
    assert 'ZABBIX_ENOM_PASS: "${ZABBIX_ENOM_PASS:-}"' in compose


def test_webhook_script_supports_legacy_and_modern_zabbix_http_clients():
    script = zws.WEBHOOK_SCRIPT

    assert "typeof HttpRequest !== 'undefined'" in script
    assert "typeof CurlHttpRequest !== 'undefined'" in script
    assert "var req = new RequestCtor();" in script
    assert "req.addHeader ? function(name, value) { req.addHeader(name, value); }" in script
    assert "function(name, value) { req.AddHeader(name, value); }" in script
    assert "req.post ? function(url, data) { return req.post(url, data); }" in script
    assert "function(url, data) { return req.Post(url, data); }" in script
    assert "req.getStatus ? function() { return req.getStatus(); }" in script
    assert "function() { return req.Status(); }" in script


def test_create_or_update_user_uses_legacy_user_medias_for_legacy_zabbix(monkeypatch):
    calls = []

    def fake_find_user(auth, username):
        return {
            "userid": "55",
            "medias": [
                {"mediaid": "9", "userid": "55", "sendto": "http://10.177.154.196/alerts/event/zabbix", "mediatypeid": "33"},
                {"mediaid": "10", "userid": "55", "sendto": "pager", "mediatypeid": "44"},
            ],
        }

    def fake_get_user_groups_for_instance(auth, cfg):
        return [{"usrgrpid": "7"}]

    def fake_zapi(method, params, auth=None):
        calls.append((method, params, auth))
        return {}

    monkeypatch.setattr(zws, "find_user", fake_find_user)
    monkeypatch.setattr(zws, "get_user_groups_for_instance", fake_get_user_groups_for_instance)
    monkeypatch.setattr(zws, "zapi", fake_zapi)
    monkeypatch.setattr(zws, "_is_legacy_zabbix", lambda: True)

    userid = zws.create_or_update_user("auth-token", {"webhook_username": "uip-webhook"}, "33")

    assert userid == "55"
    assert calls == [
        (
            "user.update",
            {
                "userid": "55",
                "usrgrps": [{"usrgrpid": "7"}],
                "user_medias": [
                    {
                        "mediatypeid": "44",
                        "sendto": "pager",
                    },
                    {
                        "mediatypeid": "33",
                        "sendto": "keep",
                        "active": "0",
                        "severity": "60",
                        "period": "1-7,00:00-24:00",
                    }
                ],
            },
            "auth-token",
        )
    ]


def test_create_or_update_action_omits_eventsource_for_existing_action(monkeypatch):
    calls = []

    monkeypatch.setattr(zws, "find_action", lambda auth, name: {"actionid": "18", "name": name})

    def fake_zapi(method, params, auth=None):
        calls.append((method, params, auth))
        return {}

    monkeypatch.setattr(zws, "zapi", fake_zapi)

    action_id = zws.create_or_update_action(
        "auth-token",
        {
            "action_name": "UIP Keep Webhook (enom)",
            "alert_group_ids": [],
            "min_severity": "2",
            "excluded_trigger_ids": [],
            "excluded_tag_names": ["dev"],
        },
        "33",
        "55",
    )

    assert action_id == "18"
    assert calls[0][0] == "action.update"
    assert calls[0][1]["actionid"] == "18"
    assert "eventsource" not in calls[0][1]


def test_cmd_status_reads_legacy_camel_case_recovery_operations(monkeypatch):
    monkeypatch.setattr(zws, "zlogin", lambda cfg: "auth-token")
    monkeypatch.setattr(zws, "zlogout", lambda auth: None)
    monkeypatch.setattr(zws, "find_media_type", lambda auth, name: {"name": name, "mediatypeid": "33", "status": "0"})
    monkeypatch.setattr(
        zws,
        "find_user",
        lambda auth, username: {"userid": "55", "username": username, "medias": [{"mediatypeid": "33", "sendto": "keep", "active": "0"}]},
    )
    monkeypatch.setattr(
        zws,
        "find_action",
        lambda auth, name: {
            "name": name,
            "actionid": "18",
            "status": "0",
            "filter": {"conditions": []},
            "operations": [{}],
            "recoveryOperations": [{}],
            "updateOperations": [],
        },
    )

    buf = io.StringIO()
    with redirect_stdout(buf):
        zws.cmd_status(
            {
                "display_name": "Enom Zabbix",
                "media_type_name": "Keep UIP Webhook (enom)",
                "webhook_username": "uip-webhook",
                "action_name": "UIP Keep Webhook (enom)",
                "zabbix_url": "https://zabbix.enom.net/api_jsonrpc.php",
            }
        )

    output = buf.getvalue()
    assert "Operations: 1 problem, 1 recovery, 0 update" in output
