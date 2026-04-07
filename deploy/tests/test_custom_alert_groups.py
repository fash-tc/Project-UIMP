import types
import uuid
from pathlib import Path


ALERT_STATE_API_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\alert-state-api\alert-state-api.py")
TEST_DB_ROOT = Path(r"C:\Users\fash\Documents\UIP\deploy\tests\_tmp_custom_groups")


def load_alert_state_api():
    source = ALERT_STATE_API_PATH.read_text(encoding="utf-8")
    trimmed_source = source.split("db = _init_db()", 1)[0]
    module = types.ModuleType("alert_state_api_under_test")
    module.__file__ = str(ALERT_STATE_API_PATH)
    exec(compile(trimmed_source, str(ALERT_STATE_API_PATH), "exec"), module.__dict__)
    return module


def make_db_path():
    TEST_DB_ROOT.mkdir(exist_ok=True)
    return TEST_DB_ROOT / f"alert-state-{uuid.uuid4().hex}.db"


def build_module(monkeypatch):
    monkeypatch.setenv("DB_PATH", str(make_db_path()))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    module = load_alert_state_api()
    module.db = module._init_db()
    return module


def test_rename_custom_group_updates_name_and_timestamp(monkeypatch):
    module = build_module(monkeypatch)
    created = module._create_custom_group("Initial Group", ["fp-1", "fp-2"], "fash")

    renamed = module._rename_custom_group(created["id"], "Renamed Group", "fash")

    assert renamed["name"] == "Renamed Group"
    assert renamed["fingerprints"] == ["fp-1", "fp-2"]
    stored = module.db.execute("SELECT name FROM custom_alert_groups WHERE id = ?", (created["id"],)).fetchone()
    assert stored["name"] == "Renamed Group"


def test_add_alerts_to_custom_group_appends_members_without_replacing_existing(monkeypatch):
    module = build_module(monkeypatch)
    created = module._create_custom_group("Append Group", ["fp-1"], "fash")

    updated = module._add_alerts_to_custom_group(created["id"], ["fp-2", "fp-3"], "fash")

    assert updated["fingerprints"] == ["fp-1", "fp-2", "fp-3"]


def test_add_alerts_to_custom_group_rejects_alerts_owned_by_another_group(monkeypatch):
    module = build_module(monkeypatch)
    target = module._create_custom_group("Target", ["fp-1"], "fash")
    module._create_custom_group("Other", ["fp-9"], "fash")

    try:
        module._add_alerts_to_custom_group(target["id"], ["fp-9"], "fash")
    except ValueError as exc:
        assert "already belongs to custom group" in str(exc)
    else:
        raise AssertionError("Expected add to reject alerts already assigned to another custom group")
