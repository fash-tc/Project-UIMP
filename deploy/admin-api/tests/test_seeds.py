import json
import os


def test_config_seed_has_required_fields():
    seed_path = os.path.join(os.path.dirname(__file__), "..", "seeds", "config_seed.json")
    with open(seed_path) as f:
        seed = json.load(f)
    assert seed["version"] >= 1
    required = {"scope", "value_type", "default", "reload_kind", "description", "validation", "is_secret", "env_legacy", "consumed_by"}
    for key, entry in seed["keys"].items():
        assert required.issubset(entry.keys()), f"{key} missing fields: {required - entry.keys()}"
        assert entry["value_type"] in {"int", "float", "string", "bool", "json", "secret"}
        assert entry["reload_kind"] in {"hot", "restart"}
        assert isinstance(entry["is_secret"], bool)


def test_services_seed_has_uip_admin_api_excluded():
    seed_path = os.path.join(os.path.dirname(__file__), "..", "seeds", "services_seed.json")
    with open(seed_path) as f:
        seed = json.load(f)
    assert "uip-admin-api" not in seed["restartable_containers"], \
        "admin-api must not be in restartable list (self-restart loops)"
