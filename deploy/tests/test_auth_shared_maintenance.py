import types
import uuid
from pathlib import Path


AUTH_API_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\auth-api\auth-api.py")
TEST_DB_ROOT = Path(r"C:\Users\fash\Documents\UIP\deploy\tests\_tmp_auth_shared")


def load_auth_api():
    source = AUTH_API_PATH.read_text(encoding="utf-8")
    trimmed_source = source.split('db = _init_db()', 1)[0]
    module = types.ModuleType("auth_api_under_test")
    module.__file__ = str(AUTH_API_PATH)
    exec(compile(trimmed_source, str(AUTH_API_PATH), "exec"), module.__dict__)
    return module


def make_db_path():
    TEST_DB_ROOT.mkdir(exist_ok=True)
    return TEST_DB_ROOT / f"auth-{uuid.uuid4().hex}.db"


def test_init_db_creates_shared_integrations_table(monkeypatch):
    monkeypatch.setenv("DB_PATH", str(make_db_path()))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()

    db = auth_api._init_db()
    row = db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'shared_integrations'"
    ).fetchone()

    assert row["name"] == "shared_integrations"


def test_shared_maintenance_password_round_trip_is_encrypted(monkeypatch):
    monkeypatch.setenv("DB_PATH", str(make_db_path()))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()
    db = auth_api._init_db()

    auth_api._set_shared_integration_secret(
        db,
        "maintenance_api",
        username="maint-user",
        password="maint-pass",
        updated_by="fash",
    )

    stored = db.execute(
        "SELECT username, password_ciphertext, updated_by FROM shared_integrations WHERE key = ?",
        ("maintenance_api",),
    ).fetchone()

    assert stored["username"] == "maint-user"
    assert stored["updated_by"] == "fash"
    assert stored["password_ciphertext"] != "maint-pass"
    assert auth_api._get_shared_integration_secret(db, "maintenance_api")["password"] == "maint-pass"


def test_bootstrap_requires_admin_or_sre_role(monkeypatch):
    monkeypatch.setenv("DB_PATH", str(make_db_path()))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()
    db = auth_api._init_db()

    db.execute("UPDATE users SET role_id = 3 WHERE username = 'jpratt'")
    db.commit()

    allowed, reason = auth_api._can_bootstrap_maintenance(db, {"u": "jpratt"})

    assert allowed is False
    assert reason == "forbidden"


def test_bootstrap_uses_shared_maintenance_credentials(monkeypatch):
    monkeypatch.setenv("DB_PATH", str(make_db_path()))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()
    db = auth_api._init_db()
    auth_api._set_shared_integration_secret(db, "maintenance_api", "maint-user", "maint-pass", "fash")

    calls = []

    def fake_login(username, password):
        calls.append((username, password))
        return {"token": "maint-token"}

    auth_api._login_to_maintenance_api = fake_login

    body = auth_api._bootstrap_maintenance_token(db, {"u": "fash"})

    assert body["token"] == "maint-token"
    assert calls == [("maint-user", "maint-pass")]


def test_shared_maintenance_metadata_excludes_password(monkeypatch):
    monkeypatch.setenv("DB_PATH", str(make_db_path()))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()
    db = auth_api._init_db()
    auth_api._set_shared_integration_secret(db, "maintenance_api", "maint-user", "maint-pass", "fash")

    metadata = auth_api._get_shared_integration_metadata(db, "maintenance_api")

    assert metadata["configured"] is True
    assert metadata["username"] == "maint-user"
    assert "password" not in metadata


def test_auth_api_source_contains_shared_maintenance_routes():
    source = AUTH_API_PATH.read_text(encoding="utf-8")

    assert '/api/auth/shared-integrations/maintenance' in source
    assert '/api/auth/shared-integrations/maintenance/test' in source
    assert '/api/auth/maintenance/bootstrap' in source


def test_auth_api_compose_includes_shared_integrations_secret():
    compose = Path(r"C:\Users\fash\Documents\UIP\deploy\docker-compose.yml").read_text(encoding="utf-8")

    assert "SHARED_INTEGRATIONS_SECRET" in compose


def test_auth_api_compose_includes_jira_oauth_env_vars():
    compose = Path(r"C:\Users\fash\Documents\UIP\deploy\docker-compose.yml").read_text(encoding="utf-8")

    assert 'JIRA_OAUTH_CLIENT_ID: "${JIRA_OAUTH_CLIENT_ID}"' in compose
    assert 'JIRA_OAUTH_CLIENT_SECRET: "${JIRA_OAUTH_CLIENT_SECRET}"' in compose
    assert 'JIRA_OAUTH_REDIRECT_URI: "${JIRA_OAUTH_REDIRECT_URI}"' in compose


def test_webhook_subscriber_secret_round_trip(monkeypatch):
    monkeypatch.setenv("DB_PATH", str(make_db_path()))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("SHARED_INTEGRATIONS_SECRET", "0123456789abcdef0123456789abcdef")
    auth_api = load_auth_api()
    db = auth_api._init_db()

    auth_api._set_webhook_subscriber_secret(
        db,
        subscriber_id=7,
        name="Customer Preview",
        url="https://hooks.example/customer-preview",
        secret="preview-secret",
        updated_by="fash",
    )

    secrets = auth_api._get_webhook_subscriber_secret_map(db)

    assert secrets["7"]["secret"] == "preview-secret"
    assert secrets["7"]["name"] == "Customer Preview"
    assert secrets["7"]["url"] == "https://hooks.example/customer-preview"


def test_auth_api_source_contains_webhook_secret_routes():
    source = AUTH_API_PATH.read_text(encoding="utf-8")

    assert '/api/auth/webhook-subscriber-secrets/' in source
    assert '/api/auth/internal/webhook-subscriber-secrets' in source


def test_frontend_path_defaults_to_portal(monkeypatch):
    monkeypatch.setenv("DB_PATH", str(make_db_path()))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.delenv("FRONTEND_BASE_PATH", raising=False)
    auth_api = load_auth_api()

    assert auth_api._frontend_path("/settings?jira_connected=true") == "/portal/settings?jira_connected=true"
    assert auth_api._frontend_path("login?error=auth_required") == "/portal/login?error=auth_required"


def test_frontend_path_honors_configured_base_path(monkeypatch):
    monkeypatch.setenv("DB_PATH", str(make_db_path()))
    monkeypatch.setenv("AUTH_SECRET", "test-auth-secret")
    monkeypatch.setenv("FRONTEND_BASE_PATH", "/ops")
    auth_api = load_auth_api()

    assert auth_api._frontend_path("/settings") == "/ops/settings"
