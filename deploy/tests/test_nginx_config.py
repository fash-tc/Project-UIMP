from pathlib import Path


NGINX_CONFIG_PATH = Path(__file__).resolve().parents[1] / "nginx-default.conf"
COMPOSE_PATH = Path(__file__).resolve().parents[1] / "docker-compose.yml"


def test_runbook_proxy_uses_re_resolved_upstream_variable():
    config = NGINX_CONFIG_PATH.read_text(encoding="utf-8")

    assert "set $runbook_api http://runbook-api:8090;" in config
    assert "location /api/runbook/ {" in config
    assert "proxy_pass $runbook_api;" in config
    assert "proxy_pass http://runbook-api:8090/api/runbook/;" not in config


def test_portal_proxy_uses_re_resolved_frontend_upstream_variable():
    config = NGINX_CONFIG_PATH.read_text(encoding="utf-8")

    assert "set $sre_frontend http://sre-frontend:3000;" in config
    assert "location /portal/ {" in config
    assert "proxy_pass $sre_frontend;" in config
    assert "proxy_pass http://sre-frontend:3000;" not in config


def test_nginx_config_serves_https_with_self_signed_sslip_cert():
    config = NGINX_CONFIG_PATH.read_text(encoding="utf-8")

    assert "listen 443 ssl default_server;" in config
    assert "ssl_certificate /etc/nginx/ssl/selfsigned.crt;" in config
    assert "ssl_certificate_key /etc/nginx/ssl/selfsigned.key;" in config


def test_nginx_compose_publishes_https_and_mounts_ssl_dir():
    compose = COMPOSE_PATH.read_text(encoding="utf-8")

    assert '- "443:443"' in compose
    assert "./nginx/ssl:/etc/nginx/ssl:ro" in compose
