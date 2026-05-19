"""
UIP Health Checker — Lightweight service health monitor.
Queries Docker socket for container status, checks HTTP endpoints,
and exposes a REST API on port 8089.
"""

import json
import os
import socket
import time
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

API_PORT = int(os.environ.get("API_PORT", "8089"))

# Services to monitor via Docker socket
DOCKER_CONTAINERS = {
    "postgres":        {"display": "PostgreSQL",        "role": "Database"},
    "keep-api":        {"display": "Keep API",          "role": "Alert Backend"},
    "keep-ui":         {"display": "Keep Frontend",     "role": "Admin UI"},
    "ollama":          {"display": "Ollama LLM",        "role": "AI Inference"},
    "alert-enricher":  {"display": "Alert Enricher",    "role": "AI Analysis"},
    "auth-api":        {"display": "Auth API",          "role": "Authentication"},
    "alert-state-api": {"display": "Alert State API",   "role": "Alert Tracking"},
    "loki-gateway":    {"display": "Loki Gateway",      "role": "Log Queries"},
    "sre-frontend":    {"display": "SRE Frontend",      "role": "SRE Portal"},
    "n8n":             {"display": "n8n Workflows",     "role": "Automation"},
    "nginx":           {"display": "Nginx Proxy",       "role": "Reverse Proxy"},
    "runbook-api":     {"display": "Runbook API",       "role": "Knowledge Base"},
    "escalation-api":  {"display": "Escalation API",   "role": "IRM Escalation"},
}

# HTTP health checks (from within Docker network)
HTTP_CHECKS = {
    "keep-api":     "http://keep-api:8080/",
    "sre-frontend": "http://sre-frontend:3000/portal/",
    "n8n":          "http://n8n:5678/n8n/healthz",
    "ollama":       "http://ollama:11434/api/tags",
    "runbook-api":  "http://runbook-api:8090/api/runbook/entries?limit=1",
    "auth-api":        "http://auth-api:8093/api/auth/login",
    "alert-state-api": "http://alert-state-api:8092/api/alert-states",
    "escalation-api":  "http://escalation-api:8094/api/escalation/health",
}

KEEP_URL = os.environ.get("KEEP_URL", "http://keep-api:8080")
KEEP_API_KEY = os.environ.get("KEEP_API_KEY", "")


def docker_socket_request(path):
    """Make a request to the Docker socket and return parsed JSON."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect("/var/run/docker.sock")
        request = f"GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n"
        sock.sendall(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        # Split headers from body
        parts = response.split(b"\r\n\r\n", 1)
        if len(parts) < 2:
            return None
        body = parts[1]
        return json.loads(body)
    except Exception:
        return None
    finally:
        sock.close()


def get_container_status():
    """Get status of all UIP containers via Docker socket."""
    containers = docker_socket_request("/containers/json?all=true")
    if containers is None:
        return None

    status_map = {}
    for c in containers:
        # Container names have a leading /
        names = [n.lstrip("/") for n in c.get("Names", [])]
        for short_name, meta in DOCKER_CONTAINERS.items():
            full_name = f"uip-{short_name}"
            if full_name in names:
                state = c.get("State", "unknown")
                status_text = c.get("Status", "")
                created = c.get("Created", 0)

                status_map[short_name] = {
                    "name": meta["display"],
                    "role": meta["role"],
                    "container": full_name,
                    "state": state,
                    "status": status_text,
                    "created_ts": created,
                    "healthy": state == "running",
                }
    return status_map


def http_health_check(url, timeout=5):
    """Check if an HTTP endpoint responds successfully."""
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=timeout)
        return {
            "reachable": True,
            "status_code": resp.getcode(),
            "response_ms": 0,  # simplified
        }
    except urllib.error.HTTPError as e:
        # Some endpoints return non-200 but are still "up"
        return {
            "reachable": True,
            "status_code": e.code,
            "response_ms": 0,
        }
    except Exception:
        return {
            "reachable": False,
            "status_code": None,
            "response_ms": None,
        }


def check_data_freshness():
    """Check Keep API for alert data freshness."""
    try:
        url = f"{KEEP_URL}/alerts?limit=5"
        req = urllib.request.Request(url)
        if KEEP_API_KEY:
            req.add_header("X-API-KEY", KEEP_API_KEY)
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        items = data if isinstance(data, list) else data.get("items", [])

        if not items:
            return {"status": "no_data", "latest_alert": None, "alert_count": 0}

        # Find the most recent lastReceived
        latest = max(items, key=lambda a: a.get("lastReceived", ""))
        return {
            "status": "ok",
            "latest_alert": latest.get("lastReceived"),
            "alert_count": len(items),
            "latest_name": latest.get("name", "")[:60],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def build_health_report():
    """Build complete health report."""
    now = datetime.now(timezone.utc).isoformat()

    # 1. Container status
    containers = get_container_status()
    docker_available = containers is not None
    if not docker_available:
        containers = {}

    # 2. HTTP health checks
    http_results = {}
    for svc, url in HTTP_CHECKS.items():
        http_results[svc] = http_health_check(url)

    # 3. Merge HTTP into container status
    for svc, result in http_results.items():
        if svc in containers:
            containers[svc]["http_check"] = result
            # Override healthy if HTTP check fails on a running container
            if containers[svc]["state"] == "running" and not result["reachable"]:
                containers[svc]["healthy"] = False

    # 4. Data freshness
    data_freshness = check_data_freshness()

    # 5. Overall status
    all_healthy = all(c.get("healthy", False) for c in containers.values())
    missing = set(DOCKER_CONTAINERS.keys()) - set(containers.keys())

    if not docker_available:
        overall = "unknown"
    elif missing or not all_healthy:
        overall = "degraded"
    else:
        overall = "healthy"

    services = []
    for short_name, meta in DOCKER_CONTAINERS.items():
        if short_name in containers:
            svc = containers[short_name]
        else:
            svc = {
                "name": meta["display"],
                "role": meta["role"],
                "container": f"uip-{short_name}",
                "state": "not_found",
                "status": "Container not found",
                "healthy": False,
            }
        services.append(svc)

    return {
        "timestamp": now,
        "overall": overall,
        "docker_available": docker_available,
        "services": services,
        "data_freshness": data_freshness,
        "missing_containers": list(missing),
    }


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/health" or self.path == "/api/health/":
            report = build_health_report()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(report, indent=2).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default request logging
        pass


def main():
    print(f"UIP Health Checker starting on port {API_PORT}")
    server = HTTPServer(("0.0.0.0", API_PORT), HealthHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
