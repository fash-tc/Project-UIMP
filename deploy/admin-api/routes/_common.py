"""Shared helpers for route modules: permission check, JSON IO."""
import json
import logging
from http.server import BaseHTTPRequestHandler

from auth import User

log = logging.getLogger("admin-api.routes")


def has_permission(user: User | None, perm: str) -> bool:
    if user is None:
        return False
    if "*" in user.permissions:
        return True
    return perm in user.permissions


def send_json(handler: BaseHTTPRequestHandler, status: int, body) -> None:
    data = json.dumps(body).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def read_json_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    return json.loads(raw.decode())


def forbid(handler: BaseHTTPRequestHandler) -> None:
    send_json(handler, 403, {"error": "forbidden"})


def unauthorized(handler: BaseHTTPRequestHandler) -> None:
    send_json(handler, 401, {"error": "unauthorized"})
