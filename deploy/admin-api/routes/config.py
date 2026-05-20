"""GET/PATCH/DELETE /api/admin/config* + /schemas/version.

Validation rules live alongside the value in the config row (`validation`
column). We re-validate server-side here, even though the UI also validates.
"""
import json
import logging
import re
from datetime import datetime, timezone

from db import get_conn
from sse import broadcast
from routes._common import has_permission, send_json, read_json_body, forbid, unauthorized
from auth import resolve_user

log = logging.getLogger("admin-api.routes.config")


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_dict(row) -> dict:
    return {
        "key": row["key"],
        "scope": row["scope"],
        "value": "***SET***" if row["is_secret"] else json.loads(row["value"]),
        "value_type": row["value_type"],
        "reload_kind": row["reload_kind"],
        "restart_target": row["restart_target"],
        "default": json.loads(row["default_value"]),
        "description": row["description"],
        "validation": json.loads(row["validation"]) if row["validation"] else None,
        "is_secret": bool(row["is_secret"]),
        "secret_rotated_at": row["secret_rotated_at"],
        "updated_at": row["updated_at"],
        "updated_by": row["updated_by"],
        "seed_version": row["seed_version"],
    }


def _validate(value, vtype: str, rule: dict | None) -> str | None:
    """Return error message if invalid, else None."""
    # Type check
    if vtype == "int":
        if not isinstance(value, int) or isinstance(value, bool):
            return f"expected int, got {type(value).__name__}"
    elif vtype == "float":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return f"expected number, got {type(value).__name__}"
    elif vtype == "bool":
        if not isinstance(value, bool):
            return f"expected bool, got {type(value).__name__}"
    elif vtype == "string":
        if not isinstance(value, str):
            return f"expected string, got {type(value).__name__}"
    # Rule check
    if not rule:
        return None
    if vtype in ("int", "float"):
        if "min" in rule and value < rule["min"]:
            return f"value {value} below min {rule['min']}"
        if "max" in rule and value > rule["max"]:
            return f"value {value} above max {rule['max']}"
    if vtype == "string":
        if "regex" in rule and not re.match(rule["regex"], value):
            return f"value does not match regex {rule['regex']}"
        if "enum" in rule and value not in rule["enum"]:
            return f"value not in enum {rule['enum']}"
    return None


def handle(handler, method: str, path: str, query: dict, db_path: str) -> bool:
    """Dispatch /api/admin/config* routes. Returns True if handled."""
    # Auth
    cookie = handler.headers.get("Cookie")
    bypass = handler.headers.get("X-Admin-Bypass")
    user = resolve_user(cookie, bypass, remote_ip=handler.client_address[0])

    if path == "/api/admin/config" and method == "GET":
        if user is None:
            unauthorized(handler); return True
        if not has_permission(user, "view_admin"):
            # Slice 1 gates by view_admin only; Slice 2+ tightens to per-scope perms.
            forbid(handler); return True
        scope = query.get("scope")
        with get_conn(db_path) as conn:
            if scope:
                rows = conn.execute("SELECT * FROM config WHERE scope=? ORDER BY key", (scope,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM config ORDER BY key").fetchall()
        send_json(handler, 200, {"items": [_row_to_dict(r) for r in rows]})
        return True

    if path == "/api/admin/config/schemas/version" and method == "GET":
        from uip_config_client.schemas import SEED_VERSION
        send_json(handler, 200, {"seed_version": SEED_VERSION})
        return True

    # /api/admin/config/{key}  (GET, PATCH, DELETE)
    if path.startswith("/api/admin/config/") and "/" not in path[len("/api/admin/config/"):]:
        key = path[len("/api/admin/config/"):]
        if not key:
            send_json(handler, 400, {"error": "missing key"}); return True

        if method == "GET":
            if user is None: unauthorized(handler); return True
            if not has_permission(user, "view_admin"):
                forbid(handler); return True
            with get_conn(db_path) as conn:
                row = conn.execute("SELECT * FROM config WHERE key=?", (key,)).fetchone()
            if row is None:
                send_json(handler, 404, {"error": "not found", "key": key}); return True
            send_json(handler, 200, _row_to_dict(row))
            return True

        if method == "PATCH":
            if user is None: unauthorized(handler); return True
            if not has_permission(user, "view_admin"):
                forbid(handler); return True
            body = read_json_body(handler)
            new_value = body.get("value")
            reason = body.get("reason")
            with get_conn(db_path) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    row = conn.execute("SELECT * FROM config WHERE key=?", (key,)).fetchone()
                    if row is None:
                        conn.execute("ROLLBACK")
                        send_json(handler, 404, {"error": "not found", "key": key}); return True
                    # Secrets must go through POST /rotate-secret (Fernet path); PATCH on is_secret=1
                    # would overwrite ciphertext with raw plaintext.
                    if row["is_secret"]:
                        conn.execute("ROLLBACK")
                        send_json(handler, 409, {"error": "use POST /api/admin/config/{key}/rotate-secret for is_secret=1 keys"}); return True
                    rule = json.loads(row["validation"]) if row["validation"] else None
                    err = _validate(new_value, row["value_type"], rule)
                    if err:
                        conn.execute("ROLLBACK")
                        send_json(handler, 400, {"error": err}); return True
                    old_value_json = row["value"]
                    new_value_json = json.dumps(new_value)
                    now = _now_iso()
                    conn.execute(
                        "UPDATE config SET value=?, updated_at=?, updated_by=? WHERE key=?",
                        (new_value_json, now, user.username, key),
                    )
                    conn.execute(
                        "INSERT INTO config_history (key, old_value, new_value, changed_by, changed_at, reason, source) VALUES (?, ?, ?, ?, ?, ?, 'user')",
                        (key, old_value_json, new_value_json, user.username, now, reason),
                    )
                    conn.execute("COMMIT")
                except Exception:
                    try: conn.execute("ROLLBACK")
                    except Exception: pass
                    raise
            broadcast("config_changed", {
                "key": key,
                "new_value": new_value,
                "updated_by": user.username,
                "updated_at": now,
                "reload_kind": row["reload_kind"],
                "restart_target": row["restart_target"],
            })
            send_json(handler, 200, {"ok": True, "key": key, "value": new_value})
            return True

        if method == "DELETE":
            if user is None: unauthorized(handler); return True
            if not has_permission(user, "view_admin"):
                forbid(handler); return True
            with get_conn(db_path) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    row = conn.execute("SELECT * FROM config WHERE key=?", (key,)).fetchone()
                    if row is None:
                        conn.execute("ROLLBACK")
                        send_json(handler, 404, {"error": "not found", "key": key}); return True
                    default_value = json.loads(row["default_value"])
                    old_value_json = row["value"]
                    new_value_json = row["default_value"]
                    now = _now_iso()
                    conn.execute(
                        "UPDATE config SET value=?, updated_at=?, updated_by=? WHERE key=?",
                        (new_value_json, now, user.username, key),
                    )
                    conn.execute(
                        "INSERT INTO config_history (key, old_value, new_value, changed_by, changed_at, reason, source) VALUES (?, ?, ?, ?, ?, ?, 'rollback')",
                        (key, old_value_json, new_value_json, user.username, now, "reset to default"),
                    )
                    conn.execute("COMMIT")
                except Exception:
                    try: conn.execute("ROLLBACK")
                    except Exception: pass
                    raise
            broadcast("config_changed", {
                "key": key,
                "new_value": default_value,
                "updated_by": user.username,
                "updated_at": now,
                "reload_kind": row["reload_kind"],
                "restart_target": row["restart_target"],
            })
            send_json(handler, 200, {"ok": True, "key": key, "value": default_value})
            return True

    return False
