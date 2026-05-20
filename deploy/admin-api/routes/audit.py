"""/api/admin/audit — list + CSV export."""
import csv
import io
import logging

from db import get_conn
from routes._common import has_permission, send_json, unauthorized
from auth import resolve_user

log = logging.getLogger("admin-api.routes.audit")


def _rows(conn, where_clauses, params, limit=500):
    q = "SELECT id, key, old_value, new_value, changed_by, changed_at, reason, source FROM config_history"
    if where_clauses:
        q += " WHERE " + " AND ".join(where_clauses)
    q += " ORDER BY changed_at DESC LIMIT ?"
    params = list(params) + [limit]
    return conn.execute(q, params).fetchall()


def handle(handler, method: str, path: str, query: dict, db_path: str) -> bool:
    user = resolve_user(handler.headers.get("Cookie"), handler.headers.get("X-Admin-Bypass"),
                        remote_ip=handler.client_address[0])
    if path in ("/api/admin/audit", "/api/admin/audit/export") and method == "GET":
        if user is None: unauthorized(handler); return True
        if not (has_permission(user, "view_audit") or has_permission(user, "view_admin")):
            send_json(handler, 403, {"error": "forbidden"}); return True
        where, params = [], []
        if key := query.get("key"): where.append("key=?"); params.append(key)
        if by := query.get("by"): where.append("changed_by=?"); params.append(by)
        if frm := query.get("from"): where.append("changed_at>=?"); params.append(frm)
        if to := query.get("to"): where.append("changed_at<=?"); params.append(to)
        with get_conn(db_path) as conn:
            rows = _rows(conn, where, params)
        items = [dict(r) for r in rows]

        if path == "/api/admin/audit/export":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["key", "old_value", "new_value", "changed_by", "changed_at", "reason", "source"])
            for r in items:
                w.writerow([r["key"], r["old_value"], r["new_value"], r["changed_by"], r["changed_at"], r["reason"], r["source"]])
            body = buf.getvalue().encode()
            handler.send_response(200)
            handler.send_header("Content-Type", "text/csv; charset=utf-8")
            handler.send_header("Content-Disposition", "attachment; filename=admin-audit.csv")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
            return True

        send_json(handler, 200, {"items": items})
        return True
    return False
