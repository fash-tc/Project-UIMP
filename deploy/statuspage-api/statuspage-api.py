"""
UIP Statuspage API - internal incident communication and email delivery.
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import smtplib
import sqlite3
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("statuspage-api")

API_PORT = int(os.environ.get("API_PORT", "8096"))
DB_PATH = os.environ.get("DB_PATH", "/data/statuspage.db")
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")
DEFAULT_SUBSCRIBER = "iu@tucows.com"
VALID_INCIDENT_STATUSES = {"investigating", "identified", "monitoring", "resolved", "scheduled_maintenance"}
VALID_IMPACTS = {"none", "minor", "major", "critical", "maintenance"}
VALID_COMPONENT_STATUSES = {"operational", "degraded_performance", "partial_outage", "major_outage", "maintenance"}
IMPACT_SEVERITY = {"none": 0, "maintenance": 1, "minor": 2, "major": 3, "critical": 4}


def init_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS component_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            display_order INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER,
            name TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'operational',
            display_order INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (group_id) REFERENCES component_groups(id)
        )
    """)
    component_columns = {row[1] for row in db.execute("PRAGMA table_info(components)").fetchall()}
    if "group_id" not in component_columns:
        db.execute("ALTER TABLE components ADD COLUMN group_id INTEGER")
    if "active" not in component_columns:
        db.execute("ALTER TABLE components ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
    db.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            impact TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            resolved_at TEXT,
            scheduled_start TEXT,
            scheduled_end TEXT,
            is_deleted INTEGER NOT NULL DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS incident_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            body TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            email_required INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS incident_components (
            incident_id INTEGER NOT NULL,
            component_id INTEGER NOT NULL,
            component_status TEXT NOT NULL,
            PRIMARY KEY (incident_id, component_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (component_id) REFERENCES components(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            label TEXT DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL DEFAULT 'system',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS email_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_update_id INTEGER NOT NULL,
            subscriber_id INTEGER,
            recipient_email TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            sent_at TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (incident_update_id) REFERENCES incident_updates(id),
            FOREIGN KEY (subscriber_id) REFERENCES subscribers(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS external_publications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_update_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            external_id TEXT DEFAULT '',
            external_url TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            error TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (incident_update_id) REFERENCES incident_updates(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS statuspage_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT '',
            updated_by TEXT NOT NULL DEFAULT 'system',
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    db.execute(
        "INSERT OR IGNORE INTO subscribers (email, label, active, created_by) VALUES (?, ?, 1, 'system')",
        (DEFAULT_SUBSCRIBER, "Internal updates relay"),
    )
    db.commit()
    return db


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def verify_auth_token(token):
    if not AUTH_SECRET or not token or "." not in token:
        return None
    payload_b64, sig = token.rsplit(".", 1)
    expected_sig = hmac_mod.new(AUTH_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    if not hmac_mod.compare_digest(sig, expected_sig):
        return None
    try:
        padded = payload_b64 + ("=" * (-len(payload_b64) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    except Exception:
        return None
    if int(payload.get("e") or 0) <= int(time.time()):
        return None
    username = (payload.get("u") or "").strip()
    return username or None


def get_username_from_headers(headers):
    cookie_header = headers.get("Cookie", "")
    for part in cookie_header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == "uip_auth":
            return verify_auth_token(value)
    return None


def active_incident_where():
    return "is_deleted = 0 AND status IN ('investigating', 'identified', 'monitoring', 'scheduled_maintenance')"


def statuspage_resource(parts):
    if len(parts) >= 3 and parts[:2] == ["api", "statuspage"]:
        return parts[2]
    return None


def create_component(db, name, description="", display_order=0):
    name = (name or "").strip()
    if not name:
        raise ValueError("name is required")
    now = utc_now()
    db.execute(
        """
        INSERT INTO components (name, description, display_order, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            description = excluded.description,
            display_order = excluded.display_order,
            updated_at = excluded.updated_at
        """,
        (name, description or "", display_order, now),
    )
    db.commit()
    row = db.execute("SELECT id FROM components WHERE name = ?", (name,)).fetchone()
    return row["id"]


def list_component_groups(db):
    rows = db.execute(
        """
        SELECT *
        FROM component_groups
        WHERE active = 1
        ORDER BY display_order, name
        """
    ).fetchall()
    return [row_to_dict(row) for row in rows]


def upsert_component_group(db, data, username):
    name = _require_text(data, "name")
    description = (data.get("description") or "").strip()
    try:
        display_order = int(data.get("display_order") or 0)
    except (TypeError, ValueError):
        raise ValueError("display_order must be a number")
    now = utc_now()
    group_id = data.get("id")
    if group_id:
        existing = db.execute("SELECT id FROM component_groups WHERE id = ?", (group_id,)).fetchone()
        if existing is None:
            raise ValueError("component group not found")
        db.execute(
            """
            UPDATE component_groups
            SET name = ?, description = ?, display_order = ?, active = 1, updated_at = ?
            WHERE id = ?
            """,
            (name, description, display_order, now, group_id),
        )
    else:
        db.execute(
            """
            INSERT INTO component_groups (name, description, display_order, active, updated_at)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(name) DO UPDATE SET
                description = excluded.description,
                display_order = excluded.display_order,
                active = 1,
                updated_at = excluded.updated_at
            """,
            (name, description, display_order, now),
        )
    db.commit()
    return row_to_dict(db.execute("SELECT * FROM component_groups WHERE name = ?", (name,)).fetchone())


def remove_component_group(db, group_id, username):
    now = utc_now()
    db.execute("UPDATE components SET group_id = NULL, updated_at = ? WHERE group_id = ?", (now, group_id))
    db.execute("UPDATE component_groups SET active = 0, updated_at = ? WHERE id = ?", (now, group_id))
    db.commit()


def list_components(db):
    rows = db.execute(
        """
        SELECT c.*, g.name AS group_name
        FROM components c
        LEFT JOIN component_groups g ON g.id = c.group_id AND g.active = 1
        WHERE c.active = 1
        ORDER BY COALESCE(g.display_order, 999999), g.name, c.display_order, c.name
        """
    ).fetchall()
    return [row_to_dict(row) for row in rows]


def build_component_groups(db):
    groups = []
    for group in list_component_groups(db):
        group["components"] = []
        groups.append(group)
    ungrouped = {"id": None, "name": "Ungrouped", "description": "", "display_order": 999999, "components": []}
    by_id = {group["id"]: group for group in groups}
    for component in list_components(db):
        target = by_id.get(component.get("group_id"))
        if target is None:
            target = ungrouped
        target["components"].append(component)
    if ungrouped["components"]:
        groups.append(ungrouped)
    return groups


def upsert_component(db, data, username):
    name = _require_text(data, "name")
    description = (data.get("description") or "").strip()
    status = _validate_choice(data.get("status") or "operational", VALID_COMPONENT_STATUSES, "status")
    group_id = data.get("group_id")
    if group_id in ("", 0):
        group_id = None
    if group_id is not None:
        existing_group = db.execute("SELECT id FROM component_groups WHERE id = ? AND active = 1", (group_id,)).fetchone()
        if existing_group is None:
            raise ValueError("component group not found")
    try:
        display_order = int(data.get("display_order") or 0)
    except (TypeError, ValueError):
        raise ValueError("display_order must be a number")
    now = utc_now()
    component_id = data.get("id")
    if component_id:
        existing = db.execute("SELECT id FROM components WHERE id = ?", (component_id,)).fetchone()
        if existing is None:
            raise ValueError("component not found")
        db.execute(
            """
            UPDATE components
            SET name = ?,
                description = ?,
                status = ?,
                group_id = ?,
                display_order = ?,
                active = 1,
                updated_at = ?
            WHERE id = ?
            """,
            (name, description, status, group_id, display_order, now, component_id),
        )
    else:
        db.execute(
            """
            INSERT INTO components (name, description, status, group_id, display_order, active, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(name) DO UPDATE SET
                description = excluded.description,
                status = excluded.status,
                group_id = excluded.group_id,
                display_order = excluded.display_order,
                active = 1,
                updated_at = excluded.updated_at
            """,
            (name, description, status, group_id, display_order, now),
        )
    db.commit()
    return row_to_dict(db.execute("SELECT * FROM components WHERE name = ?", (name,)).fetchone())


def remove_component(db, component_id, username):
    existing = db.execute("SELECT id FROM components WHERE id = ?", (component_id,)).fetchone()
    if existing is None:
        raise ValueError("component not found")
    db.execute("UPDATE components SET active = 0, updated_at = ? WHERE id = ?", (utc_now(), component_id))
    db.commit()


def _require_text(data, key):
    value = (data.get(key) or "").strip()
    if not value:
        raise ValueError(f"{key} is required")
    return value


def _validate_choice(value, allowed, field):
    if value not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise ValueError(f"{field} must be one of: {allowed_values}")
    return value


def build_email_subject(incident, update):
    prefix = os.environ.get("STATUSPAGE_EMAIL_SUBJECT_PREFIX", "[SRE Status]")
    return f"{prefix} {incident['title']} - {update['status']}"


def build_email_body(incident, update, components):
    base_url = os.environ.get("STATUSPAGE_PUBLIC_BASE_URL", "http://10.177.154.196/portal/status").rstrip("/")
    link = f"{base_url}/incidents/{incident['id']}"
    component_lines = ["Components:"]
    if components:
        for component in components:
            component_lines.append(f"- {component['name']}: {component['component_status']}")
    else:
        component_lines.append("- None")
    lines = [
        f"Title: {incident['title']}",
        f"Status: {incident['status']}",
        f"Impact: {incident['impact']}",
        f"Published by: {update['created_by']}",
        f"Time: {update['created_at']}",
        *component_lines,
        "",
        update["body"],
        "",
        f"Link: {link}",
    ]
    return "\n".join(lines)


def list_incident_components(db, incident_id):
    rows = db.execute(
        """
        SELECT
            c.id AS component_id,
            c.name,
            c.description,
            c.status,
            c.display_order,
            ic.component_status
        FROM incident_components ic
        JOIN components c ON c.id = ic.component_id
        WHERE ic.incident_id = ?
        ORDER BY c.display_order, c.name
        """,
        (incident_id,),
    ).fetchall()
    return [row_to_dict(row) for row in rows]


def _incident_summary(db, row):
    incident = row_to_dict(row)
    incident["components"] = list_incident_components(db, incident["id"])
    latest_update = db.execute(
        """
        SELECT *
        FROM incident_updates
        WHERE incident_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (incident["id"],),
    ).fetchone()
    incident["latest_update"] = row_to_dict(latest_update)
    return incident


def build_summary(db):
    components = [
        row_to_dict(row)
        for row in db.execute(
            """
            SELECT *
            FROM components
            ORDER BY display_order, name
            """
        ).fetchall()
    ]
    active_rows = db.execute(
        f"""
        SELECT *
        FROM incidents
        WHERE {active_incident_where()}
        ORDER BY created_at DESC, id DESC
        """
    ).fetchall()
    active_incidents = [_incident_summary(db, row) for row in active_rows]
    resolved_rows = db.execute(
        """
        SELECT *
        FROM incidents
        WHERE is_deleted = 0 AND status = 'resolved'
        ORDER BY COALESCE(resolved_at, updated_at, created_at) DESC, id DESC
        LIMIT 10
        """
    ).fetchall()
    recent_resolved = [_incident_summary(db, row) for row in resolved_rows]
    overall_status = "operational"
    if active_incidents:
        overall_status = max(active_incidents, key=lambda incident: IMPACT_SEVERITY.get(incident["impact"], 0))["impact"]
    return {
        "overall_status": overall_status,
        "components": components,
        "component_groups": build_component_groups(db),
        "active_incidents": active_incidents,
        "recent_incidents": recent_resolved,
        "recent_resolved": recent_resolved,
    }


def enqueue_email_deliveries(db, incident, update, components):
    subject = build_email_subject(incident, update)
    body = build_email_body(incident, update, components)
    subscribers = db.execute(
        "SELECT id, email FROM subscribers WHERE active = 1 ORDER BY id"
    ).fetchall()
    for subscriber in subscribers:
        db.execute(
            """
            INSERT INTO email_deliveries (
                incident_update_id,
                subscriber_id,
                recipient_email,
                subject,
                body,
                status,
                attempts
            )
            VALUES (?, ?, ?, ?, ?, 'pending', 0)
            """,
            (update["id"], subscriber["id"], subscriber["email"], subject, body),
        )


def add_subscriber(db, email, label, username):
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("valid email is required")
    username = (username or "").strip() or "system"
    now = utc_now()
    db.execute(
        """
        INSERT INTO subscribers (email, label, active, created_by, created_at, updated_at)
        VALUES (?, ?, 1, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
            label = excluded.label,
            active = 1,
            updated_at = excluded.updated_at
        """,
        (email, (label or "").strip(), username, now, now),
    )
    db.commit()
    return row_to_dict(db.execute("SELECT * FROM subscribers WHERE email = ?", (email,)).fetchone())


def update_subscriber(db, subscriber_id, data, username):
    subscriber = db.execute("SELECT * FROM subscribers WHERE id = ?", (subscriber_id,)).fetchone()
    if subscriber is None:
        raise ValueError("subscriber not found")
    fields = ["updated_at = ?"]
    values = [utc_now()]
    if "active" in data:
        fields.append("active = ?")
        values.append(1 if data.get("active") else 0)
    if "label" in data:
        fields.append("label = ?")
        values.append((data.get("label") or "").strip())
    values.append(subscriber_id)
    db.execute(
        f"UPDATE subscribers SET {', '.join(fields)} WHERE id = ?",
        values,
    )
    db.commit()
    return row_to_dict(db.execute("SELECT * FROM subscribers WHERE id = ?", (subscriber_id,)).fetchone())


SMTP_SETTING_KEYS = {"host", "port", "tls", "username", "password", "email_from"}


def _statuspage_settings(db):
    rows = db.execute("SELECT key, value FROM statuspage_settings").fetchall()
    return {row["key"]: row["value"] for row in rows}


def _bool_text(value):
    return "true" if value else "false"


def _smtp_settings_response(settings):
    password = settings.get("password", "")
    return {
        "host": settings.get("host", ""),
        "port": int(settings.get("port") or 25),
        "tls": settings.get("tls", "").strip().lower() in {"true", "1", "yes"},
        "username": settings.get("username", ""),
        "password": "",
        "password_set": bool(password),
        "email_from": settings.get("email_from", ""),
    }


def get_smtp_settings(db):
    return _smtp_settings_response(_statuspage_settings(db))


def update_smtp_settings(db, data, username):
    username = (username or "").strip() or "system"
    current = _statuspage_settings(db)
    next_settings = dict(current)
    if "host" in data:
        next_settings["host"] = (data.get("host") or "").strip()
    if "port" in data:
        try:
            port = int(data.get("port") or 25)
        except (TypeError, ValueError):
            raise ValueError("port must be a number")
        if port < 1 or port > 65535:
            raise ValueError("port must be between 1 and 65535")
        next_settings["port"] = str(port)
    if "tls" in data:
        next_settings["tls"] = _bool_text(bool(data.get("tls")))
    if "username" in data:
        next_settings["username"] = (data.get("username") or "").strip()
    if "password" in data and data.get("password"):
        next_settings["password"] = str(data.get("password"))
    if data.get("clear_password"):
        next_settings["password"] = ""
    if "email_from" in data:
        email_from = (data.get("email_from") or "").strip()
        if email_from and "@" not in email_from:
            raise ValueError("email_from must be a valid email address")
        next_settings["email_from"] = email_from

    now = utc_now()
    for key in SMTP_SETTING_KEYS:
        db.execute(
            """
            INSERT INTO statuspage_settings (key, value, updated_by, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            """,
            (key, next_settings.get(key, ""), username, now),
        )
    db.commit()
    return get_smtp_settings(db)


def _effective_smtp_config(db):
    settings = _statuspage_settings(db)
    return {
        "host": settings.get("host") or os.environ.get("STATUSPAGE_SMTP_HOST", ""),
        "port": int(settings.get("port") or os.environ.get("STATUSPAGE_SMTP_PORT", "25")),
        "tls": (settings.get("tls") or os.environ.get("STATUSPAGE_SMTP_TLS", "")).strip().lower() in {"true", "1", "yes"},
        "username": settings.get("username") or os.environ.get("STATUSPAGE_SMTP_USERNAME", ""),
        "password": settings.get("password") or os.environ.get("STATUSPAGE_SMTP_PASSWORD", ""),
        "email_from": settings.get("email_from") or os.environ.get("STATUSPAGE_EMAIL_FROM", ""),
    }


def smtp_configured(db):
    config = _effective_smtp_config(db)
    return bool(config["host"] and config["email_from"])


def send_delivery(db, delivery):
    if not smtp_configured(db):
        raise RuntimeError("SMTP is not configured")

    config = _effective_smtp_config(db)
    host = config["host"]
    port = config["port"]
    sender = config["email_from"]
    username = config["username"]
    password = config["password"]

    message = EmailMessage()
    message["From"] = sender
    message["To"] = delivery["recipient_email"]
    message["Subject"] = delivery["subject"]
    message.set_content(delivery["body"])

    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if config["tls"]:
            smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(message)


def send_pending_deliveries(db, delivery_id=None):
    if delivery_id is None:
        deliveries = db.execute(
            """
            SELECT *
            FROM email_deliveries
            WHERE status IN ('pending', 'failed')
            ORDER BY id
            """
        ).fetchall()
    else:
        deliveries = db.execute(
            "SELECT * FROM email_deliveries WHERE id = ?",
            (delivery_id,),
        ).fetchall()

    result = {"sent": 0, "failed": 0}
    for delivery in deliveries:
        now = utc_now()
        db.execute(
            """
            UPDATE email_deliveries
            SET attempts = attempts + 1,
                updated_at = ?
            WHERE id = ?
            """,
            (now, delivery["id"]),
        )
        updated_delivery = db.execute(
            "SELECT * FROM email_deliveries WHERE id = ?",
            (delivery["id"],),
        ).fetchone()
        try:
            send_delivery(db, updated_delivery)
            sent_at = utc_now()
            db.execute(
                """
                UPDATE email_deliveries
                SET status = 'sent',
                    sent_at = ?,
                    last_error = '',
                    updated_at = ?
                WHERE id = ?
                """,
                (sent_at, sent_at, delivery["id"]),
            )
            result["sent"] += 1
        except Exception as exc:
            failed_at = utc_now()
            db.execute(
                """
                UPDATE email_deliveries
                SET status = 'failed',
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (str(exc), failed_at, delivery["id"]),
            )
            result["failed"] += 1
        db.commit()
    return result


def list_email_deliveries(db):
    rows = db.execute(
        """
        SELECT *
        FROM email_deliveries
        ORDER BY created_at DESC, id DESC
        LIMIT 200
        """
    ).fetchall()
    return [row_to_dict(row) for row in rows]


def list_subscribers(db):
    rows = db.execute(
        """
        SELECT *
        FROM subscribers
        ORDER BY active DESC, email
        """
    ).fetchall()
    return [row_to_dict(row) for row in rows]


def create_incident(db, data, username):
    title = _require_text(data, "title")
    body = _require_text(data, "body")
    status = _validate_choice(_require_text(data, "status"), VALID_INCIDENT_STATUSES, "status")
    impact = _validate_choice(_require_text(data, "impact"), VALID_IMPACTS, "impact")
    username = (username or "").strip() or "system"
    now = utc_now()
    try:
        cursor = db.execute(
            """
            INSERT INTO incidents (title, status, impact, created_by, created_at, updated_at, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (title, status, impact, username, now, now, now if status == "resolved" else None),
        )
        incident_id = cursor.lastrowid
        update_cursor = db.execute(
            """
            INSERT INTO incident_updates (
                incident_id,
                status,
                body,
                created_by,
                created_at,
                email_required
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (incident_id, status, body, username, now, 1 if data.get("notify") else 0),
        )
        update_id = update_cursor.lastrowid

        for component in data.get("components") or []:
            component_id = component.get("component_id")
            component_status = _validate_choice(
                _require_text(component, "status"),
                VALID_COMPONENT_STATUSES,
                "component status",
            )
            existing = db.execute("SELECT id FROM components WHERE id = ?", (component_id,)).fetchone()
            if existing is None:
                raise ValueError(f"component_id does not exist: {component_id}")
            db.execute(
                """
                INSERT INTO incident_components (incident_id, component_id, component_status)
                VALUES (?, ?, ?)
                """,
                (incident_id, component_id, component_status),
            )
            db.execute(
                "UPDATE components SET status = ?, updated_at = ? WHERE id = ?",
                (component_status, now, component_id),
            )

        incident = row_to_dict(db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
        update = row_to_dict(db.execute("SELECT * FROM incident_updates WHERE id = ?", (update_id,)).fetchone())
        components = list_incident_components(db, incident_id)
        if data.get("notify"):
            enqueue_email_deliveries(db, incident, update, components)
        db.commit()
        return {"incident": incident, "update": update, "components": components}
    except Exception:
        db.rollback()
        raise


def append_incident_update(db, incident_id, data, username):
    body = _require_text(data, "body")
    status = _validate_choice(_require_text(data, "status"), VALID_INCIDENT_STATUSES, "status")
    username = (username or "").strip() or "system"
    incident = db.execute(
        "SELECT * FROM incidents WHERE id = ? AND is_deleted = 0",
        (incident_id,),
    ).fetchone()
    if incident is None:
        raise ValueError("incident not found")

    now = utc_now()
    try:
        db.execute(
            """
            UPDATE incidents
            SET status = ?,
                updated_at = ?,
                resolved_at = CASE WHEN ? = 'resolved' THEN COALESCE(resolved_at, ?) ELSE resolved_at END
            WHERE id = ?
            """,
            (status, now, status, now, incident_id),
        )
        cursor = db.execute(
            """
            INSERT INTO incident_updates (
                incident_id,
                status,
                body,
                created_by,
                created_at,
                email_required
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (incident_id, status, body, username, now, 1 if data.get("notify") else 0),
        )
        update_id = cursor.lastrowid
        if "components" in data:
            db.execute("DELETE FROM incident_components WHERE incident_id = ?", (incident_id,))
            for component in data.get("components") or []:
                component_id = component.get("component_id")
                component_status = _validate_choice(
                    _require_text(component, "status"),
                    VALID_COMPONENT_STATUSES,
                    "component status",
                )
                existing = db.execute("SELECT id FROM components WHERE id = ? AND active = 1", (component_id,)).fetchone()
                if existing is None:
                    raise ValueError(f"component_id does not exist: {component_id}")
                db.execute(
                    """
                    INSERT INTO incident_components (incident_id, component_id, component_status)
                    VALUES (?, ?, ?)
                    """,
                    (incident_id, component_id, component_status),
                )
                db.execute(
                    "UPDATE components SET status = ?, updated_at = ? WHERE id = ?",
                    (component_status, now, component_id),
                )
        updated_incident = row_to_dict(db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
        update = row_to_dict(db.execute("SELECT * FROM incident_updates WHERE id = ?", (update_id,)).fetchone())
        components = list_incident_components(db, incident_id)
        if data.get("notify"):
            enqueue_email_deliveries(db, updated_incident, update, components)
        db.commit()
        return {"incident": updated_incident, "update": update, "components": components}
    except Exception:
        db.rollback()
        raise


class StatuspageHandler(BaseHTTPRequestHandler):
    db = None

    def _json(self, status, data):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def _username(self):
        return get_username_from_headers(self.headers)

    def _require_username(self):
        username = self._username()
        if not username:
            self._json(401, {"error": "unauthorized"})
            return None
        return username

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/statuspage/summary":
            self._json(200, build_summary(self.db))
            return
        if path == "/api/statuspage/components":
            if not self._require_username():
                return
            self._json(200, list_components(self.db))
            return
        if path == "/api/statuspage/component-groups":
            if not self._require_username():
                return
            self._json(200, list_component_groups(self.db))
            return
        if path == "/api/statuspage/subscribers":
            if not self._require_username():
                return
            self._json(200, list_subscribers(self.db))
            return
        if path == "/api/statuspage/email-deliveries":
            if not self._require_username():
                return
            self._json(200, list_email_deliveries(self.db))
            return
        if path == "/api/statuspage/settings/smtp":
            if not self._require_username():
                return
            self._json(200, get_smtp_settings(self.db))
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        parts = path.strip("/").split("/")
        if path not in {"/api/statuspage/incidents", "/api/statuspage/subscribers", "/api/statuspage/components", "/api/statuspage/component-groups"}:
            if len(parts) != 5 or parts[:3] != ["api", "statuspage", "incidents"] or parts[4] != "updates":
                if len(parts) != 5 or parts[:3] != ["api", "statuspage", "email-deliveries"] or parts[4] != "retry":
                    self._json(404, {"error": "not found"})
                    return

        username = self._require_username()
        if not username:
            return

        try:
            if path == "/api/statuspage/incidents":
                created = create_incident(self.db, self._read_json(), username)
                created["email"] = send_pending_deliveries(self.db)
                self._json(201, created)
                return
            if path == "/api/statuspage/subscribers":
                data = self._read_json()
                subscriber = add_subscriber(self.db, data.get("email"), data.get("label", ""), username)
                self._json(201, subscriber)
                return
            if path == "/api/statuspage/components":
                component = upsert_component(self.db, self._read_json(), username)
                self._json(201, component)
                return
            if path == "/api/statuspage/component-groups":
                group = upsert_component_group(self.db, self._read_json(), username)
                self._json(201, group)
                return
            if len(parts) == 5 and parts[:3] == ["api", "statuspage", "incidents"] and parts[4] == "updates":
                updated = append_incident_update(self.db, int(parts[3]), self._read_json(), username)
                updated["email"] = send_pending_deliveries(self.db)
                self._json(201, updated)
                return
            if len(parts) == 5 and parts[:3] == ["api", "statuspage", "email-deliveries"] and parts[4] == "retry":
                result = send_pending_deliveries(self.db, int(parts[3]))
                self._json(200, result)
                return
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})

    def do_PATCH(self):
        path = urlparse(self.path).path
        parts = path.strip("/").split("/")
        resource = statuspage_resource(parts)
        if path != "/api/statuspage/settings/smtp" and (
            len(parts) != 4 or parts[:2] != ["api", "statuspage"] or resource not in {"subscribers", "components", "component-groups"}
        ):
            self._json(404, {"error": "not found"})
            return

        username = self._require_username()
        if not username:
            return

        try:
            if path == "/api/statuspage/settings/smtp":
                settings = update_smtp_settings(self.db, self._read_json(), username)
                self._json(200, settings)
                return
            if resource == "subscribers":
                subscriber = update_subscriber(self.db, int(parts[3]), self._read_json(), username)
                self._json(200, subscriber)
                return
            data = self._read_json()
            data["id"] = int(parts[3])
            if resource == "components":
                component = upsert_component(self.db, data, username)
                self._json(200, component)
                return
            group = upsert_component_group(self.db, data, username)
            self._json(200, group)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        parts = path.strip("/").split("/")
        resource = statuspage_resource(parts)
        if len(parts) != 4 or parts[:2] != ["api", "statuspage"] or resource not in {"components", "component-groups"}:
            self._json(404, {"error": "not found"})
            return
        username = self._require_username()
        if not username:
            return
        try:
            if resource == "components":
                remove_component(self.db, int(parts[3]), username)
            else:
                remove_component_group(self.db, int(parts[3]), username)
            self._json(200, {"ok": True})
        except ValueError as exc:
            self._json(400, {"error": str(exc)})


if __name__ == "__main__":
    StatuspageHandler.db = init_db()
    server = ThreadingHTTPServer(("", API_PORT), StatuspageHandler)
    log.info("statuspage-api listening on %s", API_PORT)
    server.serve_forever()
