"""HTTP API for NOC Escalation Bot — config, status, activity log, and log buffer."""

import json
import logging
import os
import threading
import time
import traceback
from collections import deque
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)

CONFIG_PATH = os.environ.get("NOC_BOT_CONFIG_PATH", "/data/config.json")
API_PORT = int(os.environ.get("NOC_BOT_API_PORT", "8095"))

DEFAULT_CONFIG = {
    "enabled": True,
    "escalation_enabled": True,
    "cr_summary_enabled": True,
    "ollama_model": "qwen2.5:32b",
    "test_mode_enabled": False,
    "test_channels": [],
    "test_mode_live_grafana": False,
    "ticket_reaction_enabled": True,
    "ticket_any_channel": False,
    "change_tracker_enabled": True,
    "change_tracker_channel_id": "",
    "noc_turnover_enabled": True,
    "noc_turnover_channel_id": "",
    "noc_turnover_ack_threshold_min": 15,
    # Escalation classifier (see docs/superpowers/specs/2026-04-22-escalation-classifier-design.md)
    "escalation_classifier_enabled": False,
    "escalation_classifier_wait_window_sec": 60,
    "escalation_classifier_ollama_model": "",  # empty = fall back to ollama_model
    # P3: untagged-incident detection. Two-stage flag:
    #   p3_enabled=False                 — classifier does not run at all
    #   p3_enabled=True, live=False      — shadow mode (log verdicts only)
    #   p3_enabled=True, live=True       — post prompts
    # Startup guard in bot.py forces live=False if enabled=False.
    "p3_enabled": False,
    "p3_live_mode": False,
    "p3_prompt_ttl_sec": 900,  # 15 min — spec §"Goal"
    # Incident questionnaire (Phase 1).
    #   enabled=False — triggers no-op; no post, no sweep entry, no LLM
    #   ttl_sec       — sweep auto-close horizon (seconds), range [60, 604800]
    #   resolution_detector_enabled — gates LLM auto-close on thread replies
    "incident_questionnaire_enabled": False,
    "incident_questionnaire_ttl_sec": 86400,
    "incident_resolution_detector_enabled": False,
    # Incident channel spawner (Phase 2).
    #   incident_channel_enabled=False       — entry is a no-op
    #   enabled=True, live_mode=False        — dry-run; posts notice only
    #   enabled=True, live_mode=True         — actually creates channel
    "incident_channel_enabled": False,
    "incident_channel_live_mode": False,
    "incident_channel_archive_ttl_sec": 604800,
}


class BotConfig:
    """Thread-safe, file-backed configuration store."""

    def __init__(self, path: str = CONFIG_PATH):
        self._path = path
        self._lock = threading.Lock()
        self._config = dict(DEFAULT_CONFIG)
        self._load()

    def _load(self):
        try:
            with open(self._path) as f:
                saved = json.load(f)
            self._config.update(saved)
            logger.info("Loaded config from %s", self._path)
        except FileNotFoundError:
            logger.info("No config file at %s, using defaults", self._path)
            self._save()
        except Exception:
            logger.warning("Failed to load config from %s, using defaults", self._path, exc_info=True)

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(self._path, "w") as f:
                json.dump(self._config, f, indent=2)
        except Exception:
            logger.warning("Failed to save config to %s", self._path, exc_info=True)

    def get_all(self) -> dict:
        with self._lock:
            return dict(self._config)

    def update(self, updates: dict) -> dict:
        with self._lock:
            for key, value in updates.items():
                if key in DEFAULT_CONFIG:
                    # Bounds check for ack threshold — reject out-of-range values.
                    if key == "noc_turnover_ack_threshold_min":
                        if not (isinstance(value, int) and 1 <= value <= 120):
                            continue
                        self._config[key] = value
                        continue
                    if key == "incident_questionnaire_ttl_sec":
                        if not (isinstance(value, int) and 60 <= value <= 604800):
                            continue
                        self._config[key] = value
                        continue
                    if key == "incident_channel_archive_ttl_sec":
                        if not (isinstance(value, int) and 3600 <= value <= 2592000):
                            continue
                        self._config[key] = value
                        continue
                    expected_type = type(DEFAULT_CONFIG[key])
                    if isinstance(value, expected_type):
                        self._config[key] = value
                    # Allow list of strings for list-type keys
                    elif expected_type is list and isinstance(value, list):
                        self._config[key] = [str(v) for v in value]
            self._save()
            return dict(self._config)


class ActivityLog:
    """Thread-safe ring buffer for recent bot activity."""

    def __init__(self, maxlen: int = 200):
        self._entries = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, action: str, detail: str, user: str = "", cr_key: str = "", ticket_key: str = ""):
        entry = {
            "ts": time.time(),
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            "action": action,
            "detail": detail,
            "user": user,
            "cr_key": cr_key,
            "ticket_key": ticket_key,
        }
        with self._lock:
            self._entries.appendleft(entry)

    def recent(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self._entries)[:limit]


class LogBuffer(logging.Handler):
    """Logging handler that keeps the last N records in memory for the API."""

    def __init__(self, maxlen: int = 500):
        super().__init__()
        self._entries = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord):
        entry = {
            "ts": record.created,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["traceback"] = "".join(traceback.format_exception(*record.exc_info)).strip()
        with self._lock:
            self._entries.appendleft(entry)

    def recent(self, limit: int = 100, level: str = "") -> list[dict]:
        with self._lock:
            entries = list(self._entries)
        if level:
            entries = [e for e in entries if e["level"] == level.upper()]
        return entries[:limit]


# Module-level singletons
config = BotConfig()
activity = ActivityLog()
log_buffer = LogBuffer()
_bot_start_time = time.time()
_handler_ref = None  # Set to MessageHandler instance for status queries
_change_tracker_ref = None
_turnover_ref = None


def _et_day_window() -> tuple[int, int]:
    """Return (day_start_utc, day_end_utc) epoch seconds for today in America/New_York.

    day_end is `now + 1` (exclusive upper bound — the +1 ensures `now` itself is
    included when callers pass these directly into an inclusive-on-left, exclusive-on-right
    `BETWEEN`-style query).
    """
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo
    _ET = ZoneInfo("America/New_York")
    now = datetime.now(timezone.utc)
    et_day_start = now.astimezone(_ET).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).astimezone(timezone.utc)
    return int(et_day_start.timestamp()), int(now.timestamp()) + 1


def init(handler=None, change_tracker=None, turnover_coordinator=None):
    """Wire up refs, install log buffer, and reset uptime."""
    global _handler_ref, _change_tracker_ref, _turnover_ref, _bot_start_time
    _handler_ref = handler
    _change_tracker_ref = change_tracker
    _turnover_ref = turnover_coordinator
    _bot_start_time = time.time()
    root = logging.getLogger()
    root.addHandler(log_buffer)


class APIHandler(BaseHTTPRequestHandler):
    """Handles GET/POST for /status, /config, /activity."""

    def log_message(self, format, *args):
        logger.debug("API %s", format % args)

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    def _route(self):
        from urllib.parse import urlparse
        # Strip query string, then /api/noc-bot prefix if nginx proxied
        path = urlparse(self.path).path.rstrip("/")
        if path.startswith("/api/noc-bot"):
            path = path[len("/api/noc-bot"):]
        return path or "/status"

    def do_GET(self):
        path = self._route()

        if path == "/status":
            handler = _handler_ref
            status = {
                "ok": True,
                "uptime_seconds": int(time.time() - _bot_start_time),
                "config": config.get_all(),
                "channel_id": handler.channel_id if handler else "",
                "group_ids": handler.group_ids if handler else [],
                "dedup_cache_size": len(handler._seen_messages) if handler else 0,
                "change_tracker": _change_tracker_ref.snapshot() if _change_tracker_ref else None,
                "noc_turnover": _turnover_ref.snapshot() if _turnover_ref else None,
            }
            self._send_json(status)

        elif path == "/config":
            self._send_json(config.get_all())

        elif path == "/activity":
            entries = activity.recent(100)
            self._send_json({"entries": entries})

        elif path == "/logs":
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            level = qs.get("level", [""])[0]
            limit = int(qs.get("limit", ["200"])[0])
            entries = log_buffer.recent(limit=limit, level=level)
            self._send_json({"entries": entries})

        elif path == "/ongoing":
            if _turnover_ref is None:
                self._send_json({"error": "turnover not initialized"}, 503)
                return
            try:
                store = _turnover_ref.store
                day_start, day_end = _et_day_window()
                today = store.get_incidents_in_window(day_start, day_end)
                open_now = store.get_open_incidents()
                closed_today = [i for i in today if i.resolved_at is not None]

                def row(inc):
                    return {
                        "slack_ts": inc.slack_ts,
                        "posted_at": inc.posted_at,
                        "poster_user_id": inc.poster_user_id,
                        "text_preview": inc.text_preview,
                        "permalink": inc.permalink,
                        "occir_key": inc.occir_key,
                        "occir_status": inc.occir_status,
                        "reply_count": inc.reply_count,
                        "unique_responder_count": store.unique_responder_count(inc.slack_ts),
                        "first_reply_at": inc.first_reply_at,
                        "resolved_at": inc.resolved_at,
                        "resolved_source": inc.resolved_source,
                        "mttr_seconds": (inc.resolved_at - inc.posted_at) if inc.resolved_at else None,
                        "claimed_by_user_id": getattr(inc, "claimed_by_user_id", None),
                    }

                from turnover_metrics import compute_metrics
                metrics = compute_metrics(
                    today, day_start, day_end,
                    threshold_minutes=int(config.get_all().get("noc_turnover_ack_threshold_min", 15)),
                )
                self._send_json({
                    "open": [row(i) for i in open_now],
                    "closed_today": [row(i) for i in closed_today],
                    "metrics": metrics,
                })
            except Exception as e:
                logger.exception("api /ongoing failed")
                self._send_json({"error": str(e)}, 500)

        elif path == "/metrics":
            if _turnover_ref is None:
                self._send_json({"error": "turnover not initialized"}, 503)
                return
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            window = qs.get("window", ["today"])[0]
            if window != "today":
                self._send_json({"error": "only window=today supported"}, 400)
                return
            try:
                day_start, day_end = _et_day_window()
                from turnover_metrics import compute_metrics
                rows = _turnover_ref.store.get_incidents_in_window(day_start, day_end)
                metrics = compute_metrics(
                    rows, day_start, day_end,
                    threshold_minutes=int(config.get_all().get("noc_turnover_ack_threshold_min", 15)),
                )
                metrics["window"] = "today"
                self._send_json(metrics)
            except Exception as e:
                logger.exception("api /metrics failed")
                self._send_json({"error": str(e)}, 500)

        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = self._route()

        if path == "/config":
            try:
                body = self._read_body()
                updated = config.update(body)
                activity.add("config_change", json.dumps(body))
                self._send_json(updated)
            except Exception as e:
                self._send_json({"error": str(e)}, 400)

        elif path == "/turnover/refresh":
            if _turnover_ref is None:
                self._send_json({"error": "turnover not initialized"}, 503)
                return
            try:
                result = _turnover_ref.refresh_now()
                activity.add("turnover_manual_refresh", json.dumps(result))
                self._send_json({"ok": True, **result})
            except Exception as e:
                logger.exception("api /turnover/refresh failed")
                self._send_json({"error": str(e)}, 500)

        elif path.startswith("/incident/") and path.endswith("/resolve"):
            if _turnover_ref is None:
                self._send_json({"error": "turnover not initialized"}, 503)
                return
            slack_ts = path[len("/incident/"):-len("/resolve")]
            if not slack_ts:
                self._send_json({"error": "missing slack_ts"}, 400)
                return
            try:
                body = self._read_body()
                user = body.get("user", "manual:unknown")
                existing = _turnover_ref.store.get_incident(slack_ts)
                if existing is None:
                    self._send_json({"error": "incident not found"}, 404)
                    return
                if existing.resolved_at is not None:
                    self._send_json({
                        "ok": True, "resolved_at": existing.resolved_at,
                        "source": existing.resolved_source, "already": True,
                    }, 409)
                    return
                was_new = _turnover_ref.resolver.mark_resolved(
                    slack_ts, source="manual", by_user_id=user,
                )
                activity.add("turnover_manual_resolve", f"{slack_ts} by {user}", user=user)
                inc = _turnover_ref.store.get_incident(slack_ts)
                self._send_json({"ok": was_new, "resolved_at": inc.resolved_at,
                                  "source": inc.resolved_source})
            except Exception as e:
                logger.exception("api /incident/<ts>/resolve failed")
                self._send_json({"error": str(e)}, 500)

        else:
            self._send_json({"error": "not found"}, 404)


def start_api_server():
    """Start the HTTP API server in a daemon thread."""
    server = HTTPServer(("0.0.0.0", API_PORT), APIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("NOC Bot API listening on port %d", API_PORT)
