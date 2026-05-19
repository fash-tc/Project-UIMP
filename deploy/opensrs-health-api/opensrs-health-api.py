"""OpenSRS E2E health report API.

Manual, log-derived health reports only. This service queries Grafana/Loki with
fixed allowlisted templates and may ask an OpenAI-compatible AI endpoint to summarize the compact
evidence. It never calls OpenSRS endpoints or performs OpenSRS mutations.
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import re
import sqlite3
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("opensrs-health-api")

API_PORT = int(os.environ.get("API_PORT", "8095"))
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")
DB_PATH = os.environ.get("DB_PATH", "/data/opensrs-health.db")
GRAFANA_URL = os.environ.get("GRAFANA_URL", "")
GRAFANA_USER = os.environ.get("GRAFANA_USER", "")
GRAFANA_PASS = os.environ.get("GRAFANA_PASS", "")
LOKI_DS_ID = os.environ.get("LOKI_DATASOURCE_ID", os.environ.get("LOKI_DS_ID", "17"))
AI_API_BASE = os.environ.get("AI_API_BASE", os.environ.get("OPENAI_API_BASE", "")).rstrip("/")
AI_MODEL = os.environ.get("AI_MODEL", os.environ.get("OPENAI_MODEL", "qwen-assistant:latest"))
AI_API_KEY = os.environ.get("AI_API_KEY", os.environ.get("OPENAI_API_KEY", ""))
AI_MAX_TOKENS = int(os.environ.get("AI_MAX_TOKENS", "4096"))
MAX_ENTRIES_PER_QUERY = int(os.environ.get("MAX_ENTRIES_PER_QUERY", "1000"))
MAX_SAMPLES_PER_LANE = int(os.environ.get("MAX_SAMPLES_PER_LANE", "10"))
MAX_LOG_ANALYSIS_ENTRIES = int(os.environ.get("MAX_LOG_ANALYSIS_ENTRIES", "200"))
SLOW_MS = int(os.environ.get("SLOW_MS", "5000"))
COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "60"))
REPORT_RETENTION = int(os.environ.get("REPORT_RETENTION", "100"))
ALLOWED_WINDOWS = {900, 3600, 21600, 86400}

EVIDENCE_LANES = [
    {
        "id": "synthetic",
        "label": "Synthetic Monitoring",
        "query": '{app=~"front|ra"} |= "srsopsmonitoring"',
        "parser": "parse_synthetic_lane",
    },
    {
        "id": "api",
        "label": "API",
        "query": '{app="front"} |~ "(?i)response_code|status|Read error|Exception|timeout|slow|total=|latency|duration|action:"',
        "parser": "parse_api_lane",
    },
    {
        "id": "registry",
        "label": "Registry",
        "query": '{app=~"ra|registry-agent|opensrs"} |~ "registry|registrar|epp|timeout|result code"',
        "parser": "parse_registry_lane",
    },
    {
        "id": "events",
        "label": "Events",
        "query": '{app=~"front|ra"} |~ "(?i)incident|error|exception|timeout|degraded|fail|unavailable|refused|reset|slow"',
        "parser": "parse_events_lane",
    },
]

LOG_ANALYSIS_QUERY_TEMPLATES = [
    {
        "id": "registry_timing",
        "label": "Registry timing",
        "query": '{app="ra"} |~ "total="',
        "intents": {"latency", "registry", "tld"},
    },
    {
        "id": "registry_errors",
        "label": "Registry errors",
        "query": '{app=~"ra|registry-agent|opensrs"} |~ "(?i)error|exception|timeout|fail|result code|unavailable|refused|reset"',
        "intents": {"error", "registry", "tld"},
    },
    {
        "id": "api_errors",
        "label": "API errors",
        "query": '{app="front"} |~ "(?i)response_code|status|Read error|Exception|timeout|fail|error|unavailable|refused|reset"',
        "intents": {"error", "api"},
    },
    {
        "id": "synthetic_monitoring",
        "label": "Synthetic monitoring",
        "query": '{app=~"front|ra"} |= "srsopsmonitoring"',
        "intents": {"synthetic", "monitoring"},
    },
    {
        "id": "opensrs_events",
        "label": "OpenSRS events",
        "query": '{app=~"front|ra"} |~ "(?i)incident|error|exception|timeout|degraded|fail|unavailable|refused|reset|slow|total="',
        "intents": {"error", "latency", "api", "registry", "events"},
    },
]

db = None
_db_lock = threading.Lock()
_cooldown_lock = threading.Lock()
_last_run_at = 0.0
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

_DURATION_RE = re.compile(r"(?:duration|latency|total|elapsed)[=\s:]+(\d+(?:\.\d+)?)\s*ms", re.I)
_TEXT_STATUS_RE = re.compile(r"\bstatus[=\s:]+(ok|fail|failed|error|timeout)\b", re.I)
_HTTP_STATUS_RE = re.compile(
    r"\b(?:http_status|response_code|status)[=\s:>\"]+([1-5]\d{2})\b|HTTP/\d(?:\.\d)?\"\s+([1-5]\d{2})\b",
    re.I,
)
_EPP_CODE_RE = re.compile(r"\b(?:epp[_\s-]?code|result\s+code|result_code|code)[=\s:\"]+([12]\d{3})\b", re.I)
_TIMEOUT_RE = re.compile(r"\b(?:timeout|timed out|deadline exceeded)\b", re.I)
_FAILURE_RE = re.compile(r"\b(?:fail|failed|failure|error|exception|unavailable|refused|reset)\b", re.I)
_BUSINESS_REJECTION_RE = re.compile(
    r"(?:result\s+code=['\"]?2201|code=['\"]?2201|authorization error|maximum daily connection limit|lookup refused)",
    re.I,
)
_ACTION_RE = re.compile(
    r"(?:action:\[([A-Z0-9_:-]+)\]|action[=\s:\"]+([A-Z0-9_:-]+)|object:\[([A-Z0-9_:-]+)\])",
    re.I,
)
_TLD_FIELD_RE = re.compile(r"(?:\b|_)(?:tld)[\"']?\s*(?:=>|=|:)\s*[\"']?((?:\.[A-Za-z0-9-]+)+|[A-Za-z0-9-]+)", re.I)
_DOMAIN_FIELD_RE = re.compile(
    r"(?:domainname|domain_name|domain|target)[\"']?\s*(?:=>|=|:)\s*[\"']?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)",
    re.I,
)
_XML_DOMAIN_RE = re.compile(r"<domain:name>\s*([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\s*</domain:name>", re.I)


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_window(value):
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value if value in ALLOWED_WINDOWS else None


def _health_runs_columns(conn):
    return {row[1] for row in conn.execute("PRAGMA table_info(health_runs)").fetchall()}


def _create_health_runs_table(conn, table_name="health_runs"):
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT UNIQUE NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            requested_by TEXT,
            window_seconds INTEGER NOT NULL,
            overall TEXT NOT NULL,
            report_json TEXT NOT NULL,
            error TEXT
        )
        """
    )


def _migrate_health_runs_schema(conn):
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'health_runs'"
    ).fetchone()
    if not exists:
        _create_health_runs_table(conn)
        return
    columns = _health_runs_columns(conn)
    required = {
        "id",
        "run_id",
        "started_at",
        "completed_at",
        "requested_by",
        "window_seconds",
        "overall",
        "report_json",
        "error",
    }
    if required.issubset(columns):
        return
    legacy_table = f"health_runs_legacy_{int(time.time())}"
    conn.execute(f"ALTER TABLE health_runs RENAME TO {legacy_table}")
    _create_health_runs_table(conn)
    shared = [
        name
        for name in (
            "run_id",
            "started_at",
            "completed_at",
            "requested_by",
            "window_seconds",
            "overall",
            "report_json",
            "error",
        )
        if name in columns
    ]
    if shared:
        names = ", ".join(shared)
        conn.execute(
            f"""
            INSERT OR IGNORE INTO health_runs ({names})
            SELECT {names} FROM {legacy_table}
            ORDER BY started_at ASC, run_id ASC
            """
        )
    conn.execute(f"DROP TABLE {legacy_table}")


def init_db(path=None):
    conn = sqlite3.connect(str(path or DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _migrate_health_runs_schema(conn)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_health_runs_started ON health_runs(started_at DESC)")
    conn.commit()
    return conn


def verify_token(token):
    if not AUTH_SECRET:
        return None
    try:
        payload_b64, sig = token.split(".", 1)
        expected = hmac_mod.new(AUTH_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
        if not hmac_mod.compare_digest(sig, expected):
            return None
        padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if payload.get("e", 0) < time.time():
            return None
        return payload.get("u")
    except Exception:
        return None


def _get_username_from_request(handler):
    cookie_header = handler.headers.get("Cookie", "")
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        if key.strip() == "uip_auth":
            return verify_token(value.strip())
    return None


def query_loki(logql, limit=MAX_ENTRIES_PER_QUERY, range_seconds=3600):
    now_ns = int(time.time() * 1e9)
    start_ns = now_ns - int(range_seconds * 1e9)
    params = urlencode(
        {
            "query": logql,
            "start": str(start_ns),
            "end": str(now_ns),
            "limit": str(min(int(limit), MAX_ENTRIES_PER_QUERY)),
            "direction": "backward",
        }
    )
    url = f"{GRAFANA_URL.rstrip('/')}/api/datasources/proxy/{LOKI_DS_ID}/loki/api/v1/query_range?{params}"
    req = Request(url)
    if GRAFANA_USER or GRAFANA_PASS:
        auth = base64.b64encode(f"{GRAFANA_USER}:{GRAFANA_PASS}".encode()).decode()
        req.add_header("Authorization", f"Basic {auth}")
    with urlopen(req, timeout=30, context=_ssl_ctx) as resp:
        return json.loads(resp.read())


def parse_loki_entries(raw_data):
    entries = []
    for stream in (raw_data.get("data") or {}).get("result") or []:
        labels = stream.get("stream") or {}
        for ts_ns, line in stream.get("values") or []:
            try:
                ts_sec = int(ts_ns) / 1e9
                timestamp = datetime.fromtimestamp(ts_sec, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            except (TypeError, ValueError):
                timestamp = utc_now()
            message = line
            parsed = None
            try:
                parsed = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                parsed = None
            if isinstance(parsed, dict):
                message = parsed.get("message") or parsed.get("msg") or parsed.get("MESSAGE") or line
            entries.append({"timestamp": timestamp, "labels": labels, "message": str(message)})
    entries.sort(key=lambda item: item["timestamp"])
    return entries


def extract_durations(entries):
    durations = []
    for item in entries:
        match = _DURATION_RE.search(item.get("message", ""))
        if match:
            durations.append(int(round(float(match.group(1)))))
    return durations


def entry_duration(item):
    match = _DURATION_RE.search(item.get("message", ""))
    if not match:
        return None
    return int(round(float(match.group(1))))


def avg(values):
    return int(round(sum(values) / len(values))) if values else None


def p95(values):
    if not values:
        return None
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * 0.95))
    return ordered[index]


def is_failure(message):
    text = message or ""
    if _BUSINESS_REJECTION_RE.search(text):
        return False
    text_status_match = _TEXT_STATUS_RE.search(text)
    if text_status_match:
        status = text_status_match.group(1).lower()
        if status == "ok":
            return False
        if status in {"fail", "failed", "error", "timeout"}:
            return True
    http_status_match = _HTTP_STATUS_RE.search(text)
    if http_status_match:
        status = int(http_status_match.group(1) or http_status_match.group(2))
        if 200 <= status < 400:
            return False
        if status >= 400:
            return True
    epp_code_match = _EPP_CODE_RE.search(text)
    if epp_code_match:
        code = int(epp_code_match.group(1))
        if code == 1000:
            return False
        if 2000 <= code <= 2999:
            return True
    return bool(_FAILURE_RE.search(text) or _TIMEOUT_RE.search(text))


def extract_action(message):
    match = _ACTION_RE.search(message or "")
    if not match:
        return "unknown"
    return next((group for group in match.groups() if group), "unknown")


def normalize_tld(value):
    text = (value or "").strip().strip("\"'{}[](),;")
    if not text:
        return None
    if "." not in text:
        text = "." + text
    if not re.fullmatch(r"(?:\.[A-Za-z0-9-]+)+", text):
        return None
    return text.lower()


def tld_from_domain(domain):
    text = (domain or "").strip().strip("\"'{}[](),;").lower()
    if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", text):
        return None
    return "." + text.rsplit(".", 1)[-1]


def extract_tld(message):
    text = message or ""
    match = _TLD_FIELD_RE.search(text)
    if match:
        return normalize_tld(match.group(1))
    for pattern in (_DOMAIN_FIELD_RE, _XML_DOMAIN_RE):
        match = pattern.search(text)
        if match:
            return tld_from_domain(match.group(1))
    return None


def tld_group_key(item):
    return extract_tld(item.get("message", "")) or "unknown-tld"


def entry_group_key(item):
    labels = item.get("labels") or {}
    app = labels.get("app") or labels.get("service_name") or "unknown"
    host = labels.get("host") or "unknown-host"
    action = extract_action(item.get("message", ""))
    if action == "unknown":
        action = labels.get("registry_agent") or labels.get("subservice") or labels.get("thread") or "unknown"
    return f"{app}/{host}/{action}"


def issue_type_for_counts(failures, timeouts, slow):
    if int(timeouts or 0) > 0:
        return "timeout"
    if int(slow or 0) > 0:
        return "latency"
    if int(failures or 0) > 0:
        return "error"
    return "none"


def problem_trend(first_half, second_half):
    first_half = int(first_half or 0)
    second_half = int(second_half or 0)
    if first_half == 0 and second_half > 0:
        return "new"
    if second_half > first_half:
        return "increasing"
    if first_half > second_half:
        return "decreasing"
    if first_half or second_half:
        return "steady"
    return "none"


def impact_text(problem_count, total_count):
    if not total_count:
        return "no sampled events"
    return f"{(int(problem_count or 0) / int(total_count)) * 100:.1f}% affected"


def summarize_groups(entries, key_fn, limit=5, sort_by="problems"):
    groups = {}
    split_index = max(1, len(entries) // 2)
    for index, item in enumerate(entries):
        key = key_fn(item)
        duration = entry_duration(item)
        bucket = groups.setdefault(
            key,
            {
                "key": key,
                "events": 0,
                "failures": 0,
                "timeouts": 0,
                "slow": 0,
                "_first_half": 0,
                "_second_half": 0,
                "_durations": [],
                "examples": [],
            },
        )
        message = item.get("message", "")
        failed = is_failure(message)
        timeout = bool(_TIMEOUT_RE.search(message))
        slow = duration is not None and duration >= SLOW_MS
        problem = failed or timeout or slow
        bucket["events"] += 1
        bucket["failures"] += 1 if failed else 0
        bucket["timeouts"] += 1 if timeout else 0
        bucket["slow"] += 1 if slow else 0
        if problem and index < split_index:
            bucket["_first_half"] += 1
        elif problem:
            bucket["_second_half"] += 1
        if duration is not None:
            bucket["_durations"].append(duration)
        if problem and len(bucket["examples"]) < 2:
            bucket["examples"].append(
                {
                    "timestamp": item.get("timestamp"),
                    "message": message[:300],
                }
            )
    summaries = []
    for bucket in groups.values():
        durations = bucket.pop("_durations")
        first_half = bucket.pop("_first_half")
        second_half = bucket.pop("_second_half")
        problem_count = max(int(bucket.get("failures") or 0), int(bucket.get("timeouts") or 0), int(bucket.get("slow") or 0))
        bucket["avg_latency_ms"] = avg(durations)
        bucket["p95_latency_ms"] = p95(durations)
        bucket["issue_type"] = issue_type_for_counts(bucket.get("failures"), bucket.get("timeouts"), bucket.get("slow"))
        bucket["trend"] = problem_trend(first_half, second_half)
        bucket["impact"] = impact_text(problem_count, bucket.get("events"))
        summaries.append(bucket)
    if sort_by == "latency":
        summaries.sort(
            key=lambda item: (
                item.get("p95_latency_ms") if item.get("p95_latency_ms") is not None else -1,
                item.get("avg_latency_ms") if item.get("avg_latency_ms") is not None else -1,
                int(item.get("events") or 0),
            ),
            reverse=True,
        )
    else:
        summaries.sort(
            key=lambda item: (
                int(item.get("failures") or 0) + int(item.get("timeouts") or 0) + int(item.get("slow") or 0),
                int(item.get("events") or 0),
            ),
            reverse=True,
        )
    return summaries[:limit]


def _samples(entries):
    return [
        {
            "timestamp": item.get("timestamp"),
            "message": (item.get("message") or "")[:500],
        }
        for item in entries[:MAX_SAMPLES_PER_LANE]
    ]


def _problem_samples(entries):
    problem_entries = [
        item
        for item in entries
        if is_failure(item.get("message", ""))
        or _TIMEOUT_RE.search(item.get("message", ""))
        or ((entry_duration(item) or 0) >= SLOW_MS)
    ]
    return _samples(problem_entries[:MAX_SAMPLES_PER_LANE])


def question_intents(question):
    text = (question or "").lower()
    intents = set()
    if re.search(r"\b(?:slow|slowest|latency|p95|duration|took|taking)\b", text):
        intents.add("latency")
    if re.search(r"\b(?:error|errors|fail|failure|timeout|exception|unavailable|reset|refused)\b", text):
        intents.add("error")
    if re.search(r"\b(?:tld|registry|epp|registrar|domain)\b", text):
        intents.update({"registry", "tld"})
    if re.search(r"\b(?:api|front|customer|request|lookup)\b", text):
        intents.add("api")
    if re.search(r"\b(?:synthetic|blackbox|srsopsmonitoring|monitoring)\b", text):
        intents.update({"synthetic", "monitoring"})
    if re.search(r"\b(?:event|events|health|holistic|overall)\b", text):
        intents.add("events")
    return intents or {"error", "latency", "api", "registry"}


def score_log_template(template, entries, intents):
    evidence = build_log_evidence(template["query"], entries, 900, include_scope=False)
    intent_match = len(set(template.get("intents") or set()) & set(intents))
    duration_count = sum(1 for item in entries if entry_duration(item) is not None)
    score = len(entries) + (intent_match * 10)
    if "latency" in intents:
        score += duration_count * 8
        if evidence.get("p95_latency_ms") is not None:
            score += min(int(evidence.get("p95_latency_ms") or 0), 5000) / 100
    if "error" in intents:
        score += (int(evidence.get("failures") or 0) + int(evidence.get("timeouts") or 0)) * 12
    if "synthetic" in intents and template["id"] == "synthetic_monitoring":
        score += 25
    return score, evidence


def select_log_analysis_query(question, range_seconds):
    intents = question_intents(question)
    candidates = [
        template
        for template in LOG_ANALYSIS_QUERY_TEMPLATES
        if set(template.get("intents") or set()) & intents
    ] or LOG_ANALYSIS_QUERY_TEMPLATES
    considered = []
    best = None
    for template in candidates:
        try:
            raw = query_loki(template["query"], limit=min(25, MAX_LOG_ANALYSIS_ENTRIES), range_seconds=range_seconds)
            entries = parse_loki_entries(raw)
        except Exception as exc:
            considered.append(
                {
                    "id": template["id"],
                    "label": template["label"],
                    "query": template["query"],
                    "entries": 0,
                    "score": 0,
                    "error": str(exc),
                }
            )
            continue
        score, evidence = score_log_template(template, entries, intents)
        item = {
            "id": template["id"],
            "label": template["label"],
            "query": template["query"],
            "entries": len(entries),
            "failures": evidence.get("failures", 0),
            "timeouts": evidence.get("timeouts", 0),
            "p95_latency_ms": evidence.get("p95_latency_ms"),
            "score": score,
        }
        considered.append(item)
        if best is None or score > best["score"]:
            best = {**item, "template": template}
    if best is None:
        template = LOG_ANALYSIS_QUERY_TEMPLATES[-1]
        best = {
            "id": template["id"],
            "label": template["label"],
            "query": template["query"],
            "entries": 0,
            "score": 0,
            "template": template,
        }
    return best["template"], considered


def empty_lane(lane_id, label):
    return {
        "id": lane_id,
        "label": label,
        "status": "unknown",
        "events": 0,
        "errors": 0,
        "failures": 0,
        "timeouts": 0,
        "slow": 0,
        "avg_latency_ms": None,
        "p95_latency_ms": None,
        "samples": [],
        "problem_samples": [],
        "hotspots": [],
        "top_hosts": [],
    }


def _base_lane(lane_id, label, entries):
    durations = extract_durations(entries)
    timeouts = sum(1 for item in entries if _TIMEOUT_RE.search(item.get("message", "")))
    failures = sum(1 for item in entries if is_failure(item.get("message", "")))
    slow = sum(1 for item in entries if (entry_duration(item) or 0) >= SLOW_MS)
    status = "unknown"
    if entries:
        status = "degraded" if failures or timeouts or slow else "healthy"
    return {
        "id": lane_id,
        "label": label,
        "status": status,
        "events": len(entries),
        "errors": failures,
        "failures": failures,
        "timeouts": timeouts,
        "slow": slow,
        "avg_latency_ms": avg(durations),
        "p95_latency_ms": p95(durations),
        "samples": _samples(entries),
        "problem_samples": _problem_samples(entries),
        "hotspots": summarize_groups(entries, entry_group_key),
        "top_hosts": summarize_groups(entries, lambda item: (item.get("labels") or {}).get("host") or "unknown-host"),
    }


def parse_synthetic_lane(entries):
    lane = _base_lane("synthetic", "Synthetic Monitoring", entries)
    lane["checks"] = len(entries)
    return lane


def parse_api_lane(entries):
    return _base_lane("api", "API", entries)


def parse_registry_lane(entries):
    return _base_lane("registry", "Registry", entries)


def parse_events_lane(entries):
    return _base_lane("events", "Events", entries)


def _minute_bucket(timestamp):
    text = (timestamp or "").replace("+00:00", "Z")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        dt = dt.astimezone(timezone.utc).replace(second=0, microsecond=0)
        return dt.isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def build_timeline_and_correlations(lanes):
    buckets = {}
    for lane in lanes:
        lane_id = lane.get("id")
        for sample in lane.get("samples") or []:
            bucket = _minute_bucket(sample.get("timestamp"))
            if bucket:
                buckets.setdefault(bucket, set()).add(lane_id)
    timeline = [
        {"bucket": bucket, "lanes": sorted(lane_ids)}
        for bucket, lane_ids in sorted(buckets.items())
    ]
    correlations = [
        {"bucket": item["bucket"], "lanes": item["lanes"]}
        for item in timeline
        if len(item["lanes"]) >= 2
    ]
    return timeline, correlations


def split_hotspot_key(key):
    parts = (key or "").split("/", 2)
    return {
        "app": parts[0] if len(parts) > 0 else "unknown",
        "host": parts[1] if len(parts) > 1 else "unknown-host",
        "action": parts[2] if len(parts) > 2 else "unknown",
    }


def build_issue_summary(lanes):
    health_signals = {lane.get("id", lane.get("label", "unknown")): lane.get("status", "unknown") for lane in lanes}
    issues = []
    for lane in lanes:
        events = int(lane.get("events") or 0)
        failures = int(lane.get("failures") or lane.get("errors") or 0)
        timeouts = int(lane.get("timeouts") or 0)
        slow = int(lane.get("slow") or 0)
        problem_count = max(failures, timeouts, slow)
        if not events or problem_count == 0:
            continue
        hotspots = lane.get("hotspots") if isinstance(lane.get("hotspots"), list) else []
        primary_hotspot = hotspots[0] if hotspots else {}
        key = primary_hotspot.get("key") or lane.get("label") or lane.get("id")
        parts = split_hotspot_key(key)
        issue = {
            "lane": lane.get("id"),
            "lane_label": lane.get("label"),
            "type": primary_hotspot.get("issue_type") or issue_type_for_counts(failures, timeouts, slow),
            "severity": "critical" if (problem_count / events) >= 0.25 or timeouts >= 10 else "warning",
            "where": key,
            "host": parts["host"],
            "action": parts["action"],
            "impact": impact_text(problem_count, events),
            "events": events,
            "failures": failures,
            "timeouts": timeouts,
            "slow": slow,
            "p95_latency_ms": lane.get("p95_latency_ms"),
            "trend": primary_hotspot.get("trend", "none"),
            "evidence": (primary_hotspot.get("examples") or lane.get("problem_samples") or [])[:2],
        }
        if issue["type"] == "latency":
            issue["description"] = "Confirmed latency degradation from duration metrics."
        elif issue["type"] == "timeout":
            issue["description"] = "Timeout/read failures in the customer path."
        else:
            issue["description"] = "Error responses or exceptions in sampled logs."
        issues.append(issue)
    issues.sort(
        key=lambda item: (
            {"critical": 2, "warning": 1}.get(item.get("severity"), 0),
            int(item.get("timeouts") or 0) + int(item.get("failures") or 0) + int(item.get("slow") or 0),
        ),
        reverse=True,
    )
    return {
        "has_issue": bool(issues),
        "primary_issue": issues[0] if issues else None,
        "issues": issues[:8],
        "health_signals": health_signals,
    }


def build_report(run_id, started_at, completed_at, window_seconds, lanes, ai_analysis):
    timeline, correlations = build_timeline_and_correlations(lanes)
    issue_summary = build_issue_summary(lanes)
    overall = "degraded" if any(lane.get("status") == "degraded" for lane in lanes) else "healthy"
    if any(lane.get("status") == "unknown" for lane in lanes) and overall == "healthy":
        overall = "unknown"
    return {
        "run_id": run_id,
        "started_at": started_at,
        "completed_at": completed_at,
        "window_seconds": window_seconds,
        "overall": overall,
        "lanes": lanes,
        "issue_summary": issue_summary,
        "timeline": timeline,
        "correlations": correlations,
        "ai_analysis": ai_analysis or {},
    }


def store_report(conn, report, requested_by=None, error=None):
    with _db_lock:
        conn.execute(
            """
            INSERT OR REPLACE INTO health_runs
                (run_id, started_at, completed_at, requested_by, window_seconds, overall, report_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["run_id"],
                report["started_at"],
                report["completed_at"],
                requested_by,
                report["window_seconds"],
                report["overall"],
                json.dumps(report, sort_keys=True),
                error,
            ),
        )
        conn.execute(
            """
            DELETE FROM health_runs
            WHERE run_id NOT IN (
                SELECT run_id FROM health_runs
                ORDER BY started_at DESC, id DESC
                LIMIT ?
            )
            """,
            (REPORT_RETENTION,),
        )
        conn.commit()
    return report


def _row_to_report(row):
    report = json.loads(row["report_json"])
    report["requested_by"] = row["requested_by"]
    if row["error"]:
        report["error"] = row["error"]
    return report


def list_reports(conn):
    rows = conn.execute(
        "SELECT * FROM health_runs ORDER BY started_at DESC, run_id DESC LIMIT ?",
        (REPORT_RETENTION,),
    ).fetchall()
    return [_row_to_report(row) for row in rows]


def get_report(conn, run_id):
    row = conn.execute("SELECT * FROM health_runs WHERE run_id = ?", (run_id,)).fetchone()
    return _row_to_report(row) if row else None


def extract_chat_text(raw):
    choices = raw.get("choices") if isinstance(raw, dict) else None
    first = choices[0] if isinstance(choices, list) and choices else {}
    if isinstance(first, dict):
        message = first.get("message")
        if isinstance(message, dict):
            for key in ("content", "reasoning_content", "reasoning"):
                value = message.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        text = first.get("text")
        if isinstance(text, str) and text.strip():
            return text.strip()
    return ""


def parse_ai_json_or_text(text):
    if not text.strip():
        return {"text": ""}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {"text": text}
    except json.JSONDecodeError:
        return {"text": text}


def ai_text_to_answer(text):
    stripped = (text or "").strip()
    if not stripped:
        return {"answer": "", "raw_format": "empty"}
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return {"answer": stripped, "raw_format": "text"}
    if isinstance(parsed, dict):
        for key in ("answer", "summary", "analysis", "text"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                result = {
                    "answer": value.strip(),
                    "raw_format": "json",
                }
                for extra in ("findings", "problem_areas", "likely_causes", "recommended_sre_actions"):
                    if extra in parsed:
                        result[extra] = parsed[extra]
                return result
    return {"answer": stripped, "raw_format": "text"}


def answer_mentions_evidence(answer, evidence):
    if not answer or not isinstance(answer, str):
        return False
    lowered = answer.lower()
    if evidence.get("entries_analyzed", 0) == 0:
        return True
    areas = evidence.get("problem_areas") if isinstance(evidence, dict) else []
    if isinstance(areas, list):
        for area in areas[:3]:
            key = area.get("key", "") if isinstance(area, dict) else ""
            normalized_key = re.sub(r"[^A-Za-z0-9-]+", " ", key)
            for token in normalized_key.split():
                token = token.strip().lower()
                if len(token) >= 6 and token in lowered:
                    return True
    return False


def answer_is_generic(answer, evidence):
    if not answer:
        return True
    if answer_mentions_evidence(answer, evidence):
        return False
    if len(answer.strip()) < 80:
        return True
    generic_phrases = (
        "check the logs",
        "monitor the system",
        "investigate further",
        "review dashboards",
        "look for errors",
    )
    lowered = answer.lower()
    if any(phrase in lowered for phrase in generic_phrases) and not answer_mentions_evidence(answer, evidence):
        return True
    return not answer_mentions_evidence(answer, evidence)


def tld_answer_matches_evidence(answer, evidence, question):
    if not re.search(r"\b(?:tld|tlds)\b", question or "", re.I):
        return True
    tld_areas = evidence.get("tld_areas") if isinstance(evidence, dict) else []
    if not isinstance(tld_areas, list) or not tld_areas:
        return True
    lowered = (answer or "").lower()
    return any(str(area.get("key", "")).lower() in lowered for area in tld_areas[:3] if isinstance(area, dict))


def answer_echoes_prompt(answer):
    lowered = (answer or "").lower()
    echo_markers = (
        "an sre asked this question",
        "thinking process",
        "analyze the request",
        "constraint check",
        "refinement:",
        "draft:",
        "critique:",
        "(wait,",
        "wait,",
        "the prompt asks",
        "i should",
        "**role:**",
        "**task:**",
        "**constraints:**",
        "i need to",
        "use only this read-only log evidence",
        "current loki log query results",
        '"problem_areas"',
        '"entries_analyzed"',
        '"query"',
        '{"query":',
        "evidence:\n",
    )
    return any(marker in lowered for marker in echo_markers)


def final_answer_only(answer):
    text = (answer or "").strip()
    if not text:
        return ""
    match = re.search(r"(?:final answer|answer)\s*:\s*(.+)$", text, re.I | re.S)
    if match:
        text = match.group(1).strip()
    text = re.sub(r"^\s*(?:[-*]\s*)+\s*", "", text).strip()
    text = re.sub(r"\*\*", "", text).strip()
    cut = re.search(
        r"(?im)^\s*(?:[-*]\s*)?(?:explanation|log example|refinement|constraint check|draft|critique|wait|another constraint)\s*:|\(wait,|the prompt asks|i should",
        text,
    )
    if cut:
        text = text[: cut.start()].strip()
    text = text.replace("`", "").strip()
    return text


def evidence_narrative_answer(evidence, question):
    wants_latency = bool(re.search(r"\b(?:slowest|slow|latency|p95|duration)\b", question or "", re.I))
    wants_tld = bool(re.search(r"\b(?:tld|tlds)\b", question or "", re.I))
    if wants_tld and isinstance(evidence, dict):
        tld_areas = evidence.get("tld_areas") if isinstance(evidence.get("tld_areas"), list) else []
        if wants_latency and tld_areas:
            top_tld = sorted(
                tld_areas,
                key=lambda area: (area.get("p95_latency_ms") if area.get("p95_latency_ms") is not None else area.get("avg_latency_ms") or 0),
                reverse=True,
            )[0]
            latency = top_tld.get("p95_latency_ms") if top_tld.get("p95_latency_ms") is not None else top_tld.get("avg_latency_ms")
            return (
                f"The slowest sampled TLD is {top_tld.get('key', 'unknown TLD')}, with p95/observed latency around {latency} ms. "
                f"Analyzed {evidence.get('entries_analyzed', 0)} log entries. Found {evidence.get('failures', 0)} failures, "
                f"{evidence.get('timeouts', 0)} timeouts, and {evidence.get('slow', 0)} slow entries."
            )
        scope = evidence.get("access_scope") if isinstance(evidence.get("access_scope"), dict) else {}
        considered = scope.get("considered_queries") if isinstance(scope.get("considered_queries"), list) else []
        searched = [item.get("query") for item in considered if isinstance(item, dict) and item.get("query")]
        if not searched and evidence.get("query"):
            searched = [evidence.get("query")]
        searched_text = "; ".join(searched[:4]) if searched else "no query metadata was available"
        return (
            "I could not identify the slowest TLD because the sampled logs had no TLD or domain fields I could parse. "
            f"Logs searched: {searched_text}."
        )
    if wants_latency and isinstance(evidence, dict) and isinstance(evidence.get("latency_areas"), list):
        areas = evidence.get("latency_areas")
    else:
        areas = evidence.get("problem_areas") if isinstance(evidence, dict) else []
    latency_areas = [
        area
        for area in areas
        if isinstance(area, dict) and (area.get("p95_latency_ms") is not None or area.get("avg_latency_ms") is not None)
    ] if isinstance(areas, list) else []
    if wants_latency and latency_areas:
        top = sorted(
            latency_areas,
            key=lambda area: (area.get("p95_latency_ms") if area.get("p95_latency_ms") is not None else area.get("avg_latency_ms") or 0),
            reverse=True,
        )[0]
    else:
        top = areas[0] if isinstance(areas, list) and areas else None
    answer_parts = []
    entries = evidence.get("entries_analyzed", 0)
    failures = evidence.get("failures", 0)
    timeouts = evidence.get("timeouts", 0)
    slow = evidence.get("slow", 0)
    p95_latency_ms = evidence.get("p95_latency_ms")
    answer_parts.append(
        f"Analyzed {entries} log entries. Found {failures} failures, {timeouts} timeouts, and {slow} slow entries."
    )
    if p95_latency_ms is not None:
        answer_parts[-1] += f" P95 latency was {p95_latency_ms} ms."
    if top:
        key = top.get("key", "unknown hotspot")
        has_latency = top.get("p95_latency_ms") is not None or top.get("avg_latency_ms") is not None
        if wants_latency and has_latency:
            latency = top.get("p95_latency_ms") if top.get("p95_latency_ms") is not None else top.get("avg_latency_ms")
            answer_parts.insert(
                0,
                f"The slowest sampled path is {key}, with p95/observed latency around {latency} ms.",
            )
        else:
            answer_parts.append(
                f"Primary problem area is {key}: {top.get('events', 0)} events, "
                f"{top.get('failures', 0)} failures, {top.get('timeouts', 0)} timeouts, "
                f"{top.get('slow', 0)} slow entries."
            )
        if not has_latency and slow == 0:
            answer_parts.append(
                "I would classify this as errors/timeouts from the sampled logs, not confirmed slowness, because no duration metrics were present."
            )
        examples = top.get("examples") if isinstance(top, dict) else []
        if isinstance(examples, list) and examples:
            sample = examples[0].get("message", "") if isinstance(examples[0], dict) else ""
            if sample:
                answer_parts.append(f"Representative evidence: {sample[:220]}")
    elif entries:
        answer_parts.append("No concentrated hotspot was detected in the sampled logs.")
    else:
        answer_parts.append("No log entries matched this query and time range.")
    return " ".join(answer_parts)


def health_evidence_narrative_answer(evidence):
    lanes = evidence.get("lanes") if isinstance(evidence, dict) else []
    if not isinstance(lanes, list) or not lanes:
        return "No OpenSRS health lane evidence was available for analysis."
    problem_lanes = [
        lane
        for lane in lanes
        if isinstance(lane, dict)
        and (int(lane.get("failures") or 0) or int(lane.get("timeouts") or 0) or int(lane.get("slow") or 0))
    ]
    if not problem_lanes:
        total_events = sum(int(lane.get("events") or 0) for lane in lanes if isinstance(lane, dict))
        return f"OpenSRS health evidence does not show failures, timeouts, or confirmed slowness in the sampled lanes. Total sampled events: {total_events}."
    lane = sorted(
        problem_lanes,
        key=lambda item: int(item.get("failures") or 0) + int(item.get("timeouts") or 0) + int(item.get("slow") or 0),
        reverse=True,
    )[0]
    label = lane.get("label") or lane.get("id") or "unknown lane"
    answer = (
        f"OpenSRS health is degraded mainly in {label}: {lane.get('events', 0)} events, "
        f"{lane.get('failures', 0)} failures, {lane.get('timeouts', 0)} timeouts, and {lane.get('slow', 0)} slow entries."
    )
    hotspots = lane.get("hotspots") if isinstance(lane, dict) else []
    if isinstance(hotspots, list) and hotspots:
        top = hotspots[0]
        if isinstance(top, dict):
            answer += (
                f" Top hotspot is {top.get('key', 'unknown hotspot')} with {top.get('events', 0)} events, "
                f"{top.get('failures', 0)} failures, {top.get('timeouts', 0)} timeouts, and {top.get('slow', 0)} slow entries."
            )
            if top.get("p95_latency_ms") is not None:
                answer += f" P95 latency there is {top.get('p95_latency_ms')} ms."
    return answer


def _health_problem_areas(evidence):
    areas = []
    lanes = evidence.get("lanes") if isinstance(evidence, dict) else []
    if not isinstance(lanes, list):
        return areas
    for lane in lanes:
        if not isinstance(lane, dict):
            continue
        hotspots = lane.get("hotspots")
        if isinstance(hotspots, list):
            areas.extend(item for item in hotspots if isinstance(item, dict))
    return areas


def ask_ai(evidence):
    if not AI_API_BASE:
        return {"error": "AI endpoint not configured"}
    prompt = (
        "Analyze this log-only OpenSRS health evidence. Be specific: name slow/error hotspots, "
        "hosts, actions, registry agents, timestamps, and sample messages where present. "
        "Return a plain English SRE summary, not JSON. Distinguish confirmed slowness from errors/timeouts. Evidence:\n"
        + json.dumps(evidence, sort_keys=True)
    )
    payload = json.dumps(
        {
            "model": AI_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an SRE assistant. Return plain English, not JSON. "
                        "Do not give generic advice when evidence names a host/action/hotspot. "
                        "Use only supplied read-only evidence."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": AI_MAX_TOKENS,
        }
    ).encode()
    headers = {"Content-Type": "application/json"}
    if AI_API_KEY:
        headers["Authorization"] = f"Bearer {AI_API_KEY}"
    req = Request(
        f"{AI_API_BASE}/chat/completions",
        data=payload,
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(req, timeout=45) as resp:
            raw = json.loads(resp.read())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"error": f"AI endpoint unavailable: {exc}"}
    parsed = ai_text_to_answer(extract_chat_text(raw))
    answer = parsed.get("answer", "")
    if answer:
        answer = final_answer_only(answer)
    if (
        answer
        and not answer_echoes_prompt(answer)
        and not answer_is_generic(answer, {"entries_analyzed": 1, "problem_areas": _health_problem_areas(evidence)})
    ):
        return {"summary": answer, "raw_format": parsed.get("raw_format", "text")}
    return {
        "summary": health_evidence_narrative_answer(evidence),
        "raw_format": parsed.get("raw_format", "empty"),
        "warning": (
            "AI health answer echoed prompt/evidence; returned evidence-based summary"
            if answer_echoes_prompt(answer)
            else "AI health answer was empty or too generic; returned evidence-based summary"
        ),
    }


def ask_log_ai(evidence, question):
    if not AI_API_BASE:
        return {"error": "AI endpoint not configured"}
    prompt = (
        f"Question: {question}\n"
        "Answer only the user's question. Do not add a general runbook, issue template, or extra sections unless the question asks for them. "
        "Do not repeat these instructions or the evidence JSON. Use one short log example only if it directly supports the answer. "
        "Do not call it slowness unless latency/duration exists.\n"
        "Evidence JSON:\n"
        + json.dumps(evidence, sort_keys=True)
    )
    payload = json.dumps(
        {
            "model": AI_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You analyze logs for SREs. Use only supplied evidence. "
                        "Answer the user's question first. Explain what the logs show and where "
                        "the likely issue is. Return plain English, not JSON, no markdown fences. "
                        "No mutations, no lookups, no actions."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": AI_MAX_TOKENS,
        }
    ).encode()
    headers = {"Content-Type": "application/json"}
    if AI_API_KEY:
        headers["Authorization"] = f"Bearer {AI_API_KEY}"
    req = Request(f"{AI_API_BASE}/chat/completions", data=payload, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=45) as resp:
            raw = json.loads(resp.read())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"error": f"AI endpoint unavailable: {exc}"}
    text = extract_chat_text(raw)
    parsed = ai_text_to_answer(text)
    if parsed.get("answer"):
        parsed["answer"] = final_answer_only(parsed.get("answer", ""))
    if (
        parsed.get("answer")
        and not answer_echoes_prompt(parsed.get("answer", ""))
        and not answer_is_generic(parsed.get("answer", ""), evidence)
        and tld_answer_matches_evidence(parsed.get("answer", ""), evidence, question)
    ):
        return parsed
    if parsed.get("answer"):
        return {
            "answer": evidence_narrative_answer(evidence, question),
            "raw_format": parsed.get("raw_format", "text"),
            "warning": (
                "AI answer echoed prompt/evidence; returned evidence-based answer"
                if answer_echoes_prompt(parsed.get("answer", ""))
                else "AI answer was too generic or did not reference supplied evidence; returned evidence-based answer"
            ),
        }
    return {
        "answer": evidence_narrative_answer(evidence, question),
        "summary": "AI endpoint returned an empty response; this answer was generated from the same log evidence.",
        "findings": [],
        "problem_areas": evidence.get("problem_areas", [])[:5],
        "recommended_sre_actions": [],
        "raw_format": "empty",
        "warning": "AI endpoint returned empty response",
    }


def build_log_evidence(query, entries, range_seconds, selection=None, include_scope=True):
    durations = extract_durations(entries)
    failures = sum(1 for item in entries if is_failure(item.get("message", "")))
    timeouts = sum(1 for item in entries if _TIMEOUT_RE.search(item.get("message", "")))
    slow = sum(1 for item in entries if (entry_duration(item) or 0) >= SLOW_MS)
    grouped_problem_areas = summarize_groups(entries, entry_group_key, limit=10)
    problem_areas = [
        area
        for area in grouped_problem_areas
        if int(area.get("failures") or 0) or int(area.get("timeouts") or 0) or int(area.get("slow") or 0)
    ]
    latency_areas = [
        area
        for area in summarize_groups(entries, entry_group_key, limit=10, sort_by="latency")
        if area.get("p95_latency_ms") is not None or area.get("avg_latency_ms") is not None
    ]
    tld_entries = [item for item in entries if extract_tld(item.get("message", ""))]
    tld_areas = [
        area
        for area in summarize_groups(tld_entries, tld_group_key, limit=10, sort_by="latency")
        if area.get("p95_latency_ms") is not None or area.get("avg_latency_ms") is not None
    ]
    evidence = {
        "query": query,
        "range_seconds": range_seconds,
        "entries_analyzed": len(entries),
        "failures": failures,
        "timeouts": timeouts,
        "slow": slow,
        "avg_latency_ms": avg(durations),
        "p95_latency_ms": p95(durations),
        "problem_areas": problem_areas,
        "latency_areas": latency_areas,
        "tld_areas": tld_areas,
        "top_hosts": summarize_groups(entries, lambda item: (item.get("labels") or {}).get("host") or "unknown-host", limit=10),
        "problem_samples": _problem_samples(entries)[:10],
        "samples": _samples(entries)[:10],
    }
    if include_scope:
        evidence["access_scope"] = {
            "source": "Grafana Loki",
            "query": query,
            "range_seconds": range_seconds,
            "entries_analyzed": len(entries),
            "sample_cap": MAX_LOG_ANALYSIS_ENTRIES,
            "selection_mode": "ai_selected_from_observed_logs" if selection else "provided_query",
        }
        if selection:
            evidence["access_scope"].update(selection)
    return evidence


def analyze_logs(query, range_seconds, limit, question):
    safe_limit = max(1, min(int(limit or MAX_LOG_ANALYSIS_ENTRIES), MAX_LOG_ANALYSIS_ENTRIES))
    selected_template, considered = select_log_analysis_query(question, range_seconds)
    selected_query = selected_template["query"]
    raw = query_loki(selected_query, limit=safe_limit, range_seconds=range_seconds)
    entries = parse_loki_entries(raw)
    evidence = build_log_evidence(
        selected_query,
        entries,
        range_seconds,
        selection={
            "selected_template": selected_template["id"],
            "selected_label": selected_template["label"],
            "considered_queries": considered,
            "ignored_user_query": query,
        },
    )
    return {
        "analysis": ask_log_ai(evidence, question or "Find slowness, errors, and likely problem areas."),
        "evidence": evidence,
    }


def collect_lane(lane, window_seconds):
    try:
        raw = query_loki(lane["query"], limit=MAX_ENTRIES_PER_QUERY, range_seconds=window_seconds)
        entries = parse_loki_entries(raw)
        parser = globals()[lane["parser"]]
        return parser(entries)
    except Exception as exc:
        log.warning("Lane %s collection failed: %s", lane["id"], exc)
        failed = empty_lane(lane["id"], lane["label"])
        failed["status"] = "unknown"
        failed["error"] = str(exc)
        return failed


def run_report(conn, window_seconds, requested_by=None):
    started_at = utc_now()
    run_id = str(uuid.uuid4())
    lanes = [collect_lane(lane, window_seconds) for lane in EVIDENCE_LANES]
    usable_lanes = [lane for lane in lanes if int(lane.get("events") or 0) > 0]
    if not usable_lanes:
        raise RuntimeError("No usable OpenSRS log evidence found for selected window")
    issue_summary = build_issue_summary(lanes)
    evidence = {
        "window_seconds": window_seconds,
        "issue_summary": issue_summary,
        "lanes": [
            {
                "id": lane["id"],
                "status": lane.get("status"),
                "events": lane.get("events"),
                "errors": lane.get("errors"),
                "timeouts": lane.get("timeouts"),
                "slow": lane.get("slow"),
                "avg_latency_ms": lane.get("avg_latency_ms"),
                "p95_latency_ms": lane.get("p95_latency_ms"),
                "hotspots": lane.get("hotspots", [])[:5],
                "problem_samples": lane.get("problem_samples", [])[:5],
                "samples": lane.get("samples", [])[:3],
            }
            for lane in lanes
        ],
        "problem_areas": [
            {
                "lane": lane["id"],
                "hotspots": lane.get("hotspots", [])[:3],
                "samples": lane.get("problem_samples", [])[:3],
            }
            for lane in lanes
            if lane.get("status") == "degraded" or lane.get("problem_samples")
        ],
    }
    ai_analysis = ask_ai(evidence)
    completed_at = utc_now()
    report = build_report(run_id, started_at, completed_at, window_seconds, lanes, ai_analysis)
    store_report(conn, report, requested_by=requested_by)
    return report


def reserve_report_slot(now=None):
    global _last_run_at
    current = time.time() if now is None else now
    with _cooldown_lock:
        if current - _last_run_at < COOLDOWN_SECONDS:
            return False
        _last_run_at = current
        return True


class OpenSRSHealthHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _require_user(self):
        user = _get_username_from_request(self)
        if not user:
            self._send_json(401, {"error": "unauthenticated"})
            return None
        return user

    def _read_body(self):
        raw_length = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            self._send_json(400, {"error": "invalid Content-Length"})
            return None
        if length < 0:
            self._send_json(400, {"error": "invalid Content-Length"})
            return None
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON"})
            return None
        if not isinstance(body, dict):
            self._send_json(400, {"error": "invalid JSON body"})
            return None
        return body

    def do_OPTIONS(self):
        self._send_json(200, {"ok": True})

    def do_GET(self):
        user = self._require_user()
        if not user:
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path == "/api/opensrs-health/runs":
            self._send_json(200, {"runs": list_reports(db)})
            return
        prefix = "/api/opensrs-health/runs/"
        if path.startswith(prefix):
            run_id = path[len(prefix):]
            report = get_report(db, run_id)
            if not report:
                self._send_json(404, {"error": "unknown run"})
                return
            self._send_json(200, report)
            return
        self._send_json(404, {"error": "unknown endpoint"})

    def do_POST(self):
        user = self._require_user()
        if not user:
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path not in {"/api/opensrs-health/runs", "/api/opensrs-health/analyze-logs"}:
            self._send_json(404, {"error": "unknown endpoint"})
            return
        if not GRAFANA_URL:
            self._send_json(503, {"error": "Grafana not configured"})
            return
        body = self._read_body()
        if body is None:
            return
        if path == "/api/opensrs-health/analyze-logs":
            query = body.get("query")
            if query is not None and not isinstance(query, str):
                self._send_json(400, {"error": "invalid query"})
                return
            range_seconds = validate_window(body.get("range_seconds", body.get("range", 900)))
            if range_seconds is None:
                self._send_json(400, {"error": "invalid range"})
                return
            limit = body.get("limit", MAX_LOG_ANALYSIS_ENTRIES)
            try:
                limit = int(limit)
            except (TypeError, ValueError):
                self._send_json(400, {"error": "invalid limit"})
                return
            question = body.get("question", "")
            if not isinstance(question, str):
                self._send_json(400, {"error": "invalid question"})
                return
            try:
                self._send_json(200, analyze_logs((query or "").strip(), range_seconds, limit, question.strip()))
            except Exception as exc:
                log.exception("Log analysis failed")
                self._send_json(500, {"error": str(exc)})
            return
        window_seconds = validate_window(body.get("window_seconds", 900))
        if window_seconds is None:
            self._send_json(400, {"error": "invalid window"})
            return
        if not reserve_report_slot():
            self._send_json(429, {"error": "cooldown active"})
            return
        try:
            report = run_report(db, window_seconds, requested_by=user)
            self._send_json(201, report)
        except Exception as exc:
            log.exception("Report run failed")
            self._send_json(500, {"error": str(exc)})


if __name__ == "__main__":
    if not AUTH_SECRET:
        log.warning("AUTH_SECRET is not set; tokens will use an empty secret")
    if not GRAFANA_URL:
        log.warning("GRAFANA_URL is not set; report creation will return 503")
    db = init_db()
    server = ThreadingHTTPServer(("0.0.0.0", API_PORT), OpenSRSHealthHandler)
    log.info("opensrs-health-api listening on port %s", API_PORT)
    server.serve_forever()
