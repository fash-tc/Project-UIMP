"""loki-gateway: Loki query and registry health service for UIP.

Stateless — no SQLite database, no background polling.
All endpoints are request-response only.
"""

import json
import os
import re
import ssl
import base64
import hashlib
import hmac as hmac_mod
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("loki-gateway")

API_PORT = int(os.environ.get("API_PORT", "8091"))
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")

GRAFANA_URL = os.environ.get("GRAFANA_URL", "")
GRAFANA_USER = os.environ.get("GRAFANA_USER", "")
GRAFANA_PASS = os.environ.get("GRAFANA_PASS", "")
LOKI_DS_ID = os.environ.get("LOKI_DATASOURCE_ID", "17")


# ── Agent-to-operator mapping ──────────────────────────

AGENT_OPERATOR_MAP = {
    "ARIProxy": "ari-registry",
    "AUProxy": "ari-registry",
    "BrProxy": "registro",
    "CATProxy": "corenic",
    "CentralNicCoProxy": "centralnic",
    "CentralNicProxy": "centralnic",
    "ComNetBatchProxy": "verisign",
    "ComNetProxy": "verisign",
    "CymruProxy": "nominet",
    "DonutsProxy": "identity-digital",
    "EuProxy": "eurid",
    "FuryCaProxy": "cira",
    "FuryNzProxy": "internetnz",
    "GMOProxy": "gmo-registry",
    "GMOShopProxy": "gmo-registry",
    "KNetProxy": "knet-zdns",
    "NLProxy": "sidn",
    "PIRProxy": "pir",
    "ScotProxy": "corenic",
    "UkProxy": "nominet",
    "UniregistryINTeaProxy": "uniregistry",
    "UniregistryMMXProxy": "uniregistry",
    "UniregistryProxy": "uniregistry",
    "VerisignProxy": "verisign",
    "WSProxy": "website-ws",
    "WalesProxy": "nominet",
    "ZACRAfricaProxy": "zacr",
    "ZACRCoZaProxy": "zacr",
    "ZACRProxy": "zacr",
}

_TIMING_RE = re.compile(
    r"sendRecv=(\d+).*?total=(\d+)\s+ms\s+for\s+([\w\s]+?)\s+with\s+resp\s+(\d+)"
)
_EPP_CODE_RE = re.compile(r'result code="(\d{4})"')

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


# ── Auth ───────────────────────────────────────────────

def verify_token(token):
    """Verify a UIP auth token. Returns username or None."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        expected = hmac_mod.new(AUTH_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
        if not hmac_mod.compare_digest(sig, expected):
            return None
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
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
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.strip() == "uip_auth":
                return verify_token(v.strip())
    return None


# ── Loki query helpers ─────────────────────────────────

def query_loki(logql, limit=5000, range_seconds=3600):
    """Execute a LogQL query via Grafana's datasource proxy."""
    now_ns = int(time.time() * 1e9)
    start_ns = now_ns - (range_seconds * int(1e9))

    params = urlencode({
        "query": logql,
        "start": str(start_ns),
        "end": str(now_ns),
        "limit": str(min(limit, 5000)),
        "direction": "backward",
    })

    url = f"{GRAFANA_URL}/api/datasources/proxy/{LOKI_DS_ID}/loki/api/v1/query_range?{params}"
    auth = base64.b64encode(f"{GRAFANA_USER}:{GRAFANA_PASS}".encode()).decode()

    req = Request(url)
    req.add_header("Authorization", f"Basic {auth}")

    resp = urlopen(req, timeout=30, context=_ssl_ctx)
    return json.loads(resp.read())


def _parse_loki_entries(raw_data):
    """Flatten a Loki response into a sorted list of log entries."""
    entries = []
    for stream in (raw_data.get("data") or {}).get("result") or []:
        labels = stream.get("stream", {})
        for ts_ns, line in stream.get("values") or []:
            ts_sec = int(ts_ns) / 1e9
            dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
            try:
                parsed = json.loads(line)
                message = parsed.get("message", line)
            except (json.JSONDecodeError, AttributeError):
                message = line
            entries.append({
                "timestamp": dt.isoformat(),
                "labels": labels,
                "message": message,
            })
    entries.sort(key=lambda e: e["timestamp"], reverse=True)
    return entries


# ── Registry health aggregation ────────────────────────

def aggregate_registry_health(timing_data, epp_data):
    """Process raw Loki results into per-operator health metrics."""
    raw = {}  # operator_id -> {total_times, sendrecv_times, resp_codes, epp_codes, operations}
    unmapped = set()
    log_samples = {}  # operator_id -> {errors, slow, epp_errors}

    def _bucket(op_id):
        if op_id not in raw:
            raw[op_id] = {
                "total_times": [], "sendrecv_times": [],
                "resp_codes": {}, "epp_codes": {}, "operations": {},
            }
        if op_id not in log_samples:
            log_samples[op_id] = {"errors": [], "slow": [], "epp_errors": []}
        return raw[op_id]

    # Parse timing logs
    for stream in (timing_data.get("data") or {}).get("result") or []:
        agent = stream.get("stream", {}).get("registry_agent", "")
        op_id = AGENT_OPERATOR_MAP.get(agent)
        if not op_id:
            unmapped.add(agent)
            continue

        b = _bucket(op_id)
        s = log_samples[op_id]
        for _, line in stream.get("values") or []:
            try:
                msg = json.loads(line).get("message", "")
            except (json.JSONDecodeError, AttributeError):
                msg = line
            m = _TIMING_RE.search(msg)
            if not m:
                continue
            total_ms = int(m.group(2))
            sendrecv_ms = int(m.group(1))
            resp = int(m.group(4))
            op = m.group(3).strip()
            b["total_times"].append(total_ms)
            b["sendrecv_times"].append(sendrecv_ms)
            b["resp_codes"][resp] = b["resp_codes"].get(resp, 0) + 1
            b["operations"][op] = b["operations"].get(op, 0) + 1
            if resp >= 400 and len(s["errors"]) < 10:
                s["errors"].append({"agent": agent, "op": op, "resp": resp, "ms": total_ms})
            if total_ms > 5000 and len(s["slow"]) < 5:
                s["slow"].append({"agent": agent, "op": op, "ms": total_ms})

    # Parse EPP XML responses
    for stream in (epp_data.get("data") or {}).get("result") or []:
        agent = stream.get("stream", {}).get("registry_agent", "")
        op_id = AGENT_OPERATOR_MAP.get(agent)
        if not op_id:
            unmapped.add(agent)
            continue

        b = _bucket(op_id)
        s = log_samples.get(op_id) or {"errors": [], "slow": [], "epp_errors": []}
        log_samples[op_id] = s
        for _, line in stream.get("values") or []:
            try:
                msg = json.loads(line).get("message", "")
            except (json.JSONDecodeError, AttributeError):
                msg = line
            for code_str in _EPP_CODE_RE.findall(msg):
                code = int(code_str)
                b["epp_codes"][code] = b["epp_codes"].get(code, 0) + 1
                if code >= 2000 and len(s["epp_errors"]) < 10:
                    s["epp_errors"].append({"agent": agent, "epp_code": code})

    # Compute final metrics per operator
    result = {}
    for op_id, d in raw.items():
        n = len(d["total_times"])
        if n == 0:
            result[op_id] = {
                "status": "no_data", "request_count": 0,
                "avg_response_ms": 0, "avg_sendrecv_ms": 0, "p95_response_ms": 0,
                "error_rate": 0, "resp_codes": {}, "epp_error_rate": 0,
                "epp_codes": {}, "top_operations": {},
            }
            continue

        avg_total = sum(d["total_times"]) / n
        avg_sr = sum(d["sendrecv_times"]) / n
        sorted_t = sorted(d["total_times"])
        p95 = sorted_t[min(int(n * 0.95), n - 1)]

        err_resp = sum(v for k, v in d["resp_codes"].items() if k >= 400)
        ok_resp = sum(v for k, v in d["resp_codes"].items() if k < 400)
        total_resp = err_resp + ok_resp
        error_rate = (err_resp / total_resp) if total_resp > 0 else 0

        epp_err = sum(v for k, v in d["epp_codes"].items() if k >= 2000)
        epp_ok = sum(v for k, v in d["epp_codes"].items() if k < 2000)
        epp_total = epp_err + epp_ok
        epp_error_rate = (epp_err / epp_total) if epp_total > 0 else 0

        status = "healthy"
        if error_rate > 0.5 or epp_error_rate > 0.5 or avg_total > 10000:
            status = "down"
        elif error_rate > 0.1 or epp_error_rate > 0.1 or avg_total > 5000:
            status = "degraded"

        top_ops = dict(sorted(d["operations"].items(), key=lambda x: -x[1])[:5])
        resp_sorted = {str(k): v for k, v in sorted(d["resp_codes"].items())}
        epp_sorted = {str(k): v for k, v in sorted(d["epp_codes"].items())}

        result[op_id] = {
            "status": status,
            "request_count": n,
            "avg_response_ms": round(avg_total, 1),
            "avg_sendrecv_ms": round(avg_sr, 1),
            "p95_response_ms": p95,
            "error_rate": round(error_rate, 4),
            "resp_codes": resp_sorted,
            "epp_error_rate": round(epp_error_rate, 4),
            "epp_codes": epp_sorted,
            "top_operations": top_ops,
        }

    return result, sorted(unmapped), log_samples


# ── Log context builder ────────────────────────────────

def build_log_context(alert_name, hostname):
    """Query Loki on-demand and build structured log context for an alert."""
    if not GRAFANA_URL:
        return {"has_context": False, "error": "Loki not configured"}

    try:
        timing_data = query_loki('{app="ra", registry_agent=~".+"} |~ "total="', limit=5000, range_seconds=3600)
        epp_data = query_loki('{app="ra", registry_agent=~".+"} |~ "result code"', limit=5000, range_seconds=3600)
    except Exception as e:
        log.warning(f"build_log_context Loki query failed: {e}")
        return {"has_context": False, "error": str(e)}

    operators, unmapped, log_samples = aggregate_registry_health(timing_data, epp_data)

    if not operators:
        return {"has_context": False}

    issues = []
    for op_id, metrics in operators.items():
        if metrics.get("status") in ("degraded", "down"):
            issues.append((op_id, metrics))

    total = len(operators)
    healthy = sum(1 for m in operators.values() if m.get("status") == "healthy")
    degraded = sum(1 for m in operators.values() if m.get("status") == "degraded")
    down = sum(1 for m in operators.values() if m.get("status") == "down")

    result = {
        "has_context": True,
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "total_operators": total,
        "healthy_count": healthy,
        "degraded_count": degraded,
        "down_count": down,
        "operator_issues": [],
    }

    for op_id, metrics in issues:
        op_data = {
            "operator": op_id,
            "status": metrics.get("status", "unknown"),
            "avg_response_ms": metrics.get("avg_response_ms", 0),
            "error_rate": metrics.get("error_rate", 0),
            "epp_error_rate": metrics.get("epp_error_rate", 0),
            "request_count": metrics.get("request_count", 0),
        }
        samp = log_samples.get(op_id, {})
        if samp.get("errors"):
            op_data["recent_errors"] = samp["errors"][:5]
        if samp.get("epp_errors"):
            op_data["recent_epp_errors"] = samp["epp_errors"][:5]
        if samp.get("slow"):
            op_data["slow_requests"] = samp["slow"][:3]
        result["operator_issues"].append(op_data)

    if not issues:
        result["all_healthy"] = True

    return result


# ── Registry trends ────────────────────────────────────

def _get_agents_for_operator(operator_id):
    """Return the list of agent names that map to the given operator_id."""
    return [agent for agent, op in AGENT_OPERATOR_MAP.items() if op == operator_id]


def query_registry_trends(operator_id, range_hours):
    """Query Loki for hourly bucketed metrics for a given operator."""
    agents = _get_agents_for_operator(operator_id)
    if not agents:
        return None

    # Build a regex alternation for the operator's agents
    agent_regex = "|".join(re.escape(a) for a in agents)
    range_seconds = range_hours * 3600

    try:
        timing_data = query_loki(
            f'{{app="ra", registry_agent=~"{agent_regex}"}} |~ "total="',
            limit=5000,
            range_seconds=range_seconds,
        )
    except Exception as e:
        raise RuntimeError(f"Loki query failed: {e}") from e

    # Group log lines into hourly buckets
    # bucket key = truncated-to-hour epoch seconds
    buckets = {}  # ts_hour -> {total_times, error_count, total_count}

    for stream in (timing_data.get("data") or {}).get("result") or []:
        for ts_ns, line in stream.get("values") or []:
            ts_sec = int(ts_ns) / 1e9
            # Truncate to start of hour
            hour_ts = int(ts_sec // 3600) * 3600

            try:
                msg = json.loads(line).get("message", "")
            except (json.JSONDecodeError, AttributeError):
                msg = line

            m = _TIMING_RE.search(msg)
            if not m:
                continue

            total_ms = int(m.group(2))
            resp = int(m.group(4))

            if hour_ts not in buckets:
                buckets[hour_ts] = {"total_times": [], "error_count": 0, "total_count": 0}

            buckets[hour_ts]["total_times"].append(total_ms)
            buckets[hour_ts]["total_count"] += 1
            if resp >= 400:
                buckets[hour_ts]["error_count"] += 1

    # Build sorted list of bucket objects
    result_buckets = []
    for hour_ts in sorted(buckets.keys()):
        b = buckets[hour_ts]
        n = len(b["total_times"])
        avg_ms = round(sum(b["total_times"]) / n, 1) if n > 0 else 0
        error_rate = round(b["error_count"] / b["total_count"], 4) if b["total_count"] > 0 else 0
        dt = datetime.fromtimestamp(hour_ts, tz=timezone.utc)
        result_buckets.append({
            "timestamp": dt.isoformat(),
            "avg_response_ms": avg_ms,
            "error_rate": error_rate,
            "request_count": b["total_count"],
        })

    return {
        "operator": operator_id,
        "range_hours": range_hours,
        "buckets": result_buckets,
    }


# ── HTTP Handler ───────────────────────────────────────

class LokiHandler(BaseHTTPRequestHandler):

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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _require_auth(self):
        """Check auth cookie. Returns username string, or sends 401 and returns None."""
        username = _get_username_from_request(self)
        if not username:
            self._send_json(401, {"error": "Not authenticated"})
            return None
        return username

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, fmt, *args):
        log.info("%s - - %s" % (self.address_string(), fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        # ── GET /api/loki/registry-health ────────────────
        if path == "/api/loki/registry-health":
            if not self._require_auth():
                return
            if not GRAFANA_URL:
                self._send_json(503, {"error": "Loki not configured"})
                return
            try:
                timing = query_loki('{app="ra", registry_agent=~".+"} |~ "total="', limit=5000, range_seconds=3600)
                epp = query_loki('{app="ra", registry_agent=~".+"} |~ "result code"', limit=5000, range_seconds=3600)
                operators, unmapped, _ = aggregate_registry_health(timing, epp)
                self._send_json(200, {
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "query_window_seconds": 3600,
                    "operators": operators,
                    "unmapped_agents": unmapped,
                    "loki_error": None,
                })
            except HTTPError as e:
                body = ""
                try:
                    body = e.read().decode()[:200]
                except Exception:
                    pass
                self._send_json(502, {"error": f"Loki query failed ({e.code})", "detail": body})
            except Exception as e:
                self._send_json(502, {"error": f"Loki query failed: {str(e)}"})

        # ── GET /api/loki/log-context ────────────────────
        # No auth required — called internally by the enricher service.
        elif path == "/api/loki/log-context":
            alert_name = params.get("alert_name", [""])[0]
            hostname = params.get("hostname", [""])[0]
            ctx = build_log_context(alert_name, hostname)
            self._send_json(200, ctx)

        # ── GET /api/loki/registry-trends ────────────────
        elif path == "/api/loki/registry-trends":
            if not self._require_auth():
                return
            if not GRAFANA_URL:
                self._send_json(503, {"error": "Loki not configured"})
                return

            operator = params.get("operator", [""])[0].strip()
            if not operator:
                self._send_json(400, {"error": "operator parameter is required"})
                return

            try:
                range_hours = int(params.get("range", ["24"])[0])
            except (ValueError, TypeError):
                self._send_json(400, {"error": "range must be an integer"})
                return

            if range_hours not in (6, 24, 168):
                self._send_json(400, {"error": "range must be one of: 6, 24, 168"})
                return

            agents = _get_agents_for_operator(operator)
            if not agents:
                self._send_json(404, {"error": f"Unknown operator: {operator}"})
                return

            try:
                trends = query_registry_trends(operator, range_hours)
                self._send_json(200, trends)
            except RuntimeError as e:
                self._send_json(502, {"error": str(e)})
            except Exception as e:
                self._send_json(502, {"error": f"Trends query failed: {str(e)}"})

        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # ── POST /api/loki/logs/query ─────────────────────
        if path == "/api/loki/logs/query":
            if not self._require_auth():
                return
            if not GRAFANA_URL:
                self._send_json(503, {"error": "Loki not configured"})
                return
            try:
                data = self._read_body()
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return

            query = (data.get("query") or "").strip()
            if not query:
                self._send_json(400, {"error": "query is required"})
                return

            try:
                limit = int(data.get("limit", 200))
            except (ValueError, TypeError):
                self._send_json(400, {"error": "limit must be an integer"})
                return
            if limit < 1 or limit > 1000:
                self._send_json(400, {"error": "limit must be between 1 and 1000"})
                return

            try:
                range_seconds = int(data.get("range", 3600))
            except (ValueError, TypeError):
                self._send_json(400, {"error": "range must be an integer"})
                return
            if range_seconds < 1 or range_seconds > 86400:
                self._send_json(400, {"error": "range must be between 1 and 86400 seconds"})
                return

            try:
                raw = query_loki(query, limit=limit, range_seconds=range_seconds)
                entries = _parse_loki_entries(raw)
                self._send_json(200, {
                    "entries": entries,
                    "total": len(entries),
                    "query": query,
                    "range_seconds": range_seconds,
                })
            except HTTPError as e:
                body = ""
                try:
                    body = e.read().decode()[:200]
                except Exception:
                    pass
                self._send_json(502, {"error": f"Loki query failed ({e.code})", "detail": body})
            except Exception as e:
                self._send_json(502, {"error": f"Loki query failed: {str(e)}"})

        else:
            self._send_json(404, {"error": "not found"})


# ── Main ───────────────────────────────────────────────

if not AUTH_SECRET:
    log.warning("AUTH_SECRET is not set — tokens will use an empty secret")

if not GRAFANA_URL:
    log.warning("GRAFANA_URL is not set — Loki endpoints will return 503")

server = HTTPServer(("0.0.0.0", API_PORT), LokiHandler)
log.info(f"loki-gateway listening on port {API_PORT}")
server.serve_forever()
