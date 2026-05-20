"""ConfigClient — shared library for consuming admin-api config.

This is the env-fallback skeleton (Task 7). SSE + live polling come in Task 8.
"""
import json
import logging
import os
import threading
import urllib.request
from typing import Any, Callable

from .schemas import SCHEMAS, KeySchema

log = logging.getLogger("uip_config_client")

_SENTINEL = object()


class ConfigClient:
    def __init__(
        self,
        admin_api: str = "http://admin-api:8096",
        env_fallback: bool = True,
        poll_interval_sec: int = 30,
        sse_reconnect_max_sec: int = 60,
        on_invalid_payload: Callable[[dict, Exception], None] | None = None,
        schemas: dict[str, KeySchema] | None = None,
        env_legacy_map: dict[str, tuple[str, str]] | None = None,
    ) -> None:
        self._admin_api = admin_api.rstrip("/")
        self._env_fallback = env_fallback
        self._poll_interval = poll_interval_sec
        self._sse_max = sse_reconnect_max_sec
        self._on_invalid = on_invalid_payload or self._default_on_invalid
        self._schemas: dict[str, KeySchema] = dict(SCHEMAS)
        if schemas:
            self._schemas.update(schemas)
        # env_legacy_map: {key: (env_var_name, value_type)}.
        # In Task 8 this is loaded from admin-api; for now caller passes it.
        self._env_legacy = env_legacy_map or {}
        self._values: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._listeners: dict[str, list[Callable[[Any, Any], None]]] = {}
        self._snapshot_loaded = False
        # Cold-start snapshot attempt (silent if admin-api is down)
        self._try_initial_snapshot()
        self._stop_sse = False
        self._start_sse_thread()

    # --- public ---

    def register_schema(self, key: str, schema: KeySchema) -> None:
        with self._lock:
            self._schemas[key] = schema

    def get(self, key: str, default: Any = _SENTINEL) -> Any:
        with self._lock:
            if key in self._values:
                return self._values[key]
        # Snapshot didn't have it. Try env_legacy.
        if self._env_fallback and key in self._env_legacy:
            env_name, vtype = self._env_legacy[key]
            raw = os.environ.get(env_name)
            if raw is not None:
                return self._coerce(raw, vtype)
        # Or env via UPPER_SNAKE conversion (best-effort, only if env_fallback)
        if self._env_fallback:
            snake = key.upper().replace(".", "_")
            raw = os.environ.get(snake)
            if raw is not None:
                # we don't know value_type from key alone; check schema
                schema = self._schemas.get(key)
                if schema:
                    return self._coerce(raw, schema.value_type)
        if default is not _SENTINEL:
            return default
        raise KeyError(key)

    def on_change(self, key: str, callback: Callable[[Any, Any], None]) -> None:
        with self._lock:
            self._listeners.setdefault(key, []).append(callback)

    def get_all(self, scope: str | None = None) -> dict[str, Any]:
        with self._lock:
            if scope is None:
                return dict(self._values)
            # We don't track scope locally in the values dict; if needed,
            # consumers can call /api/admin/config?scope=… directly. Returning
            # the union is fine for boot-time dumps.
            return {k: v for k, v in self._values.items() if k.startswith(f"{scope}.")}

    # --- internals ---

    def _coerce(self, raw: str, vtype: str) -> Any:
        if vtype == "int":
            return int(raw)
        if vtype == "float":
            return float(raw)
        if vtype == "bool":
            return raw.lower() in {"1", "true", "yes", "on"}
        if vtype == "json":
            return json.loads(raw)
        return raw

    def _try_initial_snapshot(self) -> None:
        try:
            with urllib.request.urlopen(f"{self._admin_api}/api/admin/config", timeout=2) as r:
                data = json.loads(r.read().decode())
                with self._lock:
                    for entry in data.get("items", []):
                        self._values[entry["key"]] = entry["value"]
                    self._snapshot_loaded = True
                log.info("initial snapshot loaded: %d keys", len(self._values))
        except Exception as e:
            log.warning("initial snapshot failed (will use env fallback): %s", e)

    def _start_sse_thread(self) -> None:
        t = threading.Thread(target=self._sse_loop, name="config-sse", daemon=True)
        t.start()
        self._sse_thread = t

    def _sse_loop(self) -> None:
        url = f"{self._admin_api}/api/admin/config/events"
        backoff = 1
        while not getattr(self, "_stop_sse", False):
            try:
                req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
                with urllib.request.urlopen(req, timeout=None) as r:
                    # Reset backoff only after we receive the first real frame, not
                    # just on connection open — a server that accepts then immediately
                    # drops would otherwise spin in a tight loop.
                    received_first_frame = False
                    event_type, data_lines = None, []
                    for raw in r:
                        line = raw.decode().rstrip("\n").rstrip("\r")
                        if line.startswith("event:"):
                            event_type = line[len("event:"):].strip()
                        elif line.startswith("data:"):
                            data_lines.append(line[len("data:"):].strip())
                        elif line == "" and event_type:
                            try:
                                payload = json.loads("\n".join(data_lines))
                                if event_type == "config_changed":
                                    self._apply_event(payload)
                                if not received_first_frame:
                                    backoff = 1
                                    received_first_frame = True
                            except Exception as e:
                                log.warning("SSE parse error: %s", e)
                            event_type, data_lines = None, []
            except Exception as e:
                log.warning("SSE reconnect in %ds: %s", backoff, e)
                import time as _time
                _time.sleep(backoff)
                backoff = min(backoff * 2, self._sse_max)

    def _apply_event(self, payload: dict) -> None:
        key = payload.get("key")
        new_value = payload.get("new_value")
        if key is None: return
        # Validate against local schema
        schema = self._schemas.get(key)
        if schema is not None:
            err = self._validate(new_value, schema)
            if err:
                try:
                    self._on_invalid(payload, ValueError(err))
                except Exception as ee:
                    log.warning("on_invalid_payload raised: %s", ee)
                return
        with self._lock:
            old_value = self._values.get(key)
            self._values[key] = new_value
            listeners = list(self._listeners.get(key, []))
        for cb in listeners:
            try:
                cb(old_value, new_value)
            except Exception as e:
                log.warning("on_change callback raised: %s", e)

    def _validate(self, value, schema) -> str | None:
        vtype = schema.value_type
        rule = schema.validation_rule
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
        if not rule: return None
        if vtype in ("int", "float"):
            if "min" in rule and value < rule["min"]: return f"value {value} below min {rule['min']}"
            if "max" in rule and value > rule["max"]: return f"value {value} above max {rule['max']}"
        if vtype == "string":
            import re
            if "regex" in rule and not re.match(rule["regex"], value):
                return f"value does not match regex"
            if "enum" in rule and value not in rule["enum"]:
                return f"value not in enum"
        return None

    def _default_on_invalid(self, payload: dict, exc: Exception) -> None:
        log.warning("invalid_config=true key=%s err=%s", payload.get("key"), exc)
