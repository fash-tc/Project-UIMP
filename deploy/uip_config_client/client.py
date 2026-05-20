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

    def _default_on_invalid(self, payload: dict, exc: Exception) -> None:
        log.warning("invalid_config=true key=%s err=%s", payload.get("key"), exc)
