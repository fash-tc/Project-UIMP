"""SSE broadcaster — same pattern as alert-state-api.py _sse_broadcast.

Holds a set of `wfile` writers. broadcast() iterates and removes dead ones.
The route handler in routes/config.py wires up subscribers.
"""
import json
import logging
import threading
from typing import Any

log = logging.getLogger("admin-api.sse")

_lock = threading.Lock()
_clients: set[Any] = set()  # set of BufferedWriter (handler.wfile)
_event_counter = 0
_MAX_CLIENTS = 50


def add_client(wfile) -> None:
    with _lock:
        if len(_clients) >= _MAX_CLIENTS:
            raise RuntimeError("SSE client limit reached")
        _clients.add(wfile)
        log.info("SSE client connected (total=%d)", len(_clients))


def remove_client(wfile) -> None:
    with _lock:
        _clients.discard(wfile)
        log.info("SSE client disconnected (total=%d)", len(_clients))


def broadcast(event_type: str, payload: dict) -> None:
    """Push an SSE event to all connected clients. Drops dead writers."""
    global _event_counter
    with _lock:
        _event_counter += 1
        event_id = _event_counter
        clients = list(_clients)

    data = json.dumps(payload)
    msg = f"id: {event_id}\nevent: {event_type}\ndata: {data}\n\n".encode()
    dead = []
    for c in clients:
        try:
            c.write(msg)
            c.flush()
        except Exception as e:
            log.warning("SSE write failed: %s", e)
            dead.append(c)
    if dead:
        with _lock:
            for d in dead:
                _clients.discard(d)
            log.info("Removed %d dead SSE client(s), %d remaining", len(dead), len(_clients))
