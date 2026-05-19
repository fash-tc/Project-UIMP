"""Active-P3-prompt registry.

Keyed on the original post's `ts`. `add()` registers a newly-posted
prompt. `remove()` is the atomic claim primitive — returns the entry
if the caller popped it, None if sweep or another click beat them.
`expire()` pops and returns every entry whose TTL has passed.

Lock discipline matches `pending_classification.PendingStore`: the
class mutates the dict only under `_lock`. All I/O (Slack edits) runs
in the caller AFTER the lock is released so a slow HTTP call can't
block the next sweep tick or button handler.

In-memory; lost on restart (acceptable — click handlers encode state
in the button value, so buttons still work; only auto-expiry is lost).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class P3Prompt:
    original_ts: str       # parent #ops-noc post
    prompt_ts: str         # the bot's thread-reply ts (edit target for expiry)
    channel_id: str
    expires_at: int        # unix seconds; = posted_at + ttl_sec


class P3PromptStore:
    def __init__(
        self,
        *,
        now_fn: Callable[[], int] = lambda: int(time.time()),
        ttl_sec: int = 900,
    ):
        self._lock = threading.Lock()
        self._map: dict[str, P3Prompt] = {}
        self._now_fn = now_fn
        self._ttl = ttl_sec

    def now(self) -> int:
        """Public clock accessor — returns current unix seconds via the
        injected `now_fn`. Exposed so callers building entries don't
        reach into a private attribute."""
        return int(self._now_fn())

    def add(self, prompt: P3Prompt) -> None:
        """Register a prompt. If one exists for the same original_ts
        (shouldn't happen in practice), overwrite — last writer wins."""
        with self._lock:
            self._map[prompt.original_ts] = prompt

    def remove(self, original_ts: str) -> Optional[P3Prompt]:
        """Atomic claim: pop and return the entry, or return None if
        someone else (sweep OR a prior click) already popped it.

        Handlers must branch on the return value — see spec
        §"Race: click and sweep" for the rules."""
        with self._lock:
            return self._map.pop(original_ts, None)

    def expire(self, now: int) -> list[P3Prompt]:
        """Pop every entry whose `expires_at < now`. Caller edits
        the prompt messages outside the lock."""
        popped: list[P3Prompt] = []
        with self._lock:
            for key in list(self._map.keys()):
                entry = self._map[key]
                if entry.expires_at < now:
                    popped.append(entry)
                    del self._map[key]
        return popped
