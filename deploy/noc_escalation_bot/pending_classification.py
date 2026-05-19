"""Wait-window state for `change_no_cr` classifier verdicts.

Keyed on (channel_id, user_id). When a classifier returns `change_no_cr`,
the caller inserts a `PendingEntry`; either a bare CR-NNNN follow-up
from the same user arrives before `expires_at` and the entry is popped
by `handle_followup`, or the sweep loop pops the entry and the caller
posts a fallback-ask reply.

Pure in-memory; lost on restart (acceptable — operator re-posts).

Lock discipline: the class mutates the dict only under `_lock`. All I/O
(Slack, Jira) happens in the caller *after* the lock is released so a
slow HTTP call can't block the next sweep tick or follow-up lookup.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, replace
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Matches OCCIR-NNNN anywhere in text. We look at follow-ups for a bare
# CR-NNNN (not OCCIR), so use a CR-only pattern.
_CR_RE = re.compile(r"\bCR-\d+\b")

# Sweep runs every 10s; an entry whose nominal expiry already passed
# but is still within the grace window is allowed to be popped by a
# follow-up (so a same-user CR arriving +2s past expiry still wins over
# the fallback-ask). 5s comfortably covers one sweep tick.
GRACE_SEC = 5


@dataclass(frozen=True)
class PendingEntry:
    original_ts: str      # ts of the @noc post
    channel_id: str
    user_id: str
    original_text: str    # preserved so esc:page can re-fetch/fallback
    expires_at: int       # unix seconds


class PendingStore:
    def __init__(self, *, now_fn: Callable[[], int], wait_window_sec: int = 60):
        self._lock = threading.Lock()
        self._map: dict[tuple[str, str], PendingEntry] = {}
        self._now_fn = now_fn
        self._wait = wait_window_sec

    def now(self) -> int:
        """Public clock accessor — returns current unix seconds via the
        injected `now_fn`. Exposed so callers (e.g. bot.py overriding
        `expires_at`) don't reach into a private attribute."""
        return int(self._now_fn())

    def enter(self, entry: PendingEntry) -> None:
        """Insert (or overwrite) a pending entry for (channel, user)."""
        key = (entry.channel_id, entry.user_id)
        with self._lock:
            self._map[key] = entry

    def handle_followup(self, *, channel: str, user: str,
                        text: str) -> Optional[PendingEntry]:
        """If `text` contains CR-NNNN and `(channel, user)` has a pending
        entry (including one in the grace window), pop and return it.
        Otherwise return None. Safe to call on every top-level message
        in the channel.
        """
        if not _CR_RE.search(text):
            return None
        key = (channel, user)
        now = self.now()
        with self._lock:
            entry = self._map.get(key)
            if entry is None:
                return None
            # Allow pops up to expires_at + GRACE_SEC so a follow-up
            # arriving near expiry still wins over the sweep.
            if entry.expires_at + GRACE_SEC < now:
                # Too late — leave it for the sweep to clean up.
                return None
            del self._map[key]
            return entry

    def expire_pending(self, now: int) -> list[PendingEntry]:
        """Pop every entry whose expires_at + GRACE_SEC <= now. Caller
        posts fallback-ask replies outside the lock."""
        popped: list[PendingEntry] = []
        with self._lock:
            for key in list(self._map.keys()):
                entry = self._map[key]
                if entry.expires_at + GRACE_SEC < now:
                    popped.append(entry)
                    del self._map[key]
        return popped

    def new_entry(self, *, original_ts: str, channel_id: str,
                  user_id: str, original_text: str) -> PendingEntry:
        """Convenience: build an entry with `expires_at = now + wait_window`."""
        return PendingEntry(
            original_ts=original_ts, channel_id=channel_id,
            user_id=user_id, original_text=original_text,
            expires_at=self.now() + self._wait,
        )
