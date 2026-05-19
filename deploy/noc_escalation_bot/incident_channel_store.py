"""Atomic JSON-backed store for incident channels.

Keyed by origin thread_ts. Atomic write via tmp + os.replace (matches
ticket_reactor._persist_dedup). Fail-closed on load: corrupt/missing
file → empty dict + WARN, never crash.

All access is guarded by a single threading.Lock. The store itself
never calls Slack; the caller (incident_channel_creator +
MessageHandler) is responsible for Slack I/O.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_STORE_PATH = os.environ.get(
    "INCIDENT_CHANNELS_PATH", "/data/incident_channels.json"
)


@dataclass
class IncidentChannelEntry:
    thread_ts: str
    origin_channel: str
    channel_id: str
    channel_name: str
    created_at: float
    created_by: str
    slug_source: str  # "llm" | "fallback"
    op_user_id: str
    initial_participants: list[str] = field(default_factory=list)
    resolved_at: Optional[float] = None
    resolved_by: Optional[str] = None
    resolved_reason: Optional[str] = None
    archive_at: Optional[float] = None
    archived_at: Optional[float] = None
    initial_post_ts: Optional[str] = None
    resolved_button_ts: Optional[str] = None
    transcript_text: Optional[str] = None
    transcript_by: Optional[str] = None
    transcript_at: Optional[float] = None


class IncidentChannelStore:
    """Thread-safe atomic JSON store keyed by thread_ts."""

    def __init__(self, path: str = DEFAULT_STORE_PATH):
        self._path = path
        self._lock = threading.Lock()
        self._entries: dict[str, IncidentChannelEntry] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self._path) as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except Exception:
            logger.warning("IncidentChannelStore: load failed from %s; "
                           "starting with empty store", self._path,
                           exc_info=True)
            return
        for k, v in (data or {}).items():
            try:
                self._entries[k] = IncidentChannelEntry(**v)
            except TypeError:
                logger.warning("IncidentChannelStore: skipping malformed "
                               "entry %s", k)
        logger.info("IncidentChannelStore: loaded %d entries from %s",
                    len(self._entries), self._path)

    def _persist_locked(self) -> None:
        """Caller holds self._lock."""
        try:
            dirpath = os.path.dirname(self._path) or "."
            os.makedirs(dirpath, exist_ok=True)
            tmp = f"{self._path}.tmp"
            snapshot = {k: asdict(v) for k, v in self._entries.items()}
            with open(tmp, "w") as f:
                json.dump(snapshot, f, indent=2)
            os.replace(tmp, self._path)
        except Exception:
            logger.warning("IncidentChannelStore: persist failed to %s",
                           self._path, exc_info=True)

    def claim(
        self,
        *,
        thread_ts: str,
        origin_channel: str,
        channel_id: str,
        channel_name: str,
        created_by: str,
        slug_source: str,
        op_user_id: str,
        initial_participants: list[str],
    ) -> tuple[IncidentChannelEntry, bool]:
        """Atomic setdefault. Returns (entry, created=True) on first write,
        or (existing_entry, False) on collision.
        """
        with self._lock:
            existing = self._entries.get(thread_ts)
            if existing is not None:
                return existing, False
            entry = IncidentChannelEntry(
                thread_ts=thread_ts,
                origin_channel=origin_channel,
                channel_id=channel_id,
                channel_name=channel_name,
                created_at=time.time(),
                created_by=created_by,
                slug_source=slug_source,
                op_user_id=op_user_id,
                initial_participants=list(initial_participants),
            )
            self._entries[thread_ts] = entry
            self._persist_locked()
            return entry, True

    def get(self, thread_ts: str) -> Optional[IncidentChannelEntry]:
        with self._lock:
            return self._entries.get(thread_ts)

    def mark_resolved(self, thread_ts: str, *, by: str,
                      reason: str) -> bool:
        """Write-once resolution. Returns True if this call wrote,
        False if already resolved or unknown thread."""
        with self._lock:
            e = self._entries.get(thread_ts)
            if e is None or e.resolved_at is not None:
                return False
            e.resolved_at = time.time()
            e.resolved_by = by
            e.resolved_reason = reason
            self._persist_locked()
            return True

    def set_archive_at(self, thread_ts: str, *, archive_at: float) -> None:
        with self._lock:
            e = self._entries.get(thread_ts)
            if e is None:
                return
            e.archive_at = archive_at
            self._persist_locked()

    def mark_archived(self, thread_ts: str, *, archived_at: float) -> None:
        with self._lock:
            e = self._entries.get(thread_ts)
            if e is None:
                return
            e.archived_at = archived_at
            self._persist_locked()

    def all_pending_archive(self, now: float) -> list[IncidentChannelEntry]:
        """Entries that are resolved, archive_at has elapsed, and not yet archived."""
        with self._lock:
            return [
                e for e in self._entries.values()
                if e.resolved_at is not None
                and e.archive_at is not None
                and e.archive_at <= now
                and e.archived_at is None
            ]

    def set_initial_post_ts(self, thread_ts: str, ts: str) -> None:
        with self._lock:
            e = self._entries.get(thread_ts)
            if e is None:
                return
            e.initial_post_ts = ts
            self._persist_locked()

    def set_resolved_button_ts(self, thread_ts: str, ts: str) -> None:
        with self._lock:
            e = self._entries.get(thread_ts)
            if e is None:
                return
            e.resolved_button_ts = ts
            self._persist_locked()

    def set_transcript(self, thread_ts: str, *, text: str, by: str) -> bool:
        with self._lock:
            e = self._entries.get(thread_ts)
            if e is None:
                return False
            e.transcript_text = text
            e.transcript_by = by
            e.transcript_at = time.time()
            self._persist_locked()
            return True

    def set_transcript_by_channel_id(self, channel_id: str, *, text: str, by: str) -> bool:
        with self._lock:
            for e in self._entries.values():
                if e.channel_id == channel_id:
                    e.transcript_text = text
                    e.transcript_by = by
                    e.transcript_at = time.time()
                    self._persist_locked()
                    return True
            return False

    def get_by_channel_id(self, channel_id: str) -> Optional[IncidentChannelEntry]:
        """Used by bot.py to route in-channel messages back to the
        incident context (LLM auto-resolve path). Only returns unresolved entries."""
        with self._lock:
            for e in self._entries.values():
                if e.channel_id == channel_id and e.resolved_at is None:
                    return e
            return None
