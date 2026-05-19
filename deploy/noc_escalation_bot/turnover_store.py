"""SQLite-backed persistence for NOC Turnover.

All DB I/O goes through this module. A single threading.Lock serializes every
call (reads and writes). FKs are NOT enforced — the REFERENCES clause is docs.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 6


@dataclass
class Incident:
    slack_ts: str
    channel_id: str
    posted_at: int
    poster_user_id: str
    text_preview: str
    permalink: str
    occir_key: Optional[str] = None
    occir_status: Optional[str] = None
    first_reply_at: Optional[int] = None
    reply_count: int = 0
    resolved_at: Optional[int] = None
    resolved_source: Optional[str] = None
    resolved_by_user_id: Optional[str] = None
    last_swept_at: Optional[int] = None
    title_summary: Optional[str] = None
    shift_excluded_at: Optional[int] = None
    claimed_by_user_id: Optional[str] = None


@dataclass
class ThreadReply:
    slack_ts: str
    incident_ts: str
    user_id: str
    posted_at: int
    text_preview: str


@dataclass
class ShiftPost:
    shift_key: str
    slot: str
    window_start: int
    window_end: int
    channel_id: str
    message_ts: str
    posted_at: int
    last_updated_at: int


@dataclass
class EscalationState:
    thread_ts: str
    channel_id: str
    last_irm_page_at: Optional[int] = None
    silence_until: Optional[int] = None


@dataclass
class CRCollectionRow:
    thread_ts: str
    user_id: str
    expires_at: int
    fallback_ask_ts: Optional[str] = None
    channel_id: Optional[str] = None


@dataclass
class HandoffItem:
    id: int
    shift_key: str
    title: str
    link: Optional[str]
    note: Optional[str]
    author_user_id: str
    created_at: int


class TurnoverStore:
    def __init__(self, db_path: str):
        self._path = db_path
        self._lock = threading.Lock()
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- migrations ---------------------------------------------------------

    def _migrate(self) -> None:
        with self._lock:
            cur = self._conn.execute("PRAGMA user_version")
            version = cur.fetchone()[0]
            if version < 1:
                self._conn.executescript(_SCHEMA_V1)
                version = 1
            if version < 2:
                self._conn.executescript(_SCHEMA_V2)
                version = 2
            if version < 3:
                self._conn.executescript(_SCHEMA_V3)
                version = 3
            if version < 4:
                self._conn.executescript(_SCHEMA_V4)
                cols = [r[1] for r in self._conn.execute(
                    "PRAGMA table_info(incidents)").fetchall()]
                if "shift_excluded_at" not in cols:
                    self._conn.execute(
                        "ALTER TABLE incidents ADD COLUMN shift_excluded_at INTEGER")
                version = 4
            if version < 5:
                self._conn.executescript(_SCHEMA_V5)
                version = 5
            if version < 6:
                self._conn.executescript(_SCHEMA_V6)
                version = 6
            cols = [r[1] for r in self._conn.execute(
                "PRAGMA table_info(incidents)").fetchall()]
            if "claimed_by_user_id" not in cols:
                self._conn.execute(
                    "ALTER TABLE incidents ADD COLUMN claimed_by_user_id TEXT")
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._conn.commit()

    # --- incidents ----------------------------------------------------------

    def insert_incident(self, inc: Incident) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO incidents
                  (slack_ts, channel_id, posted_at, poster_user_id,
                   text_preview, permalink, occir_key, occir_status,
                   first_reply_at, reply_count, resolved_at, resolved_source,
                   resolved_by_user_id, last_swept_at, claimed_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (inc.slack_ts, inc.channel_id, inc.posted_at, inc.poster_user_id,
                 inc.text_preview, inc.permalink, inc.occir_key, inc.occir_status,
                 inc.first_reply_at, inc.reply_count, inc.resolved_at,
                 inc.resolved_source, inc.resolved_by_user_id, inc.last_swept_at,
                 inc.claimed_by_user_id),
            )
            self._conn.commit()

    def delete_incident(self, ts: str) -> None:
        """Remove an incident and its thread replies. Used for hard deletes
        (e.g. the source Slack message was deleted)."""
        with self._lock:
            self._conn.execute("DELETE FROM thread_replies WHERE incident_ts = ?", (ts,))
            self._conn.execute("DELETE FROM incidents WHERE slack_ts = ?", (ts,))
            self._conn.commit()

    def get_incident(self, ts: str) -> Optional[Incident]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM incidents WHERE slack_ts = ?", (ts,)
            ).fetchone()
        return _row_to_incident(row) if row else None

    def get_open_incidents(self) -> list[Incident]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM incidents WHERE resolved_at IS NULL AND shift_excluded_at IS NULL ORDER BY posted_at ASC"
            ).fetchall()
        return [_row_to_incident(r) for r in rows]

    def get_incidents_in_window(self, start: int, end: int) -> list[Incident]:
        """Inclusive-start, exclusive-end, ordered by posted_at ASC."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM incidents "
                "WHERE posted_at >= ? AND posted_at < ? AND shift_excluded_at IS NULL "
                "ORDER BY posted_at ASC",
                (start, end),
            ).fetchall()
        return [_row_to_incident(r) for r in rows]

    def link_ticket(self, ts: str, occir_key: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET occir_key = ? WHERE slack_ts = ?",
                (occir_key, ts),
            )
            self._conn.commit()

    def update_occir_status(self, ts: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET occir_status = ? WHERE slack_ts = ?",
                (status, ts),
            )
            self._conn.commit()

    def mark_resolved(self, ts: str, resolved_at: int, source: str,
                      by_user_id: Optional[str] = None) -> bool:
        """Return True if newly resolved, False if already resolved (sticky)."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE incidents "
                "SET resolved_at = ?, resolved_source = ?, resolved_by_user_id = ? "
                "WHERE slack_ts = ? AND resolved_at IS NULL",
                (resolved_at, source, by_user_id, ts),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def mark_incident_excluded(self, incident_ts: str, at: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET shift_excluded_at = ? WHERE slack_ts = ?",
                (at, incident_ts),
            )
            self._conn.commit()

    def dismiss_open_incidents_older_than(
        self, cutoff: int, *, at: int, by_user_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> int:
        """Exclude unresolved incidents posted before cutoff from turnover.

        `by_user_id` and `reason` are accepted for scheduler compatibility;
        the current schema only persists shift_excluded_at.
        """
        with self._lock:
            cur = self._conn.execute(
                "UPDATE incidents SET shift_excluded_at = ? "
                "WHERE resolved_at IS NULL "
                "AND shift_excluded_at IS NULL "
                "AND posted_at < ?",
                (at, cutoff),
            )
            self._conn.commit()
            return cur.rowcount

    def mark_seen_in_shift(
        self, incident_ts: str, *, shift_key: str, is_carryover: bool,
    ) -> None:
        """Compatibility hook for scheduler shift accounting.

        Current DB schema derives carryover from timestamps/open state, so no
        persisted write is needed here.
        """
        return None

    def claim_incident(self, ts: str, user_id: str) -> bool:
        """Return True if newly claimed, False if already claimed/missing."""
        if not user_id:
            return False
        with self._lock:
            cur = self._conn.execute(
                "UPDATE incidents SET claimed_by_user_id = ? "
                "WHERE slack_ts = ? AND claimed_by_user_id IS NULL",
                (user_id, ts),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def update_title_summary(self, ts: str, summary: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET title_summary = ? WHERE slack_ts = ?",
                (summary, ts),
            )
            self._conn.commit()

    def incidents_missing_title_summary(self, limit: int = 500) -> list[str]:
        """Return slack_ts of incidents whose title_summary is not yet set,
        newest first so the freshly visible ones get processed before the
        long tail of historical records."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT slack_ts FROM incidents "
                "WHERE title_summary IS NULL OR title_summary = '' "
                "ORDER BY posted_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [r["slack_ts"] for r in rows]

    def update_last_swept(self, ts: str, swept_at: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET last_swept_at = ? WHERE slack_ts = ?",
                (swept_at, ts),
            )
            self._conn.commit()

    # --- thread_replies -----------------------------------------------------

    def insert_reply(self, reply: ThreadReply) -> None:
        """Insert a reply. If the parent incident doesn't exist, silently drop."""
        with self._lock:
            parent = self._conn.execute(
                "SELECT 1 FROM incidents WHERE slack_ts = ?",
                (reply.incident_ts,),
            ).fetchone()
            if not parent:
                logger.debug(
                    "turnover_store: reply %s dropped (no parent incident %s)",
                    reply.slack_ts, reply.incident_ts,
                )
                return
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO thread_replies "
                "(slack_ts, incident_ts, user_id, posted_at, text_preview) "
                "VALUES (?, ?, ?, ?, ?)",
                (reply.slack_ts, reply.incident_ts, reply.user_id,
                 reply.posted_at, reply.text_preview),
            )
            if cur.rowcount > 0:
                self._conn.execute(
                    "UPDATE incidents "
                    "SET reply_count = reply_count + 1, "
                    "    first_reply_at = COALESCE(first_reply_at, ?) "
                    "WHERE slack_ts = ?",
                    (reply.posted_at, reply.incident_ts),
                )
            self._conn.commit()

    def latest_reply_at(self, incident_ts: str) -> Optional[int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(posted_at) FROM thread_replies WHERE incident_ts = ?",
                (incident_ts,),
            ).fetchone()
        return row[0] if row and row[0] is not None else None

    def last_reply(self, incident_ts: str) -> Optional[ThreadReply]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM thread_replies WHERE incident_ts = ? "
                "ORDER BY posted_at DESC LIMIT 1",
                (incident_ts,),
            ).fetchone()
        if not row:
            return None
        return ThreadReply(
            slack_ts=row["slack_ts"], incident_ts=row["incident_ts"],
            user_id=row["user_id"], posted_at=row["posted_at"],
            text_preview=row["text_preview"],
        )

    def unique_responder_count(self, incident_ts: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM thread_replies WHERE incident_ts = ?",
                (incident_ts,),
            ).fetchone()
        return int(row[0] or 0)

    def concat_thread(self, incident_ts: str, char_limit: int) -> str:
        """Parent text preview + thread replies, joined by newline.

        When the thread exceeds `char_limit`, keep the parent (context anchor)
        and the MOST RECENT replies that fit — resolution signals land near
        the end of the thread, so tail-weighting beats head-truncation. As a
        last resort (parent alone already exceeds the budget) the whole blob
        is hard-truncated to `char_limit` chars.
        """
        with self._lock:
            parent = self._conn.execute(
                "SELECT text_preview FROM incidents WHERE slack_ts = ?",
                (incident_ts,),
            ).fetchone()
            replies = self._conn.execute(
                "SELECT text_preview FROM thread_replies "
                "WHERE incident_ts = ? ORDER BY posted_at ASC",
                (incident_ts,),
            ).fetchall()
        parent_text = parent["text_preview"] if parent else ""
        reply_texts = [r["text_preview"] for r in replies]

        # Budget accounting: each joined segment costs len(text)+1 (newline).
        head = [parent_text] if parent_text else []
        used = len(parent_text) + (1 if parent_text else 0)
        kept_tail: list[str] = []
        for t in reversed(reply_texts):
            cost = len(t) + 1
            if used + cost > char_limit:
                break
            kept_tail.insert(0, t)
            used += cost
        blob = "\n".join(head + kept_tail)
        # Defensive clamp in case the parent alone overflows.
        return blob[:char_limit]

    # --- shift_posts --------------------------------------------------------

    def record_shift_post(self, sp: ShiftPost) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO shift_posts "
                "(shift_key, slot, window_start, window_end, channel_id, "
                " message_ts, posted_at, last_updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (sp.shift_key, sp.slot, sp.window_start, sp.window_end,
                 sp.channel_id, sp.message_ts, sp.posted_at, sp.last_updated_at),
            )
            self._conn.commit()

    def get_shift_post(self, shift_key: str) -> Optional[ShiftPost]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM shift_posts WHERE shift_key = ?", (shift_key,)
            ).fetchone()
        return _row_to_shift_post(row) if row else None

    def active_shift_posts(self, now: int) -> list[ShiftPost]:
        """Shift posts that should still be refreshed on the 30-minute tick.

        A prospective turnover post is pinned at the shift boundary the
        shift begins (posted_at == window_start). It stays refreshable
        until the next shift boundary supersedes it — the overnight shift
        is the longest at 9 hours, so a 9-hour lookback covers every
        active shift without holding stale ones."""
        cutoff = now - 9 * 3600
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM shift_posts WHERE posted_at > ? "
                "ORDER BY posted_at DESC",
                (cutoff,),
            ).fetchall()
        return [_row_to_shift_post(r) for r in rows]

    def all_shift_posts(self) -> list[ShiftPost]:
        """Every ShiftPost row ignoring the active-window filter.

        Used by manual-delete flows that need to resolve a message_ts back
        to a shift_key regardless of age.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM shift_posts ORDER BY posted_at DESC"
            ).fetchall()
        return [_row_to_shift_post(r) for r in rows]

    def touch_shift_post(self, shift_key: str, now: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE shift_posts SET last_updated_at = ? WHERE shift_key = ?",
                (now, shift_key),
            )
            self._conn.commit()

    def delete_shift_post(self, shift_key: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM shift_posts WHERE shift_key = ?", (shift_key,)
            )
            self._conn.commit()

    # --- escalation_state --------------------------------------------------

    def get_escalation_state(self, thread_ts: str) -> Optional[EscalationState]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM escalation_state WHERE thread_ts = ?", (thread_ts,),
            ).fetchone()
        if not row:
            return None
        return EscalationState(
            thread_ts=row["thread_ts"], channel_id=row["channel_id"],
            last_irm_page_at=row["last_irm_page_at"],
            silence_until=row["silence_until"],
        )

    def record_irm_page(self, thread_ts: str, channel_id: str, at: int) -> None:
        """Upsert last_irm_page_at; preserves silence_until on existing row."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO escalation_state (thread_ts, channel_id, last_irm_page_at)
                VALUES (?, ?, ?)
                ON CONFLICT(thread_ts) DO UPDATE SET
                    last_irm_page_at = excluded.last_irm_page_at,
                    channel_id = excluded.channel_id
                """,
                (thread_ts, channel_id, at),
            )
            self._conn.commit()

    def set_silence(self, thread_ts: str, channel_id: str, until: int) -> None:
        """Upsert silence_until; preserves last_irm_page_at on existing row."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO escalation_state (thread_ts, channel_id, silence_until)
                VALUES (?, ?, ?)
                ON CONFLICT(thread_ts) DO UPDATE SET
                    silence_until = excluded.silence_until,
                    channel_id = excluded.channel_id
                """,
                (thread_ts, channel_id, until),
            )
            self._conn.commit()

    # --- handoff_items -----------------------------------------------------

    def insert_handoff_item(
        self, shift_key: str, title: str, link: Optional[str],
        note: Optional[str], author: str, at: int,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO handoff_items
                  (shift_key, title, link, note, author_user_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (shift_key, title, link, note, author, at),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_handoff_items(self, shift_key: str) -> list["HandoffItem"]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM handoff_items WHERE shift_key = ? ORDER BY id ASC",
                (shift_key,),
            ).fetchall()
        return [
            HandoffItem(
                id=r["id"], shift_key=r["shift_key"], title=r["title"],
                link=r["link"], note=r["note"],
                author_user_id=r["author_user_id"], created_at=r["created_at"],
            )
            for r in rows
        ]

    # --- cr collection ------------------------------------------------------

    def set_cr_collection(self, *, thread_ts: str, user_id: str,
                          expires_at: int,
                          fallback_ask_ts: Optional[str] = None,
                          channel_id: Optional[str] = None) -> None:
        """Upsert a CR-collection flag for the given @noc thread.

        `fallback_ask_ts` + `channel_id` let the ingestor's completion
        path post a final `chat_update` ("CR summary posted") on the
        fallback-ask message. They are optional — a set with neither
        just skips that third edit."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO cr_collection
                    (thread_ts, user_id, expires_at, fallback_ask_ts, channel_id)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(thread_ts) DO UPDATE SET
                    user_id=excluded.user_id,
                    expires_at=excluded.expires_at,
                    fallback_ask_ts=excluded.fallback_ask_ts,
                    channel_id=excluded.channel_id
                """,
                (thread_ts, user_id, expires_at, fallback_ask_ts, channel_id),
            )
            self._conn.commit()

    def get_cr_collection(self, *, thread_ts: str,
                          now: int) -> Optional[CRCollectionRow]:
        """Return the row only if present and not expired. Expired rows
        sit around until overwritten or cleared — the read filters them."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM cr_collection WHERE thread_ts = ? AND expires_at > ?",
                (thread_ts, now),
            ).fetchone()
        if row is None:
            return None
        keys = set(row.keys())
        return CRCollectionRow(
            thread_ts=row["thread_ts"], user_id=row["user_id"],
            expires_at=row["expires_at"],
            fallback_ask_ts=row["fallback_ask_ts"] if "fallback_ask_ts" in keys else None,
            channel_id=row["channel_id"] if "channel_id" in keys else None,
        )

    def clear_cr_collection(self, *, thread_ts: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM cr_collection WHERE thread_ts = ?", (thread_ts,)
            )
            self._conn.commit()


# --- helpers ---------------------------------------------------------------

def _row_get(row: sqlite3.Row, key: str):
    """Tolerant Row.__getitem__ — returns None if the column is absent, so
    incident fetches work across schema versions (e.g. read-path code that
    hits a DB that hasn't migrated yet)."""
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


def _row_to_incident(row: sqlite3.Row) -> Incident:
    return Incident(
        slack_ts=row["slack_ts"], channel_id=row["channel_id"],
        posted_at=row["posted_at"], poster_user_id=row["poster_user_id"],
        text_preview=row["text_preview"], permalink=row["permalink"],
        occir_key=row["occir_key"], occir_status=row["occir_status"],
        first_reply_at=row["first_reply_at"], reply_count=row["reply_count"],
        resolved_at=row["resolved_at"], resolved_source=row["resolved_source"],
        resolved_by_user_id=_row_get(row, "resolved_by_user_id"),
        last_swept_at=row["last_swept_at"],
        title_summary=_row_get(row, "title_summary"),
        shift_excluded_at=_row_get(row, "shift_excluded_at"),
        claimed_by_user_id=_row_get(row, "claimed_by_user_id"),
    )


def _row_to_shift_post(row: sqlite3.Row) -> ShiftPost:
    return ShiftPost(
        shift_key=row["shift_key"], slot=row["slot"],
        window_start=row["window_start"], window_end=row["window_end"],
        channel_id=row["channel_id"], message_ts=row["message_ts"],
        posted_at=row["posted_at"], last_updated_at=row["last_updated_at"],
    )


_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS incidents (
    slack_ts         TEXT PRIMARY KEY,
    channel_id       TEXT NOT NULL,
    posted_at        INTEGER NOT NULL,
    poster_user_id   TEXT NOT NULL,
    text_preview     TEXT NOT NULL,
    permalink        TEXT NOT NULL,
    occir_key        TEXT,
    occir_status     TEXT,
    first_reply_at   INTEGER,
    reply_count      INTEGER NOT NULL DEFAULT 0,
    resolved_at      INTEGER,
    resolved_source  TEXT,
    last_swept_at    INTEGER
);
CREATE INDEX IF NOT EXISTS ix_incidents_posted_at ON incidents(posted_at);
CREATE INDEX IF NOT EXISTS ix_incidents_resolved  ON incidents(resolved_at);

CREATE TABLE IF NOT EXISTS thread_replies (
    slack_ts        TEXT PRIMARY KEY,
    incident_ts     TEXT NOT NULL REFERENCES incidents(slack_ts),
    user_id         TEXT NOT NULL,
    posted_at       INTEGER NOT NULL,
    text_preview    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_replies_incident ON thread_replies(incident_ts);

CREATE TABLE IF NOT EXISTS shift_posts (
    shift_key       TEXT PRIMARY KEY,
    slot            TEXT NOT NULL,
    window_start    INTEGER NOT NULL,
    window_end      INTEGER NOT NULL,
    channel_id      TEXT NOT NULL,
    message_ts      TEXT NOT NULL,
    posted_at       INTEGER NOT NULL,
    last_updated_at INTEGER NOT NULL
);
"""

# v2 adds resolved_by_user_id. For fresh DBs the column is already present
# via ALTER on an empty table; for existing DBs this backfills it as NULL.
_SCHEMA_V2 = """
ALTER TABLE incidents ADD COLUMN resolved_by_user_id TEXT;
"""

# v3 adds title_summary — an LLM-distilled concise title.
_SCHEMA_V3 = """
ALTER TABLE incidents ADD COLUMN title_summary TEXT;
"""

# v4 adds escalation_state and handoff_items tables, plus shift_excluded_at
# on incidents (added separately via ALTER TABLE in _migrate for idempotency).
_SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS escalation_state (
    thread_ts        TEXT PRIMARY KEY,
    channel_id       TEXT NOT NULL,
    last_irm_page_at INTEGER,
    silence_until    INTEGER
);

CREATE TABLE IF NOT EXISTS handoff_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    shift_key       TEXT NOT NULL,
    title           TEXT NOT NULL,
    link            TEXT,
    note            TEXT,
    author_user_id  TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_handoff_shift ON handoff_items(shift_key);
"""

# v5 adds cr_collection — the "paste a CR" handoff flag set when an
# operator clicks esc:paste_cr on a fallback-ask. Keyed by the @noc
# post's thread_ts; expires_at is a unix second so reads can filter
# stale rows without a separate sweep.
_SCHEMA_V5 = """
CREATE TABLE IF NOT EXISTS cr_collection (
    thread_ts       TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    fallback_ask_ts TEXT,
    channel_id      TEXT
);
"""

# v6 adds claimed_by_user_id. First @noc/@domains-sre poster/replier owns
# the turnover item; manual Claim button uses the same sticky field.
_SCHEMA_V6 = """
ALTER TABLE incidents ADD COLUMN claimed_by_user_id TEXT;
"""

