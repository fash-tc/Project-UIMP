"""Ingests Slack events into the NOC Turnover store.

Hooks:
  - record_message(event) — from MessageHandler.handle_message (synchronous)
  - link_ticket(channel, ts, occir_key) — from ReactionHandler after :ticket:
  - handle_resolve_reaction(event) — from ReactionHandler for :white_check_mark:/:resolved:
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

from turnover_store import Incident, ThreadReply, TurnoverStore

logger = logging.getLogger(__name__)

# Per-message preview cap. Raised from 300 → 1000 so resolution signals
# (often in paragraph-style replies: "looks like it was a flap, back to
# normal, no further alerts") aren't chopped before the LLM ever sees them.
TEXT_PREVIEW_CHAR_LIMIT = 1000
RESOLVE_REACTIONS = {"white_check_mark", "resolved", "heavy_check_mark"}

# Matches OCCIR-<digits> anywhere in Slack text. We pick the first occurrence
# so a long thread with multiple keys pinned to the original incident.
_OCCIR_RE = re.compile(r"\bOCCIR-\d+\b")

# Matches Jira Change Record keys (CR-NNNN). A top-level post mentioning one
# is an FYI about a scheduled change, not an incident — the bot responds
# with a CR summary instead of escalating, and the turnover list shouldn't
# include it. Case-sensitive on purpose: "cr-1234" in prose is ambiguous.
_CR_RE = re.compile(r"\bCR-\d+\b")


def _extract_occir_key(text: str) -> Optional[str]:
    """Return the first OCCIR-NNNN key found in `text`, or None."""
    if not text:
        return None
    m = _OCCIR_RE.search(text)
    return m.group(0) if m else None


class Ingestor:
    def __init__(self, store: TurnoverStore, slack_client, resolver,
                 ops_noc_channel_id: str, title_summarizer=None,
                 jira_client=None, ollama_url: str = "",
                 ollama_model: str = "", jira_base_url: str = "",
                 group_cache=None):
        self._store = store
        self._slack = slack_client
        self._resolver = resolver
        self._ops_noc = ops_noc_channel_id
        self._title_summarizer = title_summarizer
        self._jira_client = jira_client
        self._ollama_url = ollama_url
        self._ollama_model = ollama_model
        self._jira_base_url = jira_base_url
        self._group_cache = group_cache

    # --- messages -----------------------------------------------------------

    def record_message(self, event: dict) -> None:
        """Record a message event. Never raises."""
        try:
            self._record_message_impl(event)
        except Exception:
            logger.warning("turnover_ingestor: record_message failed", exc_info=True)

    def _record_message_impl(self, event: dict) -> None:
        # Channel filter
        if event.get("channel") != self._ops_noc:
            return
        # Subtype filter (edits, deletes, channel joins, etc.).
        # `thread_broadcast` is a real reply the user chose to echo to the
        # channel — it carries full text + thread_ts, so we DO want to
        # ingest it. It's the most common form of "resolved" post on a
        # live incident (operator announces recovery to the channel),
        # and dropping it starved the LLM classifier of the strongest
        # signal.
        subtype = event.get("subtype")
        if subtype and subtype != "thread_broadcast":
            return
        # Bot messages
        if event.get("bot_id"):
            return

        ts = event.get("ts") or ""
        if not ts:
            return

        thread_ts = event.get("thread_ts")
        user = event.get("user") or ""
        text = (event.get("text") or "")[:TEXT_PREVIEW_CHAR_LIMIT]
        posted_at = int(float(ts))

        is_reply = bool(thread_ts) and thread_ts != ts
        if is_reply:
            self._store.insert_reply(ThreadReply(
                slack_ts=ts, incident_ts=thread_ts,
                user_id=user, posted_at=posted_at, text_preview=text,
            ))
            self._auto_claim_if_team_member(thread_ts, user)
            # If the parent incident has no ticket yet and this reply mentions
            # an OCCIR key, auto-link it. First reply wins.
            key = _extract_occir_key(text)
            if key:
                parent = self._store.get_incident(thread_ts)
                if parent is not None and not parent.occir_key:
                    self._store.link_ticket(thread_ts, key)
                    logger.info(
                        "turnover_ingestor: auto-linked %s to incident %s from reply",
                        key, thread_ts,
                    )
            self._maybe_complete_cr_collection(
                thread_ts=thread_ts, user_id=user, text=text,
            )
            return

        # Top-level post mentioning a Jira CR key — this is a change-record
        # FYI, not an incident. bot.py treats it as a CR summary path rather
        # than an escalation; match that policy here so the turnover list
        # doesn't fill up with scheduled-change posts.
        if _CR_RE.search(text):
            logger.info(
                "turnover_ingestor: skipping CR mention ts=%s (not an incident)", ts,
            )
            return

        # Top-level post — need a permalink
        permalink = self._fetch_permalink(self._ops_noc, ts)
        occir_key = _extract_occir_key(text)
        self._store.insert_incident(Incident(
            slack_ts=ts, channel_id=self._ops_noc,
            posted_at=posted_at, poster_user_id=user,
            text_preview=text, permalink=permalink,
            occir_key=occir_key,
            claimed_by_user_id=user if self._is_team_member(user) else None,
        ))
        if self._title_summarizer is not None:
            self._title_summarizer.submit(ts)

    def _maybe_complete_cr_collection(self, *, thread_ts: str,
                                       user_id: str, text: str) -> None:
        """If a `cr_collection` flag is set for this thread by the replying
        user and the reply contains a CR-NNNN token, fetch the CR from Jira,
        post a summary threaded on the parent incident, edit the fallback-ask
        message to "CR summary posted", and clear the flag.

        Silent no-op on: no jira_client, no flag, expired flag, user
        mismatch, no CR in text, missing CR in Jira, any Slack error."""
        try:
            if self._jira_client is None:
                return
            now = int(time.time())
            row = self._store.get_cr_collection(thread_ts=thread_ts, now=now)
            if row is None:
                return  # no flag or expired
            if row.user_id != user_id:
                return  # silent on user mismatch
            m = _CR_RE.search(text or "")
            if not m:
                return
            cr_key = m.group(0)
            cr_data = self._jira_client.fetch_cr(cr_key)
            if cr_data is None:
                logger.info(
                    "turnover_ingestor: cr_collection: CR %s not found", cr_key,
                )
                return
            # Lazy imports — avoid forcing jira_cr on module import for
            # tests that don't exercise this path.
            from jira_cr import (
                assess_cr_impact, format_cr_slack_message, summarize_cr,
            )
            summary = summarize_cr(cr_data, self._ollama_url, self._ollama_model)
            impact = assess_cr_impact(cr_data, self._ollama_url, self._ollama_model)
            message = format_cr_slack_message(
                cr_data, summary, self._jira_base_url, impact_assessment=impact,
            )
            try:
                self._slack.chat_postMessage(
                    channel=self._ops_noc, thread_ts=thread_ts, text=message,
                )
            except Exception:
                logger.warning(
                    "turnover_ingestor: cr_collection: post summary failed",
                    exc_info=True,
                )
                # Preserve the flag so the next matching reply retries.
                return
            # Best-effort terminal edit on the fallback-ask message
            if row.fallback_ask_ts and row.channel_id:
                try:
                    self._slack.chat_update(
                        channel=row.channel_id, ts=row.fallback_ask_ts,
                        text="CR summary posted.",
                    )
                except Exception:
                    logger.warning(
                        "turnover_ingestor: cr_collection: chat_update failed",
                        exc_info=True,
                    )
            # Clear last — a crash above leaves the flag for a retry.
            self._store.clear_cr_collection(thread_ts=thread_ts)
            logger.info(
                "turnover_ingestor: cr_collection completed %s on %s",
                cr_key, thread_ts,
            )
        except Exception:
            logger.warning(
                "turnover_ingestor: _maybe_complete_cr_collection failed",
                exc_info=True,
            )

    def _fetch_permalink(self, channel: str, ts: str) -> str:
        try:
            resp = self._slack.chat_getPermalink(channel=channel, message_ts=ts)
            link = resp.get("permalink") if isinstance(resp, dict) else None
            if link:
                return link
        except Exception as e:
            logger.warning("turnover_ingestor: permalink fetch failed for %s: %s", ts, e)
        # Fallback — Slack URL shape is stable enough for a link
        return f"https://slack.com/archives/{channel}/p{ts.replace('.', '')}"

    def _is_team_member(self, user_id: str) -> bool:
        if not user_id or self._group_cache is None:
            return False
        try:
            return user_id in self._group_cache.get_members(self._slack)
        except Exception:
            logger.warning(
                "turnover_ingestor: group membership lookup failed",
                exc_info=True,
            )
            return False

    def _auto_claim_if_team_member(self, incident_ts: str, user_id: str) -> None:
        if not self._is_team_member(user_id):
            return
        if self._store.claim_incident(incident_ts, user_id):
            logger.info(
                "turnover_ingestor: auto-claimed %s by team member %s",
                incident_ts, user_id,
            )

    def handle_deleted_message(self, event: dict) -> None:
        """Purge an incident when its source Slack message is deleted.

        Slack delivers `message_deleted` with subtype="message_deleted"; the
        deleted message's ts is in `event.deleted_ts` (or `event.previous_message.ts`).
        We treat this as a hard delete — the incident never existed from the
        channel's point of view, so carryover lists shouldn't keep pointing at
        a 404 permalink."""
        try:
            if event.get("channel") != self._ops_noc:
                return
            deleted_ts = event.get("deleted_ts") or (
                (event.get("previous_message") or {}).get("ts")
            )
            if not deleted_ts:
                return
            # Only purge top-level incidents; replies fall off naturally with parent.
            if self._store.get_incident(deleted_ts) is not None:
                self._store.delete_incident(deleted_ts)
                logger.info("turnover_ingestor: purged deleted incident %s", deleted_ts)
        except Exception:
            logger.warning("turnover_ingestor: handle_deleted_message failed", exc_info=True)

    # --- ticket linkage -----------------------------------------------------

    def link_ticket(self, channel: str, message_ts: str, occir_key: str) -> None:
        """Called by ReactionHandler after successful OCCIR ticket creation."""
        try:
            if channel != self._ops_noc:
                return
            if self._store.get_incident(message_ts) is None:
                logger.debug("turnover_ingestor: link_ticket skipped (unknown ts %s)",
                              message_ts)
                return
            self._store.link_ticket(message_ts, occir_key)
        except Exception:
            logger.warning("turnover_ingestor: link_ticket failed", exc_info=True)

    # --- resolve reactions --------------------------------------------------

    def handle_resolve_reaction(self, event: dict) -> None:
        """Called by ReactionHandler for every reaction_added event."""
        try:
            if event.get("reaction") not in RESOLVE_REACTIONS:
                return
            item = event.get("item") or {}
            if item.get("channel") != self._ops_noc:
                return
            ts = item.get("ts") or ""
            if not ts or self._store.get_incident(ts) is None:
                return
            reactor = event.get("user") or None
            self._resolver.mark_resolved(ts, source="reaction",
                                          by_user_id=reactor)
        except Exception:
            logger.warning("turnover_ingestor: handle_resolve_reaction failed", exc_info=True)
