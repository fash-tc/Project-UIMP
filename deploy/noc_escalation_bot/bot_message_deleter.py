"""Handle :wastebasket: reactions that let authorized users delete bot posts.

Slack only lets the message author (the bot) or workspace admins delete bot
messages. To give @noc / @domains-sre members an equivalent affordance, we
listen for a `:wastebasket:` reaction on a bot message and call chat_delete
on their behalf after verifying group membership.

After a successful delete we also purge any scheduler state tied to the
deleted ts (a stale turnover shift_posts row or change_tracker message_ts),
so the next scheduler tick doesn't try to edit a message that no longer
exists.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

DELETE_REACTION = "wastebasket"


class BotMessageDeleter:
    def __init__(self, slack_client, group_cache,
                 turnover_coordinator=None, change_tracker=None,
                 bot_user_id: Optional[str] = None):
        self._slack = slack_client
        self._group_cache = group_cache
        self._turnover = turnover_coordinator
        self._change_tracker = change_tracker
        self._bot_user_id = bot_user_id  # may be None; we fall back to bot_id check

    def handle_reaction(self, event: dict) -> None:
        """Process a `reaction_added` event. Never raises."""
        try:
            self._handle_impl(event)
        except Exception:
            logger.warning("bot_message_deleter: handle_reaction failed", exc_info=True)

    def _handle_impl(self, event: dict) -> None:
        if event.get("reaction") != DELETE_REACTION:
            return
        item = event.get("item") or {}
        if item.get("type") != "message":
            return
        channel = item.get("channel")
        ts = item.get("ts")
        reactor = event.get("user")
        if not channel or not ts or not reactor:
            return

        # Gate on group membership. Fail closed if cache yields nothing.
        members = self._group_cache.get_members(self._slack)
        if reactor not in members:
            logger.debug(
                "bot_message_deleter: %s reacted :wastebasket: on %s but is not "
                "in @noc / @domains-sre — ignoring", reactor, ts,
            )
            return

        # Confirm the target is actually one of our bot's posts so we don't
        # try to delete user messages (Slack would reject, but best to skip).
        if not self._is_our_bot_message(channel, ts):
            logger.debug("bot_message_deleter: %s is not a bot message, skipping", ts)
            return

        try:
            self._slack.chat_delete(channel=channel, ts=ts)
            logger.info(
                "bot_message_deleter: deleted bot message %s in %s at %s's request",
                ts, channel, reactor,
            )
        except Exception as e:
            logger.warning(
                "bot_message_deleter: chat_delete failed for %s/%s: %s",
                channel, ts, e,
            )
            return

        # Clean up scheduler state so the next tick doesn't try to edit the
        # message we just deleted.
        self._purge_scheduler_state(channel, ts)

    def _is_our_bot_message(self, channel: str, ts: str) -> bool:
        """Return True iff the referenced message was posted by our bot."""
        try:
            resp = self._slack.conversations_history(
                channel=channel, latest=ts, inclusive=True, limit=1,
            )
        except Exception as e:
            logger.warning(
                "bot_message_deleter: conversations_history failed for %s/%s: %s",
                channel, ts, e,
            )
            return False
        messages = resp.get("messages") or []
        if not messages:
            return False
        msg = messages[0]
        if msg.get("ts") != ts:
            return False
        # A message we posted has a bot_id set. If we also know our bot's user
        # id, match on that too — some integrations carry both.
        if msg.get("bot_id"):
            if self._bot_user_id and msg.get("user") and msg.get("user") != self._bot_user_id:
                return False
            return True
        return False

    def _purge_scheduler_state(self, channel: str, ts: str) -> None:
        if self._turnover is not None:
            try:
                store = self._turnover.store
                for sp in store.all_shift_posts():
                    if sp.channel_id == channel and sp.message_ts == ts:
                        store.delete_shift_post(sp.shift_key)
                        logger.info(
                            "bot_message_deleter: purged shift_post %s after delete",
                            sp.shift_key,
                        )
                        break
            except Exception:
                logger.warning(
                    "bot_message_deleter: turnover state purge failed",
                    exc_info=True,
                )

        if self._change_tracker is not None:
            try:
                state = getattr(self._change_tracker, "_state", None)
                if state is not None and state.channel_id == channel and state.message_ts == ts:
                    state.message_ts = ""
                    # Keep channel_id + entries so next poll reposts fresh.
                    state.save()
                    logger.info(
                        "bot_message_deleter: cleared change_tracker message_ts after delete",
                    )
            except Exception:
                logger.warning(
                    "bot_message_deleter: change_tracker state purge failed",
                    exc_info=True,
                )


