"""Incident channel creator — 9-step orchestrator.

Step 3 (store.claim) is the single atomic checkpoint. Every step after
it is best-effort with log-and-continue (Invariant #6, #7). Nothing is
ever rolled back: if invite fails after the claim, the channel still
exists and is usable; operator can /invite manually.

All Slack I/O goes through the injected slack_client for testability.
"""
from __future__ import annotations

import logging
import time
from datetime import date
from typing import Callable, Optional

from slack_sdk.errors import SlackApiError

from incident_channel import (
    compute_channel_name,
    render_initial_post,
    render_resolved_button,
    SLACK_CHANNEL_MAX_LEN,
)
from incident_channel_store import (
    IncidentChannelEntry,
    IncidentChannelStore,
)

logger = logging.getLogger(__name__)

MAX_NAME_COLLISION_RETRIES = 5
INVITE_RETRY_SLEEP_CEILING_SECONDS = 30


class IncidentChannelCreator:
    """Runs the 9-step create-and-populate flow."""

    def __init__(
        self,
        *,
        slack_client,
        store: IncidentChannelStore,
        group_cache,
        close_questionnaire_cb: Callable,
        ops_noc_channel_id: str,
    ):
        self._slack = slack_client
        self._store = store
        self._group_cache = group_cache
        self._close_questionnaire = close_questionnaire_cb
        self._ops_noc_channel_id = ops_noc_channel_id

    def create_and_populate(
        self,
        *,
        thread_ts: str,
        origin_channel: str,
        escalator_user_id: str,
        slug: str,
        slug_source: str,  # "llm" | "fallback"
        op_user_id: str,
        initial_participants: list[str],
        origin_thread_url: str,
        questionnaire_state,
    ) -> Optional[str]:
        """Returns the new channel_id on success, None on pre-claim failure."""
        existing = self._store.get(thread_ts)
        if existing is not None:
            self._post_already_escalated(origin_channel, thread_ts, existing)
            return existing.channel_id

        channel_id, channel_name = self._create_with_retries(
            today=date.today(), slug=slug, origin_channel=origin_channel,
            thread_ts=thread_ts,
        )
        if channel_id is None:
            return None

        entry, created = self._store.claim(
            thread_ts=thread_ts,
            origin_channel=origin_channel,
            channel_id=channel_id,
            channel_name=channel_name,
            created_by=escalator_user_id,
            slug_source=slug_source,
            op_user_id=op_user_id,
            initial_participants=initial_participants,
        )
        if not created:
            logger.warning("iq:create: lost claim race for %s; archiving "
                           "orphan channel %s", thread_ts, channel_id)
            try:
                self._slack.conversations_archive(channel=channel_id)
            except Exception:
                logger.warning("iq:create: orphan archive failed",
                               exc_info=True)
            self._post_already_escalated(origin_channel, thread_ts, entry)
            return entry.channel_id

        self._safe_invite(
            channel_id=channel_id,
            thread_ts=thread_ts,
            initial_participants=initial_participants,
            op_user_id=op_user_id,
            escalator_user_id=escalator_user_id,
        )

        metadata_ts = self._safe_post_metadata(
            channel_id, questionnaire_state, origin_thread_url,
            escalator_user_id, op_user_id,
        )
        if metadata_ts:
            self._store.set_initial_post_ts(thread_ts, metadata_ts)
            self._safe_pin(channel_id, metadata_ts)

        resolved_ts = self._safe_post_resolved_button(channel_id)
        if resolved_ts:
            self._store.set_resolved_button_ts(thread_ts, resolved_ts)
            self._safe_pin(channel_id, resolved_ts)

        self._safe_post_thread_notice(origin_channel, thread_ts, channel_id)

        self._safe_close_questionnaire(thread_ts, escalator_user_id)

        return channel_id

    # --- helpers ---------------------------------------------------------

    def _post_already_escalated(self, origin_channel: str, thread_ts: str,
                                entry) -> None:
        try:
            self._slack.chat_postMessage(
                channel=origin_channel, thread_ts=thread_ts,
                text=f"This thread is already escalated — see <#{entry.channel_id}>.",
                unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("iq:create: already-escalated notice failed",
                           exc_info=True)

    def _post_thread_error(self, origin_channel, thread_ts, msg):
        try:
            self._slack.chat_postMessage(
                channel=origin_channel, thread_ts=thread_ts,
                text=msg, unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("iq:create: thread-error notice failed",
                           exc_info=True)

    def _create_with_retries(self, *, today: date, slug: str,
                             origin_channel: str, thread_ts: str):
        """Step 1-2. Returns (channel_id, channel_name) on success,
        (None, None) on any pre-claim failure (name collision exhausted,
        missing scope, other API error)."""
        for attempt in range(MAX_NAME_COLLISION_RETRIES + 1):
            suffix = attempt + 1 if attempt > 0 else None
            name = compute_channel_name(today, slug, collision_suffix=suffix)
            try:
                resp = self._slack.conversations_create(
                    name=name, is_private=False,
                )
                channel_id = resp["channel"]["id"]
                return channel_id, name
            except SlackApiError as e:
                err = e.response.get("error") if e.response else None
                if err == "name_taken":
                    continue
                logger.warning("iq:create: conversations.create failed "
                               "(%s)", err, exc_info=True)
                self._post_thread_error(
                    origin_channel, thread_ts,
                    f"Couldn't create incident channel: `{err}`.",
                )
                return None, None
            except Exception:
                logger.warning("iq:create: conversations.create "
                               "unexpected", exc_info=True)
                self._post_thread_error(
                    origin_channel, thread_ts,
                    "Couldn't create incident channel — internal error.",
                )
                return None, None

        logger.warning("iq:create: name_taken exhausted %d retries for "
                       "slug=%s", MAX_NAME_COLLISION_RETRIES, slug)
        self._post_thread_error(
            origin_channel, thread_ts,
            "Couldn't create incident channel: name collisions.",
        )
        return None, None

    def _safe_invite(
        self, *, channel_id: str, thread_ts: str,
        initial_participants: list[str],
        op_user_id: str, escalator_user_id: str,
    ) -> None:
        """Expand subteams, dedup, single batch invite with one 429 retry.

        Partial-success errors (ok=True, errors[]) are logged and
        swallowed per invariant #6 and spec advisory #2.
        """
        subteam_members = set()
        try:
            subteam_members = self._group_cache.get_members(self._slack)
        except Exception:
            logger.warning("iq:create: group_cache.get_members failed",
                           exc_info=True)

        users = set()
        users.update(subteam_members)
        users.update(initial_participants)
        users.add(op_user_id)
        users.add(escalator_user_id)
        users_csv = ",".join(sorted(u for u in users if u))

        for attempt in range(2):
            try:
                resp = self._slack.conversations_invite(
                    channel=channel_id, users=users_csv,
                )
                errs = (resp or {}).get("errors") or []
                for err in errs:
                    logger.warning(
                        "iq:create: invite per-user error user=%s error=%s",
                        err.get("user"), err.get("error"),
                    )
                return
            except SlackApiError as e:
                code = e.response.get("error") if e.response else None
                if code == "ratelimited" and attempt == 0:
                    retry_after = 1
                    try:
                        retry_after = int(
                            e.response.headers.get("Retry-After", "1")
                        )
                    except Exception:
                        pass
                    time.sleep(min(retry_after, INVITE_RETRY_SLEEP_CEILING_SECONDS))
                    continue
                logger.warning("iq:create: invite failed (%s)", code,
                               exc_info=True)
                return
            except Exception:
                logger.warning("iq:create: invite unexpected failure",
                               exc_info=True)
                return

    def _safe_post_metadata(self, channel_id, state, origin_url,
                            escalator_user_id, op_user_id):
        try:
            blocks = render_initial_post(
                state, origin_url=origin_url,
                escalator_user_id=escalator_user_id,
                op_user_id=op_user_id,
            )
            resp = self._slack.chat_postMessage(
                channel=channel_id, blocks=blocks,
                text="Incident channel opened.",
                unfurl_links=False, unfurl_media=False,
            )
            return resp.get("ts")
        except Exception:
            logger.warning("iq:create: metadata post failed", exc_info=True)
            return None

    def _safe_post_resolved_button(self, channel_id):
        try:
            blocks = render_resolved_button()
            resp = self._slack.chat_postMessage(
                channel=channel_id, blocks=blocks,
                text="Click Resolved when the incident is over.",
                unfurl_links=False, unfurl_media=False,
            )
            return resp.get("ts")
        except Exception:
            logger.warning("iq:create: resolved-button post failed",
                           exc_info=True)
            return None

    def _safe_pin(self, channel_id, ts):
        try:
            self._slack.pins_add(channel=channel_id, timestamp=ts)
        except Exception:
            logger.warning("iq:create: pin add failed", exc_info=True)

    def _safe_post_thread_notice(self, origin_channel, thread_ts, channel_id):
        try:
            self._slack.chat_postMessage(
                channel=origin_channel, thread_ts=thread_ts,
                text=f"Moving conversation to <#{channel_id}>.",
                unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("iq:create: thread-notice post failed",
                           exc_info=True)

    def _safe_close_questionnaire(self, thread_ts, escalator_user_id):
        try:
            self._close_questionnaire(
                thread_ts=thread_ts, reason="escalated",
                closed_by=escalator_user_id,
            )
        except Exception:
            logger.warning("iq:create: close questionnaire failed",
                           exc_info=True)
