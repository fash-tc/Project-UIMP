"""Slack `block_actions` and `view_submission` handlers.

All interactions on bot-authored posts land here: escalation ack buttons,
turnover per-incident overflow menus, the turnover global actions row,
and the handoff-item modal. `BotActions(...).register(app)` wires every
listener; dependencies are injected.

Actions gated on @noc / @domains-sre membership route through
`_is_privileged`, which fails closed if the group cache is cold.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import datetime
from typing import Callable, Optional
from zoneinfo import ZoneInfo

from turnover_reporter import build_shift_report

logger = logging.getLogger(__name__)

COOL_DOWN_DEFAULT = 300  # 5 minutes


def _truncate_report_fallback(text: str, limit: int = 3500) -> str:
    prefix = "Warning: couldn't DM private report. Fallback copy:\n\n"
    budget = max(0, limit - len(prefix))
    if len(text) <= budget:
        return prefix + text
    return prefix + text[:max(0, budget - 25)].rstrip() + "\n... truncated"


class BotActions:
    def __init__(self, *, slack_client, irm_client, occir_client,
                 reaction_handler, turnover, group_cache,
                 bot_user_id: Optional[str], oncall_schedule_id: str,
                 manager_chain_id: str, reescalate_cooldown_sec: int,
                 activity, p3_prompts=None,
                  close_questionnaire=None,
                  post_incident_questionnaire=None,
                  create_channel=None,
                  resolve_incident=None,
                  incident_channel_store=None,
                  jira_base_url: str = ""):
        self._slack = slack_client
        self._irm = irm_client
        self._occir = occir_client
        self._reactor = reaction_handler
        self._turnover = turnover  # TurnoverCoordinator; has .store, .resolver, .scheduler
        self._groups = group_cache
        self._bot_user_id = bot_user_id
        self._oncall_schedule_id = oncall_schedule_id
        self._manager_chain_id = manager_chain_id
        self._reescalate_cooldown = reescalate_cooldown_sec
        self._activity = activity
        self._p3_prompts = p3_prompts
        self._close_questionnaire_cb = close_questionnaire
        self._post_iq_cb = post_incident_questionnaire
        self._create_channel_cb = create_channel
        self._resolve_incident_cb = resolve_incident
        self._incident_channel_store = incident_channel_store
        self._jira_base_url = jira_base_url
        self._refresh_rate_limit: dict[str, float] = {}
        self._refresh_lock = threading.Lock()
        self._oncall_cache: tuple[float, list[str]] = (0.0, [])
        self._oncall_cache_lock = threading.Lock()

    # --- helpers -----------------------------------------------------------

    def _is_privileged(self, user_id: str) -> bool:
        try:
            members = self._groups.get_members(self._slack)
        except Exception:
            logger.warning("bot_actions: group_cache failed", exc_info=True)
            members = set()
        if not members:
            return False
        return user_id in members

    def _decode_value(self, value: str) -> tuple[str, str]:
        """Decode `thread_ts|channel_id` from an action value."""
        ts, _, ch = value.partition("|")
        return ts, ch

    def _ephemeral(self, client, body, text: str) -> None:
        """Post an ephemeral via chat_postEphemeral.

        We deliberately do NOT use Bolt's `respond()` helper here: for
        `block_actions`, the response_url it writes to defaults to
        `replace_original: true`, which silently edits the original
        turnover / escalation-ack post into the ephemeral text. That
        destroyed the interactive post on every click.

        This helper is reserved for FAILURES (privilege denied, rate
        limit, on-call lookup, etc.) — successful actions should rely on
        the re-render for feedback and not post any visible message.
        """
        try:
            user = (body.get("user") or {}).get("id") or ""
            container = body.get("container") or {}
            channel = container.get("channel_id") or (
                (body.get("channel") or {}).get("id")
            )
            if not channel or not user:
                return
            # Thread the ephemeral back into the same thread the button was
            # clicked from, so the reply appears where the operator is
            # looking. Priority: container.thread_ts (present for
            # block_actions inside threads) > message.thread_ts > message.ts
            # (when the message IS the thread parent). Falls through to an
            # unthreaded ephemeral when none apply — e.g. buttons on a
            # top-level turnover row.
            message = body.get("message") or {}
            thread_ts = (
                container.get("thread_ts")
                or message.get("thread_ts")
            )
            kwargs = {"channel": channel, "user": user, "text": text}
            if thread_ts:
                kwargs["thread_ts"] = thread_ts
            client.chat_postEphemeral(**kwargs)
        except Exception:
            logger.warning("bot_actions: chat_postEphemeral failed", exc_info=True)

    def _safe(self, handler):
        # NOTE: deliberately NOT using @functools.wraps. Bolt introspects the
        # listener's signature with inspect.signature() to decide which args
        # to inject; wraps() would expose the inner handler's (ack-less)
        # signature and Bolt would skip passing `ack`, crashing the call.
        def wrapped(ack, body, respond, client):
            ack()
            try:
                return handler(body=body, respond=respond, client=client)
            except Exception as e:
                logger.warning("bot_actions: %s failed",
                               handler.__name__, exc_info=True)
                self._ephemeral(client, body,
                                f"⚠️ Action failed: {type(e).__name__}")
        wrapped.__name__ = f"safe_{handler.__name__}"
        return wrapped

    # --- entry point -------------------------------------------------------

    def register(self, app) -> None:
        """Wire every @app.action / @app.view handler. Called once at boot."""
        app.action("esc:re_escalate")(self._safe(self._on_esc_re_escalate))
        app.action("esc:page_manager")(self._safe(self._on_esc_page_manager))
        app.action("esc:oncall")(self._safe(self._on_esc_oncall))
        app.action("esc:resolve")(self._safe(self._on_esc_resolve))
        app.action("esc:ticket")(self._safe(self._on_esc_ticket))
        app.action("esc:silence")(self._safe(self._on_esc_silence))
        app.action("esc:page")(self._safe(self._on_esc_page))
        app.action("esc:paste_cr")(self._safe(self._on_esc_paste_cr))
        app.action("p3:page")(self._safe(self._on_p3_page))
        app.action("p3:dismiss")(self._safe(self._on_p3_dismiss))

        app.action(re.compile(r"^iq:impact:"))(self._safe(self._on_iq_impact))
        app.action("iq:channel")(self._on_iq_channel)
        from incident_channel import ACTION_ADD_TRANSCRIPT, ACTION_RESOLVED
        app.action(ACTION_RESOLVED)(self._on_iq_channel_resolved)
        app.action(ACTION_ADD_TRANSCRIPT)(self._on_iq_add_transcript)
        app.action("iq:resolved")(self._safe(self._on_iq_resolved))
        # v1.1 deprecation shim: pre-1.1 posts in flight may fire
        # iq:sev:* or iq:ticket:* action_ids for up to 24h after deploy
        # (incident_questionnaire_ttl_sec). Ack silently so users don't
        # see a Slack "unhandled action" error. Safe to remove once the
        # TTL window elapses.
        app.action(re.compile(r"^iq:(sev|ticket):"))(self._on_iq_legacy_sev_ticket)

        # Bolt expects a compiled Pattern here, not a dict — `{"re": "..."}`
        # tripped the middleware with "must be either str or Pattern".
        app.action(re.compile(r"^t_row:"))(self._safe(self._on_turnover_row))
        app.action("t_refresh")(self._safe(self._on_turnover_refresh))
        app.action("t_add_handoff")(self._safe(self._on_turnover_add_handoff))
        app.action("t_report")(self._safe(self._on_turnover_report))
        app.action("t_delete")(self._safe(self._on_turnover_delete))

        app.view("turnover_handoff_add")(self._safe(self._on_handoff_submit))
        app.view("incident_channel_confirm")(self._on_iq_channel_confirm)
        app.view("incident_transcript_add")(self._on_iq_transcript_submit)

    # Escalation ack button handlers (Task 13).
    #
    # Success paths here intentionally do NOT post any user-visible
    # message: Grafana firing a new page or the ticket link appearing in
    # the thread provides the real signal. Only post an ephemeral when the
    # click did NOT fire (silence gate, cooldown, privilege denied, error)
    # so the clicker knows why nothing happened.
    def _on_esc_re_escalate(self, body, respond, client):
        ts, channel = self._decode_value(body["actions"][0]["value"])
        clicker = body["user"]["id"]
        es = self._turnover.store.get_escalation_state(ts)
        now = int(time.time())
        if es and es.silence_until and es.silence_until > now:
            remaining = es.silence_until - now
            self._ephemeral(client, body,
                            f"🔇 Thread silenced for another {remaining}s.")
            return
        if es and es.last_irm_page_at and (now - es.last_irm_page_at) < self._reescalate_cooldown:
            remaining = self._reescalate_cooldown - (now - es.last_irm_page_at)
            self._ephemeral(
                client, body,
                f"⏳ Wait {remaining}s — last page fired {now - es.last_irm_page_at}s ago.",
            )
            return
        permalink = self._slack.chat_getPermalink(
            channel=channel, message_ts=ts,
        ).get("permalink", "")
        self._irm.escalate(
            title="NOC Re-escalation",
            message=f"re-escalated by <@{clicker}>",
            source_link=permalink,
        )
        self._turnover.store.record_irm_page(ts, channel, now)
        self._activity.add("button_re_escalate", f"{ts} by {clicker}", user=clicker)

    def _on_esc_page_manager(self, body, respond, client):
        ts, channel = self._decode_value(body["actions"][0]["value"])
        clicker = body["user"]["id"]
        permalink = self._slack.chat_getPermalink(
            channel=channel, message_ts=ts,
        ).get("permalink", "")
        self._irm.escalate(
            title="NOC escalation to Manager",
            message=f"manager-paged by <@{clicker}>",
            source_link=permalink,
            escalation_chain_id=self._manager_chain_id,
        )
        self._activity.add("button_page_manager", f"{ts} by {clicker}", user=clicker)

    def _on_esc_oncall(self, body, respond, client):
        # The ONE button whose entire purpose is to show text, so we DO
        # post an ephemeral with the roster.
        with self._oncall_cache_lock:
            at, names = self._oncall_cache
            if time.time() - at < 60:
                cached = names
            else:
                cached = None
        if cached is None:
            names = self._irm.get_oncall(self._oncall_schedule_id)
            with self._oncall_cache_lock:
                self._oncall_cache = (time.time(), names)
        else:
            names = cached
        if not names:
            self._ephemeral(client, body, "⚠️ Couldn't fetch on-call roster.")
            return
        self._ephemeral(client, body, f"👥 On-call now: {', '.join(names)}")

    def _on_esc_resolve(self, body, respond, client):
        clicker = body["user"]["id"]
        if not self._is_privileged(clicker):
            self._ephemeral(client, body,
                            "Only @noc / @domains-sre can use this action.")
            return
        ts, _ch = self._decode_value(body["actions"][0]["value"])
        self._turnover.resolver.mark_resolved(
            ts, source="button", by_user_id=clicker,
        )
        self._activity.add("button_resolve", f"{ts} by {clicker}", user=clicker)

    def _on_esc_ticket(self, body, respond, client):
        clicker = body["user"]["id"]
        if not self._is_privileged(clicker):
            self._ephemeral(client, body,
                            "Only @noc / @domains-sre can use this action.")
            return
        ts, channel = self._decode_value(body["actions"][0]["value"])
        key = self._reactor.create_occir(
            channel=channel, ts=ts, requested_by=clicker, occir_work_type="incident"
        )
        if not key:
            self._ephemeral(client, body,
                            "⚠️ Ticket creation skipped (already ticketed or error).")
            return
        self._activity.add("button_ticket", f"{ts} → {key} by {clicker}", user=clicker)

    def _on_esc_silence(self, body, respond, client):
        clicker = body["user"]["id"]
        if not self._is_privileged(clicker):
            self._ephemeral(client, body,
                            "Only @noc / @domains-sre can use this action.")
            return
        ts, channel = self._decode_value(body["actions"][0]["value"])
        until = int(time.time()) + 3600
        self._turnover.store.set_silence(ts, channel, until)
        self._activity.add("button_silence", f"{ts} +1h by {clicker}", user=clicker)

    def _on_esc_paste_cr(self, body, respond, client):
        """Fallback-ask :clipboard: button. Flags the thread for CR
        collection and prompts the clicker to reply with a CR-NNNN."""
        original_ts, channel = self._decode_value(body["actions"][0]["value"])
        clicker = body["user"]["id"]
        now = int(time.time())
        expires_at = now + 600  # 10 min

        # Persist fallback_ask_ts + channel so the ingestor's
        # completion path can post the third terminal edit ("CR summary
        # posted") on this very message when the CR eventually arrives.
        fallback_ts = (body.get("message") or {}).get("ts") or (
            (body.get("container") or {}).get("message_ts")
        )
        self._turnover.store.set_cr_collection(
            thread_ts=original_ts, user_id=clicker, expires_at=expires_at,
            fallback_ask_ts=fallback_ts, channel_id=channel,
        )

        # Ephemeral threaded on the ORIGINAL @noc post, not the fallback
        # ask's ts — operator expects the conversation to stay in the
        # original thread. Call chat_postEphemeral directly to override
        # the _ephemeral helper's default thread_ts resolution.
        try:
            client.chat_postEphemeral(
                channel=channel, user=clicker, thread_ts=original_ts,
                text="Reply with the `CR-NNNN` and I'll post a summary.",
            )
        except Exception:
            logger.warning("bot_actions: paste_cr ephemeral failed", exc_info=True)

        if fallback_ts:
            try:
                self._slack.chat_update(
                    channel=channel, ts=fallback_ts,
                    text=f":clipboard: Waiting for CR from <@{clicker}>",
                    blocks=[{"type": "section", "text": {"type": "mrkdwn",
                            "text": f":clipboard: Waiting for CR from <@{clicker}>"}}],
                )
            except Exception:
                logger.warning("bot_actions: paste_cr chat_update failed", exc_info=True)

        self._activity.add("button_paste_cr", f"{original_ts} by {clicker}", user=clicker)

    def _on_esc_page(self, body, respond, client):
        """Fallback-ask :rotating_light: button. Re-runs the escalation
        path using the original @noc post's text (re-fetched from Slack;
        the pending entry is always gone by the time this button exists
        because the sweep popped it to post the fallback-ask)."""
        original_ts, channel = self._decode_value(body["actions"][0]["value"])
        clicker = body["user"]["id"]
        # Re-fetch original text — single source of truth.
        try:
            resp = self._slack.conversations_history(
                channel=channel, latest=original_ts, limit=1, inclusive=True,
            )
            msgs = resp.get("messages") or []
            original_text = msgs[0].get("text") if msgs else ""
        except Exception:
            logger.warning("bot_actions: esc:page history fetch failed", exc_info=True)
            original_text = ""
        permalink = self._slack.chat_getPermalink(
            channel=channel, message_ts=original_ts,
        ).get("permalink", "")
        self._irm.escalate(
            title="NOC Escalation (fallback-ask)",
            message=f"<@{clicker}> paged after classifier wait: {original_text}",
            source_link=permalink,
        )
        self._turnover.store.record_irm_page(original_ts, channel, int(time.time()))
        self._activity.add("button_esc_page", f"{original_ts} by {clicker}", user=clicker)
        # Match the full escalation path: rotating_light reaction on the
        # @noc post + escalation-ack block-kit reply threaded on the
        # original post, with the same button row the auto-escalation
        # path posts.
        try:
            self._slack.reactions_add(
                channel=channel, timestamp=original_ts, name="rotating_light",
            )
        except Exception:
            logger.warning("bot_actions: esc:page reactions_add failed", exc_info=True)
        try:
            from turnover_renderer import render_escalation_ack_blocks
            hhmm = datetime.now(ZoneInfo("America/New_York")).strftime("%H:%M")
            inc = self._turnover.store.get_incident(original_ts)
            has_ticket = bool(inc and getattr(inc, "occir_key", None))
            fallback_text, blocks = render_escalation_ack_blocks(
                thread_ts=original_ts, channel_id=channel,
                escalator_name=f"<@{clicker}>", escalated_at_et=hhmm,
                has_ticket=has_ticket, is_test=False,
            )
            self._slack.chat_postMessage(
                channel=channel, thread_ts=original_ts,
                text=fallback_text, blocks=blocks,
                unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("bot_actions: esc:page ack block failed", exc_info=True)

        # Edit the fallback-ask message to its terminal state.
        fallback_ts = (body.get("message") or {}).get("ts") or (
            (body.get("container") or {}).get("message_ts")
        )
        if fallback_ts:
            try:
                hhmm = datetime.now(ZoneInfo("America/New_York")).strftime("%H:%M")
                self._slack.chat_update(
                    channel=channel, ts=fallback_ts,
                    text=f":rotating_light: Paged by <@{clicker}> at {hhmm} ET",
                    blocks=[{"type": "section", "text": {"type": "mrkdwn",
                            "text": (f":rotating_light: Paged by <@{clicker}> "
                                     f"at {hhmm} ET")}}],
                )
            except Exception:
                logger.warning("bot_actions: esc:page chat_update failed", exc_info=True)

    def _on_p3_page(self, body, respond, client):
        """P3 'Page on-call' button. Any channel member can click.

        Claim: `self._p3_prompts.remove(original_ts)`. Whether we won
        or lost the claim, we escalate and edit the prompt — Page is
        intent-bearing (see spec §'Race: click and sweep'). If sweep
        already edited the prompt to 'No response — not escalated', we
        overwrite it; this is correct: the page DID happen."""
        original_ts, channel = self._decode_value(body["actions"][0]["value"])
        clicker = body["user"]["id"]

        if self._p3_prompts is not None:
            self._p3_prompts.remove(original_ts)  # return value ignored on Page

        try:
            resp = self._slack.conversations_history(
                channel=channel, latest=original_ts, limit=1, inclusive=True,
            )
            msgs = resp.get("messages") or []
            original_text = msgs[0].get("text") if msgs else ""
        except Exception:
            logger.warning("bot_actions: p3:page history fetch failed",
                           exc_info=True)
            original_text = ""

        try:
            permalink = self._slack.chat_getPermalink(
                channel=channel, message_ts=original_ts,
            ).get("permalink", "")
        except Exception:
            permalink = ""

        try:
            self._irm.escalate(
                title="NOC Escalation (P3 untagged)",
                message=f"<@{clicker}> paged via P3 prompt: {original_text}",
                source_link=permalink,
            )
            self._turnover.store.record_irm_page(
                original_ts, channel, int(time.time()),
            )
        except Exception:
            logger.warning("bot_actions: p3:page IRM escalate failed",
                           exc_info=True)

        self._activity.add("button_p3_page",
                           f"{original_ts} by {clicker}", user=clicker)

        try:
            self._slack.reactions_add(
                channel=channel, timestamp=original_ts, name="rotating_light",
            )
        except Exception:
            logger.warning("bot_actions: p3:page reactions_add failed",
                           exc_info=True)

        try:
            from turnover_renderer import render_escalation_ack_blocks
            hhmm = datetime.now(ZoneInfo("America/New_York")).strftime("%H:%M")
            inc = self._turnover.store.get_incident(original_ts)
            has_ticket = bool(inc and getattr(inc, "occir_key", None))
            fallback_text, blocks = render_escalation_ack_blocks(
                thread_ts=original_ts, channel_id=channel,
                escalator_name=f"<@{clicker}>", escalated_at_et=hhmm,
                has_ticket=has_ticket, is_test=False,
            )
            self._slack.chat_postMessage(
                channel=channel, thread_ts=original_ts,
                text=fallback_text, blocks=blocks,
                unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("bot_actions: p3:page ack block failed",
                           exc_info=True)

        prompt_ts = (body.get("message") or {}).get("ts") or (
            (body.get("container") or {}).get("message_ts")
        )
        if prompt_ts:
            try:
                hhmm = datetime.now(ZoneInfo("America/New_York")).strftime("%H:%M")
                text = f":rotating_light: Paged by <@{clicker}> at {hhmm} ET"
                self._slack.chat_update(
                    channel=channel, ts=prompt_ts, text=text,
                    blocks=[{"type": "section", "text":
                             {"type": "mrkdwn", "text": text}}],
                )
            except Exception:
                logger.warning("bot_actions: p3:page chat_update failed",
                               exc_info=True)

        if self._post_iq_cb is not None:
            try:
                self._post_iq_cb(channel, original_ts)
            except Exception:
                logger.warning("bot_actions: p3:page post_iq_cb failed",
                               exc_info=True)

    def _on_p3_dismiss(self, body, respond, client):
        """P3 'Not an incident' button. Any channel member can click.

        Dismiss is cosmetic. If the claim is lost (sweep or prior click
        already popped), do nothing — the prompt is already in a
        terminal state. See spec §'Race: click and sweep'."""
        original_ts, channel = self._decode_value(body["actions"][0]["value"])
        clicker = body["user"]["id"]

        if self._p3_prompts is None:
            return
        claimed = self._p3_prompts.remove(original_ts)
        if claimed is None:
            return

        self._activity.add("button_p3_dismiss",
                           f"{original_ts} by {clicker}", user=clicker)

        prompt_ts = (body.get("message") or {}).get("ts") or (
            (body.get("container") or {}).get("message_ts")
        )
        if not prompt_ts:
            return
        try:
            hhmm = datetime.now(ZoneInfo("America/New_York")).strftime("%H:%M")
            text = f":white_check_mark: Dismissed by <@{clicker}> at {hhmm} ET"
            self._slack.chat_update(
                channel=channel, ts=prompt_ts, text=text,
                blocks=[{"type": "section", "text":
                         {"type": "mrkdwn", "text": text}}],
            )
        except Exception:
            logger.warning("bot_actions: p3:dismiss chat_update failed",
                           exc_info=True)

    def _on_iq_resolved(self, body, respond, client):
        """Resolved button -> delegate to MessageHandler._close_questionnaire
        via injected callback. Callback is None in early tests / before
        startup back-fill; no-op in that case (the questionnaire is still
        closeable via TTL)."""
        value = body["actions"][0].get("value", "")
        thread_ts, _channel = self._decode_value(value)
        if not thread_ts:
            message = body.get("message") or {}
            container = body.get("container") or {}
            thread_ts = (
                message.get("thread_ts")
                or container.get("thread_ts")
                or message.get("ts")
                or container.get("message_ts")
                or ""
            )
        clicker = body["user"]["id"]
        if not thread_ts:
            logger.warning("bot_actions: iq:resolved clicked without thread_ts")
            return
        if self._close_questionnaire_cb is None:
            logger.warning("bot_actions: iq:resolved clicked but "
                           "close_questionnaire callback not wired")
            return
        try:
            self._close_questionnaire_cb(
                thread_ts, reason="button", closed_by=clicker,
            )
        except Exception:
            logger.warning("bot_actions: iq:resolved callback failed",
                           exc_info=True)

    # ---- Incident questionnaire answer handlers ----
    #
    # Each handler: parse current blocks → mutate one field → render →
    # chat_update. Errors log-and-swallow (spec Invariant #2). The
    # injected close-callback is used only by _on_iq_resolved; these
    # answer handlers never close the post.

    def _iq_update(self, body, mutator) -> None:
        message = body.get("message") or {}
        channel = (body.get("channel") or {}).get("id", "")
        ts = message.get("ts", "")
        blocks = message.get("blocks") or []
        if not ts or not channel or not blocks:
            return
        self._iq_apply(channel, ts, blocks, mutator)

    def _iq_apply(self, channel: str, ts: str, blocks: list, mutator) -> None:
        """Parse → resolved-guard → mutate → render → chat_update. Errors
        log-and-swallow (Invariant #2). Closed posts are terminal
        (Invariant #3)."""
        from incident_questionnaire import parse_state, render
        try:
            state = parse_state(blocks)
            if state.resolved:
                # Closed is terminal; ignore clicks on a closed post
                # (race: user clicked answer just as TTL fired).
                return
            mutator(state)
            self._slack.chat_update(
                channel=channel, ts=ts,
                text="Incident questionnaire — click to answer.",
                blocks=render(state, channel_id=channel),
            )
        except Exception:
            logger.warning("bot_actions: iq update failed", exc_info=True)

    def _on_iq_impact(self, body, respond, client):
        value = body["actions"][0]["action_id"].split(":")[-1]  # yes|no|unknown
        user = body["user"]["id"]
        now = int(time.time())

        def mut(state):
            state.customer_impact = value
            state.customer_impact_by = user
            state.customer_impact_at = now
            if value == "yes":
                state.channel_expanded = True

        self._iq_update(body, mut)

    # TODO(remove-by: 2026-04-25)  # deploy 2026-04-23 + 48h
    def _on_iq_legacy_sev_ticket(self, ack, body, **kwargs):
        """Ack-only shim for pre-1.1 iq:sev:* and iq:ticket:* action_ids.

        These action_ids are emitted by questionnaire posts rendered before
        the v1.1 deploy. Posts live for up to incident_questionnaire_ttl_sec
        (default 24h); during that window Slack will fire these action_ids
        when an operator clicks a button on an old post.

        We must ack() to prevent Slack from showing an "unhandled action"
        error to the operator. We deliberately do NOT attempt to parse or
        mutate the old post — the block schema changed in v1.1 and the
        parse would raise. The operator sees no feedback (the old post is
        not re-rendered), which is acceptable: old posts will expire via TTL.
        """
        try:
            ack()
        except Exception:
            logger.warning("bot_actions: legacy sev/ticket ack failed",
                           exc_info=True)

    def _on_iq_channel(self, ack, body, client, respond):
        """Incident questionnaire channel button.

        Opens a confirm modal first so a single accidental click cannot
        create a Slack channel.
        """
        ack()

        user = body["user"]["id"]

        channel = body["channel"]["id"]
        ts = body["message"]["ts"]
        thread_ts = body["message"].get("thread_ts") or ts
        metadata = {
            "origin_channel": channel,
            "thread_ts": thread_ts,
            "requester": user,
        }
        try:
            client.views_open(
                trigger_id=body.get("trigger_id", ""),
                view={
                    "type": "modal",
                    "callback_id": "incident_channel_confirm",
                    "private_metadata": json.dumps(metadata),
                    "title": {
                        "type": "plain_text",
                        "text": "Incident channel",
                    },
                    "submit": {
                        "type": "plain_text",
                        "text": "Create channel",
                    },
                    "close": {
                        "type": "plain_text",
                        "text": "Cancel",
                    },
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    "Create a dedicated incident channel for "
                                    f"<#{channel}> thread `{thread_ts}`?"
                                ),
                            },
                        },
                        {
                            "type": "context",
                            "elements": [{
                                "type": "mrkdwn",
                                "text": (
                                    "This will invite responders, close the "
                                    "questionnaire, and post an audit line "
                                    "in the source thread."
                                ),
                            }],
                        },
                    ],
                },
            )
        except Exception:
            logger.warning("bot_actions: incident channel confirm modal failed",
                           exc_info=True)
            self._ephemeral(client, body,
                            "Could not open confirmation modal.")

    def _on_iq_channel_confirm(self, ack, body, client, respond):
        ack()
        try:
            meta = json.loads((body.get("view") or {}).get("private_metadata") or "{}")
        except json.JSONDecodeError:
            logger.warning("bot_actions: bad incident_channel_confirm metadata")
            return

        origin_channel = meta.get("origin_channel") or ""
        thread_ts = meta.get("thread_ts") or ""
        requester = meta.get("requester") or (body.get("user") or {}).get("id") or ""
        if not origin_channel or not thread_ts or not requester:
            logger.warning("bot_actions: incomplete incident_channel_confirm metadata")
            return

        try:
            client.chat_postMessage(
                channel=origin_channel,
                thread_ts=thread_ts,
                text=f"Incident channel requested by <@{requester}>.",
                unfurl_links=False,
                unfurl_media=False,
            )
        except Exception:
            logger.warning("bot_actions: incident channel audit post failed",
                           exc_info=True)

        if self._create_channel_cb is not None:
            try:
                self._create_channel_cb(
                    origin_channel=origin_channel,
                    thread_ts=thread_ts,
                    escalator_user_id=requester,
                )
            except Exception:
                logger.warning("bot_actions: _on_iq_channel_confirm create_cb failed",
                               exc_info=True)

    def _on_iq_channel_resolved(self, ack, body, client, respond):
        """Pinned Resolved button in an incident channel. Dispatches to
        MessageHandler._resolve_incident via injected cb. Handler itself
        never raises (Invariant #2)."""
        ack()
        if self._resolve_incident_cb is None:
            logger.warning("bot_actions: _on_iq_channel_resolved with no cb")
            return
        try:
            self._resolve_incident_cb(
                channel_id=body["channel"]["id"],
                by_user_id=body["user"]["id"],
                reason="button",
            )
        except Exception:
            logger.warning("bot_actions: _on_iq_channel_resolved cb failed",
                           exc_info=True)

    def _on_iq_add_transcript(self, ack, body, client, respond):
        ack()
        channel_id = (body.get("channel") or {}).get("id") or (
            body.get("container") or {}
        ).get("channel_id", "")
        try:
            client.views_open(
                trigger_id=body.get("trigger_id"),
                view={
                    "type": "modal",
                    "callback_id": "incident_transcript_add",
                    "private_metadata": channel_id,
                    "title": {"type": "plain_text", "text": "Add transcript"},
                    "submit": {"type": "plain_text", "text": "Attach"},
                    "close": {"type": "plain_text", "text": "Cancel"},
                    "blocks": [{
                        "type": "input",
                        "block_id": "transcript_text",
                        "element": {
                            "type": "plain_text_input",
                            "action_id": "transcript_text_input",
                            "multiline": True,
                            "placeholder": {
                                "type": "plain_text",
                                "text": "Paste Google Meet transcript here",
                            },
                        },
                        "label": {"type": "plain_text", "text": "Transcript"},
                    }],
                },
            )
        except Exception:
            logger.warning("bot_actions: transcript modal open failed", exc_info=True)

    def _on_iq_transcript_submit(self, ack, body, client):
        view = body.get("view") or {}
        values = ((view.get("state") or {}).get("values") or {})
        text = (
            values.get("transcript_text", {})
            .get("transcript_text_input", {})
            .get("value")
            or ""
        ).strip()
        if not text:
            ack(response_action="errors", errors={"transcript_text": "Paste transcript text."})
            return
        ack()
        channel_id = view.get("private_metadata", "")
        user_id = (body.get("user") or {}).get("id", "")
        ok = False
        if self._incident_channel_store is not None:
            ok = self._incident_channel_store.set_transcript_by_channel_id(
                channel_id, text=text, by=user_id,
            )
        if ok:
            try:
                client.chat_postMessage(
                    channel=channel_id,
                    text=f"Transcript attached to RCA evidence by <@{user_id}>.",
                    unfurl_links=False,
                    unfurl_media=False,
                )
            except Exception:
                logger.warning("bot_actions: transcript confirm failed", exc_info=True)

    def post_p3_expiry(self, prompt) -> None:
        """Called by the sweep thread AFTER it has already popped the
        entry from the store under lock. Edits the bot's prompt message
        to the terminal 'No response — not escalated' state.

        Section block, not actions block: Slack rejects actions blocks
        with zero elements. Best-effort — log and swallow on failure."""
        text = ":hourglass_flowing_sand: No response — not escalated."
        try:
            self._slack.chat_update(
                channel=prompt.channel_id, ts=prompt.prompt_ts,
                text=text,
                blocks=[{"type": "section", "text":
                         {"type": "mrkdwn", "text": text}}],
            )
        except Exception:
            logger.warning("bot_actions: post_p3_expiry failed", exc_info=True)

    # --- fallback-ask helper (classifier sweep entrypoint) -----------------

    def post_fallback_ask(self, entry) -> None:
        """Post a thread reply asking the operator to clarify. One-shot;
        the two buttons drive the terminal state edits."""
        # Encoded value matches _decode_value's `thread_ts|channel_id`.
        val = f"{entry.original_ts}|{entry.channel_id}"
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn",
             "text": ":thinking_face: I wasn't sure if this is an incident "
                     "or a change announcement, and I didn't see a CR link "
                     "in the next minute."}},
            {"type": "actions", "elements": [
                {"type": "button", "action_id": "esc:page",
                 "style": "danger",
                 "text": {"type": "plain_text", "emoji": True,
                          "text": ":rotating_light: Page on-call"},
                 "value": val},
                {"type": "button", "action_id": "esc:paste_cr",
                 "text": {"type": "plain_text", "emoji": True,
                          "text": ":clipboard: This is a change — paste CR"},
                 "value": val},
            ]},
        ]
        try:
            self._slack.chat_postMessage(
                channel=entry.channel_id,
                thread_ts=entry.original_ts,
                text="Not sure if incident or change — please clarify.",
                blocks=blocks,
                unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("bot_actions: post_fallback_ask failed", exc_info=True)

    def post_p3_prompt(self, *, channel_id: str, original_ts: str,
                       poster_user_id: str) -> Optional[str]:
        """Post the P3 'looks like an incident — page?' thread reply.
        Returns the posted message's ts (the edit target for expiry /
        click terminal states) or None on failure."""
        val = f"{original_ts}|{channel_id}"
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn",
             "text": (":thinking_face: This looks like an incident — "
                      f"want on-call paged? (asked from <@{poster_user_id}>'s post)")}},
            {"type": "actions", "elements": [
                {"type": "button", "action_id": "p3:page",
                 "style": "danger",
                 "text": {"type": "plain_text", "emoji": True,
                          "text": ":rotating_light: Page on-call"},
                 "value": val},
                {"type": "button", "action_id": "p3:dismiss",
                 "text": {"type": "plain_text", "emoji": True,
                          "text": ":white_check_mark: Not an incident"},
                 "value": val},
            ]},
        ]
        try:
            resp = self._slack.chat_postMessage(
                channel=channel_id, thread_ts=original_ts,
                text="This looks like an incident — want on-call paged?",
                blocks=blocks, unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("bot_actions: post_p3_prompt failed", exc_info=True)
            return None
        return resp.get("ts")

    def post_incident_questionnaire(self, *, channel_id: str,
                                    thread_ts: str) -> Optional[str]:
        """Post the initial in-thread incident questionnaire. Returns the
        new message's ts or None on failure.

        INVARIANT: MUST always pass `thread_ts=thread_ts`. This method
        is the only Slack-side post-site for the questionnaire — the
        hard "never top-level" rule is enforced here. No config-flag
        check happens in this method; the gate lives in
        MessageHandler.post_incident_questionnaire. All callers in
        bot.py route through that wrapper.
        """
        from incident_questionnaire import QuestionnaireState, render
        blocks = render(QuestionnaireState(), thread_ts=thread_ts, channel_id=channel_id)
        try:
            resp = self._slack.chat_postMessage(
                channel=channel_id, thread_ts=thread_ts,
                text="Incident questionnaire — click to answer.",
                blocks=blocks, unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("bot_actions: post_incident_questionnaire failed",
                           exc_info=True)
            return None
        return resp.get("ts")

    def _shift_key_for_message(self, channel_id: str, message_ts: str) -> Optional[str]:
        for sp in self._turnover.store.all_shift_posts():
            if sp.channel_id == channel_id and sp.message_ts == message_ts:
                return sp.shift_key
        return None

    def _on_turnover_row(self, body, respond, client):
        clicker = body["user"]["id"]
        if not self._is_privileged(clicker):
            self._ephemeral(client, body,
                            "Only @noc / @domains-sre can use this action.")
            return
        action = body["actions"][0]
        aid = action["action_id"]
        selected_verb = action.get("selected_option", {}).get("value")
        parts = aid.split(":", 2)
        if len(parts) == 3:
            incident_ts = parts[2]
            verb = selected_verb if parts[1] == "more" and selected_verb else parts[1]
        else:
            _prefix, _, incident_ts = aid.partition(":")
            verb = action.get("value") or selected_verb
        container = body.get("container", {})
        channel = container.get("channel_id")
        message_ts = container.get("message_ts")
        shift_key = self._shift_key_for_message(channel, message_ts)

        if verb == "claim":
            claimed = self._turnover.store.claim_incident(incident_ts, clicker)
            self._activity.add(
                "button_row_claim",
                f"{incident_ts} claimed={claimed} by {clicker}",
                user=clicker,
            )
        elif verb == "resolve":
            self._turnover.resolver.mark_resolved(
                incident_ts, source="button", by_user_id=clicker,
            )
            self._activity.add("button_row_resolve", f"{incident_ts} by {clicker}", user=clicker)
        elif verb == "ticket":
            key = self._reactor.create_occir(
                channel=channel, ts=incident_ts, requested_by=clicker,
            )
            if not key:
                self._ephemeral(client, body, "⚠️ Ticket creation skipped.")
                return
            self._activity.add("button_row_ticket", f"{incident_ts} → {key} by {clicker}", user=clicker)
        elif verb == "rerun":
            inc = self._turnover.store.get_incident(incident_ts)
            if not inc:
                self._ephemeral(client, body, "⚠️ Incident not found.")
                return
            did_resolve = self._turnover.resolver.check_incident(inc, force=True)
            self._activity.add("button_row_rerun", f"{incident_ts} resolved={did_resolve} by {clicker}", user=clicker)
        elif verb == "skip":
            self._turnover.store.mark_incident_excluded(incident_ts, int(time.time()))
            self._activity.add("button_row_skip", f"{incident_ts} by {clicker}", user=clicker)
        elif verb == "delete":
            self._turnover.store.delete_incident(incident_ts)
            self._activity.add("button_row_delete", f"{incident_ts} by {clicker}", user=clicker)
        else:
            self._ephemeral(client, body, f"⚠️ Unknown verb {verb!r}")
            return

        # Re-render is the feedback — post updates in place, no chat noise.
        if shift_key:
            self._turnover.scheduler.rerender(shift_key)

    def _on_turnover_refresh(self, body, respond, client):
        clicker = body["user"]["id"]
        if not self._is_privileged(clicker):
            self._ephemeral(client, body,
                            "Only @noc / @domains-sre can use this action.")
            return
        shift_key = body["actions"][0]["value"]
        with self._refresh_lock:
            last = self._refresh_rate_limit.get(shift_key, 0.0)
            now = time.time()
            if now - last < 10:
                self._ephemeral(client, body,
                                "⏳ Refreshing too fast — wait a few seconds.")
                return
            self._refresh_rate_limit[shift_key] = now
        self._turnover.scheduler.rerender(shift_key)
        self._activity.add("button_refresh", f"{shift_key} by {clicker}", user=clicker)

    def _on_turnover_delete(self, body, respond, client):
        clicker = body["user"]["id"]
        if not self._is_privileged(clicker):
            self._ephemeral(client, body,
                            "Only @noc / @domains-sre can use this action.")
            return
        container = body.get("container", {})
        channel = container.get("channel_id")
        message_ts = container.get("message_ts")
        try:
            self._slack.chat_delete(channel=channel, ts=message_ts)
        except Exception as e:
            err_code = None
            resp = getattr(e, "response", None)
            if isinstance(resp, dict):
                err_code = resp.get("error")
            if err_code != "message_not_found":
                raise
        shift_key = self._shift_key_for_message(channel, message_ts)
        if shift_key:
            self._turnover.store.delete_shift_post(shift_key)
        self._activity.add("button_delete", f"{shift_key} by {clicker}", user=clicker)

    def _on_turnover_report(self, body, respond, client):
        clicker = body["user"]["id"]
        if not self._is_privileged(clicker):
            self._ephemeral(client, body,
                            "Only @noc / @domains-sre can use this action.")
            return
        shift_key = body["actions"][0]["value"]
        sp = self._turnover.store.get_shift_post(shift_key)
        if sp is None:
            self._ephemeral(client, body, "Warning: shift post not found.")
            return

        user_lookup = getattr(getattr(self._turnover, "scheduler", None),
                              "_user_name", None)
        if user_lookup is None:
            user_lookup = getattr(self._turnover, "user_names", None)
        if user_lookup is None:
            user_lookup = lambda user_id: user_id

        text, blocks = build_shift_report(
            store=self._turnover.store,
            shift_key=sp.shift_key,
            window_start=sp.window_start,
            window_end=sp.window_end,
            user_name_lookup=user_lookup,
            jira_base_url=self._jira_base_url,
        )

        try:
            opened = client.conversations_open(users=clicker)
            dm_channel = (opened.get("channel") or {}).get("id")
            if not dm_channel:
                raise RuntimeError("missing_dm_channel")
            client.chat_postMessage(
                channel=dm_channel,
                text=text,
                blocks=blocks,
                unfurl_links=False,
                unfurl_media=False,
            )
            self._ephemeral(client, body, "Private turnover report sent by DM.")
        except Exception:
            logger.warning("bot_actions: turnover report DM failed", exc_info=True)
            self._ephemeral(client, body, _truncate_report_fallback(text))
        self._activity.add("button_turnover_report", f"{shift_key} by {clicker}", user=clicker)

    def _on_turnover_add_handoff(self, body, respond, client):
        clicker = body["user"]["id"]
        if not self._is_privileged(clicker):
            self._ephemeral(client, body,
                            "Only @noc / @domains-sre can use this action.")
            return
        shift_key = body["actions"][0]["value"]
        container = body.get("container", {})
        private_meta = json.dumps({
            "shift_key": shift_key,
            "channel_id": container.get("channel_id"),
            "message_ts": container.get("message_ts"),
        })
        trigger_id = body["trigger_id"]
        view = {
            "type": "modal",
            "callback_id": "turnover_handoff_add",
            "title":  {"type": "plain_text", "text": "Add handoff item"},
            "submit": {"type": "plain_text", "text": "Add"},
            "close":  {"type": "plain_text", "text": "Cancel"},
            "private_metadata": private_meta,
            "blocks": [
                {"type": "input", "block_id": "handoff_title",
                 "label": {"type": "plain_text", "text": "Title"},
                 "element": {"type": "plain_text_input", "action_id": "title_input"}},
                {"type": "input", "block_id": "handoff_link",
                 "optional": True,
                 "label": {"type": "plain_text", "text": "Link (optional)"},
                 "element": {"type": "plain_text_input", "action_id": "link_input"}},
                {"type": "input", "block_id": "handoff_note",
                 "optional": True,
                 "label": {"type": "plain_text", "text": "Note (optional)"},
                 "element": {"type": "plain_text_input", "action_id": "note_input",
                              "multiline": True}},
            ],
        }
        self._slack.views_open(trigger_id=trigger_id, view=view)

    def _on_handoff_submit(self, body, respond, client):
        view = body["view"]
        meta = json.loads(view.get("private_metadata") or "{}")
        shift_key = meta.get("shift_key") or ""
        clicker = body["user"]["id"]

        if not self._is_privileged(clicker):
            # Modal has already opened — surface the denial as the view's
            # response_action so the user sees an error in-modal.
            return {
                "response_action": "errors",
                "errors": {"handoff_title": "Only @noc / @domains-sre can submit."},
            }

        values = view["state"]["values"]

        def _field(block_id: str, action_id: str) -> Optional[str]:
            v = (values.get(block_id) or {}).get(action_id, {}).get("value")
            if v is None or v.strip() == "":
                return None
            return v.strip()

        title = _field("handoff_title", "title_input") or ""
        link = _field("handoff_link", "link_input")
        note = _field("handoff_note", "note_input")
        now = int(time.time())
        self._turnover.store.insert_handoff_item(
            shift_key=shift_key, title=title, link=link, note=note,
            author=clicker, at=now,
        )
        self._activity.add("button_add_handoff",
                           f"{shift_key}: {title[:60]} by {clicker}", user=clicker)
        if shift_key:
            self._turnover.scheduler.rerender(shift_key)
