import logging
import os
import re
import threading
import time
from dataclasses import replace
from datetime import datetime
from zoneinfo import ZoneInfo

from cachetools import TTLCache
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk.errors import SlackApiError

from grafana_irm import GrafanaIRMClient, EscalationError
from jira_cr import JiraCRClient, summarize_cr, format_cr_slack_message, assess_cr_impact
from group_cache import GroupMembershipCache
from occir_jira import OccirJiraClient
from ticket_reactor import ReactionHandler
from turnover_coordinator import TurnoverCoordinator
from turnover_renderer import render_escalation_ack_blocks
from api import config, activity, init as init_api, start_api_server
from change_tracker import ChangeTracker
from bot_message_deleter import BotMessageDeleter
from bot_actions import BotActions
from incident_channel_store import IncidentChannelStore
from incident_channel_creator import IncidentChannelCreator
from incident_channel import generate_slug
from incident_rca import generate_incident_rca, render_rca_blocks
from escalation_classifier import (
    classify as classify_escalation,
    classify_p3, P3Verdict, Verdict,
    classify_resolution, ResolutionVerdict,
)
from p3_prompts import P3Prompt, P3PromptStore
from alert_qa import (
    AlertQAConfig,
    AlertQAHandler,
    ConfluenceSearchSource,
    JiraOccirSearchSource,
    SlackOpsNocSearchSource,
)

logger = logging.getLogger(__name__)

_P3_MIN_TEXT_LEN = 20


def _format_et_now() -> str:
    return datetime.now(ZoneInfo("America/New_York")).strftime("%H:%M")


def _change_tracker_ollama_model() -> str:
    return os.environ.get("CHANGE_TRACKER_OLLAMA_MODEL") or "qwen2.5:32b"


class MessageHandler:
    def __init__(self, slack_client, irm_client, channel_id: str,
                 group_membership_cache: GroupMembershipCache,
                 jira_client=None, ollama_url: str = "", ollama_model: str = "",
                 jira_base_url: str = "",
                 turnover_coordinator=None, pending=None, p3_prompts=None,
                 alert_qa=None):
        self.slack_client = slack_client
        self.irm_client = irm_client
        self.channel_id = channel_id
        self.group_cache = group_membership_cache
        self.group_ids = group_membership_cache.group_ids  # kept for api.py /status endpoint
        self.bot_user_id = slack_client.auth_test()["user_id"]

        self._cache_lock = threading.Lock()                # still needed for _seen_messages dedup

        # Message dedup set: message_ts -> True, 10-min TTL
        self._seen_messages = TTLCache(maxsize=4096, ttl=600)

        self.jira_client = jira_client
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.jira_base_url = jira_base_url
        self.turnover = turnover_coordinator
        self.turnover_store = turnover_coordinator.store if turnover_coordinator else None
        self.pending = pending
        self.p3_prompts = p3_prompts
        self.alert_qa = alert_qa
        self.post_p3_prompt = None

        # CR detection pattern
        self._cr_pattern = re.compile(r"\bCR-(\d+)\b")
        self._jira_issue_pattern = re.compile(r"\b(?:CR|OCCIR)-\d+\b", re.IGNORECASE)

        # Build mention patterns: <!subteam^GROUP_ID>
        self._mention_pattern = re.compile(
            "|".join(f"<!subteam\\^{gid}>" for gid in self.group_ids)
        )

        # Incident questionnaire tracker (Phase 1). Maps
        # thread_ts -> (channel_id, questionnaire_ts, posted_at_epoch).
        # In-memory only; lost on restart. Sole consumer is
        # _pending_sweep_loop for TTL expiry. All writes under the lock.
        self._open_questionnaires: dict[str, tuple[str, str, int]] = {}
        self._open_questionnaires_lock = threading.Lock()
        # Back-filled in main() after BotActions is constructed.
        self._bot_actions = None

        # Incident channel (Phase 2) state.
        self._incident_channels = IncidentChannelStore()
        self._incident_channel_creator: IncidentChannelCreator | None = None
        # creator instance is wired in main() after group_cache is built

    def _create_incident_channel(
        self, *, origin_channel: str, thread_ts: str,
        escalator_user_id: str,
        slug: str | None = None,
        slug_source: str | None = None,
    ):
        """Flag-gated entry for channel creation.

        Called from:
          - bot_actions._on_iq_channel (first click; slug=None -> we call
            generate_slug then proceed with "llm" or "fallback" source)

        The `slug`/`slug_source` kwargs exist on the signature so a future
        modal-override phase can re-enter this method with an operator-
        typed slug without breaking callers.
        """
        cfg = config.get_all()
        if not cfg.get("incident_channel_enabled"):
            return None
        if not cfg.get("incident_channel_live_mode"):
            try:
                self.slack_client.chat_postMessage(
                    channel=origin_channel, thread_ts=thread_ts,
                    text=("(dry-run) Incident channel creation is enabled "
                          "but live_mode is off - would create a channel now."),
                    unfurl_links=False, unfurl_media=False,
                )
            except Exception:
                logger.warning("iq: dry-run notice failed", exc_info=True)
            return None

        existing = self._incident_channels.get(thread_ts)
        if existing is not None:
            try:
                self.slack_client.chat_postMessage(
                    channel=origin_channel, thread_ts=thread_ts,
                    text=f"This thread is already escalated - see "
                         f"<#{existing.channel_id}>.",
                    unfurl_links=False, unfurl_media=False,
                )
            except Exception:
                pass
            return existing.channel_id

        op_text, op_user_id = self._fetch_thread_op(origin_channel, thread_ts)
        if slug is None:
            ollama_url = os.environ.get("OLLAMA_URL", "")
            ollama_model = os.environ.get("OLLAMA_MODEL", "qwen2.5:32b")
            slug = generate_slug(
                op_text, ollama_url=ollama_url, ollama_model=ollama_model,
            )
            if slug is None:
                slug = "unknown"
                slug_source = "fallback"
            else:
                slug_source = "llm"

        participants = self._fetch_thread_participants(origin_channel, thread_ts)
        origin_url = self._build_origin_url(origin_channel, thread_ts)
        state = self._get_questionnaire_state(thread_ts)

        if self._incident_channel_creator is None:
            logger.warning("iq: _incident_channel_creator not wired; aborting")
            return None
        return self._incident_channel_creator.create_and_populate(
            thread_ts=thread_ts,
            origin_channel=origin_channel,
            escalator_user_id=escalator_user_id,
            slug=slug,
            slug_source=slug_source or "llm",
            op_user_id=op_user_id,
            initial_participants=participants,
            origin_thread_url=origin_url,
            questionnaire_state=state,
        )

    def _fetch_thread_op(self, channel_id: str, thread_ts: str):
        """Returns (op_text, op_user_id). Falls back to empty strings on error."""
        try:
            resp = self.slack_client.conversations_replies(
                channel=channel_id, ts=thread_ts, limit=1,
            )
            msgs = resp.get("messages") or []
            if msgs:
                return msgs[0].get("text", ""), msgs[0].get("user", "")
        except Exception:
            logger.warning("iq: fetch_thread_op failed", exc_info=True)
        return "", ""

    def _fetch_thread_participants(self, channel_id: str,
                                   thread_ts: str) -> list[str]:
        out: set[str] = set()
        cursor = None
        for _ in range(5):
            try:
                resp = self.slack_client.conversations_replies(
                    channel=channel_id, ts=thread_ts, limit=200,
                    cursor=cursor,
                )
            except Exception:
                logger.warning("iq: fetch_thread_participants failed",
                               exc_info=True)
                break
            for m in resp.get("messages") or []:
                if m.get("user"):
                    out.add(m["user"])
            cursor = (resp.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                break
        return sorted(out)

    def _build_origin_url(self, channel_id: str, thread_ts: str) -> str:
        try:
            resp = self.slack_client.chat_getPermalink(
                channel=channel_id, message_ts=thread_ts,
            )
            return resp.get("permalink", "") or ""
        except Exception:
            return f"https://app.slack.com/client/{channel_id}/{thread_ts}"

    def _get_questionnaire_state(self, thread_ts: str):
        """Look up the Phase 1 questionnaire state by parsing the thread
        message. Returns an empty state on failure."""
        from incident_questionnaire import parse_state, QuestionnaireState
        try:
            entry = self._open_questionnaires.get(thread_ts)
            if entry is None:
                return QuestionnaireState()
            ch, qts, _posted_at = entry
            resp = self.slack_client.conversations_history(
                channel=ch, latest=qts, inclusive=True, limit=1,
            )
            msgs = resp.get("messages") or []
            if not msgs:
                return QuestionnaireState()
            blocks = msgs[0].get("blocks") or []
            return parse_state(blocks)
        except Exception:
            logger.warning("iq: _get_questionnaire_state failed",
                           exc_info=True)
            return QuestionnaireState()

    def handle_message(self, event: dict, *, skip_alert_qa: bool = False) -> bool:
        """Process a message event. Returns True if escalation was triggered."""
        # Pre-filter: bot disabled via config
        cfg = config.get_all()
        if not cfg.get("enabled", True):
            return False

        # Pre-filter: subtypes (edits, deletes, bot messages). Before dropping
        # the event, forward deletes to turnover so it can purge the phantom
        # row (otherwise a deleted alert keeps showing up in carryover with a
        # stale 404 permalink).
        subtype = event.get("subtype")
        if subtype:
            if subtype == "message_deleted" and self.turnover is not None:
                self.turnover.ingestor.handle_deleted_message(event)
            return False

        # Pre-filter: bot messages or own messages
        if event.get("bot_id") or event.get("user") == self.bot_user_id:
            return False

        # Pre-filter: dedup (under lock for thread safety)
        ts = event.get("ts", "")
        if not _mark_seen(self, ts):
            return False

        if not skip_alert_qa and self.alert_qa and self.alert_qa.handle_event(
            event, is_app_mention=False
        ):
            return False

        # Pre-filter: channel check (production channel or test channels)
        channel = event.get("channel", "")
        test_channels = cfg.get("test_channels", []) if cfg.get("test_mode_enabled") else []
        is_test = channel in test_channels
        # Phase 2: known incident channels bypass the origin-channel filter
        # so messages in them reach the LLM auto-resolver below.
        is_incident_channel = (
            self._incident_channels.get_by_channel_id(channel) is not None
        )
        if channel != self.channel_id and not is_test and not is_incident_channel:
            return False

        # Phase 2: messages in known incident channels go through LLM
        # auto-resolver. The thread_ts guard avoids picking up replies to
        # bot-posted announcements.
        if is_incident_channel and not event.get("thread_ts"):
            self._handle_incident_channel_message(
                channel_id=channel,
                user_id=event.get("user", ""),
                text=event.get("text", ""),
            )
            return False

        # Classifier follow-up: a top-level CR-NNNN from the same user
        # within the wait window completes a prior `change_no_cr` post.
        # Runs BEFORE record_message so the CR announcement doesn't
        # become an incident row. Replies (thread_ts set) never qualify.
        thread_ts_raw = event.get("thread_ts")
        is_top_level = not thread_ts_raw or thread_ts_raw == ts
        if (self.pending is not None and is_top_level
                and channel == self.channel_id):
            user = event.get("user", "")
            popped = self.pending.handle_followup(
                channel=channel, user=user, text=event.get("text", ""),
            )
            if popped is not None:
                self._post_cr_followup(popped, event)
                return False

        # Turnover ingestion — runs for every real user message (parent or reply)
        # in the channel, independent of the escalation path. Safe no-op if
        # turnover is disabled.
        if self.turnover is not None:
            self.turnover.ingestor.record_message(event)

        # Pre-filter: thread replies — only top-level channel messages escalate.
        # A thread reply has thread_ts set to the parent's ts; the parent's
        # own message event has no thread_ts, so this skips replies only.
        thread_ts = event.get("thread_ts")
        if thread_ts and thread_ts != event.get("ts"):
            # Phase 2: escalated threads bridge to the incident channel
            # and skip Phase 1 resolver (Invariant #10).
            if self._bridge_thread_reply(
                origin_channel=channel,
                thread_ts=thread_ts,
                user_id=event.get("user", ""),
            ):
                return False
            # Phase 1: LLM auto-resolve on replies in threads with an
            # open questionnaire. Gated by its own flag. Fail-closed:
            # any exception returns UNRESOLVED and the post stays open.
            if (cfg.get("incident_resolution_detector_enabled", False)
                    and thread_ts in self._open_questionnaires):
                reply_text = event.get("text", "")
                reply_user = event.get("user", "")
                try:
                    verdict = classify_resolution(
                        reply_text,
                        ollama_url=self.ollama_url,
                        ollama_model=(cfg.get("escalation_classifier_ollama_model")
                                      or self.ollama_model),
                    )
                except Exception:
                    logger.warning("iq: classify_resolution raised",
                                   exc_info=True)
                    verdict = ResolutionVerdict.UNRESOLVED
                if verdict == ResolutionVerdict.RESOLVED:
                    try:
                        self._close_questionnaire(
                            thread_ts, reason="llm",
                            closed_by=reply_user or None,
                        )
                    except Exception:
                        logger.warning("iq: llm-close failed", exc_info=True)
            return False

        # Pre-filter: silenced-thread gate. A NOC member can click "Silence 1h"
        # on a previous escalation ack; until that TTL expires, we don't re-page.
        thread_key = event.get("ts", "")
        if self.turnover_store is not None and thread_key:
            try:
                es = self.turnover_store.get_escalation_state(thread_key)
            except Exception:
                es = None
            silence_until = getattr(es, "silence_until", None) if es else None
            if isinstance(silence_until, int) and silence_until > int(time.time()):
                logger.debug(
                    "escalation: thread %s silenced until %s — skipping",
                    thread_key, silence_until,
                )
                return False

        text = event.get("text", "")

        # Step 1: Mention check
        if not self._mention_pattern.search(text):
            return self._handle_untagged_post(event, cfg)

        # Step 2: Sender exclusion (skipped in test channels)
        sender = event.get("user", "")
        if not is_test:
            members = self.group_cache.get_members(self.slack_client)
            if sender in members:
                logger.info("Sender %s is a group member, skipping", sender)
                return False

        # Step 3: Classifier (shadow-mode or live-mode) + CR detection
        #
        # Shadow-mode: always run the classifier and log its verdict, but
        # do NOT change routing. This lets us compare against the regex
        # ladder in prod logs for a few days before flipping.
        #
        # IMPORTANT: only fetch the CR from Jira when cr_summary_enabled,
        # otherwise a disabled CR path would still burn a Jira HTTP call
        # on every mention (regression vs. today).
        cr_data = None
        jira_key = (
            self._extract_linked_jira_key(text)
            if self.jira_client and cfg.get("cr_summary_enabled", True)
            else None
        )
        if jira_key:
            try:
                cr_data = self.jira_client.fetch_cr(jira_key)
            except Exception:
                logger.warning("classifier: jira fetch_cr failed", exc_info=True)
                cr_data = None
        model = cfg.get("escalation_classifier_ollama_model") or self.ollama_model
        verdict = classify_escalation(
            text=text, cr_data=cr_data,
            ollama_url=self.ollama_url, ollama_model=model,
        )
        # Shadow-mode observability: verdict without the stale
        # ladder-comparison collapse (removed in Phase 4b; the offline
        # shadow-eval is the source of truth now, and the 4-class verdict
        # space can't be collapsed to the 2-way ladder coherently).
        logger.info(
            "escalation_classifier_shadow: verdict=%s", verdict.value,
        )

        classifier_live = cfg.get("escalation_classifier_enabled", False)
        if classifier_live:
            if verdict == Verdict.FYI:
                logger.info(
                    "classifier: fyi verdict, taking no action (ts=%s user=%s)",
                    ts, sender,
                )
                return False
            if verdict == Verdict.CHANGE_WITH_CR:
                if cr_data is None:
                    # Classifier post-processing should have downgraded
                    # this to INCIDENT; defensive: just escalate.
                    logger.warning("classifier: change_with_cr with no cr_data; escalating")
                else:
                    return self._handle_cr_summary(cr_data, event, cfg)
            elif verdict == Verdict.CHANGE_NO_CR:
                if self.pending is not None:
                    wait = int(cfg.get(
                        "escalation_classifier_wait_window_sec", 60,
                    ))
                    entry = self.pending.new_entry(
                        original_ts=ts, channel_id=channel,
                        user_id=sender, original_text=text,
                    )
                    # Honor the wait_window_sec config by overriding
                    # expires_at — new_entry uses the store's own default.
                    # Config precedence: config > default.
                    entry = replace(entry, expires_at=self.pending.now() + wait)
                    self.pending.enter(entry)
                logger.info("classifier: change_no_cr entered pending ts=%s user=%s", ts, sender)
                return False
            # Verdict.INCIDENT falls through to Step 4 (escalate)
        else:
            if cfg.get("cr_summary_enabled", True) and cr_data is not None:
                return self._handle_cr_summary(cr_data, event, cfg)
            # else fall through to escalate as today

        # Step 4: Escalate (no CR found, or CR fetch failed -> fall through)
        if not cfg.get("escalation_enabled", True):
            activity.add("escalation_skipped", "Escalation disabled via config", user=sender)
            return False

        live_in_test = cfg.get("test_mode_live_grafana", False)
        if is_test and not live_in_test:
            # Test mode: skip real IRM paging, post dry-run ack
            activity.add("test_escalation", f"[DRY RUN] {text[:100]}", user=sender)
            try:
                self.slack_client.reactions_add(
                    channel=channel, timestamp=ts, name="test_tube"
                )
                self.slack_client.chat_postMessage(
                    channel=channel,
                    thread_ts=ts,
                    text="[TEST] Would escalate to domains-sre via Grafana IRM.",
                )
            except Exception:
                logger.warning("Failed to post test ack for %s", ts)
            return True

        try:
            sender_name = self._get_user_name(sender)
            permalink = self._get_permalink(channel, ts)

            self.irm_client.escalate(
                title="NOC Escalation from #ops-noc",
                message=f"@{sender_name}: {text}",
                source_link=permalink,
            )
            if self.turnover_store is not None:
                self.turnover_store.record_irm_page(
                    ts, channel, int(time.time()),
                )
            activity.add("escalation", f"@{sender_name}: {text[:100]}", user=sender)
        except EscalationError as exc:
            logger.critical(
                "Escalation failed for message %s from user %s", ts, sender,
                exc_info=True,
            )
            activity.add("escalation_failed", str(exc), user=sender)
            return False

        # Step 5: Acknowledge escalation (best-effort) — block-kit with buttons.
        inc = self.turnover_store.get_incident(ts) if self.turnover_store else None
        has_ticket = bool(inc and getattr(inc, "occir_key", None))
        fallback_text, blocks = render_escalation_ack_blocks(
            thread_ts=ts, channel_id=channel,
            escalator_name=sender_name, escalated_at_et=_format_et_now(),
            has_ticket=has_ticket, is_test=(is_test and live_in_test),
        )
        try:
            self.slack_client.reactions_add(
                channel=channel, timestamp=ts, name="rotating_light"
            )
            self.slack_client.chat_postMessage(
                channel=channel, thread_ts=ts,
                text=fallback_text, blocks=blocks,
                unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("Failed to acknowledge escalation in Slack for %s", ts)

        # Phase 1: incident questionnaire. Gated by its own flag inside
        # the wrapper; never blocks the page.
        try:
            self.post_incident_questionnaire(channel, ts)
        except Exception:
            logger.warning("iq: post on three-way ESCALATE failed",
                           exc_info=True)

        return True

    def post_incident_questionnaire(self, channel_id: str,
                                    thread_ts: str) -> "str | None":
        """Gate + dedup + post. Single entry point for all triggers.

        Returns the posted message's ts, or None if (a) the feature
        flag is off, (b) a questionnaire is already open on this
        thread (dedup), or (c) the Slack post failed. The tracker is
        populated under the lock only on confirmed success.
        """
        cfg = config.get_all()
        if not cfg.get("incident_questionnaire_enabled", False):
            return None
        if self._bot_actions is None:
            logger.warning("iq: bot_actions not wired; cannot post")
            return None
        with self._open_questionnaires_lock:
            if thread_ts in self._open_questionnaires:
                logger.info("iq: dedup skip thread_ts=%s", thread_ts)
                return None
        # Post OUTSIDE the lock — Slack call can be slow.
        ts = self._bot_actions.post_incident_questionnaire(
            channel_id=channel_id, thread_ts=thread_ts,
        )
        if ts is None:
            return None
        now = int(time.time())
        with self._open_questionnaires_lock:
            # Race: two triggers post concurrently. Second writer wins
            # the tracker slot; extra post in Slack is visible and
            # accepted (spec §"Re-trigger after restart").
            self._open_questionnaires[thread_ts] = (channel_id, ts, now)
        return ts

    def _close_questionnaire(self, thread_ts: str, *, reason: str,
                             closed_by: "str | None") -> None:
        """Single closure choke point. Idempotent via atomic dict.pop.

        Used by: (1) the Resolved button, via an injected callback in
        BotActions; (2) the TTL sweep in _pending_sweep_loop; (3) the
        LLM auto-resolve in the reply-path hook. First mover wins the
        pop; losers return silently. Errors on the chat_update are
        logged and swallowed — the tracker entry is already gone so
        the post is considered closed regardless.
        """
        from incident_questionnaire import parse_state, render_closed
        with self._open_questionnaires_lock:
            claimed = self._open_questionnaires.pop(thread_ts, None)
        if claimed is None:
            return
        channel_id, questionnaire_ts, _posted_at = claimed
        try:
            resp = self.slack_client.conversations_history(
                channel=channel_id, latest=questionnaire_ts,
                limit=1, inclusive=True,
            )
            msgs = resp.get("messages") or []
            blocks = msgs[0].get("blocks") if msgs else []
        except Exception:
            logger.warning("iq: close history fetch failed for %s; "
                           "rolling back tracker claim", thread_ts, exc_info=True)
            # Put the claim back so a retry path (TTL sweep, re-clicked
            # button) can try again. Race: if another closer populated
            # the slot in between, we leave their claim alone.
            with self._open_questionnaires_lock:
                if thread_ts not in self._open_questionnaires:
                    self._open_questionnaires[thread_ts] = claimed
            return

        state = parse_state(blocks or [])
        state.resolved = True
        state.resolved_by = closed_by
        state.resolved_at = int(time.time())
        state.resolved_reason = reason  # "button" | "ttl" | "llm"

        try:
            self.slack_client.chat_update(
                channel=channel_id, ts=questionnaire_ts,
                text="Incident questionnaire (closed).",
                blocks=render_closed(state),
            )
            logger.info("iq: closed thread_ts=%s reason=%s by=%s",
                        thread_ts, reason, closed_by)
        except Exception:
            logger.warning("iq: close chat_update failed for %s",
                           thread_ts, exc_info=True)

    def _extract_linked_jira_key(self, text: str) -> str | None:
        """Return first Jira issue key attached to the Slack post."""
        match = self._jira_issue_pattern.search(text or "")
        return match.group(0).upper() if match else None

    def _handle_untagged_post(self, event: dict, cfg: dict) -> bool:
        """Dispatch for top-level #ops-noc posts that did NOT tag
        @noc / @domains-sre. Runs the P3 classifier in shadow or live
        mode per config. Always returns False (P3 never claims to be
        an escalation in its own right; live mode posts a prompt and
        lets the user's button click drive the escalation path).

        Preconditions, in order:
          1. p3_enabled (master; escape hatch for Ollama outages)
          2. channel == production #ops-noc (no test-channel support in v1)
          3. len(text) >= _P3_MIN_TEXT_LEN (cheap filter for "ok"/":eyes:")
        If any fails, no classification runs.
        """
        if not cfg.get("p3_enabled", False):
            return False
        channel = event.get("channel", "")
        if channel != self.channel_id:
            return False
        text = event.get("text", "")
        if len(text) < _P3_MIN_TEXT_LEN:
            return False

        # No sender-based filter by design: NOC operators posting a
        # real incident and getting distracted before tagging is the
        # PRIMARY failure mode P3 protects against. Spec §"No sender-
        # based filtering". Do not add a group-member skip here.
        verdict = classify_p3(
            text=text,
            ollama_url=self.ollama_url,
            ollama_model=(cfg.get("escalation_classifier_ollama_model")
                          or self.ollama_model),
        )
        live = bool(cfg.get("p3_live_mode", False))
        ts = event.get("ts", "")
        preview = text.replace("\n", " ")[:120]
        logger.info(
            "p3_verdict=%s live=%s ts=%s preview=%s",
            verdict.value, live, ts, preview,
        )
        if not live:
            return False
        if verdict != P3Verdict.INCIDENT:
            return False
        if self.p3_prompts is None or self.post_p3_prompt is None:
            # Not wired (old tests, or pre-launch config) — shadow-equivalent.
            return False
        try:
            prompt_ts = self.post_p3_prompt(
                channel_id=channel,
                original_ts=ts,
                poster_user_id=event.get("user", ""),
            )
        except Exception:
            logger.warning("p3: post_p3_prompt failed", exc_info=True)
            return False
        if not prompt_ts:
            return False
        ttl = int(cfg.get("p3_prompt_ttl_sec", 900))
        self.p3_prompts.add(P3Prompt(
            original_ts=ts,
            prompt_ts=prompt_ts,
            channel_id=channel,
            expires_at=self.p3_prompts.now() + ttl,
        ))
        return False

    def _handle_cr_summary(self, cr_data, event: dict, cfg: dict = None) -> str:
        """Post a CR summary as a thread reply. Returns 'cr_summary'."""
        ts = event.get("ts", "")
        channel = event.get("channel", self.channel_id)
        cfg = cfg or config.get_all()

        model = cfg.get("ollama_model") or self.ollama_model
        summary = summarize_cr(cr_data, self.ollama_url, model)
        impact_assessment = assess_cr_impact(cr_data, self.ollama_url, model)
        message = format_cr_slack_message(
            cr_data, summary, self.jira_base_url,
            impact_assessment=impact_assessment,
        )
        activity.add("cr_summary", f"{cr_data.key}: {cr_data.summary[:80]}", user=event.get("user", ""), cr_key=cr_data.key)

        try:
            self.slack_client.reactions_add(
                channel=channel, timestamp=ts, name="memo"
            )
            self.slack_client.chat_postMessage(
                channel=channel,
                thread_ts=ts,
                text=message,
            )
        except Exception:
            logger.warning("Failed to post CR summary for %s", ts)

        return "cr_summary"

    def _post_cr_followup(self, popped, event: dict) -> None:
        """A bare CR-NNNN follow-up just popped a `change_no_cr` entry.
        Fetch the CR and post a summary threaded on the ORIGINAL @noc
        post (not this follow-up's ts)."""
        text = event.get("text", "")
        m = self._cr_pattern.search(text)
        if not m or self.jira_client is None:
            return
        cr_key = f"CR-{m.group(1)}"
        cr_data = self.jira_client.fetch_cr(cr_key)
        if not cr_data:
            return
        cfg = config.get_all()
        model = cfg.get("ollama_model") or self.ollama_model
        summary = summarize_cr(cr_data, self.ollama_url, model)
        impact = assess_cr_impact(cr_data, self.ollama_url, model)
        message = format_cr_slack_message(
            cr_data, summary, self.jira_base_url, impact_assessment=impact,
        )
        try:
            self.slack_client.chat_postMessage(
                channel=popped.channel_id,
                thread_ts=popped.original_ts,
                text=message,
            )
            activity.add(
                "cr_followup_matched",
                f"{cr_data.key} matched to {popped.original_ts}",
                user=event.get("user", ""),
            )
        except Exception:
            logger.warning("classifier: cr followup post failed", exc_info=True)

    def _get_user_name(self, user_id: str) -> str:
        try:
            resp = self.slack_client.users_info(user=user_id)
            return resp["user"]["real_name"]
        except Exception:
            return user_id

    def _get_permalink(self, channel: str, message_ts: str) -> str:
        try:
            resp = self.slack_client.chat_getPermalink(channel=channel, message_ts=message_ts)
            return resp["permalink"]
        except Exception:
            return f"https://app.slack.com/client/{channel}/{message_ts}"

    def _resolve_incident(self, *, channel_id: str = None,
                          by_user_id: str, reason: str,
                          thread_ts: str = None) -> bool:
        """Idempotent resolution. Returns True iff this call wrote the
        resolution; False if already resolved or unknown channel."""
        from incident_channel import render_resolved_announcement

        if thread_ts is None:
            entry = self._incident_channels.get_by_channel_id(channel_id)
        else:
            entry = self._incident_channels.get(thread_ts)
        if entry is None:
            return False

        wrote = self._incident_channels.mark_resolved(
            entry.thread_ts, by=by_user_id, reason=reason,
        )
        if not wrote:
            return False

        cfg = config.get_all()
        ttl = int(cfg.get("incident_channel_archive_ttl_sec", 604800))
        archive_at = time.time() + ttl
        self._incident_channels.set_archive_at(
            entry.thread_ts, archive_at=archive_at,
        )
        entry = self._incident_channels.get(entry.thread_ts)

        by_display_name = by_user_id
        if by_user_id.upper() == "LLM":
            by_display_name = "LLM auto-resolver"
        else:
            try:
                r = self.slack_client.users_info(user=by_user_id)
                prof = (r.get("user") or {}).get("profile") or {}
                by_display_name = "@" + (
                    prof.get("display_name") or prof.get("real_name")
                    or by_user_id
                )
            except Exception:
                pass

        if entry.resolved_button_ts:
            try:
                self.slack_client.chat_update(
                    channel=entry.channel_id, ts=entry.resolved_button_ts,
                    blocks=render_resolved_announcement(
                        by_display_name=by_display_name,
                        resolved_at=entry.resolved_at,
                        archive_at=entry.archive_at,
                    ),
                    text="Incident resolved.",
                )
            except Exception:
                logger.warning("iq: resolved chat_update failed",
                               exc_info=True)

        try:
            archive_date = datetime.fromtimestamp(entry.archive_at).strftime("%Y-%m-%d")
            self.slack_client.chat_postMessage(
                channel=entry.origin_channel, thread_ts=entry.thread_ts,
                text=(f"Incident resolved by {by_display_name}. "
                      f"Channel <#{entry.channel_id}> archives on "
                      f"{archive_date}."),
                unfurl_links=False, unfurl_media=False,
            )
        except Exception:
            logger.warning("iq: resolved origin-thread post failed",
                           exc_info=True)
        self._post_incident_rca(entry)
        return True

    def _incident_channel_messages_text(self, channel_id: str) -> str:
        lines: list[str] = []
        cursor = None
        for _ in range(5):
            try:
                resp = self.slack_client.conversations_history(
                    channel=channel_id, limit=200, cursor=cursor,
                )
            except Exception:
                logger.warning("iq: RCA history fetch failed", exc_info=True)
                break
            for msg in reversed(resp.get("messages") or []):
                text = (msg.get("text") or "").strip()
                if text:
                    lines.append(f"{msg.get('ts', '')} <@{msg.get('user', 'unknown')}>: {text}")
            cursor = (resp.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                break
        return "\n".join(lines)

    def _post_incident_rca(self, entry) -> None:
        try:
            origin_url = self._build_origin_url(entry.origin_channel, entry.thread_ts)
            rca = generate_incident_rca(
                messages_text=self._incident_channel_messages_text(entry.channel_id),
                transcript_text=getattr(entry, "transcript_text", None) or "",
                origin_url=origin_url,
                ollama_url=self.ollama_url,
                ollama_model=self.ollama_model,
            )
            blocks = render_rca_blocks(rca)
            self.slack_client.chat_postMessage(
                channel=entry.channel_id,
                text="AI RCA",
                blocks=blocks,
                unfurl_links=False,
                unfurl_media=False,
            )
            self.slack_client.chat_postMessage(
                channel=entry.origin_channel,
                thread_ts=entry.thread_ts,
                text="AI RCA",
                blocks=blocks,
                unfurl_links=False,
                unfurl_media=False,
            )
        except Exception:
            logger.warning("iq: RCA post failed", exc_info=True)

    def _bridge_thread_reply(self, *, origin_channel: str,
                             thread_ts: str, user_id: str) -> bool:
        """Fire-and-forget invite for late thread repliers. Returns True
        if the thread is escalated and we attempted an invite (caller
        short-circuits the normal reply-path resolver); False if the
        thread is not escalated."""
        entry = self._incident_channels.get(thread_ts)
        if entry is None:
            return False
        if entry.resolved_at is not None:
            return True
        try:
            self.slack_client.conversations_invite(
                channel=entry.channel_id, users=user_id,
            )
        except SlackApiError as e:
            code = e.response.get("error") if e.response else None
            if code in ("already_in_channel", "cant_invite_self"):
                pass
            else:
                logger.warning("iq: bridge invite failed (%s)", code,
                               exc_info=True)
        except Exception:
            logger.warning("iq: bridge invite unexpected", exc_info=True)
        return True

    def _handle_thread_reply(self, *, origin_channel: str,
                             thread_ts: str, user_id: str,
                             text: str) -> None:
        """Called from handle_message reply-path. Runs the bridge first;
        if the thread is escalated, short-circuit and skip
        classify_resolution (Invariant #10)."""
        if self._bridge_thread_reply(
            origin_channel=origin_channel, thread_ts=thread_ts,
            user_id=user_id,
        ):
            return

    def _handle_incident_channel_message(self, *, channel_id: str,
                                         user_id: str, text: str) -> None:
        """Called from handle_message when a message lands in a known
        incident channel. Gated by `incident_resolution_detector_enabled`."""
        if not config.get_all().get("incident_resolution_detector_enabled"):
            return
        entry = self._incident_channels.get_by_channel_id(channel_id)
        if entry is None or entry.resolved_at is not None:
            return
        if not text or not text.strip():
            return
        try:
            verdict = classify_resolution(
                text,
                ollama_url=os.environ.get("OLLAMA_URL", ""),
                ollama_model=os.environ.get("OLLAMA_MODEL", "qwen2.5:32b"),
            )
        except Exception:
            logger.warning("iq: in-channel classify_resolution failed",
                           exc_info=True)
            return
        if verdict != ResolutionVerdict.RESOLVED:
            return
        self._resolve_incident(
            channel_id=channel_id, by_user_id="LLM", reason="llm",
        )


def _heartbeat():
    """Log a heartbeat every 60 seconds to confirm the bot is alive."""
    while True:
        logger.info("Heartbeat: Socket Mode connection alive")
        time.sleep(60)


# --- Self-healing watchdog --------------------------------------------------
# 2026-04-25: bot went silent for 36h after slack_bolt's Socket Mode entered a
# BrokenPipeError reconnect loop. The in-process heartbeat kept logging
# "alive" because the thread itself was still scheduled — only the WebSocket
# was dead. Container had to be restarted manually.
#
# Fix: attach a logging.Handler to the slack_sdk/slack_bolt loggers, count
# ERROR-level records over a sliding window, and os._exit(1) when we cross
# a threshold. Docker's `restart: unless-stopped` policy then revives us.

_WATCHDOG_WINDOW_SEC = 300         # look at the last 5 minutes
_WATCHDOG_ERROR_LIMIT = 20         # >20 ERRORs in 5 min ⇒ force restart


class _SocketHealthHandler(logging.Handler):
    """Counts ERROR records from slack_sdk/slack_bolt within a sliding
    window. When the count exceeds the limit, force-exit so Docker
    restarts the container with a fresh socket pool."""

    def __init__(self, window_sec: int, limit: int):
        super().__init__(level=logging.ERROR)
        self._window_sec = window_sec
        self._limit = limit
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D401
        if record.levelno < logging.ERROR:
            return
        now = time.time()
        with self._lock:
            self._timestamps.append(now)
            cutoff = now - self._window_sec
            # Drop timestamps outside the window.
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.pop(0)
            count = len(self._timestamps)
        if count > self._limit:
            logger.error(
                "Watchdog: %d slack errors in last %ds (limit %d) — "
                "forcing exit so Docker restarts the container",
                count, self._window_sec, self._limit,
            )
            # Hard exit. SystemExit would be caught by slack_bolt's loop;
            # os._exit bypasses Python finalizers and is exactly what we
            # want here — Docker's restart policy will spin us back up.
            os._exit(1)


def _install_socket_watchdog() -> None:
    """Attach the health handler to the slack_sdk + slack_bolt loggers."""
    health = _SocketHealthHandler(
        window_sec=_WATCHDOG_WINDOW_SEC, limit=_WATCHDOG_ERROR_LIMIT,
    )
    for name in ("slack_sdk", "slack_bolt"):
        lg = logging.getLogger(name)
        lg.addHandler(health)
    logger.info(
        "Watchdog installed: force-exit if >%d slack errors in %ds",
        _WATCHDOG_ERROR_LIMIT, _WATCHDOG_WINDOW_SEC,
    )


def _sweep_questionnaires_once(handler, now: int) -> None:
    """One tick of the questionnaire TTL sweep. Per-entry try/except so
    one bad entry can't abort the rest. Called from _pending_sweep_loop."""
    cfg = config.get_all()
    ttl = int(cfg.get("incident_questionnaire_ttl_sec", 86400))
    with handler._open_questionnaires_lock:
        snapshot = list(handler._open_questionnaires.items())
    for thread_ts, (_channel, _qts, posted_at) in snapshot:
        if posted_at + ttl >= now:
            continue
        try:
            handler._close_questionnaire(
                thread_ts, reason="ttl", closed_by=None,
            )
        except Exception:
            logger.warning("iq: sweep close failed for %s",
                           thread_ts, exc_info=True)


def _sweep_incident_archives_once(handler, now: float) -> None:
    """Archive resolved incidents whose archive_at has elapsed.
    Called on each tick of _pending_sweep_loop."""
    entries = handler._incident_channels.all_pending_archive(now)
    for entry in entries:
        try:
            handler.slack_client.conversations_archive(
                channel=entry.channel_id,
            )
            handler._incident_channels.mark_archived(
                entry.thread_ts, archived_at=now,
            )
            logger.info("iq: archived incident channel %s for thread %s",
                        entry.channel_id, entry.thread_ts)
        except SlackApiError as e:
            code = e.response.get("error") if e.response else None
            if code in ("already_archived", "channel_not_found"):
                handler._incident_channels.mark_archived(
                    entry.thread_ts, archived_at=now,
                )
            else:
                logger.warning("iq: archive failed (%s) for %s",
                               code, entry.channel_id, exc_info=True)
        except Exception:
            logger.warning("iq: archive unexpected failure for %s",
                           entry.channel_id, exc_info=True)


def _pending_sweep_loop(pending, p3_prompts, post_fallback_ask, post_p3_expiry,
                        handler=None):
    """Unified sweep tick — 10s interval, iterates both the classifier
    pending-store and the P3 prompt-store. For each expired entry, calls
    the corresponding terminal-state edit helper. One bad entry can't
    halt the thread (outer try/except); one bad store can't starve the
    other (inner try/except per dispatch)."""
    while True:
        try:
            now = int(time.time())
            for e in pending.expire_pending(now):
                try:
                    post_fallback_ask(e)
                except Exception:
                    logger.warning(
                        "classifier: fallback-ask post failed", exc_info=True,
                    )
            for p in p3_prompts.expire(now):
                try:
                    post_p3_expiry(p)
                except Exception:
                    logger.warning(
                        "p3: expiry edit failed", exc_info=True,
                    )
            if handler is not None:
                try:
                    _sweep_questionnaires_once(handler, now)
                except Exception:
                    logger.warning(
                        "iq: sweep tick failed", exc_info=True,
                    )
            # Phase 2: incident channel archive sweep
            if handler is not None:
                try:
                    _sweep_incident_archives_once(handler, time.time())
                except Exception:
                    logger.warning("iq: sweep section failed", exc_info=True)
        except Exception:
            logger.exception("pending/p3 sweep failed")
        time.sleep(10)


def _mark_seen(handler, ts: str) -> bool:
    if not ts:
        return True
    with handler._cache_lock:
        if ts in handler._seen_messages:
            return False
        handler._seen_messages[ts] = True
    return True


def _handle_app_mention(handler, alert_qa, event: dict) -> None:
    if event.get("subtype") or event.get("bot_id"):
        return
    if event.get("user") == handler.bot_user_id:
        return
    ts = event.get("ts", "")
    app_mention_ts = f"app_mention:{ts}" if ts else ""
    if not _mark_seen(handler, app_mention_ts):
        return
    if alert_qa.handle_event(event, is_app_mention=True):
        return
    handler.handle_message(event, skip_alert_qa=True)


def _handle_reaction_removed(event: dict) -> None:
    logger.debug(
        "Ignoring reaction_removed reaction=%s channel=%s ts=%s",
        event.get("reaction"),
        (event.get("item") or {}).get("channel"),
        (event.get("item") or {}).get("ts"),
    )


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    )

    slack_bot_token = os.environ["SLACK_BOT_TOKEN"]
    slack_app_token = os.environ["SLACK_APP_TOKEN"]

    app = App(token=slack_bot_token)

    irm_client = GrafanaIRMClient(
        base_url=os.environ["GRAFANA_IRM_URL"],
        api_key=os.environ["GRAFANA_IRM_API_KEY"],
        integration_id=os.environ["GRAFANA_IRM_INTEGRATION_ID"],
        escalation_chain_id=os.environ["GRAFANA_IRM_ESCALATION_CHAIN_ID"],
        # OnCall REST API lives on a different URL than the direct_paging
        # webhook and wants its own token. Optional — absent means the
        # On-Call button returns the empty-roster ephemeral.
        oncall_api_url=os.environ.get("GRAFANA_ONCALL_API_URL", ""),
        oncall_api_token=os.environ.get("GRAFANA_ONCALL_API_TOKEN", ""),
    )

    # Resolve group IDs for @noc and @domains-sre
    group_handles = {"noc", "domains-sre"}
    group_ids = []
    try:
        groups_resp = app.client.usergroups_list()
        for group in groups_resp.get("usergroups", []):
            if group.get("handle") in group_handles:
                group_ids.append(group["id"])
                logger.info("Resolved group @%s -> %s", group["handle"], group["id"])
    except Exception:
        logger.critical("Failed to resolve Slack user group IDs. Cannot start.")
        raise

    if len(group_ids) < len(group_handles):
        logger.warning(
            "Only resolved %d of %d groups. Some groups may not be found.",
            len(group_ids), len(group_handles),
        )

    group_cache = GroupMembershipCache(group_ids=group_ids)

    jira_client = JiraCRClient(
        base_url=os.environ.get("JIRA_BASE_URL", ""),
        email=os.environ.get("JIRA_EMAIL", ""),
        api_token=os.environ.get("JIRA_API_TOKEN", ""),
    ) if os.environ.get("JIRA_BASE_URL") else None

    occir_client = OccirJiraClient(
        base_url=os.environ.get("JIRA_BASE_URL", ""),
        email=os.environ.get("JIRA_EMAIL", ""),
        api_token=os.environ.get("JIRA_API_TOKEN", ""),
    )

    turnover = TurnoverCoordinator(
        db_path=os.environ.get("NOC_TURNOVER_DB_PATH", "/data/noc_turnover.db"),
        slack_client=app.client,
        occir_client=occir_client,
        config=config,
        activity=activity,
        jira_base_url=os.environ.get("JIRA_BASE_URL", ""),
        dashboard_url=os.environ.get(
            "UIP_DASHBOARD_URL",
            "https://uip.example.com/noc-bot#ongoing",
        ),
        ops_noc_channel_id=os.environ["OPS_NOC_CHANNEL_ID"],
        default_turnover_channel_id=os.environ.get(
            "NOC_TURNOVER_CHANNEL_ID", "C0477H3BFHD"
        ),
        ollama_url=os.environ.get("OLLAMA_URL", ""),
        ollama_model=os.environ.get("OLLAMA_MODEL", "qwen2.5:32b"),
        turnover_ollama_model=os.environ.get("TURNOVER_OLLAMA_MODEL", ""),
        jira_client=jira_client,
        group_cache=group_cache,
    ) if os.environ.get("OPS_NOC_CHANNEL_ID") else None

    alert_qa_config = AlertQAConfig.from_env()
    alert_qa_timeout = alert_qa_config.source_timeout_sec
    alert_qa = AlertQAHandler(
        slack_client=app.client,
        group_cache=group_cache,
        config=alert_qa_config,
        sources=[
            SlackOpsNocSearchSource(
                slack_client=app.client,
                ops_noc_channel_id=alert_qa_config.ops_noc_channel_id,
                ops_noc_channel_name=os.environ.get(
                    "OPS_NOC_CHANNEL_NAME", "ops-noc"
                ),
                timeout=alert_qa_timeout,
                group_cache=group_cache,
            ),
            ConfluenceSearchSource(
                base_url=alert_qa_config.confluence_base_url,
                email=alert_qa_config.confluence_email,
                api_token=alert_qa_config.confluence_api_token,
                timeout=alert_qa_timeout,
            ),
            JiraOccirSearchSource(
                base_url=alert_qa_config.jira_base_url,
                email=alert_qa_config.jira_email,
                api_token=alert_qa_config.jira_api_token,
                timeout=alert_qa_timeout,
            ),
        ],
    )

    handler = MessageHandler(
        slack_client=app.client,
        irm_client=irm_client,
        channel_id=os.environ["OPS_NOC_CHANNEL_ID"],
        group_membership_cache=group_cache,
        jira_client=jira_client,
        ollama_url=os.environ.get("OLLAMA_URL", ""),
        ollama_model=os.environ.get("OLLAMA_MODEL", "qwen2.5:32b"),
        jira_base_url=os.environ.get("JIRA_BASE_URL", ""),
        turnover_coordinator=turnover,
        alert_qa=alert_qa,
    )

    reaction_handler = ReactionHandler(
        slack_client=app.client,
        channel_id=os.environ["OPS_NOC_CHANNEL_ID"],
        group_membership_cache=group_cache,
        occir_client=occir_client,
        ollama_url=os.environ.get("OLLAMA_URL", ""),
        ollama_model=os.environ.get("OLLAMA_MODEL", "qwen2.5:32b"),
        jira_base_url=os.environ.get("JIRA_BASE_URL", ""),
        turnover_coordinator=turnover,
    )

    change_tracker = ChangeTracker(
        slack_client=app.client,
        jira_client=jira_client,
        config=config,
        activity=activity,
        state_path=os.environ.get(
            "CHANGE_TRACKER_STATE_PATH", "/data/change_tracker_state.json"
        ),
        jira_base_url=os.environ.get("JIRA_BASE_URL", ""),
        default_channel_id=os.environ.get("CHANGE_TRACKER_CHANNEL_ID", ""),
        ollama_url=os.environ.get("OLLAMA_URL", ""),
        ollama_model=_change_tracker_ollama_model(),
    ) if jira_client else None

    # Initialize API config and activity log
    init_api(handler=handler, change_tracker=change_tracker,
             turnover_coordinator=turnover)
    start_api_server()

    if change_tracker:
        change_tracker.start()
        logger.info("Change tracker started")
    else:
        logger.warning("Change tracker disabled: no Jira client configured")

    if turnover is not None:
        turnover.start()
        logger.info("Turnover coordinator started")

    # Resolve our own bot user id once so the delete handler can verify that
    # a target message really came from us.
    try:
        auth = app.client.auth_test()
        bot_user_id = auth.get("user_id") if isinstance(auth, dict) else auth["user_id"]
    except Exception:
        bot_user_id = None
        logger.warning("bot: auth_test failed; wastebasket delete will match on bot_id only")

    message_deleter = BotMessageDeleter(
        slack_client=app.client, group_cache=group_cache,
        turnover_coordinator=turnover, change_tracker=change_tracker,
        bot_user_id=bot_user_id,
    )

    # Interactive UI wiring: registers @app.action / @app.view listeners for
    # the block-kit buttons on escalation ack posts and turnover posts.
    bot_actions = BotActions(
        slack_client=app.client,
        irm_client=irm_client,
        occir_client=occir_client,
        reaction_handler=reaction_handler,
        turnover=turnover,
        group_cache=group_cache,
        bot_user_id=bot_user_id,
        oncall_schedule_id=os.environ.get("GRAFANA_IRM_ONCALL_SCHEDULE_ID", ""),
        manager_chain_id=os.environ.get(
            "GRAFANA_IRM_ESCALATION_CHAIN_MANAGER_ID", ""
        ),
        reescalate_cooldown_sec=int(
            os.environ.get("RE_ESCALATE_COOLDOWN_SEC", "300")
        ),
        activity=activity,
        jira_base_url=os.environ.get("JIRA_BASE_URL", ""),
    )
    from pending_classification import PendingStore
    pending = PendingStore(
        now_fn=lambda: int(time.time()),
        wait_window_sec=config.get_all().get(
            "escalation_classifier_wait_window_sec", 60,
        ),
    )
    handler.pending = pending  # back-fill; avoids constructor churn

    p3_prompts = P3PromptStore(
        now_fn=lambda: int(time.time()),
        ttl_sec=int(config.get_all().get("p3_prompt_ttl_sec", 900)),
    )
    handler.p3_prompts = p3_prompts  # back-fill; avoids constructor churn

    # Startup guard: live mode without the master flag is incoherent.
    # Force live=False for this process lifetime; operator must flip
    # both flags together. Misconfig degrades safely rather than
    # silently doing nothing.
    _cfg = config.get_all()
    if _cfg.get("p3_live_mode") and not _cfg.get("p3_enabled"):
        logger.error(
            "p3: p3_live_mode=True but p3_enabled=False — "
            "forcing p3_live_mode=False for this process",
        )
        config.update({"p3_live_mode": False})

    bot_actions.p3_prompts = p3_prompts  # back-fill; Task 9 adds ctor kwarg
    handler.post_p3_prompt = bot_actions.post_p3_prompt
    bot_actions._post_iq_cb = handler.post_incident_questionnaire
    handler._bot_actions = bot_actions
    bot_actions._close_questionnaire_cb = handler._close_questionnaire

    # Phase 2: wire incident channel creator + bot_actions callbacks
    handler._incident_channel_creator = IncidentChannelCreator(
        slack_client=app.client,
        store=handler._incident_channels,
        group_cache=group_cache,
        close_questionnaire_cb=handler._close_questionnaire,
        ops_noc_channel_id=os.environ["OPS_NOC_CHANNEL_ID"],
    )
    bot_actions._create_channel_cb = handler._create_incident_channel
    bot_actions._resolve_incident_cb = handler._resolve_incident
    bot_actions._incident_channel_store = handler._incident_channels

    sweep_thread = threading.Thread(
        target=_pending_sweep_loop,
        args=(
            pending,
            p3_prompts,
            bot_actions.post_fallback_ask,
            bot_actions.post_p3_expiry,
            handler,
        ),
        daemon=True,
    )
    sweep_thread.start()
    logger.info("pending_classification + p3 sweep started")

    bot_actions.register(app)

    @app.event("message")
    def on_message(event, say):
        handler.handle_message(event)

    @app.event("app_mention")
    def on_app_mention(event, say):
        _handle_app_mention(handler, alert_qa, event)

    @app.event("reaction_added")
    def on_reaction_added(event):
        try:
            reaction_handler.handle_reaction(event)
        except Exception:
            logger.exception("reaction_handler.handle_reaction failed")
        if turnover is not None:
            turnover.ingestor.handle_resolve_reaction(event)
        message_deleter.handle_reaction(event)

    @app.event("reaction_removed")
    def on_reaction_removed(event):
        _handle_reaction_removed(event)

    # Start heartbeat thread
    heartbeat_thread = threading.Thread(target=_heartbeat, daemon=True)
    heartbeat_thread.start()

    # Self-healing watchdog: force-exit if the slack loggers emit a storm
    # of errors (the BrokenPipeError reconnect loop we hit on 2026-04-25).
    _install_socket_watchdog()

    logger.info("NOC Escalation Bot starting in Socket Mode")
    socket_handler = SocketModeHandler(app, slack_app_token)
    socket_handler.start()


if __name__ == "__main__":
    main()
