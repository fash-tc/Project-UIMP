"""Incident-questionnaire rendering + parsing — pure, no I/O.

The Slack post is the source of truth for answer state. `render()`
produces the interactive block-kit for an open questionnaire; once a
field is populated on the `QuestionnaireState`, the corresponding
section text is re-rendered to include the answer + setter + time.
`render_closed()` strips every `actions` / `input` / `button` block and
appends a context footnote naming the closer — buttons are gone, the
post is read-only. `parse_state(blocks)` recovers the dataclass from a
rendered post; it must round-trip both open and closed forms so
button handlers can read → mutate → re-render without losing state.

Block IDs are fixed (`iq_impact`, `iq_channel` + `_actions` suffixes)
so parse_state can locate sections by ID rather than position. Action
IDs follow `iq:<question>:<value>` so a single registered handler per
question can branch on the clicked value. Populated sections suffix
`#<epoch>` to the base; see `_block_id` / `_split_block_id`.

Two optional questions (Impact always, Channel when expanded) plus
Resolved button. See the design spec appendix A.1-A.5 for canonical
block-kit JSON.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional
from zoneinfo import ZoneInfo

Impact = Literal["yes", "no", "unknown"]
ResolutionReason = Literal["button", "ttl", "llm"]

# Accepts CR-NNNN, OCCIR-NNNN, OPSNOC-NNNN, SRE-NNNN (1-8 digits). Case-
# insensitive; caller normalizes project prefix to uppercase before store.
TICKET_KEY_RE = re.compile(r"^(CR|OCCIR|OPSNOC|SRE)-\d{1,8}$")

ET = ZoneInfo("America/New_York")

BLOCK_IMPACT = "iq_impact"
BLOCK_IMPACT_ACTIONS = "iq_impact_actions"
BLOCK_CHANNEL = "iq_channel"
BLOCK_CHANNEL_ACTIONS = "iq_channel_actions"
BLOCK_RESOLVED_ACTIONS = "iq_resolved_actions"
BLOCK_CLOSED_FOOTER = "iq_closed_footer"


@dataclass
class QuestionnaireState:
    customer_impact: Optional[Impact] = None
    customer_impact_by: Optional[str] = None
    customer_impact_at: Optional[int] = None
    channel_expanded: bool = False
    channel_requested: bool = False
    channel_requested_by: Optional[str] = None
    channel_requested_at: Optional[int] = None
    resolved: bool = False
    resolved_by: Optional[str] = None
    resolved_at: Optional[int] = None
    resolved_reason: Optional[ResolutionReason] = None


def _iq_action(question: str, value: str) -> str:
    """Build an action_id per the docstring grammar: iq:<question>:<value>."""
    return f"iq:{question}:{value}"


def _fmt_et(epoch: Optional[int]) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=ET).strftime("%H:%M ET")


def _block_id(base: str, epoch: Optional[int]) -> str:
    """Append `#<epoch>` to the base block_id when populated.

    Rendered text prints only `HH:MM ET` (lossy to the minute), so we
    smuggle the full epoch through the block_id suffix. parse_state /
    _split_block_id recover it on the way back in. Unpopulated sections
    keep the bare constant.
    """
    return f"{base}#{epoch}" if epoch else base


def _impact_text(state: QuestionnaireState) -> str:
    if state.customer_impact is None:
        return "*Impact:* _not answered_"
    marker = {
        "yes": "Yes",
        "no": "No",
        "unknown": "Unknown",
    }[state.customer_impact]
    return (f"*Impact:* {marker} - set by "
            f"<@{state.customer_impact_by}> at {_fmt_et(state.customer_impact_at)}")


def _channel_text(state: QuestionnaireState) -> str:
    if not state.channel_requested:
        return "*Channel:* _not requested_"
    return (f"*Channel:* requested by "
            f"<@{state.channel_requested_by}> at "
            f"{_fmt_et(state.channel_requested_at)}")


def render(
    state: QuestionnaireState,
    *,
    thread_ts: str = "",
    channel_id: str = "",
) -> list[dict]:
    """Produce compact interactive block-kit for an open questionnaire."""
    resolved_button = {
        "type": "button",
        "action_id": "iq:resolved",
        "style": "primary",
        "text": {"type": "plain_text", "text": "Resolved"},
        "confirm": {
            "title": {"type": "plain_text", "text": "Resolve incident?"},
            "text": {"type": "plain_text", "text": "Close this questionnaire."},
            "confirm": {"type": "plain_text", "text": "Resolve"},
            "deny": {"type": "plain_text", "text": "Cancel"},
        },
    }
    if thread_ts or channel_id:
        resolved_button["value"] = f"{thread_ts}|{channel_id}"

    return [
        {"type": "section",
         "block_id": _block_id(BLOCK_IMPACT, state.customer_impact_at),
         "text": {"type": "mrkdwn", "text": _impact_text(state)}},
        {"type": "actions", "block_id": BLOCK_IMPACT_ACTIONS, "elements": [
            {"type": "button", "action_id": _iq_action("impact", "yes"),
             "style": "danger",
             "text": {"type": "plain_text", "text": "Yes"}},
            {"type": "button", "action_id": _iq_action("impact", "no"),
             "text": {"type": "plain_text", "text": "No"}},
            {"type": "button", "action_id": _iq_action("impact", "unknown"),
             "text": {"type": "plain_text", "text": "Unknown"}},
        ]},
        {"type": "section",
         "block_id": _block_id(BLOCK_CHANNEL, state.channel_requested_at),
         "text": {"type": "mrkdwn", "text": _channel_text(state)}},
        {"type": "actions", "block_id": BLOCK_CHANNEL_ACTIONS, "elements": [
            {"type": "button", "action_id": "iq:channel", "style": "primary",
             "text": {"type": "plain_text", "text": "Open channel"}},
        ]},
        {"type": "actions", "block_id": BLOCK_RESOLVED_ACTIONS, "elements": [
            resolved_button,
        ]},
    ]

def _closed_footer_text(state: QuestionnaireState) -> str:
    hhmm = _fmt_et(state.resolved_at)
    if state.resolved_reason == "button":
        return (f":white_check_mark: Closed — Resolved by "
                f"<@{state.resolved_by}> at {hhmm}")
    if state.resolved_reason == "ttl":
        return f":white_check_mark: Closed — Auto-closed at {hhmm} (24h TTL)"
    if state.resolved_reason == "llm":
        return (f":white_check_mark: Closed — Auto-detected resolution from "
                f"<@{state.resolved_by}>'s reply at {hhmm}")
    return f":white_check_mark: Closed at {hhmm}"


def render_closed(state: QuestionnaireState) -> list[dict]:
    """Read-only snapshot. No actions, no inputs, no buttons. A final context
    block names the closer (or anonymous for TTL). Channel section appears
    iff state.channel_expanded is True."""
    blocks: list[dict] = [
        {"type": "header",
         "text": {"type": "plain_text", "text": "Incident questionnaire",
                  "emoji": True}},
        {"type": "divider"},
        {"type": "section",
         "block_id": _block_id(BLOCK_IMPACT, state.customer_impact_at),
         "text": {"type": "mrkdwn", "text": _impact_text(state)}},
    ]
    if state.channel_expanded:
        blocks.append(
            {"type": "section",
             "block_id": _block_id(BLOCK_CHANNEL, state.channel_requested_at),
             "text": {"type": "mrkdwn", "text": _channel_text(state)}},
        )
    blocks.extend([
        {"type": "divider"},
        {"type": "context",
         "block_id": _block_id(BLOCK_CLOSED_FOOTER, state.resolved_at),
         "elements": [
            {"type": "mrkdwn", "text": _closed_footer_text(state)},
        ]},
    ])
    return blocks


def _split_block_id(raw: Optional[str]) -> tuple[str, Optional[int]]:
    """Split `iq_impact#1714000000` -> ("iq_impact", 1714000000)."""
    if not raw:
        return "", None
    base, sep, suffix = raw.partition("#")
    if not sep or not suffix.isdigit():
        return base, None
    return base, int(suffix)


_USER_RE = re.compile(r"<@([A-Z0-9]+)>")


def _parse_user(text: str) -> Optional[str]:
    m = _USER_RE.search(text)
    return m.group(1) if m else None


def parse_state(blocks: list[dict]) -> QuestionnaireState:
    """Recover a QuestionnaireState from rendered blocks. Works for both
    render() and render_closed() output on **open** posts. Closed posts are
    terminal — not re-parsed (spec §4 note). Unknown blocks (including
    legacy iq_sev / iq_ticket from pre-1.1 posts) are silently ignored.
    Does not raise on malformed input."""
    by_base: dict[str, tuple[dict, Optional[int]]] = {}
    for b in blocks:
        base, epoch = _split_block_id(b.get("block_id"))
        if base:
            by_base[base] = (b, epoch)

    state = QuestionnaireState()

    # channel_expanded: block-presence marker
    state.channel_expanded = BLOCK_CHANNEL in by_base

    # Impact
    if BLOCK_IMPACT in by_base:
        b, epoch = by_base[BLOCK_IMPACT]
        text = b.get("text", {}).get("text", "")
        if "_not answered_" not in text:
            if "Yes" in text:
                state.customer_impact = "yes"
            elif "No" in text:
                state.customer_impact = "no"
            elif "Unknown" in text:
                state.customer_impact = "unknown"
            state.customer_impact_by = _parse_user(text)
            state.customer_impact_at = epoch

    # Channel
    if BLOCK_CHANNEL in by_base:
        b, epoch = by_base[BLOCK_CHANNEL]
        text = b.get("text", {}).get("text", "")
        if "_not requested_" not in text:
            state.channel_requested = True
            state.channel_requested_by = _parse_user(text)
            state.channel_requested_at = epoch

    # Closed footer
    if BLOCK_CLOSED_FOOTER in by_base:
        b, epoch = by_base[BLOCK_CLOSED_FOOTER]
        text = b.get("elements", [{}])[0].get("text", "")
        state.resolved = True
        state.resolved_at = epoch
        if "Auto-closed" in text:
            state.resolved_reason = "ttl"
            state.resolved_by = None
        elif "Auto-detected resolution" in text:
            state.resolved_reason = "llm"
            state.resolved_by = _parse_user(text)
        elif "Resolved by" in text:
            state.resolved_reason = "button"
            state.resolved_by = _parse_user(text)

    return state
