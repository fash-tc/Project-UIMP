"""Pure Slack message builder for NOC Turnover posts."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Callable, Optional
from zoneinfo import ZoneInfo

from turnover_store import Incident, ThreadReply
from turnover_time import ET

logger = logging.getLogger(__name__)

MAX_SLACK_CHARS = 4000
CARRYOVER_TRUNCATE_LIMIT = 10
STRUCTURED_ROW_LIMIT = 8

SLOT_DISPLAY = {
    "evening":   "Evening Shift",
    "overnight": "Overnight Shift",
    "morning":   "Morning Shift",
}


def _split_mrkdwn_to_sections(text: str, limit: int = 2900) -> list[dict]:
    """Split mrkdwn text into a list of Slack section blocks under `limit`.

    Splits on blank-line boundaries to avoid cutting lines in half. Slack's
    section block has a 3000-char mrkdwn cap; we default to 2900 for slack."""
    if len(text) <= limit:
        return [{"type": "section",
                 "text": {"type": "mrkdwn", "text": text}}]
    parts = text.split("\n\n")
    chunks: list[str] = []
    cur = ""
    for p in parts:
        candidate = p if not cur else cur + "\n\n" + p
        if len(candidate) > limit and cur:
            chunks.append(cur)
            cur = p
        else:
            cur = candidate
    if cur:
        chunks.append(cur)
    return [{"type": "section",
             "text": {"type": "mrkdwn", "text": c}} for c in chunks]


def _underline(s: str) -> str:
    """Fake underline for Slack mrkdwn using the U+0332 combining low line.

    Slack has no native underline in mrkdwn, but the fonts Slack ships on
    desktop + mobile render the combining low line correctly, which yields a
    continuous underline under every glyph."""
    return "".join(ch + "\u0332" if ch != " " else ch for ch in s)


# Slack mention tokens — if these survive into a rendered turnover post they
# re-activate and ping the referenced user/group/channel every time the shift
# post is edited. Always neutralize before rendering.
_RE_SUBTEAM = re.compile(r"<!subteam\^[A-Z0-9]+(?:\|([^>]+))?>")
_RE_USER = re.compile(r"<@[UW][A-Z0-9]+(?:\|([^>]+))?>")
_RE_CHANNEL_BROADCAST = re.compile(r"<!(channel|here|everyone)(?:\|[^>]+)?>")
_RE_LINK_LABELED = re.compile(r"<([^|>]+)\|([^>]+)>")
_RE_LINK_BARE = re.compile(r"<([^>]+)>")


def _strip_mentions(s: str) -> str:
    """Replace Slack mention tokens with inert plaintext so re-rendering does
    not ping the referenced users/groups. Also flattens link tokens so what's
    left is safe to escape."""
    if not s:
        return s
    s = _RE_SUBTEAM.sub(lambda m: f"@{m.group(1)}" if m.group(1) else "@group", s)
    s = _RE_USER.sub(lambda m: f"@{m.group(1)}" if m.group(1) else "@user", s)
    s = _RE_CHANNEL_BROADCAST.sub(lambda m: f"@{m.group(1)}", s)
    s = _RE_LINK_LABELED.sub(lambda m: m.group(2), s)
    s = _RE_LINK_BARE.sub(lambda m: m.group(1), s)
    return s


def _escape_slack(s: str) -> str:
    s = _strip_mentions(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _format_age(seconds: int) -> str:
    if seconds < 60:
        return "<1m"
    if seconds < 3600:
        return f"{seconds // 60}m"
    h, rem = divmod(seconds, 3600)
    m = rem // 60
    return f"{h}h {m}m"


def _format_et_time(unix_sec: int) -> str:
    return datetime.fromtimestamp(unix_sec, ET).strftime("%H:%M")


def _format_et_datetime(unix_sec: int) -> str:
    return datetime.fromtimestamp(unix_sec, ET).strftime("%b %d %H:%M")


def _format_et_range(start_unix: int, end_unix: int) -> str:
    start = datetime.fromtimestamp(start_unix, ET)
    end = datetime.fromtimestamp(end_unix, ET)
    return f"{start.strftime('%b %d, %H:%M')}–{end.strftime('%H:%M')} ET"


_TITLE_MAX = 60

# OCCIR ticket keys surface as their own segment in the rendered line, so
# drop them (and any other standalone ticket-looking tokens) from the title.
_RE_TICKET_TOKEN = re.compile(r"\b[A-Z]{2,}-\d+\b")


def _derive_title(raw: str) -> str:
    """Pick a meaningful title line from the message text.

    Slack alert messages routinely lead with `@group @user` pings and a
    ticket link before the actual description. Strip all that noise and
    return the first line with real content."""
    if not raw:
        return "(no text)"
    cleaned = _strip_mentions(raw)
    best = ""
    for line in cleaned.splitlines():
        # Measure substantive content: strip ticket tokens, @mention stubs
        # left over from _strip_mentions (e.g. "@group", "@user"), and
        # punctuation. A line is usable if what's left has ≥8 real chars.
        probe = _RE_TICKET_TOKEN.sub("", line)
        probe = re.sub(r"@\w+", "", probe)
        probe = re.sub(r"[\s:·•\-—–|]+", " ", probe).strip()
        if len(probe) >= 8:
            best = line.strip()
            break
    if not best:
        # Fallback: whole text collapsed into one line.
        best = " ".join(cleaned.split()).strip() or "(no text)"
    # Drop any remaining ticket tokens and stray mention markers from the
    # final title — the ticket key renders as its own segment elsewhere.
    best = _RE_TICKET_TOKEN.sub("", best)
    best = re.sub(r"@\w+", "", best)
    best = re.sub(r"\s+", " ", best).strip(" -—–·:")
    if not best:
        best = "(no text)"
    if len(best) > _TITLE_MAX:
        best = best[:_TITLE_MAX] + "…"
    return best


# Back-compat alias — some call sites may still use the old name.
_truncate_title = _derive_title


def _pick_title(inc: Incident) -> str:
    """Prefer the LLM-distilled summary when available, fall back to the
    heuristic derivation."""
    summary = (inc.title_summary or "").strip()
    if summary:
        if len(summary) > _TITLE_MAX:
            summary = summary[:_TITLE_MAX] + "…"
        return summary
    return _derive_title(inc.text_preview or "(no text)")


def _ticket_segment(inc: Incident, jira_base_url: str) -> str:
    """Render the ticket key (as a link) or an empty string if none.

    When there is no ticket we deliberately omit the inline segment — a single
    `⚠ no ticket` warning on the detail line is clearer than rendering it
    twice (spec: the warning badge is the canonical "no ticket" indicator)."""
    if inc.occir_key:
        return f" <{jira_base_url}/browse/{inc.occir_key}|{inc.occir_key}>"
    return ""


def _open_line(inc: Incident,
               last_reply: Optional[ThreadReply],
               user_name_lookup: Callable[[str], str],
               now_utc: datetime,
               jira_base_url: str) -> str:
    posted_display = _format_et_time(inc.posted_at)
    title = _escape_slack(_pick_title(inc))
    ticket = _ticket_segment(inc, jira_base_url)
    head = f"  • *<{inc.permalink}|{posted_display}>*{ticket} — {title}"
    age = _format_age(int(now_utc.timestamp()) - inc.posted_at)
    parts = _state_parts(
        inc, is_carryover=False,
        user_name_lookup=user_name_lookup, now_utc=now_utc,
    )
    parts.extend([f"age {age}", f"{inc.reply_count} replies"])
    if last_reply:
        last_reply_user = _escape_slack(user_name_lookup(last_reply.user_id))
        last_reply_time = _format_et_time(last_reply.posted_at)
        parts.append(f"last reply {last_reply_time} by @{last_reply_user}")
    detail = "     " + " · ".join(parts)
    if not inc.occir_key:
        detail += "  ⚠ *no ticket*"
    return head + "\n" + detail


def _carryover_line(inc: Incident,
                    last_reply: Optional[ThreadReply],
                    user_name_lookup: Callable[[str], str],
                    now_utc: datetime,
                    jira_base_url: str) -> str:
    posted_display = _format_et_datetime(inc.posted_at)
    title = _escape_slack(_pick_title(inc))
    ticket = _ticket_segment(inc, jira_base_url)
    head = f"  • *<{inc.permalink}|{posted_display}>*{ticket} — {title}"
    age = _format_age(int(now_utc.timestamp()) - inc.posted_at)
    parts = _state_parts(
        inc, is_carryover=True,
        user_name_lookup=user_name_lookup, now_utc=now_utc,
    )
    parts.extend([f"age {age}", f"{inc.reply_count} replies"])
    if last_reply:
        last_reply_user = _escape_slack(user_name_lookup(last_reply.user_id))
        last_reply_time = _format_et_time(last_reply.posted_at)
        parts.append(f"last reply {last_reply_time} by @{last_reply_user}")
    detail = "     " + " · ".join(parts)
    if not inc.occir_key:
        detail += "  ⚠ *no ticket*"
    return head + "\n" + detail


def _incident_line_mrkdwn(
    inc: Incident,
    jira_base_url: str,
    *,
    is_carryover: bool,
    user_name_lookup: Callable[[str], str],
    now_utc: datetime,
) -> str:
    if inc.resolved_at is None:
        posted_display = _format_et_time(inc.posted_at)
    else:
        posted_display = _format_et_datetime(inc.posted_at)
    title = _escape_slack(_pick_title(inc))
    ticket = _ticket_segment(inc, jira_base_url)
    line = f"*<{inc.permalink}|{posted_display}>*{ticket} - {title}"
    line += "\n" + " - ".join(_state_parts(
        inc,
        is_carryover=is_carryover,
        user_name_lookup=user_name_lookup,
        now_utc=now_utc,
    ))
    if not inc.occir_key:
        line += "  *no ticket*"
    return line

def _incident_card_mrkdwn(
    inc: Incident,
    jira_base_url: str,
    *,
    is_carryover: bool,
    user_name_lookup: Callable[[str], str],
    now_utc: datetime,
) -> str:
    posted_display = _format_et_time(inc.posted_at)
    posted_link = f"<{inc.permalink}|{posted_display}>" if inc.permalink else posted_display
    title = _escape_slack(_pick_title(inc))
    if inc.occir_key:
        ticket = f" · <{jira_base_url}/browse/{inc.occir_key}|{inc.occir_key}>"
    else:
        ticket = " · *no ticket*"
    state = " · ".join(_state_parts(
        inc,
        is_carryover=is_carryover,
        user_name_lookup=user_name_lookup,
        now_utc=now_utc,
    ))
    age = _format_age(int(now_utc.timestamp()) - inc.posted_at)
    meta = f"{state} · age {age} · {inc.reply_count} replies"
    return f"*{posted_link}*{ticket}\n{title}\n_{meta}_"

def _incident_block(
    inc: Incident,
    jira_base_url: str,
    *,
    is_carryover: bool,
    user_name_lookup: Callable[[str], str],
    now_utc: datetime,
) -> list[dict]:
    """Build Slack blocks for an open/carryover incident.

    Slack overflow menus allow at most five options, so the always-needed row
    actions render as buttons and the remaining operator controls live in a
    bounded overflow menu.
    """
    elements = []
    if not inc.claimed_by_user_id:
        elements.append({
            "type": "button",
            "action_id": f"t_row:claim:{inc.slack_ts}",
            "text": {"type": "plain_text", "text": "Claim"},
            "value": "claim",
        })
    elements.append({
        "type": "button",
        "action_id": f"t_row:resolve:{inc.slack_ts}",
        "text": {"type": "plain_text", "text": "Resolve"},
        "value": "resolve",
    })
    if inc.occir_key is None:
        elements.append({
            "type": "button",
            "action_id": f"t_row:ticket:{inc.slack_ts}",
            "text": {"type": "plain_text", "text": "Create OCCIR"},
            "value": "ticket",
        })
    more_options = [
        {"text": {"type": "plain_text", "text": "Re-run resolve check"}, "value": "rerun"},
        {"text": {"type": "plain_text", "text": "Skip from this shift"}, "value": "skip"},
        {"text": {"type": "plain_text", "text": "Delete from turnover"}, "value": "delete"},
    ]
    elements.append({
        "type": "overflow",
        "action_id": f"t_row:more:{inc.slack_ts}",
        "options": more_options,
    })
    return [{
        "type": "section",
        "text": {"type": "mrkdwn", "text": _incident_card_mrkdwn(
            inc,
            jira_base_url,
            is_carryover=is_carryover,
            user_name_lookup=user_name_lookup,
            now_utc=now_utc,
        )},
    }, {
        "type": "actions",
        "elements": elements,
    }]

def _resolved_line(inc: Incident,
                   user_name_lookup: Callable[[str], str],
                   jira_base_url: str) -> str:
    posted_display = _format_et_time(inc.posted_at)
    title = _escape_slack(_pick_title(inc))
    ticket = _ticket_segment(inc, jira_base_url)
    resolved_hm = _format_et_time(inc.resolved_at or 0)
    mttr = _format_age((inc.resolved_at or 0) - inc.posted_at)
    source = inc.resolved_source or "unknown"
    # "by whom" is the actor (reactor / manual-resolver / author of the
    # reply the LLM consumed). Jira-driven resolutions have no user attached.
    by_id = inc.resolved_by_user_id
    if by_id:
        by = _escape_slack(user_name_lookup(by_id))
        resolved_segment = f"✅ {resolved_hm} by @{by} ({source})"
    else:
        resolved_segment = f"✅ {resolved_hm} ({source})"
    return (
        f"  • <{inc.permalink}|{posted_display}>{ticket} — {title} "
        f"· {resolved_segment} · MTTR {mttr}"
    )


def _mrkdwn_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _format_handoff_section(items: list, user_name_lookup) -> str:
    if not items:
        return ""
    lines = ["📎 *Passed from previous shift*"]
    for it in items:
        head = f"• *{_mrkdwn_escape(it.title)}*"
        if it.link:
            head += f" — <{it.link}|link>"
        author = user_name_lookup(it.author_user_id) or it.author_user_id
        head += f"  _by {author}_"
        lines.append(head)
        if it.note:
            for nl in it.note.splitlines():
                if nl.strip():
                    lines.append(f"     └ {_mrkdwn_escape(nl)}")
    return "\n".join(lines)


def _format_metrics_strip(metrics: dict) -> str:
    def fmt_sec(s):
        return _format_age(int(s)) if s is not None else "—"

    def fmt_pct(p):
        return f"{p * 100:.0f}%" if p is not None else "—"

    def fmt_avg(a):
        return f"{a:.1f}" if a is not None else "—"

    lines = [
        f"📊 This shift: {metrics['total']} escalations · "
        f"{metrics['resolved']} resolved · {metrics['open']} open",
        f"⏱  Response (Median): {fmt_sec(metrics['median_ack_seconds'])} · "
        f"{fmt_pct(metrics['pct_acked_within_threshold'])} acked "
        f"≤{metrics['threshold_minutes']}m · "
        f"avg {fmt_avg(metrics['avg_replies'])} replies/incident",
        f"🕓 MTTR (Median): {fmt_sec(metrics['mttr_seconds'])}",
    ]
    return "\n".join(lines)


def _summary_get(summary, key: str, default=0):
    if isinstance(summary, dict):
        return summary.get(key, default)
    return getattr(summary, key, default)


def _format_sweep_summary(sweep_summary) -> str:
    if not sweep_summary:
        return ""
    errors = _summary_get(sweep_summary, "errors", 0)
    if errors:
        if isinstance(errors, (list, tuple)):
            detail = "; ".join(str(e) for e in errors)
        else:
            detail = f"{errors} errors"
        return f"Resolve check incomplete: {detail}. Items kept open."
    checked = _summary_get(sweep_summary, "checked", 0)
    auto_cleared = _summary_get(
        sweep_summary, "auto_resolved",
        _summary_get(sweep_summary, "auto_cleared", 0),
    )
    still_open = _summary_get(sweep_summary, "still_open", 0)
    carried_forward = _summary_get(sweep_summary, "carried_forward", still_open)
    return (
        "Pre-shift resolve check: "
        f"checked {checked} - auto-cleared {auto_cleared} - "
        f"still open {still_open} - carried forward {carried_forward}"
    )


def _format_active_metrics_strip(metrics: dict) -> str:
    def fmt_sec(s):
        return _format_age(int(s)) if s is not None else "-"

    def fmt_pct(p):
        return f"{p * 100:.0f}%" if p is not None else "-"

    def fmt_avg(a):
        return f"{a:.1f}" if a is not None else "-"

    return "\n".join([
        f"This shift: {metrics['total']} escalations - {metrics['open']} open",
        f"Response (Median): {fmt_sec(metrics['median_ack_seconds'])} - "
        f"{fmt_pct(metrics['pct_acked_within_threshold'])} acked "
        f"<={metrics['threshold_minutes']}m - "
        f"avg {fmt_avg(metrics['avg_replies'])} replies/incident",
    ])


def _state_parts(
    inc: Incident,
    *,
    is_carryover: bool,
    user_name_lookup: Callable[[str], str],
    now_utc: datetime,
) -> list[str]:
    parts = ["Open"]
    if is_carryover:
        parts.append("Carried forward")
    if inc.claimed_by_user_id:
        owner = _escape_slack(user_name_lookup(inc.claimed_by_user_id))
        parts.append(f"@{owner}")
    else:
        parts.append("Unowned")
    if getattr(inc, "highlighted_at", None):
        parts.append("Highlighted")
    now_ts = int(now_utc.timestamp())
    snoozed_until = getattr(inc, "snoozed_until", None)
    if snoozed_until and snoozed_until > now_ts:
        parts.append(f"Snoozed until {_format_et_datetime(snoozed_until)}")
    return parts


def _build_sections(
    in_window_open: list[Incident],
    in_window_resolved: list[Incident],
    carryover: list[Incident],
    last_reply_lookup,
    user_name_lookup,
    now_utc: datetime,
    jira_base_url: str,
    *,
    collapse_resolved: bool = False,
    carryover_truncate: bool = False,
    open_truncate: bool = False,
    handoff_items: list | None = None,
) -> str:
    parts: list[str] = []
    spacer = "\u200b"

    if handoff_items:
        handoff_block = _format_handoff_section(handoff_items, user_name_lookup)
        parts.append(handoff_block)
        parts.append("")

    parts.append(spacer)
    parts.append(f"*Needs action*  (*{len(in_window_open)}*)")
    shown_open = in_window_open
    if open_truncate and len(in_window_open) > CARRYOVER_TRUNCATE_LIMIT:
        shown_open = in_window_open[:CARRYOVER_TRUNCATE_LIMIT]
    for inc in shown_open:
        parts.append(_open_line(inc, last_reply_lookup(inc.slack_ts),
                                user_name_lookup, now_utc, jira_base_url))
    if open_truncate and len(in_window_open) > CARRYOVER_TRUNCATE_LIMIT:
        parts.append(f"  ... +{len(in_window_open) - CARRYOVER_TRUNCATE_LIMIT} not shown")

    parts.append("")
    parts.append(spacer)
    parts.append(f"*Still open from previous shift*  (*{len(carryover)}*)")
    shown_carry = carryover
    if carryover_truncate and len(carryover) > CARRYOVER_TRUNCATE_LIMIT:
        shown_carry = carryover[:CARRYOVER_TRUNCATE_LIMIT]
    for inc in shown_carry:
        parts.append(_carryover_line(inc, last_reply_lookup(inc.slack_ts),
                                     user_name_lookup, now_utc, jira_base_url))
    if carryover_truncate and len(carryover) > CARRYOVER_TRUNCATE_LIMIT:
        parts.append(f"  ... +{len(carryover) - CARRYOVER_TRUNCATE_LIMIT} not shown")

    return "\n".join(parts)

def render_shift_post(
    shift_key: str,
    window_start: int,
    window_end: int,
    incidents_in_window: list[Incident],
    carryover_incidents: list[Incident],
    handoff_items: list,
    last_reply_lookup: Callable[[str], Optional[ThreadReply]],
    unique_responder_lookup: Callable[[str], int],
    metrics: dict,
    user_name_lookup: Callable[[str], str],
    now_utc: datetime,
    next_refresh_utc: datetime,
    jira_base_url: str,
    dashboard_url: str,
    sweep_summary=None,
) -> tuple[str, list[dict]]:
    """Build the Slack message for a shift turnover post.

    Returns (text, blocks). `text` is the plain-mrkdwn fallback used for
    notifications; `blocks` is the rendered layout with a rich_text header
    so the title can be bold + underlined (mrkdwn has no underline)."""

    slot = shift_key.rsplit("-", 1)[-1]
    slot_display = SLOT_DISPLAY.get(slot, slot)

    # The header is built as a rich_text block (see bottom of function) so
    # Slack renders the title bold AND underlined — mrkdwn has no underline.
    # Here we build the plain-text fallback equivalent (used for notifications
    # and as the message `text=` parameter).
    title_plain = (
        f"Turnover — {slot_display} "
        f"- ({_format_et_range(window_start, window_end)})"
    )
    header_title = f"📋 {title_plain}"
    sweep_line = _format_sweep_summary(sweep_summary)
    header_lines = [header_title, "\u200b", _format_active_metrics_strip(metrics)]
    if sweep_line:
        header_lines.append(sweep_line)
    header = "\n".join(header_lines)

    in_window_open = [i for i in incidents_in_window if i.resolved_at is None]
    in_window_resolved = [i for i in incidents_in_window if i.resolved_at is not None]

    sections = _build_sections(
        in_window_open, in_window_resolved, carryover_incidents,
        last_reply_lookup, user_name_lookup, now_utc, jira_base_url,
        handoff_items=handoff_items,
    )

    footer = (
        f"_refreshed {now_utc.astimezone(ET).strftime('%H:%M')} · "
        f"next {next_refresh_utc.astimezone(ET).strftime('%H:%M')} ET_"
    )

    msg = f"{header}\n\n{sections}\n\n{footer}"

    def _truncate_if_needed() -> tuple[str, str]:
        nonlocal sections
        m = f"{header}\n\n{sections}\n\n{footer}"
        if len(m) <= MAX_SLACK_CHARS:
            return m, sections
        sections = _build_sections(
            in_window_open, in_window_resolved, carryover_incidents,
            last_reply_lookup, user_name_lookup, now_utc, jira_base_url,
            collapse_resolved=True, handoff_items=handoff_items,
        )
        m = f"{header}\n\n{sections}\n\n{footer}"
        if len(m) <= MAX_SLACK_CHARS:
            return m, sections
        sections = _build_sections(
            in_window_open, in_window_resolved, carryover_incidents,
            last_reply_lookup, user_name_lookup, now_utc, jira_base_url,
            collapse_resolved=True, carryover_truncate=True,
            handoff_items=handoff_items,
        )
        m = f"{header}\n\n{sections}\n\n{footer}"
        if len(m) <= MAX_SLACK_CHARS:
            return m, sections
        sections = _build_sections(
            in_window_open, in_window_resolved, carryover_incidents,
            last_reply_lookup, user_name_lookup, now_utc, jira_base_url,
            collapse_resolved=True, carryover_truncate=True, open_truncate=True,
            handoff_items=handoff_items,
        )
        m = f"{header}\n\n{sections}\n\n{footer}"
        if len(m) > MAX_SLACK_CHARS:
            logger.warning(
                "turnover_renderer: message still over %d chars after truncation (len=%d)",
                MAX_SLACK_CHARS, len(m),
            )
            m = m[:MAX_SLACK_CHARS - len("\n...(truncated)")] + "\n...(truncated)"
        return m, sections

    msg, sections = _truncate_if_needed()

    # --- blocks layout -----------------------------------------------------
    # Header: rich_text block with bold+underline on the title string.
    header_block = {
        "type": "rich_text",
        "elements": [{
            "type": "rich_text_section",
            "elements": [
                {"type": "text", "text": "📋 "},
                {
                    "type": "text",
                    "text": title_plain,
                    "style": {"bold": True, "underline": True},
                },
            ],
        }],
    }

    actions_block = {
        "type": "actions",
        "elements": [
            {"type": "button",
             "action_id": "t_refresh",
             "text": {"type": "plain_text", "text": "Refresh"},
             "value": shift_key},
            {"type": "button",
             "action_id": "t_add_handoff",
             "text": {"type": "plain_text", "text": "Add handoff"},
             "value": shift_key},
            {"type": "button",
             "action_id": "t_report",
             "text": {"type": "plain_text", "text": "Report"},
             "value": shift_key},
            {"type": "button",
             "action_id": "t_delete",
             "style": "danger",
             "text": {"type": "plain_text", "text": "Delete"},
             "value": shift_key,
             "confirm": {
                 "title": {"type": "plain_text", "text": "Delete turnover post?"},
                 "text":  {"type": "plain_text", "text": "This removes the post from Slack and its scheduler row."},
                 "confirm": {"type": "plain_text", "text": "Delete"},
                 "deny":    {"type": "plain_text", "text": "Cancel"},
             }},
        ],
    }
    # Context/footer block.
    footer_block = {
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": footer}],
    }

    # Build the structured block list.  We aim for a per-incident section with
    # an overflow accessory for each open/carryover incident.  Slack's block
    # cap is 50; if we'd exceed 45 (safety margin), fall back to the old
    # single-section-text layout so the post always renders.
    structured_blocks: list[dict] = [header_block]

    # Compact metrics strip
    structured_blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": _format_active_metrics_strip(metrics)}],
    })
    if sweep_line:
        structured_blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": sweep_line}],
        })
    structured_blocks.append({"type": "divider"})

    # Handoff items (above incidents, matching mrkdwn text order)
    if handoff_items:
        structured_blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": _format_handoff_section(handoff_items, user_name_lookup)},
        })

    structured_blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn",
                 "text": f"*Open Incidents* ({len(in_window_open)})"},
    })
    shown_open_blocks = in_window_open[:STRUCTURED_ROW_LIMIT]
    for inc in shown_open_blocks:
        structured_blocks.extend(_incident_block(
            inc,
            jira_base_url,
            is_carryover=False,
            user_name_lookup=user_name_lookup,
            now_utc=now_utc,
        ))
    if len(in_window_open) > len(shown_open_blocks):
        structured_blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"_... +{len(in_window_open) - len(shown_open_blocks)} not shown_",
            },
        })

    structured_blocks.append({"type": "divider"})

    if carryover_incidents:
        structured_blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"*Carryover* ({len(carryover_incidents)})"},
        })
        shown_carryover_blocks = carryover_incidents[:STRUCTURED_ROW_LIMIT]
        for inc in shown_carryover_blocks:
            structured_blocks.extend(_incident_block(
                inc,
                jira_base_url,
                is_carryover=True,
                user_name_lookup=user_name_lookup,
                now_utc=now_utc,
            ))
        if len(carryover_incidents) > len(shown_carryover_blocks):
            structured_blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"_... +{len(carryover_incidents) - len(shown_carryover_blocks)} not shown_",
                },
            })
    else:
        structured_blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "_Carryover clear · no open items from previous shift_",
            },
        })

    structured_blocks.append({"type": "divider"})
    structured_blocks.append(actions_block)
    structured_blocks.append(footer_block)

    # Safety net: if we'd bust Slack's 50-block cap fall back to the old
    # body-as-single-section layout (preserves notification previews).
    BLOCK_THRESHOLD = 45
    if len(structured_blocks) > BLOCK_THRESHOLD:
        logger.warning(
            "turnover_renderer: %d blocks would exceed threshold (%d); "
            "falling back to mrkdwn-section layout",
            len(structured_blocks), BLOCK_THRESHOLD,
        )
        body_parts = [_format_active_metrics_strip(metrics)]
        if sweep_line:
            body_parts.append(sweep_line)
        body_parts.extend([sections, footer])
        body_text = "\n\n".join(body_parts)
        body_blocks = _split_mrkdwn_to_sections(body_text, limit=2900)
        blocks = [header_block] + body_blocks + [actions_block, footer_block]
    else:
        blocks = structured_blocks

    return msg, blocks


def render_escalation_ack_blocks(
    *, thread_ts: str, channel_id: str,
    escalator_name: str, escalated_at_et: str,
    has_ticket: bool, is_test: bool,
) -> tuple[str, list[dict]]:
    """Return (fallback_text, blocks) for the post-escalation thread ack."""
    header_text = "🚨 Escalated to domains-sre via Grafana IRM"
    if is_test:
        header_text = "⚠️ [TEST CHANNEL] " + header_text
    context_text = (
        f"{header_text}\n"
        f"at {escalated_at_et} ET · by @{escalator_name} · thread {thread_ts}"
    )
    value = f"{thread_ts}|{channel_id}"
    buttons = [
        ("esc:re_escalate",  "🔁 Re-escalate"),
        ("esc:page_manager", "📣 Page Manager"),
        ("esc:oncall",       "👥 On-call"),
        ("esc:resolve",      "✅ Resolve"),
    ]
    if not has_ticket:
        buttons.append(("esc:ticket", "Create Incident"))
    buttons.append(("esc:silence", "🔇 Silence 1h"))

    elements = [
        {"type": "button",
         "action_id": aid,
         "text": {"type": "plain_text", "text": label},
         "value": value}
        for (aid, label) in buttons
    ]

    blocks = [
        {"type": "context", "elements": [
            {"type": "mrkdwn", "text": context_text}
        ]},
        {"type": "actions", "elements": elements},
    ]
    return context_text, blocks
