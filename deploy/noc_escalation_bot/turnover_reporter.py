"""Private shift turnover report builder.

Public turnover stays active-only. This module builds the audit/report view
on demand and sends it privately to the requester.
"""

from __future__ import annotations

from typing import Callable

from turnover_renderer import _escape_slack, _format_age
from turnover_store import Incident

MAX_BLOCK_TEXT = 2800
MAX_ROW_TEXT = 1800


def build_shift_report(
    *,
    store,
    shift_key: str,
    window_start: int,
    window_end: int,
    user_name_lookup: Callable[[str], str],
    jira_base_url: str,
) -> tuple[str, list[dict]]:
    in_window = list(store.get_incidents_in_window(window_start, window_end))
    window_ts = {i.slack_ts for i in in_window}
    carryover = [
        i for i in store.get_open_incidents()
        if i.slack_ts not in window_ts and i.shift_excluded_at is None
    ]
    open_rows = [i for i in in_window if i.resolved_at is None and i.shift_excluded_at is None]
    resolved_rows = [i for i in in_window if i.resolved_at is not None]
    dismissed_rows = [i for i in in_window if i.shift_excluded_at is not None]
    active_open = open_rows + carryover

    lines: list[str] = [
        f"*Private Turnover Report* - `{_escape_slack(shift_key)}`",
        "",
        "*Counts*",
        f"- active/open: {len(active_open)}",
        f"- resolved: {len(resolved_rows)}",
        f"- dismissed/skipped: {len(dismissed_rows)}",
        f"- carryover: {len(carryover)}",
        "",
    ]
    lines.extend(_section("Active / Open", active_open, _open_line, user_name_lookup, jira_base_url))
    lines.extend(_section("Resolved", resolved_rows, _resolved_line, user_name_lookup, jira_base_url))
    lines.extend(_section("Dismissed / Skipped", dismissed_rows, _dismissed_line, user_name_lookup, jira_base_url))

    text = "\n".join(lines).strip()
    return text, _blocks_from_text(text)


def _section(name, rows, formatter, user_name_lookup, jira_base_url) -> list[str]:
    out = [f"*{name}* ({len(rows)})"]
    if not rows:
        out.extend(["- none", ""])
        return out
    for inc in rows:
        out.append(formatter(inc, user_name_lookup, jira_base_url))
    out.append("")
    return out


def _open_line(inc: Incident, user_name_lookup, jira_base_url: str) -> str:
    parts = [_linked_title(inc, jira_base_url), _owner(inc, user_name_lookup)]
    parts.append(f"{inc.reply_count} replies")
    if inc.shift_excluded_at is not None:
        parts.append("skipped")
    return _row("- " + " - ".join(parts))


def _resolved_line(inc: Incident, user_name_lookup, jira_base_url: str) -> str:
    parts = [_linked_title(inc, jira_base_url)]
    if inc.resolved_source:
        parts.append(f"source {inc.resolved_source}")
    if inc.resolved_by_user_id:
        parts.append(f"by @{_escape_slack(user_name_lookup(inc.resolved_by_user_id))}")
    if inc.resolved_at is not None:
        parts.append(f"MTTR {_format_age(max(0, inc.resolved_at - inc.posted_at))}")
    return _row("- " + " - ".join(parts))


def _dismissed_line(inc: Incident, user_name_lookup, jira_base_url: str) -> str:
    parts = [_linked_title(inc, jira_base_url), _owner(inc, user_name_lookup), "skipped"]
    return _row("- " + " - ".join(parts))


def _linked_title(inc: Incident, jira_base_url: str) -> str:
    title = _escape_slack(inc.title_summary or inc.text_preview or inc.slack_ts)
    if len(title) > 140:
        title = title[:126].rstrip() + " ...(truncated)"
    ticket = _ticket(inc, jira_base_url)
    base = f"<{inc.permalink}|{title}>" if inc.permalink else title
    return f"{base} {ticket}".strip()


def _ticket(inc: Incident, jira_base_url: str) -> str:
    if not inc.occir_key:
        return ""
    key = _escape_slack(inc.occir_key)
    if jira_base_url:
        return f"(<{jira_base_url.rstrip('/')}/browse/{key}|{key}>)"
    return f"({key})"


def _owner(inc: Incident, user_name_lookup) -> str:
    if not inc.claimed_by_user_id:
        return "unowned"
    return f"@{_escape_slack(user_name_lookup(inc.claimed_by_user_id))}"


def _row(value: str) -> str:
    if len(value) <= MAX_ROW_TEXT:
        return value
    return value[: MAX_ROW_TEXT - 14].rstrip() + " ...(truncated)"


def _blocks_from_text(text: str) -> list[dict]:
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in text.splitlines():
        extra = len(line) + 1
        if current and current_len + extra > MAX_BLOCK_TEXT:
            chunks.append("\n".join(current))
            current = []
            current_len = 0
        current.append(line)
        current_len += extra
    if current:
        chunks.append("\n".join(current))
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": chunk}}
        for chunk in chunks
    ]
