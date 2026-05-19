"""Incident channel — pure module (rendering + slug LLM).

No Slack client, no store, no network except Ollama HTTP in generate_slug.
All functions are thread-safe and side-effect-free except where marked.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# Slack platform constraints
SLACK_CHANNEL_MAX_LEN = 80
SLACK_CHANNEL_VALID_RE = re.compile(r"[a-z0-9._-]+")
# Kebab-case slug from LLM: lowercase letters, digits, single hyphens.
# Rejects leading/trailing hyphens, multiple consecutive hyphens, empty.
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

OLLAMA_TIMEOUT_SECONDS = 15
TEXT_CHAR_LIMIT = 4000

# Block IDs (fixed — tests assert on them, register() uses them)
BLOCK_INITIAL_HEADER = "ic_header"
BLOCK_INITIAL_METADATA = "ic_metadata"
BLOCK_INITIAL_BACKLINK = "ic_backlink"
BLOCK_RESOLVED_ACTIONS = "ic_resolved_actions"
BLOCK_RESOLVED_ANNOUNCE = "ic_resolved_announce"
BLOCK_RCA_SUMMARY = "ic_rca_summary"

# Action IDs
ACTION_RESOLVED = "iq:channel:resolved"
ACTION_ADD_TRANSCRIPT = "iq:channel:add_transcript"


def _sanitize_slug(slug: str) -> str:
    """Lowercase, drop invalid chars, collapse adjacent hyphens."""
    lower = slug.lower()
    # Keep only a-z 0-9 - _ . ; everything else becomes a hyphen
    parts = []
    for ch in lower:
        if SLACK_CHANNEL_VALID_RE.match(ch):
            parts.append(ch)
        else:
            parts.append("-")
    collapsed = re.sub(r"-+", "-", "".join(parts)).strip("-._")
    return collapsed


def compute_channel_name(
    today: date,
    slug: str,
    *,
    collision_suffix: int | None = None,
) -> str:
    """Format `incident-YYYYMMDD-<slug>[-N]` respecting the 80-char cap.

    Truncates the slug portion (never the date or prefix) when the total
    exceeds SLACK_CHANNEL_MAX_LEN. Sanitizes invalid chars.
    """
    date_part = today.strftime("%Y%m%d")
    prefix = f"incident-{date_part}-"
    suffix = f"-{collision_suffix}" if collision_suffix is not None else ""
    clean_slug = _sanitize_slug(slug) or "incident"
    available = SLACK_CHANNEL_MAX_LEN - len(prefix) - len(suffix)
    available = max(0, available)
    if len(clean_slug) > available:
        clean_slug = clean_slug[:available].rstrip("-._") or "incident"
    return f"{prefix}{clean_slug}{suffix}"


_SLUG_PROMPT = """You produce a SHORT kebab-case slug naming an incident, from its opening Slack post.

Rules:
- 2 to 5 words, hyphen-separated.
- Lowercase ASCII letters and digits only. Hyphens between words.
- No articles ("a", "the"), no filler ("about", "with").
- Focus on the symptom + the system. E.g. "prod-api-5xx", "db-replica-lag", "kafka-backlog".
- If you cannot determine a good slug, return {"slug": ""}.

Post:
<<TEXT>>

Reply with JSON only: {"slug": "<kebab-case-or-empty>"}"""


def generate_slug(text: str, *, ollama_url: str,
                  ollama_model: str) -> Optional[str]:
    """LLM slug generator. Returns clean kebab-case slug or None.

    Fail-closed: every error path returns None so the caller falls back
    to the deterministic slug "unknown" (slug_source="fallback"). Never
    raises.
    """
    prompt = _SLUG_PROMPT.replace("<<TEXT>>", text[:TEXT_CHAR_LIMIT])
    payload = {
        "model": ollama_model,
        "format": "json",
        "stream": False,
        "messages": [
            {"role": "system",
             "content": "You are a strict JSON responder. Output only the requested JSON."},
            {"role": "user", "content": prompt},
        ],
    }
    try:
        resp = requests.post(f"{ollama_url}/api/chat", json=payload,
                             timeout=OLLAMA_TIMEOUT_SECONDS)
    except requests.RequestException as e:
        logger.warning("generate_slug: Ollama request failed: %s", e)
        return None

    if resp.status_code != 200:
        logger.warning("generate_slug: Ollama %d: %s",
                       resp.status_code, resp.text[:200])
        return None

    try:
        outer = resp.json()
        if not isinstance(outer, dict):
            logger.warning("generate_slug: non-dict outer response")
            return None
        content = outer.get("message", {})
        if not isinstance(content, dict):
            logger.warning("generate_slug: non-dict message field")
            return None
        parsed = json.loads(content.get("content", ""))
    except (ValueError, json.JSONDecodeError) as e:
        logger.warning("generate_slug: malformed response (%s)", e)
        return None

    if not isinstance(parsed, dict):
        logger.warning("generate_slug: non-dict slug payload")
        return None
    slug = parsed.get("slug", "")
    if not isinstance(slug, str) or not slug:
        return None
    slug = slug.strip()
    if not SLUG_RE.match(slug):
        logger.warning("generate_slug: slug %r failed SLUG_RE", slug)
        return None
    return slug


def _fmt_et(ts: float) -> str:
    """Format UTC epoch seconds as 'HH:MM ET' in America/New_York."""
    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo("America/New_York")
    except Exception:
        tz = timezone.utc
    return datetime.fromtimestamp(ts, tz=tz).strftime("%H:%M ET")


def _fmt_date(ts: float) -> str:
    """Format UTC epoch seconds as ISO date YYYY-MM-DD in ET."""
    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo("America/New_York")
    except Exception:
        tz = timezone.utc
    return datetime.fromtimestamp(ts, tz=tz).strftime("%Y-%m-%d")


def render_initial_post(
    state: Any,  # QuestionnaireState — avoid circular import at module-load time
    *,
    origin_url: str,
    escalator_user_id: str,
    op_user_id: str,
) -> list[dict]:
    """Render the pinned metadata post for a newly-created incident channel.

    Contains: header, raised-by/escalated-by, backlink to origin thread,
    and whatever impact/sev/ticket the Phase 1 questionnaire captured.
    """
    meta_lines = []
    impact = getattr(state, "customer_impact", None)
    if impact:
        meta_lines.append(f"*Customer-impacting:* {impact}")
    if getattr(state, "channel_requested", False):
        meta_lines.append("*Channel requested:* yes")

    metadata_text = "\n".join(meta_lines) if meta_lines else "_No metadata captured yet._"

    return [
        {
            "type": "header",
            "block_id": BLOCK_INITIAL_HEADER,
            "text": {"type": "plain_text", "text": "Incident channel"},
        },
        {
            "type": "section",
            "block_id": BLOCK_INITIAL_METADATA,
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"Raised by <@{op_user_id}>. Escalated by <@{escalator_user_id}>.\n"
                    f"{metadata_text}"
                ),
            },
        },
        {
            "type": "section",
            "block_id": BLOCK_INITIAL_BACKLINK,
            "text": {
                "type": "mrkdwn",
                "text": f"<{origin_url}|Origin thread in #ops-noc>",
            },
        },
    ]


def render_resolved_button() -> list[dict]:
    """Render the pinned Resolved button — clicked to close the incident."""
    return [
        {
            "type": "actions",
            "block_id": BLOCK_RESOLVED_ACTIONS,
            "elements": [
                {
                    "type": "button",
                    "action_id": ACTION_ADD_TRANSCRIPT,
                    "text": {"type": "plain_text", "text": "Add transcript"},
                },
                {
                    "type": "button",
                    "action_id": ACTION_RESOLVED,
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "✅ Resolved"},
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Resolve incident?"},
                        "text": {
                            "type": "plain_text",
                            "text": "This marks the incident resolved and schedules channel archive in 7 days.",
                        },
                        "confirm": {"type": "plain_text", "text": "Resolve"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
            ],
        },
    ]


def render_resolved_announcement(
    *,
    by_display_name: str,
    resolved_at: float,
    archive_at: float,
) -> list[dict]:
    """Render the chat.update replacement for the resolved-button post."""
    return [
        {
            "type": "section",
            "block_id": BLOCK_RESOLVED_ANNOUNCE,
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"✅ *Resolved* by {by_display_name} at {_fmt_et(resolved_at)}. "
                    f"This channel archives on {_fmt_date(archive_at)}."
                ),
            },
        },
    ]
