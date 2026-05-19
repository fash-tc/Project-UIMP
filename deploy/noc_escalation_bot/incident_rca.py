from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)

RCA_TIMEOUT_SECONDS = 20
TEXT_LIMIT = 12000


@dataclass
class IncidentRCA:
    summary: str
    impact: str
    timeline: list[str]
    cause: str
    actions: list[str]
    evidence: list[str]
    used_transcript: bool


def _fallback_rca(*, messages_text: str, transcript_text: str) -> IncidentRCA:
    return IncidentRCA(
        summary="RCA needs review. AI summary was unavailable.",
        impact="Review incident channel and transcript for confirmed impact.",
        timeline=[line[:180] for line in messages_text.splitlines()[:8] if line.strip()],
        cause="Not determined from automated RCA.",
        actions=["Review evidence and add follow-up actions."],
        evidence=["Slack incident channel"] + (["Meet transcript"] if transcript_text else []),
        used_transcript=bool(transcript_text.strip()),
    )


def generate_incident_rca(
    *,
    messages_text: str,
    transcript_text: str,
    origin_url: str,
    ollama_url: str,
    ollama_model: str,
) -> IncidentRCA:
    if not ollama_url:
        return _fallback_rca(messages_text=messages_text, transcript_text=transcript_text)

    prompt = (
        "Create a concise incident RCA from Slack incident-channel messages "
        "and an optional meeting transcript. Return JSON with keys: "
        "summary, impact, timeline, cause, actions, evidence. timeline/actions/evidence are arrays. "
        "Use only provided evidence; say unknown when unknown.\n\n"
        f"Origin thread: {origin_url}\n\n"
        f"Slack messages:\n---\n{messages_text[:TEXT_LIMIT]}\n---\n\n"
        f"Meet transcript:\n---\n{transcript_text[:TEXT_LIMIT]}\n---"
    )
    payload = {
        "model": ollama_model,
        "format": "json",
        "stream": False,
        "messages": [
            {"role": "system", "content": "You write concise SRE incident RCAs as valid JSON only."},
            {"role": "user", "content": prompt},
        ],
    }
    try:
        resp = requests.post(f"{ollama_url}/api/chat", json=payload, timeout=RCA_TIMEOUT_SECONDS)
        resp.raise_for_status()
        content = resp.json()["message"]["content"]
        data = json.loads(content)
        return IncidentRCA(
            summary=str(data.get("summary") or "Summary unavailable.")[:1000],
            impact=str(data.get("impact") or "Impact unknown.")[:1000],
            timeline=[str(x)[:300] for x in (data.get("timeline") or [])][:12],
            cause=str(data.get("cause") or "Cause unknown.")[:1000],
            actions=[str(x)[:300] for x in (data.get("actions") or [])][:12],
            evidence=[str(x)[:300] for x in (data.get("evidence") or [])][:12],
            used_transcript=bool(transcript_text.strip()),
        )
    except Exception:
        logger.warning("incident_rca: generation failed", exc_info=True)
        return _fallback_rca(messages_text=messages_text, transcript_text=transcript_text)


def _bullets(items: list[str]) -> str:
    if not items:
        return "- None captured"
    return "\n".join(f"- {item}" for item in items)


def render_rca_blocks(rca: IncidentRCA) -> list[dict]:
    transcript_status = "Meet transcript included" if rca.used_transcript else "No Meet transcript attached"
    return [
        {"type": "header", "text": {"type": "plain_text", "text": "AI RCA"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": (
            f"*Summary*\n{rca.summary}\n\n"
            f"*Impact*\n{rca.impact}\n\n"
            f"*Cause / suspected cause*\n{rca.cause}\n\n"
            f"*Transcript:* {transcript_status}"
        )}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Timeline*\n{_bullets(rca.timeline)}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Follow-ups*\n{_bullets(rca.actions)}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Evidence*\n{_bullets(rca.evidence)}"}},
    ]
