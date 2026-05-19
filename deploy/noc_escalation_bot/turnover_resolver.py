"""Resolution detection for NOC Turnover incidents.

Priority order during a sweep (first hit wins, sticky):
  1. OCCIR Jira status in RESOLVED_STATUSES
  2. LLM thread classification (only if new thread activity since last sweep)
  3. Reaction-based resolution — handled event-driven by ingestor, not here.
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Optional

import requests

from turnover_store import TurnoverStore

logger = logging.getLogger(__name__)

RESOLVED_STATUSES = {"Done", "Resolved", "Closed", "Cancelled"}

THREAD_CHAR_LIMIT = 2000
OLLAMA_TIMEOUT_SECONDS = 15


def classify_resolution(thread_text: str, ollama_url: str, ollama_model: str) -> bool:
    """Ask the LLM whether the thread indicates the incident is resolved.

    Returns False on any error. Never raises.
    """
    prompt = (
        "Given this #ops-noc incident thread, determine whether the incident "
        "has been resolved or mitigated.\n"
        "Reply ONLY with JSON: {\"resolved\": true|false}.\n\n"
        "IMPORTANT: The LAST message in the thread is the MOST RECENT. "
        "Weight recent messages heavily — an earlier \"still broken\" is "
        "superseded by a later \"back to normal\".\n\n"
        "Resolution signals (any of these in a recent message = resolved): "
        "\"resolved\", \"mitigated\", \"fixed\", \"false alarm\", \"all clear\", "
        "\"nevermind\", \"ignore this\", \"working now\", \"closing this out\", "
        "\"back up\", \"back online\", \"back to normal\", \"recovered\", "
        "\"up again\", \"stable now\", \"no further alerts\", \"cleared\", "
        "\"self-recovered\", \"self-healed\", \"flap\" / \"flapped\" (transient, "
        "now fine), \"no impact\", \"benign\".\n"
        "Non-resolution signals: questions, investigations in progress, "
        "acknowledgments without a fix, \"looking into it\", \"will update\", "
        "\"still seeing it\", \"still investigating\".\n\n"
        f"Thread:\n---\n{thread_text[:THREAD_CHAR_LIMIT]}\n---"
    )
    # Diagnostic log so we can see exactly what the LLM got when a thread
    # the humans knew was resolved comes back as not-resolved.
    tail = thread_text[-200:] if thread_text else ""
    logger.info("turnover_resolver: classify_resolution tail=%r", tail)
    payload = {
        "model": ollama_model,
        "format": "json",
        "stream": False,
        "messages": [
            {"role": "system",
             "content": "You are a strict JSON classifier. Output only the requested JSON."},
            {"role": "user", "content": prompt},
        ],
    }
    try:
        resp = requests.post(f"{ollama_url}/api/chat", json=payload,
                             timeout=OLLAMA_TIMEOUT_SECONDS)
    except requests.RequestException as e:
        logger.warning("turnover_resolver: Ollama request failed: %s", e)
        return False

    if resp.status_code != 200:
        logger.warning("turnover_resolver: Ollama %d: %s",
                       resp.status_code, resp.text[:200])
        return False

    try:
        content = resp.json().get("message", {}).get("content", "")
        parsed = json.loads(content)
    except (ValueError, json.JSONDecodeError) as e:
        logger.warning("turnover_resolver: malformed Ollama response (%s)", e)
        return False

    resolved = parsed.get("resolved")
    if not isinstance(resolved, bool):
        logger.warning("turnover_resolver: non-bool 'resolved' value: %r", resolved)
        return False

    logger.info("turnover_resolver: classify_resolution verdict=%s", resolved)
    return resolved


class Resolver:
    def __init__(self, store: TurnoverStore, occir_client, ollama_url: str,
                 ollama_model: str, activity, now_fn: Callable[[], int]):
        self._store = store
        self._occir = occir_client
        self._ollama_url = ollama_url
        self._ollama_model = ollama_model
        self._activity = activity
        self._now = now_fn

    def mark_resolved(self, incident_ts: str, source: str,
                      by_user_id: Optional[str] = None,
                      resolved_at: Optional[int] = None) -> bool:
        """Record resolution. Returns True if newly marked, False if already set.

        `resolved_at` lets callers override the wall-clock "when". LLM-based
        resolution runs on a polling loop and only discovers the thread is
        resolved minutes later, so MTTR should anchor on the resolving
        message's timestamp, not the sweep's."""
        effective = resolved_at if resolved_at is not None else self._now()
        was_new = self._store.mark_resolved(
            incident_ts, resolved_at=effective, source=source, by_user_id=by_user_id,
        )
        if was_new:
            self._activity.add(
                "turnover_resolved",
                f"{incident_ts} via {source} by {by_user_id or '-'}",
            )
        return was_new

    def check_incident(self, inc, *, force: bool = False) -> bool:
        """Apply Jira → LLM resolution detection to a single incident.

        Returns True if the incident was newly marked resolved by this call.
        With force=True, the LLM is consulted even if there is no new thread
        activity since the last sweep (used by the 'Re-run LLM resolve check'
        button for idle threads that were missed).
        """
        now = self._now()

        # 1. Jira wins
        if inc.occir_key and self._occir is not None:
            try:
                status = self._occir.get_status(inc.occir_key)
            except Exception as e:
                logger.warning("turnover_resolver: Jira status failed for %s: %s",
                                inc.occir_key, e)
                status = None
            if status:
                if status in RESOLVED_STATUSES:
                    return self.mark_resolved(inc.slack_ts, source="jira")
                # Capture current status for the dashboard
                self._store.update_occir_status(inc.slack_ts, status)

        # 2. LLM — only if new thread activity since last sweep (unless forced)
        last_reply = self._store.latest_reply_at(inc.slack_ts)
        should_consult = force or (last_reply and last_reply > (inc.last_swept_at or 0))
        if should_consult:
            thread_text = self._store.concat_thread(
                inc.slack_ts, char_limit=THREAD_CHAR_LIMIT)
            if classify_resolution(thread_text, self._ollama_url, self._ollama_model):
                # Credit the author of the latest reply — that's the
                # evidence the LLM consumed to call it resolved.
                lr = self._store.last_reply(inc.slack_ts)
                return self.mark_resolved(
                    inc.slack_ts, source="llm",
                    by_user_id=lr.user_id if lr else None,
                    resolved_at=lr.posted_at if lr else None,
                )

        self._store.update_last_swept(inc.slack_ts, now)
        return False

    def sweep(self) -> None:
        """Walk all open incidents and apply Jira → LLM resolution detection."""
        for inc in self._store.get_open_incidents():
            self.check_incident(inc)
