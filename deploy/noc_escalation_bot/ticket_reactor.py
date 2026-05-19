"""Handles :ticket: emoji reactions → OCCIR Jira incident ticket creation."""

import json
import logging
import os
import re
import threading
import time
from typing import Optional

import requests
from cachetools import TTLCache

from api import config, activity
from occir_jira import OccirJiraClient, OccirJiraError

logger = logging.getLogger(__name__)

_DEFAULT_DEDUP_PATH = os.environ.get("TICKET_DEDUP_PATH", "/data/ticket_dedup.json")
_GENERIC_TITLES = {
    "incident from #ops-noc",
    "incident from ops-noc",
    "ticket requested from #ops-noc",
    "new incident channel created from #ops-noc",
}
_LOCATION_CONTEXT_RE = re.compile(
    r"\b(?:incident|ticket)\b.*\b(?:from|created|requested)\b.*#[a-z0-9_-]+",
    re.IGNORECASE,
)
_SLACK_MARKUP_RE = re.compile(r"<(?:!subteam\^[^>|]+|@[^>|]+|#[^>|]+)(?:\|([^>]+))?>")
_URL_LABEL_RE = re.compile(r"<(https?://[^>|]+)(?:\|([^>]+))?>")


def _is_generic_title(title: str) -> bool:
    normalized = " ".join((title or "").strip().lower().split())
    return normalized in _GENERIC_TITLES or bool(_LOCATION_CONTEXT_RE.search(normalized))


def _derive_title(message_text: str) -> str:
    for raw_line in (message_text or "").splitlines():
        line = _clean_slack_text(raw_line)
        if not line or _is_generic_title(line):
            continue
        if _looks_like_alert_title(line):
            return _trim_title(line)
    for raw_line in (message_text or "").splitlines():
        line = _clean_slack_text(raw_line)
        if line and not _is_generic_title(line):
            return _trim_title(line)
    return ""


def _looks_like_alert_title(line: str) -> bool:
    lowered = line.lower()
    return any(
        marker in lowered
        for marker in (
            "alert",
            "critical",
            "error",
            "failed",
            "host:",
            "non 200",
            "returning 500",
            "timeout",
            "unavailable",
        )
    )


def _clean_slack_text(text: str) -> str:
    text = _URL_LABEL_RE.sub(lambda m: m.group(2) or m.group(1), text or "")
    text = _SLACK_MARKUP_RE.sub(lambda m: m.group(1) or "", text)
    text = text.replace("*", "").replace("_", "").replace("`", "")
    text = " ".join(text.split())
    return text.strip(" -\t")


def _trim_title(title: str, limit: int = 80) -> str:
    if len(title) <= limit:
        return title
    return title[: limit - 3].rstrip(" -") + "..."


class ReactionHandler:
    """Processes reaction_added events and creates OCCIR Jira tickets."""

    def __init__(
        self,
        slack_client,
        channel_id: str,
        group_membership_cache,
        occir_client: OccirJiraClient,
        ollama_url: str,
        ollama_model: str,
        jira_base_url: str,
        dedup_path: str = _DEFAULT_DEDUP_PATH,
        turnover_coordinator=None,
        allowed_channel_ids: Optional[list[str] | set[str] | tuple[str, ...]] = None,
    ):
        self.slack_client = slack_client
        self.channel_id = channel_id
        env_allowed = [
            ch.strip()
            for ch in os.environ.get("TICKET_ALLOWED_CHANNEL_IDS", "").split(",")
            if ch.strip()
        ]
        self.allowed_channel_ids = {channel_id, *env_allowed, *(allowed_channel_ids or [])}
        self.group_cache = group_membership_cache
        self.occir_client = occir_client
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.jira_base_url = jira_base_url.rstrip("/")
        self._dedup_path = dedup_path
        self.turnover = turnover_coordinator

        self._dedup: TTLCache = TTLCache(maxsize=2048, ttl=86400)
        self._dedup_lock = threading.Lock()
        self._load_dedup()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def handle_reaction(self, event: dict) -> None:
        """Process a reaction_added Slack event."""
        # Gate 1: only message reactions (ignore file reactions, etc.)
        item = event.get("item", {})
        if item.get("type") != "message":
            return

        # Gate 2: only the :ticket: reaction
        if event.get("reaction") != "ticket":
            return

        cfg = config.get_all()

        # Gate 3: feature enabled
        if not cfg.get("ticket_reaction_enabled", True):
            return

        # Gate 4: channel check
        channel = item.get("channel", "")
        if channel not in self.allowed_channel_ids and not cfg.get("ticket_any_channel", False):
            return

        # Gate 5: reactor is a member of @noc or @domains-sre
        reactor_id = event.get("user", "")
        members = self.group_cache.get_members(self.slack_client)
        if reactor_id not in members:
            return

        message_ts = item.get("ts", "")
        dedup_key = f"{channel}:{message_ts}"

        # Dedup check — add :white_check_mark: if already ticketed
        with self._dedup_lock:
            if dedup_key in self._dedup:
                try:
                    self.slack_client.reactions_add(
                        channel=channel, timestamp=message_ts, name="white_check_mark"
                    )
                except Exception:
                    logger.warning("Failed to add :white_check_mark: reaction")
                return

        ticket_key = self.create_occir(
            channel=channel, ts=message_ts, requested_by=reactor_id
        )
        if ticket_key is None:
            return

        # Build and post thread confirmation reply
        llm = self._last_llm_result
        confidence = llm["confidence"]
        service = llm["service"]
        ticket_url = f"{self.jira_base_url}/browse/{ticket_key}"
        reply = f"🎫 *<{ticket_url}|{ticket_key}>* created"
        if confidence == "error":
            reply += (
                "\n⚠️ _Could not classify service automatically — "
                "defaulted to Infrastructure. Please update the ticket._"
            )
        elif confidence == "low":
            reply += (
                f"\n⚠️ _Operational Service set to {service} based on context "
                "— please verify._"
            )

        self._post_thread(channel, message_ts, reply)

    def create_occir(self, channel: str, ts: str, requested_by: str, occir_work_type: str = "ticket") -> Optional[str]:
        """Create an OCCIR Jira ticket for the Slack thread at (channel, ts).

        Returns the newly-created OCCIR key, or None if a ticket already
        exists for this thread, creation failed, or the thread isn't eligible.

        This is the same code path as the :ticket: reaction, minus the
        subteam-membership gate and the thread-reply confirmation — callers
        enforce their own gating and post their own confirmation (if any).
        """
        dedup_key = f"{channel}:{ts}"

        # Dedup check — reserve slot immediately to prevent concurrent duplicates
        with self._dedup_lock:
            if dedup_key in self._dedup:
                return None
            # Reserve the slot now; if Jira fails we'll release it to allow retry
            self._dedup[dedup_key] = time.time()

        # Fetch original message text plus thread context. The ticket reaction is
        # sometimes clicked on a channel/turnover context message; replies often
        # contain the actual alert.
        message_text = self._fetch_message_context(channel, ts)
        if not message_text:
            with self._dedup_lock:
                self._dedup.pop(dedup_key, None)
            self._post_thread(
                channel, ts,
                "⚠️ Could not create ticket automatically — please create manually in OCCIR."
            )
            return None

        permalink = self._get_permalink(channel, ts)
        reactor_name = self._get_user_name(requested_by)

        # LLM classification
        fallback_title = _derive_title(message_text)
        llm = self._classify_with_llm(message_text, fallback_title=fallback_title)
        # Stash on instance so handle_reaction can read confidence/service for reply text
        self._last_llm_result = llm
        title = llm["title"]
        if _is_generic_title(title) and fallback_title:
            title = fallback_title
        service = llm["service"]

        # Create Jira ticket
        description_text = (
            f"{message_text}\n\nReported by: {reactor_name}\nSlack: {permalink}"
        )
        work_type_label = "incident" if occir_work_type == "incident" else "ticket"
        try:
            ticket_key = self.occir_client.create_incident(
                summary=title[:255],
                description_text=description_text,
                alert_link=permalink,
                service_name=service,
                occir_work_type=occir_work_type,
            )
        except OccirJiraError as exc:
            logger.error("Failed to create OCCIR %s: %s", work_type_label, exc)
            # Release the reservation so the operator can retry
            with self._dedup_lock:
                self._dedup.pop(dedup_key, None)
            self._post_thread(
                channel, ts,
                "⚠️ Could not create ticket automatically — please create manually in OCCIR."
            )
            activity.add("ticket_failed", str(exc), user=requested_by)
            return None

        # Mark dedup only after successful creation
        with self._dedup_lock:
            self._dedup[dedup_key] = time.time()
        self._persist_dedup()

        if self.turnover is not None:
            self.turnover.ingestor.link_ticket(channel, ts, ticket_key)
        activity.add(
            "ticket_created",
            f"{ticket_key}: {title[:80]}",
            user=requested_by,
            ticket_key=ticket_key,
        )

        return ticket_key

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch_message_text(self, channel: str, ts: str) -> str | None:
        """Fetch the original message text. Returns None on failure."""
        try:
            resp = self.slack_client.conversations_history(
                channel=channel, latest=ts, oldest=ts, inclusive=True, limit=1
            )
            messages = resp.get("messages", [])
            if messages:
                return messages[0].get("text", "")
            return None
        except Exception:
            logger.error(
                "Failed to fetch message %s in %s", ts, channel, exc_info=True
            )
            return None

    def _fetch_message_context(self, channel: str, ts: str) -> str | None:
        root = self._fetch_message_text(channel, ts)
        if root is None:
            return None
        try:
            resp = self.slack_client.conversations_replies(
                channel=channel,
                ts=ts,
                limit=20,
            )
            parts = []
            for msg in resp.get("messages", []):
                text = (msg.get("text") or "").strip()
                if text and text not in parts:
                    parts.append(text)
            if parts:
                return "\n".join(parts)
        except Exception:
            logger.warning("Failed to fetch thread context for %s in %s", ts, channel)
        return root

    def _classify_with_llm(self, message_text: str, fallback_title: str = "") -> dict:
        """Call Ollama to classify the incident. Returns {title, service, confidence}.

        Falls back to Infrastructure on any failure.
        """
        fallback = {
            "title": fallback_title or "Incident from #ops-noc",
            "service": "Infrastructure",
            "confidence": "error",
        }
        if not self.ollama_url:
            return fallback

        service_list = (
            "Ascio, Enom, ExactHosting, Hosted Email, Hover, "
            "Infrastructure, OpenSRS, TRS (Tucows Registry Service)"
        )
        user_prompt = (
            "Classify this Slack message as an incident. "
            "Return JSON with exactly these keys:\n"
            f'- "title": a short rewritten incident title (5-9 words, under 70 chars)\n'
            "  Use the concrete alert symptom and affected host/service. "
            "Do not copy the full Slack message; summarize it into a ticket title. "
            "Do not title it from the Slack channel, incident channel, or where it was created.\n"
            f'- "service": exactly one of: {service_list}\n'
            '- "confidence": "high" if the service is clearly identifiable, "low" if uncertain\n\n'
            f"Message:\n---\n{message_text}\n---"
        )

        try:
            resp = requests.post(
                f"{self.ollama_url}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a concise incident classifier. "
                                "Output only valid JSON, no explanation, no markdown."
                            ),
                        },
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                },
                timeout=15,
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"].strip()
            if content.startswith("```"):
                # Strip ```json...``` or ```...``` wrappers
                lines = content.split("\n")
                content = "\n".join(lines[1:-1]) if len(lines) > 2 else content
            result = json.loads(content)
            title = str(result["title"]).strip()
            if _is_generic_title(title) and fallback_title:
                title = fallback_title
            title = _trim_title(title, limit=70)
            return {
                "title": title,
                "service": result["service"],
                "confidence": result.get("confidence", "low"),
            }
        except Exception:
            logger.warning("LLM classification failed, using fallback", exc_info=True)
            return fallback

    def _post_thread(self, channel: str, thread_ts: str, text: str) -> None:
        try:
            self.slack_client.chat_postMessage(
                channel=channel, thread_ts=thread_ts, text=text
            )
        except Exception:
            logger.warning(
                "Failed to post thread reply in %s at %s", channel, thread_ts
            )

    def _get_user_name(self, user_id: str) -> str:
        try:
            resp = self.slack_client.users_info(user=user_id)
            return resp["user"]["real_name"]
        except Exception:
            return user_id

    def _get_permalink(self, channel: str, message_ts: str) -> str:
        try:
            resp = self.slack_client.chat_getPermalink(
                channel=channel, message_ts=message_ts
            )
            return resp["permalink"]
        except Exception:
            return f"https://app.slack.com/client/{channel}/{message_ts}"

    def _load_dedup(self) -> None:
        """Load persisted dedup entries from disk, pruning those older than 24h."""
        try:
            with open(self._dedup_path) as f:
                data = json.load(f)
            now = time.time()
            loaded = 0
            for key, ts in data.items():
                if now - ts < 86400:
                    self._dedup[key] = ts
                    loaded += 1
            logger.info("Loaded %d dedup entries from %s", loaded, self._dedup_path)
        except FileNotFoundError:
            pass
        except Exception:
            logger.warning(
                "Failed to load dedup cache from %s", self._dedup_path, exc_info=True
            )

    def _persist_dedup(self) -> None:
        """Write current dedup entries to disk for restart survival (atomic write)."""
        try:
            target = self._dedup_path
            dirpath = os.path.dirname(target) or "."
            os.makedirs(dirpath, exist_ok=True)
            with self._dedup_lock:
                snapshot = dict(self._dedup.items())
            tmp = f"{target}.tmp"
            with open(tmp, "w") as f:
                json.dump(snapshot, f)
            os.replace(tmp, target)  # atomic on POSIX; best-effort on Windows
        except Exception:
            logger.warning(
                "Failed to persist dedup cache to %s", self._dedup_path, exc_info=True
            )
