import logging
import os
import re
from html import unescape
from concurrent.futures import TimeoutError as FuturesTimeoutError
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Protocol

import requests


logger = logging.getLogger(__name__)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if not value:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_csv(name: str) -> list[str]:
    return [
        item.strip()
        for item in os.environ.get(name, "").split(",")
        if item.strip()
    ]


@dataclass
class AlertQAConfig:
    enabled: bool = False
    noc_info_channel_id: str = ""
    allowed_channel_ids: list[str] = field(default_factory=list)
    ops_noc_channel_id: str = ""
    runbook_api_url: str = ""
    confluence_base_url: str = ""
    confluence_email: str = ""
    confluence_api_token: str = ""
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    ollama_url: str = ""
    ollama_model: str = "qwen-assistant"
    ollama_timeout_sec: float = 6.0
    source_timeout_sec: float = 12.0
    max_evidence: int = 6

    @classmethod
    def from_env(cls) -> "AlertQAConfig":
        jira_email = os.environ.get("JIRA_EMAIL", "")
        jira_api_token = os.environ.get("JIRA_API_TOKEN", "")
        allowed_channel_ids = _env_csv("ALERT_QA_ALLOWED_CHANNEL_IDS")
        for channel_id in (
            os.environ.get("ALERT_QA_ALLOWED_CHANNEL_ID", ""),
            os.environ.get("ALERT_QA_TESTER_CHANNEL_ID", ""),
        ):
            if channel_id and channel_id not in allowed_channel_ids:
                allowed_channel_ids.append(channel_id)
        return cls(
            enabled=_env_bool("ALERT_QA_ENABLED", False),
            noc_info_channel_id=os.environ.get("ALERT_QA_ALLOWED_CHANNEL_ID", ""),
            allowed_channel_ids=allowed_channel_ids,
            ops_noc_channel_id=os.environ.get("OPS_NOC_CHANNEL_ID", ""),
            runbook_api_url=os.environ.get("RUNBOOK_API_URL", ""),
            confluence_base_url=os.environ.get("CONFLUENCE_BASE_URL", ""),
            confluence_email=os.environ.get("CONFLUENCE_EMAIL", jira_email),
            confluence_api_token=os.environ.get("CONFLUENCE_API_TOKEN", jira_api_token),
            jira_base_url=os.environ.get("JIRA_BASE_URL", ""),
            jira_email=jira_email,
            jira_api_token=jira_api_token,
            ollama_url=os.environ.get("OLLAMA_URL", ""),
            ollama_model=os.environ.get(
                "ALERT_QA_OLLAMA_MODEL", os.environ.get("OLLAMA_MODEL", "qwen-assistant")
            ),
            ollama_timeout_sec=_env_float("ALERT_QA_OLLAMA_TIMEOUT_SEC", 6.0),
            source_timeout_sec=_env_float("ALERT_QA_SOURCE_TIMEOUT_SEC", 12.0),
            max_evidence=_env_int("ALERT_QA_MAX_EVIDENCE", 6),
        )


@dataclass
class Evidence:
    source: str
    title: str
    snippet: str
    url: str
    updated_at: str = ""
    score: float = 0.0


@dataclass
class SourceResult:
    source: str
    evidence: list[Evidence] = field(default_factory=list)
    status: str = "ok"
    error: str = ""


class AlertQASource(Protocol):
    name: str

    def search(self, query: str) -> SourceResult:
        ...


_MENTION_RE = re.compile(r"<@([A-Z0-9]+)>")
_URL_RE = re.compile(r"^<?https?://\S+>?$", re.IGNORECASE)
_QUESTION_WORDS = {
    "what",
    "why",
    "when",
    "where",
    "who",
    "which",
    "how",
    "has",
    "have",
    "is",
    "are",
    "can",
    "could",
    "did",
    "does",
    "do",
    "was",
    "were",
}
_REQUEST_WORDS = {
    "check",
    "explain",
    "find",
    "investigate",
    "search",
    "show",
    "summarize",
    "tell",
}
_OPERATIONAL_HINTS = {
    "alert",
    "bind",
    "caused",
    "critical",
    "delay",
    "delays",
    "email",
    "error",
    "failed",
    "handled",
    "happened",
    "host",
    "incident",
    "last",
    "mailbox",
    "mailboxes",
    "occir",
    "osrs",
    "outage",
    "previous",
    "runbook",
    "signer",
    "ticket",
    "time",
}
_VAGUE_PROMPTS = {
    "look at this",
    "check this",
    "thoughts",
    "help",
    "this",
}
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_SLACK_SAFE_TERM_RE = re.compile(r"[A-Za-z0-9_.:-]{2,}")
_SLACK_SEARCH_OPERATORS = {
    "after",
    "before",
    "during",
    "from",
    "has",
    "in",
    "on",
}
_SLACK_MENTION_RE = re.compile(r"<@([A-Z0-9]+)>")
_SLACK_SUBTEAM_RE = re.compile(r"<!subteam\^([A-Z0-9]+)(?:\|([^>]+))?>")
_SLACK_LINK_RE = re.compile(r"<(https?://[^>|]+)(?:\|([^>]+))?>")
_GRAFANA_URL_RE = re.compile(r"https?://[^\s<>()|]*grafana\.net/\S+", re.IGNORECASE)
_SLACK_MESSAGE_URL_RE = re.compile(
    r"https?://[^/\s]+/archives/([A-Z0-9]+)/p(\d{10})(\d{1,6})",
    re.IGNORECASE,
)
_MAX_SYNTHESIZED_CHARS = 700
_MIN_EVIDENCE_SCORE = 0.25
_SEARCHED_LABEL = "Searched: #ops-noc, Confluence, Jira OCCIR"
_SOURCE_PRIORITY = {"slack": 0, "confluence": 1, "jira": 2}
_KNOWN_SLACK_GROUPS = {
    "S09E57PR736": "domains-sre",
    "S6DE2CJF4": "noc",
}
_ANCHOR_STOP_WORDS = {
    "connection",
    "critical",
    "down",
    "error",
    "failed",
    "registry",
    "service",
    "timeout",
    "unavailable",
}
_QUERY_STOP_WORDS = {
    "a",
    "about",
    "alert",
    "an",
    "and",
    "any",
    "are",
    "as",
    "at",
    "be",
    "by",
    "can",
    "code",
    "do",
    "does",
    "for",
    "from",
    "has",
    "have",
    "host",
    "how",
    "i",
    "in",
    "is",
    "it",
    "me",
    "of",
    "on",
    "or",
    "please",
    "received",
    "should",
    "that",
    "the",
    "this",
    "to",
    "what",
    "when",
    "where",
    "which",
    "who",
    "why",
    "with",
}
_HOST_TLDS = {"cloud", "com", "io", "my", "net", "org", "systems"}


def _without_grafana_links(text: str) -> str:
    original = text or ""

    def _replace_slack_link(match: re.Match[str]) -> str:
        url = match.group(1)
        if "grafana.net" not in url.lower():
            return match.group(0)
        return match.group(2) or ""

    safe = _SLACK_LINK_RE.sub(_replace_slack_link, original)
    safe = _GRAFANA_URL_RE.sub(" ", safe)
    if safe == original:
        return original
    return " ".join(safe.split())


def _split_compound_token(term: str) -> list[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", term or "")
    spaced = re.sub(r"(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])", " ", spaced)
    parts = [
        part.lower()
        for part in re.split(r"[^A-Za-z0-9]+", spaced)
        if len(part) >= 3
    ]
    if len(parts) <= 1:
        return []
    return parts


def _text_terms(text: str) -> set[str]:
    raw_text = _without_grafana_links(text or "")
    lowered = raw_text.lower()
    terms = set(re.findall(r"[a-z0-9][a-z0-9_.-]*", lowered))
    for raw in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.-]*", raw_text):
        terms.update(_split_compound_token(raw))
    for term in list(terms):
        if "." in term:
            terms.update(part for part in term.split(".") if part)
    return terms


def _score(query: str, text: str) -> float:
    query_terms = set(_alert_terms(query))
    if not query_terms:
        return 0.0
    text_lower = _without_grafana_links(text or "").lower()
    text_parts = _text_terms(text or "")
    matched = sum(
        1
        for term in query_terms
        if (("." in term and term in text_lower) or term in text_parts)
    )
    return matched / len(query_terms)


def _alert_terms(query: str) -> list[str]:
    terms = []
    raw_query = query or ""
    compound_lowers = set()
    for raw_term in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.-]*", raw_query):
        compound_parts = _split_compound_token(raw_term)
        if compound_parts:
            compound_lowers.add(raw_term.lower())
        raw_terms = compound_parts or [raw_term.lower()]
        for term in raw_terms:
            if term in _QUERY_STOP_WORDS:
                continue
            if len(term) < 2 and not term.isdigit():
                continue
            terms.append(term)
            if "." in term:
                terms.extend(
                    part
                    for part in term.split(".")
                    if len(part) >= 3 and part not in _HOST_TLDS
                )
    for term in re.findall(r"[a-z0-9][a-z0-9_.-]*", raw_query.lower()):
        if term in compound_lowers:
            continue
        if term in _QUERY_STOP_WORDS:
            continue
        if len(term) < 2 and not term.isdigit():
            continue
        terms.append(term)
        if "." in term:
            terms.extend(
                part
                for part in term.split(".")
                if len(part) >= 3 and part not in _HOST_TLDS
            )
    return terms


def _required_anchor_terms(query: str) -> set[str]:
    anchors = set()
    for term in _alert_terms(query):
        if "." in term:
            anchors.add(term)
            continue
        if len(term) >= 5 and term not in _ANCHOR_STOP_WORDS:
            anchors.add(term)
    return anchors


def _evidence_matches_query(query: str, item: Evidence) -> bool:
    if item.score < _MIN_EVIDENCE_SCORE:
        return False
    anchors = _required_anchor_terms(query)
    if not anchors:
        return True
    text = _without_grafana_links(f"{item.title} {item.snippet} {item.url}").lower()
    return any(anchor in text for anchor in anchors)


def _snippet(text: str, limit: int = 220) -> str:
    compact = " ".join((text or "").split())
    if len(compact) <= limit:
        return compact
    return compact[: max(0, limit - 3)].rstrip() + "..."


def _strip_html(text: str) -> str:
    return _snippet(unescape(_HTML_TAG_RE.sub(" ", text or "")))


def _source_name(source) -> str:
    return getattr(source, "name", source.__class__.__name__)


def _join_base_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _sanitize_slack_search_terms(query: str) -> str:
    terms = []
    for term in _SLACK_SAFE_TERM_RE.findall(" ".join(_alert_terms(query))):
        prefix = term.split(":", 1)[0].lower()
        if ":" in term and prefix in _SLACK_SEARCH_OPERATORS:
            continue
        terms.append(term)
    return " ".join(terms)


def _evidence_sort_key(item: Evidence) -> tuple[int, float, str]:
    return (_SOURCE_PRIORITY.get(item.source, 99), -item.score, item.updated_at or "")


def _evidence_rank_key(query: str, item: Evidence) -> tuple[float, int, str]:
    text = _without_grafana_links(f"{item.title} {item.snippet} {item.url}").lower()
    anchors = _required_anchor_terms(query)
    anchor_hits = sum(1 for anchor in anchors if anchor in text)
    return (-item.score, -anchor_hits, item.updated_at or "")


class SlackOpsNocSearchSource:
    name = "slack"

    def __init__(
        self,
        slack_client,
        ops_noc_channel_id: str,
        limit: int = 5,
        ops_noc_channel_name: str = "ops-noc",
        timeout: float | None = None,
        team_member_ids: set[str] | None = None,
        group_cache=None,
    ):
        self.slack_client = slack_client
        self.ops_noc_channel_id = ops_noc_channel_id
        self.ops_noc_channel_name = ops_noc_channel_name
        self.limit = limit
        self.team_member_ids = team_member_ids or set()
        self.group_cache = group_cache
        # Slack SDK call timeouts are configured on the WebClient, not per method.
        self.timeout = timeout

    def search(self, query: str) -> SourceResult:
        try:
            resp = self.slack_client.search_messages(
                query=self._build_search_query(query),
                count=self.limit,
                sort="timestamp",
                sort_dir="desc",
            )
            matches = resp.get("messages", {}).get("matches", [])
            evidence = [self._evidence_from_match(query, match) for match in matches]
            evidence = self._rank_and_filter(query, evidence)
            return SourceResult(
                source=self.name,
                evidence=evidence[: self.limit],
            )
        except Exception as exc:
            return self._search_recent_history(query, exc)

    def _build_search_query(self, query: str) -> str:
        safe_query = _sanitize_slack_search_terms(query)
        if safe_query:
            return f"{safe_query} in:{self.ops_noc_channel_name}"
        return f"in:{self.ops_noc_channel_name}"

    def _team_members(self) -> set[str]:
        if self.team_member_ids:
            return set(self.team_member_ids)
        if self.group_cache is None:
            return set()
        try:
            return set(self.group_cache.get_members(self.slack_client))
        except Exception:
            logger.warning("alert_qa: failed to fetch team members for Slack ranking", exc_info=True)
            return set()

    def _rank_and_filter(self, query: str, evidence: list[Evidence]) -> list[Evidence]:
        relevant = [item for item in evidence if _evidence_matches_query(query, item)]
        return sorted(relevant, key=lambda item: _evidence_rank_key(query, item))

    def _search_recent_history(self, query: str, error: Exception) -> SourceResult:
        try:
            evidence = []
            low_score_roots = []
            cursor = None
            for _page in range(10):
                kwargs = {
                    "channel": self.ops_noc_channel_id,
                    "limit": 200,
                }
                if cursor:
                    kwargs["cursor"] = cursor
                resp = self.slack_client.conversations_history(**kwargs)
                for message in resp.get("messages", []):
                    score = _score(query, message.get("text", ""))
                    if score < _MIN_EVIDENCE_SCORE:
                        low_score_roots.append(message)
                        continue
                    permalink_resp = self.slack_client.chat_getPermalink(
                        channel=self.ops_noc_channel_id,
                        message_ts=message.get("ts", ""),
                    )
                    evidence.append(
                        Evidence(
                            source=self.name,
                            title="Slack #ops-noc message",
                            snippet=_snippet(message.get("text", "")),
                            url=permalink_resp.get("permalink", ""),
                            updated_at=message.get("ts", ""),
                            score=score,
                        )
                    )
                evidence = self._rank_and_filter(query, evidence)
                if len(evidence) >= self.limit:
                    break
                cursor = (
                    resp.get("response_metadata", {}).get("next_cursor")
                    or resp.get("next_cursor")
                )
                if not cursor:
                    break
            if len(evidence) < self.limit:
                evidence.extend(
                    self._search_recent_replies(
                        query,
                        low_score_roots,
                        remaining=self.limit - len(evidence),
                    )
                )
                evidence = self._rank_and_filter(query, evidence)
            return SourceResult(
                source=self.name,
                evidence=evidence[: self.limit],
                status="degraded",
                error=str(error),
            )
        except Exception as fallback_exc:
            return SourceResult(source=self.name, status="failed", error=str(fallback_exc))

    def _search_recent_replies(
        self,
        query: str,
        messages: list[dict],
        remaining: int,
    ) -> list[Evidence]:
        evidence = []
        for message in messages[:5]:
            root_ts = message.get("thread_ts") or message.get("ts")
            if not root_ts:
                continue
            try:
                resp = self.slack_client.conversations_replies(
                    channel=self.ops_noc_channel_id,
                    ts=root_ts,
                    limit=20,
                )
            except Exception:
                continue
            for reply in resp.get("messages", [])[1:]:
                score = _score(query, reply.get("text", ""))
                if score < _MIN_EVIDENCE_SCORE:
                    continue
                permalink_resp = self.slack_client.chat_getPermalink(
                    channel=self.ops_noc_channel_id,
                    message_ts=reply.get("ts", ""),
                )
                evidence.append(
                    Evidence(
                        source=self.name,
                        title="Slack #ops-noc message",
                        snippet=_snippet(reply.get("text", "")),
                        url=permalink_resp.get("permalink", ""),
                        updated_at=reply.get("ts", ""),
                        score=score,
                    )
                )
                if len(evidence) >= remaining:
                    return evidence
        return evidence

    def _evidence_from_match(self, query: str, match: dict) -> Evidence:
        text = match.get("text", "")
        snippet = self._thread_context_snippet(match, text)
        user_id = match.get("user") or match.get("user_id") or ""
        score = _score(query, snippet)
        if user_id in self._team_members():
            score += 0.25
        return Evidence(
            source=self.name,
            title="Slack #ops-noc message",
            snippet=_snippet(snippet, limit=520),
            url=match.get("permalink", ""),
            updated_at=match.get("ts", ""),
            score=score,
        )

    def _thread_context_snippet(self, match: dict, fallback_text: str) -> str:
        channel = match.get("channel")
        channel_id = channel.get("id", "") if isinstance(channel, dict) else ""
        ts = match.get("ts", "")
        if not (channel_id and ts):
            return fallback_text
        try:
            resp = self.slack_client.conversations_replies(
                channel=channel_id,
                ts=ts,
                limit=12,
            )
        except Exception:
            return fallback_text

        messages = resp.get("messages", [])
        if not messages:
            return fallback_text
        team_members = self._team_members()
        root = messages[0]
        replies = messages[1:]
        team_replies = [msg for msg in replies if msg.get("user") in team_members]
        other_replies = [msg for msg in replies if msg.get("user") not in team_members]
        parts = [root.get("text", "")] + [
            msg.get("text", "") for msg in team_replies + other_replies
        ]
        return " | ".join(part for part in parts if part) or fallback_text


class RunbookSearchSource:
    name = "runbook"

    def __init__(
        self,
        base_url: str,
        public_base_url: str = "",
        timeout: float = 8.0,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.public_base_url = (public_base_url or "").rstrip("/")
        self.timeout = timeout

    def search(self, query: str) -> SourceResult:
        if not self.base_url:
            return SourceResult(
                source=self.name,
                status="unavailable",
                error="missing runbook base URL",
            )
        try:
            resp = requests.get(
                _join_base_url(self.base_url, "/api/runbook/match"),
                params={"alert_name": query},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                entries = data.get("matches") or data.get("entries") or []
            else:
                entries = []
            return SourceResult(
                source=self.name,
                evidence=[self._evidence_from_entry(query, entry) for entry in entries],
            )
        except Exception as exc:
            return SourceResult(source=self.name, status="failed", error=str(exc))

    def _evidence_from_entry(self, query: str, entry: dict) -> Evidence:
        title = (
            entry.get("alert_name")
            or entry.get("title")
            or entry.get("service")
            or "Runbook match"
        )
        body = (
            entry.get("remediation")
            or entry.get("notes")
            or entry.get("description")
            or ""
        )
        entry_id = entry.get("id")
        link_base_url = self.public_base_url or self.base_url
        url = (
            _join_base_url(link_base_url, f"/api/runbook/entries/{entry_id}")
            if entry_id
            else link_base_url
        )
        return Evidence(
            source=self.name,
            title=title,
            snippet=_snippet(body),
            url=url,
            updated_at=entry.get("updated_at", ""),
            score=float(entry.get("score") or _score(query, f"{title} {body}")),
        )


class ConfluenceSearchSource:
    name = "confluence"

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        timeout: float = 8.0,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.email = email
        self.api_token = api_token
        self.timeout = timeout

    def search(self, query: str) -> SourceResult:
        if not (self.base_url and self.email and self.api_token):
            return SourceResult(
                source=self.name,
                status="unavailable",
                error="missing confluence configuration",
            )
        try:
            resp = requests.get(
                _join_base_url(self.base_url, "/wiki/rest/api/search"),
                params={
                    "cql": f'text ~ "{_escape_query(query)}" ORDER BY lastmodified DESC',
                    "limit": 5,
                    "expand": "content.version",
                },
                auth=(self.email, self.api_token),
                timeout=self.timeout,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
            return SourceResult(
                source=self.name,
                evidence=[self._evidence_from_result(query, item) for item in results],
            )
        except Exception as exc:
            return SourceResult(source=self.name, status="failed", error=str(exc))

    def _evidence_from_result(self, query: str, item: dict) -> Evidence:
        content = item.get("content", {})
        title = content.get("title") or item.get("title") or "Confluence result"
        webui = item.get("_links", {}).get("webui", "")
        snippet = _strip_html(item.get("excerpt", ""))
        return Evidence(
            source=self.name,
            title=title,
            snippet=snippet,
            url=_join_base_url(self.base_url, webui) if webui else self.base_url,
            updated_at=content.get("version", {}).get("when", ""),
            score=_score(query, f"{title} {snippet}"),
        )


class JiraOccirSearchSource:
    name = "jira"

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        timeout: float = 8.0,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.email = email
        self.api_token = api_token
        self.timeout = timeout

    def search(self, query: str) -> SourceResult:
        if not (self.base_url and self.email and self.api_token):
            return SourceResult(
                source=self.name,
                status="unavailable",
                error="missing jira configuration",
            )
        try:
            jql = (
                f'project = "OCCIR" AND text ~ "{_escape_query(query)}" '
                "ORDER BY updated DESC"
            )
            resp = requests.post(
                _join_base_url(self.base_url, "/rest/api/3/search/jql"),
                json={
                    "jql": jql,
                    "maxResults": 5,
                    "fields": ["summary", "status", "updated"],
                },
                auth=(self.email, self.api_token),
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return SourceResult(
                source=self.name,
                evidence=[
                    self._evidence_from_issue(query, issue)
                    for issue in resp.json().get("issues", [])
                ],
            )
        except Exception as exc:
            return SourceResult(source=self.name, status="failed", error=str(exc))

    def _evidence_from_issue(self, query: str, issue: dict) -> Evidence:
        fields = issue.get("fields", {})
        key = issue.get("key", "")
        summary = fields.get("summary", "")
        status = fields.get("status", {}).get("name", "")
        title = f"{key} {summary}".strip()
        snippet = f"Status: {status}" if status else ""
        return Evidence(
            source=self.name,
            title=title,
            snippet=snippet,
            url=_join_base_url(self.base_url, f"/browse/{key}") if key else self.base_url,
            updated_at=fields.get("updated", ""),
            score=_score(query, f"{title} {snippet}"),
        )


def _escape_query(query: str) -> str:
    return (query or "").replace("\\", "\\\\").replace('"', '\\"')


def _humanize_slack_mrkdwn(text: str) -> str:
    def _subteam_label(match: re.Match[str]) -> str:
        group_id = match.group(1)
        label = match.group(2) or _KNOWN_SLACK_GROUPS.get(group_id) or group_id
        return f"@{label}"

    def _link_label(match: re.Match[str]) -> str:
        return match.group(2) or match.group(1)

    safe = _without_grafana_links(text or "")
    safe = _SLACK_SUBTEAM_RE.sub(_subteam_label, safe)
    safe = _SLACK_LINK_RE.sub(_link_label, safe)
    safe = _SLACK_MENTION_RE.sub(r"@\1", safe)
    return safe


def _escape_slack_text(text: str) -> str:
    safe = "".join(
        char for char in _humanize_slack_mrkdwn(text) if ord(char) >= 32 and ord(char) != 127
    )
    safe = " ".join(safe.split())
    safe = (
        safe.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "-")
    )
    return safe


def _clamp_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _is_safe_slack_url(url: str) -> bool:
    return (
        url.startswith(("http://", "https://"))
        and not any(char in url for char in "|<>")
        and not any(ord(char) < 33 or ord(char) == 127 or char.isspace() for char in url)
    )


def _slack_link(url: str, title: str) -> str:
    label = _escape_slack_text(title)
    if url and _is_safe_slack_url(url):
        return f"<{url}|{label}>"
    if url and url.startswith(("http://", "https://")):
        return f"{label} {_escape_slack_text(url)}"
    return label


def _source_status_line(
    source_results: list[SourceResult],
    evidence: list[Evidence] | None = None,
) -> str:
    sources_with_evidence = {
        result.source
        for result in source_results
        if result.evidence
    }
    sources_with_evidence.update(item.source for item in (evidence or []))
    degraded = [
        result.source
        for result in source_results
        if result.status in {"failed", "degraded", "unavailable"}
        and result.source != "runbook"
        and result.source not in sources_with_evidence
    ]
    if not degraded:
        return ""
    return "Unavailable/degraded: " + ", ".join(degraded)


def _fallback_answer_from_evidence(item: Evidence) -> str:
    snippet = _humanize_slack_mrkdwn(_without_grafana_links(item.snippet))
    snippet = re.sub(r"@\S+\s*", "", snippet)
    snippet = re.sub(r"\bplease check\b[:\s-]*", "", snippet, flags=re.IGNORECASE)
    snippet = re.sub(r"\s+", " ", snippet).strip(" :-")
    if not snippet:
        snippet = item.title
    return f"Closest evidence points to: {_snippet(snippet, limit=180)}"


def _looks_like_action_question(question: str) -> bool:
    lowered = (question or "").lower()
    return any(
        phrase in lowered
        for phrase in (
            "what should i do",
            "who should",
            "who do i",
            "where should",
            "escalate",
            "escalated",
            "owner",
            "team",
            "group",
            "go to",
        )
    )


def _looks_like_escalation_owner_question(question: str) -> bool:
    lowered = (question or "").lower()
    return any(
        phrase in lowered
        for phrase in (
            "what should i do",
            "what do i do",
            "what to do",
            "who should",
            "who do i",
            "which team",
            "what team",
            "what group",
            "owner",
            "escalate",
            "escalated",
            "go to",
        )
    )


def _ticket_url_map(evidence: list[Evidence], config: AlertQAConfig) -> dict[str, str]:
    urls: dict[str, str] = {}
    browse_re = re.compile(
        r"https?://[^\s<>()|]+/browse/((?:OCCIR|CR)-\d+)",
        re.IGNORECASE,
    )
    key_re = re.compile(r"\b(?:OCCIR|CR)-\d+\b", re.IGNORECASE)
    for item in evidence:
        for match in browse_re.finditer(f"{item.url} {item.snippet}"):
            key = match.group(1).upper()
            url = match.group(0)
            if _is_safe_slack_url(url):
                urls.setdefault(key, url)
        if config.jira_base_url:
            for match in key_re.finditer(f"{item.title} {item.snippet}"):
                key = match.group(0).upper()
                urls.setdefault(key, _join_base_url(config.jira_base_url, f"/browse/{key}"))
    return urls


def _link_ticket_refs(text: str, evidence: list[Evidence], config: AlertQAConfig) -> str:
    urls = _ticket_url_map(evidence, config)
    if not urls:
        return text

    def _replace(match: re.Match[str]) -> str:
        key = match.group(0).upper()
        url = urls.get(key)
        if not url or not _is_safe_slack_url(url):
            return match.group(0)
        return f"<{url}|{key}>"

    return re.sub(r"\b(?:OCCIR|CR)-\d+\b", _replace, text or "", flags=re.IGNORECASE)


def _evidence_owner_hint(evidence: list[Evidence]) -> str:
    patterns = [
        r"\b(?:escalation\s+owner|owner\s+team|owner|team|group)\s*[:=-]\s*([^.\n;]+)",
        r"\b(?:escalate|route|page|notify|contact)\s+(?:to\s+)?([^.\n;]+)",
    ]
    blocked = {"@domains-sre", "domains-sre", "@noc", "noc"}
    for item in evidence[:4]:
        text = _humanize_slack_mrkdwn(_without_grafana_links(f"{item.title}. {item.snippet}"))
        text = re.sub(r"https?://\S+", " ", text)
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if not match:
                continue
            owner = re.sub(r"\s+", " ", match.group(1)).strip(" :-")
            owner_key = owner.lower()
            if owner and owner_key not in blocked and "@domains-sre" not in owner_key and "@noc" not in owner_key:
                return owner
    return ""


def _fallback_guidance_from_evidence(
    question: str,
    evidence: list[Evidence],
    config: AlertQAConfig,
) -> str:
    text = " ".join(
        _humanize_slack_mrkdwn(_without_grafana_links(f"{item.title} {item.snippet}"))
        for item in evidence[:3]
    )
    ticket_match = re.search(r"\b(?:OCCIR|CR)-\d+\b", text, re.IGNORECASE)
    ticket = ticket_match.group(0).upper() if ticket_match else ""
    wants_owner = _looks_like_escalation_owner_question(question)
    owner = _evidence_owner_hint(evidence) if wants_owner else ""

    parts = []
    if wants_owner:
        parts.append(
            f"Owner/team: {owner}"
            if owner
            else "Owner/team: not found in current evidence"
        )
    if ticket:
        parts.append(f"check or update {ticket}")
    if not parts:
        parts.append("use the closest linked evidence below, but treat it as weak")

    answer = " and ".join(parts)
    if _looks_like_action_question(question):
        return f"Suggested next step: {answer}. The matches are similar, not a guaranteed exact runbook."
    return _fallback_answer_from_evidence(evidence[0])


def render_evidence_answer(
    question: str,
    evidence: list[Evidence],
    failed_sources: list[SourceResult],
    config: AlertQAConfig,
) -> str:
    lines = []
    status_line = _source_status_line(failed_sources, evidence)
    if not evidence:
        lines.append("*Likely answer*")
        lines.append("No reliable answer found from current evidence.")
        lines.append("")
        lines.append(f"_{_SEARCHED_LABEL}_")
        if status_line:
            lines.append(f"_{status_line}_")
        return "\n".join(lines)

    synthesized = _synthesize_with_ollama(question, evidence, config).strip()
    lines.append("*Likely answer*")
    if synthesized:
        synthesized = _clamp_text(
            _escape_slack_text(synthesized),
            _MAX_SYNTHESIZED_CHARS,
        )
        synthesized = _link_ticket_refs(synthesized, evidence, config)
        if synthesized.startswith(("Likely answer:", "Answer:", "No reliable answer")):
            lines.append(_strip_answer_label(synthesized))
        else:
            lines.append(synthesized)
    else:
        fallback = _escape_slack_text(
            _fallback_guidance_from_evidence(question, evidence, config)
        )
        lines.append(_link_ticket_refs(fallback, evidence, config))

    lines.append("")
    lines.append("*Evidence*")
    for index, item in enumerate(evidence[:2], start=1):
        lines.append(f"{index}. {_slack_link(item.url, item.title)}")
    lines.append(f"_{_SEARCHED_LABEL}_")
    if status_line:
        lines.append(f"_{status_line}_")
    return "\n".join(lines)


def _strip_answer_label(text: str) -> str:
    return re.sub(
        r"^(?:Likely answer:|Answer:)\s*",
        "",
        text or "",
        flags=re.IGNORECASE,
    )


def _synthesize_with_ollama(
    question: str,
    evidence: list[Evidence],
    config: AlertQAConfig,
) -> str:
    if not config.ollama_url:
        return ""
    evidence_lines = []
    for index, item in enumerate(evidence, start=1):
        evidence_lines.append(
            f"{index}. Source: {item.source}\n"
            f"Title: {item.title}\n"
            f"Snippet: {_without_grafana_links(item.snippet)}\n"
            f"URL: {item.url}"
        )
    prompt = (
        "You are assisting NOC and SRE engineers. Answer the user's question directly, "
        "then give the next operational action. Use only the supplied evidence. "
        "When asked who, what team, or what group should handle an alert, prioritize "
        "naming that owning team/group/person before other guidance. "
        "Do not route alerts to @domains-sre or @noc; those are the teams using you. "
        "Do not treat Grafana URL parameters like team=, alert group ids, node names, "
        "or hostnames as owning teams. "
        "If you tell the user to check an OCCIR, include the OCCIR key. "
        "Do not paste raw evidence as the answer. If evidence is only similar or weak, "
        "say that clearly and give the safest next step. Keep it under 5 sentences.\n\n"
        f"Question: {question}\n\n"
        "Evidence:\n"
        + "\n\n".join(evidence_lines)
    )
    try:
        resp = requests.post(
            _join_base_url(config.ollama_url, "/api/generate"),
            json={
                "model": config.ollama_model,
                "prompt": prompt,
                "stream": False,
            },
            timeout=config.ollama_timeout_sec,
        )
        resp.raise_for_status()
        return (resp.json().get("response") or "").strip()
    except Exception:
        logger.warning("alert_qa: ollama synthesis failed", exc_info=True)
        return ""


def strip_bot_mention(text: str, bot_user_id: str = "") -> str:
    def _replace(match: re.Match[str]) -> str:
        if not bot_user_id or match.group(1) == bot_user_id:
            return " "
        return match.group(0)

    stripped = _MENTION_RE.sub(_replace, text or "")
    return " ".join(stripped.split())


def _slack_message_refs(text: str) -> list[tuple[str, str]]:
    refs = []
    for match in _SLACK_MESSAGE_URL_RE.finditer(text or ""):
        channel = match.group(1)
        ts = f"{match.group(2)}.{match.group(3).ljust(6, '0')}"
        refs.append((channel, ts))
    return refs


def is_clear_question(text: str) -> bool:
    normalized = strip_bot_mention(text).strip()
    if len(normalized) < 8:
        return False
    lowered = normalized.lower()
    if _URL_RE.fullmatch(lowered):
        return False
    if lowered in _VAGUE_PROMPTS:
        return False

    tokens = re.findall(r"[a-z0-9][a-z0-9_-]*", lowered)
    if len(tokens) < 3:
        return False

    first_token = tokens[0] if tokens else ""
    has_question_word = first_token in _QUESTION_WORDS
    has_request_word = first_token in _REQUEST_WORDS
    has_question_mark = "?" in normalized
    has_operational_hint = any(
        token in _OPERATIONAL_HINTS
        or token.startswith("occir")
        or token.startswith("osrs-")
        or "." in token
        for token in tokens
    )

    if has_question_word and (has_question_mark or has_operational_hint):
        return True
    if has_request_word and (has_operational_hint or len(_alert_terms(normalized)) >= 2):
        return True
    return False


class AlertQAHandler:
    def __init__(self, slack_client, group_cache, config: AlertQAConfig, sources=None):
        self.slack_client = slack_client
        self.group_cache = group_cache
        self.config = config
        self.sources = list(sources or [])

    def should_handle(self, event: dict, is_app_mention: bool = False) -> bool:
        if not self.config.enabled:
            return False
        if event.get("bot_id") or event.get("subtype"):
            return False
        if event.get("channel_type") == "im":
            return True
        allowed_channels = set(self.config.allowed_channel_ids)
        if self.config.noc_info_channel_id:
            allowed_channels.add(self.config.noc_info_channel_id)
        return (
            is_app_mention
            and bool(allowed_channels)
            and event.get("channel") in allowed_channels
        )

    def handle_event(self, event: dict, is_app_mention: bool = False) -> bool:
        if not self.should_handle(event, is_app_mention=is_app_mention):
            return False

        if not self._is_authorized(event.get("user", "")):
            self._reply(event, "You are not authorized to use Alert Q&A.")
            return True

        text = strip_bot_mention(event.get("text", ""))
        if not is_clear_question(text):
            self._reply(event, "What do you want to know about this alert?")
            return True

        query = self._expand_link_context(text)
        self._reply(event, "Checking #ops-noc, Confluence, and Jira OCCIR...")
        self._reply(event, self.answer(query))
        return True

    def _is_authorized(self, user_id: str) -> bool:
        if not user_id or self.group_cache is None:
            return False
        group_ids = getattr(self.group_cache, "group_ids", None)
        if isinstance(group_ids, (list, tuple, set)):
            try:
                for group_id in group_ids:
                    resp = self.slack_client.usergroups_users_list(usergroup=group_id)
                    if user_id in set(resp.get("users", [])):
                        return True
                return False
            except Exception:
                logger.warning("alert_qa: live group lookup failed", exc_info=True)
                return False
        try:
            return user_id in self.group_cache.get_members(self.slack_client)
        except Exception:
            return False

    def answer(self, question: str) -> str:
        results = self._search_sources(question)
        evidence = []
        for result in results:
            evidence.extend(result.evidence)
        evidence = sorted(
            [item for item in evidence if _evidence_matches_query(question, item)],
            key=lambda item: _evidence_rank_key(question, item),
        )
        return render_evidence_answer(
            question,
            evidence[: self.config.max_evidence],
            results,
            self.config,
        )

    def _expand_link_context(self, text: str) -> str:
        snippets = []
        for channel, ts in _slack_message_refs(text):
            try:
                resp = self.slack_client.conversations_replies(
                    channel=channel,
                    ts=ts,
                    limit=1,
                )
            except Exception:
                logger.warning("alert_qa: failed to fetch linked Slack message", exc_info=True)
                continue
            messages = resp.get("messages", [])
            if messages:
                snippet = _snippet(messages[0].get("text", ""), limit=420)
                if snippet:
                    snippets.append(snippet)
        if not snippets:
            return text
        return f"{text}\n\nLinked alert context:\n" + "\n".join(snippets)

    def _search_sources(self, query: str) -> list[SourceResult]:
        if not self.sources:
            return []

        results: list[SourceResult] = []
        executor = ThreadPoolExecutor(max_workers=len(self.sources))
        try:
            future_to_source = {
                executor.submit(source.search, query): source for source in self.sources
            }
            seen = set()
            try:
                for future in as_completed(
                    future_to_source, timeout=self.config.source_timeout_sec
                ):
                    seen.add(future)
                    source = future_to_source[future]
                    source_name = _source_name(source)
                    try:
                        results.append(future.result())
                    except Exception as exc:
                        results.append(
                            SourceResult(source=source_name, status="failed", error=str(exc))
                        )
            except FuturesTimeoutError:
                pass

            for future, source in future_to_source.items():
                if future in seen:
                    continue
                source_name = _source_name(source)
                results.append(
                    SourceResult(source=source_name, status="failed", error="timed out")
                )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        return results

    def _reply(self, event: dict, text: str) -> None:
        self.slack_client.chat_postMessage(
            channel=event.get("channel"),
            text=text,
            thread_ts=event.get("thread_ts") or event.get("ts"),
            unfurl_links=False,
            unfurl_media=False,
        )
