"""Jira CR integration: fetch Change Records, convert ADF, summarize via LLM."""

import base64
import json
import logging
from dataclasses import dataclass
from datetime import datetime

import requests

logger = logging.getLogger(__name__)


# --- ADF to plain text conversion ---

def adf_to_text(adf: dict | None) -> str:
    """Convert Atlassian Document Format JSON to plain text."""
    if not adf:
        return ""
    parts = []
    _walk_adf(adf, parts, in_list=False)
    return "".join(parts)


def _walk_adf(node: dict, parts: list[str], in_list: bool) -> None:
    node_type = node.get("type", "")
    children = node.get("content", [])

    if node_type == "text":
        parts.append(node.get("text", ""))
        return

    if node_type == "hardBreak":
        parts.append("\n")
        return

    if node_type in ("paragraph", "heading"):
        for child in children:
            _walk_adf(child, parts, in_list=in_list)
        parts.append("\n")
        return

    if node_type == "codeBlock":
        for child in children:
            _walk_adf(child, parts, in_list=False)
        parts.append("\n")
        return

    if node_type in ("bulletList", "orderedList"):
        for child in children:
            _walk_adf(child, parts, in_list=True)
        return

    if node_type == "listItem":
        parts.append("- ")
        for child in children:
            _walk_adf(child, parts, in_list=True)
        return

    # Unrecognized nodes: recurse into children
    for child in children:
        _walk_adf(child, parts, in_list=in_list)


# --- Jira CR client ---

JIRA_FIELDS = (
    "summary,status,description,"
    "customfield_10160,customfield_10161,customfield_10164,"
    "customfield_10165,customfield_10167,customfield_10168,"
    "customfield_10098,customfield_10097"
)


@dataclass
class CRData:
    """Parsed fields from a Jira Change Record."""
    key: str
    summary: str
    status: str
    description: str
    start_date: str
    backout_plan: str
    change_type: str
    implementation_plan: str
    change_category: str
    customer_impact: str
    service: str
    environment: str


@dataclass
class CRWindowEntry:
    """Minimal CR fields used by the change tracker window scan."""
    key: str
    summary: str
    description: str
    planned_start: str
    impacted_services: str


class JiraCRClient:
    def __init__(self, base_url: str, email: str, api_token: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        credentials = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        self.session.headers.update({
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
        })

    def fetch_cr(self, cr_key: str) -> CRData | None:
        """Fetch a CR from Jira. Returns None on any failure."""
        url = f"{self.base_url}/rest/api/3/issue/{cr_key}"
        try:
            resp = self.session.get(url, params={"fields": JIRA_FIELDS}, timeout=15)
        except requests.RequestException as e:
            logger.error("Jira request failed for %s: %s", cr_key, e)
            return None

        if resp.status_code == 404:
            logger.warning("CR %s not found in Jira", cr_key)
            return None

        if resp.status_code != 200:
            logger.error("Jira API error for %s: %d %s", cr_key, resp.status_code, resp.text)
            return None

        data = resp.json()
        fields = data.get("fields", {})

        return CRData(
            key=data.get("key", cr_key),
            summary=fields.get("summary", ""),
            status=fields.get("status", {}).get("name", "") if fields.get("status") else "",
            description=adf_to_text(fields.get("description")),
            start_date=fields.get("customfield_10160") or "",
            backout_plan=adf_to_text(fields.get("customfield_10161")),
            change_type=(fields.get("customfield_10164") or {}).get("value", ""),
            implementation_plan=adf_to_text(fields.get("customfield_10165")),
            change_category=(fields.get("customfield_10167") or {}).get("value", ""),
            customer_impact=adf_to_text(fields.get("customfield_10168")),
            service=(fields.get("customfield_10098") or {}).get("value", ""),
            environment=", ".join(
                item.get("value", "") for item in (fields.get("customfield_10097") or [])
            ),
        )

    def search_crs_in_window(self, start: datetime, end: datetime) -> list[CRWindowEntry]:
        """Fetch CRs whose 'Change start date' (customfield_10160) is in [start, end].

        `start` / `end` are timezone-aware datetimes (UTC expected).

        Note: customfield_10160 ("Change start date") is not JQL-searchable on this
        Jira instance (the field-config has it indexed=off), so filtering by the
        field via JQL silently returns zero. Workaround: fetch a wider net by the
        indexed `created` field (the CR lookback window — CRs are rarely created
        >90 days before their scheduled start on this project), then filter by the
        real start-date field client-side. Paginates to cover all matches.

        Returns [] on any failure (logs the error).
        """
        url = f"{self.base_url}/rest/api/3/search/jql"
        # How far back to scan by `created`. 90 days is generous for a short
        # rolling window; older scheduled changes slip only on the rare CR
        # created more than 90d before its execution.
        jql = 'project = "CR" AND created >= -90d ORDER BY created DESC'
        fields = [
            "summary",
            "description",
            "customfield_10160",  # Change start date (the effective Planned Start)
            "customfield_10098",  # Service (impacted)
        ]

        all_issues: list[dict] = []
        next_page_token: str | None = None
        max_pages = 10  # safety cap; 10 × 100 = up to 1000 CRs scanned

        for _ in range(max_pages):
            body: dict = {"jql": jql, "maxResults": 100, "fields": fields}
            if next_page_token:
                body["nextPageToken"] = next_page_token
            try:
                resp = self.session.post(url, json=body, timeout=20)
            except requests.RequestException as e:
                logger.error("Jira window search failed: %s", e)
                return []

            if resp.status_code != 200:
                logger.error(
                    "Jira window search error %d: %s",
                    resp.status_code, resp.text[:200],
                )
                return []

            try:
                payload = resp.json()
            except ValueError as e:
                logger.error("Jira window search: malformed JSON: %s", e)
                return []

            page_issues = payload.get("issues", []) or []
            all_issues.extend(page_issues)

            if payload.get("isLast") is True:
                break
            next_page_token = payload.get("nextPageToken")
            if not next_page_token:
                break

        out: list[CRWindowEntry] = []
        for issue in all_issues:
            fields_v = issue.get("fields", {})
            raw_start = fields_v.get("customfield_10160")
            if not raw_start:
                continue
            try:
                cr_dt = datetime.fromisoformat(raw_start.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                logger.debug("Unparseable Change start date %r on %s",
                             raw_start, issue.get("key"))
                continue
            if not (start <= cr_dt <= end):
                continue
            service = fields_v.get("customfield_10098")
            out.append(
                CRWindowEntry(
                    key=issue.get("key", ""),
                    summary=fields_v.get("summary", ""),
                    description=adf_to_text(fields_v.get("description")),
                    planned_start=raw_start,
                    impacted_services=(service or {}).get("value", "") if isinstance(service, dict) else "",
                )
            )
        out.sort(key=lambda e: e.planned_start)
        return out


# --- Ollama summarization ---

def assess_cr_impact(cr: CRData, ollama_url: str, ollama_model: str) -> dict:
    """Evaluate whether a CR describes real service/user/customer impact.

    The Jira "Customer Impact" field is often filled with implementation
    steps rather than actual disruption. This helper asks the LLM to
    distinguish between the two.

    Returns a dict with:
      bucket:  "has_impact" | "unclear_impact" | "no_impact_defined"
      text:    short sentence suitable for rendering (empty when no_impact_defined)

    Never raises — falls back to {"bucket": "unclear_impact", "text": ""} on
    any error so the caller can still render the rest of the summary."""
    fallback = {"bucket": "unclear_impact", "text": ""}
    raw_impact = (cr.customer_impact or "").strip()
    summary_text = (cr.summary or "").strip()
    desc_text = (cr.description or "").strip()[:1500]

    user_prompt = (
        "You are evaluating whether a Jira Change Record describes real "
        "impact. IMPACT means service availability is disrupted, "
        "functionality is degraded, or users/customers will see downtime, "
        "errors, latency, or altered behavior DURING the change. "
        "Implementation steps (\"run X, restart Y, deploy Z\") performed on "
        "the system are NOT impact on their own.\n\n"
        "Return ONLY valid JSON with these exact keys:\n"
        "  \"bucket\": one of \"has_impact\", \"unclear_impact\", \"no_impact_defined\"\n"
        "  \"text\":   one short sentence describing the impact (empty string when no_impact_defined)\n\n"
        "Classify as \"no_impact_defined\" when the CR's impact field is empty, "
        "says \"none\" / \"n/a\" / \"no customer impact\", or only lists procedural "
        "steps with no disruption described.\n"
        "Classify as \"has_impact\" only when disruption to a system, user, or "
        "customer is explicitly stated.\n"
        "Prefer \"unclear_impact\" over guessing.\n\n"
        f"CR: {cr.key} — {summary_text}\n\n"
        f"Customer Impact field:\n---\n{raw_impact or '(empty)'}\n---\n\n"
        f"Description:\n---\n{desc_text or '(empty)'}\n---"
    )
    payload = {
        "model": ollama_model,
        "messages": [
            {"role": "system", "content": "You output valid JSON only."},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "format": "json",
    }
    try:
        resp = requests.post(f"{ollama_url}/api/chat", json=payload, timeout=15)
    except requests.RequestException as e:
        logger.warning("assess_cr_impact: ollama request failed for %s: %s", cr.key, e)
        return fallback
    if resp.status_code != 200:
        logger.warning("assess_cr_impact: ollama %d for %s", resp.status_code, cr.key)
        return fallback
    try:
        parsed = json.loads(resp.json()["message"]["content"])
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        logger.warning("assess_cr_impact: parse error for %s: %s", cr.key, e)
        return fallback
    bucket = parsed.get("bucket")
    if bucket not in ("has_impact", "unclear_impact", "no_impact_defined"):
        return fallback
    text = str(parsed.get("text") or "").strip()
    if bucket == "no_impact_defined":
        text = ""
    # Cap to a single line of reasonable length.
    text = text.splitlines()[0][:280] if text else ""
    return {"bucket": bucket, "text": text}


def _build_cr_prompt(cr: CRData) -> str:
    """Build the structured text blob sent to the LLM."""
    lines = [f"{cr.key} | {cr.summary}"]
    lines.append(f"Status: {cr.status}")

    type_parts = []
    if cr.change_type:
        type_parts.append(f"Type: {cr.change_type}")
    if cr.change_category:
        type_parts.append(f"Category: {cr.change_category}")
    if type_parts:
        lines.append(" | ".join(type_parts))

    loc_parts = []
    if cr.service:
        loc_parts.append(f"Service: {cr.service}")
    if cr.environment:
        loc_parts.append(f"Environment: {cr.environment}")
    if loc_parts:
        lines.append(" | ".join(loc_parts))

    if cr.start_date:
        lines.append(f"Change Start: {cr.start_date}")

    for label, value in [
        ("Description", cr.description),
        ("Implementation Plan", cr.implementation_plan),
        ("Customer Impact", cr.customer_impact),
        ("Backout Plan", cr.backout_plan),
    ]:
        if value and value.strip():
            lines.append(f"\n{label}:\n{value.strip()}")

    return "\n".join(lines)


def summarize_cr(cr: CRData, ollama_url: str, ollama_model: str) -> str | None:
    """Call Ollama to summarize a CR. Returns None on failure."""
    prompt_text = _build_cr_prompt(cr)
    payload = {
        "model": ollama_model,
        "messages": [
            {
                "role": "system",
                "content": "You are a concise technical summarizer. Output plain text bullet points only.",
            },
            {
                "role": "user",
                "content": (
                    "Summarize this Jira Change Record for an ops team in 3-5 bullet points.\n"
                    "Focus on: what is changing, what service/environment is affected, "
                    "when it starts, and the rollback plan. Be concise.\n"
                    "Do NOT restate implementation steps as impact. If the CR's "
                    "\"Customer Impact\" field only lists procedural steps (\"run X, "
                    "restart Y, deploy Z\") without actual service/user disruption, "
                    "omit impact entirely — that is not impact.\n\n"
                    f"---\n{prompt_text}\n---"
                ),
            },
        ],
        "stream": False,
    }

    try:
        resp = requests.post(
            f"{ollama_url}/api/chat",
            json=payload,
            timeout=30,
        )
    except requests.RequestException as e:
        logger.error("Ollama request failed: %s", e)
        return None

    if resp.status_code != 200:
        logger.error("Ollama error (%d): %s", resp.status_code, resp.text)
        return None

    try:
        return resp.json()["message"]["content"]
    except (KeyError, json.JSONDecodeError) as e:
        logger.error("Ollama response parse error: %s", e)
        return None


# --- Slack message formatting ---

def _format_start_date(iso_date: str) -> str:
    """Format ISO datetime to 'YYYY-MM-DD h:MM AM/PM TZ'."""
    try:
        dt = datetime.fromisoformat(iso_date)
        offset = dt.strftime("%z")
        return dt.strftime("%Y-%m-%d") + " " + dt.strftime("%I:%M %p").lstrip("0") + f" (UTC{offset[:3]}:{offset[3:]})"
    except (ValueError, AttributeError):
        return iso_date


_IMPACT_ICON = {
    "has_impact":        ":red_circle:",
    "unclear_impact":    ":large_yellow_circle:",
    "no_impact_defined": ":white_circle:",
}
_IMPACT_LABEL = {
    "has_impact":        "Has Impact",
    "unclear_impact":    "Unclear Impact",
    "no_impact_defined": "No Impact Defined",
}


def format_cr_slack_message(
    cr: CRData,
    summary: str | None,
    jira_base_url: str,
    impact_assessment: dict | None = None,
) -> str:
    """Format the Slack thread reply for a CR summary.

    `impact_assessment` is the dict returned by `assess_cr_impact`. If None,
    we fall back to labelling the CR "Unclear Impact" (we used to dump the
    raw Customer Impact field, but that field is frequently filled with
    procedural steps rather than real service disruption)."""
    cr_url = f"{jira_base_url}/browse/{cr.key}"

    # Title: linked CR key — no emoji
    lines = [f"*<{cr_url}|{cr.key}>* \u2014 {cr.summary}"]

    # Metadata: one field per line
    if cr.status:
        lines.append(f"*Status:* {cr.status}")
    if cr.change_type:
        lines.append(f"*Type:* {cr.change_type}")
    if cr.change_category:
        lines.append(f"*Category:* {cr.change_category}")
    if cr.service:
        lines.append(f"*Service:* {cr.service}")
    if cr.environment:
        lines.append(f"*Environment:* {cr.environment}")
    if cr.start_date:
        lines.append(f"*Scheduled:* {_format_start_date(cr.start_date)}")

    # Impact — classify via assess_cr_impact (prevents dumping procedural
    # steps from the Customer Impact field as if they were real impact).
    assessment = impact_assessment or {"bucket": "unclear_impact", "text": ""}
    bucket = assessment.get("bucket", "unclear_impact")
    if bucket not in _IMPACT_LABEL:
        bucket = "unclear_impact"
    icon = _IMPACT_ICON[bucket]
    label = _IMPACT_LABEL[bucket]
    lines.append("")
    lines.append(f"{icon} *{label}*")
    text = (assessment.get("text") or "").strip()
    if bucket == "has_impact" and text:
        lines.append(f"> {text}")
    elif bucket == "unclear_impact" and text:
        lines.append(f"> {text}")

    lines.append("")  # blank line before summary

    if summary:
        for line in summary.strip().split("\n"):
            if line.strip():
                lines.append(f"> {line}")
    else:
        lines.append("_(Summary unavailable \u2014 see full CR)_")

    return "\n".join(lines)
