"""OCCIR Jira incident ticket creation. Mirrors jira_cr.py Basic Auth pattern."""

import logging
import os
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)

# Normalised lowercase keys → Jira option ID
OPERATIONAL_SERVICES: dict[str, str] = {
    "ascio":                          "11231",
    "enom":                           "11232",
    "exacthosting":                   "11236",
    "hosted email":                   "11235",
    "hover":                          "11234",
    "infrastructure":                 "11237",
    "opensrs":                        "11233",
    "trs (tucows registry service)":  "11239",
    "trs":                            "11239",  # short-form alias
}

OPERATIONAL_SERVICE_DISPLAY = [
    "Ascio", "Enom", "ExactHosting", "Hosted Email",
    "Hover", "Infrastructure", "OpenSRS", "TRS (Tucows Registry Service)",
]


OCCIR_INCIDENT_ISSUETYPE_ID = os.environ.get("OCCIR_INCIDENT_ISSUETYPE_ID", "10333")
OCCIR_TICKET_ISSUETYPE_ID = os.environ.get("OCCIR_TICKET_ISSUETYPE_ID", "")


def resolve_occir_issue_type_id(work_type: str) -> str:
    normalized = (work_type or "incident").strip().lower()
    if normalized == "ticket":
        if not OCCIR_TICKET_ISSUETYPE_ID:
            raise OccirJiraError("OCCIR Ticket work type is not configured")
        return OCCIR_TICKET_ISSUETYPE_ID
    return OCCIR_INCIDENT_ISSUETYPE_ID


class OccirJiraError(Exception):
    """Raised when OCCIR ticket creation fails."""


class OccirJiraClient:
    """Creates OCCIR incidents via Jira REST API v3."""

    def __init__(self, base_url: str, email: str, api_token: str):
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.auth = HTTPBasicAuth(email, api_token)
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _build_adf_description(self, text: str) -> dict:
        """Wrap plain text in ADF (Jira REST API v3 requires this for description)."""
        return {
            "version": 1,
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": text}],
                }
            ],
        }

    def create_incident(
        self,
        summary: str,
        description_text: str,
        alert_link: str,
        service_name: str,
        occir_work_type: str = "incident",
    ) -> str:
        """Create an OCCIR Jira issue. Returns the ticket key (e.g. OCCIR-123).

        Raises OccirJiraError on failure.
        """
        service_id = OPERATIONAL_SERVICES.get(service_name.strip().lower(), "11237")
        issue_type_id = resolve_occir_issue_type_id(occir_work_type)

        payload = {
            "fields": {
                "project":            {"key": "OCCIR"},
                "issuetype":          {"id": issue_type_id},
                "summary":            summary[:255],
                "description":        self._build_adf_description(description_text),
                "customfield_10306":  {"id": "11229"},          # Class III
                "customfield_10307":  {"id": service_id},       # Operational Service
                "customfield_10308":  alert_link,               # Alert Link URL
            }
        }

        url = f"{self.base_url}/rest/api/3/issue"
        try:
            resp = self._session.post(url, json=payload)
        except requests.RequestException as exc:
            raise OccirJiraError(f"Request failed: {exc}") from exc

        if resp.status_code not in (200, 201):
            raise OccirJiraError(
                f"Jira API error ({resp.status_code}): {resp.text}"
            )

        return resp.json()["key"]

    def get_status(self, ticket_key: str) -> Optional[str]:
        """Return the current status name, or None on any failure."""
        url = f"{self.base_url}/rest/api/3/issue/{ticket_key}"
        try:
            resp = self._session.get(url, params={"fields": "status"}, timeout=10)
        except requests.RequestException as e:
            logger.warning("OccirJiraClient.get_status: request failed: %s", e)
            return None
        if resp.status_code != 200:
            logger.warning("OccirJiraClient.get_status: %d %s",
                            resp.status_code, resp.text[:200])
            return None
        try:
            data = resp.json()
        except ValueError as e:
            logger.warning("OccirJiraClient.get_status: bad json: %s", e)
            return None
        status = ((data.get("fields") or {}).get("status") or {}).get("name")
        return status if isinstance(status, str) else None
