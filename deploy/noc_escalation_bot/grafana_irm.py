import json
import logging
import time
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)


class EscalationError(Exception):
    """Raised when an escalation to Grafana IRM fails."""
    pass


class GrafanaIRMClient:
    def __init__(self, base_url: str, api_key: str, integration_id: str, escalation_chain_id: str,
                 oncall_api_url: str = "", oncall_api_token: str = ""):
        # Keep trailing slash — Grafana's direct_paging webhook redirects the
        # no-slash form to the slash form, which requests follows as GET
        # (dropping the POST body) and returns an HTML info page instead of
        # creating an alert.
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.api_key = api_key
        self.integration_id = integration_id
        self.escalation_chain_id = escalation_chain_id
        # Grafana OnCall's REST API lives on a different URL than the
        # direct_paging webhook — and wants a different token (created in
        # Grafana OnCall → Settings → API Keys; sent as raw Authorization,
        # no "Bearer " prefix). Both are optional; if either is missing,
        # get_oncall returns [] and the caller shows the empty-roster
        # ephemeral.
        self.oncall_api_url = (oncall_api_url or "").rstrip("/")
        self.oncall_api_token = oncall_api_token or ""
        self.session = requests.Session()
        # base_url is the full webhook URL for a Grafana OnCall/IRM
        # "Direct Paging" integration (contains the integration secret).
        # No Authorization header is required — the secret is in the URL.
        self.session.headers.update({
            "Content-Type": "application/json",
        })

    def get_oncall(self, schedule_id: str) -> list[str]:
        """Return the list of user handles currently on call for `schedule_id`.

        Hits Grafana OnCall's `/api/v1/schedules/{id}/final_shifts` endpoint
        (scoped to today in UTC) and returns the email local-parts of the
        users on shift. Returns an empty list on any error or when the
        OnCall API URL/token aren't configured; caller emits a user-visible
        ephemeral."""
        if not schedule_id or not self.oncall_api_url or not self.oncall_api_token:
            return []
        try:
            today = datetime.now(timezone.utc).date().isoformat()
            resp = requests.get(
                f"{self.oncall_api_url}/api/v1/schedules/{schedule_id}/final_shifts",
                headers={"Authorization": self.oncall_api_token},
                params={"start_date": today, "end_date": today},
                timeout=5,
            )
            resp.raise_for_status()
            results = resp.json().get("results", []) or []
            seen: set[str] = set()
            names: list[str] = []
            for r in results:
                raw = (r.get("user_username") or r.get("user_email") or "").strip()
                if not raw:
                    continue
                # strip email domain for cleaner display (aplacid@x.com → aplacid)
                name = raw.split("@", 1)[0]
                if name and name not in seen:
                    seen.add(name)
                    names.append(name)
            return names
        except Exception as e:
            logger.warning("grafana_irm: get_oncall(%s) failed: %s", schedule_id, e)
            return []

    def escalate(self, title: str, message: str, source_link: str,
                 escalation_chain_id: str = "") -> bool:
        """Fire a page via the direct-paging integration webhook.

        `escalation_chain_id` overrides the chain baked into the webhook —
        used by the "Page Manager" button to route to a different chain.
        Grafana's direct_paging integration reads `payload.oncall.escalation_chain`
        when present; otherwise it falls back to the integration's configured
        chain (the default domains-sre chain for routine pages).
        """
        url = self.base_url
        # Grafana OnCall "direct_paging" integration templates read from
        # payload.oncall.*; wrapping the fields avoids the "Template Warning"
        # fallback alert that fires when payload.oncall is missing.
        oncall = {
            "title": title,
            "message": message,
            "source_url": source_link,
            "state": "alerting",
        }
        if escalation_chain_id:
            oncall["escalation_chain"] = escalation_chain_id
        payload = {"oncall": oncall}

        last_error = None
        for attempt in range(2):  # Initial + 1 retry
            try:
                resp = self.session.post(url, data=json.dumps(payload))
            except requests.RequestException as e:
                last_error = str(e)
                logger.error("Grafana IRM request failed: %s", e)
                if attempt == 0:
                    time.sleep(5)
                    continue
                break

            if resp.status_code in (200, 201):
                logger.info("Escalation created: %s", resp.text)
                return True

            if resp.status_code in (401, 403):
                raise EscalationError(
                    f"Grafana IRM auth failure ({resp.status_code}): {resp.text}"
                )

            if resp.status_code == 429:
                try:
                    retry_after = int(resp.headers.get("Retry-After", "5"))
                except ValueError:
                    retry_after = 5
                logger.warning("Rate limited, retrying after %ds", retry_after)
                if attempt == 0:
                    time.sleep(retry_after)
                    continue
                last_error = f"Rate limited: {resp.text}"
                break

            # 5xx or other
            logger.error(
                "Grafana IRM error (%d): %s", resp.status_code, resp.text
            )
            last_error = f"HTTP {resp.status_code}: {resp.text}"
            if attempt == 0:
                time.sleep(5)
                continue

        raise EscalationError(
            f"Escalation failed after retry: {last_error}"
        )
