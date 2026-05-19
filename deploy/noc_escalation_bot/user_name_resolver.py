"""Thread-safe Slack user-ID → display-name cache.

Slack user IDs (`U…`, `W…`) are opaque. For turnover posts we want human
names, so we hit `users.info` once per ID and keep the answer. Unresolvable
IDs (deactivated users, non-user tokens) cache as a short fallback so we
don't retry on every render.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)


class UserNameResolver:
    def __init__(self, slack_client):
        self._slack = slack_client
        self._cache: dict[str, str] = {}
        self._lock = threading.Lock()

    def __call__(self, user_id: Optional[str]) -> str:
        """Return a display name for `user_id`, or a safe fallback."""
        if not user_id:
            return "unknown"
        with self._lock:
            cached = self._cache.get(user_id)
        if cached is not None:
            return cached

        name = self._fetch(user_id)
        with self._lock:
            self._cache[user_id] = name
        return name

    def _fetch(self, user_id: str) -> str:
        try:
            resp = self._slack.users_info(user=user_id)
        except Exception as e:
            logger.debug("user_name_resolver: users_info failed for %s: %s",
                          user_id, e)
            return user_id  # fall back to raw ID so the post still renders

        # SlackResponse is dict-like but not a dict instance — use .get().
        if not resp or not resp.get("ok"):
            return user_id

        user = resp.get("user") or {}
        profile = user.get("profile") or {}
        for key in ("display_name_normalized", "display_name",
                    "real_name_normalized", "real_name"):
            val = profile.get(key)
            if val:
                return val
        name = user.get("name")
        return name or user_id
