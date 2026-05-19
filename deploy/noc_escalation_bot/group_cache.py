import logging
import threading

from cachetools import TTLCache

logger = logging.getLogger(__name__)


class GroupMembershipCache:
    """Thread-safe, TTL-backed cache of Slack user group membership.

    Shared between MessageHandler and ReactionHandler so group lookups
    are deduplicated and thread-safe in one place.
    """

    def __init__(self, group_ids: list[str]):
        self.group_ids = group_ids
        self._cache = TTLCache(maxsize=16, ttl=300)   # 5-min TTL per group
        self._stale: dict[str, set[str]] = {}          # Fallback on API failure
        self._lock = threading.Lock()

    def get_members(self, slack_client) -> set[str]:
        """Return combined membership of all watched groups. Fail-open on error."""
        members: set[str] = set()
        for gid in self.group_ids:
            with self._lock:
                cached = self._cache.get(gid)
            if cached is not None:
                members.update(cached)
                continue

            try:
                resp = slack_client.usergroups_users_list(usergroup=gid)
                user_ids = set(resp["users"])
                with self._lock:
                    self._cache[gid] = user_ids
                    self._stale[gid] = user_ids
                members.update(user_ids)
            except Exception:
                logger.warning(
                    "Failed to fetch group %s members, using fallback", gid, exc_info=True
                )
                with self._lock:
                    stale = self._stale.get(gid)
                if stale:
                    members.update(stale)

        return members
