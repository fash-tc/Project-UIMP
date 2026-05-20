"""Session validation client. Asks auth-api /me to resolve cookie → user.

Also supports the ADMIN_BYPASS_TOKEN escape hatch (spec §3.3).
"""
import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger("admin-api.auth")


@dataclass
class User:
    username: str
    permissions: list[str] = field(default_factory=list)


@dataclass
class BypassUser(User):
    """Synthetic user materialized when X-Admin-Bypass header matches the token."""
    pass


def _all_permissions() -> list[str]:
    """Returns the full UIP permission set. Used by BypassUser for full access.
    Kept simple: bypass has '*' which routes treat as omnipotent."""
    return ["*"]


def resolve_user(cookie: str | None, bypass_header: str | None, remote_ip: str = "0.0.0.0") -> User | None:
    """Return a User if the request is authenticated, else None.

    Priority:
      1. X-Admin-Bypass header matching ADMIN_BYPASS_TOKEN (if set) → BypassUser.
      2. Session cookie → /me on auth-api → User.
      3. Otherwise None (handler returns 401).
    """
    token = (os.environ.get("ADMIN_BYPASS_TOKEN") or "").strip()
    if bypass_header:
        # Log every bypass attempt — match goes through, mismatch is noisy security signal.
        if token and bypass_header == token:
            log.warning("audit_bypass=true result=match ip=%s", remote_ip)
            return BypassUser(username=f"__bypass__:{remote_ip}", permissions=_all_permissions())
        log.warning("audit_bypass=true result=reject ip=%s", remote_ip)

    if not cookie:
        return None
    base = os.environ.get("AUTH_API_URL", "http://auth-api:8093").rstrip("/")
    req = urllib.request.Request(f"{base}/me", headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            if r.status != 200:
                return None
            data = json.loads(r.read().decode())
            return User(username=data.get("username", ""), permissions=data.get("permissions", []))
    except urllib.error.HTTPError:
        return None
    except Exception as e:
        log.warning("auth-api unreachable: %s", e)
        return None
