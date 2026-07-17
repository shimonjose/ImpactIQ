"""The permission wall: builder actions are role-gated.

The requesting user must hold the ``IMPACTIQ_BUILDER_ROLE`` security role
(default "ImpactIQ Builder") **in the sandbox environment**, checked under
the DELEGATED user identity (the service principal's own roles are
irrelevant - the human triggers the fix, the human must be authorized).

Only DIRECT role assignment is checked (``systemuserroles_association``);
roles inherited via team membership are not resolved - assign the role to
the user, not a team. Known identity seam: without Teams SSO, the
"requesting user" is the locally signed-in user.
"""

from __future__ import annotations

import time

import httpx

from ..agents.runtime import delegated_credential
from ..identity import token_owner
from ..settings import Settings
from . import BuilderRefusal, assert_builder_walls

API_VERSION = "v9.2"

# (tenant_id, object_id, build_url, role) -> (held, checked_at). The cache key
# MUST carry the requesting user's immutable identity: authorization results
# are per-user, and a key without the user would hand one user's cached answer
# to the next caller. TTL keeps chat turns snappy while still noticing a
# revoked role within minutes; the Apply endpoint bypasses the cache entirely.
_ROLE_CACHE: dict[tuple[str, str, str, str], tuple[bool, float]] = {}
ROLE_CACHE_TTL = 300.0

# Cache identity for the local single-user path (CLI / F5, no Teams token -
# the browser sign-in IS the requesting user there).
_LOCAL_OWNER = ("local", "local")


def _user_role_names(
    settings: Settings, build_url: str, user_assertion: str | None = None
) -> list[str]:
    # The role check runs as the requesting user: On-Behalf-Of when hosted, or
    # the local browser sign-in for the CLI. (The app's delegated Dynamics CRM
    # user_impersonation grant covers the sandbox Dataverse over OBO.)
    token = delegated_credential(settings, user_assertion).get_token(f"{build_url}/.default").token
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }
    api = f"{build_url}/api/data/{API_VERSION}"
    with httpx.Client(timeout=30.0) as http:
        who = http.get(f"{api}/WhoAmI", headers=headers)
        if who.status_code >= 400:
            raise BuilderRefusal(
                f"sandbox identity check failed (HTTP {who.status_code}) - is the "
                "requesting user a member of the sandbox environment?"
            )
        uid = who.json()["UserId"]
        resp = http.get(
            f"{api}/systemusers({uid})",
            params={"$select": "fullname", "$expand": "systemuserroles_association($select=name)"},
            headers=headers,
        )
        if resp.status_code >= 400:
            raise BuilderRefusal(f"sandbox role read failed (HTTP {resp.status_code})")
        return [
            r.get("name", "")
            for r in resp.json().get("systemuserroles_association", [])
        ]


def has_builder_permission(
    settings: Settings, user_assertion: str | None = None, *, fresh: bool = False
) -> bool:
    """Whether the requesting user holds the builder role.

    Cached 5m PER USER - the key is (tenant, object id, environment, role),
    so one user's result can never be served to another. ``fresh=True``
    skips the cache read (the write path re-checks live at Apply time).
    Shares the cache with :func:`assert_builder_permission`."""
    build_url = assert_builder_walls(settings)
    role = (getattr(settings, "impactiq_builder_role", None) or "ImpactIQ Builder").strip()
    owner = token_owner(user_assertion) or _LOCAL_OWNER
    key = (owner[0], owner[1], build_url, role.lower())
    now = time.monotonic()
    if not fresh:
        cached = _ROLE_CACHE.get(key)
        if cached and now - cached[1] < ROLE_CACHE_TTL:
            return cached[0]
    names = _user_role_names(settings, build_url, user_assertion)
    held = role.lower() in {n.strip().lower() for n in names}
    _ROLE_CACHE[key] = (held, now)
    return held


def assert_builder_permission(
    settings: Settings, user_assertion: str | None = None, *, fresh: bool = False
) -> None:
    """Refuse unless the requesting user holds the builder role.

    Pass ``fresh=True`` at mutation/Apply time: the permission is then
    re-checked live against the sandbox rather than served from the
    per-user cache (role revocation takes effect immediately)."""
    role = (getattr(settings, "impactiq_builder_role", None) or "ImpactIQ Builder").strip()
    if not has_builder_permission(settings, user_assertion, fresh=fresh):
        raise BuilderRefusal(
            f"you don't hold the '{role}' security role in the sandbox "
            "environment - builder actions are role-gated (ask an admin to "
            "assign it)."
        )
