"""The permission wall: builder actions are role-gated.

The requesting user must hold the ``IMPACTIQ_BUILDER_ROLE`` security role
(default "ImpactIQ Builder") **in the sandbox environment**, checked under
the DELEGATED user identity (the service principal's own roles are
irrelevant — the human triggers the fix, the human must be authorized).

v1 checks DIRECT role assignment (``systemuserroles_association``); roles
inherited via team membership are not resolved — assign the role to the
user, not a team. Known identity seam: until Teams SSO lands, the
"requesting user" is the locally signed-in user.
"""

from __future__ import annotations

import time

import httpx

from ..agents.runtime import delegated_credential
from ..settings import Settings
from . import BuilderRefusal, assert_builder_walls

API_VERSION = "v9.2"

# (build_url, role) -> (held, checked_at). TTL keeps chat turns snappy while
# still noticing a revoked role within minutes.
_ROLE_CACHE: dict[tuple[str, str], tuple[bool, float]] = {}
ROLE_CACHE_TTL = 300.0


def _user_role_names(
    settings: Settings, build_url: str, user_assertion: str | None = None
) -> list[str]:
    # The role check runs as the requesting user: On-Behalf-Of when hosted, or
    # the local browser sign-in for the CLI. (impactiq-workiq's delegated
    # Dynamics CRM user_impersonation covers the sandbox Dataverse over OBO.)
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
                f"sandbox identity check failed (HTTP {who.status_code}) — is the "
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


def has_builder_permission(settings: Settings, user_assertion: str | None = None) -> bool:
    """Whether the requesting user holds the builder role (cached 5m). Shares
    the cache with :func:`assert_builder_permission`. Used to make the agent
    permission-AWARE upfront (phrase the offer honestly) — the hard gate at
    tool-call and Apply time is still :func:`assert_builder_permission`."""
    build_url = assert_builder_walls(settings)
    role = (getattr(settings, "impactiq_builder_role", None) or "ImpactIQ Builder").strip()
    key = (build_url, role.lower())
    cached = _ROLE_CACHE.get(key)
    now = time.monotonic()
    if cached and now - cached[1] < ROLE_CACHE_TTL:
        return cached[0]
    names = _user_role_names(settings, build_url, user_assertion)
    held = role.lower() in {n.strip().lower() for n in names}
    _ROLE_CACHE[key] = (held, now)
    return held


def assert_builder_permission(settings: Settings, user_assertion: str | None = None) -> None:
    """Refuse unless the requesting user holds the builder role (cached 5m)."""
    role = (getattr(settings, "impactiq_builder_role", None) or "ImpactIQ Builder").strip()
    if not has_builder_permission(settings, user_assertion):
        raise BuilderRefusal(
            f"you don't hold the '{role}' security role in the sandbox "
            "environment — builder actions are role-gated (ask an admin to "
            "assign it)."
        )
