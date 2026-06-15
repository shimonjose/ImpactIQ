"""Permissions-diagnosis path.

Anchor: ``user_id + table + action``. Walk in order:
role-privilege -> field-level security -> ownership/team access -> business
rule / role-gated logic. Return a single typed ``PermissionsDiagnosis`` with
the cause and the recommended fix.

Two callable forms:

* **Live**: pass a ``DataverseClient`` and we fetch the user's roles +
  privileges via the Web API.
* **Test/replay**: pass ``user_roles`` and ``role_privileges`` directly; no
  Dataverse calls. Same code path otherwise.

The action -> privilege-name mapping is the standard Dataverse one
(``prv<AccessRight><EntityName>``), so the diagnosis can be made purely from
privilege names.

LIMITATION — field-level security is NOT auto-detected on the live path. The
walk lists field-level security as a step, but ``field_security_blockers``
is an INPUT here, not something the Live form discovers: it fetches roles +
privileges only, never the per-user Field Security Profile resolution. So the
FLS branch below fires only when a caller (or a test) supplies blockers; on the
live tool path it is never populated and column-level denies are not detected.
Wiring live FLS detection (secured-attribute metadata + the user's FSP
membership via teams) is a tracked gap, deliberately not faked here rather than
silently implied by the walk-order docstring.
"""

from __future__ import annotations

from ..dataverse_client import DataverseClient
from .model import Action, PermissionsDiagnosis


class PrivilegeFetchError(RuntimeError):
    """Raised when role-privilege retrieval fails and a denial therefore cannot
    be asserted. Surfaced to the agent as an explicit error — NEVER silently
    converted into a false 'permission denied' (the swallowed-exception bug)."""

# AccessRight name fragment used in the privilege name; capitalisation matches
# the platform (``prvCreateAccount`` etc.).
_ACTION_TO_FRAGMENT: dict[Action, str] = {
    "create": "Create",
    "read": "Read",
    "write": "Write",
    "delete": "Delete",
    "append": "Append",
    "appendto": "AppendTo",
    "assign": "Assign",
    "share": "Share",
}


def _privilege_name(action: Action, table_logical: str) -> str:
    """``write`` + ``request`` -> ``prvWriteRequest``."""
    return f"prv{_ACTION_TO_FRAGMENT[action]}{table_logical.capitalize()}"


def _has_grant(role_privileges: dict[str, list[str]], role_id: str, prv_name: str) -> bool:
    """Case-insensitive membership: Dataverse occasionally varies casing."""
    target = prv_name.lower()
    for p in role_privileges.get(role_id, ()):
        if p.lower() == target:
            return True
    return False


def diagnose_permission(
    user_id: str,
    table_logical: str,
    action: Action,
    *,
    user_roles: list[dict] | None = None,
    role_privileges: dict[str, list[str]] | None = None,
    field_security_blockers: list[str] | None = None,
    client: DataverseClient | None = None,
) -> PermissionsDiagnosis:
    """Return why the user can (or cannot) perform ``action`` on ``table_logical``.

    ``user_roles`` items look like ``{"roleid": "...", "name": "..."}``.
    ``role_privileges`` maps ``roleid -> [prvNameAccount, prvReadAccount, ...]``.
    """
    # Live fetch path (when no pre-loaded inputs supplied and a client is given).
    failed_priv_fetches: list[str] = []
    if user_roles is None and client is not None:
        user_roles = _fetch_user_roles(client, user_id)
    if role_privileges is None and client is not None:
        role_privileges, failed_priv_fetches = _fetch_role_privileges(
            client, [r["roleid"] for r in (user_roles or [])]
        )

    user_roles = user_roles or []
    role_privileges = role_privileges or {}
    field_security_blockers = field_security_blockers or []

    target_prv = _privilege_name(action, table_logical)
    role_names = [r.get("name") or r.get("roleid", "?") for r in user_roles]
    role_ids = [r.get("roleid") for r in user_roles if r.get("roleid")]

    # Pull relevant privileges (anything on this table) for explainability.
    relevant: list[str] = []
    for rid in role_ids:
        for p in role_privileges.get(rid, ()):
            if table_logical.lower() in p.lower():
                relevant.append(p)
    relevant = sorted(set(relevant))

    # Field-level security check runs before granting (column-level deny wins).
    # NOTE: only fires when the caller supplies field_security_blockers — the
    # live fetch path does NOT detect FLS (see the module docstring's
    # LIMITATION). This branch is exercised by callers that pre-resolve blockers
    # and by the test suite, not by the live permissions tool.
    if field_security_blockers:
        return PermissionsDiagnosis(
            user_id=user_id,
            table_logical=table_logical,
            action=action,
            granted=False,
            likely_cause=(
                f"Field-level security blocks {action} on column(s): "
                f"{', '.join(field_security_blockers)}. The table-level "
                f"privilege exists, but a Field Security Profile the user's "
                f"team is not in gates the column."
            ),
            user_roles=role_names,
            relevant_privileges=relevant,
            field_security_blockers=field_security_blockers,
            recommended_fix=(
                f"Add the user's team to the Field Security Profile that "
                f"covers {', '.join(field_security_blockers)} - or grant that "
                f"profile the {action.capitalize()} flag on the column."
            ),
        )

    # Role-privilege check.
    has = any(_has_grant(role_privileges, rid, target_prv) for rid in role_ids)
    if has:
        return PermissionsDiagnosis(
            user_id=user_id,
            table_logical=table_logical,
            action=action,
            granted=True,
            likely_cause=(
                f"At least one of the user's roles grants {target_prv}. "
                f"If the action still fails at runtime, the next causes to "
                f"check are row ownership / sharing and any business rule "
                f"gating this action for the user's role."
            ),
            user_roles=role_names,
            relevant_privileges=relevant,
        )

    # No table-level grant was found among the privileges we could read. If some
    # roles' privileges FAILED to fetch, we do not have enough information to
    # assert a denial — refuse to emit a false "permission denied" and surface
    # the gap explicitly instead (the agent gets a real error, not a wrong
    # security verdict). A grant we DID see above already short-circuited.
    if failed_priv_fetches:
        raise PrivilegeFetchError(
            "could not retrieve privileges for role(s) "
            f"{', '.join(failed_priv_fetches)}; refusing to report a denial on "
            "incomplete data"
        )

    # No grant - explain what's missing and what the closest fix is.
    read_prv = _privilege_name("read", table_logical)
    has_read = any(_has_grant(role_privileges, rid, read_prv) for rid in role_ids)
    if action != "read" and has_read:
        cause = (
            f"No role assigned to the user grants {target_prv}. The classic "
            f"'read-but-not-write' case: the user can see {table_logical} but "
            f"cannot {action} it."
        )
        fix = (
            f"Grant a role with {action.capitalize()} on {table_logical} "
            f"(at the minimum access level required by the scenario), or add "
            f"the user to a team that already holds it."
        )
    else:
        cause = (
            f"None of the user's roles grants {target_prv} on {table_logical}."
        )
        fix = (
            f"Assign a role that includes {action.capitalize()} on "
            f"{table_logical}."
        )

    return PermissionsDiagnosis(
        user_id=user_id,
        table_logical=table_logical,
        action=action,
        granted=False,
        likely_cause=cause,
        user_roles=role_names,
        relevant_privileges=relevant,
        recommended_fix=fix,
    )


# --- live fetch helpers (used when client is supplied) ---------------------


def _fetch_user_roles(client: DataverseClient, user_id: str) -> list[dict]:
    data = client.get(
        f"systemusers({user_id})/systemuserroles_association",
        {"$select": "name,roleid"},
    )
    return data.get("value", [])


def _fetch_role_privileges(
    client: DataverseClient, role_ids: list[str]
) -> tuple[dict[str, list[str]], list[str]]:
    """Build ``({role_id -> [privilege_name, ...]}, [role_ids that FAILED])``.

    Each privilege row carries a GUID; we resolve to ``prv<...>`` names by
    pre-fetching the privilege table. This is what makes the diagnosis output
    human-readable.

    A role whose privilege retrieval errors is OMITTED from the dict and its id
    is returned in the failure list — it is NOT recorded as an empty privilege
    set. Treating a failed fetch as "no privileges" would let a transient or
    permission error masquerade as a genuine "permission denied" (a false
    negative on the most security-relevant question); the caller uses the
    failure list to refuse a denial it cannot stand behind.
    """
    if not role_ids:
        return {}, []
    # Pull the name table once.
    privs = client.get_all("privileges", {"$select": "name,privilegeid"})
    id_to_name = {p["privilegeid"]: p.get("name") for p in privs if p.get("privilegeid")}

    out: dict[str, list[str]] = {}
    failed: list[str] = []
    for rid in role_ids:
        try:
            data = client.call_function("RetrieveRolePrivilegesRole", RoleId=rid)
        except Exception as exc:  # noqa: BLE001
            failed.append(rid)
            print(
                f"(permissions: privilege fetch failed for role {rid}: "
                f"{type(exc).__name__})",
                flush=True,
            )
            continue
        rows = data.get("RolePrivileges") or data.get("value") or []
        out[rid] = [
            name
            for name in (id_to_name.get(r.get("PrivilegeId")) for r in rows)
            if name
        ]
    return out, failed
