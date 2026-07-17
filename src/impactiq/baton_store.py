"""Cross-session context-baton store - the one piece of state the interactive
notify-and-handoff needs.

The baton is written by the notifying user (B) and read by the recipient
manager in *their own* session, so the manager's Work IQ can supply their side
of the context. It lives in ImpactIQ's **own** Dataverse table
``new_impactiq_baton`` (display name "impactiq_baton").

Identity & bounds:
* All access is under the **delegated user identity** (never the read-only
  service identity). B creates the row (Create=User); the manager reads it
  (Read=Organization, since they're in a different Business Unit).
* This is the only sanctioned write outside the bounded-write path. It touches
  ImpactIQ's own table only - never customer business data, config or schema -
  and every write is audit-logged.
* ``set_status`` is best-effort: the manager holds only User-level Write, so
  cannot patch a row B owns. The manager's ack/resume are therefore recorded
  as *audit events*, not row writes; status mutation is reserved for the
  owner (B) or a future Org-scoped grant.

Column logical names follow the live schema: the publisher prefix is ``new_``
and the primary-name column is ``new_impactiqname`` (no underscore before
"name").
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from .agents.runtime import delegated_credential
from .audit import audit_log
from .report.artifacts import ContextBaton
from .settings import Settings

_ENTITY_SET = "new_impactiq_batons"
_PK = "new_impactiq_batonid"
_NAME = "new_impactiqname"  # primary name col - holds the baton-… correlation id

# baton field -> Dataverse column logical name (excludes name/version handled
# explicitly because of their distinct types/roles).
_COLS = {
    "requesting_user": "new_impactiq_requesting_user",
    "recipient": "new_impactiq_recipient",
    "intent": "new_impactiq_intent",
    "anchor": "new_impactiq_anchor",
    "proposed_change": "new_impactiq_proposed_change",
    "impacted_components": "new_impactiq_impacted_components",
    "risk_level": "new_impactiq_risk_level",
    "resume_hint": "new_impactiq_resume_hint",
    "status": "new_impactiq_status",
}
_VERSION = "new_impactiq_baton_version"

_SELECT = ",".join(
    [_PK, _NAME, _VERSION, "createdon", *_COLS.values()]
)


class BatonStoreError(RuntimeError):
    """A non-2xx from the baton table (message extracted, never secrets)."""


@dataclass
class StoredBaton:
    baton: ContextBaton
    recipient: str
    status: str
    row_id: str  # the Dataverse GUID (new_impactiq_batonid)


def _api_base(settings: Settings) -> str:
    base = (settings.dataverse_url or "").rstrip("/")
    if not base:
        raise BatonStoreError("DATAVERSE_URL is not configured")
    return f"{base}/api/data/v9.2"


def _token(settings: Settings, user_assertion: str | None = None) -> str:
    base = (settings.dataverse_url or "").rstrip("/")
    return delegated_credential(settings, user_assertion).get_token(f"{base}/.default").token


def _headers(token: str, *, representation: bool = False) -> dict[str, str]:
    h = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
    }
    if representation:
        h["Prefer"] = "return=representation"
    return h


def _err(resp: httpx.Response) -> str:
    detail = resp.text
    try:
        body = resp.json()
        if isinstance(body, dict) and "error" in body:
            detail = body["error"].get("message", detail)
    except Exception:
        pass
    return f"HTTP {resp.status_code} from baton store: {detail[:400]}"


def _baton_to_row(baton: ContextBaton, recipient: str, status: str) -> dict:
    """Map a ContextBaton onto the table's columns. NodeRef fields are stored
    as JSON in their Memo columns; nothing here can carry the other team's
    content (the baton has no such field - a deliberate structural property)."""
    anchor = json.dumps(baton.anchor.model_dump()) if baton.anchor else ""
    impacted = json.dumps([c.model_dump() for c in baton.impacted_components])
    return {
        _NAME: baton.baton_id,
        _VERSION: int(baton.baton_version),
        _COLS["requesting_user"]: baton.requesting_user,
        _COLS["recipient"]: recipient,
        _COLS["intent"]: baton.intent,
        _COLS["anchor"]: anchor,
        _COLS["proposed_change"]: baton.proposed_change,
        _COLS["impacted_components"]: impacted,
        _COLS["risk_level"]: baton.risk_level,
        _COLS["resume_hint"]: baton.resume_hint,
        _COLS["status"]: status,
    }


def _row_to_stored(row: dict) -> StoredBaton:
    def _loads(s: str | None):
        if not s:
            return None
        try:
            return json.loads(s)
        except (json.JSONDecodeError, TypeError):
            return None

    baton = ContextBaton.model_validate(
        {
            "baton_id": row.get(_NAME) or "",
            "created_utc": row.get("createdon") or None,
            "baton_version": row.get(_VERSION) or 1,
            "requesting_user": row.get(_COLS["requesting_user"]) or "requesting user",
            "intent": (row.get(_COLS["intent"]) or "VALIDATE"),
            "anchor": _loads(row.get(_COLS["anchor"])),
            "proposed_change": row.get(_COLS["proposed_change"]) or "",
            "impacted_components": _loads(row.get(_COLS["impacted_components"])) or [],
            "risk_level": (row.get(_COLS["risk_level"]) or "low"),
            "resume_hint": row.get(_COLS["resume_hint"]) or "",
        }
    )
    return StoredBaton(
        baton=baton,
        recipient=row.get(_COLS["recipient"]) or "",
        status=row.get(_COLS["status"]) or "sent",
        row_id=row.get(_PK) or "",
    )


def put_baton(
    settings: Settings,
    baton: ContextBaton,
    recipient: str,
    *,
    status: str = "sent",
    user_assertion: str | None = None,
) -> StoredBaton:
    """Create the baton row under the delegated (notifying user) identity.
    Returns the StoredBaton including its Dataverse GUID. Audit-logged."""
    token = _token(settings, user_assertion)
    body = _baton_to_row(baton, recipient, status)
    resp = httpx.post(
        f"{_api_base(settings)}/{_ENTITY_SET}",
        json=body,
        headers=_headers(token, representation=True),
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        raise BatonStoreError(_err(resp))
    stored = _row_to_stored(resp.json())
    audit_log(
        "baton_persisted",
        {
            "baton_id": baton.baton_id,
            "row_id": stored.row_id,
            "requesting_user": baton.requesting_user,
            "recipient": recipient,
            "intent": baton.intent,
            "status": status,
        },
    )
    return stored


def get_baton(
    settings: Settings, baton_id: str, user_assertion: str | None = None
) -> StoredBaton | None:
    """Read a baton by its correlation id (the primary-name column), under the
    caller's delegated identity. The manager resumes with this in their own
    session (Org-level Read)."""
    token = _token(settings, user_assertion)
    safe = baton_id.replace("'", "''")
    resp = httpx.get(
        f"{_api_base(settings)}/{_ENTITY_SET}",
        params={"$select": _SELECT, "$filter": f"{_NAME} eq '{safe}'", "$top": 1},
        headers=_headers(token),
        timeout=30,
    )
    if resp.status_code != 200:
        raise BatonStoreError(_err(resp))
    rows = resp.json().get("value", [])
    return _row_to_stored(rows[0]) if rows else None


def set_status(
    settings: Settings, baton_id: str, status: str, user_assertion: str | None = None
) -> bool:
    """Best-effort status update (owner / Org-scoped Write only). Returns
    whether the patch landed. Audit-logged either way. The handoff flow does
    NOT rely on this - the manager's ack/resume are recorded as audit events."""
    try:
        existing = get_baton(settings, baton_id, user_assertion)
        if existing is None:
            audit_log("baton_status_change_failed", {"baton_id": baton_id, "reason": "not found"})
            return False
        token = _token(settings, user_assertion)
        resp = httpx.patch(
            f"{_api_base(settings)}/{_ENTITY_SET}({existing.row_id})",
            json={_COLS["status"]: status},
            headers={**_headers(token), "If-Match": "*"},  # update-only, never create
            timeout=30,
        )
        ok = resp.status_code in (200, 204)
        audit_log(
            "baton_status_changed" if ok else "baton_status_change_failed",
            {"baton_id": baton_id, "status": status, "detail": None if ok else _err(resp)},
        )
        return ok
    except Exception as exc:  # noqa: BLE001 - best-effort by contract
        audit_log("baton_status_change_failed", {"baton_id": baton_id, "reason": str(exc)})
        return False
