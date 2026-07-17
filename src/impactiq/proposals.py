"""Owner-bound, one-time, server-side proposal store.

Every mutation the bridge offers (sandbox fix, flow resubmit, record
remediation) is registered HERE at proposal time and consumed exactly once
at execution time. The execution endpoints never trust a client-supplied
artifact: they look up the canonical server-stored one by id and validate
that the caller is the same identity (tenant + object id) the proposal was
issued to, that it hasn't expired, and that it hasn't already been consumed.

Single-instance by design (the bridge runs one worker); the lock makes
consumption atomic within the process. A multi-instance deployment must move
this to a durable store with atomic compare-and-delete (e.g. Cosmos DB /
Redis) - the interface below is deliberately store-shaped for that swap.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from typing import Any

_LOCK = threading.Lock()
_STORE: dict[str, dict] = {}
_MAX = 64
DEFAULT_TTL_S = 1800.0  # a proposal older than 30 min must be re-proposed


class ProposalError(Exception):
    """Raised when a proposal cannot be consumed. ``status`` maps to HTTP."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def canonical_hash(obj: Any) -> str:
    """SHA-256 of the canonical JSON form (sorted keys, no whitespace)."""
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def register(
    operation: str,
    artifact: Any,
    *,
    owner: tuple[str, str] | None = None,
    conversation: str | None = None,
    ttl_s: float = DEFAULT_TTL_S,
    extra: dict | None = None,
    prefix: str = "prop",
) -> str:
    """Store a proposal as a security object; returns its one-time id."""
    now = time.time()
    proposal_id = f"{prefix}-{uuid.uuid4().hex[:16]}"
    with _LOCK:
        # Sweep expired, then FIFO-evict past the cap.
        for pid in [p for p, v in _STORE.items() if v["expires_at"] <= now]:
            _STORE.pop(pid, None)
        while len(_STORE) >= _MAX:
            _STORE.pop(next(iter(_STORE)), None)
        _STORE[proposal_id] = {
            "operation": operation,
            "artifact": artifact,
            "artifact_sha256": canonical_hash(artifact),
            "owner": owner,
            "conversation": conversation,
            "created_at": now,
            "expires_at": now + ttl_s,
            "extra": dict(extra or {}),
        }
    return proposal_id


def _validate(
    proposal_id: str,
    operation: str,
    owner: tuple[str, str] | None,
    conversation: str | None,
) -> dict:
    """Shared validation for consume/verify. Caller holds ``_LOCK``.

    Validation order matters: the caller's right to the proposal is checked
    BEFORE anything is removed, so an unauthorised request can neither execute
    nor destroy someone else's pending proposal.
    """
    entry = _STORE.get(proposal_id or "")
    if entry is None or entry["operation"] != operation:
        raise ProposalError(
            404, "that proposal is unknown or has expired - ask the agent to propose it again"
        )
    if entry["expires_at"] <= time.time():
        _STORE.pop(proposal_id, None)
        raise ProposalError(
            404, "that proposal has expired - ask the agent to propose it again"
        )
    # Owner binding: a proposal issued to an identified user may only be used by
    # that same (tenant, object id). A proposal registered with no owner (local
    # single-user dev, no token) stays unbound.
    if entry["owner"] is not None and entry["owner"] != owner:
        raise ProposalError(403, "this proposal belongs to a different user")
    if entry["conversation"] and conversation and entry["conversation"] != conversation:
        raise ProposalError(403, "this proposal belongs to a different conversation")
    return entry


def consume(
    proposal_id: str,
    operation: str,
    *,
    owner: tuple[str, str] | None = None,
    conversation: str | None = None,
) -> dict:
    """Atomically validate + remove a proposal (one-time); returns the stored
    object. Use for irreversible actions (a record write, a notification send)
    where the proposal must not be replayable."""
    with _LOCK:
        _validate(proposal_id, operation, owner, conversation)
        return _STORE.pop(proposal_id)


def verify(
    proposal_id: str,
    operation: str,
    *,
    owner: tuple[str, str] | None = None,
    conversation: str | None = None,
) -> dict:
    """Validate a proposal and return a COPY of the stored object WITHOUT
    removing it. Use to prove that an action's content matches what the owner
    previewed while still allowing a repeat of a reversible action (e.g. saving
    an editable draft into the user's own mailbox)."""
    with _LOCK:
        return dict(_validate(proposal_id, operation, owner, conversation))
