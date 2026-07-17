"""Bridge: a local HTTP API between the Teams agent (surface/) and the Python
pipeline.

The TypeScript Custom Engine Agent is a thin surface - every decision that
matters happens here, where the deterministic gates already live:

* ``POST /agent`` - launch the unified agent turn as a background job; the
  surface polls ``/agent/result`` for the reply (and, when the deep pipeline
  ran, the validated ImpactReport + its Adaptive Cards).
* ``POST /action/send_handoff`` - confirm-before-send. The bot may call this
  ONLY from an explicit user tap; the server re-checks the artifact shape,
  audit-logs, and returns the exact text to post. The server never sends
  anything itself.
* ``POST /action/remediate`` - the ONLY write path in the system. Re-runs the
  offer gate server-side (never trusts the card payload), enforces tap vs
  typed confirmation, executes ONE record PATCH against Dataverse under the
  **delegated user identity**, and audit-logs the full chain. The read-only
  service identity is never used for writes.

Identity note: locally the delegated credential is the signed-in user (same
browser-cached sign-in as ``cli ask --as-user``). Hosted, the surface forwards
the Teams user's token and the bridge exchanges it On-Behalf-Of; the gate and
audit shapes are identical either way.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import proposals
from .audit import audit_log
from .identity import (
    TokenVerificationError,
    token_identity,
    token_owner,
    verify_token,
)
from .proposals import ProposalError
from .report.artifacts import RemediationProposal, validate_artifact_payload
from .report.card import artifact_card, editable_draft_card
from .report.render import artifact_offer, report_summary_markdown
from .report.schema import ImpactReport
from .agents.instructions import ACK_INSTRUCTIONS, UNIFIED_INSTRUCTIONS
from .settings import get_settings

app = FastAPI(title="ImpactIQ bridge", version="0.8.0")


# ── Bridge auth guard ─────────────────────────────────────────────────────
# The surface (surface/) is the only legitimate caller. When IMPACTIQ_BRIDGE_KEY
# is set (production), every request must present it in the X-ImpactIQ-Key
# header; the liveness endpoint and Azure's warm-up probe ("/") stay open so
# the platform health checks still pass. When the var is unset (local dev / F5),
# the guard is a no-op - local behaviour is unchanged. This is defence in depth
# alongside network access restrictions, not a replacement for them.
#
# On top of the shared key, each request is signed (HMAC over timestamp + nonce
# + path + body hash) so a captured request cannot be replayed or its body
# tampered with by anyone who does not hold the key. Signing is enforced
# whenever the key is set; set IMPACTIQ_REQUIRE_SIGNED_REQUESTS=0 only to roll
# out a bridge ahead of the matching surface build.
_BRIDGE_KEY = os.getenv("IMPACTIQ_BRIDGE_KEY", "").strip()
_OPEN_PATHS = frozenset({"/", "/health"})
_REQUIRE_SIGNED = os.getenv("IMPACTIQ_REQUIRE_SIGNED_REQUESTS", "1").strip() != "0"
_SIGN_WINDOW_S = 300  # accept a request timestamp within +/- 5 minutes

# Recently-seen request nonces, so a signed request is single-use inside its
# time window (defeats replay). Bounded FIFO; entries also age out.
_SEEN_NONCES: dict[str, float] = {}
_NONCE_MAX = 8192
_NONCE_LOCK = threading.Lock()


def _nonce_is_fresh(nonce: str) -> bool:
    now = time.time()
    with _NONCE_LOCK:
        for n in [n for n, t in _SEEN_NONCES.items() if now - t > _SIGN_WINDOW_S * 2]:
            _SEEN_NONCES.pop(n, None)
        if nonce in _SEEN_NONCES:
            return False
        _SEEN_NONCES[nonce] = now
        while len(_SEEN_NONCES) > _NONCE_MAX:
            _SEEN_NONCES.pop(next(iter(_SEEN_NONCES)), None)
    return True


def _verify_signature(path: str, body: bytes, headers: dict[str, str]) -> bool:
    """True when the request carries a valid, fresh, in-window HMAC signature."""
    ts = headers.get("x-impactiq-timestamp", "")
    nonce = headers.get("x-impactiq-nonce", "")
    sig = headers.get("x-impactiq-signature", "")
    if not (ts and nonce and sig):
        return False
    try:
        if abs(time.time() - float(ts)) > _SIGN_WINDOW_S:
            return False
    except ValueError:
        return False
    body_hash = hashlib.sha256(body).hexdigest()
    msg = f"{ts}\n{nonce}\n{path}\n{body_hash}"
    expected = hmac.new(_BRIDGE_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    return _nonce_is_fresh(nonce)


async def _send_json(send, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({"type": "http.response.body", "body": body})


async def _drain_body(receive) -> bytes:
    chunks: list[bytes] = []
    more = True
    while more:
        message = await receive()
        if message["type"] == "http.request":
            chunks.append(message.get("body", b""))
            more = message.get("more_body", False)
        else:  # http.disconnect
            break
    return b"".join(chunks)


def _replay_receive(body: bytes):
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


class _BridgeAuthMiddleware:
    """Pure-ASGI gate: shared-key check, replay-resistant request signature, and
    one-time user-token verification, before any route runs. Implemented at the
    ASGI layer so the request body can be buffered for signature verification
    and then replayed intact to the handler."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path in _OPEN_PATHS:
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        if _BRIDGE_KEY:
            # Constant-time compare - a plain != leaks key prefixes via timing.
            if not hmac.compare_digest(headers.get("x-impactiq-key", ""), _BRIDGE_KEY):
                return await _send_json(send, 401, {"detail": "unauthorized"})
            if _REQUIRE_SIGNED:
                body = await _drain_body(receive)
                if not _verify_signature(path, body, headers):
                    return await _send_json(
                        send, 401, {"detail": "request signature invalid or expired"}
                    )
                receive = _replay_receive(body)
        # A forwarded user token is verified once, for every path: a spoofed or
        # expired assertion is rejected before any handler trusts its claims for
        # ownership or audit attribution. Absent token = no-op.
        user_token = headers.get("x-impactiq-user-token")
        if user_token:
            try:
                _verify_user_token(user_token)
            except HTTPException as exc:
                return await _send_json(send, exc.status_code, {"detail": exc.detail})
        return await self.app(scope, receive, send)


app.add_middleware(_BridgeAuthMiddleware)


# ── Delegated identity (OBO) ──────────────────────────────────────────────
# The surface forwards each Teams user's token as X-ImpactIQ-User-Token; the
# bridge exchanges it On-Behalf-Of (runtime.obo_credential) for every content
# read / Work IQ call / bounded write. When that header is ABSENT and we're
# running hosted, there is no browser/keyring to fall back to - so we ask the
# user to sign in rather than crash. Locally (not hosted) the absent-token path
# still falls back to the browser sign-in, so `cli ask --as-user` / F5 dev are
# unchanged. App Service always sets WEBSITE_INSTANCE_ID.
_HOSTED = bool(os.getenv("WEBSITE_INSTANCE_ID"))

# Fail-fast, not fail-open: a hosted bridge without its shared key would accept
# requests from ANY caller that can reach it. Refuse to start instead. (Local
# dev / F5 keeps the no-key no-op guard - nothing is reachable off-machine.)
if _HOSTED and not _BRIDGE_KEY:
    raise RuntimeError(
        "IMPACTIQ_BRIDGE_KEY must be set on a hosted bridge - refusing to start "
        "with the auth guard disabled. Set the same value on the surface app."
    )

_SIGNIN_TEXT = (
    "I need you to sign in before I can look at your records, Work IQ signals, "
    "or apply a fix - please tap **Sign in** and ask again."
)


def _needs_signin(user_assertion: str | None) -> bool:
    """True when an as-user path was requested with no Teams token while hosted."""
    return _HOSTED and not user_assertion


def _verify_user_token(user_assertion: str | None) -> None:
    """Reject a forwarded user token that is not a genuine, unexpired Entra
    token for the configured tenant BEFORE its claims are trusted for ownership
    or audit attribution.

    No token (local CLI / F5 development) or no configured tenant is a no-op -
    those paths carry no delegated identity to verify. A present token with a
    configured tenant must verify: the signature is checked against the tenant's
    published keys, along with issuer, audience, and expiry. A failure raises
    401 rather than letting a spoofed identity reach the owner-binding logic.
    """
    if not user_assertion:
        return
    settings = get_settings()
    tenant = settings.entra_tenant_id
    if not tenant:
        return
    try:
        verify_token(
            user_assertion,
            tenant_id=tenant,
            audiences=settings.expected_token_audiences(),
        )
    except TokenVerificationError as exc:
        raise HTTPException(
            status_code=401,
            detail=f"your sign-in could not be verified - please sign in again ({exc})",
        )


def _signin_result() -> dict:
    """The job-result shape the surface renders when sign-in is required."""
    return {"status": "needs_signin", "text": _SIGNIN_TEXT, "suggestions": []}


def _assist_result(turn) -> dict:
    """Shape an assist TurnResult for the surface. When the run paused on a
    gated mutating tool, hand back everything the surface needs to show an
    Approve/Deny card and later resume the SAME run via /agent/approve."""
    if turn.run_status == "pending_approval":
        return {
            "status": "pending_approval",
            "text": turn.raw_text or "",
            "pending_approvals": turn.pending_approvals,
            "resume_response_id": turn.resume_response_id,
            "agent_name": turn.agent_name,
            "agent_version": turn.agent_version,
        }
    return {"status": turn.run_status, "text": turn.raw_text or ""}


class AssistApproveRequest(BaseModel):
    agent_name: str
    agent_version: str | None = None
    response_id: str
    approvals: dict[str, bool]        # approval_request_id -> approve/deny
    pending: list[dict] = []          # echoed pending_approvals, for the audit detail
    user: str = "unknown"




# Suspended unified runs awaiting an approval decision: the engine-tool
# dispatch (and its open Dataverse client) must survive until the run is
# resumed, because the model may keep calling engine tools after the human
# approves. Keyed by resume_response_id; pruned oldest-first.
_PENDING_RUNS: dict[str, dict] = {}
_PENDING_RUNS_MAX = 8


def _stash_pending_run(
    response_id: str,
    dispatch: dict,
    client: Any,
    report_holder: dict | None = None,
    owner: tuple[str, str] | None = None,
) -> None:
    while len(_PENDING_RUNS) >= _PENDING_RUNS_MAX:
        # FIFO eviction (insertion order): drop the oldest entry. popitem()
        # would be LIFO, evicting the most-recently-suspended run (exactly the
        # one most likely still awaiting its approval) while stale entries
        # linger.
        oldest_id = next(iter(_PENDING_RUNS))
        _close_quietly(_PENDING_RUNS.pop(oldest_id).get("client"))
    _PENDING_RUNS[response_id] = {
        "dispatch": dispatch,
        "client": client,
        "report_holder": report_holder if report_holder is not None else {},
        # Owner binding: only the (tenant, object id) this run was suspended
        # for may approve/deny it. None = local single-user dev (no token).
        "owner": owner,
    }


def _audit_identity(user_assertion: str | None, display_name: str | None) -> dict:
    """Audit attribution from the validated token's claims, never from a
    client-supplied display name (names are neither unique nor immutable).
    The display name is kept as a convenience label only."""
    ident = token_identity(user_assertion)
    return {
        "tenant_id": ident.get("tenant_id"),
        "object_id": ident.get("object_id"),
        "upn": ident.get("upn"),
        "display_name": display_name or ident.get("name") or "unknown",
    }


def _digest(text: str | None, keep: int = 120) -> dict:
    """Log a hash + excerpt of long free-text instead of the full body -
    the audit chain needs proof-of-content, not a copy of the content."""
    t = text or ""
    return {
        "sha256": hashlib.sha256(t.encode("utf-8")).hexdigest(),
        "length": len(t),
        "excerpt": t[:keep],
    }


def _register_remediation(
    artifact: dict,
    *,
    owner: tuple[str, str] | None,
    conversation: str | None,
    user_assertion: str | None,
) -> dict:
    """Store a remediation artifact server-side as the canonical, owner-bound,
    one-time proposal, and stamp its id into the dict the surface round-trips.
    For updates, the record's current ETag is captured now so execution can
    detect a record that changed after the user previewed it."""
    extra: dict = {}
    if artifact.get("operation") == "update" and artifact.get("record_id"):
        extra["etag"] = _capture_record_etag(
            get_settings(), artifact.get("record_table"), artifact.get("record_id"),
            user_assertion,
        )
    artifact = dict(artifact)
    artifact["proposal_id"] = proposals.register(
        "remediation", {k: v for k, v in artifact.items() if k != "proposal_id"},
        owner=owner, conversation=conversation, extra=extra, prefix="rem",
    )
    return artifact


# Artifact types that notify or draft to a person (Outlook draft, manager
# handoff, Teams intro). Their recipient and routing must be pinned to a
# server-stored proposal so the action executes against exactly what the owner
# previewed, not a client-mutated copy.
_NOTIFY_ARTIFACT_TYPES = frozenset(
    {"manager_handoff", "draft_teams_intro", "notification_draft"}
)


def _register_notify_artifact(
    artifact: dict,
    *,
    owner: tuple[str, str] | None,
    conversation: str | None,
) -> dict:
    """Store a notify/draft artifact as an owner-bound proposal and stamp its id
    into the dict the surface round-trips, so the send/draft endpoints can bind
    the recipient and routing back to this canonical copy."""
    artifact = dict(artifact)
    artifact["proposal_id"] = proposals.register(
        "notify", {k: v for k, v in artifact.items() if k != "proposal_id"},
        owner=owner, conversation=conversation, prefix="ntf",
    )
    return artifact


def _bound_notify_artifact(
    client_artifact: dict,
    *,
    user_assertion: str | None,
    consume: bool,
) -> dict | None:
    """Resolve the canonical, owner-bound notify/draft artifact for an action.

    When the client artifact carries a ``proposal_id``, validate it (owner-bound)
    and return the SERVER-stored copy, so the recipient and routing are exactly
    what was proposed. ``consume=True`` spends the proposal (one-time, for an
    irreversible send); ``consume=False`` leaves it (a repeatable, reversible
    draft). When there is no proposal id: refuse on a hosted deployment (a
    server proposal is required there), and fall back to the client artifact
    only in local single-user development.
    """
    proposal_id = (client_artifact or {}).get("proposal_id")
    owner = token_owner(user_assertion)
    if proposal_id:
        try:
            fn = proposals.consume if consume else proposals.verify
            entry = fn(proposal_id, "notify", owner=owner)
        except ProposalError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail)
        return entry["artifact"]
    if _HOSTED:
        raise HTTPException(
            status_code=403,
            detail="this action requires a server-issued proposal - re-ask so the agent can prepare it",
        )
    return None


def _capture_record_etag(
    settings, table: str | None, record_id: str | None, user_assertion: str | None
) -> str | None:
    """Best-effort @odata.etag read for the record a proposal will update."""
    if not table or not record_id:
        return None
    try:
        base = (settings.dataverse_url or "").rstrip("/")
        token = _dataverse_user_token(settings, user_assertion)
        entity_set = _entity_set_name(base, token, table)
        r = httpx.get(
            f"{base}/api/data/v9.2/{entity_set}({record_id})",
            params={"$select": "modifiedon"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=30,
        )
        if r.status_code == 200:
            return r.json().get("@odata.etag")
    except Exception:  # noqa: BLE001 - capture is best-effort; execution re-fetches
        pass
    return None


def _attach_report_cards(
    result: dict,
    report_holder: dict,
    *,
    owner: tuple[str, str] | None = None,
    conversation: str | None = None,
    user_assertion: str | None = None,
) -> dict:
    """If the deep pipeline ran during the turn, attach its validated report
    and the actionable cards (offer / bounded-write fix preview / editable
    draft) so the surface can keep the exact same confirm-gated flows. If the agent
    presented records, attach their cards (read-only, deep-link to Power Apps
    for editing) for the bot's carousel.

    Any remediation artifact attached here is FIRST registered server-side as
    an owner-bound one-time proposal; /action/remediate executes only against
    that stored canonical copy, never the card payload."""
    report = report_holder.get("report")
    if report is not None:
        report_dict = report.model_dump()
        art = report_dict.get("generated_artifact")
        if isinstance(art, dict) and art.get("artifact_type") == "remediation_proposal":
            report_dict["generated_artifact"] = _register_remediation(
                art, owner=owner, conversation=conversation, user_assertion=user_assertion
            )
        elif isinstance(art, dict) and art.get("artifact_type") in _NOTIFY_ARTIFACT_TYPES:
            report_dict["generated_artifact"] = _register_notify_artifact(
                art, owner=owner, conversation=conversation
            )
        result["report"] = report_dict
        result["offer"] = artifact_offer(report)
        result["artifact_card"] = artifact_card(report)
        result["draft_card"] = editable_draft_card(report)
    records_payload = report_holder.get("records_payload")
    if records_payload:
        from .report.card import record_cards

        settings = get_settings()
        result["record_cards"] = record_cards(
            records_payload,
            settings.dataverse_url or "",
            settings.powerapps_app_id,
        )
        result["records_title"] = records_payload.get("title") or ""
        print(f"(record cards attached: {len(result['record_cards'])})", flush=True)
    fix_proposal = report_holder.get("sandbox_fix")
    if fix_proposal:
        from .report.card import sandbox_fix_card

        result["sandbox_fix_card"] = sandbox_fix_card(
            fix_proposal["fix_id"],
            fix_proposal["title"],
            fix_proposal["rationale"],
            fix_proposal["ops"],
        )
        print(f"(sandbox fix proposed: {fix_proposal['fix_id']})", flush=True)
    unified_artifact = report_holder.get("unified_artifact")
    if unified_artifact:
        from .report.card import standalone_artifact_card

        unified_artifact = _register_remediation(
            unified_artifact, owner=owner, conversation=conversation,
            user_assertion=user_assertion,
        )
        # Its OWN key (not artifact_card) so the surface can tell a BARE
        # bounded-write proposal (the card's buttons ARE the next step →
        # suppress chips) from a deep-pipeline report's optional offer (chips
        # still wanted).
        result["record_fix_card"] = standalone_artifact_card(unified_artifact)
        # The surface's confirm tap reads state.report.generated_artifact -
        # a deep-pipeline report (if any) wins; otherwise supply the minimal
        # shape so the unified-born proposal is confirmable.
        result.setdefault("report", {"generated_artifact": unified_artifact})
        print("(unified record-fix proposed - preview card attached)", flush=True)
    resubmits = report_holder.get("resubmit_runs")
    if resubmits:
        from .report.card import resubmit_card

        result["resubmit_cards"] = [
            resubmit_card(r["resubmit_id"], r["flow_name"], r["run_name"], r.get("started"))
            for r in resubmits
        ]
        print(f"(resubmit proposed: {[r['resubmit_id'] for r in resubmits]})", flush=True)
    return result


def _sources_footer(turn: Any, report_holder: dict) -> str:
    """Attach the clickable numbered SOURCE references for KB/SOP-grounded
    answers.

    When governance is routed through the deep pipeline, the KB's citations land
    on the *report* (merged from the knowledge specialist's runtime citations),
    NOT on the unified agent's synthesized reply text. Re-attach them as a
    numbered, clickable Sources list (the number links to the source). Pulls
    from the unified turn's own citations too, for the DIRECT path where it
    queried the KB itself."""
    seen: set[str] = set()
    cites: list[tuple[str, str]] = []  # (title, url)

    def _add(url: Any, title: Any) -> None:
        u = str(url or "").strip()
        if not u or u in seen:
            return
        seen.add(u)
        cites.append((str(title or u).strip(), u))

    for c in getattr(turn, "citations", None) or []:
        _add(c.get("url"), c.get("title"))
    report = report_holder.get("report")
    if report is not None:
        for c in getattr(report, "citations", []) or []:
            _add(getattr(c, "url", None), getattr(c, "title", None))

    if not cites:
        return ""
    lines = ["", "**Sources**"]
    for i, (title, url) in enumerate(cites, 1):
        lines.append(f"[{i}]({url}) {title}")
    return "\n".join(lines)


def _affected_people_footer(report_holder: dict) -> str:
    """Surface the human fallout in the reply by CODE - who the failure affects /
    who is waiting - so the LLM synthesis can't drop them. The list is already
    role-tagged ('(customer)', '(owner)'); the agent's own text can still offer
    the per-person actions, but the people themselves cannot silently vanish
    from the reply."""
    report = report_holder.get("report")
    people = [str(p).strip() for p in (getattr(report, "affected_people", None) or []) if str(p).strip()]
    if not people:
        return ""
    return "**People affected:** " + "; ".join(people)


def _reasoning_footer(report_holder: dict) -> str:
    """Surface the deep pipeline's REASONING into the reply so it's auditable -
    the adjudicator's `reconciliation` (what was checked, what agreed or
    conflicted, what it means) plus the evidence facts. Appended VERBATIM (not
    paraphrased) when the deep pipeline ran, so the user can audit HOW the
    conclusion was reached rather than only seeing the conclusion. Empty when no
    deep report ran."""
    report = report_holder.get("report")
    if report is None:
        return ""
    parts: list[str] = []
    reconciliation = (getattr(report, "reconciliation", "") or "").strip()
    if reconciliation:
        parts.append("**Reasoning**\n" + reconciliation)
    facts = [
        str(getattr(e, "detail", "")).strip()
        for e in (getattr(report, "evidence", None) or [])
        if str(getattr(e, "detail", "")).strip()
    ][:8]
    if facts:
        parts.append("**What I checked:** " + " · ".join(facts))
    return "\n\n".join(parts)


# Proposed sandbox fixes and failed-run resubmits live in the owner-bound
# one-time proposal store (proposals.py): each is registered to the requesting
# user's (tenant, object id) at proposal time and can only be consumed - once,
# atomically, after the authorization check - by that same identity.


def _stash_pending_fix(
    ops: list, title: str, rationale: str, owner: tuple[str, str] | None = None
) -> str:
    return proposals.register(
        "sandbox_fix",
        {"ops": ops, "title": title, "rationale": rationale},
        owner=owner,
        prefix="fix",
    )


def _stash_pending_resubmit(payload: dict, owner: tuple[str, str] | None = None) -> str:
    return proposals.register("resubmit_run", payload, owner=owner, prefix="rerun")


def _resubmit_tool_specs(
    settings, report_holder: dict | None = None, user_assertion: str | None = None
) -> list:
    """`resubmit_flow_run` - PROPOSE re-running ONE failed run of a LIVE
    flow (the closing step after a sandbox fix reaches live via export).
    The tool never resubmits: it resolves the flow + failed run with the
    read-only service identity, stashes the proposal and the user gets a
    Resubmit card; /action/resubmit_run executes behind their tap under the
    DELEGATED user identity (the platform enforces the user's own flow
    permissions)."""
    holder = report_holder if report_holder is not None else {}
    from .agents.tools import EngineToolSpec

    def _impl(args: dict) -> str:
        flow_name = str(args.get("flow") or "").strip()
        if not flow_name:
            return json.dumps({"error": "flow (live display name) is required"})
        run_name = str(args.get("run") or "").strip()
        from .dataverse_client import DataverseClient

        try:
            with DataverseClient(settings) as dv:
                safe = flow_name.replace("'", "''")
                rows = dv.get(
                    "workflows",
                    {"$select": "workflowid,name",
                     "$filter": f"name eq '{safe}' and category eq 5"},
                ).get("value", [])
                if not rows:
                    rows = dv.get(
                        "workflows",
                        {"$select": "workflowid,name",
                         "$filter": f"contains(name, '{safe}') and category eq 5"},
                    ).get("value", [])
                if len(rows) != 1:
                    names = sorted(r["name"] for r in rows)[:8]
                    return json.dumps(
                        {"error": f"could not resolve ONE live flow for "
                                  f"{flow_name!r}; candidates: {names}"}
                    )
                wf = rows[0]
                filt = f"_workflow_value eq {wf['workflowid']} and status eq 'Failed'"
                if run_name:
                    # Escape single quotes so a run name can't break out of the
                    # OData string literal (same guard as the flow name above).
                    safe_run = run_name.replace("'", "''")
                    filt += f" and name eq '{safe_run}'"
                runs = dv.get(
                    "flowruns",
                    {"$select": "name,status,starttime,resourceid,errorcode",
                     "$filter": filt, "$orderby": "starttime desc", "$top": "5"},
                ).get("value", [])
                if not runs:
                    return json.dumps(
                        {"error": f"no failed runs found for live flow {wf['name']!r}"
                                  + (f" matching run {run_name!r}" if run_name else "")}
                    )
                org = dv.get(
                    "RetrieveCurrentOrganization(AccessType="
                    "Microsoft.Dynamics.CRM.EndpointAccessType'Default')"
                )
                env_id = (org.get("Detail") or {}).get("EnvironmentId")
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": str(exc)})
        if not env_id:
            return json.dumps({"error": "could not resolve the live EnvironmentId"})
        run = runs[0]
        proposal = {
            "flow_name": wf["name"],
            "run_name": run["name"],
            "started": run.get("starttime"),
            "env_id": env_id,
            "flow_resource": run["resourceid"],
        }
        resubmit_id = _stash_pending_resubmit(proposal, owner=token_owner(user_assertion))
        holder.setdefault("resubmit_runs", []).append(
            {"resubmit_id": resubmit_id, **proposal}
        )
        audit_log(
            "flow_resubmit_proposed",
            {"resubmit_id": resubmit_id, "flow": wf["name"], "run": run["name"]},
        )
        return json.dumps(
            {
                "proposed": True,
                "resubmit_id": resubmit_id,
                "flow": wf["name"],
                "run": run["name"],
                "run_started": run.get("starttime"),
                "other_failed_runs": [
                    {"run": r["name"], "started": r.get("starttime")} for r in runs[1:]
                ],
                "note": (
                    "NOT resubmitted yet - the user gets a Resubmit card for "
                    "this one run; it executes only after their tap. One run "
                    "per call: call again for each additional failed run. "
                    "Resubmit re-runs the trigger against the CURRENT live "
                    "definition - only propose it once the fix has reached "
                    "live (or the failure cause is otherwise resolved)."
                ),
            }
        )

    spec = EngineToolSpec(
        name="resubmit_flow_run",
        description=(
            "PROPOSE re-running ONE failed run of a LIVE cloud flow - the "
            "closing step of a remediation, used AFTER the underlying cause "
            "is fixed in live (e.g. the repaired flow was exported from the "
            "sandbox). Nothing is resubmitted by this call: the user gets a "
            "per-run Resubmit card and the rerun happens only after their "
            "tap, under their own identity. If a fix has NOT reached live "
            "yet, say so instead of proposing - a resubmit would just fail "
            "again. Default is the most recent failed run; pass run to pick "
            "a specific one from run history."
        ),
        parameters={
            "type": "object",
            "properties": {
                "flow": {
                    "type": "string",
                    "description": "The LIVE flow's display name.",
                },
                "run": {
                    "type": "string",
                    "description": "Optional specific run name from run history.",
                },
            },
            "required": ["flow"],
        },
        impl=_impl,
    )
    return [spec]


def _record_fix_tool_specs(report_holder: dict | None = None) -> list:
    """`propose_record_fix` - the unified agent's direct path to a per-record
    bounded-write proposal (investigation and action proposals belong to the
    unified layer; the deep pipeline is for adjudicated verdicts). The tool runs
    the SAME deterministic offer gate as the pipeline's adjudicator
    (`validate_artifact_payload`) and stashes the validated artifact; the user
    gets the preview-and-confirm card and the write still runs only behind
    /action/remediate's tap/typed re-check."""
    holder = report_holder if report_holder is not None else {}
    from .agents.tools import EngineToolSpec

    def _impl(args: dict) -> str:
        from .report.artifacts import validate_artifact_payload

        payload = args.get("artifact") or {}
        # Document-grounded remediation is intentionally DORMANT on this live
        # surface. The document-grounded path (schema fields, gate discipline,
        # source-span card, tests) exists end-to-end, but the unified agent is
        # deliberately steered to evidence_source="diagnosis" only (see this
        # tool's description + UNIFIED_INSTRUCTIONS) and never sets the flag below.
        # Why it stays unwired: it's injection-suspect, and wiring it on
        # safely requires deciding "did the user explicitly reference a document
        # THIS turn?" SERVER-SIDE - it must NOT be a value the model asserts
        # about itself - plus an extraction-confidence floor. Until that
        # server-side determination exists the capability stays ready but off
        # here. `user_referenced_document` is still forwarded so the gate stays
        # honest if a doc-grounded payload ever arrives (e.g. from the CLI
        # single-agent path).
        artifact, refusal = validate_artifact_payload(
            "DIAGNOSE",
            payload,
            user_referenced_document=bool(args.get("user_referenced_document")),
        )
        if refusal is not None:
            refusal = dict(refusal)
            refusal["instruction"] = (
                "fix the listed fields and call propose_record_fix again "
                "(or follow use_instead)"
            )
            return json.dumps(refusal)
        holder["unified_artifact"] = artifact
        audit_log(
            "remediation_proposed",
            {"surface": "unified", "operation": artifact.get("operation"),
             "record_table": artifact.get("record_table")},
        )
        return json.dumps(
            {
                "validated": True,
                "proposed": True,
                "note": (
                    "NOT applied - the user now sees the preview-and-confirm "
                    "card for this exact change (update: tap; create: typed "
                    "confirmation). Summarise the change in your reply and "
                    "point them at the card. Never claim it was applied."
                ),
            }
        )

    spec = EngineToolSpec(
        name="propose_record_fix",
        description=(
            "PROPOSE one per-record Dataverse data fix from YOUR OWN "
            "completed diagnosis. Nothing is written by this call: "
            "the user gets a preview-and-confirm card and the write runs "
            "only after their confirmation, under their identity. Two "
            "operations: 'update' corrects fields on ONE existing record "
            "(record_id required); 'create' replays the ONE row a failed "
            "automation never wrote (record_id EMPTY, every column value "
            "taken from the failure evidence - trigger outputs, action "
            "parameters - never invented; always typed-confirmed). "
            "DIAGNOSE-grounded only, diagnosis_confidence >= 0.8, business "
            "data only (configuration tables are refused). Artifact shape: "
            '{"artifact_type":"remediation_proposal","operation":"update"|'
            '"create","record_table":"<logical>","record_id":"<guid or '
            'empty>","record_name":"<label>","changes":[{"column":"<logical '
            'or <col>@odata.bind>","current_value":<as-is or null>,'
            '"proposed_value":<value>}],"evidence_source":"diagnosis",'
            '"diagnosis_summary":"<why>","diagnosis_confidence":0.0-1.0,'
            '"downstream_preview":["<what fires on this write>"]}. '
            "For MANY records describe a backfill instead - never loop this."
        ),
        parameters={
            "type": "object",
            "properties": {
                "artifact": {
                    "type": "object",
                    "description": "The remediation_proposal payload (shape above).",
                },
                "user_referenced_document": {
                    "type": "boolean",
                    "description": (
                        "True ONLY if the user explicitly attached/named a "
                        "document in the CURRENT turn."
                    ),
                },
            },
            "required": ["artifact"],
        },
        impl=_impl,
    )
    return [spec]


def _builder_access_note(settings, user_assertion: str | None = None) -> str:
    """A context line telling the agent whether THIS user can use the Builder,
    so its sandbox-fix offer is honest. Empty when no sandbox is configured
    (the Builder tools aren't attached at all). Best-effort: on a permission-
    check error, stay silent rather than mislead either way."""
    if not getattr(settings, "build_dataverse_url", None):
        return ""
    try:
        from .builder.gate import has_builder_permission

        held = has_builder_permission(settings, user_assertion)
    except Exception:  # noqa: BLE001 - never block the turn on a role check
        return ""
    if held:
        return (
            "\n\n[BUILDER ACCESS: this user HOLDS the ImpactIQ Builder role - "
            "you may offer and prepare a sandbox fix for them.]\n"
        )
    return (
        "\n\n[BUILDER ACCESS: this user does NOT hold the ImpactIQ Builder "
        "role. Do NOT promise to build/apply a sandbox fix yourself. You may "
        "still explain WHAT the fix would be and that it needs a Builder-role "
        "holder (or an admin to grant the role); frame it as a recommendation, "
        "not an action you'll take.]\n"
    )


def _builder_tool_specs(settings, report_holder: dict | None = None, user_assertion: str | None = None) -> list:
    """The sandbox FIX tools. Empty when no sandbox is configured. Every call
    re-checks the permission wall (ImpactIQ Builder role, delegated identity,
    5-min cache) - a refusal comes back to the model as an error it must relay,
    never bypass.

    ``sandbox_fix`` PROPOSES: the ops are stashed server-side and the user
    gets an Apply card; the write runs only behind /action/sandbox_fix with
    the confirmed tap.
    """
    if not getattr(settings, "build_dataverse_url", None):
        return []
    holder = report_holder if report_holder is not None else {}
    from .agents.tools import EngineToolSpec

    def _gate() -> str | None:
        try:
            from .builder.gate import assert_builder_permission

            assert_builder_permission(settings, user_assertion)
            return None
        except Exception as exc:  # noqa: BLE001 - surface refusals verbatim
            return str(exc)

    solution = (settings.impactiq_build_solution or "").strip()

    def _sandbox_inspect_impl(args: dict) -> str:
        denied = _gate()
        if denied:
            return json.dumps({"error": denied})
        kind = str(args.get("kind") or "").strip()
        name = str(args.get("name") or "").strip()
        if kind not in ("flow", "table") or not name:
            return json.dumps({"error": "kind must be 'flow' or 'table' and name is required"})
        from .builder.executor import (
            SandboxClient,
            child_flow_references,
            failed_run_details,
            locate_flow,
            recent_flow_runs,
            table_schema,
        )

        try:
            with SandboxClient(settings) as client:
                if kind == "flow":
                    row = locate_flow(client, solution, name)
                    out = {
                        "kind": "flow",
                        "name": row["name"],
                        "workflowid": row["workflowid"],
                        "state": "on" if row["statecode"] == 1 else "off",
                        "recent_runs": recent_flow_runs(client, row["workflowid"]),
                        "clientdata": row.get("clientdata"),
                    }
                    # Child-flow drill-down seeds: resolve each 'Run a Child
                    # Flow' reference to a flow name so the model can repeat
                    # the protocol on the child.
                    children = child_flow_references(
                        json.loads(row.get("clientdata") or "{}")
                    )
                    for child in children:
                        ref = child.get("workflow_reference")
                        if not ref:
                            continue
                        # Reference comes from the parent flow's clientdata; escape
                        # it before it enters the OData string literal.
                        safe_ref = str(ref).replace("'", "''")
                        for field in ("workflowidunique", "workflowid", "resourceid"):
                            try:
                                hits = client.get(
                                    "workflows",
                                    {
                                        "$select": "name",
                                        "$filter": f"{field} eq '{safe_ref}'"
                                        if field == "resourceid"
                                        else f"{field} eq {safe_ref}",
                                    },
                                ).get("value", [])
                                if hits:
                                    child["flow_name"] = hits[0]["name"]
                                    break
                            except Exception:  # noqa: BLE001 - resolution degrades
                                continue
                    if children:
                        out["child_flows"] = children
                    try:
                        # Maker-grade forensics: failing action + the platform's
                        # actual error body + the inputs the action sent.
                        out["failed_run_details"] = failed_run_details(
                            client, settings, row["workflowid"],
                            user_assertion=user_assertion,
                        )
                    except Exception as exc:  # noqa: BLE001 - forensics degrade
                        out["failed_run_details"] = f"(unavailable: {exc})"
                    return json.dumps(out)
                # kind == "table": full column semantics - the grounding a
                # row-write fix needs (autonumber, lookup bind shapes, required).
                return json.dumps({"kind": "table", **table_schema(client, name)})
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": str(exc)})

    def _sandbox_fix_impl(args: dict) -> str:
        denied = _gate()
        if denied:
            return json.dumps({"error": denied})
        ops = args.get("ops") or []
        if not isinstance(ops, list) or not ops:
            return json.dumps({"error": "ops must be a non-empty array of fix operations"})
        title = str(args.get("title") or "Sandbox fix").strip()
        rationale = str(args.get("rationale") or "").strip()
        if not rationale:
            return json.dumps(
                {
                    "error": (
                        "rationale is required: state why the component exists "
                        "(grounded in the SOPs/workplace context you checked, or "
                        "in the definition itself) and what the fix changes."
                    )
                }
            )
        fix_id = _stash_pending_fix(ops, title, rationale, owner=token_owner(user_assertion))
        holder["sandbox_fix"] = {
            "fix_id": fix_id,
            "title": title,
            "rationale": rationale,
            "ops": ops,
        }
        audit_log("builder_fix_proposed", {"fix_id": fix_id, "title": title, "ops": ops})
        return json.dumps(
            {
                "proposed": True,
                "fix_id": fix_id,
                "note": (
                    "NOT applied yet - the user is being shown an Apply card "
                    "for this exact fix. In your reply, explain what the "
                    "component does, why, what's wrong, and what the fix will "
                    "change; tell them to tap Apply to proceed. Never claim "
                    "the fix is done."
                ),
            }
        )

    inspect_spec = EngineToolSpec(
        name="sandbox_inspect",
        description=(
            "Read ONE component in the dedicated SANDBOX environment (never "
            "the live one). kind=flow (by display name): on/off state, recent "
            "runs, the full definition clientdata, child_flows (any 'Run a "
            "Child Flow' actions, resolved to names - inspect those too for "
            "the full picture), AND failed_run_details - maker-grade "
            "forensics: the exact action that failed, the platform's real "
            "error response, the input values the action sent, plus the "
            "trigger's raw outputs and every step's raw inputs/outputs so a "
            "bad value can be traced to the step that produced it. "
            "kind=table (logical OR entity-set name, e.g. the "
            "entityName from a flow action): the table's column semantics - "
            "which columns are AUTONUMBER (platform-generated, never set), "
            "lookup targets with the exact '<entityset>(<id>)' bind shape, "
            "required levels. ALWAYS inspect the target table before "
            "proposing a fix that sets row values. Role-gated: only users "
            "holding the ImpactIQ Builder role."
        ),
        parameters={
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["flow", "table"]},
                "name": {
                    "type": "string",
                    "description": (
                        "Flow display name, or table logical/entity-set name."
                    ),
                },
            },
            "required": ["kind", "name"],
        },
        impl=_sandbox_inspect_impl,
    )
    fix_spec = EngineToolSpec(
        name="sandbox_fix",
        description=(
            "PROPOSE configuration fixes to EXISTING components in the "
            "dedicated SANDBOX environment - never the live environment. "
            "Nothing is applied by this call: the user is shown an Apply "
            "card for the exact ops, and the fix runs only after their "
            "confirmation tap. FIX-ONLY: cannot create or delete anything. "
            "Role-gated (ImpactIQ Builder). Each op is one of: "
            '{"op":"set_flow_state","flow":"<display name>","state":"on"|"off"} | '
            '{"op":"set_flow_action_parameter","flow":"<display name>",'
            '"action":"<action name from the definition>","parameter":'
            '"<e.g. item/new_name>","value":<any JSON value, e.g. a string '
            "or @-expression; null REMOVES the parameter - the right fix "
            "for autonumber columns>} - PREFER THIS for changing specific "
            "values: it edits the definition surgically and cannot corrupt "
            "it. Row writes are schema-guarded: lookup binds must be "
            "'<entityset>(<id>)' and autonumber columns are refused | "
            '{"op":"patch_flow_definition","flow":"<display name>","clientdata":'
            '"<the FULL repaired clientdata JSON as a string - ONLY for '
            "structural rewrites; start from sandbox_inspect's current "
            'clientdata and preserve its connectionReferences>"} | '
            '{"op":"alter_table","table":"<logical>","set":{"display_name"?, '
            '"description"?}} | '
            '{"op":"alter_column","table":"<logical>","column":"<logical>",'
            '"set":{"display_name"?, "description"?, "required_level": '
            '"None"|"Recommended"|"ApplicationRequired"}}. '
            "The rationale must state why the component exists (grounded in "
            "SOPs/workplace context when available, else in the definition) "
            "and what the fix changes."
        ),
        parameters={
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short human title for the fix (card heading).",
                },
                "rationale": {
                    "type": "string",
                    "description": (
                        "Why the component exists + what's wrong + what the fix "
                        "changes (2-4 sentences, grounded)."
                    ),
                },
                "ops": {
                    "type": "array",
                    "description": "The typed fix operations to run, in order.",
                    "items": {"type": "object"},
                },
            },
            "required": ["ops", "rationale"],
        },
        impl=_sandbox_fix_impl,
    )
    return [inspect_spec, fix_spec]


def _close_quietly(client: Any) -> None:
    try:
        if client is not None:
            client.close()
    except Exception:
        pass


# ── Live progress (so a long turn isn't a silent wait) ───────────────────────
# Without this, a long /agent turn is one generic heartbeat and then nothing
# until the answer lands, leaving the user in limbo. The bridge already KNOWS
# each milestone (it logs resolve/walk/deep_impact/etc.),
# so we record a short human line per milestone into a per-conversation buffer;
# the surface polls /progress every few seconds and posts new lines proactively
# (it can, because /agent is fire-and-forget with a proactive sender). Kept as a
# poll side-channel - NOT streamed inside the /agent response - so it can't
# recreate the fetch-timeout/abort failure mode that holding a long response
# open causes.
_PROGRESS: dict[str, list[str]] = {}
_PROGRESS_LOCK = threading.Lock()

# Tool wire-name → short, human, present-tense milestone. Unmapped tools emit
# NOTHING (silence beats noise) - only the meaningful steps surface. The deep
# pipeline pushes its own pre-phrased lines (per-specialist) directly.
_PROGRESS_PHRASES: dict[str, str] = {
    "resolve_anchor": "Locating the component…",
    "walk_anchor": "Mapping its dependencies…",
    "walk_required": "Mapping what it depends on…",
    "inspect_flow": "Inspecting the flow…",
    "find_failed_flows": "Checking recent run failures…",
    "flow_run_details": "Pulling the failure details…",
    "deep_impact_analysis": "Running the full impact analysis - dependencies, governance, and people affected…",
    "sandbox_inspect": "Preparing the fix in the sandbox…",
    "sandbox_fix": "Validating the fix…",
    "propose_record_fix": "Preparing a record fix…",
    "resubmit_flow_run": "Getting ready to resubmit the failed run…",
    "draft_reply": "Looking up the recipient and drafting the email…",
}


def _push_progress(conv: str, line: str) -> None:
    """Append a milestone line for a conversation (consecutive-dedup so a tool
    called twice doesn't repeat). No-op when there's no conversation key."""
    if not conv or not line:
        return
    with _PROGRESS_LOCK:
        buf = _PROGRESS.setdefault(conv, [])
        if buf and buf[-1] == line:
            return
        buf.append(line)


def _drain_progress(conv: str) -> list[str]:
    """Return and clear the pending lines for a conversation (each poll gets
    only what's NEW)."""
    with _PROGRESS_LOCK:
        out = _PROGRESS.get(conv, [])
        _PROGRESS[conv] = []
        return out


def _reset_progress(conv: str) -> None:
    if not conv:
        return
    with _PROGRESS_LOCK:
        _PROGRESS.pop(conv, None)


# ── Async job registry (production-robust long turns) ────────────────────────
# A full analysis can run minutes. Holding ONE HTTP request open that long
# trips the surface's fetch timeout AND host idle timeouts (e.g. Azure App
# Service's ~230s rule) - the request is killed and the finished report thrown
# away. Instead, /agent LAUNCHES a job and returns a job_id at once; the surface
# polls /agent/result. Every HTTP call stays sub-second, so no idle timeout can
# fire regardless of how long the work takes. /progress still streams the
# play-by-play during the wait.
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_JOBS_MAX = 64
# Hard concurrency bounds - an authenticated caller must not be able to spawn
# unbounded worker threads (thread exhaustion, runaway Foundry/model spend).
_MAX_RUNNING_JOBS = int(os.getenv("IMPACTIQ_MAX_RUNNING_JOBS", "8"))
_MAX_RUNNING_JOBS_PER_USER = int(os.getenv("IMPACTIQ_MAX_RUNNING_JOBS_PER_USER", "2"))


def _launch_job(work: Any, owner: tuple[str, str] | None = None) -> dict:
    """Run ``work() -> dict`` in a daemon thread; return ``{job_id, job_status}``
    immediately. Exceptions are captured onto the job (never crash the worker
    thread silently). Evicts oldest COMPLETED jobs past the cap - never a
    running one.

    Bounded: at most ``_MAX_RUNNING_JOBS`` concurrent workers overall and
    ``_MAX_RUNNING_JOBS_PER_USER`` per (tenant, object id) - excess requests
    are rejected with 429 instead of silently stacking threads. Each job is
    owner-stamped; /agent/result only returns it to that owner."""
    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        running = [v for v in _JOBS.values() if v.get("job_status") == "running"]
        if len(running) >= _MAX_RUNNING_JOBS:
            raise HTTPException(
                status_code=429,
                detail="the bridge is at its concurrent-analysis limit - try again shortly",
            )
        if owner is not None and (
            sum(1 for v in running if v.get("owner") == owner)
            >= _MAX_RUNNING_JOBS_PER_USER
        ):
            raise HTTPException(
                status_code=429,
                detail="you already have analyses running - wait for one to finish",
            )
        _JOBS[job_id] = {"job_status": "running", "started": time.time(), "owner": owner}
        while len(_JOBS) > _JOBS_MAX:
            victim = next(
                (k for k, v in _JOBS.items() if v.get("job_status") != "running"),
                None,
            )
            if victim is None:
                break
            _JOBS.pop(victim, None)

    def _run() -> None:
        try:
            result = work()
            with _JOBS_LOCK:
                if job_id in _JOBS:
                    _JOBS[job_id].update(job_status="done", result=result)
        except Exception as exc:  # noqa: BLE001 - surface the failure via the job
            print(f"[job {job_id[:8]}] failed: {type(exc).__name__}: {exc}", flush=True)
            with _JOBS_LOCK:
                if job_id in _JOBS:
                    _JOBS[job_id].update(job_status="error", detail=str(exc)[:500])

    threading.Thread(target=_run, name=f"job-{job_id[:8]}", daemon=True).start()
    return {"job_id": job_id, "job_status": "running"}


class JobRequest(BaseModel):
    job_id: str


@app.post("/agent/result")
def agent_result(
    req: JobRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Poll a launched job. ``job_status`` is running|done|error|unknown; when
    done the full result dict is under ``result`` (kept separate from the
    result's OWN ``status``, which is the agent run_status the surface reads).

    Owner-bound: a job launched for one (tenant, object id) is only visible to
    that identity - any other caller gets ``unknown`` (existence not leaked)."""
    with _JOBS_LOCK:
        job = dict(_JOBS.get(req.job_id) or {})
    if job.get("owner") is not None and job.get("owner") != token_owner(x_user_token):
        return {"job_status": "unknown"}
    js = job.get("job_status")
    if js == "done":
        return {"job_status": "done", "result": job.get("result")}
    if js == "error":
        return {"job_status": "error", "detail": job.get("detail")}
    if js == "running":
        return {"job_status": "running"}
    return {"job_status": "unknown"}


# ── Per-conversation memory (the container for prior deep analyses) ───────────
# The deep pipeline (orchestrator + 3 specialists + adjudicator) is the expensive
# part of a turn (~minutes). When the user follows up on the SAME subject in the
# same conversation - "propose a sandboxed update to that flow", "apply the fix",
# "notify the owner" - re-running the whole pipeline reproduces a verdict we
# already have. This holds the last deep report per conversation. A follow-up on
# the SAME subject REUSES it; a genuine PIVOT (a different component/idea)
# bypasses and overwrites it. Keyed by the short conversation id.
_CONV_MEMORY: dict[str, dict] = {}
_CONV_MEMORY_LOCK = threading.Lock()
_CONV_MEMORY_MAX = 64
_CONV_MEMORY_TTL_S = 1800  # 30 min - a stale verdict must not haunt a later turn


def _remember_analysis(conv: str, *, question: str, report: Any) -> None:
    """Store the latest deep report for a conversation (the container fill)."""
    if not conv:
        return
    try:
        anchor = (report.anchor.name if report.anchor else "") or ""
        intent = report.intent
    except Exception:  # noqa: BLE001
        anchor, intent = "", ""
    with _CONV_MEMORY_LOCK:
        _CONV_MEMORY[conv] = {
            "report": report, "question": question, "anchor": anchor,
            "intent": intent, "ts": time.time(),
        }
        while len(_CONV_MEMORY) > _CONV_MEMORY_MAX:
            _CONV_MEMORY.pop(next(iter(_CONV_MEMORY)), None)  # FIFO evict oldest


def _recall_analysis(conv: str) -> dict | None:
    """Return the conversation's prior analysis if present and not expired."""
    if not conv:
        return None
    with _CONV_MEMORY_LOCK:
        prior = _CONV_MEMORY.get(conv)
    if not prior:
        return None
    if time.time() - prior.get("ts", 0) > _CONV_MEMORY_TTL_S:
        with _CONV_MEMORY_LOCK:
            _CONV_MEMORY.pop(conv, None)
        return None
    return prior


# Trivial confirmations that are ALWAYS a continuation of the prior subject -
# no classifier hop needed.
_FOLLOW_THROUGH_CONFIRMS = frozenset(
    {
        "yes", "y", "ok", "okay", "sure", "go ahead", "do it", "proceed",
        "go for it", "apply", "apply it", "apply the fix", "yes please",
        "please do", "do that", "go on",
    }
)


def _same_subject(settings, prior: dict, new_request: str) -> bool:
    """REASON about whether ``new_request`` is the SAME subject as the prior deep
    analysis (so its verdict still applies) or a PIVOT to something new. Cheap
    deterministic fast-paths first, then a one-word classifier hop. On any doubt
    return False (treat as a pivot → re-run) - never serve a stale verdict for a
    possibly-different subject."""
    req = (new_request or "").strip().lower()
    if not req:
        return False
    if req.rstrip(".!") in _FOLLOW_THROUGH_CONFIRMS:
        return True
    prior_anchor = (prior.get("anchor") or "").strip().lower()
    # Strong same-subject signal: the request names the prior anchor outright.
    if len(prior_anchor) >= 4 and prior_anchor in req:
        return True
    model = settings.foundry_specialist_deployment or settings.foundry_model_deployment
    if not model:
        return False
    from .agents.loop import run_agent_turn
    from .agents.runtime import make_project_client

    instr = (
        "You decide whether a new user request is about the SAME subject as a "
        "prior impact analysis (so its verdict still applies) or a NEW/DIFFERENT "
        "subject. A follow-up ACTION on the prior subject - apply/propose the "
        "fix, do it in sandbox, notify the owner, create the missing record, "
        "resubmit the runs, draft the reply - is SAME. A request about a "
        "different component/table/flow/idea is NEW. Answer EXACTLY one word: "
        "SAME or NEW."
    )
    try:
        with make_project_client(settings) as pc:
            turn = run_agent_turn(
                pc, agent_name="ImpactIQ-pivot", model=model,
                instructions=instr, tools=[], dispatch={},
                user_input=(
                    f"Prior analysis subject: {prior.get('anchor') or '?'} - "
                    f"{(prior.get('question') or '')[:300]}\n\n"
                    f"New request:\n{new_request}"
                ),
                cache_version=True,  # stateless tool-less hop - reuse the version
            )
        return (turn.raw_text or "").strip().upper().startswith("SAME")
    except Exception:  # noqa: BLE001 - pivot check best-effort; doubt → re-run
        return False


def _wrap_dispatch_with_progress(dispatch: dict, conv: str) -> dict:
    """Wrap each local tool impl so dispatching it records a milestone line
    BEFORE it runs. Pure side-effect; the impl and its result are untouched."""
    if not conv:
        return dispatch

    def wrap(name: str, impl):
        phrase = _PROGRESS_PHRASES.get(name)

        def wrapped(args: dict):
            if phrase:
                _push_progress(conv, phrase)
            return impl(args)

        return wrapped

    return {name: wrap(name, impl) for name, impl in dispatch.items()}


def _unified_tools(
    settings, solution: str, progress: Any = None,
    *, conversation: str = "", reuse_prior: Any = None,
    user_assertion: str | None = None,
) -> tuple[list, dict, Any, dict]:
    """The UNION toolset: estate engine reads + Dataverse record reads + all
    Work IQ surfaces (gated mutations) + governance KB + the deep multi-agent
    pipeline as a callable tool. Returns
    (tools, dispatch, dataverse_client_to_close, report_holder). Estate
    prewarm degrades gracefully - Work IQ + KB still attach if the estate
    can't be built.

    ``reuse_prior`` (an ImpactReport): when set, ``deep_impact_analysis`` REUSES
    it instead of re-running the pipeline (the conversation already analysed this
    subject - see _recall_analysis/_same_subject). ``conversation`` keys where a
    freshly-run analysis is remembered for the next turn."""
    from .agents.single_agent import _build_mcp_kb_tool
    from .agents.tools import (
        TECHNICAL_TOOL_NAMES,
        EngineToolSpec,
        ToolContext,
        build_engine_tool_specs,
        select_engine_tools,
    )
    from .agents.workiq import build_workiq_tool
    from .dataverse_client import DataverseClient
    from .estate_cache import get_estate_cached
    from .graph import build_graph

    tools: list = []
    dispatch: dict = {}
    dv_client: Any = None
    try:
        dv_client = DataverseClient(settings)
        scope, fragment = get_estate_cached(dv_client, settings, solution)
        graph = build_graph(fragment)
        ctx = ToolContext(client=dv_client, scope=scope, graph=graph, user_assertion=user_assertion)
        specs = build_engine_tool_specs(ctx)
        tool_defs, dispatch = select_engine_tools(specs, TECHNICAL_TOOL_NAMES)
        tools.extend(tool_defs)
    except Exception as exc:  # noqa: BLE001 - degrade to Work IQ + KB
        print(f"(unified agent: estate engine unavailable - {exc})", flush=True)
        _close_quietly(dv_client)
        dv_client = None

    # The multi-agent pipeline (orchestrator → technical/knowledge/context
    # specialists → adjudicator) attached AS A TOOL: the front agent decides
    # when a question deserves the formal verdict - no pre-routing, no
    # scripted examples. The validated report lands in `report_holder` so the
    # endpoint can attach its actionable cards (bounded-write fix / notify) to
    # the response.
    report_holder: dict = {}

    def _deep_summary(report: ImpactReport, *, reused: bool) -> str:
        artifact_type = (report.generated_artifact or {}).get("artifact_type")
        note = (
            "The user is automatically shown an actionable card for the "
            "generated artifact (if any) - mention the next step naturally, "
            "do not repeat the full report verbatim. If `affected_people` "
            "is non-empty, name who is waiting and OFFER to draft a "
            "reply/follow-up to them (a draft, confirm-before-send)."
        )
        if reused:
            note = (
                "REUSED the impact analysis already completed for this subject "
                "earlier in this conversation - the verdict is unchanged. Act on "
                "it (propose the fix, draft the notification, etc.); do not "
                "re-analyse. " + note
            )
        return json.dumps(
            {
                "verdict": report.verdict,
                "recommendation": report.recommendation,
                "risk": report.risk.model_dump(),
                "confidence": report.confidence,
                "affected_teams": report.affected_teams,
                # The human fallout: anyone (customer, colleague, internal user)
                # awaiting the outcome the failure swallowed. If present, the
                # front agent must NAME them and offer to draft a reply/follow-up.
                "affected_people": report.affected_people,
                "interim_actions": report.interim_actions,
                "change_collisions": [
                    {
                        "component": c.component.name,
                        "sensitivity": c.sensitivity,
                        "who": c.who,
                    }
                    for c in report.change_collisions
                ],
                "evidence": [
                    {"kind": e.kind, "detail": e.detail} for e in report.evidence
                ],
                "generated_artifact_type": artifact_type,
                "reused": reused,
                "note": note,
            }
        )

    def _deep_impact_impl(args: dict) -> str:
        from .agents.multi_agent import ask_multi

        question = str(args.get("question") or "").strip()
        if not question:
            return json.dumps({"error": "question is required"})
        # CONTAINER: if the conversation already analysed this subject (decided in
        # the handler via _same_subject), REUSE that report instead of re-running
        # the whole pipeline. The container is non-empty ⇒ use it; empty ⇒ run.
        if reuse_prior is not None:
            report_holder["report"] = reuse_prior
            print("[deep] reusing prior conversation analysis (no pipeline re-run)", flush=True)
            return _deep_summary(reuse_prior, reused=True)
        evidence = str(args.get("evidence") or "").strip()
        if evidence:
            # The front agent investigates, the pipeline adjudicates - hand over
            # what was already found so the specialists verify instead of
            # re-deriving it.
            question = (
                f"{question}\n\nEvidence already gathered by the front "
                f"agent this turn (verify and build on it - do not re-derive "
                f"from scratch):\n{evidence}"
            )
        result = ask_multi(
            settings, solution_name=solution, question=question, as_user=True,
            progress=progress, user_assertion=user_assertion,
        )
        if result.report is None:
            return json.dumps(
                {"error": f"analysis did not produce a verdict (status {result.run_status})"}
            )
        try:
            report = ImpactReport.model_validate(result.report)
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"report failed validation: {exc}"})
        report_holder["report"] = report
        # Fill the container so the next same-subject turn reuses this verdict.
        _remember_analysis(conversation, question=question, report=report)
        return _deep_summary(report, reused=False)

    def _present_records_impl(args: dict) -> str:
        table = str(args.get("table") or "").strip()
        raw = args.get("records") or []
        # Only OBJECT rows can render as cards - a row passed as a string or
        # scalar would silently produce zero cards while the model tells the
        # user "see the card above". Reject so the model re-calls correctly.
        records = [r for r in raw if isinstance(r, dict)] if isinstance(raw, list) else []
        if not table or not records:
            return json.dumps(
                {
                    "error": (
                        "table and a non-empty records array are required, and "
                        "each record must be an OBJECT like {'id': '<guid>', "
                        "'<field label>': <value>, ...} - not a string."
                    )
                }
            )
        report_holder["records_payload"] = {
            "title": str(args.get("title") or ""),
            "table": table,
            "records": records[:10],
        }
        return json.dumps(
            {
                "ok": True,
                "shown": min(len(records), 10),
                "note": (
                    "The records render as interactive cards with an 'Open in "
                    "Power Apps' button (the real editable form). Keep your text "
                    "reply to ONE short lead-in line - do not repeat the data."
                ),
            }
        )

    def _draft_reply_impl(args: dict) -> str:
        """Draft an email to a person - an internal colleague OR an external
        contact - so the front agent never has to hand-roll the mechanics. A
        tightly-scoped helper is given the mail tool AND the read-only Work IQ
        directory, and resolves the recipient in order: a named INTERNAL
        colleague via the directory (a NEW draft to their directory address), an
        EXTERNAL person (not in the directory, e.g. a customer who emailed in)
        via their own inbound email (a reply to the address on it). The draft is
        inert (auto-approved - it lands in the user's Drafts); the front agent
        supplies the recipient and the composed (grounded) body."""
        recipient = str(args.get("recipient") or "").strip()
        body = str(args.get("body") or "").strip()
        if not recipient or not body:
            return json.dumps({"error": "recipient and body are required"})
        from .agents.loop import run_agent_turn
        from .agents.runtime import make_project_client
        from .agents.workiq import build_workiq_tool

        model = settings.heavy_model_deployment or settings.foundry_model_deployment
        mail = build_workiq_tool("mail", settings)  # SearchMessages + CreateDraftMessage are ungated
        if mail is None or not model:
            return json.dumps({"error": "mail is not configured; cannot draft an email"})
        draft_tools = [mail]
        directory = build_workiq_tool("user", settings)  # GetUserDetails / GetMultipleUsersDetails (read-only)
        if directory is not None:
            draft_tools.append(directory)
        instr = (
            "ONE task: create an email DRAFT to a person, then report the address "
            "you drafted to. Resolve the recipient the way a colleague would, in "
            "this order:\n"
            "1. If RECIPIENT is already an email address, draft straight to it.\n"
            "2. Otherwise look them up in the org DIRECTORY first "
            "(GetMultipleUsersDetails, or GetUserDetails, with the name). If a "
            "match is found, they are an INTERNAL colleague: CreateDraftMessage as "
            "a NEW email TO their directory address, with a short subject you "
            "compose from the body; body = the BODY below VERBATIM.\n"
            "3. If the directory has NO match, they are likely EXTERNAL: "
            "SearchMessages with a SHORT query on the name for their most recent "
            "INBOUND email, take the sender's address + subject, and "
            "CreateDraftMessage TO that address, subject 'Re: <their subject>', "
            "body = the BODY below VERBATIM.\n"
            "Never invent an address. If neither the directory nor any inbound "
            "email yields one, reply EXACTLY 'NO RECIPIENT FOUND' and create "
            "nothing. Otherwise reply with the address you drafted to.\n\n"
            f"RECIPIENT: {recipient}\nBODY:\n{body}"
        )
        try:
            with make_project_client(settings, as_user=True, user_assertion=user_assertion) as pc:
                turn = run_agent_turn(
                    pc,
                    agent_name="ImpactIQ-draft-email",
                    model=model,
                    instructions=instr,
                    tools=draft_tools,
                    dispatch={},
                    user_input="Create the email draft now.",
                )
        except Exception as exc:  # noqa: BLE001 - surface the failure, never crash the turn
            return json.dumps({"error": f"draft_reply failed: {type(exc).__name__}: {exc}"})
        out = (turn.raw_text or "").strip()
        print(f"[draft_reply] {recipient!r} -> tools={turn.tool_names} :: {out[:120]}", flush=True)
        return json.dumps({"result": out, "tools_used": turn.tool_names})

    present_spec = EngineToolSpec(
        name="present_records",
        description=(
            "Show retrieved Dataverse records to the user as interactive cards "
            "(swipeable in chat, each with an 'Open in Power Apps' button that "
            "opens the real, editable record form). Call this whenever the user "
            "asked to SEE records. Pass DATA ROWS you actually retrieved with "
            "read_query - NEVER column definitions or schema. Each row needs "
            "its primary-key GUID as 'id' (the Open button is dropped without "
            "it) and human-readable field VALUES: if a column is a lookup "
            "(value is a GUID), first resolve it to the related record's "
            "display name - raw GUID values are hidden from the card."
        ),
        parameters={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Optional short heading."},
                "table": {
                    "type": "string",
                    "description": "The table's LOGICAL name (e.g. prefix_entityname).",
                },
                "records": {
                    "type": "array",
                    "description": (
                        "Data rows to display (max 10). Each item: {'id': "
                        "'<primary key GUID>', '<field display label>': "
                        "<human-readable value>, ...}. Values must be real "
                        "record data, never column names/types, never bare "
                        "GUIDs (resolve lookups to names first)."
                    ),
                    "items": {"type": "object"},
                },
            },
            "required": ["table", "records"],
        },
        impl=_present_records_impl,
    )
    tools.append(present_spec.to_function_tool())
    dispatch[present_spec.name] = present_spec.impl

    deep_spec = EngineToolSpec(
        name="deep_impact_analysis",
        description=(
            "Convene the full multi-agent impact analysis (dependency engine + "
            "governance + workplace context specialists, reconciled by an "
            "adjudicator) on ONE question about change impact or failure "
            "diagnosis. Slow (1-2 minutes) but produces a formal validated "
            "verdict with risk score and may generate an actionable artifact "
            "(record fix proposal, notification draft, dev ticket). Phrase the "
            "question concretely; include any pasted URL verbatim."
        ),
        parameters={
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "The concrete impact/diagnosis question to analyse.",
                },
                "evidence": {
                    "type": "string",
                    "description": (
                        "Findings you already gathered this turn (run errors, "
                        "definition excerpts, SOP quotes, owners) so the "
                        "specialists adjudicate instead of re-investigating."
                    ),
                },
            },
            "required": ["question"],
        },
        impl=_deep_impact_impl,
    )
    tools.append(deep_spec.to_function_tool())
    dispatch[deep_spec.name] = deep_spec.impl

    draft_reply_spec = EngineToolSpec(
        name="draft_reply",
        description=(
            "Create an email DRAFT to a specific PERSON - an INTERNAL colleague "
            "OR an EXTERNAL contact. ALWAYS use THIS to email or reply to a "
            "person; never hand-roll SearchMessages / CreateDraftMessage / the "
            "directory yourself. It resolves an INTERNAL colleague via the org "
            "directory and drafts a NEW email to their address, and an EXTERNAL "
            "person (not in the directory, e.g. a customer who emailed in) via "
            "their own inbound email (a reply to the address on it). You supply "
            "the recipient (a NAME or an email address) and the COMPLETE body - "
            "compose the body yourself and ground it in what actually happened; "
            "it handles finding them and creating the inert draft in the user's "
            "Drafts."
        ),
        parameters={
            "type": "object",
            "properties": {
                "recipient": {
                    "type": "string",
                    "description": "The recipient's name (internal colleague or external contact) or their email address.",
                },
                "body": {
                    "type": "string",
                    "description": (
                        "The COMPLETE reply body to draft, in your own words, "
                        "grounded in the specifics (what happened / what the flow "
                        "should have produced) - not a generic placeholder."
                    ),
                },
            },
            "required": ["recipient", "body"],
        },
        impl=_draft_reply_impl,
    )
    tools.append(draft_reply_spec.to_function_tool())
    dispatch[draft_reply_spec.name] = draft_reply_spec.impl

    # Sandbox Builder (fix-only carve-out) - attached only when a sandbox is
    # configured; role-gated on every call.
    for spec in _builder_tool_specs(settings, report_holder, user_assertion=user_assertion):
        tools.append(spec.to_function_tool())
        dispatch[spec.name] = spec.impl

    # Failed-run resubmit: proposes only; the actual resubmit runs behind
    # /action/resubmit_run with the user's per-run tap.
    for spec in _resubmit_tool_specs(settings, report_holder, user_assertion=user_assertion):
        tools.append(spec.to_function_tool())
        dispatch[spec.name] = spec.impl

    # Per-record bounded-write proposals straight from the unified diagnosis -
    # same offer gate, same /action/remediate execution.
    for spec in _record_fix_tool_specs(report_holder):
        tools.append(spec.to_function_tool())
        dispatch[spec.name] = spec.impl

    # Work IQ - full capability, mutations approval-gated. Dataverse attaches
    # READ-ONLY: record writes stay exclusively behind the bounded-write gate
    # (/action/remediate); this agent proposes fixes, it never applies them.
    for srv, kwargs in (
        ("user", {}),
        ("calendar", {}),
        ("teams", {}),
        # Mail is READ-ONLY here on purpose: given the raw draft tools, the
        # agent hand-rolls CreateDraftMessage (no address → fail / hallucinated
        # recipient) despite instructions to do otherwise. Removing them
        # FORCES every email draft through `draft_reply`, whose helper resolves
        # the recipient (directory first, then their own inbound mail) before
        # drafting.
        ("mail", {"read_only": True}),
        ("dataverse", {"read_only": True}),
    ):
        t = build_workiq_tool(srv, settings, **kwargs)
        if t is not None:
            tools.append(t)
    # Work IQ semantic WORKPLACE SEARCH (A2A, read-only): natural-language
    # search across the user's Teams/mail/meetings/documents, permission-
    # trimmed OBO - the same tool the deep pipeline's context specialist
    # carries. This is where "when/who said/what's the latest" answers live.
    from .agents.single_agent import _build_workiq_tool as _build_workiq_a2a

    a2a = _build_workiq_a2a(settings)
    if a2a is not None:
        tools.append(a2a)
    kb = _build_mcp_kb_tool(settings)
    if kb is not None:
        tools.append(kb)
    print(
        f"(unified toolset: {len(tools)} tools; engine={'yes' if dispatch else 'no'} "
        f"workplace_search={'yes' if a2a is not None else 'NO'} kb={'yes' if kb is not None else 'NO'})",
        flush=True,
    )
    return tools, dispatch, dv_client, report_holder


class WarmupRequest(BaseModel):
    solution: str = Field(default_factory=lambda: get_settings().solution)


@app.post("/warmup")
def warmup(req: WarmupRequest) -> dict:
    """Prewarm the estate cache in the background (the bot fires this on
    conversation start) so the user's FIRST question skips the build tax.
    Returns immediately; the build runs on a daemon thread under the
    read-only service identity (structure only - two identities by scope)."""
    import threading

    from .dataverse_client import DataverseClient
    from .estate_cache import get_estate_cached

    settings = get_settings()

    def _build() -> None:
        try:
            with DataverseClient(settings) as dv:
                get_estate_cached(dv, settings, req.solution)
        except Exception as exc:  # noqa: BLE001 - warmup is best-effort
            print(f"(warmup failed: {exc})", flush=True)

    def _warm_agents() -> None:
        # Pre-create the cached tool-less agent versions (triage / router /
        # suggest) so the user's FIRST message pays ~2.7s, not the ~11s
        # version-creation cold start.
        model = settings.foundry_specialist_deployment or settings.foundry_model_deployment
        if not model:
            return
        from .agents.loop import run_agent_turn
        from .agents.runtime import make_project_client

        warmers = [
            ("ImpactIQ-ack", ACK_INSTRUCTIONS),
            ("ImpactIQ-route", NEEDS_DEEP_INSTRUCTIONS),
            ("ImpactIQ-suggest", SUGGEST_INSTRUCTIONS),
        ]
        try:
            with make_project_client(settings) as pc:
                for name, instr in warmers:
                    try:
                        run_agent_turn(
                            pc, agent_name=name, model=model, instructions=instr,
                            tools=[], dispatch={}, user_input="warmup",
                            cache_version=True,
                        )
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as exc:  # noqa: BLE001 - warmup is best-effort
            print(f"(agent warmup failed: {exc})", flush=True)

    def _warm_kb() -> None:
        # The deep pipeline's knowledge specialist makes a Foundry IQ KB
        # retrieval; the FIRST one is cold (agentic retrieval over SharePoint can
        # take over two minutes), which alone could push the whole /agent turn
        # past the surface fetch timeout and make the client abort.
        # Fire one throwaway retrieval here so the agentic-retrieval pipeline is
        # hot before the user's first deep question. KB auth is the project MI
        # (project_connection_id), so the service identity warms the SAME
        # server-side pipeline the user's (OBO) call will reuse.
        from .agents.loop import run_agent_turn
        from .agents.runtime import make_project_client
        from .agents.single_agent import _build_mcp_kb_tool

        model = settings.heavy_model_deployment or settings.foundry_model_deployment
        kb_tool = _build_mcp_kb_tool(settings)
        if not (model and kb_tool):
            return
        try:
            with make_project_client(settings) as pc:
                run_agent_turn(
                    pc,
                    agent_name="ImpactIQ-kb-warm",
                    model=model,
                    instructions=(
                        "Call knowledge_base_retrieve ONCE with a short generic "
                        "query (e.g. 'process guide') to warm the index, then "
                        "reply with the single word OK. Do not analyse the result."
                    ),
                    tools=[kb_tool],
                    dispatch={},
                    user_input="warm the knowledge base",
                )
        except Exception as exc:  # noqa: BLE001 - warmup is best-effort
            print(f"(kb warmup failed: {exc})", flush=True)

    def _warm_workiq() -> None:
        # The deep pipeline's CONTEXT specialist runs live Work IQ Teams/mail
        # searches; like the KB, the FIRST one pays an A2A/Work IQ cold-start
        # that can dominate a context turn once the KB is warmed. Fire one
        # throwaway Teams + mail search to warm the shared Work IQ connection
        # before the first deep question.
        #
        # HARD RULE (two identities by scope): Work IQ reads CONTENT, so this
        # MUST run under the DELEGATED identity (as_user=True) - the same one
        # the context specialist uses - NEVER the service identity. Consent is
        # already granted (the context specialist searches successfully), so
        # this won't block on the one-time consent gate.
        # Hosted (production): warmup runs BEFORE the user signs in, so there's
        # no OBO token - Work IQ (delegated) can't be warmed here. Skip it; it
        # warms naturally on the user's first deep question after sign-in.
        # Locally the browser-cached identity still warms it.
        if _HOSTED:
            return
        from .agents.loop import run_agent_turn
        from .agents.runtime import make_project_client
        from .agents.workiq import build_workiq_tool

        model = settings.heavy_model_deployment or settings.foundry_model_deployment
        wi_tools = [
            t
            for t in (
                build_workiq_tool("teams", settings, read_only=True),
                build_workiq_tool("mail", settings, read_only=True),
            )
            if t is not None
        ]
        if not (model and wi_tools):
            return
        try:
            with make_project_client(settings, as_user=True) as pc:
                run_agent_turn(
                    pc,
                    agent_name="ImpactIQ-workiq-warm",
                    model=model,
                    instructions=(
                        "Call SearchTeamsMessages once AND SearchMessages once "
                        "with a short generic query (e.g. 'update') to warm the "
                        "live search path, then reply with the single word OK. "
                        "Do not analyse or repeat any message content."
                    ),
                    tools=wi_tools,
                    dispatch={},
                    user_input="warm the Work IQ live search",
                )
        except Exception as exc:  # noqa: BLE001 - warmup is best-effort
            print(f"(workiq warmup failed: {exc})", flush=True)

    threading.Thread(target=_build, name="estate-warmup", daemon=True).start()
    threading.Thread(target=_warm_agents, name="agent-warmup", daemon=True).start()
    threading.Thread(target=_warm_kb, name="kb-warmup", daemon=True).start()
    threading.Thread(target=_warm_workiq, name="workiq-warmup", daemon=True).start()
    return {"warming": True, "solution": req.solution}


class AgentRequest(BaseModel):
    request: str
    history: list[dict] = []
    solution: str = Field(default_factory=lambda: get_settings().solution)
    conversation: str = ""  # short conv-id suffix, for delivery forensics


class ProgressRequest(BaseModel):
    conversation: str = ""


@app.post("/progress")
def progress(req: ProgressRequest) -> dict:
    """Drain the pending milestone lines for a conversation. The surface polls
    this every few seconds DURING a long /agent turn and posts what's new, so
    the user sees the play-by-play instead of a silent wait. Served on its own
    threadpool worker, so it answers while /agent is still mid-turn."""
    return {"events": _drain_progress(req.conversation or "")}


@app.post("/agent")
def unified_agent(
    req: AgentRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Launch the unified turn as a background JOB; return ``{job_id,
    job_status}`` immediately. The surface polls ``/agent/result``. Holding one
    HTTP request open for the whole (minutes-long) turn would trip the
    surface fetch / host idle timeout and discard the finished report;
    job/poll keeps every call short so no idle timeout can fire.
    ``X-ImpactIQ-User-Token`` carries the Teams user's token for the OBO flow."""
    settings = get_settings()
    if not settings.foundry_model_deployment:
        raise HTTPException(status_code=500, detail="FOUNDRY_MODEL_DEPLOYMENT not set")
    return _launch_job(
        lambda: _run_unified_agent(req, user_assertion=x_user_token),
        owner=token_owner(x_user_token),
    )


def _run_unified_agent(req: AgentRequest, user_assertion: str | None = None) -> dict:
    """ONE capability-aware agent over the UNION of tools - estate engine
    reads, Dataverse record reads, all Work IQ surfaces (mutations pause for
    Approve/Deny), governance KB. It reasons across everything in a single
    loop instead of being pre-routed into a lane. Record writes remain
    exclusively the bounded-write path; outbound stays approval-gated; the
    dependency engine stays deterministic (it's called as tools, never
    re-derived). Runs in a job thread (see _launch_job); returns the result dict
    the surface renders."""
    from .agents.loop import run_agent_turn
    from .agents.runtime import make_project_client

    settings = get_settings()
    if _needs_signin(user_assertion):
        return _signin_result()

    print(
        f"[in] /agent conv=…{req.conversation or '?'} q={req.request[:60]!r}",
        flush=True,
    )
    t0 = time.perf_counter()
    # Live progress: clear any stale buffer for this conversation, build a sink
    # the deep pipeline writes to, and wrap the local dispatch so each milestone
    # surfaces to the user via the /progress poll.
    conv = req.conversation or ""
    _reset_progress(conv)
    progress_sink = (lambda line: _push_progress(conv, line)) if conv else None
    # Per-conversation memory (the container). If this conversation already ran a
    # deep analysis AND the new request is the SAME subject (not a pivot), reuse
    # that verdict instead of recomputing the whole pipeline. Pivot reasoning
    # decides reuse; the deep tool serves the cached report; an action
    # follow-through (sandbox fix, notify) acts on it without re-running.
    prior = _recall_analysis(conv)
    reuse_prior = None
    if prior is not None and _same_subject(settings, prior, req.request):
        reuse_prior = prior.get("report")
        print(
            f"[conv-memory] reusing prior {prior.get('intent')} analysis "
            f"(anchor={prior.get('anchor')!r}) - not a pivot",
            flush=True,
        )
    tools, dispatch, dv_client, report_holder = _unified_tools(
        settings, req.solution, progress=progress_sink,
        conversation=conv, reuse_prior=reuse_prior, user_assertion=user_assertion,
    )
    dispatch = _wrap_dispatch_with_progress(dispatch, conv)
    history_text = "\n".join(
        f"{h.get('role', '?')}: {h.get('text', '')}" for h in req.history[-8:]
    )
    # Route. When a prior verdict is reusable, do NOT re-route to deep - tell
    # the agent to act on the existing verdict (sandbox fix / notify / record
    # fix). If it calls deep_impact_analysis anyway, the tool returns the
    # cached report (no pipeline re-run). Otherwise, the focused classifier
    # decides whether this NEW message requires the formal verdict (a per-turn
    # mandate, not the front agent's mid-loop judgment).
    if reuse_prior is not None:
        needs_deep = False
        print("(route: DIRECT - reuse prior analysis)", flush=True)
        mandate = (
            "\n\n[PRIOR ANALYSIS AVAILABLE] An impact analysis for this subject "
            "was already completed earlier in this conversation; its verdict "
            "still applies. Do NOT re-run deep_impact_analysis - act on the "
            "existing verdict (propose the sandbox fix, draft the notification, "
            "create the record, resubmit the runs, as the user asks). If you "
            "genuinely need it, deep_impact_analysis returns the cached verdict "
            "instantly.\n"
        )
    else:
        needs_deep = _needs_deep_analysis(settings, req.request, req.history)
        print(f"(route: {'DEEP' if needs_deep else 'DIRECT'})", flush=True)
        mandate = (
            "\n\n[REQUIRED THIS TURN: deep_impact_analysis] This message needs the "
            "formal impact verdict. Investigate with your own tools as needed, then "
            "you MUST call deep_impact_analysis (passing your findings in `evidence`) "
            "and build your answer on its verdict, before any fix/notify action.\n"
            if needs_deep
            else ""
        )
    # Builder permission AWARENESS: tell the agent upfront whether THIS user
    # holds the ImpactIQ Builder role, so it phrases a sandbox-fix offer
    # honestly instead of promising work the role gate would later block. The
    # hard gate at tool-call / Apply time is unchanged.
    builder_note = _builder_access_note(settings, user_assertion)
    # Tell the agent the estate it's scoped to. The engine tools are already
    # bound to this solution, but without naming it the agent treats a vague
    # "the solution" as ambiguous and asks the user which one. Naming the scope
    # lets it act directly on the default solution.
    scope_note = (
        f"Estate in scope: the '{req.solution}' solution. When the user says "
        f'"the solution" or names no solution, they mean this one - analyze it '
        f"directly; do NOT ask which solution.\n\n"
    )
    user_input = (
        f"Recent conversation:\n{history_text or '(none)'}\n\n"
        f"{scope_note}"
        f"User request:\n{req.request}{mandate}{builder_note}"
    )
    suspended = False
    try:
        with make_project_client(settings, as_user=True, user_assertion=user_assertion) as pc:
            turn = run_agent_turn(
                pc,
                agent_name="ImpactIQ-unified",
                model=settings.heavy_model_deployment,
                instructions=UNIFIED_INSTRUCTIONS,
                tools=tools,
                dispatch=dispatch,
                user_input=user_input,
                max_tool_loops=16,  # busy front agent: room for error-recovery detours
                suspend_on_approval=True,
                reflect=True,  # self-verify it actually DID the work before finishing
            )
        if turn.run_status == "pending_approval" and turn.resume_response_id:
            suspended = True
            _stash_pending_run(
                turn.resume_response_id, dispatch, dv_client, report_holder,
                owner=token_owner(user_assertion),
            )
        print(
            f"[unified] status={turn.run_status} tool_calls={turn.tool_call_count} "
            f"names={turn.tool_names[:8]} chars={len(turn.raw_text or '')}",
            flush=True,
        )
        audit_log("unified_agent", {"request": req.request, "run_status": turn.run_status})
        result = _assist_result(turn)
        result["resume_path"] = "/agent/approve"
        result = _attach_report_cards(
            result, report_holder,
            owner=token_owner(user_assertion), conversation=conv,
            user_assertion=user_assertion,
        )
        # Next-step chips, grounded in this reply (skip when paused for an
        # approval - there the decision IS the next step).
        if turn.run_status != "pending_approval":
            # Human fallout, surfaced by CODE so the LLM synthesis can't drop it.
            affected = _affected_people_footer(report_holder)
            if affected and "**People affected:**" not in (result.get("text") or ""):
                result["text"] = (result.get("text") or "") + "\n\n" + affected
            # Auditable reasoning: surface the deep pipeline's reconciliation +
            # evidence VERBATIM so the user can see HOW the conclusion was
            # reached, not just the conclusion.
            reasoning = _reasoning_footer(report_holder)
            if reasoning and "**Reasoning**" not in (result.get("text") or ""):
                result["text"] = (result.get("text") or "") + "\n\n" + reasoning
            # Clickable numbered SOURCE references for KB/SOP-grounded answers
            # (the deep pipeline carries them on the report, not the reply text).
            footer = _sources_footer(turn, report_holder)
            if footer and "**Sources**" not in (result.get("text") or ""):
                result["text"] = (result.get("text") or "") + "\n" + footer
            result["suggestions"] = _suggest_next_steps(
                settings, req.history, turn.raw_text or ""
            )
            print(f"(suggestions: {len(result['suggestions'])})", flush=True)
        # Total wall-clock for the turn. Prints whether or not the surface's
        # fetch is still open - so an "operation aborted" (client gave up before
        # this line) is diagnosable to the second: this line with NO following
        # "POST /agent 200 OK" means the bridge finished but the client had
        # already timed out. Compare against the surface's bridge timeout.
        print(f"(/agent done in {time.perf_counter() - t0:.1f}s)", flush=True)
        return result
    finally:
        if not suspended:
            _close_quietly(dv_client)


@app.post("/agent/approve")
def unified_agent_approve(
    req: AssistApproveRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Launch the approval-resume as a background JOB (resumes are long turns
    too - they keep running the agent loop after the decision). Returns
    ``{job_id}``; the surface polls ``/agent/result`` exactly like /agent."""
    return _launch_job(
        lambda: _run_unified_agent_approve(req, user_assertion=x_user_token),
        owner=token_owner(x_user_token),
    )


def _run_unified_agent_approve(req: AssistApproveRequest, user_assertion: str | None = None) -> dict:
    """Resume a suspended unified run with the human's Approve/Deny. Restores
    the run's engine-tool dispatch (and Dataverse client) from the pending-run
    registry so the model can keep using estate tools after the decision. Runs
    in a job thread; returns the result dict."""
    from .agents.loop import resume_agent_turn
    from .agents.runtime import make_project_client

    settings = get_settings()
    if _needs_signin(user_assertion):
        return _signin_result()
    # Owner check BEFORE consuming: a caller who isn't the user this run was
    # suspended for must neither resume it nor destroy it.
    stashed = _PENDING_RUNS.get(req.response_id)
    if stashed is not None and stashed.get("owner") is not None and stashed[
        "owner"
    ] != token_owner(user_assertion):
        return {
            "status": "failed",
            "text": "That approval belongs to a different user - ask again yourself.",
        }
    stashed = _PENDING_RUNS.pop(req.response_id, None) or {}
    dispatch = stashed.get("dispatch", {})
    dv_client = stashed.get("client")
    report_holder = stashed.get("report_holder", {})
    suspended = False
    try:
        with make_project_client(settings, as_user=True, user_assertion=user_assertion) as pc:
            turn = resume_agent_turn(
                pc,
                agent_name=req.agent_name,
                agent_version=req.agent_version,
                response_id=req.response_id,
                approvals=req.approvals,
                dispatch=dispatch,
                max_tool_loops=16,
                suspend_on_approval=True,
                reflect=True,  # self-verify after resuming the action, too
            )
        if turn.run_status == "pending_approval" and turn.resume_response_id:
            suspended = True
            _stash_pending_run(
                turn.resume_response_id, dispatch, dv_client, report_holder,
                owner=token_owner(user_assertion),
            )
        audit_log(
            "assist_action",
            {
                "user": _audit_identity(user_assertion, req.user),
                "decisions": [
                    {
                        "tool_name": p.get("tool_name"),
                        "server_label": p.get("server_label"),
                        "arguments": p.get("arguments"),
                        "approved": bool(req.approvals.get(p.get("id"), False)),
                    }
                    for p in req.pending
                ]
                or [{"approvals": req.approvals}],
                "run_status": turn.run_status,
                "surface": "unified",
            },
        )
        result = _assist_result(turn)
        result["resume_path"] = "/agent/approve"
        return _attach_report_cards(
            result, report_holder,
            owner=token_owner(user_assertion), user_assertion=user_assertion,
        )
    finally:
        if not suspended:
            _close_quietly(dv_client)


class AckRequest(BaseModel):
    question: str
    history: list[dict] = []
    conversation: str = ""  # short conv-id suffix, for delivery forensics




NEEDS_DEEP_INSTRUCTIONS = """\
You are a fast router. Decide whether the user's message REQUIRES ImpactIQ's
full impact analysis (a formal risk-scored verdict from the specialist
pipeline), or whether the front agent's own tools suffice.

Answer DEEP when the message is any of:
* a NEW idea / automation / change the user wants built or impact-assessed
  ("I want to add…", "create an automation that…", "what's the impact of…",
  "can we change/rename…");
* a REPORTED failure / issue / error to diagnose ("X is failing", "why
  didn't Y happen", "this isn't working", "a record that should exist is missing");
* a SAFETY / validation / cross-team blast-radius question ("is it safe
  to…", "validate this", "what breaks if…").

Answer DIRECT for everything else: lookups (show records, who owns X, what's
the latest on Y), simple actions (draft an email, book a meeting), greetings,
follow-up chit-chat, or a plain factual question.

CRUCIAL - action follow-throughs are DIRECT, not DEEP. When the user is
telling you to CARRY OUT something already discussed THIS conversation - that
is an ACTION on an analysis already done, not a new analysis, and re-running
the full pipeline just to act is wasted time. This includes BOTH:
* applying/sending: "apply the fix", "apply fix in sandbox", "propose the fix",
  "do it", "go ahead", "proceed", "make that change", "draft it", "email them";
* REMEDIATING an already-diagnosed problem: "create the missing record(s)",
  "manually create the missing record for each affected row", "backfill those",
  "fix the affected records", "remediate them", "resubmit the failed runs".
If the recent history shows the issue was already diagnosed, the follow-up is
the ACTION on that diagnosis - answer DIRECT. (Only answer DEEP if the recent
history shows NO prior diagnosis of this very thing.)

Output EXACTLY one word: DEEP or DIRECT.
"""


def _needs_deep_analysis(settings, question: str, history: list[dict]) -> bool:
    """Focused binary classification: does this message REQUIRE the formal
    impact pipeline? Drives a per-turn mandate so the trigger is reliable
    for new ideas / issue reports / validations rather than left to the
    front agent's mid-loop judgment. Best-effort - on any failure return
    False (the instruction's mandatory triggers still apply)."""
    model = settings.foundry_specialist_deployment or settings.foundry_model_deployment
    if not model:
        return False
    from .agents.loop import run_agent_turn
    from .agents.runtime import make_project_client

    history_text = "\n".join(
        f"{h.get('role', '?')}: {h.get('text', '')}" for h in (history or [])[-3:]
    )
    try:
        with make_project_client(settings) as pc:
            turn = run_agent_turn(
                pc,
                agent_name="ImpactIQ-route",
                model=model,
                instructions=NEEDS_DEEP_INSTRUCTIONS,
                tools=[],
                dispatch={},
                user_input=(
                    f"Conversation so far:\n{history_text or '(none)'}\n\n"
                    f"User message:\n{question}"
                ),
                cache_version=True,  # stateless tool-less hop - reuse the version
            )
        return "DEEP" in (turn.raw_text or "").strip().upper()
    except Exception:  # noqa: BLE001 - routing is best-effort
        return False


def _parse_ack(raw: str) -> dict:
    """Parse the triage output: ANSWER:-prefixed => final reply (the surface
    skips the full agent turn); anything else => the ack line."""
    line = (raw or "").strip()
    if line.upper().startswith("ANSWER:"):
        return {"text": line[len("ANSWER:"):].strip(), "final": True}
    return {"text": line, "final": False}


@app.post("/ack")
def ack(req: AckRequest) -> dict:
    """Front-door triage (one cheap model hop, no tools): either ANSWER the
    message outright when no tools/context could help (final=True - the
    surface skips the full agent turn), or return the context-aware
    acknowledgement line to show while the real turn runs."""
    from .agents.loop import run_agent_turn
    from .agents.runtime import make_project_client

    print(
        f"[in] /ack conv=…{req.conversation or '?'} q={req.question[:60]!r}",
        flush=True,
    )
    settings = get_settings()
    model = settings.foundry_specialist_deployment or settings.foundry_model_deployment
    if not model:
        raise HTTPException(status_code=500, detail="no model deployment configured")
    history_text = "\n".join(
        f"{h.get('role', '?')}: {h.get('text', '')}" for h in req.history[-4:]
    )
    with make_project_client(settings) as pc:
        turn = run_agent_turn(
            pc,
            agent_name="ImpactIQ-ack",
            model=model,
            instructions=ACK_INSTRUCTIONS,
            tools=[],
            dispatch={},
            user_input=(
                f"Conversation so far:\n{history_text or '(none)'}\n\n"
                f"The user's new message:\n{req.question}"
            ),
            cache_version=True,  # stateless tool-less hop - reuse the version
        )
    parsed = _parse_ack(turn.raw_text or "")
    if parsed["final"]:
        parsed["text"] = parsed["text"][:1000]  # a direct answer may be a few lines
    else:
        parsed["text"] = (
            parsed["text"].splitlines()[0].strip()[:200] if parsed["text"] else ""
        )
    return parsed


SUGGEST_INSTRUCTIONS = """\
You generate the NEXT-STEP suggestions shown as tap-able chips under
ImpactIQ's reply. You are given the recent conversation and ImpactIQ's most
recent reply. Propose the 2-4 most useful things the USER might want
ImpactIQ to do NEXT - each phrased as a short first-person request the user
would tap (it is sent back verbatim as their next message).

Only suggest things ImpactIQ can actually do, and only when the reply makes
them genuinely relevant - ground every suggestion in what the reply just
said. Suggestible capabilities:
* Run a full impact report / formal risk verdict on a component or change.
* Propose a fix to a failing/broken flow or table (sandbox, preview-first).
* Apply a proposed fix, or after a fix: resubmit the failed runs.
* Propose a record fix / create a missing record (preview-and-confirm).
* Find / identify the owner of a component, or who is affected.
* Show related records, recent changes, or dependencies / blast radius.
* Check a person's calendar / set up a meeting with an owner.

Rules:
* NO MESSAGE / DRAFT CHIPS. Do NOT suggest drafting or sending a message - no
  email, Teams, reply, notify, follow-up, or "message <person>" chips. Tapped
  verbatim, those mis-frame the channel and recipient (e.g. a Teams chip to an
  external customer, or an internal explanation sent to one), and the model
  can't reliably get channel/register right in a chip. Outreach is handled
  inline by the agent's own confirm-and-channel-gated draft paths when the user
  asks. Suggest only analysis / fix / record / lookup / scheduling actions.
  (FINDING or IDENTIFYING an owner is fine - just never messaging one.)
* Next steps belong after an ANALYSIS or ANSWER the user would build on - NOT
  after every turn. If the reply is CONFIRMING a completed action (a draft was
  created/saved, a message sent, a record or flow fixed, a run resubmitted),
  return [] - the action was the conclusion; tacking on unrelated chips is
  noise. (A genuine, tightly-related follow-up to the SAME action is fine, e.g.
  right after a fix: "resubmit the failed runs" - but never generic filler.)
* Do NOT suggest something the reply says was already done.
* Do NOT suggest a fix/report on a component the reply couldn't identify.
* No generic filler ("ask me anything"); every chip must be a concrete,
  actionable next request tied to THIS reply.
* Titles <= 6 words. If nothing concrete is worth offering, return [].

Output ONLY a JSON array, nothing else:
[{"title": "<chip label>", "query": "<the full message to send on tap>"}]
"""


def _parse_json_array(text: str) -> list:
    """Pull a JSON array out of the model's reply - it may be bare or fenced,
    and may be wrapped as {"suggestions": [...]}. Returns [] on anything else
    (`extract_json_block` only handles objects, not top-level arrays)."""
    import re

    s = (text or "").strip()
    s = re.sub(r"^```(?:json)?\s*|\s*```$", "", s).strip()
    try:
        val = json.loads(s)
    except Exception:  # noqa: BLE001
        start = s.find("[")
        end = s.rfind("]")
        if start == -1 or end <= start:
            return []
        try:
            val = json.loads(s[start : end + 1])
        except Exception:  # noqa: BLE001
            return []
    if isinstance(val, dict):
        val = val.get("suggestions") or val.get("items") or []
    return val if isinstance(val, list) else []


# A chip whose query drafts/sends a MESSAGE to a person is dropped
# DETERMINISTICALLY (the instruction asks the model not to make these, this is
# the enforcement - the model isn't reliable). Tapped, a
# chip is sent verbatim, so a mis-channelled "Draft a Teams update to <customer>"
# would drive a bad turn; outreach is handled inline by the confirm-and-channel
# gated draft paths instead. NOTE: bare "teams" is deliberately NOT a marker -
# "affected teams" is a legitimate lookup chip; only message-on-Teams phrasings.
_COMMS_CHIP_MARKERS = (
    "draft", "email", "e-mail", "reply", "notify", "message", "send ",
    "follow up", "follow-up", "reach out", "ping ", "slack", "intro",
    "introduce", "teams update", "teams message", "via teams", "on teams",
)


def _is_comms_chip(chip: dict) -> bool:
    """True if the chip drafts/sends a message to a person (dropped from suggestions)."""
    blob = f"{chip.get('title', '')} {chip.get('query', '')}".lower()
    return any(m in blob for m in _COMMS_CHIP_MARKERS)


def _suggest_next_steps(settings, history: list[dict], last_reply: str) -> list[dict]:
    """Model-judged next-step chips, grounded in the latest reply. Best-effort:
    a cheap light-model hop, never blocks or breaks the turn - any failure
    returns []. The chips are imBack actions on the surface, so tapping one
    sends its `query` as the user's next message and the chain continues.
    Communication chips (email/Teams/reply/notify) are filtered out
    deterministically - see _is_comms_chip."""
    reply = (last_reply or "").strip()
    if not reply:
        return []
    model = settings.foundry_specialist_deployment or settings.foundry_model_deployment
    if not model:
        return []
    from .agents.loop import run_agent_turn
    from .agents.runtime import make_project_client

    history_text = "\n".join(
        f"{h.get('role', '?')}: {h.get('text', '')}" for h in (history or [])[-4:]
    )
    try:
        with make_project_client(settings) as pc:
            turn = run_agent_turn(
                pc,
                agent_name="ImpactIQ-suggest",
                model=model,
                instructions=SUGGEST_INSTRUCTIONS,
                tools=[],
                dispatch={},
                user_input=(
                    f"Recent conversation:\n{history_text or '(none)'}\n\n"
                    f"ImpactIQ's latest reply:\n{reply[:2000]}"
                ),
                cache_version=True,  # stateless tool-less hop - reuse the version
            )
        raw = _parse_json_array(turn.raw_text or "")
    except Exception:  # noqa: BLE001 - suggestions are an enrichment, never fatal
        return []
    out: list[dict] = []
    if isinstance(raw, list):
        for item in raw[:4]:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "").strip()[:48]
            query = str(item.get("query") or title).strip()[:300]
            if title and query:
                out.append({"title": title, "query": query})
    # Deterministic backstop: drop message/draft chips the model shouldn't have
    # offered (channel/recipient mis-framing - see _is_comms_chip).
    return [c for c in out if not _is_comms_chip(c)]


class SuggestRequest(BaseModel):
    history: list[dict] = []
    last_reply: str = ""


@app.post("/suggest")
def suggest(req: SuggestRequest) -> dict:
    """Next-step chips for the surface (used after a card action to keep the
    chain going - the /agent path attaches them inline). Best-effort."""
    return {"suggestions": _suggest_next_steps(get_settings(), req.history, req.last_reply)}


class HandoffSendRequest(BaseModel):
    artifact: dict
    user: str = "unknown"
    confirmed: bool = False  # must be the result of an explicit tap


class RemediateRequest(BaseModel):
    artifact: dict
    user: str = "unknown"
    confirmation_type: str = ""           # "tap" | "typed"
    typed_value: str | None = None        # required when typed
    user_referenced_document: bool = False
    diagnosis_id: str | None = None
    proposal_id: str | None = None        # server-issued id (also read from artifact)


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/action/send_handoff")
def send_handoff(
    req: HandoffSendRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Confirm-before-send gate. Returns the text the BOT should post; the
    server itself sends nothing (draft-only discipline lives on)."""
    if not req.confirmed:
        raise HTTPException(
            status_code=403,
            detail="send requires an explicit user confirmation (tap)",
        )
    # Send is irreversible, so bind to the server-stored proposal and consume it
    # (one-time): the recipient and body are exactly what the owner previewed,
    # and a replayed payload cannot re-send.
    bound = _bound_notify_artifact(req.artifact, user_assertion=x_user_token, consume=True)
    source = bound if bound is not None else req.artifact
    a_type = source.get("artifact_type")
    if a_type not in ("manager_handoff", "draft_teams_intro"):
        raise HTTPException(
            status_code=400, detail=f"artifact_type {a_type!r} is not sendable"
        )
    draft_text = (source.get("draft_text") or "").strip()
    recipient = (source.get("recipient") or "").strip()
    if not draft_text or not recipient:
        raise HTTPException(status_code=400, detail="artifact missing draft_text/recipient")

    event_id = audit_log(
        "handoff_sent",
        {
            "user": _audit_identity(x_user_token, req.user),
            "artifact_type": a_type,
            "recipient": recipient,
            # Proof-of-content, not a copy: message bodies are business
            # content - the chain stores their hash + an excerpt.
            "draft_text": _digest(draft_text),
            "baton_id": (source.get("baton") or {}).get("baton_id"),
            "confirmation": "tap",
        },
    )
    return {
        "send": True,
        "recipient": recipient,
        "message": draft_text,
        "audit_event_id": event_id,
    }


class SandboxFixRequest(BaseModel):
    fix_id: str
    user: str = "unknown"
    confirmed: bool = False


@app.post("/action/sandbox_fix")
def apply_sandbox_fix(
    req: SandboxFixRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Apply a PROPOSED sandbox fix behind the user's explicit Apply tap.

    Order matters: the Builder role is re-checked LIVE (uncached) first, so an
    unauthorised request can neither apply NOR consume (destroy) the pending
    proposal; only then is the owner-bound proposal atomically consumed."""
    if not req.confirmed:
        raise HTTPException(status_code=403, detail="applying a fix requires an explicit tap")
    settings = get_settings()
    from .builder import BuilderRefusal
    from .builder.executor import run_fixspec
    from .builder.gate import assert_builder_permission

    try:
        # fresh=True: the mutation boundary never trusts the role cache.
        assert_builder_permission(settings, x_user_token, fresh=True)
    except BuilderRefusal as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        proposal = proposals.consume(
            req.fix_id, "sandbox_fix", owner=token_owner(x_user_token)
        )["artifact"]
    except ProposalError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    try:
        report = run_fixspec(settings, {"ops": proposal["ops"]})
    except BuilderRefusal as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    audit_log(
        "builder_fix_applied",
        {
            "user": _audit_identity(x_user_token, req.user),
            "fix_id": req.fix_id,
            "title": proposal["title"],
            "ops": proposal["ops"],
            "report": report.to_dict(),
        },
    )
    return {"applied": True, "title": proposal["title"], **report.to_dict()}


class ResubmitRunRequest(BaseModel):
    resubmit_id: str
    user: str = "unknown"
    confirmed: bool = False


@app.post("/action/resubmit_run")
def apply_resubmit_run(
    req: ResubmitRunRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Resubmit ONE failed flow run behind the user's explicit per-run tap:
    delegated user identity - the Power Automate API enforces the user's own
    flow permissions - one-shot, owner-bound, audit-logged."""
    if not req.confirmed:
        raise HTTPException(status_code=403, detail="resubmitting a run requires an explicit tap")
    if _needs_signin(x_user_token):
        raise HTTPException(status_code=401, detail=_SIGNIN_TEXT)
    try:
        p = proposals.consume(
            req.resubmit_id, "resubmit_run", owner=token_owner(x_user_token)
        )["artifact"]
    except ProposalError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    settings = get_settings()
    from .agents.runtime import delegated_credential

    # The SAME delegated identity as every other user action: On-Behalf-Of the
    # Teams user when hosted, the local browser sign-in for CLI dev. The run
    # is resubmitted under - and attributed to - the requesting principal.
    token = (
        delegated_credential(settings, x_user_token)
        .get_token("https://service.flow.microsoft.com//.default")
        .token
    )
    base = (
        "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/"
        f"environments/{p['env_id']}/flows/{p['flow_resource']}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    run = httpx.get(
        f"{base}/runs/{p['run_name']}",
        params={"api-version": "2016-11-01"},
        headers=headers,
        timeout=30,
    )
    if run.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"could not read the run before resubmitting: HTTP {run.status_code}",
        )
    trigger = ((run.json().get("properties") or {}).get("trigger") or {}).get("name") or ""
    if not trigger:
        raise HTTPException(status_code=502, detail="run carries no trigger name")
    r = httpx.post(
        f"{base}/triggers/{trigger}/histories/{p['run_name']}/resubmit",
        params={"api-version": "2016-11-01"},
        headers=headers,
        timeout=60,
    )
    ok = r.status_code in (200, 202)
    audit_log(
        "flow_run_resubmitted" if ok else "flow_resubmit_failed",
        {
            "user": _audit_identity(x_user_token, req.user),
            "resubmit_id": req.resubmit_id,
            "flow": p["flow_name"],
            "run": p["run_name"],
            "status_code": r.status_code,
        },
    )
    if not ok:
        raise HTTPException(
            status_code=502,
            detail=f"resubmit failed: HTTP {r.status_code}: {r.text[:200]}",
        )
    return {"resubmitted": True, "flow": p["flow_name"], "run": p["run_name"]}


class CreateDraftRequest(BaseModel):
    artifact: dict
    user: str = "unknown"
    confirmed: bool = False
    edited_text: str | None = None    # the user's edited body, if any


_CREATE_DRAFT_INSTRUCTIONS = """\
You create ONE draft email in the signed-in user's Outlook mailbox, then
stop. Use the `CreateDraftMessage` tool. You CANNOT send mail and must not
try.

Create a draft with the given subject and body EXACTLY as provided (do not
rewrite the body). If a recipient is named, set it; otherwise leave
recipients empty for the user to fill. After the draft is created, reply
with one short sentence confirming it's in their Drafts. Do not send it.
"""


@app.post("/action/create_draft")
def create_draft(
    req: CreateDraftRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Create a DRAFT in the user's Outlook (Work IQ Mail MCP, draft-only).

    Behind the confirm tap, runs an as-user agent turn whose only tool is the
    Work IQ Mail draft pair (CreateDraftMessage/UpdateDraft - never send).
    The draft lands in the user's own Drafts; they review and send from
    Outlook.
    """
    if not req.confirmed:
        raise HTTPException(status_code=403, detail="creating a draft requires an explicit tap")
    if _needs_signin(x_user_token):
        raise HTTPException(status_code=401, detail=_SIGNIN_TEXT)

    settings = get_settings()
    from .agents.runtime import make_project_client
    from .agents.loop import run_agent_turn
    from .agents.single_agent import _build_workiq_mail_tool

    mail_tool = _build_workiq_mail_tool(settings)
    if mail_tool is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Work IQ Mail isn't configured (FOUNDRY_WORKIQ_MAIL_CONNECTION_ID). "
                "Drafting into the mailbox needs that connection + an as-user sign-in."
            ),
        )

    from .report.card import OUTLOOK_DRAFT_SUBJECT

    # Bind the recipient to the server-stored proposal so it cannot be swapped
    # in the client payload. The draft is reversible (it lands inert in the
    # user's OWN Drafts), so the proposal is verified, not consumed, and the
    # user's own edited body is allowed over the proposed text.
    bound = _bound_notify_artifact(req.artifact, user_assertion=x_user_token, consume=False)
    source = bound if bound is not None else req.artifact
    recipient = (source.get("recipient") or "").strip()
    body = (req.edited_text or source.get("draft_text") or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="nothing to draft (empty body)")
    subject = OUTLOOK_DRAFT_SUBJECT

    user_input = (
        f"Create a draft email.\nSubject: {subject}\n"
        f"Intended recipient (for reference): {recipient or '(leave empty)'}\n"
        f"Body (use verbatim):\n{body}"
    )
    with make_project_client(settings, as_user=True, user_assertion=x_user_token) as project_client:
        turn = run_agent_turn(
            project_client,
            agent_name="ImpactIQ-mail-drafter",
            model=settings.foundry_model_deployment or "",
            instructions=_CREATE_DRAFT_INSTRUCTIONS,
            tools=[mail_tool],
            dispatch={},
            user_input=user_input,
        )
    event_id = audit_log(
        "mail_draft_created",
        {
            "user": _audit_identity(x_user_token, req.user),
            "recipient": recipient,
            "subject": subject,
            "body": _digest(body),
            "run_status": turn.run_status,
        },
    )
    return {
        "drafted": True,
        "audit_event_id": event_id,
        "detail": turn.raw_text or "Draft created in your Outlook Drafts.",
    }


class HandoffDeliverRequest(BaseModel):
    artifact: dict           # the approved manager_handoff
    user: str = "unknown"    # B, the notifying user
    confirmed: bool = False   # explicit tap - never auto-send


class HandoffResumeRequest(BaseModel):
    baton_id: str
    user: str = "unknown"             # the manager (the tapper) - resume runs as them
    solution: str = Field(default_factory=lambda: get_settings().solution)  # estate scope


class HandoffAckRequest(BaseModel):
    baton_id: str
    stance: str = ""          # "reviewing" | "clear"
    user: str = "unknown"


@app.post("/handoff/deliver")
def handoff_deliver(
    req: HandoffDeliverRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Persist the context baton (under B's delegated identity) and return the
    interactive Card 1 for the bot to deliver to the recipient manager. B must
    have confirmed; the agent never notifies on inference."""
    if not req.confirmed:
        raise HTTPException(status_code=403, detail="delivering a handoff requires an explicit tap")
    if _needs_signin(x_user_token):
        raise HTTPException(status_code=401, detail=_SIGNIN_TEXT)
    from .report.artifacts import ManagerHandoff

    # Bind the recipient and context baton to the server-stored proposal and
    # consume it (one-time): who is notified and what context travels with the
    # handoff cannot be swapped in the client payload. The sender's own edited
    # message body is still honoured over the proposed text.
    bound = _bound_notify_artifact(req.artifact, user_assertion=x_user_token, consume=True)
    if bound is not None:
        merged = dict(bound)
        edited = (req.artifact.get("draft_text") or "").strip()
        if edited:
            merged["draft_text"] = edited
        artifact_to_validate = merged
    else:
        artifact_to_validate = req.artifact

    try:
        handoff = ManagerHandoff.model_validate(artifact_to_validate)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"not a valid manager_handoff: {exc}")

    settings = get_settings()
    from .baton_store import put_baton
    from .report.card import baton_notification_card

    stored = put_baton(
        settings, handoff.baton, handoff.recipient, status="sent",
        user_assertion=x_user_token,
    )
    event_id = audit_log(
        "handoff_delivered",
        {
            "user": _audit_identity(x_user_token, req.user),
            "recipient": handoff.recipient,
            "baton_id": handoff.baton.baton_id,
            "row_id": stored.row_id,
        },
    )
    return {
        "delivered": True,
        "baton_id": handoff.baton.baton_id,
        "recipient": handoff.recipient,
        "card": baton_notification_card(handoff),
        "audit_event_id": event_id,
    }


@app.post("/handoff/resume")
def handoff_resume(
    req: HandoffResumeRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """The manager resumes the baton in THEIR session. Loads the baton
    (delegated read), runs the impact analysis AS THE MANAGER so their own Work
    IQ surfaces their side of the collision, and returns the manager-only
    finding. Nothing computed here flows back to B unless the manager later
    chooses to share it (there is no automatic reply back to B)."""
    if _needs_signin(x_user_token):
        raise HTTPException(status_code=401, detail=_SIGNIN_TEXT)
    settings = get_settings()
    from .baton_store import get_baton

    stored = get_baton(settings, req.baton_id, x_user_token)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no baton {req.baton_id!r} found")
    b = stored.baton
    anchor = b.anchor.name if b.anchor else "the affected component"
    question = (
        f"Another team is proposing a change that may affect your team's data: "
        f'"{b.proposed_change}" (touching {anchor}). From YOUR own context and '
        f"your team's current work, what would this collide with, and what "
        f"should they be told before they proceed? {b.resume_hint}".strip()
    )

    from .agents.multi_agent import ask_multi

    result = ask_multi(
        settings, solution_name=req.solution, question=question, as_user=True,
        user_assertion=x_user_token,
    )
    summary = ""
    report_dump: dict | None = None
    if result.report is not None:
        try:
            report = ImpactReport.model_validate(result.report)
            summary = report_summary_markdown(report)
            report_dump = report.model_dump()
        except Exception:
            summary = ""
    audit_log(
        "baton_resumed",
        {
            "user": _audit_identity(x_user_token, req.user),
            "baton_id": req.baton_id,
            "requesting_user": b.requesting_user,
            "run_status": result.run_status,
        },
    )
    return {
        "baton_id": req.baton_id,
        "summary_text": summary
        or "I couldn't pull a clear read from your context this time - try asking me directly.",
        "report": report_dump,
        "run_status": result.run_status,
    }


@app.post("/handoff/ack")
def handoff_ack(
    req: HandoffAckRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Record the manager's lightweight acknowledgement ('I'll review it' /
    'No concern'). Audit event only - not a row write (the manager doesn't own
    the baton row), keeping the delegated-write bound tight.

    The ack is bound to a real handoff and its addressed recipient: the baton
    must exist, and (when running with a delegated identity) the caller's
    verified identity must match the recipient the baton was sent to. This
    stops an unrelated or spoofed caller from planting acknowledgements against
    someone else's handoff.
    """
    if _needs_signin(x_user_token):
        raise HTTPException(status_code=401, detail=_SIGNIN_TEXT)

    settings = get_settings()
    from .baton_store import get_baton

    try:
        stored = get_baton(settings, req.baton_id, x_user_token)
    except Exception:  # noqa: BLE001 - an unreadable baton fails closed as not found
        stored = None
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no baton {req.baton_id!r} found")

    # Recipient binding (skipped only in local single-user dev, where there is
    # no delegated identity to check against).
    if x_user_token:
        ident = token_identity(x_user_token)
        caller = {
            str(v).strip().lower()
            for v in (ident.get("upn"), ident.get("name"))
            if v
        }
        target = (stored.recipient or "").strip().lower()
        if target and caller and target not in caller:
            raise HTTPException(
                status_code=403,
                detail="only the addressed recipient can acknowledge this handoff",
            )

    event_id = audit_log(
        "baton_acknowledged",
        {
            "user": _audit_identity(x_user_token, req.user),
            "baton_id": req.baton_id,
            "stance": req.stance,
        },
    )
    return {"ok": True, "audit_event_id": event_id}


def _dataverse_user_token(settings: Any, user_assertion: str | None = None) -> str:
    from .agents.runtime import delegated_credential

    base = (settings.dataverse_url or "").rstrip("/")
    if not base:
        raise HTTPException(status_code=500, detail="DATAVERSE_URL not configured")
    cred = delegated_credential(settings, user_assertion)
    return cred.get_token(f"{base}/.default").token


def _entity_set_name(base: str, token: str, logical_name: str) -> str:
    r = httpx.get(
        f"{base}/api/data/v9.2/EntityDefinitions(LogicalName='{logical_name}')",
        params={"$select": "EntitySetName"},
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=30,
    )
    if r.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"could not resolve entity set for {logical_name!r}: {r.status_code}",
        )
    return r.json()["EntitySetName"]


@app.post("/action/remediate")
def remediate(
    req: RemediateRequest,
    x_user_token: str | None = Header(default=None, alias="X-ImpactIQ-User-Token"),
) -> dict:
    """Validated remediation - the system's only write path."""
    if _needs_signin(x_user_token):
        raise HTTPException(status_code=401, detail=_SIGNIN_TEXT)
    settings = get_settings()

    # 1. Resolve the SERVER-stored proposal. The client's card payload only
    # names the proposal id; the canonical artifact - what the user actually
    # previewed - is retrieved from the owner-bound one-time store (registered
    # at proposal time), so a caller cannot substitute a different artifact.
    # Hosted mode REQUIRES the binding; local single-user dev without an id
    # falls back to validating the supplied artifact (no store to bind to).
    proposal_id = req.proposal_id or (req.artifact or {}).get("proposal_id")
    etag: str | None = None
    if proposal_id:
        try:
            stored = proposals.consume(
                proposal_id, "remediation", owner=token_owner(x_user_token)
            )
        except ProposalError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
        candidate = stored["artifact"]
        etag = (stored.get("extra") or {}).get("etag")
    elif _HOSTED:
        raise HTTPException(
            status_code=403,
            detail="this write requires a server-issued proposal - ask the agent to propose the fix again",
        )
    else:
        candidate = {k: v for k, v in (req.artifact or {}).items() if k != "proposal_id"}

    # 2. Re-run the offer gate server-side at execution time: the artifact must
    # STILL pass every bounded-write bound (DIAGNOSE-only, data-only,
    # per-record, confidence floor) even though it was validated at proposal time.
    artifact_dict, refusal = validate_artifact_payload(
        "DIAGNOSE", candidate, user_referenced_document=req.user_referenced_document
    )
    if refusal is not None:
        audit_log(
            "remediation_refused",
            {"user": _audit_identity(x_user_token, req.user), "refusal": refusal},
        )
        raise HTTPException(status_code=403, detail=refusal["refused"])
    proposal = RemediationProposal.model_validate(artifact_dict)

    # 3. Confirmation friction: tap for diagnosis-grounded, TYPED for
    # document-grounded/creates - and the typed value must be the EXACT
    # proposed value. A generic "CONFIRM" is not accepted: retyping the real
    # value is the whole point of typed confirmation.
    if req.confirmation_type != proposal.confirmation:
        raise HTTPException(
            status_code=403,
            detail=f"this proposal requires {proposal.confirmation!r} confirmation",
        )
    if proposal.confirmation == "typed":
        expected = {str(c.proposed_value) for c in proposal.changes if c.proposed_value}
        typed = (req.typed_value or "").strip()
        if typed not in expected:
            raise HTTPException(
                status_code=403,
                detail="typed confirmation must be the exact proposed value shown on the card",
            )

    # 4. Execute ONE deterministic Dataverse Web API call under the DELEGATED
    # user identity - fixed table, fixed record id, schema-gated payload.
    # No model is in the execution path: the LLM proposes, the server writes.
    payload = {
        ch.column: ch.proposed_value
        for ch in proposal.changes
        if ch.proposed_value is not None
    }
    if proposal.operation == "create":
        # Create carve-out: replay the ONE row a failed automation never
        # wrote. Replay-protected by the one-time proposal consumption above.
        ok, channel, detail = _write_via_post(settings, proposal, payload, x_user_token)
    else:
        ok, channel, detail = _write_via_patch(
            settings, proposal, payload, x_user_token, etag=etag
        )
        if not ok and "stale proposal" in detail:
            raise HTTPException(status_code=409, detail=detail)

    # 5. Audit chain - success or failure, the attempt is logged.
    event_id = audit_log(
        "remediation_executed" if ok else "remediation_failed",
        {
            "user": _audit_identity(x_user_token, req.user),
            "proposal_id": proposal_id,
            "diagnosis_id": req.diagnosis_id,
            "diagnosis_summary": proposal.diagnosis_summary,
            "operation": proposal.operation,
            "record_table": proposal.record_table,
            "record_id": proposal.record_id,
            "preview": [
                {"column": c.column, "current": c.current_value, "proposed": c.proposed_value}
                for c in proposal.changes
            ],
            "confirmation_type": req.confirmation_type,
            "evidence_source": proposal.evidence_source,
            "document_name": proposal.document_name,
            "source_span": proposal.source_span,
            "write_channel": channel,
            "detail": detail,
        },
    )
    if not ok:
        raise HTTPException(
            status_code=502, detail=f"The write did not complete ({channel}): {detail}"
        )
    return {
        "executed": True,
        "record_id": proposal.record_id,
        "changes": payload,
        "write_channel": channel,
        "audit_event_id": event_id,
    }


# The LLM is NEVER in the write execution path. Routing the confirmed update
# through a model (e.g. a Work IQ Dataverse MCP *writer agent*) would put a
# model between the user's confirmation and the mutation, where adversarial
# strings inside grounded field values become a prompt-injection surface and
# "exactly one call happened" cannot be proven. The model PROPOSES (typed
# artifact → deterministic gate → user preview); the server executes one typed
# Web API call with a fixed table, fixed record id, and the confirmed payload.
# The agent-facing Dataverse MCP tools remain READ-ONLY in the unified toolset.


def _write_via_patch(
    settings,
    proposal,
    payload: dict,
    user_assertion: str | None = None,
    etag: str | None = None,
) -> tuple[bool, str, str]:
    """ONE deterministic, optimistic-concurrency PATCH under the user's
    delegated identity.

    ``etag`` is the record version captured when the proposal was registered
    (what the user actually previewed). If it's missing, the CURRENT version
    is fetched and used - never ``If-Match: *``, which would silently
    overwrite changes made after the preview. A 412 means the record changed
    since the preview: the write is refused as a stale proposal."""
    base = (settings.dataverse_url or "").rstrip("/")
    token = _dataverse_user_token(settings, user_assertion)
    entity_set = _entity_set_name(base, token, proposal.record_table)
    url = f"{base}/api/data/v9.2/{entity_set}({proposal.record_id})"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if not etag:
        pre = httpx.get(
            url, params={"$select": "modifiedon"}, headers=headers, timeout=30
        )
        if pre.status_code != 200:
            return False, "dataverse_web_api", f"record read failed: HTTP {pre.status_code}"
        etag = pre.json().get("@odata.etag")
    r = httpx.patch(
        url,
        json=payload,
        headers={
            **headers,
            "Content-Type": "application/json",
            # Version-pinned update: fails on concurrent change, never upserts.
            "If-Match": etag or "*",
        },
        timeout=30,
    )
    if r.status_code == 412:
        return False, "dataverse_web_api", (
            "the record changed after you previewed this fix (stale proposal) - "
            "re-run the diagnosis and confirm a fresh proposal"
        )
    ok = r.status_code in (200, 204)
    return ok, "dataverse_web_api", (f"HTTP {r.status_code}" if ok else r.text[:300])


def _write_via_post(
    settings, proposal, payload: dict, user_assertion: str | None = None
) -> tuple[bool, str, str]:
    """Create carve-out: ONE new row under the delegated user identity. The
    created id is returned so the audit row carries it."""
    base = (settings.dataverse_url or "").rstrip("/")
    token = _dataverse_user_token(settings, user_assertion)
    entity_set = _entity_set_name(base, token, proposal.record_table)
    r = httpx.post(
        f"{base}/api/data/v9.2/{entity_set}",
        json=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=30,
    )
    if r.status_code not in (200, 201, 204):
        return False, "dataverse_web_api_create", r.text[:300]
    created = r.headers.get("OData-EntityId", "")
    return True, "dataverse_web_api_create", f"created {created.rsplit('/', 1)[-1]}"


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port)
