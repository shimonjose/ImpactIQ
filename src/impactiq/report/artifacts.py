"""Artifact layer - the ``generated_artifact`` contract + remediation bounds.

The deterministic core stays deterministic: the agent *drafts* an artifact
payload, but every payload passes through
:func:`validate_artifact_payload` - a deterministic gate that enforces the
remediation boundary in code. Refusals come back machine-readable with a
``use_instead`` pivot so the agent can downgrade (e.g. a configuration-cause
"fix" becomes a dev ticket).

Everything here is **draft-only**: no artifact sends a message or writes a
record. Execution (tap/typed confirm, OBO write, audit chain) lives in the
Teams surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .schema import NodeRef

# ── shared pieces ────────────────────────────────────────────────────────────


class FieldChange(BaseModel):
    """One column's current → proposed change in a remediation."""

    column: str
    current_value: str | None = None
    # None = the evidence is silent on this field. No hallucinated values - a
    # None proposed_value with no options is rejected by the gate.
    proposed_value: str | None = None
    # Multiple defensible values are presented, never auto-picked.
    options: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class ContextBaton(BaseModel):
    """Cross-session context carried by a manager handoff.

    Disclosable tier ONLY, enforced structurally: there is no field that can
    carry the *other* team's content. ``proposed_change`` is the requesting
    user's own words about their own proposal - never inferred substance.
    """

    baton_id: str = Field(default_factory=lambda: f"baton-{uuid.uuid4().hex[:12]}")
    created_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    baton_version: int = 1
    # Required-ness is deliberately loose: drafting models oscillate on
    # nested required fields, and a sparse baton is less useful but never
    # UNSAFE - the safety property is structural (fields that can't exist),
    # not completeness. Essentials still live on the handoff itself
    # (recipient, draft_text).
    requesting_user: str = "requesting user"
    intent: Literal["DIAGNOSE", "VALIDATE"] = "VALIDATE"
    anchor: NodeRef | None = None
    proposed_change: str = ""
    impacted_components: list[NodeRef] = Field(default_factory=list)
    risk_level: Literal["low", "medium", "high"] = "low"
    # What the resuming (manager) session should do - phrased so the manager's
    # own identity/Work IQ supplies their side of the context.
    resume_hint: str = ""

    model_config = ConfigDict(extra="ignore")


# ── artifact types ───────────────────────────────────────────────────────────


class DevTicket(BaseModel):
    artifact_type: Literal["dev_ticket"] = "dev_ticket"
    title: str
    severity: Literal["low", "medium", "high"] = "medium"
    component: NodeRef | None = None
    description: str = ""
    root_cause: str = ""
    evidence_summary: str = ""
    suggested_fix: str = ""
    acceptance_criteria: list[str] = Field(default_factory=list)
    impacted_components: list[NodeRef] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")

    @field_validator("impacted_components", mode="before")
    @classmethod
    def _coerce_impacted(cls, v: object) -> object:
        if not isinstance(v, list):
            return v
        return [
            {"id": s, "kind": "Reference", "name": s} if isinstance(s, str) else s
            for s in v
        ]


class ReuseBlueprint(BaseModel):
    artifact_type: Literal["reuse_blueprint"] = "reuse_blueprint"
    existing_components: list[NodeRef] = Field(default_factory=list)
    gap_analysis: str = ""
    recommendation: Literal["reuse", "extend", "build_new"] = "extend"
    steps: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class DraftTeamsIntro(BaseModel):
    """Draft-only Teams intro to a component's owner. Never auto-sent."""

    artifact_type: Literal["draft_teams_intro"] = "draft_teams_intro"
    recipient: str
    # Routing names come from structural ownership, never from the content of
    # anyone's threads/documents.
    recipient_source: Literal["structural_ownership"] = "structural_ownership"
    draft_text: str
    status: Literal["draft"] = "draft"

    model_config = ConfigDict(extra="ignore")


class ManagerHandoff(BaseModel):
    """Notify-and-handoff: impact-assertion-only draft + context baton."""

    artifact_type: Literal["manager_handoff"] = "manager_handoff"
    recipient: str
    recipient_source: Literal["structural_ownership"] = "structural_ownership"
    # Impact assertion + consult request, nothing more. The content discipline
    # (no inferred reasons that could reconstruct the other team's substance)
    # is checked by the gate below at the cheap-heuristic level and re-stated
    # to the model in the agent instructions.
    draft_text: str
    baton: ContextBaton
    status: Literal["draft"] = "draft"

    model_config = ConfigDict(extra="ignore")


class RemediationProposal(BaseModel):
    """Per-record, DIAGNOSE-only, preview-and-confirm data fix.

    ``operation="create"`` replays the single row a failed automation never
    wrote: still a per-record data write under the delegated identity, but
    ALWAYS typed-confirmed and diagnosis-grounded only (the failed action's
    own parameters define the payload - documents can never seed a create)."""

    artifact_type: Literal["remediation_proposal"] = "remediation_proposal"
    operation: Literal["update", "create"] = "update"
    record_table: str
    record_id: str = ""
    record_name: str = ""
    identifying_columns: dict[str, str] = Field(default_factory=dict)
    changes: list[FieldChange]
    evidence_source: Literal["diagnosis", "document"]
    diagnosis_summary: str = ""
    diagnosis_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    # Document-grounded only. NOTE: dormant on the live surface -
    # propose_record_fix sends diagnosis-grounded proposals only by choice;
    # these fields are exercised by the CLI + tests and kept ready to wire on
    # (see the gate's document branch below for the safety caveat).
    document_name: str | None = None
    source_span: str | None = None
    extraction_confidence: float | None = None
    # Dependency-aware downstream preview from the already-done walk.
    downstream_preview: list[str] = Field(default_factory=list)
    confirmation: Literal["tap", "typed"] = "tap"
    # Always False until the surface wires execution. This layer cannot execute.
    executed: Literal[False] = False

    model_config = ConfigDict(extra="ignore")

    @model_validator(mode="after")
    def _force_typed_for_document(self) -> "RemediationProposal":
        # Document-grounded proposals ALWAYS require typed confirmation,
        # regardless of what the drafting model set. Creates likewise: writing
        # a NEW row is higher-consequence than correcting a field, so a tap
        # never suffices.
        if self.evidence_source == "document" or self.operation == "create":
            object.__setattr__(self, "confirmation", "typed")
        return self


class BackfillBlueprint(BaseModel):
    """Bulk path: a routed document, never a tap."""

    artifact_type: Literal["backfill_blueprint"] = "backfill_blueprint"
    query: str
    query_language: Literal["fetchxml", "odata"] = "odata"
    per_record_update: list[FieldChange]
    idempotency_note: str
    estimated_record_count: int | None = None
    suggested_approver: str = ""
    approver_source: Literal["structural_ownership"] = "structural_ownership"
    draft_message: str = ""
    routed_via: Literal["manager_handoff"] = "manager_handoff"

    model_config = ConfigDict(extra="ignore")


Artifact = Annotated[
    Union[
        DevTicket,
        ReuseBlueprint,
        DraftTeamsIntro,
        ManagerHandoff,
        RemediationProposal,
        BackfillBlueprint,
    ],
    Field(discriminator="artifact_type"),
]


class _ArtifactWrapper(BaseModel):
    artifact: Artifact


def parse_artifact(payload: dict) -> BaseModel:
    """Parse + discriminate an artifact payload (raises on invalid)."""
    return _ArtifactWrapper(artifact=payload).artifact


# ── deterministic remediation gates ──────────────────────────────────────────

# Tables that are configuration, not business data. A remediation targeting
# one of these is a configuration change in disguise (out-of-scope).
CONFIGURATION_TABLES = frozenset(
    {
        "workflow",
        "savedquery",
        "userquery",
        "systemform",
        "role",
        "fieldsecurityprofile",
        "fieldpermission",
        "solution",
        "publisher",
        "sdkmessageprocessingstep",
        "plugintype",
        "pluginassembly",
        "environmentvariabledefinition",
        "environmentvariablevalue",
        "connectionreference",
        "webresource",
        "sitemap",
        "appmodule",
        "businessunit",
        "team",
        "systemuser",
    }
)

REMEDIATION_CONFIDENCE_FLOOR = 0.8  # configurable


def validate_artifact_payload(
    intent: str,
    payload: dict,
    *,
    user_referenced_document: bool = False,
) -> tuple[dict | None, dict | None]:
    """The remediation offer gate, deterministic. Returns (artifact, refusal).

    Exactly one of the pair is non-None. ``refusal`` is machine-readable:
    ``{"refused": <reason>, "use_instead": <artifact_type or None>}`` so the
    drafting agent can pivot instead of arguing.
    """

    def _refuse(reason: str, use_instead: str | None = None) -> tuple[None, dict]:
        return None, {"refused": reason, "use_instead": use_instead}

    try:
        artifact = parse_artifact(payload)
    except Exception as exc:
        return _refuse(f"artifact failed schema validation: {exc}")

    if isinstance(artifact, RemediationProposal):
        # DIAGNOSE-only. VALIDATE never executes ideas.
        if intent != "DIAGNOSE":
            return _refuse(
                "remediation is DIAGNOSE-only; VALIDATE proposals are never "
                "executed",
                use_instead="manager_handoff",
            )
        # Per-record only. Updates need ONE concrete record id; creates must
        # NOT carry one (the platform mints it - a supplied id smells like a
        # disguised upsert).
        if artifact.operation == "update" and not artifact.record_id.strip():
            return _refuse(
                "remediation_proposal requires a single concrete record_id; "
                "for multiple records produce a backfill_blueprint",
                use_instead="backfill_blueprint",
            )
        if artifact.operation == "create":
            if artifact.record_id.strip():
                return _refuse(
                    "a create proposal must not carry a record_id - the "
                    "platform mints it; to change an existing record use "
                    "operation='update'"
                )
            # Creates are diagnosis-grounded ONLY: a document can never seed a
            # new row, and every column needs a concrete value (options are a
            # preview affordance for updates).
            if artifact.evidence_source != "diagnosis":
                return _refuse(
                    "create proposals must be diagnosis-grounded - the failed "
                    "automation's own parameters define the payload; a "
                    "document cannot seed a new row"
                )
            for ch in artifact.changes:
                if ch.proposed_value is None:
                    return _refuse(
                        f"create proposal: no concrete value for column "
                        f"'{ch.column}' - every column of a new row must come "
                        "from the diagnosis evidence"
                    )
        # Out-of-scope: configuration changes in disguise.
        if artifact.record_table.lower() in CONFIGURATION_TABLES:
            return _refuse(
                f"'{artifact.record_table}' is configuration, not business "
                "data; configuration changes are out of remediation scope "
                "- raise a dev ticket / handoff instead",
                use_instead="dev_ticket",
            )
        # Confidence floor.
        if artifact.diagnosis_confidence < REMEDIATION_CONFIDENCE_FLOOR:
            return _refuse(
                f"diagnosis confidence {artifact.diagnosis_confidence:.2f} is "
                f"below the {REMEDIATION_CONFIDENCE_FLOOR} offer floor "
                "- hand off instead of offering a write",
                use_instead="manager_handoff",
            )
        # No hallucinated values - every change needs a proposed value or
        # explicit options; evidence silent => no proposal.
        for ch in artifact.changes:
            if ch.proposed_value is None and not ch.options:
                return _refuse(
                    f"no proposed value for column '{ch.column}' and no "
                    "options - the evidence is silent on this field, so no "
                    "write may be proposed (no hallucinated values)"
                )
        if not artifact.changes:
            return _refuse("remediation_proposal carries no field changes")
        # Document-grounded discipline.
        # NOTE: this branch is currently reached only by the CLI (single_agent)
        # and the test suite. The live unified surface
        # (server.propose_record_fix) is diagnosis-only by choice, so it never
        # sends evidence_source="document". The gate is kept complete so the
        # path is ready to wire on - but `user_referenced_document` arrives from
        # the caller, and wiring document-grounding into the live agent must
        # FIRST make that determination server-side (it cannot be a value the
        # model asserts about itself). See server.propose_record_fix for why.
        if artifact.evidence_source == "document":
            if not user_referenced_document:
                return _refuse(
                    "document-grounded proposal but the user did not "
                    "explicitly reference a document in the current turn - "
                    "agent-initiated document retrieval cannot seed a write; "
                    "refused outright"
                )
            if not (artifact.document_name and artifact.source_span):
                return _refuse(
                    "document-grounded proposal must carry document_name and "
                    "the exact source_span for the preview pane"
                )

    if isinstance(artifact, BackfillBlueprint):
        if not artifact.idempotency_note.strip():
            return _refuse(
                "backfill_blueprint requires an idempotency note - the "
                "update must be a no-op if a downstream flow has since "
                "corrected the record"
            )
        if not artifact.query.strip():
            return _refuse("backfill_blueprint requires the identifying query")

    if isinstance(artifact, ManagerHandoff):
        if not artifact.draft_text.strip():
            return _refuse("manager_handoff requires draft_text")

    return artifact.model_dump(), None
