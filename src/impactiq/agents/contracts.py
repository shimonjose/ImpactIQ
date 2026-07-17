"""Finding contracts - the inter-agent protocol.

Specialists never see each other's raw context; only the adjudicator sees
all findings. ``ActiveWork`` is the disclosable tier ONLY: there is no field
that can carry the substance of another team's work - the disclosure
boundary is enforced structurally, not by trusting the model to omit.

All models are deliberately lenient (defaults + extra="ignore") - drafting
models drift on nested required fields, and a sparse finding is less useful
but never unsafe.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..report.schema import Citation, NodeRef, RiskOut


def _coerce_noderef_list(v: object) -> object:
    if not isinstance(v, list):
        return v
    out = []
    for item in v:
        if isinstance(item, str):
            out.append({"id": item, "kind": "Reference", "name": item})
        else:
            out.append(item)
    return out


class RecentChange(BaseModel):
    component: NodeRef | None = None
    modified_on: str | None = None
    modified_by: str | None = None
    days_ago: int | None = None

    model_config = ConfigDict(extra="ignore")


class TechnicalFinding(BaseModel):
    likely_cause: str | None = None          # diagnose
    blast_radius: list[NodeRef] = Field(default_factory=list)   # validate
    impacted_components: list[NodeRef] = Field(default_factory=list)
    causal_neighbour_count: int = 0
    structural_neighbour_count: int = 0
    recent_editors: list[RecentChange] = Field(default_factory=list)
    raw_risk: RiskOut | None = None
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)

    model_config = ConfigDict(extra="ignore")

    _coerce = field_validator("blast_radius", "impacted_components", mode="before")(
        classmethod(lambda cls, v: _coerce_noderef_list(v))
    )


class KnowledgeFinding(BaseModel):
    governance_verdict: Literal[
        "defect", "expected_per_policy", "aligned", "conflicts_with_standard",
        "no_applicable_policy",
    ] = "no_applicable_policy"
    rationale: str = ""
    citations: list[Citation] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)

    model_config = ConfigDict(extra="ignore")


class ActiveWork(BaseModel):
    """Disclosable tier ONLY - no field can carry substance."""

    component: NodeRef | None = None
    owner_or_team: str = ""
    sensitivity: Literal["open", "restricted", "unknown"] = "unknown"
    has_activity: bool = False

    model_config = ConfigDict(extra="ignore")


class ContextFinding(BaseModel):
    affected_people: list[str] = Field(default_factory=list)
    likely_owner: str | None = None
    live_signals: list[str] = Field(default_factory=list)        # diagnose
    active_change_signals: list[ActiveWork] = Field(default_factory=list)
    # Active directives that gate making changes right now - ANY kind: a
    # freeze/moratorium, an approval/sign-off gate, a change board (CAB), a
    # release embargo/blackout, an incident no-deploy window, an audit hold;
    # whatever the wording. These gate whether ANY change should proceed, so
    # they're tracked separately from component-overlap signals and weighted as
    # blockers (current-only - a lifted/granted/cleared one does not belong here).
    change_control: list[str] = Field(default_factory=list)
    informal_workaround: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)

    model_config = ConfigDict(extra="ignore")


class SpecialistResult(BaseModel):
    """Envelope a specialist run hands to the adjudicator."""

    agent: Literal["technical", "knowledge", "context"]
    status: Literal["ok", "error", "skipped"] = "ok"
    finding: dict | None = None     # the parsed Finding (loose at the seam)
    error: str | None = None
    raw_text: str = ""
    citations: list[dict] = Field(default_factory=list)
    tool_call_count: int = 0
    tool_names: list[str] = Field(default_factory=list)
    elapsed_seconds: float = 0.0

    model_config = ConfigDict(extra="ignore")


class OrchestratorPlan(BaseModel):
    """Output of the orchestrator: intent + anchor + dispatch decisions."""

    intent: Literal["DIAGNOSE", "VALIDATE"] = "DIAGNOSE"
    anchor: NodeRef | None = None
    # Which specialists to dispatch. Orchestrator may skip Context for a
    # pure-architecture validate; Technical is always on.
    specialists: list[Literal["technical", "knowledge", "context"]] = Field(
        default_factory=lambda: ["technical", "knowledge", "context"]
    )
    notes: str = ""

    model_config = ConfigDict(extra="ignore")
