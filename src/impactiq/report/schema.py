"""ImpactReport — the system's output contract.

The `generated_artifact` field is optional and populated by the artifact
generators. Citations default to an empty list until the Knowledge agent
supplies them.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class NodeRef(BaseModel):
    id: str
    kind: str
    name: str

    model_config = ConfigDict(extra="ignore")


class RiskOut(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Literal["low", "medium", "high"]
    reasons: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class Evidence(BaseModel):
    kind: str
    detail: str

    model_config = ConfigDict(extra="ignore")


class Collision(BaseModel):
    component: NodeRef
    who: str | None = None
    sensitivity: Literal["open", "restricted", "unknown"] = "unknown"
    advice: str = ""

    model_config = ConfigDict(extra="ignore")


class Citation(BaseModel):
    """Source reference. Populated by the Knowledge agent."""

    source_id: str
    title: str | None = None
    url: str | None = None

    model_config = ConfigDict(extra="ignore")


class ImpactReport(BaseModel):
    """The single answer object every turn produces."""

    intent: Literal["DIAGNOSE", "VALIDATE"]
    # `anchor` may be None when the engine honestly couldn't resolve one - the
    # design discipline: say so, don't fabricate.
    anchor: NodeRef | None = None
    verdict: str
    confidence: float = Field(ge=0.0, le=1.0)
    reconciliation: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    impacted_components: list[NodeRef] = Field(default_factory=list)
    affected_teams: list[str] = Field(default_factory=list)
    # People awaiting or impacted by the outcome a failure swallowed — ANYONE
    # (a customer, a colleague, an internal user); tag the role in parentheses
    # when known, e.g. "(customer)" / "(colleague)". Carried from the context
    # check so the answer can name who's waiting and offer a reply/follow-up.
    # Distinct from `affected_teams` (structural change-coordination).
    affected_people: list[str] = Field(default_factory=list)
    risk: RiskOut
    recommendation: str
    interim_actions: list[str] = Field(default_factory=list)
    existing_equivalents: list[NodeRef] = Field(default_factory=list)
    change_collisions: list[Collision] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    # The generated artifact. Kept as a loose dict at the report boundary so an
    # artifact-shaped hiccup can't invalidate the whole report; the TYPED
    # layer (report/artifacts.py) is enforced upstream by the
    # `validate_artifact` tool gate, and downstream by `cli artifact inspect`
    # / the card renderer, which parse it strictly.
    generated_artifact: dict | None = None

    model_config = ConfigDict(extra="ignore")

    @field_validator("existing_equivalents", "impacted_components", mode="before")
    @classmethod
    def _coerce_string_to_noderef(cls, v: object) -> object:
        """Models sometimes pass plain strings for NodeRef-typed lists
        (e.g. an SOP title in `existing_equivalents`). Coerce string -> NodeRef
        placeholder so the report still validates."""
        if not isinstance(v, list):
            return v
        out = []
        for item in v:
            if isinstance(item, str):
                out.append({"id": item, "kind": "Reference", "name": item})
            else:
                out.append(item)
        return out

    @field_validator("change_collisions", mode="before")
    @classmethod
    def _coerce_collisions(cls, v: object) -> object:
        """Models drift on Collision shape: `component` as a plain string,
        and `owner` instead of `who`. Coerce both so the report validates."""
        if not isinstance(v, list):
            return v
        out = []
        for item in v:
            if isinstance(item, dict):
                item = dict(item)
                comp = item.get("component")
                if isinstance(comp, str):
                    item["component"] = {"id": comp, "kind": "Reference", "name": comp}
                elif comp is None:
                    # Model flattened the NodeRef into the collision itself,
                    # under assorted key spellings (id / component_id, ...).
                    cid = item.get("id") or item.get("component_id")
                    if cid:
                        name = (
                            item.get("name")
                            or item.get("component_name")
                            or cid
                        )
                        kind = (
                            item.get("kind")
                            or item.get("component_kind")
                            or "Reference"
                        )
                        item["component"] = {
                            "id": str(cid),
                            "kind": str(kind),
                            "name": str(name),
                        }
                if "who" not in item and isinstance(item.get("owner"), str):
                    item["who"] = item["owner"]
            out.append(item)
        return out

    @field_validator("affected_teams", "interim_actions", mode="before")
    @classmethod
    def _coerce_dict_to_string(cls, v: object) -> object:
        """Models sometimes pass {"name": "X"} dicts where a plain string is
        wanted (typically for affected_teams). Pull the obvious string field
        out so the report still validates."""
        if not isinstance(v, list):
            return v
        out = []
        for item in v:
            if isinstance(item, dict):
                # Pick the most useful string field if present.
                for key in ("name", "team", "title", "id"):
                    if isinstance(item.get(key), str):
                        out.append(item[key])
                        break
                else:
                    out.append(str(item))
            else:
                out.append(item)
        return out
