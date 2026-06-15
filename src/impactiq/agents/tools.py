"""Engine functions as prompt-agent FunctionTool definitions + dispatch.

In the **prompt-agent** runtime (`PromptAgentDefinition`), `FunctionTool`
schemas are explicit JSON — Python signature introspection isn't used. The
runtime is also responsible for executing the function (no
``enable_auto_function_calls`` in the new path), so this module exposes
**two** things per tool:

* a ``FunctionTool`` JSON definition for the agent to see, and
* a ``Callable[[dict], str]`` for the runtime to dispatch to.

Both come from a single ``EngineToolSpec`` so they can't drift.

The implementations close over a ``ToolContext`` (pre-warmed graph + the
read-only Dataverse client) — the estate is never re-crawled inside a turn.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass

from azure.ai.projects.models import FunctionTool

from ..connectors.base import EstateScope
from ..connectors.flows import FlowsConnector
from ..connectors.solutions import SolutionsConnector
from ..dataverse_client import DataverseClient
from ..graph import (
    ImpactGraph,
    diagnose_permission as _diagnose_permission,
    recent_change_scan as _recent_change_scan,
    resolve_anchor as _resolve_anchor,
    score as _score_risk,
    walk as _walk,
)
from ..graph.risk import classify_neighbours
from ..report.artifacts import validate_artifact_payload
from .url_resolve import parse_powerapps_url


# Cloud-flow state is two Dataverse option-sets; translate to plain words so
# the agent can say "on" / "off" instead of leaking raw codes.
def _norm(s: str | None) -> str:
    """Normalize a name for fuzzy matching: lowercase, strip non-alphanumerics
    and the leading publisher prefix. So a user's display name (e.g. "My Table")
    matches the logical name "prefix_mytable" ("mytable" ⊂ "prefixmytable")."""
    import re as _re

    if not s:
        return ""
    return _re.sub(r"[^a-z0-9]", "", s.lower())


def _name_matches(query: str, candidate: str | None) -> bool:
    q, c = _norm(query), _norm(candidate)
    return bool(q and c and (q in c or c in q))


def _flow_state_label(metadata: dict) -> str:
    state = metadata.get("statecode")
    status = metadata.get("statuscode")
    # workflow.statecode: 0 = Draft (off), 1 = Activated (on).
    if state == 1:
        return "on (activated)"
    if state == 0:
        return "off (draft / turned off)"
    if status is not None:
        return f"unknown (statuscode={status})"
    return "unknown"


@dataclass
class ToolContext:
    """Per-turn shared state — read-only by construction."""

    client: DataverseClient
    scope: EstateScope
    graph: ImpactGraph
    # The signed-in user's On-Behalf-Of assertion, when hosted — needed for the
    # reads that require a delegated token (e.g. the Power Automate run-forensics
    # API behind flow_run_details). None locally (the CLI uses browser sign-in).
    user_assertion: str | None = None


@dataclass
class EngineToolSpec:
    """One engine tool: agent-facing schema + local implementation."""

    name: str
    description: str
    parameters: dict
    impl: Callable[[dict], str]

    def to_function_tool(self) -> FunctionTool:
        return FunctionTool(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
            # Optional parameters need leniency; strict=True forces every
            # property into `required`, which is awkward for depth/threshold-
            # style optional knobs. The dispatch helper coerces missing values.
            strict=False,
        )


# Defensive int coercion at the dispatch boundary — the model occasionally
# emits numeric args as strings.
def _i(v: object, default: int) -> int:
    try:
        if v is None:
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def _err(message: str) -> str:
    return json.dumps({"error": message})


def build_engine_tool_specs(ctx: ToolContext) -> dict[str, EngineToolSpec]:
    """Build every engine tool spec, keyed by name.

    Tool ownership: callers select subsets via :func:`select_engine_tools` —
    estate/graph specs go to the Technical specialist, ``validate_artifact`` to
    the Adjudicator; the single-agent baseline takes everything.
    """
    sols = SolutionsConnector(ctx.client)
    flows_conn = FlowsConnector(ctx.client)

    # ------------------------------------------------------------------
    # 1. resolve_anchor
    # ------------------------------------------------------------------
    def _resolve_anchor_impl(args: dict) -> str:
        query = str(args.get("query") or "").strip()
        if not query:
            return _err("query is required")
        candidates = _resolve_anchor(query, ctx.graph)[:10]
        out = []
        for n in candidates:
            row = {"id": n.id, "kind": n.kind, "name": n.name, "raw_ref": n.raw_ref}
            # Tables carry their Dataverse LOGICAL name explicitly (the id is
            # "t:<logical>") so record-query tools can be chained directly.
            if n.kind == "Table" and n.id.startswith("t:"):
                row["logical_name"] = n.id[2:]
            out.append(row)
        return json.dumps(out)

    resolve_anchor_spec = EngineToolSpec(
        name="resolve_anchor",
        description=(
            "Find candidate anchor nodes in the estate that match a free-text "
            "query. Use a SHORT identifier (e.g. 'account', 'request.status', "
            "a flow name) - not full sentences. Returns up to 10 ranked "
            "candidates as JSON array of {id, kind, name, raw_ref}."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Short identifier (logical name, column, flow name, or substring).",
                }
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        impl=_resolve_anchor_impl,
    )

    # ------------------------------------------------------------------
    # 2. walk_anchor (the dependency-walk primary move)
    # ------------------------------------------------------------------
    def _walk_anchor_impl(args: dict) -> str:
        anchor_id = str(args.get("anchor_id") or "")
        depth = _i(args.get("depth"), 2)
        anchor = ctx.graph.node(anchor_id)
        if not anchor:
            return _err(f"unknown anchor: {anchor_id}")
        sub = _walk(ctx.graph, anchor, intent="DIAGNOSE", direction="both", depth=depth)
        by_kind = sub.nodes_by_kind()
        causal_ids, structural_ids = classify_neighbours(sub)
        return json.dumps(
            {
                "anchor": {"id": anchor.id, "kind": anchor.kind, "name": anchor.name},
                "depth": depth,
                "causal_neighbour_count": len(causal_ids),
                "structural_neighbour_count": len(structural_ids),
                "note_on_counts": (
                    "Use `causal_neighbour_count` as 'impacted components'. "
                    "Structural neighbours (the anchor's own columns / solution "
                    "components / memberships) are NOT impacted by changes "
                    "around the anchor. Per-record (data row) impact is out "
                    "of phase-3 scope."
                ),
                "node_count": len(sub.nodes),
                "edge_count": len(sub.walked_edges),
                "nodes_by_kind": {k: len(v) for k, v in by_kind.items()},
                "causal_nodes": [
                    {
                        "id": n.id,
                        "kind": n.kind,
                        "name": n.name,
                        # Flow on/off status travels with the node so the agent
                        # can confirm "this automation is live" without guessing.
                        **(
                            {"flow_status": _flow_state_label(n.metadata)}
                            if n.kind == "Flow"
                            else {}
                        ),
                    }
                    for n in sub.nodes
                    if n.id in causal_ids
                ][:60],
                "structural_nodes_sample": [
                    {"id": n.id, "kind": n.kind, "name": n.name}
                    for n in sub.nodes
                    if n.id in structural_ids
                ][:10],
                "edges": [
                    {
                        "from": w.from_,
                        "rel": w.relation,
                        "to": w.to,
                        "direction": w.direction,
                        "hop": w.hop,
                    }
                    for w in sub.walked_edges
                ][:80],
            }
        )

    walk_anchor_spec = EngineToolSpec(
        name="walk_anchor",
        description=(
            "Walk the §4.0 dependency neighbourhood around an anchor (both "
            "directions, depth-bounded). ALWAYS call this on any anchor before "
            "reasoning. Returns causal vs structural neighbour counts + node "
            "lists. Causal = impacted (writes_to / references / secured_by); "
            "structural = grouping only (has_column / in_solution / member_of)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "anchor_id": {
                    "type": "string",
                    "description": "Canonical node id from resolve_anchor (e.g. 'table:account').",
                },
                "depth": {
                    "type": "integer",
                    "description": "BFS depth (default 2; only use 3 when explicitly thorough).",
                },
            },
            "required": ["anchor_id"],
            "additionalProperties": False,
        },
        impl=_walk_anchor_impl,
    )

    # ------------------------------------------------------------------
    # 3-5. dependency primitives (live, GUID-anchored)
    # ------------------------------------------------------------------
    def _normalize_dep_rows(rows: list[dict]) -> list[dict]:
        return [
            {
                "dependent_type": r.get("dependentcomponenttype"),
                "dependent_id": r.get("dependentcomponentobjectid"),
                "required_type": r.get("requiredcomponenttype"),
                "required_id": r.get("requiredcomponentobjectid"),
            }
            for r in rows
        ]

    def _retrieve_dependent_impl(args: dict) -> str:
        oid = str(args.get("object_id") or "")
        ctype = _i(args.get("component_type"), 0)
        if not oid:
            return _err("object_id required")
        try:
            rows = sols.retrieve_dependent_components(oid, ctype)
        except Exception as exc:
            return _err(f"{type(exc).__name__}: {exc}")
        return json.dumps(_normalize_dep_rows(rows))

    def _retrieve_required_impl(args: dict) -> str:
        oid = str(args.get("object_id") or "")
        ctype = _i(args.get("component_type"), 0)
        if not oid:
            return _err("object_id required")
        try:
            rows = sols.retrieve_required_components(oid, ctype)
        except Exception as exc:
            return _err(f"{type(exc).__name__}: {exc}")
        return json.dumps(_normalize_dep_rows(rows))

    def _retrieve_for_delete_impl(args: dict) -> str:
        oid = str(args.get("object_id") or "")
        ctype = _i(args.get("component_type"), 0)
        if not oid:
            return _err("object_id required")
        try:
            rows = sols.retrieve_dependencies_for_delete(oid, ctype)
        except Exception as exc:
            return _err(f"{type(exc).__name__}: {exc}")
        return json.dumps(_normalize_dep_rows(rows))

    _dep_params = {
        "type": "object",
        "properties": {
            "object_id": {
                "type": "string",
                "description": "GUID of the solution component.",
            },
            "component_type": {
                "type": "integer",
                "description": "componenttype enum (1=Entity, 2=Attribute, 29=Workflow, etc.).",
            },
        },
        "required": ["object_id", "component_type"],
        "additionalProperties": False,
    }

    retrieve_dependent_spec = EngineToolSpec(
        name="retrieve_dependent_components",
        description=(
            "§3.3 downstream — components that DEPEND ON (object_id, "
            "component_type). Use when probing a specific GUID directly; "
            "prefer walk_anchor when the anchor is already in the graph."
        ),
        parameters=_dep_params,
        impl=_retrieve_dependent_impl,
    )

    retrieve_required_spec = EngineToolSpec(
        name="retrieve_required_components",
        description=(
            "§3.3 upstream — components this one DEPENDS ON. Use when probing "
            "a specific GUID directly."
        ),
        parameters=_dep_params,
        impl=_retrieve_required_impl,
    )

    retrieve_for_delete_spec = EngineToolSpec(
        name="retrieve_dependencies_for_delete",
        description=(
            "§3.3 delete-blockers — what would prevent removing this "
            "component. Useful for VALIDATE on a retire/refactor proposal."
        ),
        parameters=_dep_params,
        impl=_retrieve_for_delete_impl,
    )

    # ------------------------------------------------------------------
    # 6. recent_change_scan
    # ------------------------------------------------------------------
    def _recent_change_impl(args: dict) -> str:
        anchor_id = str(args.get("anchor_id") or "")
        depth = _i(args.get("depth"), 2)
        threshold_days = _i(args.get("threshold_days"), 14)
        anchor = ctx.graph.node(anchor_id)
        if not anchor:
            return _err(f"unknown anchor: {anchor_id}")
        sub = _walk(ctx.graph, anchor, intent="VALIDATE", direction="both", depth=depth)
        hits = _recent_change_scan(sub, threshold_days=threshold_days)
        return json.dumps(
            [
                {
                    "component": {
                        "id": h.component.id,
                        "kind": h.component.kind,
                        "name": h.component.name,
                    },
                    "modified_on": h.modified_on,
                    "modified_by_id": h.modified_by_id,
                    "days_ago": h.days_ago,
                }
                for h in hits
            ]
        )

    recent_change_spec = EngineToolSpec(
        name="recent_change_scan",
        description=(
            "§4.1a estate-side change-collision scan — recently-edited "
            "components in the anchor's blast radius. Use on VALIDATE to flag "
            "potential collisions (another team mid-change on something the "
            "proposed change would touch)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "anchor_id": {"type": "string"},
                "depth": {"type": "integer"},
                "threshold_days": {"type": "integer", "description": "Window in days (default 14)."},
            },
            "required": ["anchor_id"],
            "additionalProperties": False,
        },
        impl=_recent_change_impl,
    )

    # ------------------------------------------------------------------
    # 7. diagnose_permission
    # ------------------------------------------------------------------
    def _diagnose_permission_impl(args: dict) -> str:
        user_id = str(args.get("user_id") or "")
        table_logical = str(args.get("table_logical") or "")
        action = str(args.get("action") or "")
        if not (user_id and table_logical and action):
            return _err("user_id, table_logical, action all required")
        try:
            diag = _diagnose_permission(
                user_id=user_id,
                table_logical=table_logical,
                action=action,  # type: ignore[arg-type]
                client=ctx.client,
            )
        except Exception as exc:
            return _err(f"diagnosis failed: {type(exc).__name__}: {exc}")
        return json.dumps(
            {
                "user_id": diag.user_id,
                "table": diag.table_logical,
                "action": diag.action,
                "granted": diag.granted,
                "likely_cause": diag.likely_cause,
                "user_roles": diag.user_roles,
                "relevant_privileges": diag.relevant_privileges,
                "field_security_blockers": diag.field_security_blockers,
                "recommended_fix": diag.recommended_fix,
            }
        )

    diagnose_permission_spec = EngineToolSpec(
        name="diagnose_permission",
        description=(
            "§4.2 permissions diagnosis - why can/can't a user perform an "
            "action on a table. Returns granted flag + likely cause + "
            "recommended fix."
        ),
        parameters={
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "systemuserid GUID."},
                "table_logical": {"type": "string", "description": "Table logical name."},
                "action": {
                    "type": "string",
                    "description": "One of create, read, write, delete, append, appendto, assign, share.",
                },
            },
            "required": ["user_id", "table_logical", "action"],
            "additionalProperties": False,
        },
        impl=_diagnose_permission_impl,
    )

    # ------------------------------------------------------------------
    # 8. score_risk
    # ------------------------------------------------------------------
    def _score_risk_impl(args: dict) -> str:
        anchor_id = str(args.get("anchor_id") or "")
        depth = _i(args.get("depth"), 2)
        mandatory_changes = _i(args.get("mandatory_changes"), 0)
        active_change_collisions = _i(args.get("active_change_collisions"), 0)
        anchor = ctx.graph.node(anchor_id)
        if not anchor:
            return _err(f"unknown anchor: {anchor_id}")
        sub = _walk(ctx.graph, anchor, intent="VALIDATE", direction="both", depth=depth)
        risk = _score_risk(
            sub,
            mandatory_changes=mandatory_changes,
            active_change_collisions=active_change_collisions,
        )
        return json.dumps(
            {"score": risk.score, "level": risk.level, "reasons": risk.reasons}
        )

    score_risk_spec = EngineToolSpec(
        name="score_risk",
        description=(
            "Explainable risk scorer (architecture §4). Counts CAUSAL "
            "neighbours only; structural neighbours are reported but not "
            "scored. Reasons list is printed in the final report."
        ),
        parameters={
            "type": "object",
            "properties": {
                "anchor_id": {"type": "string"},
                "depth": {"type": "integer"},
                "mandatory_changes": {"type": "integer"},
                "active_change_collisions": {"type": "integer"},
            },
            "required": ["anchor_id"],
            "additionalProperties": False,
        },
        impl=_score_risk_impl,
    )

    # ------------------------------------------------------------------
    # 9. find_failed_flows (diagnose entry point)
    # ------------------------------------------------------------------
    def _find_failed_flows_impl(args: dict) -> str:
        hours = _i(args.get("hours"), 24)
        try:
            rows = flows_conn.list_failed_runs(hours=hours)
        except Exception as exc:
            return _err(f"flowrun read failed: {type(exc).__name__}: {exc}")
        return json.dumps(
            [
                {
                    "starttime": r.get("starttime"),
                    "workflow_id": r.get("_workflow_value"),
                    "errorcode": r.get("errorcode"),
                    "errormessage": (r.get("errormessage") or "")[:300],
                }
                for r in rows[:30]
            ]
        )

    find_failed_flows_spec = EngineToolSpec(
        name="find_failed_flows",
        description=(
            "List recent FAILED cloud-flow runs (§3.2.2 diagnose entry "
            "point). Returns starttime, workflow id, error code, error "
            "message excerpt."
        ),
        parameters={
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "description": "Lookback window in hours (default 24).",
                }
            },
            "required": [],
            "additionalProperties": False,
        },
        impl=_find_failed_flows_impl,
    )

    # ------------------------------------------------------------------
    # 9b. flow_run_details (maker-grade failure forensics, LIVE env)
    # ------------------------------------------------------------------
    def _flow_run_details_impl(args: dict) -> str:
        workflow_id = str(args.get("workflow_id") or "").strip()
        if not workflow_id:
            return _err(
                "workflow_id is required (find_failed_flows and the walk return it)"
            )
        runs = _i(args.get("runs"), 1)
        # Same forensics reader the sandbox fix path uses — duck-typed over
        # the client, so the LIVE diagnosis gets the identical evidence depth
        # (the run payloads are content: read under the delegated identity).
        from ..builder.executor import failed_run_details
        from ..settings import get_settings

        try:
            details = failed_run_details(
                ctx.client, get_settings(), workflow_id,
                top=min(max(runs, 1), 3), user_assertion=ctx.user_assertion,
            )
        except Exception as exc:  # noqa: BLE001 — forensics degrade, never fail
            return _err(f"run forensics failed: {type(exc).__name__}: {exc}")
        if not details:
            return json.dumps(
                {"failed_runs": [], "note": "no failed runs recorded for this flow"}
            )
        return json.dumps(details)

    flow_run_details_spec = EngineToolSpec(
        name="flow_run_details",
        description=(
            "Maker-grade forensics for a LIVE flow's most recent failed "
            "run(s): the exact action that failed, the platform's real error "
            "response body, the input values the action sent, plus the "
            "trigger's raw outputs and every step's evaluated inputs/outputs "
            "— trace a bad value to the step that produced it. Use AFTER "
            "find_failed_flows (it returns workflow_id) whenever you need "
            "WHY a flow failed, not just that it failed."
        ),
        parameters={
            "type": "object",
            "properties": {
                "workflow_id": {
                    "type": "string",
                    "description": "The flow's workflow id (GUID).",
                },
                "runs": {
                    "type": "integer",
                    "description": "How many recent failed runs to detail (default 1, max 3).",
                },
            },
            "required": ["workflow_id"],
            "additionalProperties": False,
        },
        impl=_flow_run_details_impl,
    )

    # ------------------------------------------------------------------
    # 10. inspect_flow (confident automation confirmation)
    # ------------------------------------------------------------------
    def _inspect_flow_impl(args: dict) -> str:
        query = str(args.get("query") or "").strip().lower()
        if not query:
            return _err("query is required (a flow name or substring)")
        g = ctx.graph
        # Match a flow if the query hits its NAME, or the name of any table it
        # is triggered by / writes to / reads (so a query naming the OUTPUT
        # record finds the flow that creates it, even when the flow's own name
        # is about the trigger instead).
        matches = []
        for n in g.nodes_by_id.values():
            if n.kind != "Flow":
                continue
            if _name_matches(query, n.name) or query in n.id.lower():
                matches.append(n)
                continue
            for _, to_id, _key, _data in g.nx_graph.out_edges(
                n.id, keys=True, data=True
            ):
                target = g.node(to_id)
                if target and _name_matches(query, target.name):
                    matches.append(n)
                    break
        if not matches:
            return json.dumps(
                {
                    "matched_flows": [],
                    "note": (
                        "No cloud flow matched. The automation may be a classic "
                        "workflow, a child flow, or named differently - ask the "
                        "user for the flow's display name or a maker URL."
                    ),
                }
            )
        out = []
        for fnode in matches[:5]:
            writes, reads, triggers, refs = [], [], [], []
            for _, to_id, _key, data in g.nx_graph.out_edges(
                fnode.id, keys=True, data=True
            ):
                rel = data.get("relation")
                target = g.node(to_id)
                tname = target.name if target else to_id
                tkind = target.kind if target else "?"
                entry = {"id": to_id, "kind": tkind, "name": tname}
                if rel == "writes_to":
                    writes.append(entry)
                elif rel == "reads_from":
                    reads.append(entry)
                elif rel == "triggered_by":
                    triggers.append(entry)
                elif rel == "references":
                    refs.append(entry)
            out.append(
                {
                    "id": fnode.id,
                    "name": fnode.name,
                    "status": _flow_state_label(fnode.metadata),
                    "triggered_by": triggers,
                    "creates_or_updates": writes,  # CreateRecord/UpdateRecord targets
                    "reads": reads,
                    "references": refs,
                }
            )
        return json.dumps({"matched_flows": out})

    inspect_flow_spec = EngineToolSpec(
        name="inspect_flow",
        description=(
            "Inspect cloud flow(s) matching a name/substring: on/off status, "
            "what table it is triggered by, and what tables/columns it "
            "CREATES or UPDATES (writes_to) and reads. Use this to confirm "
            "whether an automation exists and is live (e.g. 'does a flow "
            "create a <record> when a <trigger event> occurs?'). If nothing "
            "matches, ask the user for the flow's display name or a URL."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Flow display-name substring, or a word for the record it produces / the event that triggers it.",
                }
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        impl=_inspect_flow_impl,
    )

    # ------------------------------------------------------------------
    # 11. resolve_owner (structural ownership, the authoritative team)
    # ------------------------------------------------------------------
    def _resolve_owner_impl(args: dict) -> str:
        node_id = str(args.get("component_id") or "").strip()
        node = ctx.graph.node(node_id)
        if not node:
            return _err(f"unknown component: {node_id}")
        try:
            if node.kind == "Flow" and node.raw_ref:
                row = ctx.client.get(
                    f"workflows({node.raw_ref})",
                    {
                        "$select": "name",
                        "$expand": (
                            "owninguser($select=fullname,internalemailaddress),"
                            "owningteam($select=name),"
                            "owningbusinessunit($select=name)"
                        ),
                    },
                )
                team = (row.get("owningteam") or {}).get("name")
                user = (row.get("owninguser") or {}).get("fullname")
                bu = (row.get("owningbusinessunit") or {}).get("name")
                return json.dumps(
                    {
                        "component": {"id": node.id, "kind": node.kind, "name": node.name},
                        "owning_team": team,
                        "owning_user": user,
                        "owning_business_unit": bu,
                        "note": (
                            "These are STRUCTURAL owners from Dataverse - the "
                            "authoritative 'who owns this'. Use the team name "
                            "(or business unit, or user) for routing. Do NOT "
                            "use the solution name as a team."
                        ),
                    }
                )
            if node.kind == "Table" and node.raw_ref:
                # Org-owned tables have one owning BU; user/team-owned tables
                # vary by record, so report the ownership model honestly.
                meta = ctx.client.get(
                    f"EntityDefinitions(LogicalName='{node.raw_ref}')",
                    {"$select": "OwnershipType,LogicalCollectionName"},
                )
                return json.dumps(
                    {
                        "component": {"id": node.id, "kind": node.kind, "name": node.name},
                        "ownership_type": meta.get("OwnershipType"),
                        "note": (
                            "Table records are owned per the ownership type; for "
                            "user/team-owned tables the responsible team varies "
                            "by record (use the owning team of specific records, "
                            "or the owners of the flows that write to this table). "
                            "Never invent a team name."
                        ),
                    }
                )
        except Exception as exc:
            return _err(f"owner lookup failed: {type(exc).__name__}: {exc}")
        return json.dumps(
            {"component": {"id": node.id, "kind": node.kind, "name": node.name},
             "note": "no structural owner resolvable for this component kind"}
        )

    resolve_owner_spec = EngineToolSpec(
        name="resolve_owner",
        description=(
            "Resolve the STRUCTURAL owner of an impacted component (the "
            "authoritative 'affected team'): a flow's owning team / user / "
            "business unit, or a table's ownership model. Use this to fill "
            "affected_teams with REAL names from Dataverse - never guess, and "
            "never use the solution name as a team."
        ),
        parameters={
            "type": "object",
            "properties": {
                "component_id": {
                    "type": "string",
                    "description": "Node id from the walk (e.g. 'flow:<guid>' or 'table:<logical>').",
                }
            },
            "required": ["component_id"],
            "additionalProperties": False,
        },
        impl=_resolve_owner_impl,
    )

    # ------------------------------------------------------------------
    # 12. resolve_url (disambiguate from a pasted Power Apps URL)
    # ------------------------------------------------------------------
    def _resolve_url_impl(args: dict) -> str:
        url = str(args.get("url") or "").strip()
        if not url:
            return _err("url is required")
        parsed = parse_powerapps_url(url)
        if not parsed:
            return json.dumps({"parsed": {}, "note": "could not parse this URL"})
        result: dict = {"parsed": parsed}
        etn = parsed.get("entity_logical")
        if etn:
            tnode = ctx.graph.node(f"table:{etn}")
            if tnode:
                result["resolved_table"] = {
                    "id": tnode.id,
                    "kind": tnode.kind,
                    "name": tnode.name,
                }
            else:
                result["resolved_table"] = None
                result["note"] = (
                    f"URL points at entity '{etn}', which isn't in the current "
                    "solution scope - it may live in another solution."
                )
        if parsed.get("record_id"):
            result["record_id"] = parsed["record_id"]
        return json.dumps(result)

    resolve_url_spec = EngineToolSpec(
        name="resolve_url",
        description=(
            "Parse a pasted Power Apps / Dynamics 365 URL into the exact "
            "estate object: entity logical name, record id, view/form id. Use "
            "when the user can't name something precisely and pastes a URL "
            "from their screen. Returns the resolved table node if it's in "
            "scope."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The pasted Power Apps/Dynamics URL."}
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        impl=_resolve_url_impl,
    )

    # ------------------------------------------------------------------
    # 12. validate_artifact (the validated-write offer gate, deterministic)
    # ------------------------------------------------------------------
    def _validate_artifact_impl(args: dict) -> str:
        intent = str(args.get("intent") or "").upper()
        payload = args.get("artifact")
        if not isinstance(payload, dict):
            return _err("artifact must be a JSON object")
        if intent not in ("DIAGNOSE", "VALIDATE"):
            return _err("intent must be DIAGNOSE or VALIDATE")
        user_doc = bool(args.get("user_referenced_document", False))
        artifact, refusal = validate_artifact_payload(
            intent, payload, user_referenced_document=user_doc
        )
        # CLI-phase observability: gate decisions go to stderr so a failing
        # acceptance run shows WHY an artifact was refused.
        if refusal is not None:
            print(
                f"[validate_artifact] REFUSED "
                f"({payload.get('artifact_type')!r}): {refusal['refused']}",
                file=sys.stderr,
                flush=True,
            )
            refusal = dict(refusal)
            refusal["instruction"] = (
                "Fix the issue and call validate_artifact again (redraft as "
                "use_instead if set; otherwise correct the listed fields). "
                "Do NOT fall back to generated_artifact: null after a refusal."
            )
            return json.dumps(refusal)
        print(
            f"[validate_artifact] OK ({payload.get('artifact_type')!r})",
            file=sys.stderr,
            flush=True,
        )
        return json.dumps({"validated": True, "artifact": artifact})

    validate_artifact_spec = EngineToolSpec(
        name="validate_artifact",
        description=(
            "§7.2 offer gate. Validate a drafted artifact (dev_ticket | "
            "reuse_blueprint | draft_teams_intro | manager_handoff | "
            "remediation_proposal | backfill_blueprint) against the safety "
            "bounds BEFORE embedding it in the final report. Returns "
            "{validated, artifact} (use the returned, normalized artifact "
            "verbatim as generated_artifact) or {refused, use_instead} - "
            "if refused, redraft as the suggested type instead of arguing."
        ),
        parameters={
            "type": "object",
            "properties": {
                "intent": {
                    "type": "string",
                    "description": "DIAGNOSE or VALIDATE (this turn's intent).",
                },
                "artifact": {
                    "type": "object",
                    "description": "The drafted artifact payload, including artifact_type.",
                },
                "user_referenced_document": {
                    "type": "boolean",
                    "description": (
                        "True ONLY if the user explicitly attached/named a "
                        "document in the CURRENT turn. Never set true for "
                        "documents you retrieved yourself."
                    ),
                },
            },
            "required": ["intent", "artifact"],
            "additionalProperties": False,
        },
        impl=_validate_artifact_impl,
    )

    specs = [
        resolve_anchor_spec,
        walk_anchor_spec,
        retrieve_dependent_spec,
        retrieve_required_spec,
        retrieve_for_delete_spec,
        recent_change_spec,
        diagnose_permission_spec,
        score_risk_spec,
        find_failed_flows_spec,
        flow_run_details_spec,
        inspect_flow_spec,
        resolve_owner_spec,
        resolve_url_spec,
        validate_artifact_spec,
    ]
    return {s.name: s for s in specs}


# Tool-ownership sets.
TECHNICAL_TOOL_NAMES = (
    "resolve_anchor",
    "walk_anchor",
    "retrieve_dependent_components",
    "retrieve_required_components",
    "retrieve_dependencies_for_delete",
    "recent_change_scan",
    "diagnose_permission",
    "score_risk",
    "find_failed_flows",
    "flow_run_details",
    "inspect_flow",
    "resolve_owner",
    "resolve_url",
)
ORCHESTRATOR_TOOL_NAMES = ("resolve_anchor", "resolve_url")
ADJUDICATOR_TOOL_NAMES = ("validate_artifact",)


def select_engine_tools(
    specs: dict[str, EngineToolSpec], names: tuple[str, ...] | list[str]
) -> tuple[list[FunctionTool], dict[str, Callable[[dict], str]]]:
    """(tool definitions, dispatch map) for a subset of specs by name."""
    chosen = [specs[n] for n in names]
    return [s.to_function_tool() for s in chosen], {s.name: s.impl for s in chosen}


def build_engine_tools(
    ctx: ToolContext,
) -> tuple[list[FunctionTool], dict[str, Callable[[dict], str]]]:
    """All engine tools — the single-agent baseline surface.

    Definitions and dispatch derive from the same specs, so drift between
    "what the agent sees" and "what the runtime calls" is structurally
    impossible.
    """
    specs = build_engine_tool_specs(ctx)
    return select_engine_tools(specs, list(specs))
