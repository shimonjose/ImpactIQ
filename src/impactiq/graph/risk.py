"""Explainable risk scorer.

Pure function. Every contribution to the score is recorded in ``reasons`` so
the report can print *why* a number landed where it did. The numbers are
heuristic; the discipline is that they are reproducible and reviewable.

The formula (informal):

    risk = f(#downstream_components, #affected_teams, mandatory_changes,
             managed_layer_conflicts, flows_that_write_without_new_field,
             active_change_collisions)

**Causal vs structural neighbours.** A walked node connected to the anchor
*only* through containment relations (``has_column``, ``in_solution``,
``member_of``) is **structural** — it's grouped with the anchor, not impacted
by changes around the anchor. A node touched by any causal relation
(``writes_to``, ``reads_from``, ``references``, ``triggered_by``,
``secured_by``, ``surfaces``, ``mandatory_on``, ``depends_on``) is **causal**.
Only causal neighbours count toward "impacted components" and risk. Counting
a table's own columns as "impacted by adding a sibling column" is the bug
this distinction exists to prevent.
"""

from __future__ import annotations

from .model import Risk, RiskLevel, SubGraph


# Relations that group nodes together without implying impact propagation.
CONTAINMENT_RELATIONS = frozenset({"has_column", "in_solution", "member_of"})


def classify_neighbours(subgraph: SubGraph) -> tuple[set[str], set[str]]:
    """Partition the subgraph's non-anchor nodes into (causal, structural).

    A node is *causal* if any walked edge incident on it uses a non-containment
    relation. A node connected to the anchor's neighbourhood only through
    containment is *structural*.
    """
    causal_ids: set[str] = set()
    for w in subgraph.walked_edges:
        if w.relation in CONTAINMENT_RELATIONS:
            continue
        causal_ids.add(w.from_)
        causal_ids.add(w.to)
    causal_ids.discard(subgraph.anchor.id)

    all_ids = {n.id for n in subgraph.nodes if n.id != subgraph.anchor.id}
    causal_ids &= all_ids  # only nodes actually in the subgraph
    structural_ids = all_ids - causal_ids
    return causal_ids, structural_ids


# Weights are tunable; explicit constants beat magic numbers in the body.
_W_PER_COMPONENT = 2
_CAP_FROM_COMPONENTS = 40
_W_PER_TEAM = 5
_CAP_FROM_TEAMS = 25
_W_PER_FLOW = 4
_CAP_FROM_FLOWS = 20
_W_PER_MANDATORY_CHANGE = 12
_W_PER_COLLISION = 8
_CAP_FROM_COLLISIONS = 30
_W_MANAGED_CONFLICT = 10


def _level(score: int) -> RiskLevel:
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def score(
    subgraph: SubGraph,
    *,
    mandatory_changes: int = 0,
    managed_layer_conflicts: int = 0,
    flows_writing_without_new_field: int = 0,
    active_change_collisions: int = 0,
    affected_teams: int | None = None,
) -> Risk:
    """Score the SubGraph + the supplied side-channel counts.

    ``affected_teams``: caller supplies; if ``None`` we count Team nodes in the
    subgraph as an approximation.
    """
    reasons: list[str] = []
    total = 0

    causal_ids, structural_ids = classify_neighbours(subgraph)

    # 1. Blast-radius size — CAUSAL neighbours only. Structural neighbours
    #    (containment) are recorded for context but do NOT contribute to risk.
    n_causal = len(causal_ids)
    n_structural = len(structural_ids)
    component_pts = min(n_causal * _W_PER_COMPONENT, _CAP_FROM_COMPONENTS)
    if n_causal:
        reasons.append(
            f"{n_causal} causal neighbour(s) in the {subgraph.depth}-hop "
            f"radius (+{component_pts}) - flows / surfaces / roles / "
            f"references that touch the anchor"
        )
    if n_structural:
        # Honest accounting: surface the structural count but score it 0.
        reasons.append(
            f"{n_structural} structural neighbour(s) (containment only - "
            f"the anchor's own columns / solution components / team "
            f"memberships); not counted as impact"
        )
    if n_causal == 0 and n_structural == 0:
        reasons.append(
            "anchor has no neighbours within the current scope - the report "
            "covers structural impact only; per-record / data-row impact is "
            "out of scope here (see validated remediation)"
        )
    elif n_causal == 0:
        reasons.append(
            "no causal neighbours in scope - broader downstream effects on "
            "existing data rows are out of scope here"
        )
    total += component_pts

    # 2. Flow density in the radius (causal subset only).
    flow_count = sum(
        1
        for n in subgraph.nodes
        if n.kind == "Flow" and n.id in causal_ids
    )
    if flow_count:
        flow_pts = min(flow_count * _W_PER_FLOW, _CAP_FROM_FLOWS)
        reasons.append(f"{flow_count} flow(s) in the causal radius (+{flow_pts})")
        total += flow_pts

    # 3. Affected teams.
    if affected_teams is None:
        affected_teams = sum(1 for n in subgraph.nodes if n.kind == "Team")
    if affected_teams:
        team_pts = min(affected_teams * _W_PER_TEAM, _CAP_FROM_TEAMS)
        reasons.append(f"{affected_teams} affected team(s) (+{team_pts})")
        total += team_pts

    # 4. Structural changes that propagate widely.
    if mandatory_changes:
        m_pts = mandatory_changes * _W_PER_MANDATORY_CHANGE
        reasons.append(
            f"{mandatory_changes} mandatory-column change(s) (+{m_pts}) - "
            f"every existing writer must be checked"
        )
        total += m_pts

    if managed_layer_conflicts:
        c_pts = managed_layer_conflicts * _W_MANAGED_CONFLICT
        reasons.append(
            f"{managed_layer_conflicts} managed-layer conflict(s) (+{c_pts})"
        )
        total += c_pts

    if flows_writing_without_new_field:
        f_pts = flows_writing_without_new_field * _W_PER_FLOW
        reasons.append(
            f"{flows_writing_without_new_field} existing writer(s) miss the "
            f"new field (+{f_pts}) - VALIDATE 'unset rows after deploy' risk"
        )
        total += f_pts

    # 5. Active change collisions.
    if active_change_collisions:
        col_pts = min(active_change_collisions * _W_PER_COLLISION, _CAP_FROM_COLLISIONS)
        reasons.append(
            f"{active_change_collisions} active change collision(s) (+{col_pts}) - "
            f"another team is mid-change on something in the radius"
        )
        total += col_pts

    total = max(0, min(100, total))
    return Risk(score=total, level=_level(total), reasons=reasons)
