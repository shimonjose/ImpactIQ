"""Dependency walk - the engine's primary first move, across four anchor
kinds: ``Column``, ``Flow``, ``View``, ``SecurityRole``.

Each test asserts both:

* **DIAGNOSE suspect population** - the set of components capable of touching
  the anchor (incoming + immediate outgoing neighbours).
* **VALIDATE blast radius** - the components a hypothetical change to the
  anchor would impact.

The walk produces the same data for both intents; the interpretation differs.
The tests reflect that explicitly so a regression in either direction is
caught.
"""

from __future__ import annotations

from impactiq.graph import ImpactGraph, walk


# ---------------------------------------------------------------------------
# Column anchor - the classic "what touches `request.status`?" case
# ---------------------------------------------------------------------------


def test_column_anchor_diagnose_suspect_population(graph: ImpactGraph):
    anchor = graph.node("column:request.status")
    assert anchor is not None
    sub = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)

    ids = sub.node_ids
    # Direct writers of the column.
    assert "flow:close_request" in ids
    # Parent table (via has_column from the table).
    assert "table:request" in ids
    # Field-security profile gating the column.
    assert "fsp:status_fsp" in ids
    # View that references the column.
    assert "view:open_requests" in ids
    # Within depth=2 we also reach assign_owner (via table:request).
    assert "flow:assign_owner" in ids
    # The unrelated contact path is NOT reached.
    assert "table:contact" not in ids
    assert "flow:notify_contact" not in ids


def test_column_anchor_validate_blast_radius_same_set(graph: ImpactGraph):
    """VALIDATE on the same anchor walks the same edges - intent only
    relabels."""
    anchor = graph.node("column:request.status")
    diagnose = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)
    validate = walk(graph, anchor, intent="VALIDATE", direction="both", depth=2)
    assert diagnose.node_ids == validate.node_ids


def test_column_anchor_walked_edges_are_direction_tagged(graph: ImpactGraph):
    """Each WalkedEdge knows whether it was traversed incoming or outgoing -
    confusing the two leads to wrong impact conclusions."""
    anchor = graph.node("column:request.status")
    sub = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)

    # writes_to from flows is INCOMING to the column.
    writers = [w for w in sub.walked_edges
               if w.relation == "writes_to" and w.to == "column:request.status"]
    assert writers
    assert all(w.direction == "incoming" for w in writers)

    # mandatory_on from the column to the table is OUTGOING.
    mandatory = [w for w in sub.walked_edges
                 if w.relation == "mandatory_on" and w.from_ == "column:request.status"]
    assert mandatory
    assert all(w.direction == "outgoing" for w in mandatory)


# ---------------------------------------------------------------------------
# Flow anchor
# ---------------------------------------------------------------------------


def test_flow_anchor_diagnose_surfaces_what_it_touches(graph: ImpactGraph):
    anchor = graph.node("flow:close_request")
    assert anchor is not None
    sub = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)

    ids = sub.node_ids
    # Columns the flow writes.
    assert "column:request.status" in ids
    assert "column:request.resolution" in ids
    # Trigger table.
    assert "table:request" in ids
    # And, within depth=2, the other writer reachable via the table.
    assert "flow:assign_owner" in ids


def test_flow_anchor_validate_blast_radius_same_set(graph: ImpactGraph):
    anchor = graph.node("flow:close_request")
    diagnose = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)
    validate = walk(graph, anchor, intent="VALIDATE", direction="both", depth=2)
    assert diagnose.node_ids == validate.node_ids


# ---------------------------------------------------------------------------
# View anchor
# ---------------------------------------------------------------------------


def test_view_anchor_diagnose_surfaces_underlying_columns_and_table(graph: ImpactGraph):
    anchor = graph.node("view:open_requests")
    assert anchor is not None
    sub = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)

    ids = sub.node_ids
    assert "column:request.status" in ids
    assert "column:request.ownerid" in ids
    assert "table:request" in ids
    # Within depth=2 the writers behind those columns also surface (the
    # things that would need to change if the view's columns moved).
    assert "flow:close_request" in ids
    assert "flow:assign_owner" in ids


def test_view_anchor_validate_blast_radius_same_set(graph: ImpactGraph):
    anchor = graph.node("view:open_requests")
    diagnose = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)
    validate = walk(graph, anchor, intent="VALIDATE", direction="both", depth=2)
    assert diagnose.node_ids == validate.node_ids


# ---------------------------------------------------------------------------
# SecurityRole anchor
# ---------------------------------------------------------------------------


def test_security_role_anchor_diagnose_surfaces_secured_tables(graph: ImpactGraph):
    anchor = graph.node("role:agent_role")
    assert anchor is not None
    sub = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)

    ids = sub.node_ids
    # The table secured by this role.
    assert "table:request" in ids
    # And, at depth 2, the role's "neighbours" through the table - the
    # columns and other writers connected via the table.
    assert "flow:close_request" in ids or "flow:assign_owner" in ids


def test_security_role_anchor_validate_blast_radius_same_set(graph: ImpactGraph):
    anchor = graph.node("role:agent_role")
    diagnose = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)
    validate = walk(graph, anchor, intent="VALIDATE", direction="both", depth=2)
    assert diagnose.node_ids == validate.node_ids


# ---------------------------------------------------------------------------
# Walk discipline
# ---------------------------------------------------------------------------


def test_depth_bound_is_respected(graph: ImpactGraph):
    """Default depth 2 - depth-3 only on explicit ask."""
    anchor = graph.node("column:request.status")
    d1 = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=1)
    d2 = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)
    # Stricter bound is a subset of the looser one.
    assert d1.node_ids <= d2.node_ids
    # And depth 1 stays within the immediate neighbourhood.
    assert "flow:close_request" in d1.node_ids  # direct writer
    assert "table:request" in d1.node_ids  # has_column parent
    # close_request -> ... -> assign_owner is a depth-2 hop; absent at depth 1.
    assert "flow:assign_owner" not in d1.node_ids


def test_anchor_is_always_in_the_subgraph(graph: ImpactGraph):
    anchor = graph.node("column:request.status")
    sub = walk(graph, anchor, intent="DIAGNOSE", direction="both", depth=2)
    assert anchor.id in sub.node_ids
