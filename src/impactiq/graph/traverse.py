"""Dependency walk — the engine's primary first move on every anchor.

Run this **once** on every anchor, **both directions**, **bounded depth**
(default 2). The result is the *suspect population* (DIAGNOSE) or *blast
radius* (VALIDATE); same data, intent labels the interpretation.

Anchor-specific enrichment layers on top, never replaces. Run history,
audit, field-security checks are reads scoped to whatever the walk surfaced —
they are not the starting point.

This module is pure logic over an in-memory graph. The graph is populated by
the connectors (which call the three ``Retrieve*Components`` functions plus
the kind-specific structural reads), so the walk does not hit the platform.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable

from ..connectors.base import Edge
from .model import Direction, ImpactGraph, Intent, SubGraph, WalkedEdge


# Edges the dependency walk follows. ``depends_on`` is the canonical
# cross-kind edge; the structural relations carry the same "if this changes,
# that may break" semantic and are walked together so the engine treats
# declared and expression-level dependencies uniformly.
DEPENDENCY_LIKE_RELATIONS = frozenset({
    "depends_on",
    "writes_to",
    "reads_from",
    "references",
    "triggered_by",
    "triggers",
    "has_column",
    "secured_by",
    "owned_by",
    "surfaces",
    "member_of",
    "mandatory_on",
    "calculated_from",
    "routes_to",
    "in_solution",
})


def walk(
    graph: ImpactGraph,
    anchor,
    *,
    intent: Intent = "DIAGNOSE",
    direction: Direction = "both",
    depth: int = 2,
    relations: Iterable[str] | None = None,
) -> SubGraph:
    """BFS the anchor's neighbourhood up to ``depth`` hops.

    ``direction``:
      * ``"both"`` (default) - follow incoming AND outgoing edges
      * ``"outgoing"`` (alias ``"downstream"``) - follow outgoing edges only
      * ``"incoming"`` (alias ``"upstream"``) - follow incoming edges only

    Returns a ``SubGraph`` whose ``walked_edges`` are tagged ``incoming`` or
    ``outgoing`` relative to the anchor (the relation alone does not say which
    side of the anchor it sits on - tagging makes that explicit).
    """
    walk_in = direction in ("both", "upstream", "incoming")
    walk_out = direction in ("both", "downstream", "outgoing")
    if not (walk_in or walk_out):
        raise ValueError(f"unknown direction: {direction!r}")

    relation_filter = (
        frozenset(relations) if relations is not None else DEPENDENCY_LIKE_RELATIONS
    )

    seen: set[str] = {anchor.id}
    walked: list[WalkedEdge] = []
    # Dedup by edge identity (from, relation, to) alone. The direction tag
    # reflects which side of the anchor we *first* reached this edge from -
    # an edge visited from both ends in BFS is still the same edge.
    edge_keys: set[tuple[str, str, str]] = set()
    queue: deque[tuple[str, int]] = deque([(anchor.id, 0)])

    while queue:
        node_id, hops = queue.popleft()
        if hops >= depth:
            continue
        next_hop = hops + 1

        # Walk INCOMING first so edges incident on the anchor get tagged from
        # the anchor's perspective (the walk rule depends on that label).
        if walk_in:
            for source_id, _, key, attrs in graph.nx_graph.in_edges(
                node_id, keys=True, data=True
            ):
                rel = attrs.get("relation", key)
                if rel not in relation_filter:
                    continue
                ekey = (source_id, rel, node_id)
                if ekey not in edge_keys:
                    edge_keys.add(ekey)
                    walked.append(
                        WalkedEdge(
                            edge=Edge(
                                from_=source_id,
                                relation=rel,
                                to=node_id,
                                metadata=dict(attrs.get("metadata") or {}),
                            ),
                            direction="incoming",
                            hop=next_hop,
                        )
                    )
                if source_id not in seen:
                    seen.add(source_id)
                    queue.append((source_id, next_hop))

        if walk_out:
            for _, neighbour_id, key, attrs in graph.nx_graph.out_edges(
                node_id, keys=True, data=True
            ):
                rel = attrs.get("relation", key)
                if rel not in relation_filter:
                    continue
                ekey = (node_id, rel, neighbour_id)
                if ekey not in edge_keys:
                    edge_keys.add(ekey)
                    walked.append(
                        WalkedEdge(
                            edge=Edge(
                                from_=node_id,
                                relation=rel,
                                to=neighbour_id,
                                metadata=dict(attrs.get("metadata") or {}),
                            ),
                            direction="outgoing",
                            hop=next_hop,
                        )
                    )
                if neighbour_id not in seen:
                    seen.add(neighbour_id)
                    queue.append((neighbour_id, next_hop))

    nodes = [graph.nodes_by_id[nid] for nid in seen if nid in graph.nodes_by_id]
    return SubGraph(
        anchor=anchor,
        intent=intent,
        direction=direction,
        depth=depth,
        nodes=nodes,
        walked_edges=walked,
    )
