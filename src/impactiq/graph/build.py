"""Compile an ``EstateFragment`` into an ``ImpactGraph`` for fast traversal."""

from __future__ import annotations

import networkx as nx

from ..connectors.base import EstateFragment
from .model import ImpactGraph


def build_graph(fragment: EstateFragment) -> ImpactGraph:
    """Convert nodes + edges into a ``MultiDiGraph`` keyed by relation.

    Multiple parallel edges between the same two nodes are allowed and
    distinguished by ``relation`` (a column can be both ``has_column``-from a
    table and ``mandatory_on`` it).
    """
    g: nx.MultiDiGraph = nx.MultiDiGraph()
    nodes_by_id: dict[str, object] = {}
    for n in fragment.nodes:
        g.add_node(
            n.id,
            kind=n.kind,
            name=n.name,
            metadata=n.metadata,
            raw_ref=n.raw_ref,
        )
        nodes_by_id[n.id] = n
    for e in fragment.edges:
        # Use the relation as the MultiDiGraph edge key so parallel relations
        # between the same pair of nodes stay distinguishable.
        g.add_edge(e.from_, e.to, key=e.relation, relation=e.relation, metadata=e.metadata)
    return ImpactGraph(nx_graph=g, nodes_by_id=nodes_by_id)  # type: ignore[arg-type]
