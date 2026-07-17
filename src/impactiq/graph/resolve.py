"""Anchor resolution - deterministic string matching against the graph.

This stays LLM-free; the orchestrator adds NL parsing on top by calling this
resolver to short-list candidates. Match priority is fixed and explainable.
"""

from __future__ import annotations

from ..connectors.base import Node
from .model import ImpactGraph


def resolve_anchor(query: str, graph: ImpactGraph) -> list[Node]:
    """Return candidate nodes matching ``query`` in priority order.

    Priority (high -> low):
      1. Exact node ``id`` match (case-sensitive then case-insensitive)
      2. Exact ``name`` match (case-insensitive)
      3. ``kind:name`` pattern (e.g. ``flow:close_request``)
      4. Substring match on name
      5. Substring match on raw_ref (logical name / GUID)
    """
    if not query:
        return []
    q = query.strip()
    q_lower = q.lower()
    nodes = list(graph.nodes_by_id.values())

    direct = graph.nodes_by_id.get(q)
    if direct:
        return [direct]
    by_id_ci = [n for n in nodes if n.id.lower() == q_lower]
    if by_id_ci:
        return by_id_ci

    exact_name = [n for n in nodes if n.name.lower() == q_lower]
    if exact_name:
        return exact_name

    if ":" in q:
        kind, _, rest = q.partition(":")
        kind_l, rest_l = kind.lower(), rest.lower()
        cands = [
            n
            for n in nodes
            if n.kind.lower() == kind_l
            and (n.name.lower() == rest_l or rest_l in n.name.lower())
        ]
        if cands:
            return cands

    subs_name = [n for n in nodes if q_lower in n.name.lower()]
    if subs_name:
        return subs_name

    subs_ref = [n for n in nodes if n.raw_ref and q_lower in n.raw_ref.lower()]
    if subs_ref:
        return subs_ref

    # Final fallback: try each whitespace-separated token of length >= 3.
    # Catches "phrasey" queries (e.g. "the Account table"); it only runs when
    # every earlier tier came up empty.
    tokens = [t.strip(",.;:'\"()") for t in q_lower.split()]
    tokens = [t for t in tokens if len(t) >= 3]
    seen_ids: set[str] = set()
    out: list[Node] = []
    for tok in tokens:
        for n in nodes:
            if n.id in seen_ids:
                continue
            if tok in n.name.lower() or (n.raw_ref and tok in n.raw_ref.lower()):
                seen_ids.add(n.id)
                out.append(n)
    return out
