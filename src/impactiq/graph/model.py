"""Types for the deterministic impact-graph engine.

The engine produces structured outputs that the ``Adjudicator`` consumes and
the ``ImpactReport`` renders. Everything here is plain data — no LLM. The
goal is explainability: every score, every diagnosis carries its ``reasons``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import networkx as nx

from ..connectors.base import Edge, Node

Intent = Literal["DIAGNOSE", "VALIDATE"]
Direction = Literal["downstream", "upstream", "both"]
RiskLevel = Literal["low", "medium", "high"]
Action = Literal[
    "create", "read", "write", "delete", "append", "appendto", "assign", "share"
]


@dataclass
class ImpactGraph:
    """An ``EstateFragment`` compiled into a networkx graph for fast traversal.

    The pydantic ``Node`` / ``Edge`` objects remain authoritative for
    serialization; ``nx_graph`` is just an index over them so the walk can
    use BFS/neighbour primitives.
    """

    nx_graph: nx.MultiDiGraph
    nodes_by_id: dict[str, Node] = field(default_factory=dict)

    def node(self, node_id: str) -> Node | None:
        return self.nodes_by_id.get(node_id)


@dataclass
class WalkedEdge:
    """An edge collected during the dependency walk, tagged with which
    direction relative to the anchor it was traversed in."""

    edge: Edge
    direction: Literal["incoming", "outgoing"]
    hop: int  # 1 = direct neighbour of anchor

    @property
    def relation(self) -> str:
        return self.edge.relation

    @property
    def from_(self) -> str:
        return self.edge.from_

    @property
    def to(self) -> str:
        return self.edge.to


@dataclass
class SubGraph:
    """A bounded slice of ``ImpactGraph`` around an anchor (the dependency
    walk result). Used as ``suspect_population`` for DIAGNOSE and
    ``blast_radius`` for VALIDATE — same shape, intent labels the
    interpretation."""

    anchor: Node
    intent: Intent
    direction: Direction
    depth: int
    nodes: list[Node]
    walked_edges: list[WalkedEdge]

    @property
    def edges(self) -> list[Edge]:
        return [w.edge for w in self.walked_edges]

    @property
    def node_ids(self) -> set[str]:
        return {n.id for n in self.nodes}

    def nodes_by_kind(self) -> dict[str, list[Node]]:
        out: dict[str, list[Node]] = {}
        for n in self.nodes:
            out.setdefault(n.kind, []).append(n)
        return out


@dataclass
class Risk:
    """Explainable risk score. ``reasons`` is what the report prints."""

    score: int  # 0-100
    level: RiskLevel
    reasons: list[str] = field(default_factory=list)


@dataclass
class RecentChange:
    """A recent-edit hit on a component in the blast radius."""

    component: Node
    modified_on: str | None
    modified_by_id: str | None
    days_ago: int | None


@dataclass
class PermissionsDiagnosis:
    """Output of the permissions diagnosis path."""

    user_id: str
    table_logical: str
    action: Action
    granted: bool
    likely_cause: str
    user_roles: list[str] = field(default_factory=list)
    relevant_privileges: list[str] = field(default_factory=list)
    field_security_blockers: list[str] = field(default_factory=list)
    recommended_fix: str | None = None
