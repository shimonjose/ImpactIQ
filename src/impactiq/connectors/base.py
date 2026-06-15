"""Shared types for the estate connectors.

`Node` + `Edge` are the normalized graph primitives every connector emits.
`EstateScope` bounds a turn to one solution per the design's caching rule
("never re-crawl inside a turn"). `EstateFragment` is what each connector
returns and what the orchestrator merges.

Read-only by design: there is no node-mutation API beyond list `append`. The
orchestrator owns merging; the connectors don't reach into each other's state.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# fmt: off
NodeKind = Literal[
    "Table", "Column", "Relationship", "OptionSet",
    "Flow", "View", "Form", "BusinessRule",
    "SecurityRole", "FieldSecurityProfile", "Team", "User", "BusinessUnit",
    "ConnectionReference", "EnvironmentVariable", "SolutionComponent",
    "Dashboard", "Plugin", "CustomAPI",
    "CanvasApp", "ModelDrivenApp",
    "Mailbox", "Queue", "WebResource",
    "Solution",
    "Unknown",
]

EdgeRelation = Literal[
    "writes_to", "reads_from", "references",
    "triggered_by", "triggers",
    "secured_by", "owned_by", "surfaces",
    "depends_on", "depended_on_by",
    "member_of", "mandatory_on", "calculated_from", "routes_to",
    "in_solution", "has_column",
]
# fmt: on


class Node(BaseModel):
    """A typed node in the impact graph.

    `id` is the connector-assigned canonical id (e.g. `table:request`,
    `flow:<workflowid>`). `raw_ref` carries the platform identifier (logical
    name, GUID) so the engine can call back to Dataverse for enrichment.
    """

    id: str
    kind: NodeKind
    name: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_ref: str | None = None

    model_config = ConfigDict(extra="forbid")


class Edge(BaseModel):
    """A typed, directed edge."""

    # `from` is a Python keyword; expose it as `from_` in code and `from` in JSON.
    from_: str = Field(alias="from")
    relation: EdgeRelation
    to: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class EstateScope(BaseModel):
    """Bounds an analysis to one solution. The id is filled in after resolution."""

    solution_name: str | None = None
    solution_id: str | None = None

    @property
    def cache_key(self) -> str:
        return self.solution_id or (self.solution_name or "<unscoped>")


class EstateFragment(BaseModel):
    """A connector's output: nodes + edges, mergeable into a larger fragment."""

    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)

    def add_node(self, node: Node) -> None:
        """Append `node` unless a node with the same `id` already exists."""
        for n in self.nodes:
            if n.id == node.id:
                # Preserve first-seen kind/name; fold new metadata in.
                n.metadata.update(node.metadata)
                return
        self.nodes.append(node)

    def add_edge(self, edge: Edge) -> None:
        """Append `edge` unless an edge with the same (from, relation, to) exists."""
        key = (edge.from_, edge.relation, edge.to)
        for e in self.edges:
            if (e.from_, e.relation, e.to) == key:
                return
        self.edges.append(edge)

    def merge(self, other: "EstateFragment") -> None:
        """Union by node id and (from, relation, to). Later metadata folds in."""
        for n in other.nodes:
            self.add_node(n)
        for e in other.edges:
            self.add_edge(e)

    # Convenient JSON serialization that uses alias="from" instead of "from_".
    def to_json_obj(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, mode="json")


# ---------------------------------------------------------------------------
# Process-local fragment cache, keyed by EstateScope.cache_key.
# Function-call runs expire ~10 minutes after creation, so we must cache
# aggressively and never re-crawl inside a turn.
# ---------------------------------------------------------------------------
_FRAGMENT_CACHE: dict[str, EstateFragment] = {}


def cached_fragment(scope: EstateScope) -> EstateFragment | None:
    return _FRAGMENT_CACHE.get(scope.cache_key)


def store_fragment(scope: EstateScope, fragment: EstateFragment) -> None:
    _FRAGMENT_CACHE[scope.cache_key] = fragment


def clear_cache() -> None:
    _FRAGMENT_CACHE.clear()


# ---------------------------------------------------------------------------
# Canonical id helpers (so every connector agrees on node ids).
# ---------------------------------------------------------------------------
def table_id(logical_name: str) -> str:
    return f"table:{logical_name.lower()}"


def column_id(table_logical: str, column_logical: str) -> str:
    return f"column:{table_logical.lower()}.{column_logical.lower()}"


def flow_id(workflowid: str) -> str:
    return f"flow:{workflowid.lower()}"


def view_id(savedqueryid: str) -> str:
    return f"view:{savedqueryid.lower()}"


def role_id(roleid: str) -> str:
    return f"role:{roleid.lower()}"


def fsp_id(profile_id: str) -> str:
    return f"fsp:{profile_id.lower()}"


def team_id(teamid: str) -> str:
    return f"team:{teamid.lower()}"


def solution_id_node(solutionid: str) -> str:
    return f"solution:{solutionid.lower()}"


def connref_id(logical: str) -> str:
    return f"connref:{logical.lower()}"


def envvar_id(schema_name: str) -> str:
    return f"envvar:{schema_name.lower()}"


def component_id(component_type: int, object_id: str) -> str:
    """Generic id for a solution component when we haven't decoded its kind."""
    return f"component:{component_type}:{object_id.lower()}"
