"""Solutions + dependency primitives - the engine's spine.

This module owns the three Web API functions the engine calls on every anchor:

* ``RetrieveDependentComponents``   - downstream (what depends on X)
* ``RetrieveRequiredComponents``    - upstream   (what X depends on)
* ``RetrieveDependenciesForDelete`` - delete-blockers (refactor safety)

It also resolves an ``EstateScope`` to a concrete solution and lists the
solution's components. Other connectors (dataverse, flows) read kind-specific
detail; this module reads the *cross-kind* topology that ranks every walk.
"""

from __future__ import annotations

from ..dataverse_client import DataverseClient, DataverseError
from .base import (
    Edge,
    EstateFragment,
    EstateScope,
    Node,
    component_id,
    solution_id_node,
)

# componenttype -> human label. Common values from the Microsoft Learn
# "componenttype" enum. The enum is OPEN and grows over time - unknown values
# are reported as "Unknown:<int>" so the engine never silently swallows a new
# kind.
COMPONENT_TYPE_LABEL: dict[int, str] = {
    1: "Entity",
    2: "Attribute",
    3: "Relationship",
    9: "OptionSet",
    20: "Role",
    24: "FormXml",
    26: "SavedQuery",
    29: "Workflow",
    36: "DisplayString",
    60: "SystemForm",
    61: "WebResource",
    62: "SiteMap",
    65: "ConnectionRole",
    66: "Article",
    70: "FieldSecurityProfile",
    71: "FieldPermission",
    90: "PluginPackage",
    91: "PluginAssembly",
    92: "PluginType",
    95: "SdkMessageProcessingStep",
    104: "SDKMessageProcessingStepImage",
    150: "EntityRelationship",
    201: "SDKMessage",
    300: "CanvasApp",
    301: "AppModule",
    371: "ConvertRule",
    380: "EnvironmentVariableDefinition",
    381: "EnvironmentVariableValue",
    382: "ConnectionReference",
}


def decode_component_type(component_type: int) -> str:
    return COMPONENT_TYPE_LABEL.get(component_type, f"Unknown:{component_type}")


def _odata_literal(s: str) -> str:
    """Quote a string for an OData $filter literal; double inner single quotes."""
    return "'" + s.replace("'", "''") + "'"


def _extract_dependency_rows(payload: dict) -> list[dict]:
    """Pull the dependency rows out of a Retrieve*Components response.

    The Web API serializes the response as
    ``{"EntityCollection": {"Entities": [...]}}`` for these unbound functions,
    but some preview shapes also surface ``value`` - handle both defensively.
    """
    if isinstance(payload, dict):
        ec = payload.get("EntityCollection")
        if isinstance(ec, dict):
            ents = ec.get("Entities")
            if isinstance(ents, list):
                return ents
        if isinstance(payload.get("value"), list):
            return payload["value"]
    return []


class SolutionsConnector:
    """Solution lookup and the dependency primitives."""

    def __init__(self, client: DataverseClient):
        self._client = client

    # ----- solution lookup --------------------------------------------------
    def find_solution(self, name_or_unique: str) -> dict | None:
        """Look up a solution by either friendlyname or uniquename."""
        lit = _odata_literal(name_or_unique)
        data = self._client.get(
            "solutions",
            {
                "$select": "solutionid,uniquename,friendlyname,ismanaged,version",
                "$filter": f"friendlyname eq {lit} or uniquename eq {lit}",
            },
        )
        rows = data.get("value", [])
        return rows[0] if rows else None

    def resolve_scope(self, scope: EstateScope) -> EstateScope:
        """Populate ``scope.solution_id`` from ``solution_name`` if missing."""
        if scope.solution_id:
            return scope
        if not scope.solution_name:
            raise DataverseError("EstateScope requires solution_name or solution_id")
        sol = self.find_solution(scope.solution_name)
        if not sol:
            raise DataverseError(
                f"Solution not found by friendlyname/uniquename: {scope.solution_name!r}"
            )
        return EstateScope(
            solution_name=sol.get("friendlyname") or sol.get("uniquename"),
            solution_id=sol["solutionid"],
        )

    # ----- components -------------------------------------------------------
    def list_components(self, solution_id: str) -> list[dict]:
        return self._client.get_all(
            "solutioncomponents",
            {
                "$select": "componenttype,objectid,rootcomponentbehavior,_solutionid_value",
                "$filter": f"_solutionid_value eq {solution_id}",
            },
        )

    # ----- dependency primitives (first-class, engine calls these) -----
    def retrieve_dependent_components(
        self, object_id: str, component_type: int
    ) -> list[dict]:
        """Downstream walk: every component that DEPENDS ON (object_id, component_type)."""
        payload = self._client.call_function(
            "RetrieveDependentComponents",
            ObjectId=object_id,
            ComponentType=component_type,
        )
        return _extract_dependency_rows(payload)

    def retrieve_required_components(
        self, object_id: str, component_type: int
    ) -> list[dict]:
        """Upstream walk: every component (object_id, component_type) DEPENDS ON."""
        payload = self._client.call_function(
            "RetrieveRequiredComponents",
            ObjectId=object_id,
            ComponentType=component_type,
        )
        return _extract_dependency_rows(payload)

    def retrieve_dependencies_for_delete(
        self, object_id: str, component_type: int
    ) -> list[dict]:
        """Delete-blockers - the set that would refuse a delete of the anchor."""
        payload = self._client.call_function(
            "RetrieveDependenciesForDelete",
            ObjectId=object_id,
            ComponentType=component_type,
        )
        return _extract_dependency_rows(payload)

    # ----- combined read for dump-estate ------------------------------------
    def read(self, scope: EstateScope) -> EstateFragment:
        """Solution + SolutionComponent nodes + depends_on edges across the
        in-scope components (both directions, depth-1).

        Kind-specific connectors emit canonical Table/Flow/Role nodes
        separately; this connector emits the cross-kind "spine" the engine
        starts every walk from.
        """
        scope = self.resolve_scope(scope)
        assert scope.solution_id  # set by resolve_scope
        fragment = EstateFragment()

        # The solution itself.
        sol_node_id = solution_id_node(scope.solution_id)
        fragment.add_node(
            Node(
                id=sol_node_id,
                kind="Solution",
                name=scope.solution_name or "(unknown)",
                raw_ref=scope.solution_id,
                metadata={},
            )
        )

        components = self.list_components(scope.solution_id)
        for c in components:
            ctype = int(c["componenttype"])
            oid = str(c["objectid"])
            self._ensure_component_node(fragment, ctype, oid, out_of_scope=False)
            fragment.add_edge(
                Edge(
                    from_=component_id(ctype, oid),
                    relation="in_solution",
                    to=sol_node_id,
                )
            )

        # Per-component dependency walk - both directions, depth 1. This
        # exercises the same primitive the engine calls on every anchor.
        for c in components:
            ctype = int(c["componenttype"])
            oid = str(c["objectid"])
            try:
                required = self.retrieve_required_components(oid, ctype)
            except DataverseError:
                required = []
            for dep in required:
                self._emit_dependency_edge(fragment, dep)
            try:
                dependents = self.retrieve_dependent_components(oid, ctype)
            except DataverseError:
                dependents = []
            for dep in dependents:
                self._emit_dependency_edge(fragment, dep)

        return fragment

    # ----- helpers ----------------------------------------------------------
    def _ensure_component_node(
        self,
        fragment: EstateFragment,
        component_type: int,
        object_id: str,
        *,
        out_of_scope: bool,
    ) -> str:
        node_id = component_id(component_type, object_id)
        label = decode_component_type(component_type)
        meta: dict = {
            "componenttype": component_type,
            "componenttype_label": label,
        }
        if out_of_scope:
            meta["out_of_scope"] = True
        fragment.add_node(
            Node(
                id=node_id,
                kind="SolutionComponent",
                name=f"{label}:{object_id[:8]}",
                raw_ref=object_id,
                metadata=meta,
            )
        )
        return node_id

    def _emit_dependency_edge(self, fragment: EstateFragment, dep_row: dict) -> None:
        """Map one dependency row to a depends_on edge, materializing endpoints."""
        dep_oid = dep_row.get("dependentcomponentobjectid")
        dep_type = dep_row.get("dependentcomponenttype")
        req_oid = dep_row.get("requiredcomponentobjectid")
        req_type = dep_row.get("requiredcomponenttype")
        if not (dep_oid and req_oid and dep_type is not None and req_type is not None):
            return
        dep_node = self._ensure_component_node(
            fragment, int(dep_type), str(dep_oid), out_of_scope=True
        )
        req_node = self._ensure_component_node(
            fragment, int(req_type), str(req_oid), out_of_scope=True
        )
        # We only flagged out_of_scope=True because we don't know yet; if the
        # component was already added (in-scope), the flag was never set.
        fragment.add_edge(
            Edge(from_=dep_node, relation="depends_on", to=req_node)
        )
