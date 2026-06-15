"""Metadata + security reader.

Two responsibilities:

* **Metadata** - tables and columns via ``EntityDefinitions`` (with
  ``Attributes`` expansion). The "mandatory column" signal
  (``RequiredLevel.Value == 'ApplicationRequired'``) is captured as a
  ``mandatory_on`` edge so the column-anchor walk can read it.
* **Security model as graph** - roles, field-security profiles, teams,
  business units. The permissions-diagnosis path walks this layer.

All reads run under the read-only service identity.
"""

from __future__ import annotations

from ..dataverse_client import DataverseClient, DataverseError
from .base import (
    Edge,
    EstateFragment,
    EstateScope,
    Node,
    column_id,
    fsp_id,
    role_id,
    table_id,
    team_id,
)


def _display_label(dn: dict | None) -> str | None:
    """Extract a label from the metadata DisplayName complex object."""
    if not isinstance(dn, dict):
        return None
    ul = dn.get("UserLocalizedLabel")
    if isinstance(ul, dict):
        return ul.get("Label")
    return None


def _required_level(attr_row: dict) -> str | None:
    rl = attr_row.get("RequiredLevel")
    if isinstance(rl, dict):
        return rl.get("Value")
    return None


class DataverseConnector:
    """Metadata + security reader."""

    def __init__(self, client: DataverseClient):
        self._client = client

    # ----- metadata --------------------------------------------------------
    def list_tables(self) -> list[dict]:
        """All tables (lean projection). ``$top`` is not supported on
        ``EntityDefinitions`` in v9.2, so we always pull the full list."""
        return self._client.get_all(
            "EntityDefinitions",
            {
                "$select": (
                    "LogicalName,SchemaName,DisplayName,"
                    "LogicalCollectionName,EntitySetName,"
                    "PrimaryIdAttribute,PrimaryNameAttribute,MetadataId"
                )
            },
        )

    def get_table_by_metadata_id(self, metadata_id: str) -> dict | None:
        """Look up a table by its MetadataId GUID
        (what ``solutioncomponent.objectid`` carries for ``componenttype = 1``)."""
        try:
            return self._client.get(
                f"EntityDefinitions({metadata_id})",
                {
                    "$select": (
                        "LogicalName,SchemaName,DisplayName,"
                        "LogicalCollectionName,EntitySetName,"
                        "PrimaryIdAttribute,PrimaryNameAttribute,MetadataId"
                    )
                },
            )
        except DataverseError:
            return None

    def list_columns(self, logical_name: str) -> list[dict]:
        return self._client.get_all(
            f"EntityDefinitions(LogicalName='{logical_name}')/Attributes",
            {
                "$select": (
                    "LogicalName,SchemaName,AttributeType,RequiredLevel,"
                    "IsValidForCreate,IsValidForUpdate,IsValidForRead,"
                    "MetadataId"
                )
            },
        )

    def collection_to_logical_map(self, tables: list[dict]) -> dict[str, str]:
        """Build ``LogicalCollectionName -> LogicalName`` (and ``EntitySetName -> LogicalName``)
        so flow parsing can normalize action ``entityName`` (plural) to a Table id."""
        m: dict[str, str] = {}
        for t in tables:
            logical = t.get("LogicalName")
            if not logical:
                continue
            for key in ("LogicalCollectionName", "EntitySetName"):
                v = t.get(key)
                if v:
                    m[v] = logical
        return m

    # ----- security --------------------------------------------------------
    def list_roles(self) -> list[dict]:
        return self._client.get_all(
            "roles",
            {"$select": "name,roleid,_businessunitid_value"},
        )

    def list_field_security_profiles(self) -> list[dict]:
        return self._client.get_all(
            "fieldsecurityprofiles",
            {"$select": "name,fieldsecurityprofileid"},
        )

    def list_teams(self) -> list[dict]:
        return self._client.get_all(
            "teams",
            {"$select": "name,teamid,teamtype,_businessunitid_value"},
        )

    # ----- combined read for dump-estate -----------------------------------
    def read(
        self,
        scope: EstateScope,
        in_scope_table_metadata_ids: set[str],
    ) -> tuple[EstateFragment, list[dict]]:
        """Emit Table + Column nodes for the in-scope tables and the security
        graph (all roles, FSPs, teams in the environment).

        Returns the fragment **and** the underlying ``tables`` rows so the
        flows connector can build its ``LogicalCollectionName -> LogicalName``
        normalization map without re-reading metadata.
        """
        fragment = EstateFragment()

        # Tables in this solution (looked up by MetadataId from solutioncomponents)
        scoped_tables: list[dict] = []
        for metadata_id in in_scope_table_metadata_ids:
            row = self.get_table_by_metadata_id(metadata_id)
            if not row:
                continue
            scoped_tables.append(row)
            logical = row["LogicalName"]
            display = _display_label(row.get("DisplayName")) or logical
            tnode = table_id(logical)
            fragment.add_node(
                Node(
                    id=tnode,
                    kind="Table",
                    name=display,
                    raw_ref=logical,
                    metadata={
                        "schema_name": row.get("SchemaName"),
                        "metadata_id": row.get("MetadataId"),
                        "primary_id_attribute": row.get("PrimaryIdAttribute"),
                        "primary_name_attribute": row.get("PrimaryNameAttribute"),
                        "logical_collection_name": row.get("LogicalCollectionName"),
                        "entity_set_name": row.get("EntitySetName"),
                    },
                )
            )
            try:
                cols = self.list_columns(logical)
            except DataverseError:
                cols = []
            for col in cols:
                clogical = col["LogicalName"]
                cnode = column_id(logical, clogical)
                req = _required_level(col)
                fragment.add_node(
                    Node(
                        id=cnode,
                        kind="Column",
                        name=clogical,
                        raw_ref=clogical,
                        metadata={
                            "attribute_type": col.get("AttributeType"),
                            "required_level": req,
                            "is_valid_for_create": col.get("IsValidForCreate"),
                            "is_valid_for_update": col.get("IsValidForUpdate"),
                            "is_valid_for_read": col.get("IsValidForRead"),
                            "table": logical,
                        },
                    )
                )
                fragment.add_edge(
                    Edge(from_=tnode, relation="has_column", to=cnode)
                )
                if req == "ApplicationRequired":
                    fragment.add_edge(
                        Edge(from_=cnode, relation="mandatory_on", to=tnode)
                    )

        # Security elements (env-wide; intersection with scope can come later).
        try:
            for r in self.list_roles():
                rid = str(r["roleid"])
                fragment.add_node(
                    Node(
                        id=role_id(rid),
                        kind="SecurityRole",
                        name=r.get("name") or "(unnamed)",
                        raw_ref=rid,
                        metadata={"business_unit_id": r.get("_businessunitid_value")},
                    )
                )
        except DataverseError:
            pass

        try:
            for f in self.list_field_security_profiles():
                fid = str(f["fieldsecurityprofileid"])
                fragment.add_node(
                    Node(
                        id=fsp_id(fid),
                        kind="FieldSecurityProfile",
                        name=f.get("name") or "(unnamed)",
                        raw_ref=fid,
                    )
                )
        except DataverseError:
            pass

        try:
            for t in self.list_teams():
                tid = str(t["teamid"])
                fragment.add_node(
                    Node(
                        id=team_id(tid),
                        kind="Team",
                        name=t.get("name") or "(unnamed)",
                        raw_ref=tid,
                        metadata={
                            "team_type": t.get("teamtype"),
                            "business_unit_id": t.get("_businessunitid_value"),
                        },
                    )
                )
        except DataverseError:
            pass

        return fragment, scoped_tables
