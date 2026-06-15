"""Cloud-flow connector.

Reads the ``workflow`` table for cloud flows (``category=5``), parses each
flow's ``clientdata`` JSON into the operationId-keyed edge mapping, and reads
``FlowRun`` for the failed-flow diagnose entry point.

The parser is a pure function — tested offline without a live tenant.
"""

from __future__ import annotations

import json
from typing import Any

from ..dataverse_client import DataverseClient, DataverseError
from .base import (
    Edge,
    EstateFragment,
    Node,
    column_id,
    connref_id,
    flow_id,
    table_id,
)

# operationId -> conceptual edge direction.
TRIGGER_OPERATIONS = {"SubscribeWebhookTrigger"}
WRITE_OPERATIONS = {
    "CreateRecord",
    "CreateRecordWithFile",
    "UpdateRecord",
    "DeleteRecord",
}
READ_OPERATIONS = {"ListRecords", "GetItem", "GetItems"}
ACTION_OPERATIONS = {"PerformBoundAction", "PerformUnboundAction"}


def _iter_all_actions(actions: dict | None):
    """Yield (name, action) for every action, recursing into control-flow
    containers.

    A flow's ``CreateRecord`` / ``UpdateRecord`` often lives INSIDE a
    Condition's "if yes" branch, a Scope, a Foreach, an Until, or a Switch
    case - not at the top level. Walking only ``definition.actions`` (the
    original bug) missed those, so a flow that creates a record only inside a
    nested ``If <condition>`` branch looked like it wrote nothing.
    """
    for name, action in (actions or {}).items():
        if not isinstance(action, dict):
            continue
        yield name, action
        # Condition / Scope / Foreach / Until: nested `actions` block.
        nested = action.get("actions")
        if isinstance(nested, dict):
            yield from _iter_all_actions(nested)
        # Condition "else" branch.
        els = action.get("else")
        if isinstance(els, dict) and isinstance(els.get("actions"), dict):
            yield from _iter_all_actions(els["actions"])
        # Switch cases + default.
        cases = action.get("cases")
        if isinstance(cases, dict):
            for case in cases.values():
                if isinstance(case, dict) and isinstance(case.get("actions"), dict):
                    yield from _iter_all_actions(case["actions"])
        default = action.get("default")
        if isinstance(default, dict) and isinstance(default.get("actions"), dict):
            yield from _iter_all_actions(default["actions"])


def parse_clientdata(clientdata: str | dict | None) -> dict[str, Any]:
    """Normalize ``clientdata`` JSON into a small dict the connector can walk.

    Output shape::

        {
          "connection_references": ["<logical>", ...],
          "triggers": [
            {"operation": "...", "entity_singular": "...", "message": <int|None>}
          ],
          "actions": [
            {"operation": "...", "entity_plural": "...",
             "columns": ["<col>", ...], "action_name": "...",
             "operation_id": "..."}
          ],
        }

    The parser is intentionally lenient — flows have shipped under multiple
    schema generations and ``clientdata`` shapes vary; missing keys downgrade
    to empty lists rather than raise.
    """
    if not clientdata:
        return {"connection_references": [], "triggers": [], "actions": []}
    data = json.loads(clientdata) if isinstance(clientdata, str) else clientdata
    props = data.get("properties") or {}

    out: dict[str, Any] = {
        "connection_references": [],
        "triggers": [],
        "actions": [],
    }

    # Connection references block
    for _, entry in (props.get("connectionReferences") or {}).items():
        if not isinstance(entry, dict):
            continue
        inner = entry.get("connection")
        logical: str | None = None
        if isinstance(inner, dict):
            logical = inner.get("connectionReferenceLogicalName")
        # Some shapes put logical name at the entry root.
        if not logical:
            logical = entry.get("connectionReferenceLogicalName")
        if logical:
            out["connection_references"].append(logical)

    definition = props.get("definition") or {}

    # Triggers
    for _, trigger in (definition.get("triggers") or {}).items():
        if not isinstance(trigger, dict):
            continue
        inputs = trigger.get("inputs") or {}
        host = inputs.get("host") or {}
        op = host.get("operationId")
        if not op:
            continue
        params = inputs.get("parameters") or {}
        out["triggers"].append(
            {
                "operation": op,
                "entity_singular": params.get("subscriptionRequest/entityname"),
                "message": params.get("subscriptionRequest/message"),
            }
        )

    # Actions — recurse into nested control-flow blocks (Condition/Scope/etc).
    for action_name, action in _iter_all_actions(definition.get("actions") or {}):
        inputs = action.get("inputs") or {}
        host = inputs.get("host") or {}
        op = host.get("operationId")
        if not op:
            continue
        params = inputs.get("parameters") or {}
        columns: list[str] = []
        for key in params:
            if not isinstance(key, str) or not key.startswith("item/"):
                continue
            col = key[len("item/") :]
            if col.endswith("@odata.bind"):
                col = col[: -len("@odata.bind")]
            col = col.strip().lstrip("/")
            if col:
                columns.append(col)
        out["actions"].append(
            {
                "operation": op,
                "entity_plural": params.get("entityName"),
                "columns": columns,
                "action_name": action_name,
                "operation_id": host.get("apiId"),
            }
        )

    return out


def _fallback_singularize(plural: str) -> str:
    """Best-effort plural -> singular when the LogicalCollectionName map misses."""
    if plural.endswith("ies"):
        return plural[:-3] + "y"
    if plural.endswith(("xes", "ses", "zes", "ches", "shes")):
        return plural[:-2]
    if plural.endswith("s") and not plural.endswith("ss"):
        return plural[:-1]
    return plural


class FlowsConnector:
    """Cloud-flow read + clientdata parsing + FlowRun queries."""

    def __init__(self, client: DataverseClient):
        self._client = client

    def list_cloud_flows(
        self, in_solution_workflow_ids: set[str] | None = None
    ) -> list[dict]:
        rows = self._client.get_all(
            "workflows",
            {
                "$select": (
                    "workflowid,name,category,statecode,statuscode,"
                    "clientdata,_ownerid_value,modifiedon,_modifiedby_value"
                ),
                "$filter": "category eq 5",
            },
        )
        if in_solution_workflow_ids is None:
            return rows
        wanted = {x.lower() for x in in_solution_workflow_ids}
        return [r for r in rows if str(r["workflowid"]).lower() in wanted]

    def list_failed_runs(self, hours: int = 24) -> list[dict]:
        """Recent failed cloud-flow runs.

        Requires ``Cloud flow run history in Dataverse`` to be enabled in PPAC.
        Raises ``DataverseError`` if the entity set is unavailable; the CLI
        surfaces the error + the PPAC toggle hint.
        """
        return self._client.get_all(
            "flowruns",
            {
                "$select": (
                    "name,status,errorcode,errormessage,"
                    "starttime,endtime,_workflow_value"
                ),
                "$filter": (
                    "status eq 'Failed' and "
                    "Microsoft.Dynamics.CRM.LastXHours("
                    f"PropertyName='createdon',PropertyValue={hours})"
                ),
                "$orderby": "starttime desc",
            },
        )

    def read(
        self,
        in_solution_workflow_ids: set[str] | None,
        tables_by_collection: dict[str, str],
    ) -> EstateFragment:
        """Emit Flow nodes + parsed write/read/triggered_by/references edges.

        ``tables_by_collection`` maps the plural entity-set name (what flow
        actions use for ``entityName``) to the singular logical name (the
        canonical Table node key). A best-effort fallback singularization
        catches custom or unknown sets.
        """
        fragment = EstateFragment()
        flows = self.list_cloud_flows(in_solution_workflow_ids)

        for wf in flows:
            wid = str(wf["workflowid"])
            fnode = flow_id(wid)
            fragment.add_node(
                Node(
                    id=fnode,
                    kind="Flow",
                    name=wf.get("name") or "(unnamed)",
                    raw_ref=wid,
                    metadata={
                        "statecode": wf.get("statecode"),
                        "statuscode": wf.get("statuscode"),
                        "owner_id": wf.get("_ownerid_value"),
                        "modified_on": wf.get("modifiedon"),
                        "modified_by": wf.get("_modifiedby_value"),
                    },
                )
            )

            try:
                parsed = parse_clientdata(wf.get("clientdata"))
            except json.JSONDecodeError:
                fragment.nodes[-1].metadata["clientdata_parse_error"] = True
                continue

            for cref in parsed["connection_references"]:
                cnode = connref_id(cref)
                fragment.add_node(
                    Node(id=cnode, kind="ConnectionReference", name=cref, raw_ref=cref)
                )
                fragment.add_edge(Edge(from_=fnode, relation="references", to=cnode))

            for t in parsed["triggers"]:
                if t["operation"] in TRIGGER_OPERATIONS and t["entity_singular"]:
                    tnode = table_id(t["entity_singular"])
                    fragment.add_node(
                        Node(
                            id=tnode,
                            kind="Table",
                            name=t["entity_singular"],
                            raw_ref=t["entity_singular"],
                        )
                    )
                    fragment.add_edge(
                        Edge(
                            from_=fnode,
                            relation="triggered_by",
                            to=tnode,
                            metadata={"message_code": t.get("message")},
                        )
                    )

            for a in parsed["actions"]:
                op = a["operation"]
                plural = a["entity_plural"]
                singular: str | None = None
                if plural:
                    singular = tables_by_collection.get(plural) or _fallback_singularize(
                        plural
                    )

                if op in WRITE_OPERATIONS and singular:
                    self._emit_table_edge(
                        fragment, fnode, singular, "writes_to", op, a
                    )
                    for col in a["columns"]:
                        cnode = column_id(singular, col)
                        fragment.add_node(
                            Node(
                                id=cnode,
                                kind="Column",
                                name=col,
                                raw_ref=col,
                                metadata={"table": singular},
                            )
                        )
                        fragment.add_edge(
                            Edge(
                                from_=fnode,
                                relation="writes_to",
                                to=cnode,
                                metadata={"operation": op, "action": a["action_name"]},
                            )
                        )
                elif op in READ_OPERATIONS and singular:
                    self._emit_table_edge(
                        fragment, fnode, singular, "reads_from", op, a
                    )
                elif op in ACTION_OPERATIONS:
                    # Calls a Dataverse action / custom API. We can't always
                    # name the target precisely without parsing parameters,
                    # so the edge points at a synthetic action node carrying
                    # the operation and parameter set.
                    target = f"action:{a['action_name'] or 'unknown'}"
                    fragment.add_node(
                        Node(
                            id=target,
                            kind="CustomAPI",
                            name=a["action_name"] or "(unknown)",
                            raw_ref=None,
                            metadata={"operation": op},
                        )
                    )
                    fragment.add_edge(
                        Edge(
                            from_=fnode,
                            relation="references",
                            to=target,
                            metadata={"operation": op},
                        )
                    )

        return fragment

    @staticmethod
    def _emit_table_edge(
        fragment: EstateFragment,
        flow_node: str,
        singular: str,
        relation: str,
        op: str,
        action: dict,
    ) -> None:
        tnode = table_id(singular)
        fragment.add_node(
            Node(id=tnode, kind="Table", name=singular, raw_ref=singular)
        )
        fragment.add_edge(
            Edge(
                from_=flow_node,
                relation=relation,  # type: ignore[arg-type]
                to=tnode,
                metadata={"operation": op, "action": action["action_name"]},
            )
        )
