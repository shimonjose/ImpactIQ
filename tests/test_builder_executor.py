"""Deterministic fix executor: walls + rollback, no live calls.

The stub client records every wire call so the tests can assert WHAT the
executor would do - including what it must never do (create, drop
connections, touch components outside the solution).
"""

import json

import pytest

from impactiq.builder import BuilderRefusal, FixReport
from impactiq.builder.executor import (
    COLUMN_FIXABLE,
    alter_column,
    locate_flow,
    patch_flow_definition,
    set_flow_state,
)


class StubClient:
    """Records calls; serves canned GET responses keyed by path prefix."""

    def __init__(self, gets: dict):
        self.gets = gets
        self.patches: list[tuple[str, dict]] = []
        self.puts: list[tuple[str, dict]] = []
        self.published: list[str] = []
        self.fail_patch_containing: str | None = None

    def get(self, path, params=None):
        for prefix, value in self.gets.items():
            if path.startswith(prefix):
                return value
        raise BuilderRefusal(f"stub: no canned GET for {path}")

    def patch(self, path, payload):
        if self.fail_patch_containing and self.fail_patch_containing in str(payload):
            raise BuilderRefusal("stub: platform rejected")
        self.patches.append((path, payload))

    def put_metadata(self, path, payload):
        self.puts.append((path, payload))

    def publish(self, table):
        self.published.append(table)


_SOL = {"value": [{"solutionid": "sol-1"}]}
_IN_SOLUTION = {"value": [{"solutioncomponentid": "sc-1"}]}
_NOT_IN_SOLUTION = {"value": []}


def _flow_row(state=1, clientdata=None):
    return {
        "value": [
            {
                "workflowid": "wf-1",
                "name": "Broken Flow",
                "statecode": state,
                "statuscode": 2 if state == 1 else 1,
                "category": 5,
                "clientdata": clientdata
                or json.dumps(
                    {
                        "connectionReferences": {"shared_commondataservice": {"x": 1}},
                        "definition": {"triggers": {}},
                    }
                ),
            }
        ]
    }


def test_locate_flow_refuses_outside_solution():
    client = StubClient(
        {"workflows": _flow_row(), "solutions": _SOL, "solutioncomponents": _NOT_IN_SOLUTION}
    )
    with pytest.raises(BuilderRefusal, match="NOT in solution"):
        locate_flow(client, "ImpactIQSandbox", "Broken Flow")


class _PartialNameStub(StubClient):
    """Exact-name filter misses; contains() filter hits - the tolerant path."""

    def get(self, path, params=None):
        if path.startswith("workflows"):
            f = (params or {}).get("$filter", "")
            if f.startswith("name eq"):
                return {"value": []}
            if "contains(" in f:
                return _flow_row()
            return {"value": [{"name": "Broken Flow"}]}  # listing fallback
        return super().get(path, params)


def test_locate_flow_resolves_partial_names():
    """The model often passes a shorthand - a unique substring match must
    resolve instead of bouncing the question back to the user."""
    client = _PartialNameStub(
        {"solutions": _SOL, "solutioncomponents": _IN_SOLUTION}
    )
    flow = locate_flow(client, "ImpactIQSandbox", "Broken")
    assert flow["name"] == "Broken Flow"


class _MissStub(StubClient):
    def get(self, path, params=None):
        if path.startswith("workflows"):
            f = (params or {}).get("$filter", "")
            if "contains(" in f or f.startswith("name eq"):
                return {"value": []}
            return {"value": [{"name": "Broken Flow"}, {"name": "Other Flow"}]}
        return super().get(path, params)


def test_locate_flow_miss_lists_available_flows():
    client = _MissStub({"solutions": _SOL})
    with pytest.raises(BuilderRefusal, match="Other Flow"):
        locate_flow(client, "ImpactIQSandbox", "nope")


def test_set_flow_state_patches_update_only():
    client = StubClient(
        {"workflows": _flow_row(state=1), "solutions": _SOL, "solutioncomponents": _IN_SOLUTION}
    )
    done = set_flow_state(client, "ImpactIQSandbox", "Broken Flow", "off")
    assert done["change"] == "state -> off"
    assert client.patches == [("workflows(wf-1)", {"statecode": 0, "statuscode": 1})]


def test_patch_flow_definition_must_preserve_connection_references():
    client = StubClient(
        {"workflows": _flow_row(), "solutions": _SOL, "solutioncomponents": _IN_SOLUTION}
    )
    bad = json.dumps({"connectionReferences": {}, "definition": {"triggers": {"t": 1}}})
    report = FixReport()
    with pytest.raises(BuilderRefusal, match="preserve connections"):
        patch_flow_definition(
            client, "ImpactIQSandbox", "Broken Flow", bad, report=report
        )
    assert client.patches == []  # refused before any write


def test_patch_flow_definition_rolls_back_on_platform_rejection():
    before = json.dumps(
        {"connectionReferences": {"shared_commondataservice": {"x": 1}}, "definition": {"v": 1}}
    )
    client = StubClient(
        {
            "workflows": _flow_row(state=1, clientdata=before),
            "solutions": _SOL,
            "solutioncomponents": _IN_SOLUTION,
        }
    )
    new = json.dumps(
        {"connectionReferences": {"shared_commondataservice": {"x": 1}}, "definition": {"v": 2}}
    )
    client.fail_patch_containing = '"v": 2'
    report = FixReport()
    patch_flow_definition(client, "ImpactIQSandbox", "Broken Flow", new, report=report)
    assert report.outstanding and "rolled back" in report.outstanding[0]["reason"]
    # Last patch restored the before-image clientdata.
    assert client.patches[-1][1]["clientdata"] == before


def test_set_flow_action_parameter_edits_surgically():
    """One parameter changes; connectionReferences and the rest of the
    definition survive byte-for-byte - no model-regenerated document."""
    from impactiq.builder.executor import set_flow_action_parameter

    clientdata = json.dumps(
        {
            "properties": {
                "connectionReferences": {"shared_commondataservice": {"x": 1}},
                "definition": {
                    "actions": {
                        "Condition": {
                            "type": "If",
                            "actions": {
                                "Add_a_new_row": {
                                    "type": "OpenApiConnection",
                                    "inputs": {"parameters": {"item/new_name": "@null"}},
                                }
                            },
                        }
                    }
                },
            },
            "schemaVersion": "1.0.0.0",
        }
    )
    client = StubClient(
        {
            "workflows": _flow_row(state=1, clientdata=clientdata),
            "solutions": _SOL,
            "solutioncomponents": _IN_SOLUTION,
        }
    )
    report = FixReport()
    set_flow_action_parameter(
        client, "ImpactIQSandbox", "Broken Flow",
        "Add_a_new_row", "item/new_name", "@triggerOutputs()?['body/new_name']",
        report=report,
    )
    assert report.done and "reactivated" in report.done[0]["change"]
    # The clientdata patch carries the new value and the untouched refs.
    written = next(p for p in client.patches if "clientdata" in p[1])
    doc = json.loads(written[1]["clientdata"])
    params = doc["properties"]["definition"]["actions"]["Condition"]["actions"]["Add_a_new_row"]["inputs"]["parameters"]
    assert params["item/new_name"] == "@triggerOutputs()?['body/new_name']"
    assert doc["properties"]["connectionReferences"] == {"shared_commondataservice": {"x": 1}}


_ADMIN_TASK_FLOW = json.dumps(
    {
        "properties": {
            "connectionReferences": {"shared_commondataservice": {"x": 1}},
            "definition": {
                "actions": {
                    "Add_a_new_row": {
                        "type": "OpenApiConnection",
                        "inputs": {
                            "parameters": {
                                "entityName": "new_admintasks",
                                "item/new_name": "Complaint Admin Task",
                                "item/new_Customer@odata.bind": "@bare-guid",
                            }
                        },
                    }
                }
            },
        }
    }
)


class _SchemaStub(StubClient):
    """Serves the Admin Task table's metadata: new_name is a business-required
    AUTONUMBER, new_customer is a lookup targeting contact."""

    def get(self, path, params=None):
        if path == "EntityDefinitions(LogicalName='new_admintasks')":
            raise BuilderRefusal("not a logical name")  # entity-set fallback path
        if path == "EntityDefinitions":
            return {"value": [{"LogicalName": "new_admintask", "EntitySetName": "new_admintasks"}]}
        if path == "EntityDefinitions(LogicalName='new_admintask')/Attributes":
            return {
                "value": [
                    {
                        "LogicalName": "new_name",
                        "AttributeType": "String",
                        "AutoNumberFormat": "TASK-{SEQNUM:4}",
                        "RequiredLevel": {"Value": "ApplicationRequired"},
                        "DisplayName": {"UserLocalizedLabel": {"Label": "Task Number"}},
                    },
                    {
                        "LogicalName": "new_customer",
                        "AttributeType": "Lookup",
                        "RequiredLevel": {"Value": "None"},
                        "DisplayName": {"UserLocalizedLabel": {"Label": "Customer"}},
                    },
                ]
            }
        if "LookupAttributeMetadata" in path:
            return {"Targets": ["contact"]}
        if path == "EntityDefinitions(LogicalName='contact')":
            return {"EntitySetName": "contacts"}
        return super().get(path, params)


def _schema_client():
    return _SchemaStub(
        {
            "workflows": _flow_row(clientdata=_ADMIN_TASK_FLOW),
            "solutions": _SOL,
            "solutioncomponents": _IN_SOLUTION,
        }
    )


def test_guard_refuses_literal_in_autonumber_column():
    """The live incident: the model wrote text into the autonumber 'Task
    Number'. The executor must refuse, and - because the column is also
    business-required - point at the alter_column-first sequence."""
    from impactiq.builder.executor import set_flow_action_parameter

    with pytest.raises(BuilderRefusal, match="AUTONUMBER.*required_level"):
        set_flow_action_parameter(
            _schema_client(), "ImpactIQSandbox", "Broken Flow",
            "Add_a_new_row", "item/new_name", "Some Literal",
            report=FixReport(),
        )


def test_guard_refuses_bare_guid_lookup_bind():
    """The live incident: a lookup bind without '<entityset>(<id>)' fails at
    runtime with ODataUnrecognizedPathException. Refuse at the wire, with the
    correct shape from the column's actual target."""
    from impactiq.builder.executor import set_flow_action_parameter

    with pytest.raises(BuilderRefusal, match=r"contacts\(<contact id>\)"):
        set_flow_action_parameter(
            _schema_client(), "ImpactIQSandbox", "Broken Flow",
            "Add_a_new_row", "item/new_Customer@odata.bind",
            "@triggerOutputs()?['body/_new_customer_value']",
            report=FixReport(),
        )


def test_guard_accepts_wellformed_bind():
    from impactiq.builder.executor import set_flow_action_parameter

    client = _schema_client()
    report = FixReport()
    set_flow_action_parameter(
        client, "ImpactIQSandbox", "Broken Flow",
        "Add_a_new_row", "item/new_Customer@odata.bind",
        "contacts(@{triggerOutputs()?['body/_new_customer_value']})",
        report=report,
    )
    assert report.done


def test_value_null_removes_parameter():
    """value=None is REMOVAL - the right fix for autonumber columns."""
    from impactiq.builder.executor import set_flow_action_parameter

    client = _schema_client()
    report = FixReport()
    set_flow_action_parameter(
        client, "ImpactIQSandbox", "Broken Flow",
        "Add_a_new_row", "item/new_name", None,
        report=report,
    )
    assert report.done and "removed item/new_name" in report.done[0]["change"]
    written = next(p for p in client.patches if "clientdata" in p[1])
    doc = json.loads(written[1]["clientdata"])
    params = doc["properties"]["definition"]["actions"]["Add_a_new_row"]["inputs"]["parameters"]
    assert "item/new_name" not in params


def test_table_schema_marks_autonumber_and_bind_shape():
    from impactiq.builder.executor import table_schema

    schema = table_schema(_schema_client(), "new_admintasks")
    by_name = {c["column"]: c for c in schema["columns"]}
    assert by_name["new_name"]["autonumber"] == "TASK-{SEQNUM:4}"
    assert "alter_column" in by_name["new_name"]["note"]  # required+autonumber
    assert by_name["new_customer"]["bind_format"] == ["contacts(<contact id>)"]


def test_leaf_failed_actions_flags_containers():
    """Containers fail with 'ActionFailed' (a child failed) - only leaves
    carry the real platform error worth fetching."""
    from impactiq.builder.executor import _leaf_failed_actions

    props = {
        "actions": {
            "Condition": {"status": "Failed", "code": "ActionFailed"},
            "Add_a_new_row": {
                "status": "Failed",
                "code": "BadRequest",
                "outputsLink": {"uri": "https://x"},
            },
            "Terminate": {"status": "Skipped", "code": "ActionSkipped"},
        }
    }
    failed = {f["action"]: f for f in _leaf_failed_actions(props)}
    assert set(failed) == {"Condition", "Add_a_new_row"}
    assert failed["Add_a_new_row"]["is_leaf"] is True
    assert failed["Condition"]["is_leaf"] is False


def test_child_flow_references_found_recursively():
    """'Run a Child Flow' actions are drill-down seeds - including ones
    nested inside conditions."""
    from impactiq.builder.executor import child_flow_references

    doc = {
        "properties": {
            "definition": {
                "actions": {
                    "Condition": {
                        "type": "If",
                        "actions": {
                            "Run_Child": {
                                "type": "Workflow",
                                "inputs": {"host": {"workflowReferenceName": "abc-123"}},
                            }
                        },
                    },
                    "Plain_Step": {"type": "Compose"},
                }
            }
        }
    }
    refs = child_flow_references(doc)
    assert refs == [{"action": "Run_Child", "workflow_reference": "abc-123"}]
    assert child_flow_references({"properties": {"definition": {"actions": {}}}}) == []


def test_clip_truncates_large_payloads():
    from impactiq.builder.executor import _clip

    assert _clip({"a": 1}) == '{"a": 1}'
    assert _clip("x" * 2000, limit=100).endswith("…(truncated)")


def test_set_flow_action_parameter_miss_lists_actions():
    from impactiq.builder.executor import set_flow_action_parameter

    clientdata = json.dumps(
        {"properties": {"definition": {"actions": {"Only_Action": {"type": "If"}}}}}
    )
    client = StubClient(
        {
            "workflows": _flow_row(clientdata=clientdata),
            "solutions": _SOL,
            "solutioncomponents": _IN_SOLUTION,
        }
    )
    with pytest.raises(BuilderRefusal, match="Only_Action"):
        set_flow_action_parameter(
            client, "ImpactIQSandbox", "Broken Flow", "Nope", "item/x", "v",
            report=FixReport(),
        )


def test_alter_column_refuses_unknown_properties():
    client = StubClient({})
    with pytest.raises(BuilderRefusal, match="column fix only supports"):
        alter_column(client, "ImpactIQSandbox", "new_table", "new_col", {"max_length": 500})
    assert "required_level" in COLUMN_FIXABLE  # the documented surface


def test_sandbox_client_has_no_record_create_surface():
    """Fix-only is structural: the client class exposes no record POST."""
    from impactiq.builder.executor import SandboxClient

    assert not hasattr(SandboxClient, "post")
    assert not hasattr(SandboxClient, "create")
    # patch is update-only by header; put_metadata is EntityDefinitions-only.
    import inspect

    src = inspect.getsource(SandboxClient.patch)
    assert "If-Match" in src
