"""Offline tests for the clientdata parser.

No LLM, no live tenant. The fixture is a worked example, so any drift in the
parser is caught here before it leaks into edges.
"""

from __future__ import annotations

import json

from impactiq.connectors.flows import (
    _fallback_singularize,
    parse_clientdata,
)


# The worked example, verbatim.
ARCHITECTURE_DOC_FIXTURE = {
    "properties": {
        "connectionReferences": {
            "shared_commondataserviceforapps": {
                "connection": {"connectionReferenceLogicalName": "new_dvconn"}
            }
        },
        "definition": {
            "triggers": {
                "When_a_row_is_added_or_modified": {
                    "type": "OpenApiConnectionWebhook",
                    "inputs": {
                        "host": {
                            "connectionName": "shared_commondataserviceforapps",
                            "operationId": "SubscribeWebhookTrigger",
                        },
                        "parameters": {
                            "subscriptionRequest/entityname": "request",
                            "subscriptionRequest/scope": 4,
                            "subscriptionRequest/message": 3,
                        },
                    },
                }
            },
            "actions": {
                "Update_a_row": {
                    "type": "OpenApiConnection",
                    "inputs": {
                        "host": {
                            "connectionName": "shared_commondataserviceforapps",
                            "operationId": "UpdateRecord",
                        },
                        "parameters": {
                            "entityName": "requests",
                            "recordId": "@triggerOutputs()?['body/requestid']",
                            "item/statuscode": 2,
                            "item/resolutionnotes": "@...",
                            "item/primarycontactid@odata.bind": "/contacts(<id>)",
                        },
                    },
                }
            },
        },
    }
}


def test_parses_architecture_doc_fixture_as_dict():
    parsed = parse_clientdata(ARCHITECTURE_DOC_FIXTURE)

    assert parsed["connection_references"] == ["new_dvconn"]

    assert len(parsed["triggers"]) == 1
    trig = parsed["triggers"][0]
    assert trig["operation"] == "SubscribeWebhookTrigger"
    assert trig["entity_singular"] == "request"
    assert trig["message"] == 3

    assert len(parsed["actions"]) == 1
    act = parsed["actions"][0]
    assert act["operation"] == "UpdateRecord"
    assert act["entity_plural"] == "requests"
    assert act["action_name"] == "Update_a_row"
    # Lookup binding suffix is stripped.
    assert set(act["columns"]) == {"statuscode", "resolutionnotes", "primarycontactid"}


def test_parses_architecture_doc_fixture_as_string():
    """`clientdata` arrives as a JSON string from Dataverse; same result either way."""
    parsed = parse_clientdata(json.dumps(ARCHITECTURE_DOC_FIXTURE))
    assert parsed["connection_references"] == ["new_dvconn"]
    assert parsed["actions"][0]["operation"] == "UpdateRecord"


def test_empty_and_missing_inputs_dont_raise():
    assert parse_clientdata(None) == {
        "connection_references": [],
        "triggers": [],
        "actions": [],
    }
    assert parse_clientdata("") == {
        "connection_references": [],
        "triggers": [],
        "actions": [],
    }
    # Properties block missing entirely.
    assert parse_clientdata({"properties": {}}) == {
        "connection_references": [],
        "triggers": [],
        "actions": [],
    }


def test_action_with_no_columns():
    """A read action (ListRecords) has no item/<col> keys."""
    parsed = parse_clientdata(
        {
            "properties": {
                "definition": {
                    "actions": {
                        "List_rows": {
                            "inputs": {
                                "host": {"operationId": "ListRecords"},
                                "parameters": {"entityName": "contacts"},
                            }
                        }
                    }
                }
            }
        }
    )
    assert parsed["actions"][0]["operation"] == "ListRecords"
    assert parsed["actions"][0]["entity_plural"] == "contacts"
    assert parsed["actions"][0]["columns"] == []


def test_parses_create_record_nested_in_condition():
    """The real 'When Complaint Created' flow: the CreateRecord that adds an
    Admin Task lives inside the Condition's 'if yes' branch, not at top level.
    Regression for the parser missing nested control-flow actions."""
    fixture = {
        "properties": {
            "definition": {
                "triggers": {
                    "When_a_row_is_added": {
                        "inputs": {
                            "host": {"operationId": "SubscribeWebhookTrigger"},
                            "parameters": {
                                "subscriptionRequest/entityname": "new_customerrequest",
                                "subscriptionRequest/message": 1,
                            },
                        }
                    }
                },
                "actions": {
                    "Condition": {
                        "type": "If",
                        "actions": {
                            "Add_a_new_row_to_Admin_Task_Table": {
                                "inputs": {
                                    "host": {"operationId": "CreateRecord"},
                                    "parameters": {
                                        "entityName": "new_admintasks",
                                        "item/new_tasknumber": "@null",
                                    },
                                }
                            }
                        },
                        "else": {
                            "actions": {
                                "Terminate": {
                                    "inputs": {"host": {"operationId": "Terminate"}}
                                }
                            }
                        },
                    }
                },
            }
        }
    }
    parsed = parse_clientdata(fixture)
    ops = {a["operation"]: a for a in parsed["actions"]}
    assert "CreateRecord" in ops, "nested CreateRecord was not parsed"
    assert ops["CreateRecord"]["entity_plural"] == "new_admintasks"
    assert "new_tasknumber" in ops["CreateRecord"]["columns"]


def test_parses_actions_in_switch_cases():
    fixture = {
        "properties": {
            "definition": {
                "actions": {
                    "Switch": {
                        "type": "Switch",
                        "cases": {
                            "Case_Complaint": {
                                "actions": {
                                    "Create_task": {
                                        "inputs": {
                                            "host": {"operationId": "CreateRecord"},
                                            "parameters": {"entityName": "tasks"},
                                        }
                                    }
                                }
                            }
                        },
                        "default": {"actions": {}},
                    }
                }
            }
        }
    }
    parsed = parse_clientdata(fixture)
    assert any(a["operation"] == "CreateRecord" for a in parsed["actions"])


def test_fallback_singularizer_handles_common_plurals():
    assert _fallback_singularize("requests") == "request"
    assert _fallback_singularize("contacts") == "contact"
    assert _fallback_singularize("opportunities") == "opportunity"
    assert _fallback_singularize("addresses") == "address"
    # ss / unrecognized stays as-is.
    assert _fallback_singularize("access") == "access"
    assert _fallback_singularize("msdyn_kpi") == "msdyn_kpi"
