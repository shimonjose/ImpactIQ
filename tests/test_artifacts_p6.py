"""Offer-gate enforcement, baton round-trip, card rendering.

These tests pin the SAFETY bounds in code: configuration refusal,
bulk-to-blueprint, document-grounded discipline (typed confirm, source span,
no agent-fished docs, no hallucinated values), draft-only statuses, and the
context baton's structural inability to carry restricted substance.
"""

from __future__ import annotations

import json

import pytest

from impactiq.report.artifacts import (
    ContextBaton,
    ManagerHandoff,
    RemediationProposal,
    parse_artifact,
    validate_artifact_payload,
)
from impactiq.report.card import report_to_adaptive_card
from impactiq.report.schema import ImpactReport


def _remediation(**over) -> dict:
    base = {
        "artifact_type": "remediation_proposal",
        "record_table": "new_customerrequest",
        "record_id": "11111111-2222-3333-4444-555555555555",
        "record_name": "CR-1042",
        "changes": [
            {"column": "statuscode", "current_value": "Closed", "proposed_value": "Reopened"}
        ],
        "evidence_source": "diagnosis",
        "diagnosis_summary": "flow failed before stamping status",
        "diagnosis_confidence": 0.92,
        "downstream_preview": ["Flow 'Notify owner' will fire on update"],
    }
    base.update(over)
    return base


# ── offer gate ───────────────────────────────────────────────────────────────


def test_remediation_validates_on_diagnose():
    artifact, refusal = validate_artifact_payload("DIAGNOSE", _remediation())
    assert refusal is None
    assert artifact["confirmation"] == "tap"
    assert artifact["executed"] is False


def test_remediation_refused_on_validate_intent():
    artifact, refusal = validate_artifact_payload("VALIDATE", _remediation())
    assert artifact is None
    assert refusal["use_instead"] == "manager_handoff"


def test_remediation_refused_on_configuration_table():
    artifact, refusal = validate_artifact_payload(
        "DIAGNOSE", _remediation(record_table="workflow")
    )
    assert artifact is None
    assert refusal["use_instead"] == "dev_ticket"
    assert "configuration" in refusal["refused"]


def test_remediation_refused_below_confidence_floor():
    artifact, refusal = validate_artifact_payload(
        "DIAGNOSE", _remediation(diagnosis_confidence=0.6)
    )
    assert artifact is None
    assert "confidence" in refusal["refused"]


def test_remediation_requires_record_id():
    artifact, refusal = validate_artifact_payload(
        "DIAGNOSE", _remediation(record_id="  ")
    )
    assert artifact is None
    assert refusal["use_instead"] == "backfill_blueprint"


def test_no_hallucinated_values():
    bad = _remediation(
        changes=[{"column": "new_rootcause", "current_value": None, "proposed_value": None}]
    )
    artifact, refusal = validate_artifact_payload("DIAGNOSE", bad)
    assert artifact is None
    assert "silent" in refusal["refused"]


# ── document-grounded discipline ─────────────────────────────────────────────


def _doc_remediation(**over) -> dict:
    doc_fields = {
        "evidence_source": "document",
        "document_name": "Corrections March.docx",
        "source_span": "set CR-1042 status to Reopened per customer call",
        "extraction_confidence": 0.9,
    }
    doc_fields.update(over)
    return _remediation(**doc_fields)


def test_document_grounded_forces_typed_confirmation():
    artifact, refusal = validate_artifact_payload(
        "DIAGNOSE", _doc_remediation(), user_referenced_document=True
    )
    assert refusal is None
    assert artifact["confirmation"] == "typed"


def test_document_grounded_refused_without_user_reference():
    artifact, refusal = validate_artifact_payload(
        "DIAGNOSE", _doc_remediation(), user_referenced_document=False
    )
    assert artifact is None
    assert "agent-initiated" in refusal["refused"]


def test_document_grounded_requires_source_span():
    artifact, refusal = validate_artifact_payload(
        "DIAGNOSE",
        _doc_remediation(source_span=None),
        user_referenced_document=True,
    )
    assert artifact is None
    assert "source_span" in refusal["refused"]


# ── bulk path ────────────────────────────────────────────────────────────────


def test_backfill_requires_idempotency_note():
    payload = {
        "artifact_type": "backfill_blueprint",
        "query": "statuscode eq 'Closed' and modifiedon lt 2026-06-01",
        "per_record_update": [
            {"column": "statuscode", "proposed_value": "Reopened"}
        ],
        "idempotency_note": "",
    }
    artifact, refusal = validate_artifact_payload("DIAGNOSE", payload)
    assert artifact is None
    assert "idempotency" in refusal["refused"]


# ── handoff + baton ──────────────────────────────────────────────────────────


def _handoff() -> dict:
    return {
        "artifact_type": "manager_handoff",
        "recipient": "Sam (Team A manager)",
        "draft_text": (
            "User B from Team B proposes a change the dependency map suggests "
            "may affect your team's data on Customer Request. You may want to "
            "review before they proceed."
        ),
        "baton": {
            "requesting_user": "User B",
            "intent": "VALIDATE",
            "anchor": {"id": "table:new_customerrequest", "kind": "Table", "name": "Customer Request"},
            "proposed_change": "add a new column and auto-stamp flow",
            "impacted_components": [
                {"id": "flow:abc", "kind": "Flow", "name": "Complaint creation flow"}
            ],
            "risk_level": "medium",
            "resume_hint": "assess impact on Team A assets",
        },
    }


def test_handoff_validates_and_baton_round_trips():
    artifact, refusal = validate_artifact_payload("VALIDATE", _handoff())
    assert refusal is None
    assert artifact["status"] == "draft"
    # Round-trip: dump -> JSON -> parse -> same baton identity + content.
    raw = json.dumps(artifact)
    parsed = parse_artifact(json.loads(raw))
    assert isinstance(parsed, ManagerHandoff)
    assert parsed.baton.baton_id == artifact["baton"]["baton_id"]
    assert parsed.baton.anchor.name == "Customer Request"
    assert parsed.baton.requesting_user == "User B"


def test_baton_cannot_carry_substance_field():
    # Structural enforcement: unknown fields like a "details"/"substance"
    # payload are DROPPED by the model config, so a drafting LLM cannot smuggle
    # another team's content through the baton.
    b = ContextBaton.model_validate(
        {
            "requesting_user": "User B",
            "intent": "VALIDATE",
            "anchor": {"id": "t:x", "kind": "Table", "name": "X"},
            "proposed_change": "rename column",
            "confidential_details": "Team A is secretly working on Project Layoffs",
        }
    )
    assert "confidential_details" not in b.model_dump()


def test_remediation_executed_cannot_be_true():
    with pytest.raises(Exception):
        RemediationProposal.model_validate(_remediation(executed=True))


# ── collision-shape coercion (observed model drift) ──────────────────────────


@pytest.mark.parametrize(
    "collision",
    [
        # string component
        {"component": "Flow X", "who": "Team A"},
        # flattened NodeRef
        {"id": "flow:1", "kind": "Flow", "name": "Flow X", "owner": "Team A"},
        # component_id spelling
        {"component_id": "flow:1", "component_name": "Flow X", "owner": "Team A"},
    ],
)
def test_collision_shape_coercion(collision):
    report = ImpactReport.model_validate(
        {
            "intent": "VALIDATE",
            "verdict": "v",
            "confidence": 0.9,
            "risk": {"score": 10, "level": "low", "reasons": []},
            "recommendation": "r",
            "change_collisions": [collision],
        }
    )
    coll = report.change_collisions[0]
    assert coll.component.name == "Flow X" or coll.component.id
    assert coll.who == "Team A"


# ── create extension ─────────────────────────────────────────────────────────


def _create_proposal(**over) -> dict:
    base = _remediation(
        operation="create",
        record_id="",
        record_name="",
        changes=[
            {"column": "new_internalnotes", "proposed_value": "Created for CR-1042"},
            {
                "column": "new_relatedrequest@odata.bind",
                "proposed_value": "new_customerrequests(11111111-2222-3333-4444-555555555555)",
            },
        ],
        diagnosis_summary="flow failed before writing the row; payload from the failed action",
    )
    base.update(over)
    return base


def test_create_proposal_validates_and_forces_typed():
    artifact, refusal = validate_artifact_payload("DIAGNOSE", _create_proposal())
    assert refusal is None
    assert artifact["operation"] == "create"
    # A new row is higher-consequence than a field fix: tap never suffices.
    assert artifact["confirmation"] == "typed"


def test_create_proposal_refuses_record_id():
    _, refusal = validate_artifact_payload(
        "DIAGNOSE", _create_proposal(record_id="11111111-2222-3333-4444-555555555555")
    )
    assert refusal is not None and "must not carry a record_id" in refusal["refused"]


def test_create_proposal_refuses_document_grounding():
    _, refusal = validate_artifact_payload(
        "DIAGNOSE",
        _create_proposal(
            evidence_source="document",
            document_name="spec.docx",
            source_span="…",
            extraction_confidence=0.99,
        ),
        user_referenced_document=True,
    )
    assert refusal is not None and "diagnosis-grounded" in refusal["refused"]


def test_create_proposal_refuses_valueless_column():
    bad = _create_proposal()
    bad["changes"].append({"column": "statuscode", "options": ["1", "2"]})
    _, refusal = validate_artifact_payload("DIAGNOSE", bad)
    assert refusal is not None and "no concrete value" in refusal["refused"]


def test_card_renders_create_with_typed_input():
    artifact, _ = validate_artifact_payload("DIAGNOSE", _create_proposal())
    card = report_to_adaptive_card(_report_with(artifact))
    blob = json.dumps(card)
    assert "create the missing row" in blob
    assert "typed_confirmation" in blob
    assert '"confirmation": "typed"' in blob
    assert "sourceSpanPane" not in blob  # diagnosis-grounded


# ── card rendering ───────────────────────────────────────────────────────────


def _report_with(artifact: dict | None) -> ImpactReport:
    return ImpactReport.model_validate(
        {
            "intent": "DIAGNOSE",
            "anchor": {"id": "t:x", "kind": "Table", "name": "X"},
            "verdict": "v",
            "confidence": 0.9,
            "risk": {"score": 10, "level": "low", "reasons": ["r"]},
            "recommendation": "do x",
            "evidence": [{"kind": "tool", "detail": "walk found 2 causal"}],
            "generated_artifact": artifact,
        }
    )


def test_card_renders_diagnosis_remediation_with_tap():
    artifact, _ = validate_artifact_payload("DIAGNOSE", _remediation())
    card = report_to_adaptive_card(_report_with(artifact))
    blob = json.dumps(card)
    assert card["type"] == "AdaptiveCard"
    assert "confirm_remediation" in blob
    assert '"confirmation": "tap"' in blob
    assert "sourceSpanPane" not in blob  # diagnosis-grounded: no doc pane


def test_card_renders_document_remediation_with_span_pane_and_typed():
    artifact, _ = validate_artifact_payload(
        "DIAGNOSE", _doc_remediation(), user_referenced_document=True
    )
    card = report_to_adaptive_card(_report_with(artifact))
    blob = json.dumps(card)
    assert "sourceSpanPane" in blob  # document-grounded: never omitted
    assert "typed_confirmation" in blob
    assert '"confirmation": "typed"' in blob


def test_card_renders_handoff_with_approve_action():
    artifact, _ = validate_artifact_payload("VALIDATE", _handoff())
    card = report_to_adaptive_card(_report_with(artifact))
    blob = json.dumps(card)
    assert "send_handoff" in blob
    assert "Approve & send" in blob
