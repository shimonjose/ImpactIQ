"""Boundary between the unified layer and the deep pipeline: the unified layer
investigates and proposes actions; the deep pipeline adjudicates. These tests
pin the seams: `propose_record_fix` (same offer gate, card attached, never
executes) and the deep tool's evidence handoff.
"""

from __future__ import annotations

import json

from impactiq.server import _attach_report_cards, _record_fix_tool_specs


def _create_payload() -> dict:
    return {
        "artifact_type": "remediation_proposal",
        "operation": "create",
        "record_table": "new_admintask",
        "record_id": "",
        "record_name": "",
        "changes": [
            {"column": "new_internalnotes", "proposed_value": "Backfill for CR-1042"},
        ],
        "evidence_source": "diagnosis",
        "diagnosis_summary": "flow failed before writing the row",
        "diagnosis_confidence": 0.9,
    }


def test_propose_record_fix_stashes_validated_artifact(tmp_path, monkeypatch):
    monkeypatch.setenv("IMPACTIQ_AUDIT_DIR", str(tmp_path))
    holder: dict = {}
    spec = _record_fix_tool_specs(holder)[0]
    out = json.loads(spec.impl({"artifact": _create_payload()}))
    assert out["proposed"] is True and "NOT applied" in out["note"]
    art = holder["unified_artifact"]
    assert art["operation"] == "create"
    assert art["confirmation"] == "typed"  # creates never tap


def test_propose_record_fix_passes_gate_refusals_through():
    """The same deterministic offer gate the adjudicator uses - a config-table
    proposal is refused with the pivot instruction, nothing stashed."""
    holder: dict = {}
    spec = _record_fix_tool_specs(holder)[0]
    bad = _create_payload()
    bad["record_table"] = "workflow"  # configuration in disguise
    out = json.loads(spec.impl({"artifact": bad}))
    assert "refused" in out and "configuration" in out["refused"]
    assert "unified_artifact" not in holder


def test_attach_cards_renders_unified_proposal_and_minimal_report(tmp_path, monkeypatch):
    monkeypatch.setenv("IMPACTIQ_AUDIT_DIR", str(tmp_path))
    holder: dict = {}
    spec = _record_fix_tool_specs(holder)[0]
    spec.impl({"artifact": _create_payload()})
    result = _attach_report_cards({"text": "found it"}, holder)
    # The preview card is attached under its own key (record_fix_card - kept
    # distinct from a deep report's artifact_card so chips suppress correctly)
    # and is typed-gated…
    blob = json.dumps(result["record_fix_card"])
    assert "confirm_remediation" in blob and "typed_confirmation" in blob
    # …and the minimal report shape lets the surface's confirm tap resolve
    # state.report.generated_artifact without a deep-pipeline report.
    assert result["report"]["generated_artifact"]["operation"] == "create"


def test_deep_tool_carries_evidence_param():
    """The deep pipeline accepts the front agent's findings - adjudicate,
    don't re-derive."""
    from impactiq.agents.tools import EngineToolSpec  # noqa: F401 - import sanity
    import inspect

    import impactiq.server as srv

    src = inspect.getsource(srv._unified_tools)
    assert '"evidence"' in src
    assert "do not re-derive" in src


def test_standalone_artifact_card_matches_report_embedded_rendering():
    from impactiq.report.artifacts import validate_artifact_payload
    from impactiq.report.card import standalone_artifact_card

    artifact, refusal = validate_artifact_payload("DIAGNOSE", _create_payload())
    assert refusal is None
    card = standalone_artifact_card(artifact)
    blob = json.dumps(card)
    assert card["type"] == "AdaptiveCard"
    assert "create the missing row" in blob
