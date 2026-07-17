"""The deterministic post-adjudication verdict gate.

These are negative tests: one case per rule that FAILS if the gate regresses,
plus the load-bearing acceptance that SHADOW mode is a byte-for-byte no-op.
They also cover the write-refused bound (at the end).

Pure logic, no LLM, no network - the gate is deterministic by construction.
"""

from __future__ import annotations

from impactiq.report.verdict_gate import GateFinding, gate_report


def _ctx(finding: dict, citations: list[dict] | None = None) -> dict:
    return {"agent": "context", "finding": finding, "citations": citations or []}


def _tech(finding: dict) -> dict:
    return {"agent": "technical", "finding": finding, "citations": []}


def _know(finding: dict, citations: list[dict] | None = None) -> dict:
    return {"agent": "knowledge", "finding": finding, "citations": citations or []}


def _rules(findings: list[GateFinding]) -> set[str]:
    return {f.rule for f in findings}


# ── the load-bearing acceptance: shadow is a no-op ───────────────────────────


def test_shadow_mode_is_byte_identical_noop():
    """SHADOW computes + reports findings but returns the report UNCHANGED - the
    SAME object, nothing mutated. This is the 'zero output diff vs baseline'
    acceptance gate for wiring the gate on by default."""
    report = {
        "citations": [{"source_id": "INVENTED-SOP"}],          # ungrounded
        "affected_teams": ["Totally Made Up Team"],            # unprovenanced
        "risk": {"score": 5, "level": "low", "reasons": []},
        "recommendation": "Safe to proceed.",
    }
    results = [_ctx({"change_control": ["Power Platform freeze, per Robin"]})]
    before = {**report, "citations": list(report["citations"])}

    out, findings = gate_report(
        {}, results, report, runtime_citations=[], mode="shadow"
    )

    assert out is report                  # same object, untouched
    assert out == before                  # value-identical
    assert findings                        # but it DID notice the problems
    assert all(f.applied is False for f in findings)


def test_default_mode_is_shadow(monkeypatch):
    """Unset IMPACTIQ_VERDICT_GATE → shadow (returns unchanged)."""
    monkeypatch.delenv("IMPACTIQ_VERDICT_GATE", raising=False)
    report = {"citations": [{"source_id": "X"}], "risk": {"level": "low"}}
    out, findings = gate_report({}, [], report, runtime_citations=[])
    assert out is report
    assert out["citations"] == [{"source_id": "X"}]


def test_off_mode_does_nothing():
    report = {"citations": [{"source_id": "X"}]}
    out, findings = gate_report({}, [], report, runtime_citations=[], mode="off")
    assert out is report
    assert findings == []


# ── rule 1: citation grounding ───────────────────────────────────────────────


def test_enforce_drops_ungrounded_citation_keeps_grounded():
    report = {
        "citations": [
            {"source_id": "GROUNDED", "title": "real SOP"},
            {"source_id": "HALLUCINATED", "title": "invented"},
        ],
    }
    out, findings = gate_report(
        {}, [], report,
        runtime_citations=[{"source_id": "GROUNDED"}],
        mode="enforce",
    )
    ids = [c["source_id"] for c in out["citations"]]
    assert ids == ["GROUNDED"]
    assert "citation_grounding" in _rules(findings)
    assert any(f.applied for f in findings if f.rule == "citation_grounding")


def test_specialist_runtime_citation_grounds_a_report_citation():
    """A citation surfaced by a specialist's runtime annotations is ground truth
    even if the adjudicator's own turn didn't re-annotate it."""
    report = {"citations": [{"source_id": "FROM-KNOWLEDGE"}]}
    results = [_know({}, citations=[{"source_id": "FROM-KNOWLEDGE"}])]
    out, findings = gate_report(
        {}, results, report, runtime_citations=[], mode="enforce"
    )
    assert out["citations"] == [{"source_id": "FROM-KNOWLEDGE"}]
    assert "citation_grounding" not in _rules(findings)


def test_kb_finding_citation_is_grounded_not_false_flagged():
    """Foundry-IQ KB citations arrive through the knowledge FINDING's citations
    field (not as response annotations). They must count as grounded - else the
    gate false-flags every real SOP/policy reference (in enforce mode it would
    have dropped legitimate citations)."""
    report = {"citations": [{"source_id": "SOP-FILE-citation-abc_pages_1"}]}
    results = [
        {
            "agent": "knowledge",
            "finding": {
                "governance_verdict": "expected_per_policy",
                "citations": [{"source_id": "SOP-FILE-citation-abc_pages_1"}],
            },
            "citations": [],  # NOTHING in the runtime annotations
        }
    ]
    out, findings = gate_report(
        {}, results, report, runtime_citations=[], mode="enforce"
    )
    assert out["citations"] == [{"source_id": "SOP-FILE-citation-abc_pages_1"}]
    assert "citation_grounding" not in _rules(findings)


def test_adjudicator_invented_citation_still_flagged_even_with_kb_finding():
    """The KB-finding allowance must NOT let a truly invented adjudicator
    citation through: one that matches neither a runtime annotation nor any
    finding citation is still dropped."""
    report = {"citations": [
        {"source_id": "REAL-KB-cite"},      # in the knowledge finding
        {"source_id": "INVENTED-cite"},     # nowhere
    ]}
    results = [_know({"citations": [{"source_id": "REAL-KB-cite"}]})]
    out, findings = gate_report({}, results, report, runtime_citations=[], mode="enforce")
    ids = [c["source_id"] for c in out["citations"]]
    assert ids == ["REAL-KB-cite"]
    assert "citation_grounding" in _rules(findings)


# ── rule 2: owner/people provenance ──────────────────────────────────────────


def test_enforce_strips_invented_team_keeps_resolved_one():
    results = [
        _ctx({"affected_people": ["Sam Rivera (owner)"], "likely_owner": "Sam Rivera"}),
        _tech({"evidence": ["resolve_owner returned the CRM Operations team"]}),
    ]
    report = {
        "affected_teams": ["CRM Operations", "Phantom Finance Squad"],
    }
    out, findings = gate_report({}, results, report, mode="enforce")
    assert out["affected_teams"] == ["CRM Operations"]      # resolved one survives
    assert "owner_provenance" in _rules(findings)


def test_enforce_strips_solution_name_used_as_a_team():
    results = [_tech({"evidence": ["walk done"]})]   # provenance source present
    report = {"affected_teams": ["Customer Service Hub"]}
    out, findings = gate_report(
        {}, results, report, solution_name="Customer Service Hub", mode="enforce"
    )
    assert out["affected_teams"] == []
    assert any("solution name" in f.detail for f in findings)


def test_provenance_skipped_when_no_specialist_findings():
    """With no technical/context finding (e.g. the legacy single-agent path) we
    have no provenance source - never strip a name on no evidence."""
    report = {"affected_teams": ["Some Team"]}
    out, findings = gate_report({}, [], report, mode="enforce")
    assert out["affected_teams"] == ["Some Team"]
    assert "owner_provenance" not in _rules(findings)


def test_enforce_clears_unprovenanced_collision_who():
    results = [_tech({"evidence": ["walk found flow X"]})]
    report = {
        "change_collisions": [
            {"component": {"id": "f", "kind": "Flow", "name": "X"},
             "who": "Imaginary Person", "sensitivity": "open", "advice": "coordinate"}
        ]
    }
    out, findings = gate_report({}, results, report, mode="enforce")
    assert out["change_collisions"][0]["who"] is None
    assert "owner_provenance" in _rules(findings)


# ── rule 3a: freeze dominance ────────────────────────────────────────────────


def test_freeze_raises_low_risk_and_flags_missing_hold():
    results = [_ctx({"change_control": ["Change freeze on Power Platform (Robin)"]})]
    report = {
        "risk": {"score": 8, "level": "low", "reasons": ["sparse radius"]},
        "recommendation": "Looks safe - go ahead and ship it.",
    }
    out, findings = gate_report({}, results, report, mode="enforce")
    assert out["risk"]["level"] == "medium"
    assert out["risk"]["score"] >= 35
    rules = _rules(findings)
    assert "change_control_dominance" in rules
    # both the raise AND the missing-hold flag fired
    actions = {(f.rule, f.action) for f in findings}
    assert ("change_control_dominance", "raise_risk") in actions
    assert ("change_control_dominance", "flag") in actions


def test_freeze_honoured_recommendation_does_not_flag_missing_hold():
    results = [_ctx({"change_control": ["Change freeze on Power Platform (Robin)"]})]
    report = {
        "risk": {"score": 40, "level": "medium", "reasons": []},
        "recommendation": "Hold this change until the freeze lifts; coordinate first.",
    }
    out, findings = gate_report({}, results, report, mode="enforce")
    # medium already → no raise; recommendation honours the freeze → no flag
    assert "change_control_dominance" not in _rules(findings)


def test_no_freeze_no_freeze_findings():
    results = [_ctx({"change_control": []})]
    report = {"risk": {"score": 5, "level": "low"}, "recommendation": "ship it"}
    out, findings = gate_report({}, results, report, mode="enforce")
    assert "change_control_dominance" not in _rules(findings)


def test_change_control_dominance_ignores_a_lifted_freeze():
    """A freeze that was already LIFTED is not an active blocker - it must NOT
    fire change_control_dominance or floor the risk."""
    for cc in (
        "The Power Platform change freeze was lifted on Monday.",
        "Earlier change freeze has been rescinded; changes allowed again.",
        "Freeze is over - back to normal.",
    ):
        results = [_ctx({"change_control": [cc]})]
        report = {"risk": {"score": 8, "level": "low"}, "recommendation": "ship it"}
        out, findings = gate_report({}, results, report, mode="enforce")
        assert "change_control_dominance" not in _rules(findings), cc
        assert out["risk"]["level"] == "low"  # not floored by a dead freeze


def test_change_control_dominance_generalises_beyond_freeze():
    """The rule fires for ANY active directive - an approval/sign-off gate, a
    release embargo, an active incident - not just a freeze; and it ignores ones
    already SATISFIED (approval granted / signed off / cleared)."""
    active = [
        "Changes to Admin Task need Alex's approval first (per the change board).",
        "Release embargo in effect until the audit completes.",
        "Active incident - no deploys to this environment right now.",
    ]
    for cc in active:
        results = [_ctx({"change_control": [cc]})]
        report = {"risk": {"score": 8, "level": "low"}, "recommendation": "ship it"}
        out, findings = gate_report({}, results, report, mode="enforce")
        assert "change_control_dominance" in _rules(findings), cc
        assert out["risk"]["level"] == "medium", cc

    satisfied = [
        "Approval granted - Alex signed off and cleared it.",
        "Embargo over; incident resolved.",
    ]
    for cc in satisfied:
        results = [_ctx({"change_control": [cc]})]
        report = {"risk": {"score": 8, "level": "low"}, "recommendation": "ship it"}
        out, findings = gate_report({}, results, report, mode="enforce")
        assert "change_control_dominance" not in _rules(findings), cc
        assert out["risk"]["level"] == "low", cc


def test_change_control_dominance_fires_for_active_and_future_lift():
    """An active freeze (or one only scheduled to lift LATER) is still current →
    it fires and floors the risk."""
    for cc in (
        "Active Power Platform change freeze announced by Robin, no end date.",
        "Freeze will be lifted next week - until then, no changes.",
    ):
        results = [_ctx({"change_control": [cc]})]
        report = {"risk": {"score": 8, "level": "low"}, "recommendation": "ship it"}
        out, findings = gate_report({}, results, report, mode="enforce")
        assert "change_control_dominance" in _rules(findings), cc
        assert out["risk"]["level"] == "medium"


# ── rule 3b: defect-vs-expected flip ─────────────────────────────────────────


def test_unflipped_defect_under_expected_policy_is_flagged():
    results = [
        _know({"governance_verdict": "expected_per_policy"}),
        _tech({"likely_cause": "the flow is broken and never ran"}),
    ]
    report = {
        "verdict": "This is a defect in the close-request flow.",
        "reconciliation": "The flow looks wrong.",
        "citations": [],
    }
    out, findings = gate_report({}, results, report, mode="enforce")
    assert "defect_expected_flip" in _rules(findings)


def test_properly_flipped_verdict_is_not_flagged():
    results = [
        _know({"governance_verdict": "expected_per_policy"}),
        _tech({"likely_cause": "the flow is broken and never ran"}),
    ]
    report = {
        "verdict": "This is expected behaviour per policy, not a defect.",
        "reconciliation": "The SOP documents this as the standard behaviour.",
        "citations": [],
    }
    out, findings = gate_report({}, results, report, mode="enforce")
    assert "defect_expected_flip" not in _rules(findings)


# ── the gate must never crash a turn ─────────────────────────────────────────


def test_gate_never_raises_on_garbage():
    # citations is a string, risk is an int - all the wrong shapes.
    report = {"citations": "not-a-list", "risk": 7, "affected_teams": 3}
    out, findings = gate_report({}, [_tech({})], report, mode="enforce")
    # Either it coped (returned a report) - it must never raise.
    assert isinstance(out, dict)


# ── write bound is actually refused ──────────────────────────────────────────


def test_validate_intent_remediation_is_refused():
    from impactiq.report.artifacts import validate_artifact_payload

    payload = {
        "artifact_type": "remediation_proposal",
        "operation": "update",
        "record_table": "account",
        "record_id": "rec-1",
        "changes": [{"column": "statuscode", "proposed_value": "1"}],
        "evidence_source": "diagnosis",
        "diagnosis_confidence": 0.95,
    }
    artifact, refusal = validate_artifact_payload("VALIDATE", payload)
    assert artifact is None
    assert refusal and refusal["use_instead"] == "manager_handoff"


def test_remediation_on_configuration_table_is_refused():
    from impactiq.report.artifacts import validate_artifact_payload

    payload = {
        "artifact_type": "remediation_proposal",
        "operation": "update",
        "record_table": "team",   # configuration, not business data
        "record_id": "team-1",
        "changes": [{"column": "name", "proposed_value": "X"}],
        "evidence_source": "diagnosis",
        "diagnosis_confidence": 0.95,
    }
    artifact, refusal = validate_artifact_payload("DIAGNOSE", payload)
    assert artifact is None
    assert refusal and "configuration" in refusal["refused"]
