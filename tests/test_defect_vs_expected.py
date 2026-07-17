"""Defect-vs-expected reconciliation - the engine's part of the adjudication
rule (pure logic, no LLM).

The full adjudicator is a reasoning agent; here we verify the deterministic
rule it dispatches to so the case is reproducible end-to-end before any model
runs.
"""

from __future__ import annotations

from impactiq.graph import (
    KnowledgeVerdict,
    TechnicalVerdict,
    reconcile_defect_vs_expected,
)


def test_conflict_flips_to_expected_per_policy():
    """The headline beat: Technical says 'defect', Knowledge says
    'expected_per_policy' -> verdict flips to expected, with the policy fix."""
    technical = TechnicalVerdict(
        verdict="defect",
        rationale=(
            "Flow close_request rewrites Request.status to 'closed' even when "
            "the request is already closed - structurally looks like a redundant "
            "or wrong write."
        ),
        confidence=0.75,
    )
    knowledge = KnowledgeVerdict(
        verdict="expected_per_policy",
        rationale=(
            "SOP-CRM-014 mandates that close_request always emits a terminal "
            "audit row, so re-stamping status on already-closed requests is "
            "the documented behaviour."
        ),
        citations=["SOP-CRM-014#close-audit"],
        confidence=0.85,
    )
    result = reconcile_defect_vs_expected(technical, knowledge)

    assert result.resolution == "expected_behaviour"
    assert "expected" in result.verdict_text.lower()
    # The cited SOP rides through to the final report.
    assert "SOP-CRM-014#close-audit" in result.cited_sources
    # Conflict outcomes show both views with reduced confidence vs full
    # agreement (so the final report can surface the disagreement).
    assert result.confidence < 0.85


def test_agreement_on_no_issue_keeps_expected_with_higher_confidence():
    technical = TechnicalVerdict(verdict="no_issue", rationale="No anomaly.", confidence=0.8)
    knowledge = KnowledgeVerdict(
        verdict="aligned",
        rationale="Aligned with the policy.",
        citations=["ADR-008"],
        confidence=0.8,
    )
    result = reconcile_defect_vs_expected(technical, knowledge)
    assert result.resolution == "expected_behaviour"
    # Agreement raises confidence above the simple average.
    assert result.confidence > 0.8


def test_defect_with_no_policy_override_stays_defect():
    technical = TechnicalVerdict(verdict="defect", rationale="Missing writer.", confidence=0.8)
    knowledge = KnowledgeVerdict(
        verdict="aligned",
        rationale="Policy is silent on this case; nothing overrides.",
        citations=[],
        confidence=0.6,
    )
    result = reconcile_defect_vs_expected(technical, knowledge)
    assert result.resolution == "defect"
