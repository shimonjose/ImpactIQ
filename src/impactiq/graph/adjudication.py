"""Adjudication rule helpers (pure logic, no LLM).

The full Adjudicator is a reasoning agent; this module captures the
*deterministic* rules so the engine can apply them directly in tests and the
single-agent baseline can fall back to them if the agent doesn't run.

Rules implemented:

* **defect-vs-expected** — Technical says "defect", Knowledge says
  "expected_per_policy" → verdict flips to "expected behaviour"; the
  recommendation targets the policy-aware fix.
* **collision** — fold Technical's ``recent_editors`` and Context's
  ``active_change_signals`` into a list of ``Collision`` advisories.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Verdict = Literal[
    "defect", "expected_per_policy", "aligned", "conflicts_with_standard"
]
Resolution = Literal["defect", "expected_behaviour", "candidate_defect"]


@dataclass
class TechnicalVerdict:
    """Stub of the ``TechnicalFinding`` for the defect-vs-expected rule."""

    verdict: Literal["defect", "no_issue"]
    rationale: str
    confidence: float = 0.5


@dataclass
class KnowledgeVerdict:
    """Stub of the ``KnowledgeFinding`` for the defect-vs-expected rule."""

    verdict: Verdict
    rationale: str
    citations: list[str]
    confidence: float = 0.5


@dataclass
class ReconciledFinding:
    resolution: Resolution
    verdict_text: str
    confidence: float
    cited_sources: list[str]
    reasoning: str


def reconcile_defect_vs_expected(
    technical: TechnicalVerdict,
    knowledge: KnowledgeVerdict,
) -> ReconciledFinding:
    """Apply the defect-vs-expected conflict rule.

    The rule: when Technical=defect conflicts with
    Knowledge=expected_per_policy, the verdict flips to "expected behaviour"
    and the recommendation targets the policy-aware fix, not the apparent bug.
    """
    # Agreement: both findings line up.
    if technical.verdict == "no_issue" and knowledge.verdict in (
        "aligned",
        "expected_per_policy",
    ):
        return ReconciledFinding(
            resolution="expected_behaviour",
            verdict_text=(
                "No defect: the technical walk and the documented policy agree."
            ),
            confidence=min(0.99, (technical.confidence + knowledge.confidence) / 2 + 0.1),
            cited_sources=list(knowledge.citations),
            reasoning="Findings agree; confidence raised.",
        )

    # The headline conflict case.
    if technical.verdict == "defect" and knowledge.verdict == "expected_per_policy":
        return ReconciledFinding(
            resolution="expected_behaviour",
            verdict_text=(
                "Behaviour is expected per policy. The structural walk flagged "
                "what looks like a defect, but the cited SOP explicitly "
                "describes this as the intended outcome."
            ),
            # Lower than full agreement: conflict means we surface both views.
            confidence=max(0.4, (technical.confidence + knowledge.confidence) / 2 - 0.1),
            cited_sources=list(knowledge.citations),
            reasoning=(
                "Defect-vs-expected: Knowledge cites policy that overrides "
                "the structural reading. Verdict flipped to expected; "
                "recommendation targets the policy-aware fix, not the "
                "apparent bug."
            ),
        )

    # Technical defect + Knowledge silent or conflicts_with_standard -> defect.
    if technical.verdict == "defect" and knowledge.verdict in (
        "conflicts_with_standard",
        "aligned",
    ):
        return ReconciledFinding(
            resolution="defect",
            verdict_text=(
                "Structural defect, and no policy reading reverses it."
            ),
            confidence=min(0.95, (technical.confidence + knowledge.confidence) / 2 + 0.05),
            cited_sources=list(knowledge.citations),
            reasoning="Findings agree on defect.",
        )

    # Mixed / unclear -> candidate, surface both views.
    return ReconciledFinding(
        resolution="candidate_defect",
        verdict_text=(
            "Possible defect; the structural and policy readings do not fully "
            "agree. Both are surfaced for review."
        ),
        confidence=max(0.3, (technical.confidence + knowledge.confidence) / 2 - 0.15),
        cited_sources=list(knowledge.citations),
        reasoning=(
            f"Technical: {technical.verdict} / Knowledge: {knowledge.verdict}. "
            f"Confidence lowered; evidence preserved."
        ),
    )
