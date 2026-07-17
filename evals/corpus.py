"""The golden corpus: labelled ImpactIQ scenarios.

Two kinds:

* ``gate``   - mock/deterministic: a draft report with a KNOWN flaw + the
  findings that should ground it, fed through the real verdict gate (enforce).
  Grades that the gate corrected exactly what it should (one negative case per
  gate rule).
* ``golden`` - mock/deterministic: a CORRECT report for a showcase scenario.
  Grades the hard fields + verdict class, and asserts the gate finds NOTHING to
  fix (a clean verdict stays clean).

``reasoning`` (live) cases run the real pipeline; left as templates here because
they need a live tenant/estate matching the labels (see evals/run.py --live).

The reasoning showcase - freeze dominance, defect-vs-expected flip,
existing-equivalent reuse, change-collision, clarify-don't-hedge - is covered
explicitly below; those are the product's differentiator.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Expected:
    # hard labels (None = not graded for this case)
    intent: str | None = None
    anchor_id: str | None = None
    verdict_class: str | None = None
    risk_bucket: str | None = None
    must_mention: list[str] = field(default_factory=list)
    must_not_mention: list[str] = field(default_factory=list)
    artifact_type: str | None = "ANY"          # "ANY" = unchecked; None = must be absent
    required_citations: list[str] = field(default_factory=list)
    # gate-behaviour expectations (mock)
    gate_clean: bool = False                    # True = the gate must find NOTHING
    gate_rules_fire: list[str] = field(default_factory=list)
    citations_dropped: list[str] = field(default_factory=list)
    names_stripped: list[str] = field(default_factory=list)
    risk_floored_to: str | None = None
    write_denied: bool = False


@dataclass
class EvalCase:
    name: str
    kind: str                                   # "gate" | "golden" | "reasoning"
    expected: Expected
    description: str = ""
    # mock inputs
    results: list[dict] = field(default_factory=list)
    draft_report: dict = field(default_factory=dict)
    runtime_citations: list[dict] = field(default_factory=list)
    solution_name: str = "Customer Service"
    # live inputs
    question: str = ""
    as_user: bool = False


def _ctx(finding: dict) -> dict:
    return {"agent": "context", "finding": finding, "citations": []}


def _tech(finding: dict) -> dict:
    return {"agent": "technical", "finding": finding, "citations": []}


def _know(finding: dict, citations: list[dict] | None = None) -> dict:
    return {"agent": "knowledge", "finding": finding, "citations": citations or []}


# ── one negative eval per gate ────────────────────────────────────────────────

GATE_CASES = [
    EvalCase(
        name="gate_citation_grounding",
        kind="gate",
        description="A hallucinated citation is dropped; the grounded one survives.",
        results=[_know({"governance_verdict": "expected_per_policy"},
                       citations=[{"source_id": "SOP-CRM-014"}])],
        runtime_citations=[{"source_id": "SOP-CRM-014"}],
        draft_report={
            "intent": "DIAGNOSE",
            "verdict": "Expected per policy.",
            "citations": [{"source_id": "SOP-CRM-014"}, {"source_id": "INVENTED-POLICY-9"}],
            "risk": {"score": 10, "level": "low", "reasons": []},
        },
        expected=Expected(
            gate_rules_fire=["citation_grounding"],
            citations_dropped=["INVENTED-POLICY-9"],
            required_citations=["SOP-CRM-014"],
        ),
    ),
    EvalCase(
        name="gate_owner_provenance",
        kind="gate",
        description="An invented team is stripped; a resolved owner survives.",
        results=[
            _ctx({"affected_people": ["Sam Rivera (owner)"], "likely_owner": "Sam Rivera"}),
            _tech({"evidence": ["resolve_owner returned the CRM Operations team"]}),
        ],
        draft_report={
            "intent": "DIAGNOSE",
            "verdict": "Coordinate before changing.",
            "affected_teams": ["CRM Operations", "Phantom Finance Squad"],
            "risk": {"score": 20, "level": "low", "reasons": []},
        },
        expected=Expected(
            gate_rules_fire=["owner_provenance"],
            names_stripped=["Phantom Finance Squad"],
            must_not_mention=["Phantom Finance Squad"],
        ),
    ),
    EvalCase(
        name="gate_change_control_dominance",
        kind="gate",
        description="A change freeze floors a 'low' risk to medium.",
        results=[_ctx({"change_control": ["Power Platform change freeze announced by Robin"]})],
        draft_report={
            "intent": "VALIDATE",
            "verdict": "Looks fine.",
            "recommendation": "Go ahead and ship it.",
            "risk": {"score": 8, "level": "low", "reasons": ["sparse radius"]},
        },
        expected=Expected(gate_rules_fire=["change_control_dominance"], risk_floored_to="medium"),
    ),
    EvalCase(
        name="gate_change_control_approval_gate",
        kind="gate",
        description="A NON-freeze directive (an approval/sign-off gate via the change board) also dominates → floors low risk to medium.",
        results=[_ctx({"change_control": ["Changes to Admin Task need Alex's sign-off first (per the change board)"]})],
        draft_report={
            "intent": "VALIDATE",
            "verdict": "Looks fine.",
            "recommendation": "Go ahead and ship it.",
            "risk": {"score": 8, "level": "low", "reasons": []},
        },
        expected=Expected(gate_rules_fire=["change_control_dominance"], risk_floored_to="medium"),
    ),
    EvalCase(
        name="gate_defect_vs_expected_unflipped",
        kind="gate",
        description="Knowledge=expected + Technical defect but verdict still reads as a defect → flagged.",
        results=[
            _know({"governance_verdict": "expected_per_policy"}),
            _tech({"likely_cause": "the close_request flow is broken and never ran"}),
        ],
        draft_report={
            "intent": "DIAGNOSE",
            "verdict": "This is a defect in the close_request flow.",
            "reconciliation": "The flow looks wrong.",
            "citations": [],
            "risk": {"score": 30, "level": "low", "reasons": []},
        },
        expected=Expected(gate_rules_fire=["defect_expected_flip"]),
    ),
]


# ── reasoning showcase, as golden (correct) reports ───────────────────────────

GOLDEN_CASES = [
    EvalCase(
        name="showcase_change_control_dominance",
        kind="golden",
        description="VALIDATE under an active freeze: lead with the hold, risk >= medium.",
        results=[_ctx({"change_control": ["Power Platform change freeze (per Robin), no end date"]})],
        draft_report={
            "intent": "VALIDATE",
            "verdict": "Do not proceed yet - there is an active change freeze on Power Platform.",
            "reconciliation": "A freeze is in effect, which overrides the low technical risk.",
            "recommendation": "Hold this change until the freeze lifts; coordinate with Robin first.",
            "risk": {"score": 40, "level": "medium", "reasons": ["active change freeze"]},
            "confidence": 0.8,
        },
        expected=Expected(
            intent="VALIDATE", verdict_class="blocked_by_change_control",
            risk_bucket="medium", gate_clean=True,
        ),
    ),
    EvalCase(
        name="showcase_defect_to_expected_flip",
        kind="golden",
        description="Technical defect flipped to expected-per-policy with the citation.",
        results=[
            _know({"governance_verdict": "expected_per_policy"},
                  citations=[{"source_id": "SOP-CRM-014"}]),
            _tech({"likely_cause": "close_request re-stamps status on already-closed requests"}),
        ],
        runtime_citations=[{"source_id": "SOP-CRM-014"}],
        draft_report={
            "intent": "DIAGNOSE",
            "verdict": "This is expected behaviour per policy, not a defect.",
            "reconciliation": "The SOP documents the re-stamp as the standard terminal-audit behaviour.",
            "recommendation": "No fix needed; this matches the documented process.",
            "citations": [{"source_id": "SOP-CRM-014", "title": "SOP-CRM-014"}],
            "risk": {"score": 15, "level": "low", "reasons": []},
            "confidence": 0.7,
        },
        expected=Expected(
            intent="DIAGNOSE", verdict_class="expected_per_policy",
            required_citations=["SOP-CRM-014"], gate_clean=True,
        ),
    ),
    EvalCase(
        name="showcase_reuse",
        kind="golden",
        description="VALIDATE with an existing equivalent → reuse, not build.",
        results=[_tech({"evidence": ["found existing flow assign_owner that already does this"]})],
        draft_report={
            "intent": "VALIDATE",
            "verdict": "Reuse the existing 'assign_owner' flow rather than building a new one.",
            "reconciliation": "An equivalent already exists and covers this need.",
            "recommendation": "Extend the existing assign_owner flow instead of building new.",
            "existing_equivalents": [{"id": "flow:assign_owner", "kind": "Flow", "name": "assign_owner"}],
            "risk": {"score": 10, "level": "low", "reasons": []},
            "confidence": 0.8,
        },
        expected=Expected(intent="VALIDATE", verdict_class="reuse", gate_clean=True),
    ),
    EvalCase(
        name="showcase_change_collision",
        kind="golden",
        description="A recent editor overlaps the blast radius → grounded collision + raised risk.",
        results=[
            _tech({
                "impacted_components": [{"id": "flow:close_request", "kind": "Flow", "name": "close_request"}],
                "recent_editors": [{"component": {"id": "flow:close_request", "kind": "Flow", "name": "close_request"},
                                    "modified_by": "user-alice", "days_ago": 8}],
            }),
            _ctx({"active_change_signals": [{"component": {"id": "flow:close_request", "kind": "Flow", "name": "close_request"},
                                             "owner_or_team": "user-alice", "sensitivity": "open", "has_activity": True}]}),
        ],
        draft_report={
            "intent": "VALIDATE",
            "verdict": "Proceed carefully - someone recently changed a flow in scope.",
            "recommendation": "Coordinate with user-alice on close_request before proceeding.",
            "impacted_components": [{"id": "flow:close_request", "kind": "Flow", "name": "close_request"}],
            "change_collisions": [{"component": {"id": "flow:close_request", "kind": "Flow", "name": "close_request"},
                                   "who": "user-alice", "sensitivity": "open",
                                   "advice": "coordinate with user-alice before proceeding"}],
            "risk": {"score": 45, "level": "medium", "reasons": ["recent edit overlaps the radius"]},
            "confidence": 0.7,
        },
        expected=Expected(
            intent="VALIDATE", risk_bucket="medium",
            must_mention=["close_request"], gate_clean=True,
        ),
    ),
    EvalCase(
        name="showcase_clarify_dont_hedge",
        kind="golden",
        description="Unresolved anchor → a crisp clarifying question, not a hedged verdict.",
        results=[_tech({"likely_cause": "could not confidently resolve the object the user named; needs confirmation"})],
        draft_report={
            "intent": "DIAGNOSE",
            "anchor": None,
            "verdict": "Could you confirm which table you mean - the display name or a pasted URL?",
            "recommendation": "Share the exact table name or the Power Apps URL so I can pinpoint it.",
            "risk": {"score": 0, "level": "low", "reasons": []},
            "confidence": 0.3,
            "generated_artifact": None,
        },
        expected=Expected(
            intent="DIAGNOSE", verdict_class="needs_clarification",
            artifact_type=None, gate_clean=True,
        ),
    ),
]


# ── critic / write-verify (mock: feed apply_write_deny) ───────────────────────

CRITIC_CASES = [
    EvalCase(
        name="critic_denies_unsupported_write",
        kind="critic",
        description="A data-fix not supported by the diagnosis is default-denied (artifact nulled).",
        draft_report={
            "intent": "DIAGNOSE",
            "verdict": "The account email status is wrong; correct it.",
            "recommendation": "Set the account's emailsent flag to true.",
            "generated_artifact": {
                "artifact_type": "remediation_proposal", "operation": "update",
                "record_table": "account", "record_id": "acc-1",
                "changes": [{"column": "new_emailsent", "proposed_value": "true"}],
                "evidence_source": "diagnosis", "diagnosis_confidence": 0.85,
            },
            "risk": {"score": 20, "level": "low", "reasons": []},
        },
        expected=Expected(write_denied=True, artifact_type=None),
    ),
]


ALL_CASES = GATE_CASES + GOLDEN_CASES + CRITIC_CASES
MOCK_CASES = ALL_CASES  # every case here is deterministic (mock); live cases TBD
