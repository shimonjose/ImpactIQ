"""CI gate for the eval harness: every MOCK case must pass, every field.

Unlike the getsource pins, a regression in the verdict gate (a citation no
longer dropped, a freeze no longer flooring risk, an invented owner no longer
stripped) FAILS here. The live reasoning cases + LLM judge are exercised
separately (evals/run.py --live/--judge).
"""

from __future__ import annotations

import pytest

from evals.corpus import ALL_CASES
from evals.run import run_case

_MOCK = [c for c in ALL_CASES if c.kind in ("gate", "golden", "critic")]


@pytest.mark.parametrize("case", _MOCK, ids=[c.name for c in _MOCK])
def test_eval_case_passes(case):
    fields = run_case(case)
    assert fields, f"{case.name} produced no graded fields"
    failures = [f for f in fields if not f.passed]
    assert not failures, "; ".join(f"{f.field}: {f.detail}" for f in failures)


def test_corpus_covers_the_reasoning_showcase():
    """The reasoning showcase must stay covered (the product differentiator)."""
    names = {c.name for c in ALL_CASES}
    for required in (
        "showcase_change_control_dominance",
        "showcase_defect_to_expected_flip",
        "showcase_reuse",
        "showcase_change_collision",
        "showcase_clarify_dont_hedge",
    ):
        assert required in names, f"missing reasoning-showcase case: {required}"


def test_one_negative_eval_per_gate():
    """Every verdict-gate rule has a case that fails if the gate regresses."""
    gate_rules = {
        r for c in ALL_CASES for r in c.expected.gate_rules_fire
    }
    for rule in ("citation_grounding", "owner_provenance", "change_control_dominance", "defect_expected_flip"):
        assert rule in gate_rules, f"no negative eval guards gate rule: {rule}"
