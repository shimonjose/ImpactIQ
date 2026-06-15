"""Eval runner + scorecard.

Default (no flags): run the MOCK corpus — deterministic, no tenant, no LLM — and
print a per-case + aggregate scorecard. Exit non-zero if any field fails (so it
gates merges). This is what tests/test_evals.py drives in CI.

  python evals/run.py                # mock scorecard (CI)
  python evals/run.py --judge        # + live LLM judge on each report (costs calls)
  python evals/run.py --live         # + run live reasoning cases (needs a tenant)

Mock-mode mechanics: a ``gate``/``golden`` case feeds its draft report through
the REAL verdict gate (enforce) and grades the result; a ``critic`` case feeds
the deterministic ``apply_write_deny``.
"""

from __future__ import annotations

import argparse
import os
import sys

# Make both the repo root (for `import evals`) and src (for `import impactiq`)
# importable regardless of the cwd the runner was launched from.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, _ROOT)

from evals.corpus import ALL_CASES  # noqa: E402
from evals.graders import FieldResult, grade_gate, grade_hard, llm_judge  # noqa: E402


def run_case(case) -> list[FieldResult]:
    """Run one MOCK case and return its graded fields."""
    from impactiq.report.verdict_gate import gate_report

    out: list[FieldResult] = []
    if case.kind in ("gate", "golden"):
        after, findings = gate_report(
            {}, case.results, dict(case.draft_report),
            runtime_citations=case.runtime_citations,
            solution_name=case.solution_name, mode="enforce",
        )
        if case.expected.gate_clean:
            out.append(FieldResult(
                "gate_clean", not findings,
                "clean" if not findings else f"unexpected: {[f.rule for f in findings]}",
            ))
        out += grade_gate(findings, case.draft_report, after, case.expected)
        out += grade_hard(after, case.expected)
    elif case.kind == "critic":
        from impactiq.agents.critic import apply_write_deny

        after = apply_write_deny(
            dict(case.draft_report),
            "verifier: the proposed value isn't supported by the diagnosis",
        )
        out += grade_gate([], case.draft_report, after, case.expected)
        out += grade_hard(after, case.expected)
    return out


def run_mock() -> dict[str, list[FieldResult]]:
    """Run every mock case. Returns {case_name: [FieldResult, ...]}."""
    return {c.name: run_case(c) for c in ALL_CASES if c.kind in ("gate", "golden", "critic")}


def _print_scorecard(graded: dict[str, list[FieldResult]]) -> bool:
    total = passed = 0
    all_ok = True
    for name, fields in graded.items():
        cpass = sum(1 for f in fields if f.passed)
        ok = all(f.passed for f in fields)
        all_ok = all_ok and ok
        print(f"\n[{'PASS' if ok else 'FAIL'}] {name}  ({cpass}/{len(fields)})", flush=True)
        for f in fields:
            mark = "ok " if f.passed else "XX "
            print(f"    {mark}{f.field}: {f.detail}", flush=True)
        total += len(fields)
        passed += cpass
    print(f"\n== scorecard: {passed}/{total} fields passed across "
          f"{len(graded)} cases; {'ALL PASS' if all_ok else 'FAILURES'} ==", flush=True)
    return all_ok


def _run_judge() -> None:
    """Live: run the fixed-rubric LLM judge over each case's report."""
    from impactiq.agents.runtime import make_project_client
    from impactiq.settings import Settings

    settings = Settings()
    with make_project_client(settings, as_user=False) as pc:
        for c in ALL_CASES:
            scores = llm_judge(c.draft_report, pc, settings)
            print(f"  judge[{c.name}]: {scores}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", action="store_true", help="run the live LLM judge")
    ap.add_argument("--live", action="store_true", help="run live reasoning cases")
    args = ap.parse_args()

    graded = run_mock()
    all_ok = _print_scorecard(graded)

    if args.judge:
        print("\n-- LLM judge (live) --", flush=True)
        _run_judge()
    if args.live:
        live = [c for c in ALL_CASES if c.kind == "reasoning"]
        print(f"\n-- live reasoning cases: {len(live)} (none defined yet) --", flush=True)

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
