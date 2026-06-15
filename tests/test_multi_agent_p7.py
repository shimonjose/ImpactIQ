"""Finding contracts, multi-agent workflow wiring, parallel fan-out proof.

The workflow tests inject sync stubs through ``build_workflow`` so the
graph semantics (fan-out to 3, fan-in list, output) and the thread-level
parallelism are pinned without any Foundry round-trip.
"""

from __future__ import annotations

import asyncio
import time
import warnings

import pytest

warnings.filterwarnings("ignore")

from impactiq.agents.contracts import (
    ActiveWork,
    ContextFinding,
    KnowledgeFinding,
    OrchestratorPlan,
    SpecialistResult,
    TechnicalFinding,
)
from impactiq.agents.multi_agent import _salvage_plan, build_workflow


# ── contracts: lenient by design ─────────────────────────────────────────────


def test_technical_finding_minimal():
    f = TechnicalFinding.model_validate({"likely_cause": "flow failed"})
    assert f.confidence == 0.0
    assert f.impacted_components == []


def test_technical_finding_coerces_string_noderefs():
    f = TechnicalFinding.model_validate({"blast_radius": ["Customer Request"]})
    assert f.blast_radius[0].name == "Customer Request"


def test_knowledge_finding_defaults_to_no_policy():
    f = KnowledgeFinding.model_validate({})
    assert f.governance_verdict == "no_applicable_policy"


def test_active_work_cannot_carry_substance():
    w = ActiveWork.model_validate(
        {
            "owner_or_team": "Team A",
            "has_activity": True,
            "details": "secret project to retire the table",
            "substance": "confidential",
        }
    )
    dumped = w.model_dump()
    assert "details" not in dumped and "substance" not in dumped


def test_context_finding_minimal():
    f = ContextFinding.model_validate({"likely_owner": "Sam"})
    assert f.active_change_signals == []


def test_orchestrator_plan_defaults_dispatch_all():
    p = OrchestratorPlan.model_validate({})
    assert p.specialists == ["technical", "knowledge", "context"]
    assert p.intent == "DIAGNOSE"


# ── orchestrator-plan salvage: a parse hiccup must never flip intent / drop
#    the anchor (the silent `except: OrchestratorPlan()` landmine) ──────────────


def test_salvage_preserves_intent_when_only_specialists_are_bad():
    """A lowercase intent + a malformed specialists list used to fail strict
    validation outright → all-defaults → intent silently flipped to DIAGNOSE.
    Salvage keeps the (case-insensitive) VALIDATE."""
    p = _salvage_plan({"intent": "validate", "specialists": ["Technical", "BOGUS"]})
    assert p.intent == "VALIDATE"
    # one specialist normalised to lowercase survived; the junk was dropped
    assert p.specialists == ["technical"]


def test_salvage_keeps_a_resolved_anchor_missing_kind_and_name():
    """An anchor missing kind/name would fail NodeRef validation and the WHOLE
    plan (incl. intent) would be discarded. Salvage coerces and keeps it."""
    p = _salvage_plan({"intent": "VALIDATE", "anchor": {"id": "new_field"}})
    assert p.anchor is not None
    assert p.anchor.id == "new_field"
    assert p.anchor.name == "new_field"      # filled from id
    assert p.anchor.kind == "Reference"      # filled default
    assert p.intent == "VALIDATE"            # not flipped


def test_salvage_combined_landmine_keeps_intent_and_anchor():
    """The full landmine: lowercase intent + bare-string anchor + bad
    specialists. Previously → DIAGNOSE, anchor=None, all-three. Now everything
    salvageable is preserved."""
    p = _salvage_plan(
        {"intent": "validate", "anchor": "Account.statuscode", "specialists": "nonsense"}
    )
    assert p.intent == "VALIDATE"
    assert p.anchor is not None and p.anchor.name == "Account.statuscode"
    # unreadable specialists → safe default (dispatch all), never empty
    assert p.specialists == ["technical", "knowledge", "context"]


def test_salvage_unreadable_intent_falls_back_to_diagnose_default():
    p = _salvage_plan({"intent": "maybe-both", "specialists": ["context"]})
    assert p.intent == "DIAGNOSE"            # genuinely couldn't read one
    assert p.specialists == ["context"]


def test_salvage_handles_non_dict():
    assert _salvage_plan("not a dict").intent == "DIAGNOSE"
    assert _salvage_plan(None).specialists == ["technical", "knowledge", "context"]


# ── workflow wiring ──────────────────────────────────────────────────────────


def _stub_result(agent: str, sleep: float = 0.0) -> dict:
    if sleep:
        time.sleep(sleep)
    return SpecialistResult(agent=agent, status="ok", finding={"x": agent}).model_dump()


def test_workflow_fans_out_and_in():
    received: dict = {}

    def adjudicate(results: list[dict]) -> dict:
        received["results"] = results
        return {"raw_text": "done"}

    wf = build_workflow(
        lambda plan: _stub_result("technical"),
        lambda plan: _stub_result("knowledge"),
        lambda plan: _stub_result("context"),
        adjudicate,
    )
    result = asyncio.run(wf.run({"intent": "DIAGNOSE"}))
    outputs = result.get_outputs()
    assert outputs == [{"raw_text": "done"}]
    agents = sorted(r["agent"] for r in received["results"])
    assert agents == ["context", "knowledge", "technical"]


def test_workflow_runs_specialists_in_parallel():
    def adjudicate(results: list[dict]) -> dict:
        return {"n": len(results)}

    wf = build_workflow(
        lambda plan: _stub_result("technical", sleep=0.4),
        lambda plan: _stub_result("knowledge", sleep=0.4),
        lambda plan: _stub_result("context", sleep=0.4),
        adjudicate,
    )
    t0 = time.perf_counter()
    result = asyncio.run(wf.run({}))
    elapsed = time.perf_counter() - t0
    assert result.get_outputs() == [{"n": 3}]
    # Serial would be >= 1.2s; parallel threads should land well under that.
    assert elapsed < 1.0, f"specialists did not run in parallel ({elapsed:.2f}s)"


def test_workflow_propagates_skipped_specialists():
    def adjudicate(results: list[dict]) -> dict:
        return {"statuses": sorted(f"{r['agent']}={r['status']}" for r in results)}

    skipped = SpecialistResult(
        agent="context", status="skipped", error="Work IQ unavailable"
    ).model_dump()
    wf = build_workflow(
        lambda plan: _stub_result("technical"),
        lambda plan: _stub_result("knowledge"),
        lambda plan: skipped,
        adjudicate,
    )
    result = asyncio.run(wf.run({}))
    assert result.get_outputs()[0]["statuses"] == [
        "context=skipped",
        "knowledge=ok",
        "technical=ok",
    ]
