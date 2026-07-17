"""Per-conversation memory: reuse a prior deep analysis instead of re-running.

A follow-up on the SAME subject in a conversation ("propose the sandbox fix",
"notify the owner") must REUSE the verdict already computed, not re-run the
~minutes-long pipeline. A genuine PIVOT re-runs. These pin the container
(remember/recall + TTL/cap), the pivot reasoning's deterministic fast-paths +
classifier branch, and the deep tool's reuse-vs-run behavior.
"""

from __future__ import annotations

import json
import time

import pytest

import impactiq.server as srv
from impactiq.report.schema import ImpactReport


def _report(verdict="Low risk.", intent="VALIDATE", anchor_name="close_request"):
    return ImpactReport.model_validate(
        {
            "intent": intent,
            "anchor": {"id": "f1", "kind": "Flow", "name": anchor_name},
            "verdict": verdict,
            "confidence": 0.9,
            "risk": {"score": 10, "level": "low", "reasons": []},
            "recommendation": "Proceed.",
        }
    )


@pytest.fixture(autouse=True)
def _clear_memory():
    srv._CONV_MEMORY.clear()
    yield
    srv._CONV_MEMORY.clear()


# ── the container: remember / recall ─────────────────────────────────────────


def test_remember_and_recall_roundtrip():
    srv._remember_analysis("conv1", question="rename X", report=_report(anchor_name="X flow"))
    prior = srv._recall_analysis("conv1")
    assert prior is not None
    assert prior["anchor"] == "X flow"
    assert prior["intent"] == "VALIDATE"
    assert prior["report"].verdict == "Low risk."


def test_recall_empty_is_none():
    assert srv._recall_analysis("nope") is None
    assert srv._recall_analysis("") is None


def test_recall_expires_after_ttl(monkeypatch):
    srv._remember_analysis("conv2", question="q", report=_report())
    # fast-forward past the TTL (capture real time first - srv.time IS the time
    # module, so the lambda must not call the patched time.time again).
    future = time.time() + srv._CONV_MEMORY_TTL_S + 10
    monkeypatch.setattr(srv.time, "time", lambda: future)
    assert srv._recall_analysis("conv2") is None


def test_memory_evicts_oldest_past_cap():
    for i in range(srv._CONV_MEMORY_MAX + 5):
        srv._remember_analysis(f"c{i}", question="q", report=_report())
    assert len(srv._CONV_MEMORY) <= srv._CONV_MEMORY_MAX
    assert "c0" not in srv._CONV_MEMORY            # oldest evicted
    assert f"c{srv._CONV_MEMORY_MAX + 4}" in srv._CONV_MEMORY  # newest kept


# ── pivot reasoning: same subject vs genuine pivot ───────────────────────────


def test_same_subject_trivial_confirmations_no_hop():
    prior = {"anchor": "close_request", "question": "rename it"}
    for req in ("apply the fix", "go ahead", "do it", "yes", "Proceed."):
        assert srv._same_subject(srv.get_settings(), prior, req) is True


def test_same_subject_request_names_the_anchor_no_hop():
    prior = {"anchor": "close_request", "question": "is it safe to change it"}
    assert srv._same_subject(
        srv.get_settings(), prior, "propose a sandboxed update to close_request"
    ) is True


def test_same_subject_classifier_branch(monkeypatch):
    """When no fast-path matches, the one-word classifier decides; doubt → NEW."""
    import impactiq.agents.loop as loop_mod

    class _Turn:
        def __init__(self, txt):
            self.raw_text = txt

    prior = {"anchor": "close_request", "question": "rename the status column"}

    monkeypatch.setattr(loop_mod, "run_agent_turn", lambda *a, **k: _Turn("SAME"))
    assert srv._same_subject(srv.get_settings(), prior, "now also email the owner") is True

    monkeypatch.setattr(loop_mod, "run_agent_turn", lambda *a, **k: _Turn("NEW"))
    assert srv._same_subject(srv.get_settings(), prior, "what about the Account table?") is False

    # classifier error → treat as a pivot (re-run), never a stale reuse
    def _boom(*a, **k):
        raise RuntimeError("model down")

    monkeypatch.setattr(loop_mod, "run_agent_turn", _boom)
    assert srv._same_subject(srv.get_settings(), prior, "something ambiguous here") is False


# ── the deep tool reuses the container instead of re-running ─────────────────


def _force_estate_unavailable(monkeypatch):
    import impactiq.dataverse_client as dvc

    monkeypatch.setattr(
        dvc.DataverseClient, "__init__",
        lambda self, s: (_ for _ in ()).throw(RuntimeError("no estate in test")),
    )


def test_deep_tool_reuses_prior_without_rerunning_pipeline(monkeypatch):
    _force_estate_unavailable(monkeypatch)
    import impactiq.agents.multi_agent as ma

    def _must_not_run(*a, **k):
        raise AssertionError("pipeline re-ran despite a reusable prior")

    monkeypatch.setattr(ma, "ask_multi", _must_not_run)

    prior = _report(verdict="Reused verdict.")
    _tools, dispatch, _dv, holder = srv._unified_tools(
        srv.get_settings(), "Enterprise CRM", conversation="cX", reuse_prior=prior
    )
    out = json.loads(dispatch["deep_impact_analysis"]({"question": "propose the sandbox fix"}))
    assert out["reused"] is True
    assert out["verdict"] == "Reused verdict."
    assert holder["report"] is prior  # cards still attach off the reused report


def test_deep_tool_runs_and_remembers_when_no_prior(monkeypatch):
    _force_estate_unavailable(monkeypatch)
    import impactiq.agents.multi_agent as ma

    class _AskResult:
        run_status = "completed"
        report = {
            "intent": "VALIDATE",
            "anchor": {"id": "f1", "kind": "Flow", "name": "close_request"},
            "verdict": "Freshly analysed.",
            "confidence": 0.8,
            "risk": {"score": 12, "level": "low", "reasons": []},
            "recommendation": "Go.",
        }

    monkeypatch.setattr(ma, "ask_multi", lambda *a, **k: _AskResult())

    _tools, dispatch, _dv, _holder = srv._unified_tools(
        srv.get_settings(), "Enterprise CRM", conversation="cFresh", reuse_prior=None
    )
    out = json.loads(dispatch["deep_impact_analysis"]({"question": "is it safe to add a column?"}))
    assert out["reused"] is False
    assert out["verdict"] == "Freshly analysed."
    # the container is now filled for the next same-subject turn
    prior = srv._recall_analysis("cFresh")
    assert prior is not None and prior["report"].verdict == "Freshly analysed."
