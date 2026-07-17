"""The conditional critic's deterministic pieces (offline, no model calls).

The live skeptic behaviour is covered by a separate smoke script. These pin the
parts that decide WHEN it runs and WHAT the default-deny does - the safety
guarantees - without an LLM: flag default off, trigger logic (median turn skips),
write-artifact / collision detection, and the write-deny mutation.
"""

from __future__ import annotations

from impactiq.agents.critic import (
    apply_write_deny,
    carries_write_artifact,
    critic_enabled,
    has_change_collision,
    should_critique,
)


def test_flag_off_by_default(monkeypatch):
    monkeypatch.delenv("IMPACTIQ_CRITIC", raising=False)
    assert critic_enabled() is False


def test_flag_on_values(monkeypatch):
    for v in ("1", "on", "true", "YES", "enforce"):
        monkeypatch.setenv("IMPACTIQ_CRITIC", v)
        assert critic_enabled() is True
    for v in ("0", "off", ""):
        monkeypatch.setenv("IMPACTIQ_CRITIC", v)
        assert critic_enabled() is False


# ── trigger logic: median (safe, confident, no artifact) turn skips ──────────


def test_no_trigger_on_plain_confident_turn():
    report = {"confidence": 0.9, "risk": {"level": "low"}, "verdict": "Safe to proceed."}
    assert should_critique(report, gate_findings=[]) is None


def test_trigger_on_write_artifact():
    report = {
        "confidence": 0.95,
        "generated_artifact": {"artifact_type": "remediation_proposal"},
    }
    assert should_critique(report, gate_findings=[]) == "write_artifact_present"


def test_trigger_on_change_collision():
    report = {"confidence": 0.95, "change_collisions": [{"who": "X"}]}
    assert should_critique(report, gate_findings=[]) == "change_collision_present"


def test_trigger_on_gate_flag():
    report = {"confidence": 0.95}
    assert should_critique(report, gate_findings=["something"]) == "verdict_gate_flagged"


def test_trigger_on_borderline_confidence():
    report = {"confidence": 0.5}
    reason = should_critique(report, gate_findings=[], conf_floor=0.7)
    assert reason and reason.startswith("borderline_confidence")


def test_high_confidence_above_floor_does_not_trigger():
    report = {"confidence": 0.85}
    assert should_critique(report, gate_findings=[], conf_floor=0.7) is None


# ── detectors ────────────────────────────────────────────────────────────────


def test_carries_write_artifact_only_for_data_writes():
    assert carries_write_artifact(
        {"generated_artifact": {"artifact_type": "remediation_proposal"}}
    ) == "remediation_proposal"
    assert carries_write_artifact(
        {"generated_artifact": {"artifact_type": "backfill_blueprint"}}
    ) == "backfill_blueprint"
    # a draft message is NOT a tenant data write
    assert carries_write_artifact(
        {"generated_artifact": {"artifact_type": "manager_handoff"}}
    ) is None
    assert carries_write_artifact({"generated_artifact": None}) is None
    assert carries_write_artifact({}) is None


def test_has_change_collision():
    assert has_change_collision({"change_collisions": [{"who": "X"}]}) is True
    assert has_change_collision({"change_collisions": []}) is False
    assert has_change_collision({}) is False


# ── default-deny: the safety action ──────────────────────────────────────────


def test_apply_write_deny_nulls_artifact_keeps_narrative():
    report = {
        "verdict": "Fix the record.",
        "recommendation": "Apply the proposed fix.",
        "generated_artifact": {"artifact_type": "remediation_proposal", "record_id": "r1"},
        "evidence": [{"kind": "tool", "detail": "walk done"}],
    }
    out = apply_write_deny(report, "the proposed value isn't supported by the diagnosis")

    assert out["generated_artifact"] is None                 # mutation withheld
    assert "withheld" in out["recommendation"].lower()       # caveat added
    assert "diagnosis" in out["recommendation"].lower()      # reason carried
    assert out["verdict"] == "Fix the record."               # narrative intact
    assert any("withheld" in e["detail"].lower() for e in out["evidence"])
    # input not mutated (returns a copy)
    assert report["generated_artifact"] is not None


def test_apply_write_deny_handles_empty_recommendation():
    report = {"generated_artifact": {"artifact_type": "remediation_proposal"}}
    out = apply_write_deny(report, "")
    assert out["generated_artifact"] is None
    assert out["recommendation"]  # a caveat exists even with no reason / prior rec


def test_expensive_repair_is_gated_behind_a_write_artifact():
    """Latency guard: the full adjudicator repair turn (which once pushed a turn
    long enough to trip the surface timeout) only runs when a write artifact is
    at stake; collision/borderline/gate-only triggers keep the cheap skeptic +
    write-deny and skip the re-adjudication."""
    import inspect

    import impactiq.agents.multi_agent as ma

    src = inspect.getsource(ma.ask_multi)
    assert "if defects and carries_write_artifact(report_dict):" in src
    # the skeptic + write-deny still run unconditionally on a triggered turn
    assert "run_skeptic(" in src
    assert "apply_write_deny(" in src
