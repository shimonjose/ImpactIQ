"""Agent wiring for the sandbox FIX tools: attachment + permission wall.

No live calls: the gate is monkeypatched; what's pinned is the contract —
tools absent without a sandbox, both present with one, and every impl
refusing (as a relayed error, never an exception) when the role gate denies.
"""

import json
from types import SimpleNamespace

import pytest

from impactiq.builder import BuilderRefusal
from impactiq.server import _builder_tool_specs


def _settings(**kw):
    base = {
        "build_dataverse_url": "https://sandbox123.crm6.dynamics.com",
        "dataverse_url": "https://example.crm.dynamics.com",
        "impactiq_build_solution": "ImpactIQSandbox",
        "impactiq_builder_role": "ImpactIQ Builder",
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_no_sandbox_means_no_builder_tools():
    assert _builder_tool_specs(_settings(build_dataverse_url=None)) == []


def test_sandbox_attaches_inspect_and_fix():
    specs = _builder_tool_specs(_settings())
    assert [s.name for s in specs] == ["sandbox_inspect", "sandbox_fix"]
    # The fix tool's contract documents fix-only and the role gate.
    assert "FIX-ONLY" in specs[1].description
    assert "ImpactIQ Builder" in specs[1].description


def test_impls_relay_role_refusal_as_error_json(monkeypatch):
    import impactiq.builder.gate as gate

    def _deny(settings, user_assertion=None):
        raise BuilderRefusal("you don't hold the 'ImpactIQ Builder' security role")

    monkeypatch.setattr(gate, "assert_builder_permission", _deny)
    specs = {s.name: s for s in _builder_tool_specs(_settings())}
    for name, args in (
        ("sandbox_inspect", {"kind": "flow", "name": "Broken Flow"}),
        ("sandbox_fix", {"ops": [{"op": "set_flow_state", "flow": "x", "state": "off"}]}),
    ):
        out = json.loads(specs[name].impl(args))
        assert "ImpactIQ Builder" in out["error"], f"{name} must refuse via error JSON"


def test_inspect_validates_kind_before_any_network(monkeypatch):
    import impactiq.builder.gate as gate

    monkeypatch.setattr(gate, "assert_builder_permission", lambda s, ua=None: None)
    specs = {s.name: s for s in _builder_tool_specs(_settings())}
    out = json.loads(specs["sandbox_inspect"].impl({"kind": "app", "name": "x"}))
    assert "kind must be" in out["error"]


def test_fix_is_a_proposal_not_an_apply(monkeypatch):
    """`sandbox_fix` must stash the ops behind an Apply tap — never execute
    (when confirmed, build)."""
    import impactiq.builder.gate as gate
    import impactiq.server as server

    monkeypatch.setattr(gate, "assert_builder_permission", lambda s, ua=None: None)
    holder: dict = {}
    specs = {s.name: s for s in _builder_tool_specs(_settings(), holder)}
    ops = [{"op": "set_flow_state", "flow": "Broken Flow", "state": "off"}]
    out = json.loads(
        specs["sandbox_fix"].impl(
            {"ops": ops, "title": "Disable broken flow", "rationale": "Runs are failing; SOP-7 covers complaint intake."}
        )
    )
    assert out["proposed"] is True and "NOT applied" in out["note"]
    fix_id = out["fix_id"]
    assert server._PENDING_FIXES[fix_id]["ops"] == ops
    assert holder["sandbox_fix"]["fix_id"] == fix_id
    server._PENDING_FIXES.pop(fix_id, None)


def test_fix_requires_grounded_rationale(monkeypatch):
    import impactiq.builder.gate as gate

    monkeypatch.setattr(gate, "assert_builder_permission", lambda s, ua=None: None)
    specs = {s.name: s for s in _builder_tool_specs(_settings())}
    out = json.loads(
        specs["sandbox_fix"].impl({"ops": [{"op": "set_flow_state", "flow": "f", "state": "off"}]})
    )
    assert "rationale is required" in out["error"]


def test_apply_endpoint_requires_tap_and_known_id():
    from fastapi.testclient import TestClient

    from impactiq.server import app

    client = TestClient(app)
    r = client.post("/action/sandbox_fix", json={"fix_id": "fix-x", "confirmed": False})
    assert r.status_code == 403
    r = client.post("/action/sandbox_fix", json={"fix_id": "fix-x", "confirmed": True})
    assert r.status_code == 404


def test_resubmit_endpoint_requires_tap_and_known_id():
    from fastapi.testclient import TestClient

    from impactiq.server import app

    client = TestClient(app)
    r = client.post("/action/resubmit_run", json={"resubmit_id": "rerun-x", "confirmed": False})
    assert r.status_code == 403
    r = client.post("/action/resubmit_run", json={"resubmit_id": "rerun-x", "confirmed": True})
    assert r.status_code == 404


def test_resubmit_card_carries_id_and_no_auto_run():
    from impactiq.report.card import resubmit_card

    card = resubmit_card("rerun-abc", "Broken Flow", "0858…CU26", "2026-06-12T08:38:46Z")
    runs = [a for a in card["actions"] if a["data"].get("action") == "apply_resubmit_run"]
    assert len(runs) == 1 and runs[0]["data"]["resubmit_id"] == "rerun-abc"
    # Minimal card: no ops detail, just the one-liner + decision buttons.
    assert len(card["body"]) == 1


def test_resubmit_tool_proposes_never_executes(monkeypatch):
    """The tool stashes + returns proposed; nothing calls the flow API."""
    import impactiq.server as srv

    class _DV:
        def __init__(self, settings):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

        def get(self, path, params=None):
            if path == "workflows":
                return {"value": [{"workflowid": "wf-1", "name": "Broken Flow"}]}
            if path == "flowruns":
                return {"value": [
                    {"name": "RUN1", "status": "Failed",
                     "starttime": "2026-06-12T08:38:46Z", "resourceid": "res-1"}
                ]}
            if path.startswith("RetrieveCurrentOrganization"):
                return {"Detail": {"EnvironmentId": "env-1"}}
            raise AssertionError(f"unexpected read {path}")

    import impactiq.dataverse_client as dvmod

    monkeypatch.setattr(dvmod, "DataverseClient", _DV)
    holder: dict = {}
    specs = {s.name: s for s in srv._resubmit_tool_specs(_settings(), holder)}
    out = json.loads(specs["resubmit_flow_run"].impl({"flow": "Broken"}))
    assert out["proposed"] is True and out["run"] == "RUN1"
    assert holder["resubmit_runs"][0]["env_id"] == "env-1"
    # The stashed proposal is what /action/resubmit_run will execute.
    assert srv._PENDING_RESUBMITS[out["resubmit_id"]]["flow_resource"] == "res-1"


def test_sandbox_fix_card_carries_fix_id_and_no_auto_apply():
    from impactiq.report.card import sandbox_fix_card

    card = sandbox_fix_card(
        "fix-abc", "Disable broken flow", "Why + what changes.", [
            {"op": "set_flow_state", "flow": "Broken Flow", "state": "off"}
        ],
    )
    apply_actions = [a for a in card["actions"] if a["data"].get("action") == "apply_sandbox_fix"]
    assert len(apply_actions) == 1 and apply_actions[0]["data"]["fix_id"] == "fix-abc"
    assert any(a["data"].get("action") == "discard" for a in card["actions"])
    text = json.dumps(card)
    assert "nothing changes until you tap Apply" in text
