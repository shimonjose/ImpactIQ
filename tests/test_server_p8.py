"""Bridge confirm gates + audit chain.

These pin the safety contract of the only two action endpoints:
* /action/send_handoff refuses without an explicit confirmation,
* /action/remediate re-runs the offer gate server-side (never trusts the card
  payload), enforces tap-vs-typed friction, and audit-logs.
No Foundry or Dataverse round-trips: the write path is cut off before the
HTTP call by gate failures, and the one allowed case is intercepted.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

import impactiq.audit as audit_mod
from impactiq.server import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Redirect the audit chain to a temp file per test.
    monkeypatch.setattr(audit_mod, "AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    return TestClient(app)


def _run_agent(client: TestClient, path: str, body: dict, tries: int = 120) -> dict:
    """/agent and /agent/approve are async (they launch a JOB and return a
    job_id; the surface polls /agent/result). Launch + poll to the result dict
    so these tests assert on the completed turn (and any worker side-effects like
    audit/stash are settled)."""
    launch = client.post(path, json=body)
    assert launch.status_code == 200, launch.text
    j = launch.json()
    if "job_id" not in j:
        return j  # back-compat: a synchronous bridge returned the result
    for _ in range(tries):
        rr = client.post("/agent/result", json={"job_id": j["job_id"]}).json()
        if rr.get("job_status") != "running":
            assert rr["job_status"] == "done", rr
            return rr["result"]
        time.sleep(0.03)
    raise AssertionError(f"job for {path} never completed")


def _audit_events(tmp_path) -> list[dict]:
    p = tmp_path / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line]


def _handoff_artifact() -> dict:
    return {
        "artifact_type": "manager_handoff",
        "recipient": "Sam (Team A manager)",
        "draft_text": "User B proposes a change that may affect your team's data on Customer Request.",
        "baton": {"baton_id": "baton-test123", "intent": "VALIDATE"},
        "status": "draft",
    }


def _remediation_artifact(**over) -> dict:
    base = {
        "artifact_type": "remediation_proposal",
        "record_table": "new_customerrequest",
        "record_id": "11111111-2222-3333-4444-555555555555",
        "changes": [
            {"column": "statuscode", "current_value": "Closed", "proposed_value": "Reopened"}
        ],
        "evidence_source": "diagnosis",
        "diagnosis_summary": "flow failed before stamping",
        "diagnosis_confidence": 0.9,
    }
    base.update(over)
    return base


def test_health(client):
    assert client.get("/health").json() == {"ok": True}


# ── Work IQ Mail draft tool: draft-only safety invariant ─────────────────────


def test_mail_tool_allowlist_excludes_send():
    """The Work IQ Mail allow-lists must NEVER include a send/forward/delete
    verb - draft-only is enforced at the tool layer, not by prompt. These are
    the live tool names."""
    from impactiq.agents.single_agent import (
        WORKIQ_MAIL_DRAFT_TOOLS,
        WORKIQ_MAIL_SEND_TOOLS,
    )
    from impactiq.agents.workiq import REGISTRY

    mail = REGISTRY["mail"]
    assert not (set(mail.allowed_tools) & WORKIQ_MAIL_SEND_TOOLS)
    for t in mail.allowed_tools:
        low = t.lower()
        assert "send" not in low and "forward" not in low and "delete" not in low
    # The reads must be a declared subset so read_only=True builds stay safe.
    assert set(mail.read_only_tools) <= set(mail.allowed_tools)
    assert "SearchMessages" in mail.read_only_tools
    # The headless drafter gets the draft pair only.
    assert WORKIQ_MAIL_DRAFT_TOOLS == ["CreateDraftMessage", "UpdateDraft"]
    assert not (set(WORKIQ_MAIL_DRAFT_TOOLS) & WORKIQ_MAIL_SEND_TOOLS)
    assert set(WORKIQ_MAIL_DRAFT_TOOLS) <= set(mail.allowed_tools)
    # Only INERT mutations may bypass the approval gate: drafts cannot reach
    # another person. Anything with a send path must stay gated.
    assert set(mail.auto_approve_tools) == {"CreateDraftMessage", "UpdateDraft"}
    assert set(mail.auto_approve_tools) <= set(mail.allowed_tools)
    for srv_key in ("mail", "teams", "calendar"):
        from impactiq.agents.workiq import REGISTRY as _r

        for t in _r[srv_key].auto_approve_tools:
            low = t.lower()
            assert "send" not in low and "reply" not in low and "forward" not in low


def test_workiq_registry_allowlists_are_all_safe():
    """No server's allow-list may contain a forbidden (config/destructive/
    send/membership) tool - the second wall behind the confirm gate."""
    from impactiq.agents.workiq import REGISTRY, allowlist_is_safe

    for key, server in REGISTRY.items():
        assert allowlist_is_safe(server), f"{key} allow-list contains a forbidden tool"


def test_dataverse_registry_excludes_schema_and_delete():
    """Records-only carve-out: the Dataverse server must never allow table
    schema ops or record deletion (data-writes-only)."""
    from impactiq.agents.workiq import REGISTRY

    allowed = set(REGISTRY["dataverse"].allowed_tools)
    assert "update_record" in allowed and "create_record" in allowed
    for forbidden in ("create_table", "update_table", "delete_table", "delete_record"):
        assert forbidden not in allowed


def test_user_server_is_read_only():
    from impactiq.agents.workiq import REGISTRY

    assert REGISTRY["user"].mutating is False


def test_dataverse_uses_direct_endpoint_and_live_tool_names():
    """The Dataverse MCP allow-list authorizes by CALLING APP ID, so the server
    must be reached DIRECTLY ({org}/api/mcp, presenting our allow-listed app) -
    never via the Agent365 gateway (which presents its own app and 403s). Tool
    names are the live tools/list set."""
    import dataclasses

    import impactiq.server as server_mod
    from impactiq.agents.workiq import REGISTRY, server_url

    settings = dataclasses.replace(
        server_mod.get_settings(), dataverse_url="https://example.crm.dynamics.com"
    )
    url = server_url(REGISTRY["dataverse"], settings)
    assert url == "https://example.crm.dynamics.com/api/mcp"
    assert "agent365" not in url
    # Live-confirmed names; the old guesses (fetch/describe_table/list_tables)
    # do not exist on the real server.
    assert set(REGISTRY["dataverse"].allowed_tools) == {
        "create_record", "update_record", "read_query", "search", "describe",
    }
    assert set(REGISTRY["dataverse"].read_only_tools) == {
        "read_query", "search", "describe",
    }
    # Skills/file/schema/delete surfaces stay forbidden.
    from impactiq.agents.workiq import GLOBAL_FORBIDDEN_PATTERNS

    assert "skill" in GLOBAL_FORBIDDEN_PATTERNS
    assert "file_upload" in GLOBAL_FORBIDDEN_PATTERNS


def test_read_only_subsets_exclude_mutations():
    """The read_only_tools for mutating servers must contain no create/send/
    update tool - the assist path (no confirm gate) only gets these."""
    from impactiq.agents.workiq import REGISTRY

    banned = ("create", "send", "update", "delete", "cancel")
    for key in ("calendar", "teams"):
        ro = REGISTRY[key].read_only_tools
        assert ro, f"{key} must declare a read-only subset"
        for t in ro:
            low = t.lower()
            assert not any(b in low for b in banned), f"{key}: {t} is not read-only"


def test_calendar_teams_allowlists_safe_and_have_actions():
    from impactiq.agents.workiq import REGISTRY, allowlist_is_safe

    cal, teams = REGISTRY["calendar"], REGISTRY["teams"]
    assert allowlist_is_safe(cal) and allowlist_is_safe(teams)
    assert "CreateEvent" in cal.allowed_tools  # booking available (confirm-gated)
    assert "SendMessageToUser" in teams.allowed_tools  # notify available
    # destructive ops excluded
    assert "DeleteEventById" not in cal.allowed_tools
    assert "CancelEvent" not in cal.allowed_tools
    assert "DeleteChat" not in teams.allowed_tools


def test_create_draft_requires_confirmation(client):
    r = client.post(
        "/action/create_draft",
        json={"artifact": {"recipient": "X", "draft_text": "hi"}, "confirmed": False},
    )
    assert r.status_code == 403


def test_create_draft_503_when_mail_not_configured(client, monkeypatch):
    import impactiq.server as server_mod

    # Force the mail tool builder to report "not configured".
    monkeypatch.setattr(
        server_mod, "get_settings", server_mod.get_settings
    )  # no-op, keep real settings
    from impactiq.agents import single_agent

    monkeypatch.setattr(single_agent, "_build_workiq_mail_tool", lambda s: None)
    r = client.post(
        "/action/create_draft",
        json={"artifact": {"recipient": "X", "draft_text": "hi"}, "confirmed": True},
    )
    assert r.status_code == 503
    assert "Work IQ Mail" in r.json()["detail"]


# ── /plan reasoning ──────────────────────────────────────────────────────────


def _stub_turn(monkeypatch, raw_text: str):
    import contextlib

    import impactiq.agents.loop as loop_mod
    import impactiq.agents.runtime as runtime_mod
    from impactiq.agents.loop import TurnResult

    @contextlib.contextmanager
    def fake_client(settings, **kw):
        yield object()

    monkeypatch.setattr(runtime_mod, "make_project_client", fake_client)
    monkeypatch.setattr(
        loop_mod,
        "run_agent_turn",
        lambda *a, **k: TurnResult(raw_text=raw_text, tool_call_count=0),
    )


# ── full-capability tool builder: reads free, mutations gated ────────────────


def _settings_with_workiq(monkeypatch):
    """Real settings with the calendar/teams/user connections forced on, so the
    builder produces a tool regardless of the ambient .env."""
    import dataclasses

    import impactiq.server as server_mod

    return dataclasses.replace(
        server_mod.get_settings(),
        foundry_workiq_user_connection_id="/x/conn/WorkIQUser",
        foundry_workiq_calendar_connection_id="/x/conn/WorkIQCalendar",
        foundry_workiq_teams_connection_id="/x/conn/WorkIQTeams",
    )


def test_full_capability_attaches_whole_allowlist_and_gates_mutations(monkeypatch):
    """Default build = the FULL allow-list (so the agent can reason over every
    capability) with reads auto-approved and mutating tools requiring human
    approval. This is the 'reason over everything, confirm each action' model."""
    from impactiq.agents.workiq import REGISTRY, build_workiq_tool

    settings = _settings_with_workiq(monkeypatch)
    cal = build_workiq_tool("calendar", settings)  # default: gated mutations
    assert set(cal.allowed_tools) == set(REGISTRY["calendar"].allowed_tools)
    assert "CreateEvent" in cal.allowed_tools  # mutation IS attached (reasoning)
    # Reads never prompt; everything else (CreateEvent/UpdateEvent) does.
    assert cal.require_approval == {
        "never": {"tool_names": list(REGISTRY["calendar"].read_only_tools)}
    }


def test_non_mutating_server_needs_no_approval(monkeypatch):
    from impactiq.agents.workiq import build_workiq_tool

    settings = _settings_with_workiq(monkeypatch)
    user = build_workiq_tool("user", settings)
    assert user.require_approval == "never"  # all-read server


def test_read_only_build_drops_mutations(monkeypatch):
    from impactiq.agents.workiq import REGISTRY, build_workiq_tool

    settings = _settings_with_workiq(monkeypatch)
    cal = build_workiq_tool("calendar", settings, read_only=True)
    assert set(cal.allowed_tools) == set(REGISTRY["calendar"].read_only_tools)
    assert "CreateEvent" not in cal.allowed_tools
    assert cal.require_approval == "never"


def test_ungated_build_runs_full_list_without_prompts(monkeypatch):
    """gate_mutations=False = full list, no pauses — ONLY for single-purpose
    turns already behind an explicit confirm (e.g. create_draft)."""
    from impactiq.agents.workiq import REGISTRY, build_workiq_tool

    settings = _settings_with_workiq(monkeypatch)
    cal = build_workiq_tool("calendar", settings, gate_mutations=False)
    assert set(cal.allowed_tools) == set(REGISTRY["calendar"].allowed_tools)
    assert cal.require_approval == "never"


# ── /agent/approve: resume a suspended unified run with the human decision ──


def _fake_pc(monkeypatch):
    import contextlib

    import impactiq.agents.runtime as runtime_mod

    @contextlib.contextmanager
    def fake_client(settings, **kw):
        yield object()

    monkeypatch.setattr(runtime_mod, "make_project_client", fake_client)


def test_agent_approve_resumes_and_audits(client, tmp_path, monkeypatch):
    """The resume leg sends the approval decision, completes the run, and
    audit-logs the executed action with approved=True (unified surface)."""
    import impactiq.agents.loop as loop_mod
    from impactiq.agents.loop import TurnResult

    _fake_pc(monkeypatch)
    captured: dict = {}

    def fake_resume(pc, *, approvals, **kw):
        captured["approvals"] = approvals
        return TurnResult(
            raw_text="Booked the sync with Sam for tomorrow 2pm.",
            tool_call_count=1,
            run_status="completed",
            agent_name="ImpactIQ-unified",
            agent_version="3",
        )

    monkeypatch.setattr(loop_mod, "resume_agent_turn", fake_resume)

    body = _run_agent(
        client,
        "/agent/approve",
        {
            "agent_name": "ImpactIQ-unified",
            "agent_version": "3",
            "response_id": "resp_abc",
            "approvals": {"appr_1": True},
            "pending": [
                {
                    "id": "appr_1",
                    "server_label": "workiq-calendar",
                    "tool_name": "CreateEvent",
                    "arguments": '{"subject": "Sync with Sam"}',
                }
            ],
            "user": "demo",
        },
    )
    assert body["status"] == "completed"
    assert "Booked" in body["text"]
    assert body["resume_path"] == "/agent/approve"
    assert captured["approvals"] == {"appr_1": True}

    events = _audit_events(tmp_path)
    assert events[-1]["event_type"] == "assist_action"
    assert events[-1]["surface"] == "unified"
    decision = events[-1]["decisions"][0]
    assert decision["tool_name"] == "CreateEvent"
    assert decision["approved"] is True


def test_agent_deny_is_audited_as_not_approved(client, tmp_path, monkeypatch):
    import impactiq.agents.loop as loop_mod
    from impactiq.agents.loop import TurnResult

    _fake_pc(monkeypatch)
    monkeypatch.setattr(
        loop_mod,
        "resume_agent_turn",
        lambda *a, **k: TurnResult(
            raw_text="No problem — I won't book it.",
            tool_call_count=0,
            run_status="completed",
        ),
    )

    _run_agent(
        client,
        "/agent/approve",
        {
            "agent_name": "ImpactIQ-unified",
            "agent_version": "3",
            "response_id": "resp_abc",
            "approvals": {"appr_1": False},
            "pending": [
                {
                    "id": "appr_1",
                    "server_label": "workiq-teams",
                    "tool_name": "SendMessageToUser",
                    "arguments": "{}",
                }
            ],
            "user": "demo",
        },
    )
    decision = _audit_events(tmp_path)[-1]["decisions"][0]
    assert decision["tool_name"] == "SendMessageToUser"
    assert decision["approved"] is False


# ── unified capability-aware agent (/agent) ─────────────────────────────────


def _stub_unified(monkeypatch, turn):
    import contextlib

    import impactiq.agents.loop as loop_mod
    import impactiq.agents.runtime as runtime_mod
    import impactiq.server as server_mod

    @contextlib.contextmanager
    def fake_client(settings, **kw):
        yield object()

    monkeypatch.setattr(runtime_mod, "make_project_client", fake_client)
    monkeypatch.setattr(loop_mod, "run_agent_turn", lambda *a, **k: turn)
    # Skip the estate prewarm + Work IQ wiring — toolset content is covered by
    # its own invariant test below.
    monkeypatch.setattr(
        server_mod,
        "_unified_tools",
        lambda settings, solution, progress=None, **kw: ([], {}, None, {}),
    )


def test_unified_agent_returns_text(client, monkeypatch):
    from impactiq.agents.loop import TurnResult

    _stub_unified(
        monkeypatch,
        TurnResult(raw_text="The flow failed because...", tool_call_count=3, run_status="completed"),
    )
    body = _run_agent(client, "/agent", {"request": "why did the complaint flow fail?"})
    assert body["status"] == "completed"
    assert "flow failed" in body["text"]
    assert body["resume_path"] == "/agent/approve"


def test_unified_agent_suspends_and_stashes_dispatch(client, monkeypatch):
    """A gated mutation pauses the run AND keeps the engine dispatch alive in
    the pending-run registry so resumed turns can still call engine tools."""
    import contextlib

    import impactiq.agents.loop as loop_mod
    import impactiq.agents.runtime as runtime_mod
    import impactiq.server as server_mod
    from impactiq.agents.loop import TurnResult

    @contextlib.contextmanager
    def fake_client(settings, **kw):
        yield object()

    monkeypatch.setattr(runtime_mod, "make_project_client", fake_client)
    fake_dispatch = {"walk_anchor": lambda args: "{}"}
    monkeypatch.setattr(
        server_mod,
        "_unified_tools",
        lambda settings, solution, progress=None, **kw: ([], fake_dispatch, None, {}),
    )
    monkeypatch.setattr(
        loop_mod,
        "run_agent_turn",
        lambda *a, **k: TurnResult(
            raw_text="",
            tool_call_count=2,
            run_status="pending_approval",
            pending_approvals=[
                {"id": "appr_9", "server_label": "workiq-teams",
                 "tool_name": "SendMessageToUser", "arguments": "{}"}
            ],
            resume_response_id="resp_unified_1",
            agent_name="ImpactIQ-unified",
            agent_version="3",
        ),
    )
    server_mod._PENDING_RUNS.clear()
    body = _run_agent(client, "/agent", {"request": "let the owner know"})
    assert body["status"] == "pending_approval"
    assert body["resume_path"] == "/agent/approve"
    assert server_mod._PENDING_RUNS["resp_unified_1"]["dispatch"] is fake_dispatch

    # The resume leg pops the stash and hands the SAME dispatch to the loop.
    captured: dict = {}

    def fake_resume(pc, *, dispatch, **kw):
        captured["dispatch"] = dispatch
        return TurnResult(raw_text="Sent.", tool_call_count=1, run_status="completed")

    monkeypatch.setattr(loop_mod, "resume_agent_turn", fake_resume)
    body2 = _run_agent(
        client,
        "/agent/approve",
        {
            "agent_name": "ImpactIQ-unified",
            "agent_version": "3",
            "response_id": "resp_unified_1",
            "approvals": {"appr_9": True},
            "pending": [],
            "user": "demo",
        },
    )
    assert body2["status"] == "completed"
    assert captured["dispatch"] is fake_dispatch
    assert "resp_unified_1" not in server_mod._PENDING_RUNS  # consumed


def test_unified_toolset_keeps_dataverse_read_only(monkeypatch):
    """The unified agent may READ records but never write them — record
    writes stay exclusively behind the offer gate. So the Dataverse tool in
    the union must carry only the read subset."""
    import dataclasses

    import impactiq.server as server_mod

    settings = dataclasses.replace(
        server_mod.get_settings(),
        foundry_workiq_user_connection_id="/x/conn/WorkIQUser",
        foundry_workiq_calendar_connection_id="/x/conn/WorkIQCalendar",
        foundry_workiq_teams_connection_id="/x/conn/WorkIQTeams",
        foundry_workiq_mail_connection_id="/x/conn/WorkIQMail",
        foundry_workiq_dataverse_connection_id="/x/conn/DataverseDirect1",
        dataverse_url="https://example.crm.dynamics.com",
    )
    # Force the estate prewarm to fail fast — we only inspect Work IQ tools.
    import impactiq.dataverse_client as dvc

    monkeypatch.setattr(
        dvc.DataverseClient, "__init__",
        lambda self, s: (_ for _ in ()).throw(RuntimeError("no estate in test")),
    )
    tools, dispatch, dv_client, holder = server_mod._unified_tools(settings, "Enterprise CRM")
    assert dv_client is None
    by_label = {getattr(t, "server_label", ""): t for t in tools if hasattr(t, "server_label")}
    dv = by_label["workiq-dataverse"]
    assert set(dv.allowed_tools) == {"read_query", "search", "describe"}
    assert dv.require_approval == "never"  # reads don't prompt
    # Mutating surfaces ARE attached (calendar/teams/mail) — gated, not absent.
    assert "workiq-calendar" in by_label and "workiq-teams" in by_label
    assert "CreateEvent" in by_label["workiq-calendar"].allowed_tools
    # The deep multi-agent pipeline is attached AS A TOOL — the agent decides
    # when to convene it (no pre-router); it survives even without the estate.
    assert "deep_impact_analysis" in dispatch
    assert holder == {}


def test_unified_agent_attaches_report_cards_when_deep_tool_ran(client, monkeypatch):
    """When the agent convened deep_impact_analysis, /agent carries the
    validated report + actionable cards so the remediation/handoff flows are
    intact."""
    import contextlib

    import impactiq.agents.loop as loop_mod
    import impactiq.agents.runtime as runtime_mod
    import impactiq.server as server_mod
    from impactiq.agents.loop import TurnResult
    from impactiq.report.schema import ImpactReport

    @contextlib.contextmanager
    def fake_client(settings, **kw):
        yield object()

    monkeypatch.setattr(runtime_mod, "make_project_client", fake_client)
    holder: dict = {}
    monkeypatch.setattr(
        server_mod,
        "_unified_tools",
        lambda settings, solution, progress=None, **kw: ([], {}, None, holder),
    )

    def fake_run(*a, **k):
        # Simulate the deep tool having stored its validated report mid-turn.
        holder["report"] = ImpactReport.model_validate(
            {
                "intent": "VALIDATE",
                "verdict": "Low risk, coordinate first.",
                "confidence": 0.9,
                "risk": {"score": 20, "level": "low", "reasons": []},
                "recommendation": "Talk to the owner.",
                "generated_artifact": {
                    "artifact_type": "manager_handoff",
                    "recipient": "Sam",
                    "draft_text": "please review",
                    "baton": {"intent": "VALIDATE"},
                },
            }
        )
        return TurnResult(
            raw_text="It's low risk, but loop in Sam first.",
            tool_call_count=4,
            run_status="completed",
        )

    monkeypatch.setattr(loop_mod, "run_agent_turn", fake_run)
    body = _run_agent(client, "/agent", {"request": "is it safe to add this column?"})
    assert body["status"] == "completed"
    assert body["report"]["verdict"].startswith("Low risk")
    assert body["offer"]["action"] == "draft_notification"
    assert body["draft_card"] is not None


def test_record_cards_deep_link_and_read_only():
    """Record cards deep-link to the REAL Power Apps form (same URL shape our
    url_resolve parses) and carry NO write/submit actions — record edits stay
    in Power Apps / behind the offer gate."""
    from impactiq.report.card import record_cards

    payload = {
        "title": "Latest customer requests",
        "table": "new_customerrequest",
        "records": [
            {
                "id": "11111111-2222-3333-4444-555555555555",
                "Name": "CUSTREQ-1000",
                "Type": "Complaint",
                "Created On": "2026-06-09",
            },
            {"id": "aaaa1111-2222-3333-4444-555555555555", "Name": "CUSTREQ-1001"},
        ],
    }
    cards = record_cards(payload, "https://org.crm6.dynamics.com", "app-guid-1")
    assert len(cards) == 2
    url = cards[0]["actions"][0]["url"]
    assert cards[0]["actions"][0]["type"] == "Action.OpenUrl"
    assert "appid=app-guid-1" in url
    assert "etn=new_customerrequest" in url
    assert "id=11111111-2222-3333-4444-555555555555" in url
    # No Action.Submit anywhere — read-only by construction.
    assert all(a["type"] == "Action.OpenUrl" for c in cards for a in c["actions"])
    assert "CUSTREQ-1000" in json.dumps(cards[0])


def test_unified_agent_attaches_record_cards(client, monkeypatch):
    """When the agent called present_records, /agent carries record_cards."""
    import contextlib

    import impactiq.agents.loop as loop_mod
    import impactiq.agents.runtime as runtime_mod
    import impactiq.server as server_mod
    from impactiq.agents.loop import TurnResult

    @contextlib.contextmanager
    def fake_client(settings, **kw):
        yield object()

    monkeypatch.setattr(runtime_mod, "make_project_client", fake_client)
    holder: dict = {}
    monkeypatch.setattr(
        server_mod,
        "_unified_tools",
        lambda settings, solution, progress=None, **kw: ([], {}, None, holder),
    )

    def fake_run(*a, **k):
        holder["records_payload"] = {
            "title": "Latest",
            "table": "new_customerrequest",
            "records": [{"id": "11111111-2222-3333-4444-555555555555", "Name": "CUSTREQ-1000"}],
        }
        return TurnResult(
            raw_text="Here are the latest records:", tool_call_count=2, run_status="completed"
        )

    monkeypatch.setattr(loop_mod, "run_agent_turn", fake_run)
    body = _run_agent(client, "/agent", {"request": "show latest customer requests"})
    assert len(body["record_cards"]) == 1
    assert "CUSTREQ-1000" in json.dumps(body["record_cards"][0])


def test_ack_returns_one_liner(client, monkeypatch):
    _stub_turn(monkeypatch, "Let me pull the latest Customer Request records.\nextra line")
    r = client.post("/ack", json={"question": "show latest customer requests"})
    assert r.status_code == 200
    assert r.json()["text"] == "Let me pull the latest Customer Request records."


# ── interactive baton-handoff (deliver / resume / ack) ───────────────────────


def _handoff_with_baton(**over) -> dict:
    art = {
        "artifact_type": "manager_handoff",
        "recipient": "manager@example.com",
        "draft_text": "cuser is proposing a change that may affect your team's data on Contacts.",
        "baton": {
            "baton_id": "baton-abc123",
            "requesting_user": "cuser@example.com",
            "intent": "VALIDATE",
            "anchor": {"id": "t:contact", "kind": "Table", "name": "Contacts"},
            "proposed_change": "Add a Performance column to Contacts",
            "impacted_components": [{"id": "t:contact", "kind": "Table", "name": "Contacts"}],
            "risk_level": "medium",
            "resume_hint": "Check collisions with your team's work.",
        },
    }
    art.update(over)
    return art


def test_baton_notification_card_is_impact_assertion_only():
    """Card 1 carries the baton id + the interactive buttons, and structurally
    cannot leak the other team's content (the baton has no such field)."""
    from impactiq.report.artifacts import ManagerHandoff
    from impactiq.report.card import baton_notification_card

    card = baton_notification_card(ManagerHandoff.model_validate(_handoff_with_baton()))
    actions = [a["data"]["action"] for a in card["actions"]]
    assert actions == ["baton_tell_more", "baton_ack", "baton_ack"]
    assert all(a["data"]["baton_id"] == "baton-abc123" for a in card["actions"])


def test_baton_store_row_roundtrip_uses_live_logical_names():
    """The store maps to the EXACT live column logical names (new_ prefix,
    new_impactiqname primary) and round-trips a baton."""
    from impactiq.baton_store import _NAME, _PK, _baton_to_row, _row_to_stored
    from impactiq.report.artifacts import ContextBaton

    baton = ContextBaton(
        baton_id="baton-xyz",
        requesting_user="cuser",
        intent="VALIDATE",
        anchor={"id": "t:contact", "kind": "Table", "name": "Contacts"},
        proposed_change="Add column",
        impacted_components=[{"id": "t:contact", "kind": "Table", "name": "Contacts"}],
        risk_level="medium",
        resume_hint="check",
    )
    row = _baton_to_row(baton, "mgr@example.com", "sent")
    assert _NAME == "new_impactiqname" and row[_NAME] == "baton-xyz"
    assert row["new_impactiq_recipient"] == "mgr@example.com"
    assert row["new_impactiq_baton_version"] == 1  # Integer column
    # Simulate Dataverse echoing the created row back with its PK + createdon.
    row[_PK] = "guid-1"
    row["createdon"] = "2026-06-12T00:00:00Z"
    stored = _row_to_stored(row)
    assert stored.row_id == "guid-1"
    assert stored.recipient == "mgr@example.com"
    assert stored.baton.anchor.name == "Contacts"
    assert stored.baton.impacted_components[0].name == "Contacts"
    assert stored.baton.risk_level == "medium"


def test_handoff_deliver_requires_confirmation(client, tmp_path):
    r = client.post(
        "/handoff/deliver", json={"artifact": _handoff_with_baton(), "confirmed": False}
    )
    assert r.status_code == 403
    assert _audit_events(tmp_path) == []  # nothing persisted on inference


def test_handoff_deliver_rejects_non_handoff(client):
    r = client.post(
        "/handoff/deliver",
        json={"artifact": {"artifact_type": "dev_ticket", "title": "x"}, "confirmed": True},
    )
    assert r.status_code == 400


def test_handoff_deliver_persists_and_returns_card(client, tmp_path, monkeypatch):
    import impactiq.baton_store as bs
    from impactiq.baton_store import StoredBaton

    def fake_put(settings, baton, recipient, *, status="sent", user_assertion=None):
        return StoredBaton(baton=baton, recipient=recipient, status=status, row_id="row-guid-1")

    monkeypatch.setattr(bs, "put_baton", fake_put)
    r = client.post(
        "/handoff/deliver",
        json={"artifact": _handoff_with_baton(), "user": "cuser", "confirmed": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["delivered"] is True and body["baton_id"] == "baton-abc123"
    assert "baton_tell_more" in json.dumps(body["card"])
    ev = _audit_events(tmp_path)
    assert ev[-1]["event_type"] == "handoff_delivered" and ev[-1]["row_id"] == "row-guid-1"


def test_handoff_resume_404_when_missing(client, monkeypatch):
    import impactiq.baton_store as bs

    monkeypatch.setattr(bs, "get_baton", lambda s, bid, ua=None: None)
    r = client.post("/handoff/resume", json={"baton_id": "nope"})
    assert r.status_code == 404


def test_handoff_resume_runs_as_manager_and_audits(client, tmp_path, monkeypatch):
    import types

    import impactiq.agents.multi_agent as ma
    import impactiq.baton_store as bs
    from impactiq.baton_store import StoredBaton
    from impactiq.report.artifacts import ContextBaton

    baton = ContextBaton(
        baton_id="baton-abc123",
        requesting_user="cuser",
        intent="VALIDATE",
        anchor={"id": "t:contact", "kind": "Table", "name": "Contacts"},
        proposed_change="Add Performance column",
        resume_hint="check collisions",
    )
    monkeypatch.setattr(
        bs,
        "get_baton",
        lambda s, bid, ua=None: StoredBaton(baton=baton, recipient="mgr", status="sent", row_id="r1"),
    )

    captured: dict = {}

    def fake_ask(settings, *, solution_name, question, as_user, user_assertion=None, progress=None):
        captured["question"] = question
        captured["as_user"] = as_user
        return types.SimpleNamespace(
            report={
                "intent": "VALIDATE",
                "verdict": "This collides with your Project X cutover.",
                "confidence": 0.9,
                "risk": {"score": 40, "level": "medium", "reasons": []},
                "recommendation": "Ask them to hold until next week.",
            },
            run_status="completed",
            tool_call_count=2,
        )

    monkeypatch.setattr(ma, "ask_multi", fake_ask)
    r = client.post("/handoff/resume", json={"baton_id": "baton-abc123", "user": "manager"})
    assert r.status_code == 200
    body = r.json()
    assert "Project X" in body["summary_text"]
    assert captured["as_user"] is True  # the resume runs as the manager (the tapper)
    assert "Add Performance column" in captured["question"]
    ev = _audit_events(tmp_path)
    assert ev[-1]["event_type"] == "baton_resumed" and ev[-1]["baton_id"] == "baton-abc123"


def test_handoff_ack_audits(client, tmp_path):
    r = client.post(
        "/handoff/ack",
        json={"baton_id": "baton-abc123", "stance": "reviewing", "user": "manager"},
    )
    assert r.status_code == 200 and r.json()["ok"] is True
    ev = _audit_events(tmp_path)
    assert ev[-1]["event_type"] == "baton_acknowledged" and ev[-1]["stance"] == "reviewing"


def test_dev_ticket_card_renders_full_body():
    from impactiq.report.card import artifact_card
    from impactiq.report.schema import ImpactReport

    report = ImpactReport.model_validate(
        {
            "intent": "DIAGNOSE",
            "verdict": "v",
            "confidence": 0.9,
            "risk": {"score": 10, "level": "low", "reasons": []},
            "recommendation": "r",
            "generated_artifact": {
                "artifact_type": "dev_ticket",
                "title": "Fix the complaint flow",
                "severity": "high",
                "root_cause": "action step fails on closed records",
                "suggested_fix": "guard the update on status",
                "acceptance_criteria": ["closed records update", "no duplicate writes"],
            },
        }
    )
    card = json.dumps(artifact_card(report))
    assert "Root cause" in card and "action step fails" in card
    assert "Acceptance criteria" in card and "no duplicate writes" in card


# ── chat rendering (message, not card) ───────────────────────────────────────


def test_summary_markdown_renders_collisions_plainly():
    from impactiq.report.render import report_summary_markdown
    from impactiq.report.schema import ImpactReport

    report = ImpactReport.model_validate(
        {
            "intent": "VALIDATE",
            "verdict": "Low risk, but coordinate first.",
            "confidence": 0.9,
            "risk": {"score": 20, "level": "low", "reasons": []},
            "recommendation": "Talk to the owner before building.",
            "change_collisions": [
                {
                    "component": {"id": "t:contact", "kind": "Table", "name": "Contacts"},
                    "who": None,
                    "sensitivity": "restricted",
                    "advice": "",
                }
            ],
        }
    )
    text = report_summary_markdown(report)
    assert "[restricted]" not in text  # no internal tags in user-facing text
    assert "🔒" in text and "Contacts" in text
    assert "not identified" in text  # unknown owner stays honest, not invented


def test_artifact_offer_for_handoff_and_none_for_null():
    from impactiq.report.render import artifact_offer
    from impactiq.report.schema import ImpactReport

    base = {
        "intent": "VALIDATE",
        "verdict": "v",
        "confidence": 0.9,
        "risk": {"score": 10, "level": "low", "reasons": []},
        "recommendation": "r",
    }
    no_artifact = ImpactReport.model_validate(base)
    assert artifact_offer(no_artifact) is None

    with_handoff = ImpactReport.model_validate(
        {
            **base,
            "generated_artifact": {
                "artifact_type": "manager_handoff",
                "recipient": "Sam",
                "draft_text": "please review",
                "baton": {"intent": "VALIDATE"},
            },
        }
    )
    offer = artifact_offer(with_handoff)
    assert offer["action"] == "draft_notification"
    assert "Sam" in offer["label"]


def test_editable_draft_card_prefills_text():
    from impactiq.report.card import editable_draft_card
    from impactiq.report.schema import ImpactReport

    report = ImpactReport.model_validate(
        {
            "intent": "VALIDATE",
            "verdict": "v",
            "confidence": 0.9,
            "risk": {"score": 10, "level": "low", "reasons": []},
            "recommendation": "r",
            "generated_artifact": {
                "artifact_type": "manager_handoff",
                "recipient": "Sam",
                "draft_text": "please review this proposal",
                "baton": {"intent": "VALIDATE"},
            },
        }
    )
    card = json.dumps(editable_draft_card(report))
    assert "Input.Text" in card and "please review this proposal" in card
    # The action saves an editable DRAFT to Outlook (never sends).
    assert "create_draft" in card
    assert "Save as draft" in card


# ── send_handoff gate ────────────────────────────────────────────────────────


def test_send_handoff_refused_without_confirmation(client, tmp_path):
    r = client.post(
        "/action/send_handoff",
        json={"artifact": _handoff_artifact(), "confirmed": False},
    )
    assert r.status_code == 403
    assert _audit_events(tmp_path) == []  # nothing sent, nothing logged as sent


def test_send_handoff_rejects_non_sendable_artifact(client):
    r = client.post(
        "/action/send_handoff",
        json={"artifact": _remediation_artifact(), "confirmed": True},
    )
    assert r.status_code == 400


def test_send_handoff_confirmed_returns_message_and_audits(client, tmp_path):
    r = client.post(
        "/action/send_handoff",
        json={"artifact": _handoff_artifact(), "confirmed": True, "user": "demo"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["send"] is True
    assert body["recipient"].startswith("Sam")
    events = _audit_events(tmp_path)
    assert len(events) == 1
    assert events[0]["event_type"] == "handoff_sent"
    assert events[0]["baton_id"] == "baton-test123"
    assert events[0]["confirmation"] == "tap"


# ── remediate gate ───────────────────────────────────────────────────────────


def test_remediate_refuses_configuration_table(client, tmp_path):
    r = client.post(
        "/action/remediate",
        json={
            "artifact": _remediation_artifact(record_table="workflow"),
            "confirmation_type": "tap",
        },
    )
    assert r.status_code == 403
    assert "configuration" in r.json()["detail"]
    events = _audit_events(tmp_path)
    assert events and events[0]["event_type"] == "remediation_refused"


def test_remediate_refuses_low_confidence(client):
    r = client.post(
        "/action/remediate",
        json={
            "artifact": _remediation_artifact(diagnosis_confidence=0.5),
            "confirmation_type": "tap",
        },
    )
    assert r.status_code == 403
    assert "confidence" in r.json()["detail"]


def test_remediate_enforces_typed_for_document_grounded(client):
    artifact = _remediation_artifact(
        evidence_source="document",
        document_name="Corrections.docx",
        source_span="set status to Reopened",
    )
    # Document-grounded + tap => refused (must be typed).
    r = client.post(
        "/action/remediate",
        json={
            "artifact": artifact,
            "confirmation_type": "tap",
            "user_referenced_document": True,
        },
    )
    assert r.status_code == 403
    assert "typed" in r.json()["detail"]


def test_remediate_typed_value_must_match(client):
    artifact = _remediation_artifact(
        evidence_source="document",
        document_name="Corrections.docx",
        source_span="set status to Reopened",
    )
    r = client.post(
        "/action/remediate",
        json={
            "artifact": artifact,
            "confirmation_type": "typed",
            "typed_value": "SomethingElse",
            "user_referenced_document": True,
        },
    )
    assert r.status_code == 403
    assert "does not match" in r.json()["detail"]


def test_remediate_document_without_user_reference_refused(client):
    artifact = _remediation_artifact(
        evidence_source="document",
        document_name="Corrections.docx",
        source_span="set status to Reopened",
    )
    r = client.post(
        "/action/remediate",
        json={
            "artifact": artifact,
            "confirmation_type": "typed",
            "typed_value": "Reopened",
            "user_referenced_document": False,
        },
    )
    assert r.status_code == 403
    assert "agent-initiated" in r.json()["detail"]


def test_remediate_happy_path_executes_write_and_audits(client, tmp_path, monkeypatch):
    # Intercept the delegated-identity plumbing + the Dataverse PATCH.
    import dataclasses

    import impactiq.server as server_mod

    # Force the deterministic PATCH path regardless of the ambient .env (the
    # Dataverse MCP connection may be set locally; this test exercises PATCH).
    _real = server_mod.get_settings()
    monkeypatch.setattr(
        server_mod,
        "get_settings",
        lambda: dataclasses.replace(_real, foundry_workiq_dataverse_connection_id=None),
    )
    monkeypatch.setattr(server_mod, "_dataverse_user_token", lambda s, ua=None: "fake-token")
    monkeypatch.setattr(
        server_mod, "_entity_set_name", lambda b, t, ln: "new_customerrequests"
    )

    captured: dict = {}

    class _Resp:
        status_code = 204
        headers = {"OData-EntityId": "new_customerrequests(1111...)"}
        text = ""

    def fake_patch(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _Resp()

    monkeypatch.setattr(server_mod.httpx, "patch", fake_patch)

    r = client.post(
        "/action/remediate",
        json={
            "artifact": _remediation_artifact(),
            "confirmation_type": "tap",
            "user": "demo",
            "diagnosis_id": "diag-42",
        },
    )
    assert r.status_code == 200
    assert r.json()["executed"] is True
    assert captured["json"] == {"statuscode": "Reopened"}
    assert "new_customerrequests(11111111-" in captured["url"]
    assert captured["headers"]["If-Match"] == "*"  # update-only, never create

    events = _audit_events(tmp_path)
    assert events[-1]["event_type"] == "remediation_executed"
    assert events[-1]["diagnosis_id"] == "diag-42"
    assert events[-1]["confirmation_type"] == "tap"
    assert events[-1]["preview"][0]["column"] == "statuscode"


def test_remediate_prefers_dataverse_mcp_when_configured(client, tmp_path, monkeypatch):
    """When the Dataverse MCP connection is configured, the write goes through
    the MCP path (update_record), not the Web API PATCH."""
    import dataclasses

    import impactiq.server as server_mod

    _real = server_mod.get_settings()
    monkeypatch.setattr(
        server_mod,
        "get_settings",
        lambda: dataclasses.replace(
            _real, foundry_workiq_dataverse_connection_id="/x/conn/MicrosoftDataverse"
        ),
    )
    called: dict = {}

    def fake_mcp(settings, proposal, payload, user_assertion=None):
        called["payload"] = payload
        return True, "workiq_dataverse_mcp", "done"

    monkeypatch.setattr(server_mod, "_write_via_dataverse_mcp", fake_mcp)
    # If PATCH is wrongly used, this would blow up (no token plumbing stubbed).

    r = client.post(
        "/action/remediate",
        json={"artifact": _remediation_artifact(), "confirmation_type": "tap", "user": "demo"},
    )
    assert r.status_code == 200
    assert r.json()["write_channel"] == "workiq_dataverse_mcp"
    assert called["payload"] == {"statuscode": "Reopened"}
    assert _audit_events(tmp_path)[-1]["write_channel"] == "workiq_dataverse_mcp"
