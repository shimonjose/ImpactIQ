"""Behavior pins — every live incident we fixed becomes an assertion.

Model behavior can't be unit-tested, but the *carriers* of each fix can:
instruction text, tool registries, allow-lists, card shapes, surface
plumbing. Each pin is keyed to the incident that created it; if an
instruction consolidation or refactor drops one, this suite names exactly
which live bug just came back.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from impactiq.server import ACK_INSTRUCTIONS, UNIFIED_INSTRUCTIONS

SURFACE = Path(__file__).resolve().parents[1] / "surface" / "src" / "agent.ts"


def _flat(text: str) -> str:
    """Whitespace-normalized: pins must survive re-wrapping of the prose."""
    return re.sub(r"\s+", " ", text)


# ── unified-agent instruction pins ───────────────────────────────────────────


@pytest.mark.parametrize(
    "needle, incident",
    [
        # Hosted tool wire-names MUST be named or the model never calls them
        # (the same root cause hit work_iq_preview, SearchMessages and the KB).
        ("work_iq_preview", "workplace search never invoked"),
        ("SearchMessages", "mail search never invoked"),
        ("SearchTeamsMessages", "teams search never invoked"),
        ("knowledge_base_retrieve", "KB never invoked"),
        ("sandbox_inspect", "sandbox fix path"),
        ("sandbox_fix", "sandbox fix path"),
        ("flow_run_details", "live forensics fold-back"),
        ("resubmit_flow_run", "failed-run resubmit"),
        ("deep_impact_analysis", "deep pipeline as a tool"),
        ("propose_record_fix", "unified §7.2 proposals (boundary redraw)"),
        # YOU investigate; the pipeline ADJUDICATES — no double diagnosis.
        ("the pipeline ADJUDICATES", "double-diagnosis latency"),
        # Deep analysis is REQUIRED for new ideas / issue reports / validation
        # (reversed the over-correction that made it skip the pipeline).
        ("it is REQUIRED, not optional", "deep pipeline under-triggered"),
        ("REQUIRED THIS TURN", "per-turn deep-analysis mandate"),
        # 'no governance context' claimed without calling the KB.
        ("NEVER state that no governance context exists", "KB false-negative"),
        # Proposed turning the flow off instead of repairing it.
        ("PREFER REPAIR OVER DISABLE", "disable-instead-of-fix"),
        # Shorthand flow names bounced back to the user.
        ("SAME names", "sandbox twin name resolution"),
        # The agent claimed a fix was applied at proposal time.
        ("Never claim a fix was applied", "proposal honesty"),
        # Autonumber/text + bare-GUID bind: schema grounding is mandatory.
        ("autonumber columns are", "autonumber literal write"),
        ("<entityset>(<id>)", "bare-GUID lookup bind"),
        # Trace a bad value to the step that produced it (run forensics).
        ("TRACE", "step I/O tracing"),
        ("child_flows", "child-flow drill-down"),
        # The data-debt remediation arc (creates, resubmit, fallout sweep).
        ("DATA DEBT", "missed-rows arc"),
        # A forward-only change doesn't alter existing records — don't show
        # them as "impacted" or imply a backfill (the TASK-1000 confusion).
        ("FORWARD-ONLY CHANGES", "forward-only mislabelled as impacted records"),
        # Surface the workplace-check RESULT explicitly (Teams/email verified),
        # even when negative — silence read as "didn't check".
        ("workplace-check RESULT", "Work IQ verification not visible"),
        # Take 365/Power Platform actions, don't just print them in chat
        # (the "drafted in chat, never saved to Outlook" gap).
        ("TAKE THE ACTION", "Work IQ action described instead of taken"),
        ("ONLY email-draft tool", "agent hand-rolled CreateDraftMessage instead of draft_reply"),
        # An external customer isn't in the org directory — get the address from
        # their email, don't give up and print the body asking for it.
        ("REPLYING TO A PERSON", "couldn't draft to an external customer (directory miss)"),
        # Reason the reply from the RECIPIENT's side: a customer wants the
        # outcome (the acknowledgement), not "the flow broke".
        ("ALWAYS REASON THE NATURE OF A REPLY/HANDOFF", "drafted a 'flow broke' message instead of the acknowledgement the customer expected"),
        # A LIFTED freeze + a 'coordinate with owner' requirement is NOT a hard
        # block — propose (confirm-gated) with the caveat, don't refuse.
        ("ACTIVE vs LIFTED", "refused a confirm-gated remediation citing a freeze that was lifted"),
        # Remediation follow-ups ('create the missing records') reuse the prior
        # diagnosis — don't re-run the whole pipeline.
        ("REMEDIATION follow-through", "re-ran the full pipeline for a remediation follow-up"),
        # A gated action (book meeting / Teams / reply) must carry a one-line
        # lead-in so the Approve/Deny prompt isn't a blank message.
        ("write ONE short line of context FIRST", "blank reply on a gated approval (e.g. book meeting)"),
        # A directory-miss for a Teams target = external → switch to email,
        # don't ask the user for a Teams handle.
        ("CHANNEL RECOVERY", "asked the user for a Teams handle for an external person instead of emailing"),
        # Chain tools instead of stopping at the first that comes up empty.
        ("CHAIN YOUR TOOLS", "agent acted like it didn't know its own capabilities"),
        # Teams is internal-only — an external customer is email-only; reason
        # about reachability before picking/offering a channel.
        ("MATCH THE CHANNEL TO WHO THEY ARE", "offered a Teams message to an external customer"),
        # Replying to a person goes through the deterministic draft_reply tool —
        # not hand-rolled directory/CreateDraftMessage (which kept failing).
        ("draft_reply", "reply hand-rolled with the directory and failed to address it"),
        # Acting on an already-analysed fix skips re-running deep analysis.
        ("ALREADY-ANALYSED SHORTCUT", "re-analysis on apply-fix follow-through"),
        # A change freeze / hold must block proposing or applying a fix —
        # caught semantically (any wording), never by keyword.
        ("CHANGE-CONTROL GATE", "change freeze missed before applying a fix"),
        ("judge by MEANING, never by keyword", "freeze caught semantically not by keyword"),
        # Reason like a human about what to check — lists are floors not
        # ceilings — so we stop enumerating every category by hand.
        ("CURATE YOUR OWN CHECKS", "agent waits to be told what to search for"),
        # The live Work IQ searches are a keyword backend with a 60s timeout —
        # rich concept queries time out / under-match (missed customer emails);
        # they need SHORT keyword queries, concept phrasing only for the index.
        ("LIVE SEARCH QUERY STYLE", "live keyword search timed out on concept queries"),
        ("resubmit", "post-export rerun step"),
        # Asking permission to read is a failure mode.
        ("NEVER ask permission to read", "shall-I-check prompting"),
        # Drafts are inert and auto-run; sends pause for approval.
        ("draft is inert", "draft-vs-send consequence ladder"),
        # Confidence/risk framing only for validation+diagnosis answers.
        ("ANSWER SHAPE", "score spam on casual answers"),
        # Real failures live in LIVE; fixes go to the sandbox twin.
        ("ALM TOPOLOGY", "fix applied to wrong environment"),
        # Don't promise a sandbox fix the user's role can't deliver.
        ("BUILDER ACCESS", "builder offer without permission awareness"),
        # Fix every defect the evidence shows, not just the reported one.
        ("Fix EVERY defect", "second-defect runtime failure"),
    ],
)
def test_unified_instructions_carry_fix(needle: str, incident: str):
    assert _flat(needle) in _flat(UNIFIED_INSTRUCTIONS), (
        f"UNIFIED_INSTRUCTIONS lost the {incident!r} fix (missing {needle!r})"
    )


@pytest.mark.parametrize(
    "needle, incident",
    [
        # Triage must answer generic questions itself…
        ("ANSWER:", "'Hi' routed to the heavy agent"),
        # …but never answer about tenant data from memory.
        ("from memory", "hallucinated estate answers at the front door"),
    ],
)
def test_ack_instructions_carry_fix(needle: str, incident: str):
    assert _flat(needle) in _flat(ACK_INSTRUCTIONS), (
        f"ACK_INSTRUCTIONS lost the {incident!r} fix (missing {needle!r})"
    )


# ── tool-registry pins (live-enumerated wire names, not doc-derived) ─────────


def test_mail_registry_uses_live_wire_names():
    """Incident: doc-derived names (mcp_MailTools_graph_mail_*) — the live
    server exposes different ones; drafts auto-run (inert), sends gate."""
    from impactiq.agents.workiq import REGISTRY

    mail = REGISTRY["mail"]
    for name in ("SearchMessages", "GetMessage", "CreateDraftMessage", "ReplyToMessage"):
        assert name in mail.allowed_tools
    assert set(mail.auto_approve_tools) == {"CreateDraftMessage", "UpdateDraft"}
    assert "CreateDraftMessage" not in mail.read_only_tools


def test_technical_specialist_owns_forensics():
    """The deep pipeline must keep the same evidence depth as the fix path."""
    from impactiq.agents.tools import TECHNICAL_TOOL_NAMES

    assert "find_failed_flows" in TECHNICAL_TOOL_NAMES
    assert "flow_run_details" in TECHNICAL_TOOL_NAMES


def test_specialists_run_under_a_wallclock_budget():
    """A cold knowledge KB retrieval once pushed the whole /agent turn past the
    surface fetch timeout — the client aborted and the finished report was
    discarded. Each specialist must run under a wall-clock budget and degrade to
    a 'skipped' finding (NOT an empty one) on overrun, so the fan-in never
    deadlocks and a slow hosted call can't sink the turn."""
    import inspect

    import impactiq.agents.multi_agent as ma

    assert hasattr(ma, "_SPECIALIST_BUDGET_S")
    assert ma._SPECIALIST_BUDGET_S > 0
    src = inspect.getsource(ma)
    # Override hook for ops, and every specialist routed through the budget.
    assert "IMPACTIQ_SPECIALIST_BUDGET_S" in src
    assert src.count("_run_with_budget(") >= 3  # def + 3 executors (technical/knowledge/context)
    # A timed-out specialist is 'skipped', never read as 'nothing found'.
    budget_src = inspect.getsource(ma._run_with_budget)
    assert 'status="skipped"' in budget_src
    # Context owns the slow two-search live floor, so it MUST get a larger budget
    # than the fast deterministic/KB specialists — otherwise the cap guillotines
    # it on a slow backend and discards the customer email it just found
    # (observed live: context finished at 196s but was skipped at 120s).
    assert ma._budget_for("context") > ma._budget_for("technical")
    assert ma._budget_for("context") >= 240


def test_warmup_warms_the_knowledge_base():
    """Same incident: /warmup must prewarm the Foundry IQ KB (not only the
    estate + tool-less agents), so the first deep question doesn't eat the
    cold agentic-retrieval start that triggered the abort."""
    import inspect

    import impactiq.server as srv

    src = inspect.getsource(srv.warmup)
    assert "_warm_kb" in src
    assert "kb-warmup" in src  # the daemon thread is actually started


def test_warmup_warms_workiq_under_delegated_identity():
    """Once the KB was warmed, the context specialist's live Work IQ searches
    (~115s cold) became the gating cost. /warmup must prewarm them too — and
    ONLY under the delegated identity (as_user), because Work IQ reads CONTENT
    and the service identity must never read content (two identities by
    scope)."""
    import inspect

    import impactiq.server as srv

    src = inspect.getsource(srv.warmup)
    assert "_warm_workiq" in src
    assert "workiq-warmup" in src  # the daemon thread is actually started
    # Safety: the Work IQ warm runs as_user — find that call in the function.
    warm_block = src[src.index("def _warm_workiq"):]
    assert "make_project_client(settings, as_user=True)" in warm_block


def test_progress_store_dedups_and_drains():
    """Live progress: milestones buffer per conversation, dedup consecutive
    repeats, and drain on read (each poll gets only what's new). No conversation
    key is a safe no-op."""
    from impactiq.server import _drain_progress, _push_progress, _reset_progress

    _reset_progress("pin-c1")
    _push_progress("pin-c1", "Mapping…")
    _push_progress("pin-c1", "Mapping…")  # consecutive dup collapses
    _push_progress("pin-c1", "Inspecting…")
    assert _drain_progress("pin-c1") == ["Mapping…", "Inspecting…"]
    assert _drain_progress("pin-c1") == []  # drained
    _push_progress("", "ignored")  # no conv → no-op, never raises
    assert _drain_progress("") == []


def test_progress_endpoint_and_dispatch_wrapper():
    """The /progress endpoint returns buffered events, and the dispatch wrapper
    records a milestone BEFORE running the tool while passing args/results
    through untouched."""
    from impactiq.server import (
        ProgressRequest,
        _drain_progress,
        _reset_progress,
        _wrap_dispatch_with_progress,
        progress,
    )

    _reset_progress("pin-c2")
    seen = {}
    dispatch = {"deep_impact_analysis": lambda a: seen.update({"args": a}) or "RESULT"}
    wrapped = _wrap_dispatch_with_progress(dispatch, "pin-c2")
    assert wrapped["deep_impact_analysis"]({"q": 1}) == "RESULT"  # impl untouched
    assert seen["args"] == {"q": 1}  # args passed through
    out = progress(ProgressRequest(conversation="pin-c2"))
    assert out["events"] and "impact analysis" in out["events"][0].lower()


def test_ask_multi_accepts_progress_callback():
    """The deep pipeline surfaces per-specialist milestones via an optional
    progress callback (the long pole of a turn must not be silent)."""
    import inspect

    from impactiq.agents.multi_agent import ask_multi

    assert "progress" in inspect.signature(ask_multi).parameters


def test_context_specialist_batches_independent_searches():
    """Same follow-on incident: the context specialist fired its independent
    workplace searches one-at-a-time (3 sequential live searches = ~115s). It
    must batch independent first-round searches into one parallel set — without
    losing the breadth/change-control coverage the autonomy reframe added."""
    from impactiq.agents.specialists import CONTEXT_INSTRUCTIONS

    assert _flat("BATCH FOR SPEED") in _flat(CONTEXT_INSTRUCTIONS)
    # Coverage floor must survive the speed nudge.
    assert "CHANGE-CONTROL" in CONTEXT_INSTRUCTIONS


def test_context_specialist_has_neverfail_floor_with_semantic_freedom():
    """An explicit NEVER-FAIL floor (always run BOTH live searches + check
    change-control) fixes the variability where the specialist sometimes skipped
    mail — WHILE leaving the SEMANTIC search query free-form (no forced
    wording). Floor on channels, freedom on the query."""
    from impactiq.agents.specialists import CONTEXT_INSTRUCTIONS

    flat = _flat(CONTEXT_INSTRUCTIONS)
    assert "NEVER-FAIL FLOOR" in flat
    assert "SearchTeamsMessages" in flat and "SearchMessages" in flat
    # Semantic query freedom must be explicit (not forced wording).
    assert "FULL FREEDOM" in flat


def test_context_specialist_uses_short_live_search_queries():
    """The live Work IQ searches run on a keyword backend with a 60s timeout;
    rich concept-sentence queries time out / under-match, so a reachable customer
    email was repeatedly missed. The context specialist must use SHORT keyword
    queries on the live tools (concept phrasing reserved for the semantic
    `work_iq_preview`)."""
    from impactiq.agents.specialists import CONTEXT_INSTRUCTIONS

    flat = _flat(CONTEXT_INSTRUCTIONS)
    assert "QUERY STYLE" in flat
    assert "60-SECOND TIMEOUT" in flat
    assert "SHORT keyword queries" in flat


def test_context_specialist_surfaces_awaited_outcome_fallout():
    """The search FOUND the email (short keyword query, 27k chars back), but the
    disclosure gate over-redacted it to a vague 'a related case exists', dropping
    the person's name + the actionable fact. The gate must carve out inbound
    awaited-outcome fallout — name WHOEVER reached out (customer, colleague,
    internal user — NOT hardcoded to 'customer') and the chased outcome —
    distinct from confidential internal work."""
    from impactiq.agents.specialists import CONTEXT_INSTRUCTIONS

    flat = _flat(CONTEXT_INSTRUCTIONS)
    assert "AWAITED-OUTCOME FALLOUT" in flat
    # Generic, not customer-only.
    assert "a colleague, an internal user" in flat
    # It must land somewhere actionable, not just be 'allowed'.
    assert "affected_people" in CONTEXT_INSTRUCTIONS


def test_deterministic_awaiting_party_probe():
    """Instruction-tuning couldn't reliably make the context specialist search
    the impacted-party angle (its keyword is anchor-biased), so on a DIAGNOSE
    turn a deterministic floor sweeps generic universal 'still waiting' language
    and merges whoever it finds into affected_people. The probe terms must be
    tenant-agnostic (no sample data), and it must no-op safely with no tools."""
    import inspect

    import impactiq.agents.multi_agent as ma

    assert hasattr(ma, "_probe_awaiting_parties")
    # No live search tools -> safe no-op, never raises.
    assert ma._probe_awaiting_parties(None, None, [], "issue") == []
    # Probe terms are generic universal follow-up language (no sample tokens).
    joined = " ".join(ma._AWAITING_PROBE_TERMS).lower()
    for tok in ("jordan", "alex", "pippop", "complaint", "admin", "acknowledg"):
        assert tok not in joined
    # The floor is actually merged into the context finding's affected_people.
    src = inspect.getsource(ma.ask_multi)
    assert "_probe_awaiting_parties(" in src
    assert 'setdefault("affected_people"' in src


def test_change_freeze_is_current_only():
    """A freeze can be announced and LATER LIFTED; the system must report only
    the CURRENT status, not a stale freeze. Instruction-level: the context brief
    tells the specialist to check for a lift and list only active directives.
    Gate-level: change_control_dominance ignores a change_control entry that
    reads as already lifted (future-tense lifts stay active)."""
    import inspect

    from impactiq.agents.specialists import CONTEXT_INSTRUCTIONS
    from impactiq.report import verdict_gate as vg

    flat = _flat(CONTEXT_INSTRUCTIONS).lower()
    # the supersession step + cancellation search terms are present
    assert "still in effect" in flat
    for term in ("rescinded", "resumed", "lifted"):
        assert term in flat
    # the gate's lifted-directive filter, used by change_control_dominance
    assert hasattr(vg, "_directive_is_lifted")
    assert vg._directive_is_lifted("the freeze was lifted yesterday") is True
    assert vg._directive_is_lifted("active freeze, no end date") is False
    assert vg._directive_is_lifted("freeze will be lifted next week") is False
    assert "_directive_is_lifted(" in inspect.getsource(vg._evaluate)


def test_awaiting_party_machinery_is_diagnose_only():
    """affected_people is the fallout of a FAILED outcome (DIAGNOSE). A VALIDATE
    'new idea' has no failed outcome, so the awaiting-party probe, the
    force-carry safety net, AND the context task framing are all gated to
    DIAGNOSE — otherwise a customer merely present in the area gets flagged as
    'impacted' by a change that never reaches them."""
    import inspect

    import impactiq.agents.multi_agent as ma
    from impactiq.agents.specialists import specialist_task_input

    src = inspect.getsource(ma.ask_multi)
    # the probe is gated by an intent check
    assert "intent_is_diagnose" in src
    # the force-carry merge runs only on DIAGNOSE
    assert 'plan.intent == "DIAGNOSE"' in src

    # the context task brief tells a VALIDATE run to leave affected_people empty,
    # and a DIAGNOSE run carries no such instruction.
    validate_brief = specialist_task_input(
        {"intent": "VALIDATE", "anchor": None, "notes": ""}, "add an automation", "Sol"
    )
    assert "affected_people" in validate_brief and "EMPTY" in validate_brief
    diagnose_brief = specialist_task_input(
        {"intent": "DIAGNOSE", "anchor": None, "notes": ""}, "why did it fail", "Sol"
    )
    assert "leave `affected_people` EMPTY" not in diagnose_brief


def test_catches_and_offers_every_affected_party():
    """A broken automation usually has MORE THAN ONE person to act on, in
    different roles (the owner/approver to coordinate with AND the impacted party
    waiting on the outcome) — found by DIFFERENT keywords. Context must cover
    both role-angles (not one keyword), and the agent must offer a SEPARATE
    next-step for each and let the user choose — never collapse to one. Generic
    roles, never hardcoded to 'customer'."""
    from impactiq.agents.instructions import UNIFIED_INSTRUCTIONS
    from impactiq.agents.specialists import CONTEXT_INSTRUCTIONS

    ctx = _flat(CONTEXT_INSTRUCTIONS)
    # Context covers both role-angles with distinct keywords.
    assert "role-angle" in ctx or "role-angles" in ctx
    assert "OWNER / coordinator" in ctx and "IMPACTED / waiting party" in ctx
    # The agent offers each party as its own choice.
    assert _flat("OFFER EVERY PARTY, LET THE USER CHOOSE") in _flat(UNIFIED_INSTRUCTIONS)


def test_report_carries_affected_people_end_to_end():
    """Context correctly found the waiting person, but the ImpactReport had NO
    field for them, so the adjudicator dropped them and the answer never
    mentioned them or offered a reply. affected_people must flow schema ->
    adjudicator -> deep_impact_analysis return -> render — generically (anyone
    awaiting the outcome, never hardcoded to 'customer')."""
    import inspect

    from impactiq.report.schema import ImpactReport
    from impactiq.agents import multi_agent as ma
    import impactiq.server as srv
    from impactiq.report import render

    # 1. Schema can carry it.
    assert "affected_people" in ImpactReport.model_fields
    # 2. Adjudicator is told to populate it + emits it in its JSON template.
    assert "affected_people" in ma.ADJUDICATOR_INSTRUCTIONS
    # 3. deep_impact_analysis hands it back to the front agent.
    assert "report.affected_people" in inspect.getsource(srv._unified_tools)
    # 4. It renders in the report summary.
    assert "affected_people" in inspect.getsource(render.report_summary_markdown)


def test_no_sample_tenant_data_in_instructions():
    """Agent instructions must NOT bake in a specific tenant's data (customer
    names, people, doc codes) — that overfits the agent to one sample and reads
    as 'works only for that sample'. Examples in prompts must be generic
    placeholders; the agent derives specifics from live search results."""
    from impactiq.agents import instructions as ui
    from impactiq.agents import multi_agent as ma
    from impactiq.agents import specialists as sp

    blobs = {
        "UNIFIED_INSTRUCTIONS": ui.UNIFIED_INSTRUCTIONS,
        "ACK_INSTRUCTIONS": ui.ACK_INSTRUCTIONS,
        "CONTEXT_INSTRUCTIONS": sp.CONTEXT_INSTRUCTIONS,
        "TECHNICAL_INSTRUCTIONS": sp.TECHNICAL_INSTRUCTIONS,
        "KNOWLEDGE_INSTRUCTIONS": sp.KNOWLEDGE_INSTRUCTIONS,
        "ORCHESTRATOR_INSTRUCTIONS": ma.ORCHESTRATOR_INSTRUCTIONS,
        "ADJUDICATOR_INSTRUCTIONS": ma.ADJUDICATOR_INSTRUCTIONS,
    }
    # Tokens from a sample tenant that must never appear baked into prompts.
    # "Enterprise CRM" is a sample solution name — it lives ONLY as the
    # IMPACTIQ_SOLUTION config fallback in settings.py, never in an instruction.
    forbidden = (
        "Jordan", "Blake", "pippop", "Alex", "atomicmail", "BPF3", "Enterprise CRM",
    )
    for name, text in blobs.items():
        for tok in forbidden:
            assert tok not in text, f"{name} hardcodes sample-tenant token {tok!r}"


def test_unified_agent_self_verifies_before_finishing():
    """Instead of bolting on a new rule for each 'it had the tool but didn't use
    it' failure, the front agent runs ONE generic self-verification hop before
    finishing — did it actually DO the work, recover from any empty tool, leave
    nobody out — and the front agent (only) opts in. One-shot (can't loop)."""
    import inspect

    import impactiq.agents.loop as loop
    import impactiq.server as srv

    assert hasattr(loop, "_REFLECTION_PROMPT")
    # The loop gates it: only with reflect, only once, and only for COMPLEX
    # turns (an analysis/action — not a plain lookup).
    drive = inspect.getsource(loop._drive_loop)
    assert "not reflected" in drive and "_REVIEW_WORTHY_TOOLS" in drive
    assert "deep_impact_analysis" in loop._REVIEW_WORTHY_TOOLS
    assert "propose_record_fix" in loop._REVIEW_WORTHY_TOOLS
    assert "resolve_anchor" not in loop._REVIEW_WORTHY_TOOLS  # a lookup → no review
    assert "reflected = True" in drive
    # run_agent_turn + resume both accept it; the UNIFIED endpoint turns it on.
    assert "reflect" in inspect.signature(loop.run_agent_turn).parameters
    assert "reflect" in inspect.signature(loop.resume_agent_turn).parameters
    assert "reflect=True" in inspect.getsource(srv._run_unified_agent)
    # Generic reasoning, not a per-case rule (no sample-tenant tokens).
    for tok in ("Jordan", "Alex", "Admin Task", "complaint"):
        assert tok not in loop._REFLECTION_PROMPT
    # The self-check also probes CONTENT quality, not just that an action ran —
    # a draft must be grounded in specifics, not a generic placeholder.
    assert "grounded in the specific evidence" in loop._REFLECTION_PROMPT
    # The self-check once NARRATED itself into the reply
    # ("Nothing was left half-done / no action was requested"). Two guards:
    # (1) the prompt declares the check PRIVATE and forbids the self-audit;
    assert "PRIVATE self-check" in loop._REFLECTION_PROMPT
    assert "Nothing was left half-done" in loop._REFLECTION_PROMPT  # named as a thing NOT to write
    # (2) deterministically: if the check recovers nothing, the clean PRE-check
    #     answer is kept and the re-composed narration is discarded.
    assert "pre_reflect_text" in drive
    assert "tool_call_count == tool_count_at_reflect" in drive


def test_loop_logs_search_queries():
    """Observability: the bridge log recorded THAT a hosted search ran but never
    the QUERY or whether anything came back — so 'customer email not found' was
    undiagnosable. The loop now echoes the query + result size for the search
    tools."""
    import inspect

    import impactiq.agents.loop as loop

    assert hasattr(loop, "_LOGGED_SEARCH_TOOLS")
    for name in ("SearchMessages", "SearchTeamsMessages", "knowledge_base_retrieve"):
        assert name in loop._LOGGED_SEARCH_TOOLS
    # The hosted-call extractor now carries arguments + output size.
    src = inspect.getsource(loop._hosted_tool_calls)
    assert "arguments" in src and "output" in src
    # And the loop echoes them.
    assert "[search]" in inspect.getsource(loop._drive_loop)


def test_draft_reply_resolves_internal_or_external():
    """One `draft_reply` tool drafts an email to a person — INTERNAL or EXTERNAL —
    so the front agent never hand-rolls the mechanics. Its helper is given the
    mail tool AND the read-only Work IQ directory, and resolves the recipient in
    order: a named internal colleague via the directory (a NEW draft to their
    address), an external person via their own inbound email (a reply). (The
    helper was originally mail-only, which left it unable to email an internal
    colleague who had not written in.)"""
    import inspect

    import impactiq.server as srv
    from impactiq.agents.instructions import UNIFIED_INSTRUCTIONS

    src = inspect.getsource(srv._unified_tools)
    assert 'name="draft_reply"' in src                    # the tool is registered
    assert 'build_workiq_tool("mail", settings)' in src   # helper gets mail
    assert 'build_workiq_tool("user", settings)' in src   # ...and the directory
    assert "tools=draft_tools" in src                     # both attached to the helper
    # The front agent is told to route email/replies through it, not hand-roll.
    assert "draft_reply" in UNIFIED_INSTRUCTIONS


def test_affected_people_surfaced_deterministically():
    """The context check FOUND the customer (affected_people populated) but a
    downstream LLM step (adjudicator or synthesis) DROPPED them — the reply
    missed the customer entirely. Fix is deterministic on BOTH sides: ask_multi
    carries the context finding's affected_people into the report by code, and
    the /agent endpoint surfaces them in the reply by code."""
    import inspect

    import impactiq.agents.multi_agent as ma
    from impactiq.server import _affected_people_footer, _run_unified_agent

    # 1. ask_multi merges the context finding's affected_people into the report.
    src = inspect.getsource(ma.ask_multi)
    assert 'report_dict["affected_people"]' in src
    assert 'r.get("agent") == "context"' in src

    # 2. The footer surfaces them; empty when there are none.
    class _Report:
        affected_people = ["Jordan Blake (customer)", "Alex Park (owner)"]

    out = _affected_people_footer({"report": _Report()})
    assert "People affected" in out
    assert "Jordan Blake (customer)" in out and "Alex Park (owner)" in out
    assert _affected_people_footer({}) == ""

    # 3. The endpoint appends it.
    assert "_affected_people_footer(" in inspect.getsource(_run_unified_agent)


def test_reasoning_is_surfaced_for_audit():
    """Surface the deep pipeline's reasoning into the reply so it's AUDITABLE —
    the adjudicator's reconciliation + evidence, verbatim (not paraphrased away
    by the front agent). Empty when no deep report ran; the /agent endpoint
    appends it."""
    import inspect

    from impactiq.server import _reasoning_footer, _run_unified_agent

    class _Ev:
        def __init__(self, detail):
            self.detail, self.kind = detail, "note"

    class _Report:
        reconciliation = "Checked dependencies, governance, and workplace; all agree the flow is off."
        evidence = [_Ev("No failed runs in 72h"), _Ev("Flow state is off")]

    out = _reasoning_footer({"report": _Report()})
    assert "**Reasoning**" in out
    assert "all agree the flow is off" in out  # verbatim, not paraphrased
    assert "What I checked" in out and "No failed runs in 72h" in out
    # No deep report -> no footer (no dangling 'Reasoning' header).
    assert _reasoning_footer({}) == ""
    # The endpoint actually appends it.
    assert "_reasoning_footer(" in inspect.getsource(_run_unified_agent)


def test_sources_footer_restores_clickable_citations():
    """KB/SOP citations moved onto the deep report (the knowledge specialist's
    runtime citations) and vanished from the reply text. _sources_footer
    re-attaches them as a numbered, CLICKABLE list — pulling from BOTH the
    unified turn's own citations and the deep report's."""
    from impactiq.server import _sources_footer

    class _Turn:
        citations = [{"url": "https://teams/x", "title": "Teams note"}]

    class _Cite:
        def __init__(self, url, title):
            self.url, self.title = url, title

    class _Report:
        citations = [_Cite("https://sp/guide", "Process Guide BPF3.5")]

    out = _sources_footer(_Turn(), {"report": _Report()})
    assert "**Sources**" in out
    # Clickable numbered references — the number links to the source.
    assert "[1](https://teams/x)" in out
    assert "[2](https://sp/guide)" in out
    assert "Process Guide BPF3.5" in out
    # No citations anywhere → no footer (never a dangling 'Sources' header).
    class _Empty:
        citations = []

    assert _sources_footer(_Empty(), {}) == ""


def test_surface_fetch_timeout_clears_specialist_budget():
    """The surface fetch timeout must sit ABOVE the bridge's worst case so a
    completing turn is never aborted mid-flight (240s was exactly the boundary
    that got hit live)."""
    import re

    cfg = (Path(__file__).resolve().parents[1] / "surface" / "src" / "config.ts").read_text(
        encoding="utf-8"
    )
    m = re.search(r"IMPACTIQ_BRIDGE_TIMEOUT_MS \|\| (\d+)", cfg)
    assert m, "bridgeTimeoutMs default not found in config.ts"
    assert int(m.group(1)) >= 300000


def test_context_specialist_has_live_workplace_search():
    """Asymmetry fix: the deep pipeline's context specialist must search Teams
    AND mail LIVE, not only the lagging semantic index — capability lives with
    the agent, not borrowed via an evidence handoff."""
    import inspect

    from impactiq.agents.specialists import CONTEXT_INSTRUCTIONS
    import impactiq.agents.multi_agent as ma

    # Named in the prompt (a tool the model isn't told about isn't called).
    for name in ("SearchTeamsMessages", "SearchMessages", "work_iq_preview"):
        assert name in CONTEXT_INSTRUCTIONS, f"context specialist lost {name}"
    # Actually wired into the context specialist's toolset.
    src = inspect.getsource(ma.ask_multi)
    assert 'teams_tool' in src and 'mail_tool' in src
    assert "read_only=True" in src  # reads only — no sends from a specialist


# ── surface plumbing pins (cross-language: assert on the TS source) ──────────


def _surface_src() -> str:
    return SURFACE.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "needle, incident",
    [
        # Copilot suffixes conversation ids (;messageid=…): state/dedup split.
        ('split(";")', "conversation-id fragmentation"),
        # messageBack drops its value payload in Copilot → plain Action.Submit.
        ("apply_sandbox_fix", "Apply tap reached the model as text"),
        ("apply_resubmit_run", "resubmit tap plumbing"),
        # Long runs need a heartbeat so the user isn't staring at silence.
        ("Still working on it", "silent two-minute waits"),
        # Duplicate-question window (Teams redelivery / Copilot retries).
        ("duplicateQuestion", "double answers"),
        # Next-step options as an Action.Submit card (Teams can't list multiple
        # suggestedActions under a reply once the turn has attachments).
        ("nextStepsCard", "clickable next-step options"),
        ("suggested_step", "tapped next-step chains like a typed message"),
        ("sendChipsAfter", "next-step options continue after a card action"),
        # A proposed Apply/Resubmit stays offered across turns until tapped,
        # so exploring other options never strands the prepared action.
        ("pendingActions", "Apply action lost after exploring other options"),
        ("primaryCardAction", "persistent Apply re-offer from the proposal card"),
        # Options SUPPRESSED only for a BARE proposal card (its buttons ARE the
        # next step); a deep impact report still gets options alongside its offer.
        ("suppressChips", "option/proposal-card duplication"),
        # Live progress: poll the bridge mid-turn and post each milestone so a
        # long turn isn't a silent wait; the generic heartbeat is fallback-only.
        ("drainProgress", "long turn left the user in limbo with no updates"),
        ("progressSeen", "generic heartbeat fired alongside the live play-by-play"),
    ],
)
def test_surface_carries_fix(needle: str, incident: str):
    assert needle in _surface_src(), (
        f"surface/src/agent.ts lost the {incident!r} fix (missing {needle!r})"
    )


def test_no_static_welcome_message():
    """The static greeting was removed — the first real reply (with its
    next-step chips) does the onboarding."""
    src = _surface_src()
    assert "I'm **ImpactIQ**" not in src
    assert "draft-only until you explicitly confirm" not in src
    # The useful prewarm on join stays.
    assert "/warmup" in src


def test_suggestions_suppressed_after_a_completed_action():
    """Next-step chips belong after an ANALYSIS the user builds on — NOT after
    every action. After a completed action (a draft saved, a message sent, a fix
    applied) the suggester returns [] rather than tacking on unrelated chips."""
    from impactiq.server import SUGGEST_INSTRUCTIONS

    flat = _flat(SUGGEST_INSTRUCTIONS)
    assert "CONFIRMING a completed action" in flat
    assert "return []" in flat


def test_suggestions_drop_communication_chips():
    """Suggestion chips kept mis-framing outreach — 'Draft an email EXPLAINING
    the issue to <customer>', then 'Draft a Teams update to <customer>' (Teams to
    an external party). The model wouldn't follow channel/register rules, so
    message/draft chips are dropped: the INSTRUCTION asks for none, and a
    DETERMINISTIC filter (_is_comms_chip) enforces it. Outreach happens inline
    via the agent's confirm-and-channel-gated draft paths instead."""
    from impactiq.server import SUGGEST_INSTRUCTIONS, _is_comms_chip

    flat = _flat(SUGGEST_INSTRUCTIONS)
    assert "NO MESSAGE / DRAFT CHIPS" in flat

    # the deterministic filter catches the misfiring chips...
    assert _is_comms_chip({"title": "Draft a Teams update to Jordan",
                           "query": "Draft a Teams update to Jordan about the issue"})
    assert _is_comms_chip({"title": "Email the customer",
                           "query": "Draft an email reply to Jordan"})
    assert _is_comms_chip({"title": "Notify the owner",
                           "query": "Notify Alex about the change"})
    # ...but keeps legitimate analysis / lookup chips, incl. 'affected teams'
    assert not _is_comms_chip({"title": "Run impact report",
                               "query": "Run a full impact analysis on this flow"})
    assert not _is_comms_chip({"title": "Show affected teams",
                               "query": "Show the teams affected by this change"})
    assert not _is_comms_chip({"title": "Find the owner",
                               "query": "Who owns the Admin Task table?"})


def test_suggest_endpoint_shapes_chips():
    """The bridge produces title/query chip objects; malformed model output
    degrades to [] rather than breaking the turn."""
    from impactiq.server import _suggest_next_steps

    # No model configured in tests → best-effort empty, never raises.
    out = _suggest_next_steps(_StubSettings(), [], "some reply")
    assert out == []


def test_needs_deep_analysis_degrades_safely():
    """The deep-analysis router is best-effort: no model → False, never
    raises (the instruction's mandatory triggers still apply)."""
    from impactiq.server import _needs_deep_analysis

    assert _needs_deep_analysis(_StubSettings(), "is it safe to rename X?", []) is False


def test_router_treats_remediation_followups_as_direct():
    """'Manually create an admin task for the impacted records' (after a
    diagnosis already ran) re-ran the ENTIRE deep pipeline. The router's
    action-follow-through list must include REMEDIATION of an already-diagnosed
    problem, not just 'apply the fix' phrasings."""
    from impactiq.server import NEEDS_DEEP_INSTRUCTIONS

    flat = _flat(NEEDS_DEEP_INSTRUCTIONS)
    assert "REMEDIATING an already-diagnosed problem" in flat
    assert "create the missing record" in flat


def test_builder_access_note_empty_without_sandbox():
    """No sandbox configured → the Builder tools aren't attached, so there is
    no access note (and no role check is attempted)."""
    from impactiq.server import _builder_access_note

    class _NoSandbox:
        build_dataverse_url = None

    assert _builder_access_note(_NoSandbox()) == ""


class _StubSettings:
    foundry_specialist_deployment = ""
    foundry_model_deployment = ""


def test_surface_describes_live_mail_tool_names():
    """describeAction↔registry coupling: the TS preview labels must track the
    Python registry's live wire names."""
    src = _surface_src()
    for name in ("CreateDraftMessage", "ReplyToMessage"):
        assert name in src, f"describeAction lost the {name} mapping"


def test_mcp_write_is_verified_not_trusted_on_word():
    """The Dataverse-MCP write declared success on `run_status == 'completed'`
    while the prompt asked the model to 'reply done' — so a model that never
    called update_record produced a logged remediation_executed and a false
    'Fix applied'. The MCP path now confirms the write by reading the record
    back; unverifiable => the verified PATCH fallback runs instead of a
    write-on-the-model's-word."""
    import inspect

    import impactiq.server as server

    assert hasattr(server, "_verify_record_write")
    mcp = inspect.getsource(server._write_via_dataverse_mcp)
    assert 'turn.run_status == "completed"' not in mcp  # no success-on-word
    assert "_verify_record_write" in mcp
    verify = inspect.getsource(server._verify_record_write)
    assert "httpx.get" in verify and "mismatched" in verify  # real read-back compare


def test_pending_caches_evict_oldest_not_newest():
    """_PENDING_RUNS eviction used dict.popitem() (LIFO), dropping the
    most-recently-suspended run while the comment promised 'oldest-first' — a
    recent run could be evicted and its approval lost. All three pending caches
    now evict FIFO (oldest) via next(iter(...))."""
    import inspect

    import impactiq.server as server

    for fn in (
        server._stash_pending_run,
        server._stash_pending_fix,
        server._stash_pending_resubmit,
    ):
        src = inspect.getsource(fn)
        assert ".popitem()" not in src, f"{fn.__name__} still LIFO-evicts (popitem)"
        assert "next(iter(" in src, f"{fn.__name__} should FIFO-evict the oldest"


def test_permission_fetch_failure_is_not_a_false_denial():
    """A swallowed exception in _fetch_role_privileges turned a failed
    role-privilege fetch into [] privileges -> a false 'permission denied'. It
    now omits the failed role + records it, and diagnose_permission raises
    PrivilegeFetchError rather than asserting a denial on incomplete data. FLS is
    also documented as NOT auto-detected on the live path (the dead-branch
    over-claim is named, not silently implied)."""
    import inspect

    import impactiq.graph.permissions as perms

    assert hasattr(perms, "PrivilegeFetchError")
    fetch = inspect.getsource(perms._fetch_role_privileges)
    assert "failed" in fetch and "continue" in fetch  # failed roles omitted, not []
    diag = inspect.getsource(perms.diagnose_permission)
    assert "PrivilegeFetchError" in diag and "failed_priv_fetches" in diag
    assert "limitation" in (perms.__doc__ or "").lower()  # FLS honesty in docstring
