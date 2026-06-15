"""Multi-agent pipeline: orchestrator → 3 parallel specialists → adjudicator.

Hybrid architecture: **Microsoft Agent Framework** provides the workflow graph
— genuine fan-out/fan-in edges with parallel execution — while every node
internally runs the hardened prompt-agent loop (agents/loop.py), so the KB MCP
tool, the Work IQ A2A tool + consent gate, and the 5xx/429 retry behaviour are
inherited unchanged.

Graph:

    dispatch ──fan-out──> technical ─┐
             ├──────────> knowledge ─┼──fan-in──> adjudicate ──> ImpactReport
             └──────────> context   ─┘

Identity: ``as_user=True`` runs all Foundry calls as the signed-in user
(required for Work IQ); otherwise the service principal runs
technical+knowledge and the context specialist reports ``skipped``.
The Dataverse estate pre-warm always stays on the read-only service
identity — two identities by scope.
"""

# NOTE: no `from __future__ import annotations` here — the MAF executor
# decorator validates signatures at definition time and cannot resolve
# postponed (string) annotations for closure-scoped types like
# WorkflowContext[dict].

import asyncio
import json
import os
from typing import Any

from ..connectors import EstateScope  # noqa: F401 — re-exported for callers/tests
from ..dataverse_client import DataverseClient
from ..graph import build_graph
from ..settings import Settings
from .contracts import OrchestratorPlan, SpecialistResult
from .loop import extract_json_block, run_agent_turn
from .runtime import make_project_client
from .single_agent import AskResult, _build_mcp_kb_tool, _build_workiq_tool
from .workiq import build_workiq_tool as _build_registry_workiq_tool
from .specialists import (
    CONTEXT_INSTRUCTIONS,
    KNOWLEDGE_INSTRUCTIONS,
    TECHNICAL_INSTRUCTIONS,
    run_specialist,
    specialist_task_input,
)
from .tools import (
    ADJUDICATOR_TOOL_NAMES,
    ORCHESTRATOR_TOOL_NAMES,
    TECHNICAL_TOOL_NAMES,
    ToolContext,
    build_engine_tool_specs,
    select_engine_tools,
)

ORCHESTRATOR_INSTRUCTIONS = """\
You are ImpactIQ's ORCHESTRATOR. You do not analyse anything yourself - you
classify, resolve the anchor, and dispatch specialists.

1. Classify intent: DIAGNOSE (a symptom/problem) or VALIDATE (a proposed
   change / new feature).
2. Resolve the anchor: if the user pasted a Power Apps / Dynamics URL, call
   `resolve_url` to get the exact entity. Otherwise call `resolve_anchor`
   with a SHORT identifier from the question. If nothing resolves
   confidently, set anchor = null and say so in notes (the specialists will
   still try; the adjudicator may ask the user to confirm the object).
3. Decide specialists (default all three):
   * technical - always.
   * knowledge - skip ONLY if the question cannot possibly be governed by
     policy/SOP (rare).
   * context - skip for pure-architecture questions with no human/process
     dimension.

Final output: EXACTLY one JSON object in a ```json fence:
{
  "intent": "DIAGNOSE",
  "anchor": {"id": "...", "kind": "...", "name": "..."},
  "specialists": ["technical", "knowledge", "context"],
  "notes": "<one line>"
}
"""

ADJUDICATOR_INSTRUCTIONS = """\
You are ImpactIQ's ADJUDICATOR. You receive an orchestrator plan and the
Findings of up to three specialists (technical / knowledge / context). You
reconcile them into ONE ImpactReport. You have no estate or IQ tools - only
`validate_artifact`.

# Object resolution — ask, don't hedge (do this FIRST)

If the Technical finding shows the anchor or a key object the user named
could not be confidently identified (it didn't resolve, or its
`likely_cause` flags that it needs confirmation), DO NOT produce a hedged
verdict. Instead make the verdict a brief, friendly CLARIFYING QUESTION:
ask the user to confirm the object - its UI/display name as they see it on
screen, or to paste the Power Apps URL of the record/table/field (the URL
encodes the exact entity). Set confidence low, `generated_artifact: null`,
and put the ask in `recommendation`. A precise answer next turn beats a
vague one now.

If an automation clearly DOES exist (inspect_flow showed a matching flow),
confirm it confidently: name the flow, state whether it's on, and what it
creates/updates - e.g. "Yes - the flow 'X' is on and creates a <record> when
a <trigger event> occurs." Then note any concern (off? no failed
runs? recently changed?) and ask if they want to dig into a specific part.

# Adjudication rules (§5.7 - these ARE the reasoning showcase)

* **Change control DOMINATES (VALIDATE/any change)**: if Context returns a
  non-empty `change_control` — ANY active directive that gates changes right
  now: a freeze/moratorium, an approval/sign-off gate, a change board (CAB), a
  release embargo/blackout, an incident "no deploys" window — it OVERRIDES the
  technical risk score and the verdict must lead with it (never a bare "safe to
  proceed"). But HONOUR THE DIRECTIVE'S OWN KIND — do not flatten everything to
  "hold":
  * a HARD STOP (freeze / moratorium / embargo / blackout / active incident):
    do NOT proceed — recommend holding and waiting for it to lift ("Hold this
    change — there is an active change freeze per <who>; wait for it to lift").
  * a GATE you pass THROUGH (approval / sign-off / CAB / "run it past <owner>"):
    do NOT refuse — recommend going through it ("Get <who>'s sign-off / route
    through the change board before applying"). Proposing the change while
    flagging the required approval is the RIGHT move, not a refusal.
  Use the directive's ACTUAL words (don't call an approval gate a "freeze"),
  state it in `reconciliation`, and keep risk at least medium. A green verdict
  that IGNORES an active directive is a WRONG answer.
* **Defect vs expected**: if Technical suggests a defect AND Knowledge says
  "expected_per_policy", FLIP the verdict to expected-per-policy, cite the
  policy, and target the recommendation at the policy-aware path (not the
  apparent bug). Explain the flip in `reconciliation`.
* **Existing equivalents (VALIDATE)**: verdict = reuse/extend, not build.
* **Change collisions (VALIDATE)**: intersect the blast radius with
  Technical's recent_editors and Context's active_change_signals. Each
  overlap -> a change_collision entry + raised risk + "coordinate with X on
  Y before proceeding". A component merely HAVING an owner is NOT a
  collision - emit one ONLY when a recent_editor or active_change_signal
  actually overlaps the radius; otherwise change_collisions stays empty.
  Vague "solution-level" / "environment-level" activity with no specific
  component AND no named owner is NOT a collision - drop it rather than
  emitting a contradictory "restricted activity, owner not identified" line.
  For sensitivity != "open", the advice must stay content-free; use this
  phrasing with the owner named inline: "There is restricted activity in
  this area - coordinate with <owner> before proceeding." Never name
  restricted artifacts or substance. This template is for the collision's
  `advice` field ONLY - the `recommendation` stays a normal actionable
  sentence in your own words.
* **Owner/team names are facts, not decorations**: `affected_teams` and
  collision `who` may ONLY contain names that came from `resolve_owner`
  (structural ownership) or a disclosable Work IQ signal. If no real owner
  was resolved, leave `affected_teams` EMPTY and `who` null - an unknown
  owner is honest; a guessed one is a leak.
  **The solution name is NOT a team.** The solution that scopes this analysis
  is the container under inspection - never put it, or any component/table
  name, in `affected_teams`. Teams come from owning team/user/business-unit
  data only.
* **Affected people (the human fallout)**: carry the Context specialist's
  `affected_people` into the report's `affected_people` VERBATIM — ALL of them,
  not just the first. These are people awaiting or impacted by the outcome the
  failure swallowed, and they are ANYONE (a customer, a colleague, an internal
  user); keep whatever role tag Context gave, e.g. "(customer)"/"(owner)". This
  is separate from `affected_teams` (structural coordination). For EACH distinct
  party, add its OWN follow-up to `interim_actions`, matched to the role — e.g.
  "coordinate with <owner> before changing" for an owner/approver, "reply to
  <person> about <the outcome they're waiting on>" for an impacted party — so
  the user can act on each. If Context surfaced no one, leave it empty (never
  invent).
* **Low risk is not "no coordination"**: if the blast radius includes
  components owned or routinely updated by someone else (from
  `resolve_owner` or Technical's recent_editors), the `recommendation`
  must name the verification step with that person/team — "verify with
  <owner>, who maintains <component>" — even when the risk score is low.
  A minor downstream impact with an identifiable maintainer is exactly the
  case where one short conversation prevents a surprise.
* **Confidence weighting**: findings agree -> raise confidence; conflict ->
  lower it and surface BOTH views in `evidence`.
* **Citations**: carry the Knowledge specialist's citations into
  `citations[]` (and only claims with citations may rely on policy).
* Specialist errors/skips: note them honestly in `evidence` (kind "note");
  never invent what a missing specialist would have said.

# Artifact — only REAL, executable actions (honesty rule)

`generated_artifact` is for actions ImpactIQ can ACTUALLY perform through a
real channel, each behind its safety gate. There are exactly three:
* **manager_handoff** - notify the owning team's manager. Real channel:
  message send (draft -> the user confirms -> sent). MANDATORY for a
  cross-team VALIDATE: impact-assertion-only draft + context baton; NEVER
  inferred reasons about the other team's work.
* **remediation_proposal** - apply a single-record DATA fix the user could
  make in the UI. Real channel: Dataverse write under the user's identity.
  Only on DIAGNOSE, confidence >= 0.8, never configuration tables,
  document-grounded ONLY if the user explicitly referenced a document this
  turn. Two operations: `operation:"update"` corrects fields on ONE existing
  record (record_id required); `operation:"create"` replays the ONE row a
  failed automation never wrote — record_id EMPTY (the platform mints it),
  diagnosis-grounded only, every column's value taken from the failed
  action's own parameters/trigger evidence (never invented), always
  typed-confirmed. One missing row per proposal; many -> backfill_blueprint.
* **backfill_blueprint** - the same data fix across many records. Routed to
  the data owner via handoff (never executed directly).

Do NOT emit any artifact for things ImpactIQ has no channel to do. We do
NOT file tickets in any external system, so do not produce a dev_ticket as
if it were an action. If the only "next step" is paperwork (a ticket, a
spec, an FRD), leave `generated_artifact: null` - the user can ASK me to
draft that text and I will (it's a document, not an action). Likewise set
null for informational answers, "no issue found", "safe to proceed", and
casual questions. NEVER manufacture an artifact whose content amounts to
"no action needed".

When you DO emit one, FULLY POPULATE it from the specialist findings (a
complete, ready-to-send `draft_text`; every field you have evidence for),
then run it through `validate_artifact` BEFORE the final answer. If it
refuses: `use_instead` set -> redraft as that type; otherwise FIX the listed
fields and call it again - a refusal means repair, never a silent skip.
Embed the RETURNED artifact verbatim as `generated_artifact`.

# Writing style (user-facing text - NOT optional)

The verdict, reconciliation, recommendation, collision advice and evidence
details are read by BUSINESS USERS in a Teams card. Write them in plain
English:
* No internal jargon: never say "anchor", "blast radius", "causal/structural
  neighbours", "specialist", "adjudicator", "DIAGNOSE/VALIDATE", "Work IQ",
  "KB". Say what was checked instead: "the dependency scan", "your
  governance documents", "recent activity in your workspace".
* Verdict: one short sentence a manager understands at a glance.
* Reconciliation: 2-3 plain sentences - what we checked, what agreed or
  conflicted, what that means. Concrete numbers beat abstractions ("3
  flows depend on this field", not "the radius contains 3 causal nodes").
* Recommendation: lead with the action ("Talk to X before building",
  "Safe to proceed - nothing else uses this field").
* Evidence details: one understandable fact each, no tool names.

# Final output

EXACTLY one JSON object in a ```json fence:

```json
{
  "intent": "DIAGNOSE",
  "anchor": {"id": "...", "kind": "...", "name": "..."},
  "verdict": "<one-sentence>",
  "confidence": 0.0,
  "reconciliation": "<how you weighed/reconciled the findings>",
  "evidence": [{"kind": "tool|note|citation|workiq", "detail": "..."}],
  "impacted_components": [{"id": "...", "kind": "...", "name": "..."}],
  "affected_teams": [],
  "affected_people": ["<anyone awaiting the swallowed outcome, role-tagged when known e.g. '(customer)'/'(colleague)'; [] if none>"],
  "risk": {"score": 0, "level": "low", "reasons": ["..."]},
  "recommendation": "<what the user should do>",
  "interim_actions": [],
  "existing_equivalents": [],
  "change_collisions": [{"component": {"id":"...","kind":"...","name":"..."}, "who": "...", "sensitivity": "open|restricted|unknown", "advice": "..."}],
  "citations": [{"source_id": "...", "title": "...", "url": "..."}],
  "generated_artifact": {"artifact_type": "<manager_handoff | remediation_proposal | backfill_blueprint>", "...": "as returned by validate_artifact"}
}
```
"""


def _adjudicator_input(
    plan: dict, question: str, solution_name: str, results: list[dict]
) -> str:
    parts = [
        f"Scope: solution '{solution_name}'.",
        f"Orchestrator plan: {json.dumps(plan)}",
        f"User question:\n{question}",
        "",
        "# Specialist findings",
    ]
    for r in results:
        header = (
            f"## {r.get('agent', '?').upper()} - status={r.get('status')}"
            f" ({r.get('elapsed_seconds', 0):.1f}s,"
            f" {r.get('tool_call_count', 0)} tool calls)"
        )
        parts.append(header)
        if r.get("error"):
            parts.append(f"(note: {r['error']})")
        parts.append(json.dumps(r.get("finding") or {}, indent=2))
        if r.get("citations"):
            parts.append(f"Runtime citations: {json.dumps(r['citations'])}")
        parts.append("")
    return "\n".join(parts)


# Per-specialist wall-clock budget. The specialists fan out in parallel, so a
# single slow one (e.g. a cold Foundry IQ KB retrieval can take ~140s) gates the
# whole turn — and once the turn crosses the surface's fetch timeout the client
# aborts and the finished report is thrown away ("operation aborted").
# A specialist that overruns its budget returns a `skipped` finding so the fan-in
# never deadlocks and the adjudicator still produces a verdict; the abandoned
# thread's hosted call completes in the background and is discarded. This catches
# pathology, not normal latency. Override with IMPACTIQ_SPECIALIST_BUDGET_S.
_SPECIALIST_BUDGET_S = float(os.environ.get("IMPACTIQ_SPECIALIST_BUDGET_S", "120"))

# The CONTEXT specialist runs the slow LIVE workplace searches, and its NEVER-FAIL
# floor mandates BOTH (Teams AND mail). On a degraded Work IQ / Copilot backend a
# single live search can take ~100s, so the two mandatory searches alone run
# ~200s — past the default cap, which would DROP the context finding (incl. a
# customer email it had just retrieved) milliseconds before it completed.
# Give context its own budget, sized to (floor of two searches) x (a slow
# backend), so the cap stays a safety net against a true hang — not a guillotine
# on a specialist that is about to succeed. Still well under the 600s surface
# fetch timeout. Override with IMPACTIQ_CONTEXT_BUDGET_S.
_CONTEXT_BUDGET_S = float(os.environ.get("IMPACTIQ_CONTEXT_BUDGET_S", "300"))


def _budget_for(label: str) -> float:
    """Context gets the larger budget (it owns the slow two-search live floor);
    the deterministic/KB specialists keep the tighter default."""
    return _CONTEXT_BUDGET_S if label == "context" else _SPECIALIST_BUDGET_S


async def _run_with_budget(label: str, fn: Any, plan: dict) -> dict:
    """Run one specialist in a worker thread under a wall-clock budget.

    On overrun, return a `skipped` SpecialistResult (NOT an empty finding — the
    adjudicator must not read a timed-out check as 'nothing found', which would
    wrongly assert e.g. 'no governance context exists')."""
    budget = _budget_for(label)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(fn, plan), timeout=budget
        )
    except asyncio.TimeoutError:
        print(
            f"[{label}] exceeded {budget:.0f}s budget — proceeding without it",
            flush=True,
        )
        return SpecialistResult(
            agent=label,  # type: ignore[arg-type]
            status="skipped",
            error=(
                f"exceeded the {budget:.0f}s budget — the turn "
                f"proceeded without this specialist (NOT a 'nothing found' result)"
            ),
            elapsed_seconds=budget,
        ).model_dump()


# Generic, tenant-agnostic "I'm still waiting / chasing an outcome" follow-up
# phrasings. The deterministic awaiting-party floor sweeps these so a waiting
# person can't be missed because the model's keyword happened to be anchor-biased.
# A MENU, not a fixed set — the probe picks the few most likely (it caps queries);
# kept broad so a chaser who used different words ("haven't heard", "following
# up") is still caught.
_AWAITING_PROBE_TERMS = (
    "not received", "any update", "still waiting", "haven't heard",
    "following up", "chasing", "any news", "no response", "when will",
)


def _probe_awaiting_parties(
    project_client: Any, settings: Settings, tools: list, issue_hint: str
) -> list[str]:
    """Deterministic awaiting-party floor: ALWAYS sweep for anyone following up
    because an expected outcome never arrived, in GENERIC universal language,
    regardless of the keyword the context specialist chose. A minimal
    SINGLE-PURPOSE turn — reliable where the overloaded context specialist is
    not. Returns presence-level 'Name (role)' lines; never raises; returns []
    when there are no live search tools."""
    if not tools:
        return []
    terms = ", ".join(f"'{t}'" for t in _AWAITING_PROBE_TERMS)
    instr = (
        "You sweep the user's Teams and Outlook for ANYONE following up because "
        "something they expected never arrived. Issue SHORT keyword searches on "
        "BOTH SearchTeamsMessages AND SearchMessages using these universal "
        f"phrasings ({terms}) — short queries, never long sentences. Issue AT "
        "MOST 3 queries total (pick the most likely). Include ONLY people whose "
        f"follow-up plausibly relates to the issue under investigation: "
        f"{issue_hint!r}. For each DISTINCT person, output ONE line 'Name (role)' "
        "— role = customer / colleague / internal if you can tell, else just the "
        "name. Presence only — who reached out and that they're waiting, NEVER "
        "the private content. Output ONLY the lines, or the single word NONE."
    )
    try:
        turn = run_agent_turn(
            project_client,
            agent_name="ImpactIQ-awaiting-probe",
            model=settings.heavy_model_deployment or "",
            instructions=instr,
            tools=tools,
            dispatch={},
            user_input=(
                "Who is following up because an expected outcome didn't arrive? "
                "Search the universal phrasings and list them."
            ),
        )
    except Exception:  # noqa: BLE001 — probe is best-effort, never fatal
        return []
    out: list[str] = []
    for line in (turn.raw_text or "").splitlines():
        line = line.strip("-*•   \t")
        if line and line.upper() != "NONE" and len(line) <= 120:
            out.append(line)
    return out


_PLAN_SPECIALISTS = {"technical", "knowledge", "context"}


def _salvage_plan(raw: Any) -> OrchestratorPlan:
    """Best-effort, field-by-field salvage when strict ``OrchestratorPlan``
    validation fails.

    The previous behaviour — ``except: OrchestratorPlan()`` — discarded the
    WHOLE plan on any single bad field, silently flipping intent back to
    DIAGNOSE and DROPPING a resolved anchor (a landmine: a lowercase
    ``"validate"`` or an anchor missing one of id/kind/name would quietly
    change the KIND of analysis). This preserves every field that can be read,
    coercing the common drifts, and only falls back to a per-field default for
    the one field that genuinely can't be salvaged. It never raises and never
    flips intent or drops a usable anchor on someone else's parse error.
    """
    if not isinstance(raw, dict):
        return OrchestratorPlan()
    salvaged: dict = {}

    # intent: accept case-insensitively; only the two valid literals. If we
    # can't read a valid one we OMIT it (field default DIAGNOSE) rather than
    # asserting DIAGNOSE over a value we simply failed to normalise.
    intent = str(raw.get("intent", "")).strip().upper()
    if intent in ("DIAGNOSE", "VALIDATE"):
        salvaged["intent"] = intent

    # anchor: keep it if it can be coerced to a NodeRef — NEVER drop a usable
    # anchor because the model omitted kind/name or passed a bare string.
    anchor = raw.get("anchor")
    if isinstance(anchor, dict):
        aid = anchor.get("id") or anchor.get("name")
        if aid:
            salvaged["anchor"] = {
                "id": str(aid),
                "kind": str(anchor.get("kind") or "Reference"),
                "name": str(anchor.get("name") or aid),
            }
    elif isinstance(anchor, str) and anchor.strip():
        salvaged["anchor"] = {"id": anchor, "kind": "Reference", "name": anchor}

    # specialists: keep the valid ones (case-insensitively); fall back to all
    # three only if NONE survive.
    specs = raw.get("specialists")
    if isinstance(specs, list):
        kept = [
            s.lower() for s in specs
            if isinstance(s, str) and s.lower() in _PLAN_SPECIALISTS
        ]
        if kept:
            salvaged["specialists"] = kept

    notes = raw.get("notes")
    if isinstance(notes, str):
        salvaged["notes"] = notes

    try:
        return OrchestratorPlan.model_validate(salvaged)
    except Exception:  # noqa: BLE001 — last resort, never crash the turn
        return OrchestratorPlan(intent=salvaged.get("intent", "DIAGNOSE"))


def _people_keys(rep: dict) -> set:
    """Normalised awaiting-party identities (role tag stripped), for the
    'a repair must not drop a waiting person' guard."""
    return {
        str(p).split("(")[0].strip().lower()
        for p in (rep.get("affected_people") or [])
    }


def _critic_repair(
    project_client: Any,
    settings: Settings,
    specs: Any,
    plan_dict: dict,
    question: str,
    solution_name: str,
    results: list[dict],
    report_dict: dict,
    gate_findings: list,
    citations: list,
    defects: list[str],
    gate_report: Any,
) -> dict | None:
    """ONE bounded adjudicator repair turn driven by the verifier's defect list.

    Returns the repaired report ONLY if it is strictly safe to swap in: it
    parses, it does NOT increase the verdict-gate finding count, and it drops no
    awaiting party that was in the original. Otherwise None (keep the original)
    — so a repair can only help or no-op, never silently degrade a good report.
    """
    note = (
        "A verifier reviewing your draft flagged these issues:\n"
        + "\n".join(f"- {d}" for d in defects)
        + "\n\nRe-emit the CORRECTED ImpactReport JSON (same schema). Fix ONLY "
        "these issues; keep everything that was already right (including every "
        "affected person). If a generated_artifact is present, re-run "
        "validate_artifact before embedding it."
    )
    adj_tools, adj_dispatch = select_engine_tools(specs, ADJUDICATOR_TOOL_NAMES)
    try:
        turn = run_agent_turn(
            project_client,
            agent_name="ImpactIQ-adjudicator-repair",
            model=settings.heavy_model_deployment or "",
            instructions=ADJUDICATOR_INSTRUCTIONS,
            tools=adj_tools,
            dispatch=adj_dispatch,
            user_input=(
                _adjudicator_input(plan_dict, question, solution_name, results)
                + "\n\n"
                + note
            ),
        )
    except Exception as exc:  # noqa: BLE001 — repair is best-effort, never fatal
        print(f"(critic: repair turn failed: {type(exc).__name__}: {exc})", flush=True)
        return None
    rep = extract_json_block(turn.raw_text)
    if not isinstance(rep, dict):
        return None
    rep, rep_findings = gate_report(
        plan_dict, results, rep,
        runtime_citations=citations, solution_name=solution_name,
    )
    if len(rep_findings) <= len(gate_findings) and _people_keys(report_dict) <= _people_keys(rep):
        return rep
    print(
        f"[critic] repair rejected (gate {len(rep_findings)} vs {len(gate_findings)}, "
        f"people preserved={_people_keys(report_dict) <= _people_keys(rep)})",
        flush=True,
    )
    return None


def build_workflow(
    run_technical: Any,
    run_knowledge: Any,
    run_context: Any,
    adjudicate: Any,
):
    """Assemble the MAF fan-out/fan-in graph from four SYNC callables.

    Factored out so tests can inject stubs and verify the wiring without a
    Foundry round-trip. Each callable: ``(plan: dict) -> dict`` for the
    specialists, ``(results: list[dict]) -> dict`` for the adjudicator.
    """
    from agent_framework import WorkflowBuilder, WorkflowContext, executor

    @executor(id="dispatch")
    async def dispatch(plan: dict, ctx: WorkflowContext[dict]) -> None:
        await ctx.send_message(plan)

    @executor(id="technical")
    async def technical(plan: dict, ctx: WorkflowContext[dict]) -> None:
        await ctx.send_message(await _run_with_budget("technical", run_technical, plan))

    @executor(id="knowledge")
    async def knowledge(plan: dict, ctx: WorkflowContext[dict]) -> None:
        await ctx.send_message(await _run_with_budget("knowledge", run_knowledge, plan))

    @executor(id="context")
    async def context(plan: dict, ctx: WorkflowContext[dict]) -> None:
        await ctx.send_message(await _run_with_budget("context", run_context, plan))

    @executor(id="adjudicate", workflow_output=dict)
    async def adjudicate_node(results: list[dict], ctx: WorkflowContext) -> None:
        await ctx.yield_output(await asyncio.to_thread(adjudicate, results))

    return (
        WorkflowBuilder(start_executor=dispatch, output_from=[adjudicate_node])
        .add_fan_out_edges(dispatch, [technical, knowledge, context])
        .add_fan_in_edges([technical, knowledge, context], adjudicate_node)
        .build()
    )


def ask_multi(
    settings: Settings,
    *,
    solution_name: str,
    question: str,
    as_user: bool = False,
    progress: Any = None,
    user_assertion: str | None = None,
) -> AskResult:
    """End-to-end multi-agent turn. Same surface as single_agent.ask.

    ``progress``: optional ``Callable[[str], None]`` the bridge passes so the
    deep pipeline's per-specialist milestones surface to the user during the
    long step (it's the turn's long pole). Safe to call from specialist
    threads; None disables it (e.g. CLI runs).

    ``user_assertion``: the Teams user's token for the production On-Behalf-Of
    flow (only meaningful with ``as_user=True``). When omitted, ``as_user``
    falls back to the local browser sign-in (CLI). See runtime.delegated_credential."""
    def _say(line: str) -> None:
        if progress:
            try:
                progress(line)
            except Exception:  # noqa: BLE001 — progress is best-effort, never fatal
                pass

    if not settings.foundry_model_deployment:
        raise RuntimeError("FOUNDRY_MODEL_DEPLOYMENT is not set in .env")

    with DataverseClient(settings) as dv_client:
        from ..estate_cache import get_estate_cached

        scope, fragment = get_estate_cached(dv_client, settings, solution_name)
        graph = build_graph(fragment)
        ctx = ToolContext(client=dv_client, scope=scope, graph=graph)
        specs = build_engine_tool_specs(ctx)

        kb_tool = _build_mcp_kb_tool(settings)
        workiq_tool = _build_workiq_tool(settings) if as_user else None
        # Work IQ User (read-only org hierarchy) joins the Context specialist
        # so it can resolve real managers/owners for routing instead of
        # guessing. Runs OBO (as_user) like all Work IQ MCP tools.
        user_tool = _build_registry_workiq_tool("user", settings) if as_user else None
        # LIVE Teams + mail search (read-only) join the Context specialist so
        # it has the SAME workplace reach as the unified agent — the semantic
        # `work_iq_preview` index lags, and RECENT messages (a customer email,
        # a Teams thread) appear only in the live searches. Capability lives
        # with the agent that needs it, not borrowed via an evidence handoff —
        # this closes the unified-vs-specialist search asymmetry.
        teams_tool = (
            _build_registry_workiq_tool("teams", settings, read_only=True)
            if as_user else None
        )
        mail_tool = (
            _build_registry_workiq_tool("mail", settings, read_only=True)
            if as_user else None
        )

        with make_project_client(
            settings, as_user=as_user, user_assertion=user_assertion
        ) as project_client:
            # ── 1. Orchestrator ────────────────────────────────────────────
            orch_tools, orch_dispatch = select_engine_tools(
                specs, ORCHESTRATOR_TOOL_NAMES
            )
            # Native strict JSON-schema output for the plan when
            # IMPACTIQ_STRUCTURED_OUTPUT is on. The platform then guarantees a
            # schema-conformant plan and we stop scraping it from prose;
            # extract_json_block + _salvage_plan below remain the fallback.
            # parallel_tool_calls MUST be False under a structured-output format
            # (Responses API constraint). Flag off → no kwargs → this call is
            # byte-identical to before.
            from .structured import schema_text_format, structured_output_enabled

            _orch_fmt: dict = {}
            if structured_output_enabled():
                _orch_fmt = {
                    "text_format": schema_text_format(
                        "orchestrator_plan", OrchestratorPlan
                    ),
                    "parallel_tool_calls": False,
                }
            orch_turn = run_agent_turn(
                project_client,
                agent_name="ImpactIQ-orchestrator",
                model=settings.heavy_model_deployment,
                instructions=ORCHESTRATOR_INSTRUCTIONS,
                tools=orch_tools,
                dispatch=orch_dispatch,
                user_input=(
                    f"Scope: solution '{scope.solution_name}'.\n\n"
                    f"Question:\n{question}"
                ),
                **_orch_fmt,
            )
            plan_raw = extract_json_block(orch_turn.raw_text) or {}
            try:
                plan = OrchestratorPlan.model_validate(plan_raw)
            except Exception:
                # Don't throw the whole plan away over one bad field — salvage
                # it field-by-field so a parse hiccup never silently flips
                # intent to DIAGNOSE or drops a resolved anchor (see
                # _salvage_plan). Genuinely-unreadable fields still fall back
                # to their safe default (dispatch all).
                plan = _salvage_plan(plan_raw)
                print(
                    "[orchestrator] strict plan parse failed; salvaged "
                    f"intent={plan.intent} "
                    f"anchor={plan.anchor.name if plan.anchor else None} "
                    f"specialists={plan.specialists}",
                    flush=True,
                )
            plan_dict = plan.model_dump()
            print(
                f"[orchestrator] intent={plan.intent}"
                f" anchor={plan.anchor.name if plan.anchor else None}"
                f" specialists={plan.specialists}",
                flush=True,
            )

            task = specialist_task_input(plan_dict, question, scope.solution_name)

            # ── 2. Specialist runners (sync; executed in parallel threads) ─
            def _skipped(agent: str, reason: str) -> dict:
                return SpecialistResult(
                    agent=agent, status="skipped", error=reason  # type: ignore[arg-type]
                ).model_dump()

            def run_technical(plan_msg: dict) -> dict:
                if "technical" not in plan_msg.get("specialists", []):
                    return _skipped("technical", "orchestrator skipped")
                tools, dispatch = select_engine_tools(specs, TECHNICAL_TOOL_NAMES)
                r = run_specialist(
                    "technical", project_client, settings,
                    instructions=TECHNICAL_INSTRUCTIONS,
                    tools=tools, dispatch=dispatch, task_input=task,
                ).model_dump()
                print(f"[technical] {r['status']} in {r['elapsed_seconds']:.1f}s "
                      f"({r['tool_call_count']} tool calls)", flush=True)
                if r["status"] != "skipped":
                    _say("✓ Dependency & technical analysis done")
                return r

            def run_knowledge(plan_msg: dict) -> dict:
                if "knowledge" not in plan_msg.get("specialists", []):
                    return _skipped("knowledge", "orchestrator skipped")
                if kb_tool is None:
                    return _skipped("knowledge", "Foundry IQ KB not configured")
                r = run_specialist(
                    "knowledge", project_client, settings,
                    instructions=KNOWLEDGE_INSTRUCTIONS,
                    tools=[kb_tool], dispatch={}, task_input=task,
                ).model_dump()
                print(f"[knowledge] {r['status']} in {r['elapsed_seconds']:.1f}s "
                      f"({r.get('tool_call_count', 0)} tool calls) "
                      f"names={r.get('tool_names', [])[:8]}", flush=True)
                if r["status"] != "skipped":
                    _say("✓ Governance check done")
                return r

            def run_context(plan_msg: dict) -> dict:
                if "context" not in plan_msg.get("specialists", []):
                    return _skipped("context", "orchestrator skipped")
                context_tools = [
                    t for t in (workiq_tool, user_tool, teams_tool, mail_tool)
                    if t is not None
                ]
                if not context_tools:
                    return _skipped(
                        "context",
                        "Work IQ unavailable (requires --as-user and a Work IQ "
                        "connection: FOUNDRY_WORKIQ_CONNECTION_ID and/or _USER_)",
                    )
                r = run_specialist(
                    "context", project_client, settings,
                    instructions=CONTEXT_INSTRUCTIONS,
                    tools=context_tools, dispatch={}, task_input=task,
                ).model_dump()
                print(f"[context] {r['status']} in {r['elapsed_seconds']:.1f}s "
                      f"({r.get('tool_call_count', 0)} tool calls) "
                      f"names={r.get('tool_names', [])[:8]}", flush=True)
                # Deterministic awaiting-party floor: the specialist's keyword is
                # anchor-biased and variable (it may search the OWNER angle and
                # miss whoever is WAITING). So on a DIAGNOSE run a generic
                # universal-follow-up probe sweeps and MERGEs anyone it finds into
                # affected_people — a waiting party can't be missed because the
                # model picked the wrong keyword.
                # DIAGNOSE-ONLY: "affected_people" is the human fallout of a
                # FAILED outcome — a swallowed result someone is chasing. A
                # VALIDATE ("a new/changed automation") has no failed outcome, so
                # this probe must NOT run there — otherwise it pulls a customer
                # merely present in the area into a "people affected" list for a
                # change that never reaches them. On VALIDATE the relevant humans
                # are owners/teams to coordinate with (affected_teams /
                # change_collisions), not awaiting parties.
                intent_is_diagnose = (plan_msg.get("intent") or "DIAGNOSE").upper() == "DIAGNOSE"
                if (
                    intent_is_diagnose
                    and r.get("status") != "skipped"
                    and isinstance(r.get("finding"), dict)
                ):
                    live = [t for t in (teams_tool, mail_tool) if t is not None]
                    probed = _probe_awaiting_parties(
                        project_client, settings, live,
                        plan_msg.get("notes") or question,
                    )
                    if probed:
                        ap = r["finding"].setdefault("affected_people", []) or []
                        seen = {p.split("(")[0].strip().lower() for p in ap}
                        for p in probed:
                            key = p.split("(")[0].strip().lower()
                            if key and key not in seen:
                                ap.append(p)
                                seen.add(key)
                        r["finding"]["affected_people"] = ap
                        print(f"[context] awaiting-probe merged {len(probed)} "
                              f"-> affected_people={ap}", flush=True)
                if r["status"] != "skipped":
                    _say("✓ Workplace context check done")
                return r

            # ── 3. Adjudicator (fan-in) ────────────────────────────────────
            adjudicator_state: dict = {}

            def adjudicate(results: list[dict]) -> dict:
                _say("Weighing the verdict…")
                adj_tools, adj_dispatch = select_engine_tools(
                    specs, ADJUDICATOR_TOOL_NAMES
                )
                turn = run_agent_turn(
                    project_client,
                    agent_name="ImpactIQ-adjudicator",
                    model=settings.heavy_model_deployment or "",
                    instructions=ADJUDICATOR_INSTRUCTIONS,
                    tools=adj_tools,
                    dispatch=adj_dispatch,
                    user_input=_adjudicator_input(
                        plan_dict, question, scope.solution_name, results
                    ),
                )
                adjudicator_state["turn"] = turn
                adjudicator_state["results"] = results
                return {"raw_text": turn.raw_text}

            # ── 4. MAF workflow: genuine fan-out/fan-in, parallel threads ──
            workflow = build_workflow(
                run_technical, run_knowledge, run_context, adjudicate
            )
            asyncio.run(workflow.run(plan_dict))

            turn = adjudicator_state.get("turn")
            results = adjudicator_state.get("results", [])
            if turn is None:
                raise RuntimeError("workflow completed without adjudication")

            # Aggregate: knowledge runtime citations are ground truth; merge
            # with whatever the adjudicator's own response carried.
            citations = list(turn.citations)
            seen = {c.get("source_id") for c in citations}
            tool_names: list[str] = [f"orchestrator:{n}" for n in orch_turn.tool_names]
            tool_call_count = orch_turn.tool_call_count + turn.tool_call_count
            statuses = []
            for r in results:
                agent = r.get("agent", "?")
                statuses.append(f"{agent}={r.get('status')}")
                tool_call_count += r.get("tool_call_count", 0)
                tool_names += [f"{agent}:{n}" for n in r.get("tool_names", [])]
                for c in r.get("citations", []):
                    if c.get("source_id") not in seen:
                        citations.append(c)
                        seen.add(c.get("source_id"))
            tool_names += [f"adjudicator:{n}" for n in turn.tool_names]

            # Deterministic human-fallout safety net: the context specialist's
            # affected_people are who the failure actually affects. Carry them
            # into the report by CODE — even when the adjudicator's JSON dropped
            # them (LLM variability), so the customer/owner can't vanish
            # downstream. DIAGNOSE-ONLY: affected_people is the fallout of a
            # FAILED outcome; a VALIDATE has none, so don't force-carry awaiting
            # parties into a new-idea verdict.
            report_dict = extract_json_block(turn.raw_text) or {}
            if isinstance(report_dict, dict) and plan.intent == "DIAGNOSE":
                ctx_people: list = []
                for r in results:
                    if r.get("agent") == "context":
                        ctx_people = (r.get("finding") or {}).get("affected_people") or []
                merged = list(report_dict.get("affected_people") or [])
                seen_p = {str(p).split("(")[0].strip().lower() for p in merged}
                for p in ctx_people:
                    key = str(p).split("(")[0].strip().lower()
                    if key and key not in seen_p:
                        merged.append(p)
                        seen_p.add(key)
                if merged:
                    report_dict["affected_people"] = merged

            # Deterministic post-adjudication verdict gate: re-checks the
            # adjudicated report against the SAME ground truth the specialists
            # produced — citation grounding (against the runtime `citations`
            # aggregated above), owner/people provenance, freeze dominance,
            # defect-vs-expected flip. Pure Python, ~zero latency. SHADOW by
            # default (IMPACTIQ_VERDICT_GATE unset → logs would-be actions,
            # returns report_dict UNCHANGED so output is byte-identical to a run
            # without it); =enforce applies the corrections; =off skips it.
            if isinstance(report_dict, dict):
                from ..report.verdict_gate import gate_report

                report_dict, _gate_findings = gate_report(
                    plan_dict, results, report_dict,
                    runtime_citations=citations,
                    solution_name=scope.solution_name,
                )

                # ── Conditional critic + adversarial write-verify ──
                # Behind IMPACTIQ_CRITIC, and only on a high-stakes/uncertain
                # turn (write artifact, change-collision, gate flag, or
                # borderline confidence) — the median turn skips it entirely.
                from .critic import (
                    apply_write_deny,
                    carries_write_artifact,
                    critic_enabled,
                    run_skeptic,
                    should_critique,
                )

                if critic_enabled():
                    trigger = should_critique(report_dict, _gate_findings)
                    if trigger:
                        _say("Double-checking the verdict…")
                        print(f"[critic] triggered: {trigger}", flush=True)
                        critique = run_skeptic(
                            project_client, settings, plan_dict, question,
                            scope.solution_name, results, report_dict,
                        )
                        # Default-deny a refuted mutation (the dangerous part);
                        # the narrative still ships with a caveat. Fails OPEN:
                        # only an explicit `False` withholds the write.
                        wtype = carries_write_artifact(report_dict)
                        if wtype and critique.get("write_artifact_safe") is False:
                            report_dict = apply_write_deny(
                                report_dict,
                                str(critique.get("write_concern") or ""),
                            )
                            tool_names.append("critic:write_denied")
                            print(f"[critic] write artifact '{wtype}' DENIED: "
                                  f"{critique.get('write_concern')}", flush=True)
                        # One bounded adjudicator repair turn for narrative
                        # defects; kept only if it re-validates, does not worsen
                        # the verdict gate, and drops no awaiting party.
                        # LATENCY GUARD: the repair is a FULL adjudicator re-run
                        # (~a minute) and is often rejected as not-better, so it
                        # can push a turn past the surface fetch timeout. Restrict
                        # it to when a WRITE artifact is still on the line — the
                        # high-stakes case where re-grounding the narrative is
                        # worth the cost. For collision / borderline / gate-only
                        # triggers the cheap skeptic (and any write-deny above)
                        # already ran; we keep the verdict and just log the
                        # defects rather than paying for a re-adjudication that
                        # usually no-ops.
                        defects = [
                            d for d in (critique.get("defects") or [])
                            if isinstance(d, str) and d.strip()
                        ]
                        if defects and carries_write_artifact(report_dict):
                            repaired = _critic_repair(
                                project_client, settings, specs, plan_dict,
                                question, scope.solution_name, results,
                                report_dict, _gate_findings, citations, defects,
                                gate_report,
                            )
                            if repaired is not None:
                                report_dict = repaired
                                tool_names.append("critic:repaired")
                            else:
                                tool_names.append("critic:repair_rejected")
                        elif defects:
                            tool_names.append("critic:defects_noted")
                            print(f"[critic] {len(defects)} defect(s) noted; "
                                  "skipped repair (no write artifact at stake)",
                                  flush=True)

            return AskResult(
                raw_text=turn.raw_text,
                report=report_dict,
                tool_call_count=tool_call_count,
                citations=citations,
                run_status=f"{turn.run_status} ({', '.join(statuses)})",
                tool_names=tool_names,
            )
