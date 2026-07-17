"""Single-agent baseline: prompt-agent + responses + Foundry IQ MCP KB.

The runtime:

  1. Build the estate fragment + ImpactGraph for the scope.
  2. Build engine ``FunctionTool`` definitions + a local dispatch map.
  3. Build the Foundry IQ ``MCPTool`` (KB MCP endpoint via the project's
     RemoteTool connection; SharePoint source needs the
     ``x-ms-query-source-authorization`` header).
  3b. (``as_user=True``) Add the ``WorkIQPreviewTool`` (A2A) and swap the
     credential to the signed-in user - Work IQ rejects app-only callers.
  4. Create a versioned prompt agent (``project.agents.create_version``).
  5. Send the user question via ``openai.responses.create``; chain turns with
     ``previous_response_id`` (required by the Work IQ OAuth-consent resume,
     which is mutually exclusive with ``conversation``).
  6. **Manual tool-call loop**: parse ``response.output`` for ``function_call``
     items, dispatch each to local Python, submit ``function_call_output``
     items in a follow-up ``responses.create``, loop until no more function
     calls (with a safety bound). MCP tool calls (``knowledge_base_retrieve``)
     and Work IQ A2A calls execute server-side and don't surface as
     ``function_call`` items. ``oauth_consent_request`` items pause the loop
     for a one-time human consent (link printed to the CLI).
  7. Extract final text + URL citation annotations; parse the ImpactReport
     JSON block.
  8. Cleanup: delete the agent version.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from azure.ai.projects.models import MCPTool, WorkIQPreviewTool

from ..connectors import EstateScope  # noqa: F401 - re-exported for callers/tests
from ..dataverse_client import DataverseClient
from ..graph import build_graph
from ..settings import Settings
from .loop import extract_json_block, run_agent_turn
from .runtime import make_project_client
from .tools import ToolContext, build_engine_tools
from .workiq import REGISTRY as _workiq_registry, server_url as _workiq_server_url


# NOTE: This single-agent baseline is CLI-only (reached via cli.py's `ask`).
# Its artifact contract spans SIX types (dev_ticket / reuse_blueprint /
# draft_teams_intro + the three real actions). The production path is
# multi_agent.ask_multi, whose adjudicator restricts `generated_artifact` to
# the THREE real, executable actions (manager_handoff / remediation_proposal /
# backfill_blueprint) and treats a dev_ticket as draftable TEXT, not an
# action. The divergence below is that baseline-vs-production split, not a
# contradiction in the live agent.
SYSTEM_INSTRUCTIONS = """\
You are ImpactIQ, a read-only impact-analysis agent for Microsoft Power Platform.

Your job: take a user's question about an estate (Dataverse tables + cloud
flows + security model), call the engine tools to investigate, consult the
Foundry IQ knowledge base for governance citations, and return a structured
ImpactReport.

# Workflow (do not skip steps)

1. **Classify intent**: DIAGNOSE (a symptom / problem) or VALIDATE
   (a proposed change or new feature).
2. **Resolve the anchor**: call `resolve_anchor` with a SHORT identifier
   (a logical name like `account`, a column like `statuscode`, a flow name).
   Do NOT pass full sentences. If the first call returns `[]`, retry with
   simpler terms. If no match, set `"anchor": null` and say so honestly.
3. **Primary move (mandatory on every anchor)**: call `walk_anchor` to get
   the dependency neighbourhood. This is the suspect population (DIAGNOSE)
   / blast radius (VALIDATE).
4. **Knowledge grounding (the Foundry IQ KB)**: call the `knowledge_base_retrieve`
   MCP tool whenever a finding might be governed by policy / SOP / ADR:
   * Always consult the KB on DIAGNOSE before declaring something a "defect"
     - an SOP may describe the same behaviour as expected.
   * On VALIDATE, consult the KB on whether the proposed change conflicts
     with any documented standard.
   The KB returns matched chunks (output_mode = extractedData) - synthesize
   the verdict yourself; do not let the KB pre-commit you.
5. **Enrich by anchor kind / intent**: on Flow + DIAGNOSE call
   `find_failed_flows`; on permissions questions call `diagnose_permission`;
   on VALIDATE call `recent_change_scan` for collisions.
6. **Human-signal scan (Work IQ - only if the `work_iq_preview` tool is
   available)**: after the engine walk, ask Work IQ in natural language for
   the HUMAN side of the finding:
   * DIAGNOSE: "Has anyone discussed/raised <symptom or component> in Teams
     chats or channels recently? Are there recent emails about it (e.g. from
     a customer)? Who?" - feed real signals into `evidence` (kind "workiq")
     and owners into `affected_teams`.
   * VALIDATE: for the top blast-radius components, ask whether anyone is
     actively working on / discussing changes to them (threads, docs,
     meetings). Each overlap is a change_collision: set `who` from the
     signal's owner and raise risk.
   Work IQ runs as the signed-in user and is permission-trimmed - treat an
   empty answer as "no visible signal", not "no signal".
7. **Score risk**: call `score_risk`.
8. **Artifact (every answer ends in a deliverable - THIS STEP IS NOT
   OPTIONAL)**: draft ONE artifact and run it through `validate_artifact`
   BEFORE the final answer. A cross-team VALIDATE without a
   `manager_handoff` artifact is an INCOMPLETE answer; `generated_artifact:
   null` is acceptable only when literally none of the types applies (rare).
   Selection:
   * DIAGNOSE, configuration cause (broken/misconfigured flow, role, rule)
     -> `dev_ticket`. Never propose to change configuration yourself.
   * DIAGNOSE, per-record DATA consequence the user could fix in the UI,
     confidence >= 0.8 -> `remediation_proposal` (set diagnosis_confidence;
     fill downstream_preview from the walk; evidence_source "document" ONLY
     if the user explicitly attached/named a document in the CURRENT turn -
     then include document_name + the exact source_span).
   * The same fix needed on MANY records -> `backfill_blueprint`
     (query + idempotency note). NEVER offer "fix all" as one action.
   * VALIDATE where the blast radius touches another team's assets ->
     `manager_handoff`: impact-assertion-only draft ("a proposed change may
     affect your team's X - you may want to review") + a context baton.
     The draft must NEVER include inferred reasons about the other team's
     work or anything you could not show the requesting user.
     **Precedence: for cross-team VALIDATE, manager_handoff ALWAYS wins over
     draft_teams_intro** - the handoff carries the context baton that lets
     the owner's own session resume the analysis; a bare intro does not.
   * VALIDATE with an existing equivalent -> `reuse_blueprint`.
   * Otherwise, if an owner should simply be contacted (no cross-team
     impact assertion needed) -> `draft_teams_intro`.
   If `validate_artifact` refuses: when `use_instead` is set, redraft as
   that type; when it is not set (schema problem), FIX the listed fields and
   call `validate_artifact` again. NEVER respond with `generated_artifact:
   null` after a refusal - a refusal means "repair", not "skip". Embed the
   RETURNED (normalized) artifact verbatim as `generated_artifact`.
9. **Final ImpactReport** (JSON block; schema below).

# Discipline (not optional)

* READ-ONLY against the tenant. Recommendations are advisory.
* NEVER re-derive dependencies in tokens - always call walk_anchor or the
  retrieve_*_components primitives.
* **Causal vs structural neighbours**: only count `causal_neighbour_count` as
  "impacted". Structural neighbours (has_column / in_solution / member_of) are
  grouped with the anchor, not impacted by changes around it.
* **Defect-vs-expected reconciliation**: if the structural walk
  suggests a defect AND the KB cites a policy that describes the same
  behaviour as expected, FLIP the verdict to expected-per-policy with the
  citation. Reduce confidence to reflect the conflict you reconciled.
* When the radius is sparse (causal count = 0), say so honestly. Note that
  per-record data backfill is out of scope for this tool.
* If a tool returns `{"error": ...}`, surface it in `evidence` - never paper
  over.
* Every claim grounded in the KB MUST carry a citation entry in
  `citations[]` (source title / URL).

# Disclosure gate for Work IQ signals (safety-critical)

* **Disclose presence + owner + routing; withhold substance.** "A recent
  Teams discussion by <owner> touches this flow - coordinate with them" is
  the ceiling. Never quote, summarize, or paraphrase the *content* of other
  people's messages, documents, or meetings into the report.
* **Sensitivity**: if a signal looks restricted/confidential - or you cannot
  tell - treat it as restricted (fail closed). For restricted signals use
  EXACTLY this templated phrasing in the collision advice: "Your change
  affects an area with restricted activity - coordinate via the named owner."
  Do not name restricted artifacts (even a title can leak).
* Route via structural ownership (the component's owner/team), not via the
  names found inside confidential content.
* **Drafts only**: if the user asks for a reply/communication, produce the
  draft TEXT inside the report (recommendation / interim_actions, prefixed
  "DRAFT:"). You cannot and must not send anything.

# Final output

Respond with EXACTLY one JSON object inside a ```json fence, matching this
schema. No prose around it.

```json
{
  "intent": "DIAGNOSE",
  "anchor": {"id": "...", "kind": "...", "name": "..."},
  "verdict": "<one-sentence>",
  "confidence": 0.0,
  "reconciliation": "<how you weighed structural + KB evidence>",
  "evidence": [{"kind": "tool|note|citation", "detail": "..."}],
  "impacted_components": [{"id": "...", "kind": "...", "name": "..."}],
  "affected_teams": [],
  "risk": {"score": 0, "level": "low", "reasons": ["..."]},
  "recommendation": "<what the user should do>",
  "interim_actions": [],
  "existing_equivalents": [],
  "change_collisions": [],
  "citations": [{"source_id": "...", "title": "...", "url": "..."}],
  "generated_artifact": {"artifact_type": "<one of the six types>", "...": "fields exactly as returned by validate_artifact"}
}
```

(`generated_artifact`: paste the validated artifact object EXACTLY as the
`validate_artifact` tool returned it. Only use null in the rare case where
no artifact type applies.)
"""


def _build_mcp_kb_tool(settings: Settings) -> MCPTool | None:
    """Construct the Foundry IQ KB MCP tool, or None if not configured."""
    if not (
        settings.aisearch_endpoint
        and settings.foundry_kb_name
        and settings.foundry_kb_connection_name
    ):
        return None
    endpoint = settings.aisearch_endpoint.rstrip("/")
    mcp_url = (
        f"{endpoint}/knowledgebases/{settings.foundry_kb_name}/mcp"
        "?api-version=2026-05-01-preview"
    )
    # The `headers` field is dropped entirely: the Foundry runtime rejects
    # `x-ms-query-source-authorization` as "sensitive header not allowed", so
    # SharePoint queries return content via the project MI's auth alone.
    return MCPTool(
        server_label="foundry-iq-kb",
        server_url=mcp_url,
        require_approval="never",
        allowed_tools=["knowledge_base_retrieve"],
        project_connection_id=settings.foundry_kb_connection_name,
    )


def _build_workiq_tool(settings: Settings) -> WorkIQPreviewTool | None:
    """Construct the Work IQ A2A tool, or None if not configured.

    Unlike the SharePoint MCP source there is no header plumbing at all:
    Foundry routes the natural-language task to Work IQ over A2A and the
    OAuth identity-passthrough connection carries the signed-in user (OBO).
    """
    if not settings.foundry_workiq_connection_id:
        return None
    return WorkIQPreviewTool(
        project_connection_id=settings.foundry_workiq_connection_id,
    )


# The draft pair (live tool names) and the send/forward verbs that must never
# be allow-listed anywhere. The registry in agents/workiq.py is the source of
# truth for the full mail allow-list.
WORKIQ_MAIL_DRAFT_TOOLS = ["CreateDraftMessage", "UpdateDraft"]
WORKIQ_MAIL_SEND_TOOLS = frozenset(
    {
        "SendEmailWithAttachments",
        "SendDraftMessage",
        "ForwardMessage",
        "ForwardMessageWithFullThread",
    }
)


def _build_workiq_mail_tool(settings: Settings) -> MCPTool | None:
    """Work IQ Mail MCP tool for the confirm-gated draft endpoint.

    DRAFT pair only - never send. ``require_approval="never"`` because the
    /action/create_draft confirm tap IS the human approval and the turn runs
    headless (an MCP approval pause here would hang with no one to answer it).
    Runs OBO as the signed-in user, so the draft lands in *their* Outlook
    Drafts."""
    server = _workiq_registry["mail"]
    connection_id = getattr(settings, server.connection_attr, None)
    if not connection_id:
        return None
    return MCPTool(
        server_label="workiq-mail-draft",
        server_url=_workiq_server_url(server, settings),
        require_approval="never",
        allowed_tools=list(WORKIQ_MAIL_DRAFT_TOOLS),
        project_connection_id=connection_id,
    )


@dataclass
class AskResult:
    raw_text: str
    report: dict | None
    tool_call_count: int
    citations: list[dict] = field(default_factory=list)
    run_status: str = "unknown"
    tool_names: list[str] = field(default_factory=list)


def ask(
    settings: Settings,
    *,
    solution_name: str,
    question: str,
    agent_name: str = "ImpactIQ-baseline",
    as_user: bool = False,
) -> AskResult:
    """End-to-end: pre-warm estate, spin up a prompt agent, run the manual
    tool-call loop, return the parsed ImpactReport + citations.

    ``as_user=True``: authenticate the Foundry calls as the signed-in user
    (browser sign-in on first run) and attach the Work IQ tool. The Dataverse
    estate pre-warm below stays on the read-only service identity either way -
    two identities by scope.
    """
    if not settings.foundry_model_deployment:
        raise RuntimeError("FOUNDRY_MODEL_DEPLOYMENT is not set in .env")

    with DataverseClient(settings) as dv_client:
        # 1. Pre-warm the estate - TTL-cached across turns.
        from ..estate_cache import get_estate_cached

        scope, fragment = get_estate_cached(dv_client, settings, solution_name)
        graph = build_graph(fragment)

        ctx = ToolContext(client=dv_client, scope=scope, graph=graph)
        function_tools, dispatch = build_engine_tools(ctx)

        # 2. Foundry IQ KB MCP. Optional - if .env vars aren't set yet, run
        # engine-only so cli ask still works before the KB is configured.
        kb_tool = _build_mcp_kb_tool(settings)
        tools_list: list = list(function_tools)
        if kb_tool is not None:
            tools_list.append(kb_tool)

        # 2b. Work IQ - only under the delegated user identity; Work IQ
        # rejects app-only callers, so attaching it on an SP run would just
        # produce a guaranteed tool failure.
        if as_user:
            workiq_tool = _build_workiq_tool(settings)
            if workiq_tool is not None:
                tools_list.append(workiq_tool)

        # 3. Prompt-agent runtime - the shared hardened loop (agents/loop.py).
        with make_project_client(settings, as_user=as_user) as project_client:
            turn = run_agent_turn(
                project_client,
                agent_name=agent_name,
                model=settings.foundry_model_deployment,
                instructions=SYSTEM_INSTRUCTIONS,
                tools=tools_list,
                dispatch=dispatch,
                user_input=(
                    f"Scope: solution '{scope.solution_name}'.\n\n"
                    f"Question:\n{question}"
                ),
            )
            report = extract_json_block(turn.raw_text)
            # Verdict gate, shadow by default. On this legacy single-agent
            # path there are no specialist findings, so only citation grounding
            # is active (against this turn's runtime citations); the
            # provenance/freeze/flip rules require specialist findings and are
            # safely skipped when `results` is empty.
            if isinstance(report, dict):
                from ..report.verdict_gate import gate_report

                report, _ = gate_report(
                    {}, [], report, runtime_citations=turn.citations
                )
            return AskResult(
                raw_text=turn.raw_text,
                report=report,
                tool_call_count=turn.tool_call_count,
                citations=turn.citations,
                run_status=turn.run_status,
                tool_names=turn.tool_names,
            )
