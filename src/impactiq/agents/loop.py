"""The hardened prompt-agent turn loop, shared by all agents.

The single agent and the multi-agent specialists share this one loop, so every
hard-won behaviour is inherited unchanged:

* ``previous_response_id`` chaining (required by the Work IQ consent resume,
  mutually exclusive with ``conversation``),
* the one-time ``oauth_consent_request`` gate (interactive or poll mode),
* retry on transient 5xx and 429 (back-to-back runs trip the deployment's
  rate limit),
* URL-citation extraction from the response annotations,
* per-turn agent-version cleanup.
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from azure.ai.projects.models import PromptAgentDefinition
from openai import APIStatusError

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _ptc_kwargs(parallel_tool_calls: bool | None) -> dict:
    """Spread-able kwargs for `responses.create`: only sets parallel_tool_calls
    when a caller asked for it (structured outputs require it = False), so the
    default path is byte-identical to before (param never sent)."""
    return {} if parallel_tool_calls is None else {"parallel_tool_calls": parallel_tool_calls}

# Safety bound on the manual function-call loop. The Work IQ OAuth-consent
# resume consumes a loop iteration on first use per user.
MAX_TOOL_LOOPS = 10
# Consent gate gets its own budget so polling can't starve the tool loop.
_CONSENT_POLL_SECONDS = 20
_CONSENT_MAX_POLLS = 15  # ~5 minutes for the human to click the link


def extract_json_block(text: str) -> dict | None:
    """Pull a single JSON object out of an agent's final message text."""
    m = _FENCE_RE.search(text or "")
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    if text:
        i = text.find("{")
        j = text.rfind("}")
        if 0 <= i < j:
            try:
                return json.loads(text[i : j + 1])
            except json.JSONDecodeError:
                return None
    return None


def extract_citations(response: Any) -> list[dict]:
    """Walk the final response.output for URL citation annotations."""
    citations: list[dict] = []
    output = getattr(response, "output", None) or []
    for item in output:
        if getattr(item, "type", "") != "message":
            continue
        for content in getattr(item, "content", []) or []:
            if getattr(content, "type", "") != "output_text":
                continue
            for ann in getattr(content, "annotations", []) or []:
                if getattr(ann, "type", "") in ("url_citation", "file_citation"):
                    citations.append(
                        {
                            "url": getattr(ann, "url", None),
                            "title": getattr(ann, "title", None),
                            "source_id": (
                                getattr(ann, "file_id", None)
                                or getattr(ann, "url", None)
                            ),
                        }
                    )
    return citations


def responses_create_with_retry(
    openai_client: Any, *, max_attempts: int = 3, **kwargs: Any
) -> Any:
    """``responses.create`` with retry on transient 5xx / 429."""
    for attempt in range(1, max_attempts + 1):
        try:
            return openai_client.responses.create(**kwargs)
        except APIStatusError as exc:
            retryable = exc.status_code >= 500 or exc.status_code == 429
            if not retryable or attempt == max_attempts:
                raise
            delay = 30 if exc.status_code == 429 else 10
            print(
                f"(transient {exc.status_code} from Foundry - "
                f"retry {attempt}/{max_attempts - 1} in {delay}s...)",
                flush=True,
            )
            time.sleep(delay)


def consent_requests(response: Any) -> list[Any]:
    """Pull `oauth_consent_request` items out of a response's output."""
    return [
        item
        for item in (getattr(response, "output", None) or [])
        if getattr(item, "type", "") == "oauth_consent_request"
    ]


def approval_requests(response: Any) -> list[dict]:
    """Pull `mcp_approval_request` items (gated mutating MCP tools) out of a
    response's output, normalized to plain dicts."""
    out = []
    for item in getattr(response, "output", None) or []:
        if getattr(item, "type", "") == "mcp_approval_request":
            out.append(
                {
                    "id": getattr(item, "id", ""),
                    "server_label": getattr(item, "server_label", ""),
                    "tool_name": getattr(item, "name", ""),
                    "arguments": getattr(item, "arguments", ""),
                }
            )
    return out


@dataclass
class TurnResult:
    """Raw outcome of one agent turn (parsing left to the caller)."""

    raw_text: str
    tool_call_count: int
    citations: list[dict] = field(default_factory=list)
    run_status: str = "unknown"
    tool_names: list[str] = field(default_factory=list)
    # When run_status == "pending_approval": the gated tool calls awaiting a
    # human decision, plus everything needed to resume the run later.
    pending_approvals: list[dict] = field(default_factory=list)
    resume_response_id: str | None = None
    agent_name: str | None = None
    agent_version: str | None = None


def _default_approval_callback(req: dict) -> bool:
    """CLI default for gated mutating tools: ask when interactive, DENY when
    headless. A denied call tells the model why, so it can answer without
    the action instead of stalling."""
    interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())
    if not interactive:
        print(
            f"[approval] DENIED (non-interactive): {req['tool_name']} "
            f"{str(req['arguments'])[:120]}",
            flush=True,
        )
        return False
    ans = input(
        f"\n[approval] ImpactIQ wants to run {req['tool_name']} with "
        f"{str(req['arguments'])[:200]}\nApprove? [y/N] "
    )
    return ans.strip().lower() in ("y", "yes")


# Cached agent versions for STATELESS, tool-less hops (front-door triage,
# the deep-analysis router, next-step suggestions). These never suspend and
# their definition is constant within a process, so creating a fresh version
# (and deleting it) on every call is pure latency - each round-trip to the
# Foundry control plane costs seconds. Created once, reused, never deleted.
# Keyed by the full definition so an instruction change makes a new version.
_CACHED_AGENT_REFS: dict[tuple[str, str, str], dict] = {}


def run_agent_turn(
    project_client: Any,
    *,
    agent_name: str,
    model: str,
    instructions: str,
    tools: list,
    dispatch: dict,
    user_input: str,
    max_tool_loops: int = MAX_TOOL_LOOPS,
    approval_callback: Any = None,
    suspend_on_approval: bool = False,
    cache_version: bool = False,
    reflect: bool = False,
    text_format: Any = None,
    parallel_tool_calls: bool | None = None,
) -> TurnResult:
    """Create a versioned prompt agent, run the manual tool-call loop on a
    single user input, clean up the version. Thread-safe per call (creates
    its own OpenAI client).

    ``text_format`` (a ``PromptAgentDefinitionTextOptions``) attaches a native
    response format - e.g. a strict JSON-schema - to the agent definition so the
    platform guarantees schema-conformant final output. ``parallel_tool_calls=False``
    must accompany it (the Responses API forbids parallel function calls under a
    structured-output format). Both default to None → the param is never sent and
    behaviour is unchanged.

    ``reflect=True`` adds ONE generic self-verification hop before the turn is
    allowed to finish: the model checks it actually DID what was asked (called
    the tool, didn't just describe it) and recovered from any empty/failed tool
    instead of stopping. For the front agent that takes actions - not the
    cached tool-less hops or the narrow specialists.

    ``cache_version=True`` reuses a process-cached agent version instead of
    creating/deleting one per call - ONLY for stateless, tool-less hops that
    never suspend (triage, router, suggestions). Cuts two control-plane
    round-trips per call.

    Gated mutating MCP tools surface as ``mcp_approval_request`` items:
    * ``suspend_on_approval=True`` - return immediately with
      run_status="pending_approval" (agent version is KEPT alive); the
      caller shows Approve/Deny to the human and continues the same run via
      :func:`resume_agent_turn`. This is the Teams-surface path.
    * otherwise - ``approval_callback(request) -> bool`` decides inline
      (default: prompt on a TTY, deny when headless).
    """
    _def_kwargs: dict = {"model": model, "instructions": instructions, "tools": tools}
    if text_format is not None:
        _def_kwargs["text"] = text_format
    keep_version = cache_version
    if cache_version:
        key = (agent_name, model, instructions)
        agent_ref = _CACHED_AGENT_REFS.get(key)
        if agent_ref is None:
            created = project_client.agents.create_version(
                agent_name=agent_name,
                definition=PromptAgentDefinition(**_def_kwargs),
            )
            agent_ref = {"name": created.name, "type": "agent_reference"}
            _CACHED_AGENT_REFS[key] = agent_ref
        agent = None
    else:
        agent = project_client.agents.create_version(
            agent_name=agent_name,
            definition=PromptAgentDefinition(**_def_kwargs),
        )
        agent_ref = {"name": agent.name, "type": "agent_reference"}
    openai_client = project_client.get_openai_client()

    response = responses_create_with_retry(
        openai_client,
        input=user_input,
        extra_body={"agent_reference": agent_ref},
        **_ptc_kwargs(parallel_tool_calls),
    )
    # Cached agents are reused across calls - never hand their version to the
    # cleanup path (agent_version=None disables the delete in _drive_loop).
    return _drive_loop(
        project_client,
        openai_client,
        agent_ref,
        response,
        agent_name=agent_ref["name"],
        agent_version=None if keep_version else agent.version,
        dispatch=dispatch,
        max_tool_loops=max_tool_loops,
        approval_callback=approval_callback,
        suspend_on_approval=suspend_on_approval,
        reflect=reflect,
        parallel_tool_calls=parallel_tool_calls,
    )


def resume_agent_turn(
    project_client: Any,
    *,
    agent_name: str,
    agent_version: str | None,
    response_id: str,
    approvals: dict[str, bool],
    dispatch: dict,
    max_tool_loops: int = MAX_TOOL_LOOPS,
    approval_callback: Any = None,
    suspend_on_approval: bool = True,
    reflect: bool = False,
) -> TurnResult:
    """Continue a suspended run by answering its pending approval requests.

    ``approvals`` maps approval_request_id -> True (approve) / False (deny).
    The same loop then continues - it may complete, or pause again on the
    next gated call."""
    openai_client = project_client.get_openai_client()
    agent_ref = {"name": agent_name, "type": "agent_reference"}
    response = responses_create_with_retry(
        openai_client,
        previous_response_id=response_id,
        input=[
            {
                "type": "mcp_approval_response",
                "approval_request_id": rid,
                "approve": bool(ok),
            }
            for rid, ok in approvals.items()
        ],
        extra_body={"agent_reference": agent_ref},
    )
    return _drive_loop(
        project_client,
        openai_client,
        agent_ref,
        response,
        agent_name=agent_name,
        agent_version=agent_version,
        dispatch=dispatch,
        max_tool_loops=max_tool_loops,
        approval_callback=approval_callback,
        suspend_on_approval=suspend_on_approval,
        reflect=reflect,
    )


def _hosted_tool_calls(response: Any) -> list[tuple[str, str, str, int]]:
    """(item_id, tool_name, arguments, output_len) for executed HOSTED tool
    calls (`mcp_call` items). These run server-side (Work IQ search, the KB, any
    MCP/A2A tool) and never surface as `function_call` items - so the local
    `function_call` counter misses them entirely, and an agent that searches
    heavily via hosted tools would otherwise log "0 tool calls".

    We also surface the call's ARGUMENTS (the actual query) and a rough output
    size, so a "search found nothing" miss is diagnosable from the log instead
    of being invisible."""
    out: list[tuple[str, str, str, int]] = []
    for item in getattr(response, "output", None) or []:
        if getattr(item, "type", "") == "mcp_call":
            output = getattr(item, "output", None)
            out.append(
                (
                    getattr(item, "id", "") or "",
                    getattr(item, "name", "") or "mcp_call",
                    str(getattr(item, "arguments", "") or ""),
                    len(str(output)) if output else 0,
                )
            )
    return out


# Hosted tools whose QUERY + result size we echo to the log (search tools where
# "what did it actually ask, and did anything come back?" is the whole question).
_LOGGED_SEARCH_TOOLS = frozenset(
    {"SearchMessages", "SearchTeamsMessages", "work_iq_preview", "knowledge_base_retrieve"}
)

# The self-check is only worth running for COMPLEX turns - ones that produced a
# real ANALYSIS or took an ACTION; the review is only required when complex
# actions are involved. A pure lookup (who owns X, show records, what does the
# SOP say) needs no review and shouldn't pay the extra hop or risk the review
# adding noise.
_REVIEW_WORTHY_TOOLS = frozenset(
    {
        "deep_impact_analysis",
        "propose_record_fix",
        "sandbox_fix",
        "sandbox_inspect",
        "draft_reply",
        "resubmit_flow_run",
        "CreateEvent",
        "UpdateEvent",
        "SendMessageToUser",
        "SendMessageToChannel",
        "CreateDraftMessage",
        "ReplyToMessage",
        "ReplyAllToMessage",
    }
)

# One-shot self-verification before a turn finishes (reflect=True). GENERIC - it
# asks the model to reason about whether it actually accomplished the request,
# not a per-case rule. This is the structural cure for "it had the tool but
# didn't chain it / described the action instead of doing it / stopped at a
# tool that came up empty": a reasoning model that is prompted to CHECK its own
# work recovers on its own, instead of bolting on a new instruction for every
# failure.
_REFLECTION_PROMPT = (
    "PRIVATE self-check - the user must NEVER see any of this. Run it silently "
    "in your head; your visible reply must read exactly as if this check never "
    "happened. Do NOT add a self-audit, a 'Nothing was left half-done', a "
    "'no draft/message/action was requested', a 'the analysis was run', or any "
    "line stating what you verified, checked, or did/didn't do. If everything is "
    "already done, just leave the answer you already have - re-send it unchanged "
    "rather than appending a summary of this check.\n\n"
    "Check, in one short reasoning pass:\n"
    "1. Did you ACCOMPLISH what was asked, or only describe/plan it? If you "
    "intended any action (a draft, a message, a fix, a record change), did you "
    "actually CALL the tool to do it - or just write about it? Chat text is not "
    "the deliverable; the artifact is.\n"
    "2. If you produced a message/draft, was its CONTENT grounded in the "
    "specific evidence - what the automation actually does or should have sent, "
    "the person's actual situation - rather than a vague generic placeholder? "
    "(Aim to get this right the FIRST time; see point 5 - do not create a second "
    "draft to fix wording.)\n"
    "3. Did any tool come up empty or fail, where another tool you hold would "
    "get the answer (e.g. an address you can read off someone's own email "
    "instead of the org directory; a flow's own definition instead of "
    "guessing)? If so, try that path now rather than stopping or asking the "
    "user for something you can find yourself.\n"
    "4. Did you leave out anyone or anything the evidence shows matters?\n"
    "5. Do NOT REPEAT an action that already SUCCEEDED - this check is for work "
    "that is MISSING or FAILED, never for redoing done work. In particular, if a "
    "draft/message was already created, do NOT create a second one (you can't "
    "un-draft; a redo just litters the user's Drafts).\n"
    "If genuinely-missing work remains, do it FIRST then give the answer;"
    " otherwise re-send your existing answer unchanged. Either way the visible"
    " reply is ONE clean STANDALONE answer to the user's request - no meta-"
    "commentary about this check, no 'Nothing was left half-done', no self-"
    "audit, and no 'Additional finding' / 'Also' continuation opener."
)


def _drive_loop(
    project_client: Any,
    openai_client: Any,
    agent_ref: dict,
    response: Any,
    *,
    agent_name: str,
    agent_version: str | None,
    dispatch: dict,
    max_tool_loops: int,
    approval_callback: Any,
    suspend_on_approval: bool,
    reflect: bool = False,
    parallel_tool_calls: bool | None = None,
) -> TurnResult:
    tool_call_count = 0
    tool_names: list[str] = []
    run_status = "unknown"
    suspended = False
    nudged = False  # one-shot guard against silent empty completions
    reflected = False  # one-shot self-verification before accepting completion
    # The answer the model had BEFORE the self-check, and the tool count then.
    # If the self-check triggers NO recovery (no new tool calls), it had nothing
    # to add, so we KEEP this clean pre-check answer and discard whatever the
    # check re-composed - that's how the self-audit narration is prevented
    # deterministically, not just by asking the model not to narrate.
    pre_reflect_text = ""
    pre_reflect_citations: list = []
    tool_count_at_reflect = -1
    recoveries = 0  # tool_user_error self-correction budget per turn
    _seen_hosted: set[str] = set()

    def _record_hosted() -> None:
        """Fold server-side hosted-tool calls into the counters so they're
        VISIBLE (the local function_call counter can't see them)."""
        nonlocal tool_call_count
        for item_id, name, args, out_len in _hosted_tool_calls(response):
            if item_id and item_id in _seen_hosted:
                continue
            if item_id:
                _seen_hosted.add(item_id)
            tool_call_count += 1
            tool_names.append(name)
            # Echo the QUERY + whether anything came back for search tools, so a
            # miss ("found nothing") is diagnosable instead of invisible.
            if name in _LOGGED_SEARCH_TOOLS:
                print(
                    f"  [search] {name} args={args[:200]} -> {out_len} chars",
                    flush=True,
                )

    def _submit(input_obj: Any) -> Any:
        """Chain the next response. If a SERVER-SIDE tool call fails (Foundry
        surfaces MCP tool errors, e.g. bad SQL, as a 400 `tool_user_error` on
        the create itself), feed the error BACK to the model so it can
        diagnose and correct its call - instead of crashing the turn."""
        nonlocal recoveries
        try:
            return responses_create_with_retry(
                openai_client,
                input=input_obj,
                previous_response_id=response.id,
                extra_body={"agent_reference": agent_ref},
                **_ptc_kwargs(parallel_tool_calls),
            )
        except APIStatusError as exc:
            if (
                exc.status_code == 400
                and "tool_user_error" in str(exc)
                and recoveries < 2
            ):
                recoveries += 1
                tool_names.append("tool_error_recovered")
                note = (
                    f"(One of your tool calls failed: {str(exc)[:400]}. "
                    "Diagnose the error and adjust the call - e.g. verify "
                    "table/column names with `describe` or `resolve_anchor` "
                    "- then continue the task.)"
                )
                # CRITICAL: keep the original items (function_call_output /
                # approval responses) - dropping them orphans the pending
                # function call ("No tool output found for ...").
                recovery_input: Any = (
                    [*input_obj, {"role": "user", "content": note}]
                    if isinstance(input_obj, list)
                    else note
                )
                return responses_create_with_retry(
                    openai_client,
                    input=recovery_input,
                    previous_response_id=response.id,
                    extra_body={"agent_reference": agent_ref},
                    **_ptc_kwargs(parallel_tool_calls),
                )
            raise

    try:
        for _ in range(max_tool_loops):
            # Record any hosted (server-side) tool calls in this response so
            # they show up in tool_call_count / tool_names like local tools.
            _record_hosted()
            # Gated mutating MCP tools: pause for a human decision.
            pending = approval_requests(response)
            if pending:
                if suspend_on_approval:
                    suspended = True
                    return TurnResult(
                        raw_text=getattr(response, "output_text", "") or "",
                        tool_call_count=tool_call_count,
                        run_status="pending_approval",
                        tool_names=tool_names,
                        pending_approvals=pending,
                        resume_response_id=response.id,
                        agent_name=agent_name,
                        agent_version=agent_version,
                    )
                cb = approval_callback or _default_approval_callback
                decisions = []
                for req in pending:
                    ok = bool(cb(req))
                    tool_names.append(
                        f"{'approved' if ok else 'denied'}:{req['tool_name']}"
                    )
                    decisions.append(
                        {
                            "type": "mcp_approval_response",
                            "approval_request_id": req["id"],
                            "approve": ok,
                        }
                    )
                response = _submit(decisions)
                continue
            # Work IQ one-time consent gate (per user per connection).
            if consent_requests(response):
                for item in consent_requests(response):
                    link = getattr(item, "consent_link", None)
                    print(
                        "\n[Work IQ] One-time consent required. Open this "
                        "link in a browser, sign in as the demo user, "
                        "approve, then close the dialog:"
                    )
                    print(f"  {link or '(no consent link surfaced)'}", flush=True)
                interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())
                for _poll in range(_CONSENT_MAX_POLLS):
                    if interactive:
                        input("Press Enter here once consent is granted... ")
                    else:
                        print(
                            "(stdin is non-interactive: re-checking consent "
                            f"in {_CONSENT_POLL_SECONDS}s...)",
                            flush=True,
                        )
                        time.sleep(_CONSENT_POLL_SECONDS)
                    response = _submit("Consent granted - continue the analysis.")
                    if not consent_requests(response):
                        break
                else:
                    run_status = "consent_not_granted"
                    break
                continue

            function_calls = [
                item
                for item in (getattr(response, "output", None) or [])
                if getattr(item, "type", "") == "function_call"
            ]
            if not function_calls:
                # Guard: a run can end its tool work WITHOUT a user-visible
                # message (observed with chained server-side MCP calls). Nudge
                # the model ONCE to actually answer before declaring done.
                text_so_far = (getattr(response, "output_text", "") or "").strip()
                if not text_so_far and not nudged:
                    nudged = True
                    response = _submit(
                        "You haven't written a user-visible reply yet. Based "
                        "on the tool results above, write your final answer "
                        "for the user now (plain text, no tool calls)."
                    )
                    continue
                # One-shot self-verification: the model thinks it's done - make
                # it check it actually DID the work (and recovered from any empty
                # tool) before we accept completion. ONLY for complex turns (an
                # analysis or an action - see _REVIEW_WORTHY_TOOLS); a lookup or
                # plain reply skips it (no extra hop, no review noise).
                if (
                    reflect
                    and not reflected
                    and any(t in _REVIEW_WORTHY_TOOLS for t in tool_names)
                ):
                    reflected = True
                    pre_reflect_text = text_so_far
                    pre_reflect_citations = extract_citations(response)
                    tool_count_at_reflect = tool_call_count
                    print("(self-check before finishing)", flush=True)
                    response = _submit(_REFLECTION_PROMPT)
                    continue
                run_status = "completed"
                break

            tool_outputs: list[dict] = []
            for call in function_calls:
                tool_call_count += 1
                name = getattr(call, "name", "") or ""
                tool_names.append(name)
                try:
                    args = json.loads(getattr(call, "arguments", "") or "{}")
                except (json.JSONDecodeError, TypeError):
                    args = {}
                impl = dispatch.get(name)
                if impl is None:
                    output = json.dumps({"error": f"unknown function: {name!r}"})
                else:
                    try:
                        output = impl(args)
                    except Exception as exc:
                        output = json.dumps(
                            {"error": f"{type(exc).__name__}: {exc}"}
                        )
                tool_outputs.append(
                    {
                        "type": "function_call_output",
                        "call_id": getattr(call, "call_id", ""),
                        "output": output,
                    }
                )

            response = _submit(tool_outputs)
        else:
            run_status = "max_tool_loops_exceeded"
            # Force a final compose: the model was mid-tool-chain, so the
            # last response usually has NO user-visible text - returning it
            # as-is gives the user an empty turn. Answer any dangling
            # function calls with a budget-exhausted error, then make the
            # model report what it has.
            try:
                dangling = [
                    {
                        "type": "function_call_output",
                        "call_id": getattr(item, "call_id", ""),
                        "output": json.dumps(
                            {"error": "tool budget exhausted - no more calls this turn"}
                        ),
                    }
                    for item in (getattr(response, "output", None) or [])
                    if getattr(item, "type", "") == "function_call"
                ]
                final_input: list = [
                    *dangling,
                    {
                        "role": "user",
                        "content": (
                            "You've hit the tool-call limit for this turn. STOP "
                            "calling tools and write your reply to the user NOW "
                            "from what you've already found. If something is "
                            "still unknown, say so plainly and suggest the next "
                            "step."
                        ),
                    },
                ]
                final = _submit(final_input)
                if (getattr(final, "output_text", "") or "").strip():
                    response = final
                    run_status = "completed_at_loop_limit"
                    tool_names.append("forced_final_compose")
            except Exception as exc:  # noqa: BLE001 - never lose the turn over this
                print(f"(forced final compose failed: {exc})", flush=True)

        final_text = getattr(response, "output_text", "") or ""
        final_citations = extract_citations(response)
        # If the self-check recovered NOTHING (no new tool calls after it), it
        # had nothing to add - keep the clean PRE-check answer (and its
        # citations) and drop whatever the check re-composed (which tends to
        # leak a "Nothing was left half-done / no action was requested" self-
        # audit). When it DID recover (new tools ran), the post-recovery answer
        # is the real one - keep it.
        if (
            reflected
            and tool_count_at_reflect >= 0
            and tool_call_count == tool_count_at_reflect
            and pre_reflect_text
        ):
            final_text = pre_reflect_text
            final_citations = pre_reflect_citations
        return TurnResult(
            raw_text=final_text,
            tool_call_count=tool_call_count,
            citations=final_citations,
            run_status=run_status,
            tool_names=tool_names,
            agent_name=agent_name,
            agent_version=agent_version,
        )
    finally:
        # Keep the agent version alive while a run is suspended awaiting a
        # human approval; resume_agent_turn's completion cleans it up.
        if not suspended and agent_version is not None:
            try:
                project_client.agents.delete_version(
                    agent_name=agent_name, agent_version=agent_version
                )
            except Exception:
                pass
