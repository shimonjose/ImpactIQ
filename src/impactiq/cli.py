"""ImpactIQ command-line harness (local end-to-end, no Teams needed).

Available commands:

    whoami        identity / config status for the read-only service identity
    dump-estate   emit the normalized estate graph for one solution
    failed-flows  list recent failed cloud-flow runs
    ask           run the agent pipeline over a natural-language question

Everything is read-only against the tenant. The only outbound actions are
draft-only messages that require explicit confirmation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .connectors import (
    EstateScope,
    SolutionsConnector,
    build_estate,
)
from .connectors.flows import FlowsConnector
from .dataverse_client import DataverseClient, DataverseError
from .settings import get_settings, masked

# Single-agent imports are lazy (inside cmd_ask) so non-`ask` commands
# don't pay the azure-ai-projects import cost.


def _kv(label: str, value: str) -> None:
    print(f"  {label:<26} {value}")


def cmd_whoami(_args: argparse.Namespace) -> int:
    """Show config status for the read-only service identity.

    When the .env values are present, connects with client-credentials auth,
    reads one table, and asserts the role has no write privileges.
    """
    s = get_settings()
    print("ImpactIQ - whoami")
    print("=" * 48)
    print("Service identity (structure, read-only) - client credentials:")
    _kv("DATAVERSE_URL", s.dataverse_url or "(unset)")
    _kv("ENTRA_TENANT_ID", s.entra_tenant_id or "(unset)")
    _kv("IMPACTIQ_CLIENT_ID", s.impactiq_client_id or "(unset)")
    _kv("IMPACTIQ_CLIENT_SECRET", masked(s.impactiq_client_secret))
    print()

    missing = s.missing_service_vars()
    if missing:
        print("Status: service identity NOT configured.")
        print("Unset in .env: " + ", ".join(missing))
        print()
        print("Next: register the read-only app user + custom 'ImpactIQ")
        print("Read-Only' security role, then paste the values into .env.")
        return 0

    # Values present -> connect as the read-only service identity and verify.
    print("Status: service-identity .env values present. Connecting...")
    print()
    try:
        with DataverseClient(s) as client:
            base_url = client.base_url
            who = client.whoami()
            org = client.organization()
            table = client.first_table()
            audit = client.audit_read_only(who["UserId"])
    except DataverseError as exc:
        print("[FAIL] Could not read as the service identity:")
        print(f"  {exc}")
        return 1
    except Exception as exc:  # azure-identity / network failures
        print("[FAIL] Authentication error:")
        print(f"  {type(exc).__name__}: {exc}")
        return 1

    org_name = org.get("name") if org else "(unknown)"
    print("Connected as the read-only service identity.")
    _kv("Environment", str(org_name))
    _kv("Dataverse URL", base_url)
    _kv("App user (systemuserid)", str(who.get("UserId")))
    _kv("Sample table", table or "(none returned)")
    print()

    if audit.is_read_only:
        print(
            f"[OK] Read-only confirmed: {audit.read_privileges} read privileges, "
            f"0 write/create/delete/append/assign/share "
            f"({audit.total_privileges} total)."
        )
        return 0

    print("[FAIL] Service identity holds WRITE privileges - violates read-only.")
    print(
        f"  {len(audit.write_privileges)} write-class privileges "
        f"(of {audit.total_privileges} total). Examples:"
    )
    for name in audit.write_privileges[:15]:
        print(f"    - {name}")
    if len(audit.write_privileges) > 15:
        print(f"    ... and {len(audit.write_privileges) - 15} more")
    print()
    print("Fix: assign ONLY the custom 'ImpactIQ Read-Only' role (Org-level Read,")
    print("no Create/Write/Delete/Append/Assign/Share) to the application user.")
    print("If you temporarily assigned System Administrator, swap it back now.")
    return 1


def _open_client() -> DataverseClient | None:
    """Build a DataverseClient or print why we can't and return None."""
    s = get_settings()
    missing = s.missing_service_vars()
    if missing:
        print("Service identity not configured. Unset in .env: " + ", ".join(missing))
        print("Run `cli whoami` for details.")
        return None
    return DataverseClient(s)


def cmd_dump_estate(args: argparse.Namespace) -> int:
    """Read the full estate fragment for a solution and print as JSON."""
    if not args.solution:
        print("dump-estate requires --solution <name>")
        return 2
    client = _open_client()
    if client is None:
        return 1
    try:
        with client:
            scope, fragment = build_estate(
                client, EstateScope(solution_name=args.solution)
            )
    except DataverseError as exc:
        print(f"[FAIL] {exc}")
        return 1

    payload = {
        "scope": {
            "solution_name": scope.solution_name,
            "solution_id": scope.solution_id,
        },
        "counts": {
            "nodes": len(fragment.nodes),
            "edges": len(fragment.edges),
            "by_kind": _count_by(lambda n: n.kind, fragment.nodes),
            "by_relation": _count_by(lambda e: e.relation, fragment.edges),
        },
        "nodes": [n.model_dump(mode="json") for n in fragment.nodes],
        "edges": [e.model_dump(by_alias=True, mode="json") for e in fragment.edges],
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"Wrote {payload['counts']['nodes']} nodes / "
              f"{payload['counts']['edges']} edges to {args.output}")
        print("Counts by kind:    " + json.dumps(payload["counts"]["by_kind"]))
        print("Counts by relation:" + json.dumps(payload["counts"]["by_relation"]))
        return 0

    # Default: print the summary + a sample to stdout (full JSON can be large).
    print(f"Scope:    {scope.solution_name}  ({scope.solution_id})")
    print(f"Nodes:    {payload['counts']['nodes']}")
    print(f"  by kind:    {json.dumps(payload['counts']['by_kind'])}")
    print(f"Edges:    {payload['counts']['edges']}")
    print(f"  by relation:{json.dumps(payload['counts']['by_relation'])}")
    print()
    print("Sample nodes (first 5 of each kind):")
    seen: dict[str, int] = {}
    for n in fragment.nodes:
        c = seen.get(n.kind, 0)
        if c >= 5:
            continue
        seen[n.kind] = c + 1
        print(f"  {n.kind:>22} {n.id}  -  {n.name}")
    print()
    print("Sample edges (first 10):")
    for e in fragment.edges[:10]:
        print(f"  {e.from_} --{e.relation}--> {e.to}")
    if args.output is None:
        print()
        print("Use --output <path.json> to write the full fragment.")
    return 0


def cmd_failed_flows(args: argparse.Namespace) -> int:
    """List recent failed cloud-flow runs."""
    client = _open_client()
    if client is None:
        return 1
    try:
        with client:
            runs = FlowsConnector(client).list_failed_runs(hours=args.hours)
    except DataverseError as exc:
        msg = str(exc)
        print(f"[FAIL] {msg}")
        if "flowrun" in msg.lower() or "not found" in msg.lower() or "404" in msg:
            print()
            print("Hint: enable 'Cloud flow run history in Dataverse' in PPAC:")
            print("  Power Platform admin center -> environment -> Settings ->")
            print("  Product -> Features -> 'Cloud flow run history in Dataverse'.")
        return 1
    print(f"Failed flow runs in the last {args.hours}h: {len(runs)}")
    for r in runs[:50]:
        print(
            f"  {r.get('starttime', '?')}  workflow={r.get('_workflow_value')}  "
            f"err={r.get('errorcode')}  msg={(r.get('errormessage') or '')[:120]}"
        )
    if len(runs) > 50:
        print(f"  ... and {len(runs) - 50} more")
    return 0


def cmd_deps(args: argparse.Namespace) -> int:
    """Walk dependencies on (componentType, objectId) in one direction.

    Mirrors the engine's primary move - walk both dependents (`down`) and
    dependencies (`up`); plus `delete` for `RetrieveDependenciesForDelete`.
    """
    client = _open_client()
    if client is None:
        return 1
    sols = SolutionsConnector(client)
    try:
        with client:
            if args.direction == "down":
                rows = sols.retrieve_dependent_components(args.objectId, args.componentType)
            elif args.direction == "up":
                rows = sols.retrieve_required_components(args.objectId, args.componentType)
            elif args.direction == "delete":
                rows = sols.retrieve_dependencies_for_delete(args.objectId, args.componentType)
            else:
                print(f"unknown --direction {args.direction!r}")
                return 2
    except DataverseError as exc:
        print(f"[FAIL] {exc}")
        return 1

    print(
        f"deps {args.direction} on (componentType={args.componentType}, "
        f"objectId={args.objectId}): {len(rows)} row(s)"
    )
    for r in rows[:50]:
        dep_t = r.get("dependentcomponenttype")
        dep_o = r.get("dependentcomponentobjectid")
        req_t = r.get("requiredcomponenttype")
        req_o = r.get("requiredcomponentobjectid")
        print(
            f"  dep ({dep_t}) {dep_o} --depends_on--> req ({req_t}) {req_o}"
        )
    if len(rows) > 50:
        print(f"  ... and {len(rows) - 50} more")
    return 0


def _count_by(key, items):
    counts: dict[str, int] = {}
    for it in items:
        k = key(it)
        counts[k] = counts.get(k, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def cmd_ask(args: argparse.Namespace) -> int:
    """Run the agent pipeline on a natural-language question."""
    if not args.question:
        print("ask requires a question, e.g. `cli ask \"why is flow X failing?\"`")
        return 2

    s = get_settings()
    if s.missing_service_vars():
        print("Service identity not configured; run `cli whoami` to see what's missing.")
        return 1
    if not s.foundry_project_endpoint or not s.foundry_model_deployment:
        print("Foundry not configured. Required in .env:")
        print("  FOUNDRY_PROJECT_ENDPOINT  -  project endpoint URL")
        print("  FOUNDRY_MODEL_DEPLOYMENT  -  model deployment name")
        return 1

    # Lazy import - keeps `whoami` / `dump-estate` / `deps` fast.
    from .report.schema import ImpactReport

    single = getattr(args, "single", False)
    if single:
        from .agents.single_agent import ask
    else:
        from .agents.multi_agent import ask_multi as ask

    print(f"Scope:    solution '{args.solution}'")
    print(f"Question: {args.question}")
    print(f"Pipeline: {'single agent (baseline)' if single else 'multi-agent (orchestrator + 3 specialists + adjudicator)'}")
    print("(pre-warming estate, then dispatching...)\n")

    if getattr(args, "as_user", False) and not s.foundry_workiq_connection_id:
        print(
            "Note: --as-user set but FOUNDRY_WORKIQ_CONNECTION_ID is empty in "
            ".env - running delegated but WITHOUT the Work IQ tool."
        )

    try:
        result = ask(
            s,
            solution_name=args.solution,
            question=args.question,
            as_user=getattr(args, "as_user", False),
        )
    except DataverseError as exc:
        print(f"[FAIL] Dataverse error before the agent ran: {exc}")
        return 1
    except Exception as exc:
        print(f"[FAIL] {type(exc).__name__}: {exc}")
        return 1

    print(f"Run status:      {result.run_status}")
    print(f"Tool calls seen: {result.tool_call_count}"
          + (f" ({', '.join(result.tool_names)})" if result.tool_names else ""))
    print()

    if result.report is None:
        print("Agent returned no parseable ImpactReport. Raw response:")
        print(result.raw_text or "(empty)")
        return 1

    # Validate against the ImpactReport schema; print the validated view.
    try:
        report = ImpactReport.model_validate(result.report)
    except Exception as exc:
        print("Agent JSON did not validate against ImpactReport schema:")
        print(f"  {type(exc).__name__}: {exc}")
        print("Raw JSON:")
        print(json.dumps(result.report, indent=2))
        return 1

    if getattr(args, "save_report", None):
        Path(args.save_report).write_text(
            report.model_dump_json(indent=2), encoding="utf-8"
        )
        print(f"(validated report saved to {args.save_report})")

    print("=" * 64)
    print(f"ImpactReport ({report.intent})")
    print("=" * 64)
    print(f"Anchor:     {report.anchor.kind}  {report.anchor.id}  -  {report.anchor.name}")
    print(f"Verdict:    {report.verdict}")
    print(f"Confidence: {report.confidence:.2f}")
    if report.reconciliation:
        print(f"Reasoning:  {report.reconciliation}")
    print()
    print(f"Risk: {report.risk.score}/100 ({report.risk.level})")
    for r in report.risk.reasons:
        print(f"  - {r}")
    print()
    if report.impacted_components:
        print(f"Impacted components ({len(report.impacted_components)}):")
        for c in report.impacted_components[:15]:
            print(f"  - {c.kind:>20} {c.id}  -  {c.name}")
        if len(report.impacted_components) > 15:
            print(f"  ... and {len(report.impacted_components) - 15} more")
        print()
    if report.affected_teams:
        print("Affected teams: " + ", ".join(report.affected_teams))
        print()
    if report.evidence:
        print(f"Evidence ({len(report.evidence)}):")
        for e in report.evidence:
            print(f"  [{e.kind}] {e.detail}")
        print()
    if report.change_collisions:
        print(f"Change collisions ({len(report.change_collisions)}):")
        for coll in report.change_collisions:
            print(f"  {coll.sensitivity:>10}  {coll.component.name}  ({coll.who or '?'})  {coll.advice}")
        print()
    if report.interim_actions:
        print("Interim actions:")
        for a in report.interim_actions:
            print(f"  - {a}")
        print()
    print(f"Recommendation: {report.recommendation}")
    if report.generated_artifact:
        print()
        try:
            from .report.artifacts import parse_artifact

            _print_artifact(parse_artifact(report.generated_artifact))
        except Exception as exc:
            print(f"Generated artifact present but failed strict parse: {exc}")
    if report.citations:
        print()
        print(f"Citations (agent-asserted, {len(report.citations)}):")
        for c in report.citations:
            print(f"  - {c.source_id}  {c.title or ''}  {c.url or ''}")

    # Runtime-detected citations (URL annotations on the response output) -
    # the ground truth from the MCP tool's actual returns. Useful as a
    # cross-check on what the agent SAYS it cited.
    runtime_citations = result.citations
    if runtime_citations:
        print()
        print(f"Citations (runtime URL annotations, {len(runtime_citations)}):")
        for c in runtime_citations:
            print(
                f"  - {c.get('source_id') or '?'}  "
                f"{c.get('title') or ''}  {c.get('url') or ''}"
            )
        if not report.citations:
            print()
            print(
                "Note: the runtime saw citations but the agent didn't carry "
                "them into the ImpactReport JSON. Tighten the agent prompt "
                "if this recurs."
            )
    elif report.intent == "DIAGNOSE" and report.citations == []:
        print()
        print(
            "Note: this DIAGNOSE answer has no citations. Either the "
            "Foundry IQ KB returned nothing relevant, or the agent didn't "
            "consult it. (Check the run log if surprised.)"
        )
    return 0


def _print_artifact(artifact) -> None:
    """Human-readable bounded-write preview of a typed artifact. Never executes."""
    t = artifact.artifact_type
    print(f"Generated artifact: {t}  (draft-only - nothing is executed or sent)")
    if t == "remediation_proposal":
        print(f"  Record:  {artifact.record_table} / {artifact.record_name or artifact.record_id}")
        for k, v in artifact.identifying_columns.items():
            print(f"           {k}: {v}")
        print("  Changes (current -> proposed):")
        for ch in artifact.changes:
            proposed = (
                ch.proposed_value
                if ch.proposed_value is not None
                else " | ".join(ch.options) + "  (options - user must choose)"
            )
            print(f"    {ch.column}: {ch.current_value!r} -> {proposed!r}")
        for line in artifact.downstream_preview:
            print(f"  Downstream: {line}")
        print(f"  Evidence: {artifact.evidence_source}  |  confirmation required: {artifact.confirmation}")
        if artifact.evidence_source == "document":
            print(f"  Source doc:  {artifact.document_name}")
            print(f"  Source span: \"{artifact.source_span}\"")
    elif t == "manager_handoff":
        print(f"  To: {artifact.recipient}  (named via {artifact.recipient_source})")
        print(f"  Draft: {artifact.draft_text}")
        b = artifact.baton
        anchor_name = b.anchor.name if b.anchor else "(unspecified)"
        print(f"  Baton: {b.baton_id}  anchor={anchor_name}  from={b.requesting_user}  risk={b.risk_level}")
    elif t == "draft_teams_intro":
        print(f"  To: {artifact.recipient}  (named via {artifact.recipient_source})")
        print(f"  Draft: {artifact.draft_text}")
    elif t == "dev_ticket":
        print(f"  Title:    {artifact.title}  [{artifact.severity}]")
        if artifact.component:
            print(f"  Component: {artifact.component.kind} {artifact.component.name}")
        if artifact.description:
            print(f"  Description: {artifact.description}")
        if artifact.root_cause:
            print(f"  Root cause: {artifact.root_cause}")
        if artifact.evidence_summary:
            print(f"  Evidence: {artifact.evidence_summary}")
        if artifact.suggested_fix:
            print(f"  Suggested fix: {artifact.suggested_fix}")
        for ac in artifact.acceptance_criteria:
            print(f"  AC: {ac}")
    elif t == "backfill_blueprint":
        print(f"  Query ({artifact.query_language}): {artifact.query}")
        print(f"  Records (est.): {artifact.estimated_record_count}")
        print(f"  Idempotency: {artifact.idempotency_note}")
        print(f"  Approver: {artifact.suggested_approver}  -> routed via {artifact.routed_via}")
    elif t == "reuse_blueprint":
        print(f"  Recommendation: {artifact.recommendation}")
        for step in artifact.steps:
            print(f"  - {step}")


def _load_report(path: str):
    from .report.schema import ImpactReport

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ImpactReport.model_validate(data)


def cmd_artifact_inspect(args: argparse.Namespace) -> int:
    """Bounded-write preview of a saved report's artifact, without executing anything."""
    from .report.artifacts import parse_artifact

    report = _load_report(args.report)
    if not report.generated_artifact:
        print("Report carries no generated_artifact.")
        return 1
    try:
        artifact = parse_artifact(report.generated_artifact)
    except Exception as exc:
        print(f"Artifact failed strict parse: {exc}")
        return 1
    _print_artifact(artifact)
    return 0


def cmd_artifact_card(args: argparse.Namespace) -> int:
    """Render a saved report as Adaptive Card JSON (the Teams surface posts it)."""
    from .report.card import report_to_adaptive_card

    report = _load_report(args.report)
    card = report_to_adaptive_card(report)
    out = json.dumps(card, indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"(card JSON written to {args.out})")
    else:
        print(out)
    return 0


def _extract_baton(report) -> dict | None:
    art = report.generated_artifact or {}
    if art.get("artifact_type") == "manager_handoff" and isinstance(art.get("baton"), dict):
        return art["baton"]
    return None


def cmd_baton_inspect(args: argparse.Namespace) -> int:
    report = _load_report(args.report)
    baton = _extract_baton(report)
    if baton is None:
        print("No manager_handoff baton in this report.")
        return 1
    from .report.artifacts import ContextBaton

    b = ContextBaton.model_validate(baton)
    print(f"Baton:        {b.baton_id}  (v{b.baton_version}, {b.created_utc})")
    print(f"From:         {b.requesting_user}")
    print(f"Intent:       {b.intent}")
    if b.anchor:
        print(f"Anchor:       {b.anchor.kind}  {b.anchor.id}  -  {b.anchor.name}")
    print(f"Proposal:     {b.proposed_change}")
    print(f"Risk:         {b.risk_level}")
    if b.impacted_components:
        print(f"Impacted ({len(b.impacted_components)}):")
        for c in b.impacted_components[:10]:
            print(f"  - {c.kind:>16} {c.name}")
    if b.resume_hint:
        print(f"Resume hint:  {b.resume_hint}")
    return 0


def cmd_baton_resume(args: argparse.Namespace) -> int:
    """Stubbed 'manager session': rebuild the question from the baton and run
    the pipeline as the CURRENT identity. The receiving user's own
    permissions/Work IQ supply their side of the context - that's the whole
    point of the handoff design."""
    report = _load_report(args.report)
    baton = _extract_baton(report)
    if baton is None:
        print("No manager_handoff baton in this report.")
        return 1
    from .report.artifacts import ContextBaton

    b = ContextBaton.model_validate(baton)
    anchor_bit = f"{b.anchor.name} ({b.anchor.kind})" if b.anchor else "the flagged component"
    impacted = ", ".join(c.name for c in b.impacted_components[:8]) or anchor_bit
    question = (
        f"[Handoff resume - baton {b.baton_id}] {b.requesting_user} proposes: "
        f"{b.proposed_change}. The dependency map flagged possible impact on "
        f"{anchor_bit} and: {impacted}. As the receiving "
        "owner, assess the impact on assets I own and surface any of MY "
        "active work that collides with this proposal. "
        f"(Original intent: {b.intent}; original risk: {b.risk_level}.)"
    )
    print(f"Resuming as the current identity with baton {b.baton_id}...")
    resume_args = argparse.Namespace(
        question=question,
        solution=args.solution,
        as_user=getattr(args, "as_user", False),
        save_report=getattr(args, "save_report", None),
    )
    return cmd_ask(resume_args)


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the local HTTP bridge the Teams agent (surface/) talks to."""
    from .server import serve

    print(f"ImpactIQ bridge listening on http://{args.host}:{args.port}")
    print("(the Teams surface in surface/ posts /ask and card actions here)")
    serve(host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="impactiq",
        description="ImpactIQ - read-only Power Platform impact & change intelligence.",
    )
    parser.add_argument("--version", action="version", version=f"impactiq {__version__}")

    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    p_whoami = sub.add_parser(
        "whoami", help="show identity / config status"
    )
    p_whoami.set_defaults(func=cmd_whoami)

    p_dump = sub.add_parser(
        "dump-estate", help="emit the estate graph for one solution"
    )
    p_dump.add_argument(
        "--solution",
        required=True,
        help="solution friendlyname or uniquename to scope to",
    )
    p_dump.add_argument(
        "--output",
        help="write the full fragment as JSON to this path (default: stdout summary)",
    )
    p_dump.set_defaults(func=cmd_dump_estate)

    p_failed = sub.add_parser(
        "failed-flows", help="list recent failed cloud-flow runs"
    )
    p_failed.add_argument(
        "--hours", type=int, default=24, help="lookback window in hours (default 24)"
    )
    p_failed.set_defaults(func=cmd_failed_flows)

    p_deps = sub.add_parser(
        "deps",
        help="walk dependencies on (componentType, objectId)",
    )
    p_deps.add_argument("componentType", type=int, help="solution componenttype int (e.g. 29 = Workflow)")
    p_deps.add_argument("objectId", help="component objectid (GUID)")
    p_deps.add_argument(
        "--direction",
        choices=("down", "up", "delete"),
        default="down",
        help="down = RetrieveDependentComponents, up = RetrieveRequiredComponents, "
             "delete = RetrieveDependenciesForDelete",
    )
    p_deps.set_defaults(func=cmd_deps)

    p_ask = sub.add_parser(
        "ask", help="run the agent pipeline over a question"
    )
    p_ask.add_argument("question", help="natural-language question")
    p_ask.add_argument(
        "--solution",
        default=get_settings().solution,
        help="solution to scope the estate to (default: $IMPACTIQ_SOLUTION)",
    )
    p_ask.add_argument(
        "--as-user",
        action="store_true",
        dest="as_user",
        help=(
            "run the agent as the signed-in user (browser sign-in on first "
            "use) and attach the Work IQ tool. Without this flag the agent "
            "runs on the service principal, engine + KB only."
        ),
    )
    p_ask.add_argument(
        "--save-report",
        dest="save_report",
        default=None,
        help="write the validated ImpactReport JSON here (input for `artifact` / `baton` commands).",
    )
    p_ask.add_argument(
        "--single",
        action="store_true",
        dest="single",
        help="bypass the multi-agent pipeline and run the single-agent baseline.",
    )
    p_ask.set_defaults(func=cmd_ask)

    p_art = sub.add_parser(
        "artifact", help="inspect a saved report's generated artifact (draft-only, never executes)"
    )
    art_sub = p_art.add_subparsers(dest="artifact_cmd", required=True)
    p_art_inspect = art_sub.add_parser(
        "inspect", help="pretty-print the artifact incl. the bounded-write preview"
    )
    p_art_inspect.add_argument("report", help="path to a saved ImpactReport JSON (ask --save-report)")
    p_art_inspect.set_defaults(func=cmd_artifact_inspect)
    p_art_card = art_sub.add_parser("card", help="render the report as Adaptive Card JSON")
    p_art_card.add_argument("report", help="path to a saved ImpactReport JSON")
    p_art_card.add_argument("-o", "--out", default=None, help="write card JSON to this path")
    p_art_card.set_defaults(func=cmd_artifact_card)

    p_baton = sub.add_parser("baton", help="round-trip the manager-handoff context baton")
    baton_sub = p_baton.add_subparsers(dest="baton_cmd", required=True)
    p_b_inspect = baton_sub.add_parser("inspect", help="show the baton carried by a manager_handoff report")
    p_b_inspect.add_argument("report", help="path to a saved ImpactReport JSON")
    p_b_inspect.set_defaults(func=cmd_baton_inspect)
    p_b_resume = baton_sub.add_parser(
        "resume",
        help="stubbed manager session: resume the analysis from the baton as the CURRENT identity",
    )
    p_b_resume.add_argument("report", help="path to a saved ImpactReport JSON")
    p_b_resume.add_argument(
        "--solution",
        default=get_settings().solution,
        help="solution to scope the resumed estate to (default: $IMPACTIQ_SOLUTION)",
    )
    p_b_resume.add_argument("--as-user", action="store_true", dest="as_user")
    p_b_resume.add_argument("--save-report", dest="save_report", default=None)
    p_b_resume.set_defaults(func=cmd_baton_resume)

    p_serve = sub.add_parser(
        "serve", help="run the local HTTP bridge for the Teams surface"
    )
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8787)
    p_serve.set_defaults(func=cmd_serve)

    p_builder = sub.add_parser(
        "builder", help="sandbox fix executor"
    )
    builder_sub = p_builder.add_subparsers(dest="builder_cmd", required=True)
    p_bl_flow = builder_sub.add_parser(
        "locate-flow", help="find a cloud flow in the sandbox solution (read-only)"
    )
    p_bl_flow.add_argument("name", help="the flow's display name")
    p_bl_flow.set_defaults(func=cmd_builder_locate_flow)
    p_bl_state = builder_sub.add_parser("flow-state", help="turn a sandbox flow on/off")
    p_bl_state.add_argument("name", help="the flow's display name")
    p_bl_state.add_argument("state", choices=["on", "off"])
    p_bl_state.set_defaults(func=cmd_builder_flow_state)
    p_bl_fix = builder_sub.add_parser("fix", help="run a FixSpec JSON file")
    p_bl_fix.add_argument("spec", help="path to a FixSpec JSON ({'ops': [...]})")
    p_bl_fix.set_defaults(func=cmd_builder_fix)

    return parser


def cmd_builder_locate_flow(args) -> int:
    from .builder.executor import SandboxClient, locate_flow
    from .settings import get_settings

    s = get_settings()
    with SandboxClient(s) as client:
        flow = locate_flow(client, (s.impactiq_build_solution or "").strip(), args.name)
    state = "on" if flow["statecode"] == 1 else "off"
    print(f"found: {flow['name']}  id={flow['workflowid']}  state={state}")
    print(f"clientdata: {len(flow.get('clientdata') or '')} chars")
    return 0


def cmd_builder_flow_state(args) -> int:
    from .builder.executor import SandboxClient, set_flow_state
    from .settings import get_settings

    s = get_settings()
    with SandboxClient(s) as client:
        done = set_flow_state(
            client, (s.impactiq_build_solution or "").strip(), args.name, args.state
        )
    print(f"ok: {done['component']} - {done['change']}")
    return 0


def cmd_builder_fix(args) -> int:
    import json as _json

    from .builder.executor import run_fixspec
    from .settings import get_settings

    spec = _json.loads(open(args.spec, encoding="utf-8").read())
    report = run_fixspec(get_settings(), spec)
    print(_json.dumps(report.to_dict(), indent=2))
    return 0 if not report.outstanding else 1


def main(argv: list[str] | None = None) -> int:
    # Reconfigure stdout to UTF-8 so the model's Unicode output (arrows, em
    # dashes, curly quotes) doesn't crash the printer on Windows cp1252.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
