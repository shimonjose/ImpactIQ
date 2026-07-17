"""Deterministic post-adjudication verdict gate.

The adjudicator's verdict is the one place a reasoning error becomes a
user-facing answer, and - unlike artifacts, which `validate_artifact_payload`
re-checks server-side - nothing downstream re-validates it. This module is the
verdict's equivalent of that gate: a pure-Python, ~zero-latency pass that
re-checks the report against the SAME ground truth the specialists produced,
before the card renders. No LLM, no network, can't be bypassed.

Mode is selected by the IMPACTIQ_VERDICT_GATE environment variable:

* ``shadow`` (default - also what unset means): compute every would-be action,
  log a summary, and return ``report_dict`` UNCHANGED. Output is identical to a
  run without the gate. This is the safe default: enable enforce only once
  evaluation shows the gate strips only genuinely-ungrounded content.
* ``enforce``: actually apply the corrections - drop ungrounded citations,
  strip unprovenanced owner/team names, raise the risk floor under a freeze.
* ``off``: skip the gate entirely (no compute, no log).

Three rules, each grounded in data the run already has - never the model's word:

1. **Citation grounding.** A report ``citations[]`` entry survives only if its
   ``source_id`` is in the union of RUNTIME citations (the adjudicator's
   response annotations + each specialist's runtime citations, extracted from
   real response annotations in ``agents/loop.py``). Kills invented policy
   references. NOTE: the model's self-reported ``KnowledgeFinding.citations``
   are deliberately NOT treated as ground truth - only annotation-backed
   citations are - which is exactly why shadow is the default: if a legitimate
   KB hit fails to surface as an annotation the over-strip SHOWS UP in the
   logs before ever enforcing.
2. **Owner/people provenance.** A name in ``affected_teams`` /
   ``affected_people`` / a collision's ``who`` must trace to a typed specialist
   field (``ContextFinding.affected_people`` / ``likely_owner`` /
   ``active_change_signals[].owner_or_team``; ``TechnicalFinding``
   ``recent_editors[].modified_by``) or appear in a finding's evidence text. A
   guessed owner is a leak; an unknown owner is honest. The solution name is
   never a team - it is stripped from ``affected_teams`` outright.
3. **Adjudication invariants.**
   * *Change-control dominance* (rule ``change_control_dominance``): a non-empty
     ``ContextFinding.change_control`` - ANY active directive that gates changes
     now: a freeze/moratorium, an approval/sign-off gate, a change board (CAB), a
     release embargo/blackout, an incident no-deploy window - forces
     ``risk.level`` to at least ``medium`` (auto-corrected) and requires the
     recommendation to honour it (flagged for repair if missing - text is never
     fabricated here). CURRENT-ONLY: a directive that reads as already
     lifted/rescinded/cleared is ignored (it has a timeline; once lifted it is
     not an active blocker).
   * *Defect-vs-expected flip*: Knowledge says ``expected_per_policy`` while
     Technical flagged a defect, but the verdict still reads as a plain defect
     → flagged (a verdict cannot be deterministically rewritten; the flag feeds
     the conditional critic).

LIMITATION - provenance source set. ``resolve_owner`` tool RESULTS are not
structurally captured (they live in the technical specialist's free-text
evidence), so the allowed-name set is built from the TYPED finding fields PLUS
a normalized blob of all finding text. Matching is therefore deliberately
lenient (a name is grounded if it appears ANYWHERE in any finding) - the bar is
"genuinely invented out of thin air", which is the leak that matters, while a
legitimately-resolved owner that only shows up in evidence is preserved. The
provenance rule is skipped entirely when there are no specialist findings to
compare against (e.g. the single-agent path) rather than stripping every
name on no evidence. This conservatism is *why* enforce mode should follow an
evaluation pass rather than be flipped on blind.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass

# Risk band floor for the freeze auto-correct: the scorer's `_level` puts
# `medium` at score >= 35 (graph/risk.py). Keep the two in sync.
_MEDIUM_SCORE_FLOOR = 35

# Tokens that carry no identifying signal in an owner/team name - ignored when
# checking whether a name is grounded in the findings.
_NAME_STOPWORDS = frozenset(
    {
        "team", "teams", "group", "dept", "department", "unit", "div",
        "division", "the", "and", "of", "for", "owner", "owners", "user",
        "users", "customer", "colleague", "internal", "approver", "manager",
        "business", "bu",
    }
)

# Words that signal the recommendation HONOURS an active change-control directive
# (of ANY kind - a freeze is just one). The directive class: anything that gates
# making changes right now - freeze/moratorium, an approval/sign-off gate, a
# change board (CAB), a release embargo/blackout, an incident "no-deploy" window.
_HOLD_DIRECTIVE_WORDS = (
    "hold", "freeze", "pause", "wait", "do not proceed", "don't proceed",
    "moratorium", "stand down", "postpone", "defer", "halt",
    "await approval", "needs approval", "needs sign-off", "needs signoff",
    "sign-off", "approval", "embargo", "blackout", "do not deploy",
    "don't deploy", "coordinate", "change board", "cab", "after the incident",
)

# Phrases that mark a change-control directive as ALREADY LIFTED / no longer in
# effect. A directive is an event with a timeline - once rescinded (a freeze
# lifted, an approval granted, an embargo cleared) it is NOT an active blocker,
# so the gate must not amplify it (current-only, and generalised beyond
# freeze to any directive class).
_LIFTED_MARKERS = (
    "lifted", "rescinded", "rescind", "resumed", "unfrozen", "no longer frozen",
    "no longer in effect", "no longer applies", "no longer apply",
    "no longer required", "no longer needed", "superseded",
    "approval granted", "approved and cleared", "signed off", "sign-off received",
    "cleared to proceed", "embargo lifted", "embargo over", "blackout over",
    "incident resolved", "incident cleared",
    "freeze over", "freeze is over", "freeze ended", "freeze has ended",
    "moratorium over", "moratorium ended", "back to normal",
    "changes allowed", "changes are allowed", "can resume", "now allowed",
    "freeze removed", "freeze withdrawn", "freeze cancelled", "freeze canceled",
    "hold lifted", "hold removed",
)
# Future-tense lifts ("will be lifted next week") mean the directive is STILL
# active right now - don't treat those as lifted.
_FUTURE_LIFT = ("will be lifted", "to be lifted", "will lift", "going to lift",
                "lifts on", "lifts next", "scheduled to lift")


def _directive_is_lifted(text: str) -> bool:
    low = text.lower()
    if not any(m in low for m in _LIFTED_MARKERS):
        return False
    if any(f in low for f in _FUTURE_LIFT):
        return False  # announced lift is in the future → still in effect now
    return True

# Words in a technical likely_cause that read like a defect (vs. a benign
# observation), used by the defect-vs-expected flip check.
_DEFECT_WORDS = (
    "broken", "wrong", "missing", "fail", "defect", "redundant", "incorrect",
    "error", "misconfigur", "bug", "should have", "never ran", "didn't run",
    "did not run", "not firing",
)


@dataclass
class GateFinding:
    """One thing the gate noticed. ``applied`` is True only when enforce mode
    actually changed the report; in shadow mode every finding is ``applied=False``
    (computed and logged, nothing mutated).

    ``field``/``target`` carry the exact report field and value the enforce pass
    should act on, so the corrections never round-trip through the detail text."""

    rule: str        # citation_grounding | owner_provenance | change_control_dominance | defect_expected_flip | gate_error
    action: str      # drop | strip | raise_risk | flag
    detail: str
    applied: bool = False
    field: str = ""        # report key the correction targets (e.g. "affected_teams")
    target: object = None  # the precise value to drop/strip (a source_id or a name)


def _mode(explicit: str | None) -> str:
    raw = (explicit if explicit is not None else os.environ.get("IMPACTIQ_VERDICT_GATE") or "").strip().lower()
    if raw in ("enforce", "1", "on", "true", "yes"):
        return "enforce"
    if raw in ("off", "disable", "disabled", "no"):
        return "off"
    return "shadow"


def _norm(s: object) -> str:
    """Lowercase, drop role tags in parens, collapse to alphanumerics+spaces."""
    text = str(s or "")
    text = re.sub(r"\(.*?\)", " ", text)          # drop "(customer)" etc.
    text = re.sub(r"[^0-9a-zA-Z\s]", " ", text).lower()
    return re.sub(r"\s+", " ", text).strip()


def _name_tokens(name: str) -> list[str]:
    return [t for t in _norm(name).split() if len(t) >= 3 and t not in _NAME_STOPWORDS]


def _finding_for(results: list[dict] | None, agent: str) -> dict:
    for r in results or []:
        if r.get("agent") == agent and isinstance(r.get("finding"), dict):
            return r["finding"]
    return {}


def _collect_strings(obj: object, out: list[str]) -> None:
    """Recursively pull every string value out of a finding for the blob."""
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _collect_strings(v, out)


def _provenance_blob(results: list[dict] | None) -> str:
    parts: list[str] = []
    for r in results or []:
        f = r.get("finding")
        if isinstance(f, dict):
            _collect_strings(f, parts)
    return _norm(" ".join(parts))


def _is_grounded_name(name: str, blob: str) -> bool:
    """A name is grounded if it appears anywhere in the findings blob - either
    as a whole normalized substring, or by all its distinctive tokens."""
    norm = _norm(name)
    if not norm:
        return True  # nothing to judge; never strip an empty/symbolic entry
    if norm in blob:
        return True
    tokens = _name_tokens(name)
    if tokens:
        return all(t in blob for t in tokens)
    # No distinctive tokens (e.g. a 2-letter name); fall back to substring only.
    return norm in blob


def gate_report(
    plan: dict,
    results: list[dict] | None,
    report_dict: dict,
    *,
    runtime_citations: list[dict] | None = None,
    solution_name: str | None = None,
    mode: str | None = None,
) -> tuple[dict, list[GateFinding]]:
    """Re-validate the adjudicated report against the run's ground truth.

    Returns ``(report, findings)``. In shadow mode ``report`` is the SAME object
    passed in (unchanged); in enforce mode it is a corrected COPY. ``findings``
    lists everything noticed (logged in shadow, used by the conditional critic).

    Never raises: any internal error is itself returned as a ``gate_error``
    finding and the original report is passed through untouched - the gate must
    never take down a turn.
    """
    resolved = _mode(mode)
    if resolved == "off" or not isinstance(report_dict, dict):
        return report_dict, []

    try:
        findings = _evaluate(plan, results, report_dict, runtime_citations, solution_name)
    except Exception as exc:  # noqa: BLE001 - the gate must never crash the turn
        return report_dict, [GateFinding("gate_error", "flag", f"{type(exc).__name__}: {exc}")]

    enforce = resolved == "enforce"
    if not enforce:
        if findings:
            _log(findings, applied=False)
        return report_dict, findings

    # Enforce: apply the corrections on a COPY so a caller holding the original
    # (e.g. for an audit snapshot) is unaffected.
    out = copy.deepcopy(report_dict)
    _apply(out, findings)
    _log(findings, applied=True)
    return out, findings


def _evaluate(
    plan: dict,
    results: list[dict] | None,
    report_dict: dict,
    runtime_citations: list[dict] | None,
    solution_name: str | None,
) -> list[GateFinding]:
    findings: list[GateFinding] = []

    # ── Rule 1: citation grounding ───────────────────────────────────────────
    grounded_ids: set = set()
    for c in runtime_citations or []:
        if isinstance(c, dict):
            grounded_ids.add(c.get("source_id"))
    for r in results or []:
        # Runtime (annotation-backed) citations from the specialist's turn.
        for c in r.get("citations") or []:
            if isinstance(c, dict):
                grounded_ids.add(c.get("source_id"))
        # ALSO the citations the specialist reported INSIDE its finding. The
        # Foundry-IQ KB MCP returns file-citation ids through the knowledge
        # finding's `citations` field, NOT as response annotations - so without
        # this the gate false-flags every real KB citation as ungrounded (in
        # enforce mode it would drop legitimate SOP/policy
        # references). Finding citations are first-class ground truth:
        # the knowledge specialist's whole job is KB retrieval. This still
        # catches an ADJUDICATOR citation that matches NEITHER a runtime
        # annotation NOR any specialist finding (the real hallucination case).
        finding = r.get("finding")
        if isinstance(finding, dict):
            for c in finding.get("citations") or []:
                if isinstance(c, dict):
                    grounded_ids.add(c.get("source_id"))
    for c in report_dict.get("citations") or []:
        sid = c.get("source_id") if isinstance(c, dict) else None
        if sid not in grounded_ids:
            findings.append(
                GateFinding(
                    "citation_grounding", "drop",
                    f"report cites source_id={sid!r} not present in any runtime "
                    "(annotation-backed) citation - ungrounded reference",
                    field="citations", target=sid,
                )
            )

    # ── Rule 2: owner/people provenance ──────────────────────────────────────
    have_source = any(
        r.get("agent") in ("technical", "context") and isinstance(r.get("finding"), dict)
        for r in results or []
    )
    if have_source:
        blob = _provenance_blob(results)
        sol_norm = _norm(solution_name) if solution_name else ""
        for field in ("affected_teams", "affected_people"):
            for name in report_dict.get(field) or []:
                if sol_norm and _norm(name) == sol_norm:
                    findings.append(
                        GateFinding(
                            "owner_provenance", "strip",
                            f"{field}: {name!r} is the solution name, which is "
                            "never a team",
                            field=field, target=name,
                        )
                    )
                elif not _is_grounded_name(str(name), blob):
                    findings.append(
                        GateFinding(
                            "owner_provenance", "strip",
                            f"{field}: {name!r} traces to no specialist finding "
                            "- an unverified owner/team name (possible guess/leak)",
                            field=field, target=name,
                        )
                    )
        for col in report_dict.get("change_collisions") or []:
            who = col.get("who") if isinstance(col, dict) else None
            if who and not _is_grounded_name(str(who), blob):
                findings.append(
                    GateFinding(
                        "owner_provenance", "strip",
                        f"change_collision who={who!r} traces to no specialist "
                        "finding - an unverified name",
                        field="change_collisions", target=who,
                    )
                )

    # ── Rule 3a: change-control dominance ────────────────────────────────────
    # A freeze is only ONE kind of directive that gates changes right now - so
    # are an approval/sign-off gate, a change board (CAB), a release embargo /
    # blackout, an incident no-deploy window. ANY active one dominates the
    # technical risk; the rule is named for the general class, not freeze.
    # Current-only: a directive that was LIFTED (freeze rescinded, approval
    # granted, embargo cleared) is not active - the defensive backstop to the
    # context brief's supersession check.
    ctx = _finding_for(results, "context")
    change_control = [
        c for c in (ctx.get("change_control") or [])
        if c and not _directive_is_lifted(str(c))
    ]
    if change_control:
        risk = report_dict.get("risk") or {}
        level = (risk.get("level") or "").lower()
        if level == "low":
            findings.append(
                GateFinding(
                    "change_control_dominance", "raise_risk",
                    "an active change-control directive is in effect "
                    f"({change_control[0]!r}) but risk.level is 'low' - an active "
                    "directive overrides the technical score, floor is medium",
                )
            )
        rec = (report_dict.get("recommendation") or "").lower()
        if not any(w in rec for w in _HOLD_DIRECTIVE_WORDS):
            findings.append(
                GateFinding(
                    "change_control_dominance", "flag",
                    "an active change-control directive is in effect but the "
                    "recommendation does not honour it (no hold / await-approval / "
                    "coordinate directive) - verdict ignores the directive",
                )
            )

    # ── Rule 3b: defect-vs-expected flip ─────────────────────────────────────
    know = _finding_for(results, "knowledge")
    tech = _finding_for(results, "technical")
    k_verdict = (know.get("governance_verdict") or "").lower()
    if k_verdict == "expected_per_policy" and tech:
        lc = (tech.get("likely_cause") or "").lower()
        raw_risk = tech.get("raw_risk") or {}
        tech_defect = bool(lc) and (
            any(w in lc for w in _DEFECT_WORDS)
            or (raw_risk.get("level") in ("medium", "high"))
        )
        if tech_defect:
            blob = " ".join(
                str(report_dict.get(k) or "") for k in ("verdict", "reconciliation")
            ).lower()
            flipped = (
                "expected" in blob
                and any(w in blob for w in ("policy", "sop", "documented", "by design", "standard"))
            ) or bool(report_dict.get("citations"))
            if not flipped:
                findings.append(
                    GateFinding(
                        "defect_expected_flip", "flag",
                        "Knowledge says expected_per_policy and Technical flagged "
                        "a defect, but the verdict does not read as "
                        "expected-per-policy - possible un-flipped defect",
                    )
                )

    return findings


def _apply(report: dict, findings: list[GateFinding]) -> None:
    """Mutate ``report`` in place per the findings (enforce mode only). Every
    correction acts on the finding's explicit ``field``/``target`` - never on
    the detail text."""
    # 1. Drop ungrounded citations.
    drop_ids = {
        f.target
        for f in findings
        if f.rule == "citation_grounding" and f.action == "drop"
    }
    if drop_ids and isinstance(report.get("citations"), list):
        kept = []
        for c in report["citations"]:
            sid = c.get("source_id") if isinstance(c, dict) else None
            if sid in drop_ids:
                continue
            kept.append(c)
        report["citations"] = kept
        for f in findings:
            if f.rule == "citation_grounding":
                f.applied = True

    # 2. Strip unprovenanced names.
    for f in findings:
        if f.rule != "owner_provenance" or f.action != "strip":
            continue
        name = str(f.target)
        if f.field in ("affected_teams", "affected_people"):
            _remove_from_list(report, f.field, name)
            f.applied = True
        elif f.field == "change_collisions":
            for col in report.get("change_collisions") or []:
                if isinstance(col, dict) and str(col.get("who")) == name:
                    col["who"] = None
            f.applied = True

    # 3. Raise the risk floor under a freeze.
    for f in findings:
        if f.rule == "change_control_dominance" and f.action == "raise_risk":
            risk = report.get("risk")
            if isinstance(risk, dict):
                risk["level"] = "medium"
                if not isinstance(risk.get("score"), int) or risk["score"] < _MEDIUM_SCORE_FLOOR:
                    risk["score"] = _MEDIUM_SCORE_FLOOR
                reasons = risk.setdefault("reasons", [])
                if isinstance(reasons, list):
                    reasons.append(
                        "Risk floor raised to medium: an active change freeze "
                        "overrides the technical score."
                    )
                f.applied = True


def _remove_from_list(report: dict, field: str, value: str) -> None:
    lst = report.get(field)
    if isinstance(lst, list):
        report[field] = [x for x in lst if str(x) != value]


def _log(findings: list[GateFinding], *, applied: bool) -> None:
    if not findings:
        return
    tag = "ENFORCE" if applied else "shadow"
    print(f"[verdict_gate:{tag}] {len(findings)} finding(s):", flush=True)
    for f in findings:
        mark = "applied" if f.applied else "would"
        print(f"  - [{f.rule}/{f.action}/{mark}] {f.detail}", flush=True)
