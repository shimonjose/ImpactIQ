"""Deterministic graders + a verdict-class heuristic + an opt-in LLM judge.

HARD fields (intent, anchor, risk bucket, artifact type, component set-overlap,
citation presence, must-not-mention) are scored exactly - fast, stable, no LLM.
The verdict CLASS is a documented heuristic (structured signals first). SOFT
fields (is the recommendation actionable; did it leak substance) go to a
fixed-rubric LLM judge that must quote the offending span - opt-in (live only).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FieldResult:
    field: str
    passed: bool
    detail: str = ""


# ── verdict-class heuristic ───────────────────────────────────────────────────

# Any active change-control directive (a freeze is one example) - see
# verdict_gate's change_control_dominance. The class label is
# "blocked_by_change_control", not freeze-specific.
_DIRECTIVE_WORDS = (
    "freeze", "hold", "moratorium", "do not proceed", "don't proceed",
    "wait for it to lift", "stand down", "pause", "embargo", "blackout",
    "needs approval", "await approval", "sign-off", "change board", "cab",
    "before applying", "until the incident", "no deploy",
)
_EXPECTED_WORDS = ("policy", "sop", "documented", "by design", "standard", "expected per")
_REUSE_WORDS = ("reuse", "already exists", "extend the existing", "existing equivalent")
_SAFE_WORDS = ("safe to proceed", "no issue", "nothing else", "no impact", "low risk")


def classify_verdict(report: dict) -> str:
    """Map a report to one of the verdict classes. Heuristic, structured-signal
    first - used for grading, not in production. Order matters (freeze wins)."""
    verdict_raw = report.get("verdict") or ""
    blob = " ".join(
        str(report.get(k) or "") for k in ("verdict", "reconciliation", "recommendation")
    ).lower()
    risk = ((report.get("risk") or {}).get("level") or "").lower()
    conf = report.get("confidence", 1.0)
    art = report.get("generated_artifact") or {}
    atype = art.get("artifact_type") if isinstance(art, dict) else None

    if "?" in verdict_raw and conf < 0.6 and not report.get("generated_artifact"):
        return "needs_clarification"
    if any(w in blob for w in _DIRECTIVE_WORDS):
        return "blocked_by_change_control"
    if "expected" in blob and (report.get("citations") or any(w in blob for w in _EXPECTED_WORDS)):
        return "expected_per_policy"
    if report.get("existing_equivalents") or any(w in blob for w in _REUSE_WORDS):
        return "reuse"
    if risk == "low" and not report.get("generated_artifact") and any(w in blob for w in _SAFE_WORDS):
        return "safe"
    if atype in ("remediation_proposal", "backfill_blueprint") or risk in ("medium", "high"):
        return "defect"
    return "unknown"


# ── hard-field grading ────────────────────────────────────────────────────────


def _report_blob(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False).lower()


def _component_names(report: dict) -> str:
    parts: list[str] = []
    for c in report.get("impacted_components") or []:
        if isinstance(c, dict):
            parts += [str(c.get("id") or ""), str(c.get("name") or "")]
    return " ".join(parts).lower()


def grade_hard(report: dict, expected: Any) -> list[FieldResult]:
    """Grade every label the case actually specifies (unset labels are skipped)."""
    out: list[FieldResult] = []
    if not isinstance(report, dict):
        return [FieldResult("report", False, "no report dict produced")]

    if expected.intent is not None:
        got = report.get("intent")
        out.append(FieldResult("intent", got == expected.intent, f"{got!r} == {expected.intent!r}"))

    if expected.anchor_id is not None:
        anchor = report.get("anchor") or {}
        got = str(anchor.get("id") or anchor.get("name") or "").lower()
        want = expected.anchor_id.lower()
        out.append(FieldResult("anchor_id", want in got or got in want and bool(got),
                               f"{got!r} ~ {want!r}"))

    if expected.risk_bucket is not None:
        got = ((report.get("risk") or {}).get("level") or "").lower()
        out.append(FieldResult("risk_bucket", got == expected.risk_bucket, f"{got!r} == {expected.risk_bucket!r}"))

    if expected.verdict_class is not None:
        got = classify_verdict(report)
        out.append(FieldResult("verdict_class", got == expected.verdict_class, f"{got!r} == {expected.verdict_class!r}"))

    if expected.artifact_type != "ANY":
        art = report.get("generated_artifact")
        got = art.get("artifact_type") if isinstance(art, dict) else None
        out.append(FieldResult("artifact_type", got == expected.artifact_type, f"{got!r} == {expected.artifact_type!r}"))

    for token in expected.must_mention:
        comp = _component_names(report)
        present = token.lower() in comp or token.lower() in _report_blob(report)
        out.append(FieldResult(f"must_mention[{token}]", present, "present" if present else "MISSING"))

    for token in expected.must_not_mention:
        absent = token.lower() not in _report_blob(report)
        out.append(FieldResult(f"must_not_mention[{token}]", absent, "absent" if absent else "LEAKED"))

    for sid in expected.required_citations:
        ids = {c.get("source_id") for c in (report.get("citations") or []) if isinstance(c, dict)}
        out.append(FieldResult(f"citation[{sid}]", sid in ids, "present" if sid in ids else "MISSING"))

    return out


# ── gate-behavior grading (mock mode) ─────────────────────────────────────────


def grade_gate(
    findings: list, before: dict, after: dict, expected: Any
) -> list[FieldResult]:
    out: list[FieldResult] = []
    fired = {f.rule for f in findings}

    for rule in expected.gate_rules_fire:
        out.append(FieldResult(f"gate_fires[{rule}]", rule in fired,
                               "fired" if rule in fired else f"NOT fired (fired={sorted(fired)})"))

    after_cit_ids = {c.get("source_id") for c in (after.get("citations") or []) if isinstance(c, dict)}
    for sid in expected.citations_dropped:
        out.append(FieldResult(f"citation_dropped[{sid}]", sid not in after_cit_ids,
                               "dropped" if sid not in after_cit_ids else "still present"))

    after_blob = _report_blob(after)
    for name in expected.names_stripped:
        out.append(FieldResult(f"name_stripped[{name}]", name.lower() not in after_blob,
                               "stripped" if name.lower() not in after_blob else "still present"))

    if expected.risk_floored_to is not None:
        got = ((after.get("risk") or {}).get("level") or "").lower()
        out.append(FieldResult("risk_floored", got == expected.risk_floored_to,
                               f"{got!r} == {expected.risk_floored_to!r}"))

    if expected.write_denied:
        denied = after.get("generated_artifact") is None
        out.append(FieldResult("write_denied", denied, "denied" if denied else "artifact still present"))

    return out


# ── opt-in LLM judge for soft fields (live only) ──────────────────────────────

_JUDGE_INSTRUCTIONS = """\
You are an ImpactIQ answer JUDGE. Score the report on TWO soft qualities, each
1-5, and for any score <= 3 you MUST quote the exact offending span verbatim.

1. actionable: does the recommendation lead with a concrete action the user can
   take (name a person/component/step), not a vague hedge?
2. no_substance_leak: does it avoid quoting/paraphrasing the CONTENT of other
   people's messages/documents (presence + owner + routing is fine)?

Output EXACTLY one JSON object in a ```json fence:
{"actionable": 5, "actionable_span": "", "no_substance_leak": 5, "leak_span": ""}
"""


def llm_judge(report: dict, project_client: Any, settings: Any) -> dict:
    """Fixed-rubric judge (single hop, no tools). Returns the parsed scores, or
    {} on failure. Live only - costs a model call."""
    from impactiq.agents.loop import extract_json_block, run_agent_turn

    try:
        turn = run_agent_turn(
            project_client,
            agent_name="ImpactIQ-eval-judge",
            model=settings.heavy_model_deployment or "",
            instructions=_JUDGE_INSTRUCTIONS,
            tools=[],
            dispatch={},
            user_input="Report to judge:\n" + json.dumps(report, indent=2),
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}
    parsed = extract_json_block(turn.raw_text)
    return parsed if isinstance(parsed, dict) else {}
