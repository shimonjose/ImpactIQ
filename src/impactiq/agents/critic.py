"""Conditional critic + adversarial write-verifier (behind IMPACTIQ_CRITIC).

The adjudicator produces a verdict in a single pass; the deterministic verdict
gate re-checks it. This adds an LLM SKEPTIC on top - but only when it earns its
cost. Triggered ONLY on high-stakes / uncertain turns so the median turn pays
nothing:

  * a WRITE artifact (remediation_proposal / backfill_blueprint) is present, or
  * a change-collision is present, or
  * the verdict gate flagged a violation, or
  * confidence is borderline.

Two actions, both bounded:

  * **Adversarial write-verify.** The skeptic is prompted to find the
    strongest reason the verdict is WRONG. If a write artifact is present and it
    refutes the write, DEFAULT-DENY: null the artifact and add a caveat - the
    narrative still ships, but the dangerous part (the mutation) is withheld. A
    refused mutation is safe; a wrong one is not.
  * **Critic repair.** The skeptic's defect list feeds ONE adjudicator
    repair turn (orchestrated by the caller), kept only if it re-validates and
    does not worsen the verdict gate - so a repair can only help or no-op.

This module owns the deterministic helpers (triggers, detectors, write-deny) and
the single skeptic LLM call. The repair turn is orchestrated by
``multi_agent.ask_multi`` because it needs the adjudicator's own tools.

Failure modes are split by stakes (enforced by the caller, multi_agent):

* READ-ONLY conclusions fail OPEN - a skeptic error leaves the narrative
  unchanged (it carries no mutation).
* MUTATION proposals fail CLOSED - a write artifact ships only with the
  skeptic's explicit ``write_artifact_safe: true``; a refusal, error, or empty
  critique withholds the artifact. The human confirm gate and the server-side
  proposal binding remain in front of execution regardless.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..settings import Settings
from .loop import extract_json_block, run_agent_turn

# Artifacts that mutate tenant DATA (the high-stakes ones the verifier can veto).
# manager_handoff is a draft message (separate confirm-before-send gate); the
# data writes are what a wrong verdict turns into an incorrect mutation.
_WRITE_ARTIFACTS = frozenset({"remediation_proposal", "backfill_blueprint"})

# Borderline-confidence band that warrants a second look. Above the floor the
# verdict is confident enough; far below it the verdict is usually a clarifying
# question (already hedged). Override with IMPACTIQ_CRITIC_CONF_FLOOR.
_CONF_FLOOR = float(os.environ.get("IMPACTIQ_CRITIC_CONF_FLOOR", "0.7"))


def critic_enabled() -> bool:
    raw = (os.environ.get("IMPACTIQ_CRITIC") or "").strip().lower()
    return raw in ("1", "on", "true", "yes", "enforce")


def carries_write_artifact(report_dict: dict) -> str | None:
    """Return the artifact_type if the report carries a tenant-DATA write, else None."""
    art = report_dict.get("generated_artifact")
    if isinstance(art, dict):
        atype = art.get("artifact_type")
        if atype in _WRITE_ARTIFACTS:
            return atype
    return None


def has_change_collision(report_dict: dict) -> bool:
    cols = report_dict.get("change_collisions")
    return isinstance(cols, list) and len(cols) > 0


def should_critique(
    report_dict: dict, gate_findings: list | None, *, conf_floor: float | None = None
) -> str | None:
    """Deterministic trigger. Returns a short reason string (for logging) or
    None when the median, low-stakes turn should skip the critic entirely."""
    if not isinstance(report_dict, dict):
        return None
    if carries_write_artifact(report_dict):
        return "write_artifact_present"
    if has_change_collision(report_dict):
        return "change_collision_present"
    if gate_findings:
        return "verdict_gate_flagged"
    floor = _CONF_FLOOR if conf_floor is None else conf_floor
    conf = report_dict.get("confidence")
    if isinstance(conf, (int, float)) and conf < floor:
        return f"borderline_confidence(<{floor})"
    return None


SKEPTIC_INSTRUCTIONS = """\
You are ImpactIQ's VERIFIER - a skeptic with veto power over MUTATIONS. You are
given an analysis plan, the specialist findings, and a DRAFT verdict/report
another agent produced. Find the STRONGEST reasons the verdict could be WRONG.
Do NOT rubber-stamp it; if it is sound, say so plainly.

Check, concretely:
* Does the impacted/blast radius in the findings actually support the stated
  risk level (not inflated, not understated)?
* If a policy/citation is relied on, is it on-point for THIS verdict?
* If a DATA-FIX artifact (remediation_proposal / backfill_blueprint) is present:
  does the proposed change match the DIAGNOSED cause? Are all values grounded in
  the findings (no invented values)? Is it really per-record business DATA (not a
  configuration change in disguise)? Is the diagnosis confident enough to offer a
  write? If any of these is shaky, the write is UNSAFE - withholding a wrong
  mutation is the correct call; the narrative can still ship.
* Did the verdict overreach beyond what the evidence shows?

Output EXACTLY one JSON object in a ```json fence, nothing else:

```json
{
  "verdict_holds": true,
  "defects": ["<specific, actionable issue for the adjudicator to fix; [] if none>"],
  "write_artifact_safe": true,
  "write_concern": "<if a data-fix artifact is present and questionable, why; else empty>"
}
```
"""


def _skeptic_input(
    plan: dict, question: str, solution_name: str, results: list[dict], report_dict: dict
) -> str:
    parts = [
        f"Scope: solution '{solution_name}'.",
        f"Orchestrator plan: {json.dumps(plan)}",
        f"User question:\n{question}",
        "",
        "# Specialist findings",
    ]
    for r in results or []:
        parts.append(f"## {r.get('agent', '?').upper()} status={r.get('status')}")
        if r.get("error"):
            parts.append(f"(note: {r['error']})")
        parts.append(json.dumps(r.get("finding") or {}, indent=2))
    parts += ["", "# DRAFT verdict/report to scrutinise", json.dumps(report_dict, indent=2)]
    return "\n".join(parts)


def run_skeptic(
    project_client: Any,
    settings: Settings,
    plan: dict,
    question: str,
    solution_name: str,
    results: list[dict],
    report_dict: dict,
) -> dict:
    """Single skeptic LLM hop (no tools). Returns the parsed critique, or {}
    on any error - which the caller treats as fail-OPEN for read-only
    narratives but fail-CLOSED for mutation artifacts (no explicit
    ``write_artifact_safe: true`` → the write is withheld)."""
    try:
        turn = run_agent_turn(
            project_client,
            agent_name="ImpactIQ-verifier",
            model=settings.heavy_model_deployment or "",
            instructions=SKEPTIC_INSTRUCTIONS,
            tools=[],
            dispatch={},
            user_input=_skeptic_input(plan, question, solution_name, results, report_dict),
        )
    except Exception as exc:  # noqa: BLE001 - verifier is best-effort, never fatal
        print(f"(critic: skeptic call failed: {type(exc).__name__}: {exc})", flush=True)
        return {}
    parsed = extract_json_block(turn.raw_text)
    return parsed if isinstance(parsed, dict) else {}


def apply_write_deny(report_dict: dict, reason: str) -> dict:
    """Default-deny a refuted mutation: null the artifact and add a plain-English
    caveat to the recommendation. Returns a modified COPY (never mutates input)."""
    out = dict(report_dict)
    out["generated_artifact"] = None
    caveat = (
        "Note: the automated fix was withheld for review - "
        f"{reason.strip() or 'the proposed change could not be confirmed against the diagnosis'}. "
        "Verify the cause first, then apply any change manually."
    )
    rec = (out.get("recommendation") or "").strip()
    out["recommendation"] = f"{rec} {caveat}".strip() if rec else caveat
    ev = list(out.get("evidence") or [])
    ev.append({"kind": "note", "detail": "Verifier withheld the proposed data fix pending review."})
    out["evidence"] = ev
    return out
