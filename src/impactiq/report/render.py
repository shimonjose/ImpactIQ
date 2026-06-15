"""Plain-language chat rendering of an ImpactReport.

The report itself is a chat MESSAGE, not a card — cards are reserved for
things the user acts on (editable drafts, record-fix previews). This module
renders the message markdown and derives the single "next step" offer from
the generated artifact.
"""

from __future__ import annotations

from .artifacts import parse_artifact
from .schema import ImpactReport

_RISK_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}

_EVIDENCE_LABELS = {
    "tool": "Dependency engine",
    "citation": "Governance document",
    "workiq": "Workplace signal",
    "note": "Note",
}


def report_summary_markdown(report: ImpactReport) -> str:
    """The user-facing answer, in plain markdown. No internal vocabulary."""
    parts: list[str] = [f"**{report.verdict}**"]

    if report.reconciliation:
        parts.append(report.reconciliation)

    if report.change_collisions:
        lines = ["**Coordination needed:**"]
        for coll in report.change_collisions:
            who = (coll.who or "").strip() or "the component's owner (not identified)"
            name = coll.component.name
            if coll.sensitivity == "open":
                lines.append(
                    f"- ✏️ **{name}** is being worked on by **{who}** right now — "
                    "coordinate before proceeding."
                )
            else:
                lines.append(
                    f"- 🔒 There is restricted activity around **{name}** — "
                    f"talk to **{who}** before proceeding. (I can see that "
                    "something is happening there, but not what — it isn't "
                    "shared with you.)"
                )
        parts.append("\n".join(lines))

    if report.affected_teams:
        parts.append("**Teams affected:** " + ", ".join(report.affected_teams))

    # The human fallout — anyone (customer, colleague, internal user) waiting on
    # the outcome the failure swallowed, so the answer can offer to reply.
    if report.affected_people:
        parts.append("**Waiting on this:** " + ", ".join(report.affected_people))

    parts.append(f"**Recommendation:** {report.recommendation}")

    # Evidence — numbered, plain-language source labels, inline in the chat
    # message.
    if report.evidence:
        n = len(report.evidence)
        ev_lines = ["**What I checked:**"]
        for i, e in enumerate(report.evidence, 1):
            label = _EVIDENCE_LABELS.get(e.kind, e.kind.capitalize())
            ev_lines.append(f"{i}/{n} · _{label}_ — {e.detail}")
        parts.append("\n".join(ev_lines))

    risk = _RISK_EMOJI.get(report.risk.level, "")
    footer = f"{risk} Risk {report.risk.score}/100 · confidence {report.confidence:.0%}"
    titles = {c.title or c.source_id for c in report.citations}
    if titles:
        footer += " · grounded in: " + ", ".join(sorted(titles))
    parts.append(footer)

    return "\n\n".join(parts)


def artifact_offer(report: ImpactReport) -> dict | None:
    """Derive the single 'next step' offer button from the artifact.

    Returns {action, label, intro} or None. The artifact stays a DRAFT the
    user must explicitly ask for — nothing is shown pre-composed, let alone
    sent: offer first, draft on request, edit before send.
    """
    if not report.generated_artifact:
        return None
    try:
        artifact = parse_artifact(report.generated_artifact)
    except Exception:
        return None

    t = artifact.artifact_type
    if t in ("manager_handoff", "draft_teams_intro"):
        return {
            "action": "draft_notification",
            "label": f"Draft a notification to {artifact.recipient}",
            "intro": (
                f"I can draft a notification to **{artifact.recipient}** "
                "about this — you'll get to edit it before anything is sent."
            ),
        }
    if t == "remediation_proposal":
        n = len(artifact.changes)
        return {
            "action": "show_remediation",
            "label": f"Review the proposed fix ({n} field{'s' if n != 1 else ''}, 1 record)",
            "intro": (
                "I found a data fix you could apply yourself — want to review "
                "it? Nothing is changed until you explicitly confirm."
            ),
        }
    if t == "dev_ticket":
        return {
            "action": "show_ticket",
            "label": "Show the dev ticket draft",
            "intro": "I've prepared a dev ticket draft for this — want to see it?",
        }
    if t == "backfill_blueprint":
        return {
            "action": "show_backfill",
            "label": "Show the bulk-fix blueprint",
            "intro": (
                "The same fix applies to multiple records, so I prepared a "
                "blueprint to route to the data owner (bulk changes are never "
                "applied directly)."
            ),
        }
    if t == "reuse_blueprint":
        return {
            "action": "show_reuse",
            "label": "Show the reuse/extend plan",
            "intro": "Something similar already exists — want to see the reuse plan?",
        }
    return None
