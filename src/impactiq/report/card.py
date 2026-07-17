"""ImpactReport → Adaptive Card.

The Teams surface posts the card and wires the Action.Submit handlers. The
card JSON is also inspectable via ``cli artifact card`` and unit-tested for
shape.

Safety notes baked into the layout:
* The **source-span pane** on document-grounded remediation proposals is a
  safety mechanism, not decoration - it is always rendered, never collapsed
  away, when ``evidence_source == "document"``. (NOTE: document-grounded
  proposals are dormant on the live surface - propose_record_fix is
  diagnosis-only by choice; this pane fires for the CLI + tests and is kept
  ready to wire on. See server.propose_record_fix for the why.)
* Confirmation control is **tap** (Action.Submit) for diagnosis-grounded and
  **typed** (Input.Text the user must fill) for document-grounded.
* Handoff / intro cards carry draft text + an "Approve send" action; the
  action's payload is a request to send, not a send.
"""

from __future__ import annotations

import re
from typing import Any

from .artifacts import (
    BackfillBlueprint,
    DevTicket,
    DraftTeamsIntro,
    ManagerHandoff,
    RemediationProposal,
    ReuseBlueprint,
    parse_artifact,
)
from .schema import ImpactReport

_RISK_STYLE = {"low": "good", "medium": "warning", "high": "attention"}

# Plain-language labels for evidence sources (the raw `kind` tags are
# internal vocabulary; users shouldn't need to decode them).
_EVIDENCE_LABELS = {
    "tool": "Dependency engine",
    "citation": "Governance document",
    "workiq": "Workplace signal",
    "note": "Note",
}


def _tb(text: str, **kw: Any) -> dict:
    out: dict[str, Any] = {"type": "TextBlock", "text": text, "wrap": True}
    out.update(kw)
    return out


def _facts(pairs: list[tuple[str, str]]) -> dict:
    return {
        "type": "FactSet",
        "facts": [{"title": k, "value": v} for k, v in pairs if v],
    }


# Single source of truth for the Outlook draft subject (the create_draft
# endpoint uses it too - the preview must show exactly what gets created).
OUTLOOK_DRAFT_SUBJECT = "ImpactIQ: coordination on a proposed change"

# Plain-language labels for how the recipient was identified (the raw values
# are internal vocabulary; users shouldn't need to decode them).
_RECIPIENT_SOURCE_LABELS = {
    "structural_ownership": "component ownership (dependency graph)",
}


def _recipient_source_label(value: str) -> str:
    return _RECIPIENT_SOURCE_LABELS.get(value, value)


def _preview_header(title: str, subtitle: str = "") -> dict:
    """The tinted banner that opens every message-preview card."""
    items = [_tb(title, weight="Bolder", size="Medium")]
    if subtitle:
        items.append(_tb(subtitle, isSubtle=True, spacing="None"))
    return {"type": "Container", "style": "emphasis", "bleed": True, "items": items}


def _field_row(label: str, value: str) -> dict:
    """An email-style labelled field line (Subject: ... / To: ...)."""
    return {
        "type": "ColumnSet",
        "spacing": "Small",
        "columns": [
            {
                "type": "Column",
                "width": "90px",
                "items": [_tb(f"{label}:", weight="Bolder", isSubtle=True)],
            },
            {"type": "Column", "width": "stretch", "items": [_tb(value)]},
        ],
    }


def _artifact_body(artifact: Any) -> tuple[list[dict], list[dict]]:
    """Return (body elements, actions) for the typed artifact."""
    body: list[dict] = []
    actions: list[dict] = []

    if isinstance(artifact, RemediationProposal):
        is_create = artifact.operation == "create"
        body.append(
            _tb(
                "Proposed fix - create the missing row (preview & confirm)"
                if is_create
                else "Proposed fix (preview & confirm)",
                weight="Bolder",
                size="Medium",
            )
        )
        body.append(
            _facts(
                [
                    (
                        "Record",
                        "(new row - id assigned on create)"
                        if is_create
                        else f"{artifact.record_name or artifact.record_id}",
                    ),
                    ("Table", artifact.record_table),
                    *[(k, v) for k, v in artifact.identifying_columns.items()],
                ]
            )
        )
        for ch in artifact.changes:
            body.append(
                {
                    "type": "ColumnSet",
                    "columns": [
                        {
                            "type": "Column",
                            "width": "stretch",
                            "items": [
                                _tb(ch.column, weight="Bolder"),
                                _tb(f"current: {ch.current_value if ch.current_value is not None else '(empty)'}"),
                            ],
                        },
                        {
                            "type": "Column",
                            "width": "stretch",
                            "items": [
                                _tb("proposed", weight="Bolder"),
                                _tb(
                                    ch.proposed_value
                                    if ch.proposed_value is not None
                                    else " / ".join(ch.options) + "  (choose one)"
                                ),
                            ],
                        },
                    ],
                }
            )
        if artifact.downstream_preview:
            body.append(_tb("Downstream effects (dependency-aware)", weight="Bolder"))
            for line in artifact.downstream_preview:
                body.append(_tb(f"• {line}"))
        body.append(
            _tb(
                f"Evidence: {artifact.evidence_source} - "
                + (
                    artifact.diagnosis_summary
                    if artifact.evidence_source == "diagnosis"
                    else f"{artifact.document_name}"
                ),
                isSubtle=True,
            )
        )
        if artifact.evidence_source == "document":
            # Source-span pane: ALWAYS visible for document-grounded.
            body.append(
                {
                    "type": "Container",
                    "style": "emphasis",
                    "id": "sourceSpanPane",
                    "items": [
                        _tb("Source span (verify before confirming)", weight="Bolder"),
                        _tb(f"“{artifact.source_span}”", fontType="Monospace"),
                        _tb(
                            f"extraction confidence: {artifact.extraction_confidence}",
                            isSubtle=True,
                        ),
                    ],
                }
            )
        # The friction matches the proposal's own confirmation field -
        # document-grounded AND creates are typed (the model validator
        # forces it), so the card and the server can never disagree.
        if artifact.confirmation == "typed":
            body.append(
                {
                    "type": "Input.Text",
                    "id": "typed_confirmation",
                    "placeholder": "Type the proposed value (or CONFIRM) to enable the write",
                }
            )
            actions.append(
                {
                    "type": "Action.Submit",
                    "title": "Create this row (your identity)"
                    if is_create
                    else "Submit typed confirmation",
                    "data": {
                        "action": "confirm_remediation",
                        "confirmation": "typed",
                        "record_id": artifact.record_id,
                    },
                }
            )
        else:
            actions.append(
                {
                    "type": "Action.Submit",
                    "title": "Apply fix (1 record, your identity)",
                    "data": {
                        "action": "confirm_remediation",
                        "confirmation": "tap",
                        "record_id": artifact.record_id,
                    },
                }
            )

    elif isinstance(artifact, BackfillBlueprint):
        body.append(_tb("Backfill blueprint (bulk - routed, never a tap)", weight="Bolder", size="Medium"))
        body.append(
            _facts(
                [
                    ("Records (est.)", str(artifact.estimated_record_count or "?")),
                    ("Query language", artifact.query_language),
                    ("Suggested approver", artifact.suggested_approver),
                    ("Idempotency", artifact.idempotency_note),
                ]
            )
        )
        body.append(_tb(artifact.query, fontType="Monospace"))
        actions.append(
            {
                "type": "Action.Submit",
                "title": "Route to approver (draft handoff)",
                "data": {"action": "route_backfill"},
            }
        )

    elif isinstance(artifact, ManagerHandoff):
        body.append(
            _preview_header(
                "✉️ Manager notification (draft)", "You must approve before it sends."
            )
        )
        body.append(_field_row("To", artifact.recipient))
        if artifact.recipient_source:
            body.append(_field_row("Named via", _recipient_source_label(artifact.recipient_source)))
        body.append(
            _tb("Body:", weight="Bolder", isSubtle=True, spacing="Medium", separator=True)
        )
        body.append({"type": "Container", "style": "emphasis", "items": [_tb(artifact.draft_text)]})
        body.append(
            _tb(
                f"Carries context baton {artifact.baton.baton_id} so the "
                "recipient's own session can resume the analysis.",
                isSubtle=True,
                size="Small",
            )
        )
        actions.append(
            {
                "type": "Action.Submit",
                "title": "Approve & send",
                "data": {"action": "send_handoff", "baton_id": artifact.baton.baton_id},
            }
        )
        actions.append(
            {"type": "Action.Submit", "title": "Discard draft", "data": {"action": "discard"}}
        )

    elif isinstance(artifact, DraftTeamsIntro):
        body.append(
            _preview_header(
                "✉️ Teams intro (draft)", "You must approve before it sends."
            )
        )
        body.append(_field_row("To", artifact.recipient))
        if artifact.recipient_source:
            body.append(_field_row("Named via", _recipient_source_label(artifact.recipient_source)))
        body.append(
            _tb("Body:", weight="Bolder", isSubtle=True, spacing="Medium", separator=True)
        )
        body.append({"type": "Container", "style": "emphasis", "items": [_tb(artifact.draft_text)]})
        actions.append(
            {"type": "Action.Submit", "title": "Approve & send", "data": {"action": "send_intro"}}
        )

    elif isinstance(artifact, DevTicket):
        body.append(_tb("Dev ticket (draft)", weight="Bolder", size="Medium"))
        body.append(
            _facts(
                [
                    ("Title", artifact.title),
                    ("Severity", artifact.severity),
                    ("Component", artifact.component.name if artifact.component else ""),
                ]
            )
        )
        if artifact.description:
            body.append(_tb("Description", weight="Bolder"))
            body.append(_tb(artifact.description))
        if artifact.root_cause:
            body.append(_tb("Root cause", weight="Bolder"))
            body.append(_tb(artifact.root_cause))
        if artifact.evidence_summary:
            body.append(_tb("Evidence", weight="Bolder"))
            body.append(_tb(artifact.evidence_summary))
        if artifact.suggested_fix:
            body.append(_tb("Suggested fix", weight="Bolder"))
            body.append(_tb(artifact.suggested_fix))
        if artifact.impacted_components:
            body.append(_tb("Impacted components", weight="Bolder"))
            for c in artifact.impacted_components:
                body.append(_tb(f"• {c.name}"))
        if artifact.acceptance_criteria:
            body.append(_tb("Acceptance criteria", weight="Bolder"))
            for ac in artifact.acceptance_criteria:
                body.append(_tb(f"• {ac}"))

    elif isinstance(artifact, ReuseBlueprint):
        body.append(_tb("Reuse / extend blueprint", weight="Bolder", size="Medium"))
        body.append(_facts([("Recommendation", artifact.recommendation)]))
        if artifact.gap_analysis:
            body.append(_tb(artifact.gap_analysis))
        for step in artifact.steps:
            body.append(_tb(f"• {step}"))

    return body, actions


def _card(body: list[dict], actions: list[dict]) -> dict:
    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.5",
        "body": body,
        "actions": actions,
    }


def artifact_card(report: ImpactReport) -> dict | None:
    """A card containing ONLY the artifact preview + its actions.

    The report itself is a chat message; this card appears only when the user
    asks to see the artifact (review a fix, see a ticket, ...)."""
    if not report.generated_artifact:
        return None
    try:
        artifact = parse_artifact(report.generated_artifact)
    except Exception:
        return None
    body, actions = _artifact_body(artifact)
    return _card(body, actions) if body else None


def editable_draft_card(report: ImpactReport) -> dict | None:
    """The notification draft, free-text editable before send.

    The draft text sits in a multiline input the user can rewrite;
    'Approve & send' submits the EDITED text, which the bridge re-gates
    and audit-logs."""
    if not report.generated_artifact:
        return None
    try:
        artifact = parse_artifact(report.generated_artifact)
    except Exception:
        return None
    if not isinstance(artifact, (ManagerHandoff, DraftTeamsIntro)):
        return None
    is_handoff = isinstance(artifact, ManagerHandoff)
    body: list[dict] = [
        _preview_header(
            "✉️ Message preview",
            "Nothing goes out until you approve.",
        ),
        _field_row("To", artifact.recipient),
    ]
    if artifact.recipient_source:
        body.append(_field_row("Named via", _recipient_source_label(artifact.recipient_source)))
    body.append(_field_row("Subject", OUTLOOK_DRAFT_SUBJECT))
    body.append(
        _tb("Body:", weight="Bolder", isSubtle=True, spacing="Medium", separator=True)
    )
    body.append(
        {
            "type": "Input.Text",
            "id": "edited_text",
            "isMultiline": True,
            "value": artifact.draft_text,
        }
    )
    body.append(
        _tb(
            "Send it as is with a tap below - or rewrite the body first; "
            "your edited text is what goes out.",
            isSubtle=True,
            size="Small",
        )
    )
    if is_handoff:
        body.append(
            _tb(
                f"Carries context baton {artifact.baton.baton_id} so the "
                "recipient's own session can pick the analysis up from here.",
                isSubtle=True,
                size="Small",
            )
        )
    actions = []
    if is_handoff:
        # Interactive handoff: deliver an actionable card to the manager
        # so they can resume the analysis in their OWN session. Carries the
        # edited text along (Action.Submit includes the card's inputs).
        actions.append(
            {
                "type": "Action.Submit",
                "title": f"Notify {artifact.recipient} in Teams",
                "data": {"action": "notify_manager"},
            }
        )
    actions.append(
        {
            "type": "Action.Submit",
            "title": "Save as draft in my Outlook",
            "data": {"action": "create_draft"},
        }
    )
    actions.append(
        {"type": "Action.Submit", "title": "Discard", "data": {"action": "discard"}}
    )
    return _card(body, actions)


def _fix_op_summary(op: dict) -> str:
    kind = op.get("op", "?")
    if kind == "set_flow_state":
        return f"Turn flow “{op.get('flow', '?')}” {op.get('state', '?')}"
    if kind == "patch_flow_definition":
        return f"Repair the definition of flow “{op.get('flow', '?')}”"
    if kind == "alter_table":
        return f"Update table {op.get('table', '?')} ({', '.join(sorted(op.get('set') or {}))})"
    if kind == "alter_column":
        return (
            f"Update column {op.get('table', '?')}.{op.get('column', '?')} "
            f"({', '.join(sorted(op.get('set') or {}))})"
        )
    return f"({kind})"


def sandbox_fix_card(fix_id: str, title: str, rationale: str, ops: list[dict]) -> dict:
    """The Apply card for a PROPOSED sandbox fix: the write happens only
    behind this tap, in the sandbox environment, fix-only.

    MINIMAL by design: the agent's chat reply carries the full explanation and
    change list; the card is one line + the decision buttons.
    ``rationale``/``ops`` stay in the signature for the audit payload and
    tests, not for rendering."""
    del rationale, ops  # explained in the chat reply; card stays minimal
    body: list[dict] = [
        _tb(
            f"🔧 {title} - sandbox only; nothing changes until you tap Apply.",
            isSubtle=True,
        )
    ]
    actions = [
        {
            "type": "Action.Submit",
            "title": "Apply fix in sandbox",
            "data": {"action": "apply_sandbox_fix", "fix_id": fix_id},
        },
        {"type": "Action.Submit", "title": "Not now", "data": {"action": "discard"}},
    ]
    return _card(body, actions)


def standalone_artifact_card(artifact_payload: dict) -> dict:
    """Render ONE validated artifact as its own card - the unified agent's
    proposal path, where there is no full ImpactReport to wrap it in. Same
    body/actions as the report-embedded rendering, so the confirm flows stay
    identical."""
    artifact = parse_artifact(artifact_payload)
    body, actions = _artifact_body(artifact)
    return _card(body, actions)


def resubmit_card(
    resubmit_id: str, flow_name: str, run_name: str, started: str | None = None
) -> dict:
    """Per-run Resubmit card: one run per card, the rerun happens only behind
    this tap, under the user's own identity. Minimal like sandbox_fix_card -
    the chat reply carries the context."""
    del run_name  # in the audit payload; the card stays minimal
    when = f" (failed {started})" if started else ""
    body: list[dict] = [
        _tb(
            f"▶️ Resubmit run of “{flow_name}”{when} - re-runs against "
            "the current live definition; nothing happens until you tap.",
            isSubtle=True,
        )
    ]
    actions = [
        {
            "type": "Action.Submit",
            "title": "Resubmit this run",
            "data": {"action": "apply_resubmit_run", "resubmit_id": resubmit_id},
        },
        {"type": "Action.Submit", "title": "Not now", "data": {"action": "discard"}},
    ]
    return _card(body, actions)


def record_open_url(
    base_url: str, table_logical_name: str, record_id: str, app_id: str | None = None
) -> str:
    """The model-driven 'open this record' deep link - the same URL shape our
    url_resolve parser accepts, constructed in reverse. Opens the REAL Power
    Apps form (full edit experience, platform validation, the user's own
    permissions) - ImpactIQ never edits records inline; the validated
    remediation path stays the only write path."""
    base = (base_url or "").rstrip("/")
    app = f"appid={app_id}&" if app_id else ""
    return (
        f"{base}/main.aspx?{app}pagetype=entityrecord"
        f"&etn={table_logical_name}&id={record_id}"
    )


_GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)


def record_cards(
    payload: dict, base_url: str, app_id: str | None = None, *, max_cards: int = 10
) -> list[dict]:
    """Render retrieved records as one Adaptive Card each (the bot shows them
    as a swipeable carousel). ``payload`` comes from the agent's
    present_records call: {title?, table, records: [{id?, fields...}, ...]}.

    Read-only by design: the only action is 'Open in Power Apps' (deep link to
    the real form). No inline edit - record writes remain exclusively behind
    the preview-and-confirm gate.

    Defensive rendering: the deep link is only attached when the id is a real
    GUID (a non-GUID id would produce a dead button), and bare-GUID field
    values are hidden (a lookup the model failed to resolve to a display name
    is noise, not information)."""
    table = str(payload.get("table") or "").strip()
    records = payload.get("records") or []
    cards: list[dict] = []
    for rec in records[:max_cards]:
        if not isinstance(rec, dict):
            continue
        rec_id = str(rec.get("id") or rec.get("record_id") or "").strip()
        if not _GUID_RE.match(rec_id):
            rec_id = ""
        fields = {
            k: v
            for k, v in rec.items()
            if k not in ("id", "record_id")
            and v not in (None, "")
            and not _GUID_RE.match(str(v).strip())
        }
        # Title: first name-ish field, else the table name.
        title = None
        for key in ("name", "title", "subject", "fullname"):
            for k, v in fields.items():
                if k.lower().endswith(key):
                    title = str(v)
                    break
            if title:
                break
        body: list[dict] = [
            _tb(title or table or "Record", weight="Bolder", size="Medium"),
            _facts([(k, str(v)) for k, v in list(fields.items())[:10]]),
        ]
        actions: list[dict] = []
        if rec_id and table and base_url:
            actions.append(
                {
                    "type": "Action.OpenUrl",
                    "title": "Open in Power Apps",
                    "url": record_open_url(base_url, table, rec_id, app_id),
                }
            )
        cards.append(_card(body, actions))
    return cards


def baton_notification_card(handoff: ManagerHandoff) -> dict:
    """The impact-assertion notification DELIVERED TO the recipient manager,
    carrying the baton id so their own session can resume.

    Impact-assertion ONLY - there is structurally no field here that could
    carry the other team's content (the ContextBaton has none). The buttons
    route back to the bot: 'Tell me more' triggers the resume under the
    MANAGER's identity; the acks are recorded as audit events."""
    b = handoff.baton
    body: list[dict] = [
        _preview_header(
            "👋 Heads-up from ImpactIQ",
            "A change that may affect your team.",
        ),
        _tb(handoff.draft_text),
    ]
    rows = []
    if b.requesting_user:
        rows.append(("Raised by", b.requesting_user))
    if b.anchor:
        rows.append(("Possible impact", b.anchor.name))
    if b.proposed_change:
        rows.append(("Proposed change", b.proposed_change))
    for label, value in rows:
        if value:
            body.append(_field_row(label, value))
    body.append(
        _tb(
            "Tap **Tell me more** and I'll look at what this means in *your* "
            "context - only you can see your team's side.",
            isSubtle=True,
        )
    )
    actions = [
        {
            "type": "Action.Submit",
            "title": "Tell me more",
            "data": {"action": "baton_tell_more", "baton_id": b.baton_id},
        },
        {
            "type": "Action.Submit",
            "title": "I'll review it",
            "data": {"action": "baton_ack", "baton_id": b.baton_id, "stance": "reviewing"},
        },
        {
            "type": "Action.Submit",
            "title": "No concern",
            "data": {"action": "baton_ack", "baton_id": b.baton_id, "stance": "clear"},
        },
    ]
    return _card(body, actions)


def report_to_adaptive_card(report: ImpactReport) -> dict:
    """Render an ImpactReport as Adaptive Card 1.5 JSON."""
    risk_style = _RISK_STYLE.get(report.risk.level, "default")

    body: list[dict] = [
        {
            "type": "Container",
            "style": risk_style,
            "bleed": True,
            "items": [
                _tb(f"ImpactIQ - {report.intent}", weight="Bolder", size="Large"),
                _tb(
                    f"Risk {report.risk.score}/100 ({report.risk.level})  ·  "
                    f"confidence {report.confidence:.2f}"
                ),
            ],
        },
        _tb(report.verdict, size="Medium", weight="Bolder"),
    ]
    if report.anchor:
        body.append(_facts([("Anchor", f"{report.anchor.kind}: {report.anchor.name}")]))
    if report.reconciliation:
        body.append(_tb(report.reconciliation, isSubtle=True))

    # Collapsible evidence - numbered (1/3, 2/3, ...) with plain-language
    # source labels instead of internal [tool]/[citation] tags.
    if report.evidence:
        n = len(report.evidence)
        evidence_items: list[dict] = []
        for i, e in enumerate(report.evidence, 1):
            label = _EVIDENCE_LABELS.get(e.kind, e.kind.capitalize())
            evidence_items.append(
                _tb(f"**{i}/{n} · {label}** - {e.detail}", spacing="Small")
            )
        body.append(
            {
                "type": "Container",
                "id": "evidencePane",
                "isVisible": False,
                "items": evidence_items,
            }
        )

    if report.change_collisions:
        body.append(_tb("Change collisions", weight="Bolder"))
        for coll in report.change_collisions:
            body.append(
                _tb(f"• [{coll.sensitivity}] {coll.component.name} ({coll.who or '?'}) - {coll.advice}")
            )

    body.append(_tb(f"Recommendation: {report.recommendation}"))

    actions: list[dict] = []
    if report.evidence:
        actions.append(
            {
                "type": "Action.ToggleVisibility",
                "title": f"Show evidence ({len(report.evidence)})",
                "targetElements": ["evidencePane"],
            }
        )

    if report.generated_artifact:
        try:
            artifact = parse_artifact(report.generated_artifact)
        except Exception:
            body.append(_tb("(artifact present but failed strict parse - see raw report)", isSubtle=True))
        else:
            a_body, a_actions = _artifact_body(artifact)
            body.extend(a_body)
            actions.extend(a_actions)

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.5",
        "body": body,
        "actions": actions,
    }
