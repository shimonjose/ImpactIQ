"""Estate-side change-collision scan - recently-edited components in the blast
radius."""

from __future__ import annotations

from impactiq.graph import ImpactGraph, recent_change_scan, walk


def test_recent_editor_in_radius_is_flagged(graph: ImpactGraph, now_str: str):
    """The 14-day window catches close_request (8 days ago) but not
    assign_owner (~ 5 months ago)."""
    anchor = graph.node("column:request.status")
    radius = walk(graph, anchor, intent="VALIDATE", direction="both", depth=2)

    hits = recent_change_scan(radius, now=now_str, threshold_days=14)
    flagged_ids = {c.component.id for c in hits}

    assert "flow:close_request" in flagged_ids
    assert "flow:assign_owner" not in flagged_ids
    # And we have the editor identity (the bit that makes it actionable).
    close_change = next(c for c in hits if c.component.id == "flow:close_request")
    assert close_change.modified_by_id == "user-alice"
    assert close_change.days_ago is not None
    assert close_change.days_ago <= 14


def test_unrelated_recent_edits_outside_the_radius_are_ignored(
    graph: ImpactGraph, now_str: str
):
    """notify_contact was edited yesterday but it isn't in the request.status
    radius - the scan respects the walk's scope."""
    anchor = graph.node("column:request.status")
    radius = walk(graph, anchor, intent="VALIDATE", direction="both", depth=2)
    hits = recent_change_scan(radius, now=now_str, threshold_days=14)
    assert all(c.component.id != "flow:notify_contact" for c in hits)


def test_threshold_is_respected(graph: ImpactGraph, now_str: str):
    anchor = graph.node("column:request.status")
    radius = walk(graph, anchor, intent="VALIDATE", direction="both", depth=2)

    # A short window drops close_request.
    short = {c.component.id for c in recent_change_scan(radius, now=now_str, threshold_days=3)}
    assert "flow:close_request" not in short

    # A long window picks both flows up (assign_owner ~138 days ago).
    long = {c.component.id for c in recent_change_scan(radius, now=now_str, threshold_days=365)}
    assert "flow:close_request" in long
    assert "flow:assign_owner" in long


def test_components_without_modified_on_are_skipped(graph: ImpactGraph, now_str: str):
    """No metadata -> we don't know, don't flag (architectural: 'we don't
    know' is not 'recently changed')."""
    anchor = graph.node("view:open_requests")
    radius = walk(graph, anchor, intent="VALIDATE", direction="both", depth=2)
    hits = recent_change_scan(radius, now=now_str, threshold_days=14)
    # The view itself has no modified_on - never flagged.
    assert all(c.component.id != "view:open_requests" for c in hits)
