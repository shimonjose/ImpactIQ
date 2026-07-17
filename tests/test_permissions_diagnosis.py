"""Permissions-diagnosis path - the classic 'read-but-not-write' case plus the
field-security blocker case."""

from __future__ import annotations

from impactiq.graph import diagnose_permission


def test_read_but_not_write_is_the_likely_cause():
    """The headline outcome: user can see the table, can't update it."""
    diag = diagnose_permission(
        user_id="sarah",
        table_logical="request",
        action="write",
        user_roles=[{"roleid": "viewer-role", "name": "Viewer"}],
        role_privileges={"viewer-role": ["prvReadRequest"]},
    )
    assert diag.granted is False
    assert "Viewer" in diag.user_roles
    assert "prvReadRequest" in diag.relevant_privileges
    assert "read-but-not-write" in diag.likely_cause.lower()
    assert diag.recommended_fix is not None
    assert "Write" in diag.recommended_fix


def test_grant_present_marks_diagnosis_granted():
    diag = diagnose_permission(
        user_id="sarah",
        table_logical="request",
        action="write",
        user_roles=[{"roleid": "agent-role", "name": "Agent"}],
        role_privileges={"agent-role": ["prvReadRequest", "prvWriteRequest"]},
    )
    assert diag.granted is True
    # When granted, the next-cause hint should still be useful (ownership / BR).
    assert "ownership" in diag.likely_cause.lower() or "business rule" in diag.likely_cause.lower()


def test_field_security_blocker_overrides_table_privilege():
    """Column-level FSP deny wins even when table privilege exists."""
    diag = diagnose_permission(
        user_id="sarah",
        table_logical="request",
        action="write",
        user_roles=[{"roleid": "agent-role", "name": "Agent"}],
        role_privileges={"agent-role": ["prvReadRequest", "prvWriteRequest"]},
        field_security_blockers=["statuscode"],
    )
    assert diag.granted is False
    assert "statuscode" in diag.field_security_blockers
    assert "field-level security" in diag.likely_cause.lower()
    assert diag.recommended_fix is not None
    assert "Field Security Profile" in diag.recommended_fix


def test_no_relevant_privileges_yields_generic_missing_role_advice():
    diag = diagnose_permission(
        user_id="sarah",
        table_logical="request",
        action="write",
        user_roles=[{"roleid": "approver-role", "name": "Approver"}],
        role_privileges={"approver-role": ["prvReadAccount"]},  # different table
    )
    assert diag.granted is False
    assert diag.relevant_privileges == []
    # No read privilege present either -> generic missing-role cause, NOT the
    # specific 'read-but-not-write' phrasing.
    assert "none of the user's roles" in diag.likely_cause.lower()
