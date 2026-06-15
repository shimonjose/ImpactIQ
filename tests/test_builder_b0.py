"""The Builder walls.

These tests pin the sandbox carve-out's refusal behaviour BEFORE any executor
exists: no sandbox URL, same-environment, and missing solution scope must
all refuse loudly. The walls are the contract that lets the project tolerate
configuration writes at all.
"""

from types import SimpleNamespace

import pytest

from impactiq.builder import BuilderRefusal, FixReport, assert_builder_walls


def _settings(**kw):
    base = {
        "dataverse_url": "https://example.crm.dynamics.com",
        "build_dataverse_url": "https://sandbox123.crm6.dynamics.com",
        "impactiq_build_solution": "ImpactIQSandbox",
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_walls_pass_with_distinct_sandbox():
    url = assert_builder_walls(_settings())
    assert url == "https://sandbox123.crm6.dynamics.com"


def test_refuses_when_sandbox_unset():
    with pytest.raises(BuilderRefusal, match="BUILD_DATAVERSE_URL is not set"):
        assert_builder_walls(_settings(build_dataverse_url=None))


def test_refuses_same_environment_even_with_cosmetic_differences():
    """Trailing slash / case must not smuggle the analysis env past the wall."""
    s = _settings(build_dataverse_url="HTTPS://ORG161C993F.CRM6.DYNAMICS.COM/")
    with pytest.raises(BuilderRefusal, match="refuses to write to the analysis"):
        assert_builder_walls(s)


def test_refuses_without_solution_scope():
    with pytest.raises(BuilderRefusal, match="IMPACTIQ_BUILD_SOLUTION"):
        assert_builder_walls(_settings(impactiq_build_solution="  "))


def test_fix_report_contract_shape():
    r = FixReport()
    r.done.append({"component": "flow:Send Complaint", "change": "filter fixed"})
    r.outstanding.append({"step": "reconnect O365 connection", "reason": "SP cannot auth"})
    d = r.to_dict()
    assert set(d) == {"done", "partial", "outstanding"}
    assert d["partial"] == []


def test_settings_expose_builder_fields():
    from impactiq.settings import get_settings

    s = get_settings()
    # May be unset locally — but the fields must exist, and the role has a
    # platform-visible default.
    assert hasattr(s, "build_dataverse_url")
    assert hasattr(s, "impactiq_build_solution")
    assert s.impactiq_builder_role == "ImpactIQ Builder"
