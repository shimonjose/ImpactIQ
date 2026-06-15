"""On-Behalf-Of (OBO) delegated identity — the production path that replaces
the headless-incompatible browser sign-in.

Pins:
- ``obo_credential`` / ``delegated_credential`` build an ``OnBehalfOfCredential``
  from the impactiq-workiq middle-tier app when a Teams user token is supplied.
- ``make_project_client(as_user=True, user_assertion=...)`` uses that OBO
  credential (not the browser credential).
- A hosted as-user request with NO token returns the clean needs-signin shape
  instead of constructing a browser credential (which crashes headless).
"""

from __future__ import annotations

import dataclasses

import pytest
from azure.identity import OnBehalfOfCredential

import impactiq.agents.runtime as runtime
import impactiq.server as srv
from impactiq.settings import Settings


def _settings_with_obo(**over) -> Settings:
    base = Settings()
    return dataclasses.replace(
        base,
        entra_tenant_id="tenant-1",
        impactiq_workiq_client_id="workiq-app-id",
        impactiq_workiq_client_secret="workiq-secret",
        foundry_project_endpoint="https://example.services.ai.azure.com/api/projects/p",
        **over,
    )


def test_obo_credential_is_on_behalf_of():
    cred = runtime.obo_credential(_settings_with_obo(), "user-token-abc")
    assert isinstance(cred, OnBehalfOfCredential)


def test_obo_requires_middle_tier_app():
    # No impactiq-workiq client id/secret → cannot OBO.
    bare = dataclasses.replace(
        Settings(), entra_tenant_id="t", impactiq_workiq_client_id=None,
        impactiq_workiq_client_secret=None,
    )
    with pytest.raises(RuntimeError):
        runtime.obo_credential(bare, "tok")


def test_delegated_credential_obo_when_token_present():
    cred = runtime.delegated_credential(_settings_with_obo(), "tok")
    assert isinstance(cred, OnBehalfOfCredential)


def test_make_project_client_uses_obo_with_assertion(monkeypatch):
    captured: dict = {}

    class _FakeClient:
        def __init__(self, *, endpoint, credential, **kw):
            captured["credential"] = credential

    monkeypatch.setattr(runtime, "AIProjectClient", _FakeClient)
    runtime.make_project_client(_settings_with_obo(), as_user=True, user_assertion="tok")
    assert isinstance(captured["credential"], OnBehalfOfCredential)


def test_make_project_client_service_identity_when_not_as_user(monkeypatch):
    # The service path must NEVER become an OBO/browser credential.
    captured: dict = {}

    class _FakeClient:
        def __init__(self, *, endpoint, credential, **kw):
            captured["credential"] = credential

    monkeypatch.setattr(runtime, "AIProjectClient", _FakeClient)
    runtime.make_project_client(
        _settings_with_obo(impactiq_client_id="svc", impactiq_client_secret="x"),
        as_user=False,
    )
    assert not isinstance(captured["credential"], OnBehalfOfCredential)


def test_hosted_agent_without_token_returns_needs_signin(monkeypatch):
    # Hosted (App Service) + no Teams token → ask the user to sign in rather
    # than fall through to the browser credential (which crashes headless).
    monkeypatch.setattr(srv, "_HOSTED", True)
    req = srv.AgentRequest(request="what flows are in the solution?", conversation="c")
    result = srv._run_unified_agent(req, user_assertion=None)
    assert result["status"] == "needs_signin"
    assert "sign in" in result["text"].lower()


def test_not_hosted_without_token_does_not_force_signin(monkeypatch):
    # Local dev (not hosted): the absent-token path must NOT short-circuit to
    # needs-signin — it falls back to the browser sign-in as before.
    monkeypatch.setattr(srv, "_HOSTED", False)
    assert srv._needs_signin(None) is False
