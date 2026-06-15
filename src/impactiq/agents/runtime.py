"""Foundry project + credential wiring for the prompt-agent runtime.

The agent loop uses **only** ``AIProjectClient`` — the old ``AgentsClient``
from ``azure-ai-agents`` was dropped because the prompt-agent pattern
(``project.agents.create_version`` + ``openai.responses.create``) lives
entirely in ``azure-ai-projects``. ``ensure_os_trust`` keeps the Windows OS
cert store in the TLS path for every Foundry call (idempotent).
"""

from __future__ import annotations

from pathlib import Path

from azure.ai.projects import AIProjectClient
from azure.core.credentials import TokenCredential
from azure.identity import (
    AuthenticationRecord,
    ClientSecretCredential,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
    OnBehalfOfCredential,
    TokenCachePersistenceOptions,
)

from ..dataverse_client import ensure_os_trust
from ..settings import Settings


def _foundry_credential(settings: Settings) -> TokenCredential:
    """Pick a credential for Foundry + downstream MCP calls.

    Priority:
      1. ``ClientSecretCredential`` reusing the ``IMPACTIQ_*`` Entra app
         (deterministic; matches the existing service-identity pattern). This
         SP needs **Foundry User** at project scope, the **SharePoint** grant
         for the KB's SharePoint remote source, and the project MI needs
         **Search Index Data Reader** on the AI Search service.
      2. ``DefaultAzureCredential`` fallback (az login / VS Code / managed id).
    """
    ensure_os_trust()
    if (
        settings.entra_tenant_id
        and settings.impactiq_client_id
        and settings.impactiq_client_secret
    ):
        return ClientSecretCredential(
            tenant_id=settings.entra_tenant_id,
            client_id=settings.impactiq_client_id,
            client_secret=settings.impactiq_client_secret,
        )
    return DefaultAzureCredential()


# Where the delegated sign-in's AuthenticationRecord lands (gitignored).
# The record holds no tokens — those live in the OS-encrypted MSAL cache —
# it just lets later runs reuse the cached session without a browser pop.
_AUTH_RECORD_PATH = Path(".impactiq-user-auth.json")


def user_credential(settings: Settings) -> TokenCredential:
    """Delegated (signed-in user) credential — the Work IQ path.

    Work IQ rejects app-only auth: every request must carry a *user* context
    (it runs as the requesting user). The first call opens a browser sign-in;
    the session persists in the OS token cache so subsequent
    `cli ask --as-user` runs are silent.
    """
    ensure_os_trust()
    cache = TokenCachePersistenceOptions(name="impactiq-user")
    record: AuthenticationRecord | None = None
    if _AUTH_RECORD_PATH.exists():
        try:
            record = AuthenticationRecord.deserialize(
                _AUTH_RECORD_PATH.read_text(encoding="utf-8")
            )
        except Exception:
            record = None  # stale/corrupt record → fresh interactive sign-in
    cred = InteractiveBrowserCredential(
        tenant_id=settings.entra_tenant_id,
        cache_persistence_options=cache,
        authentication_record=record,
    )
    if record is None:
        record = cred.authenticate(scopes=["https://ai.azure.com/.default"])
        _AUTH_RECORD_PATH.write_text(record.serialize(), encoding="utf-8")
    return cred


def obo_credential(settings: Settings, user_assertion: str) -> TokenCredential:
    """On-Behalf-Of credential — the **production** delegated path.

    Exchanges a Teams user's access token (``user_assertion``) for downstream
    tokens *as that user* — no browser, no OS keyring (unlike
    ``user_credential``, which can't run on a headless host). One instance
    serves multiple scopes (one ``get_token`` per scope): ``ai.azure.com``
    for Foundry ``responses`` and ``{dataverse}`` for record reads and
    validated writes.

    Middle tier = the **impactiq-workiq** Entra app, which must hold delegated
    **Azure Machine Learning Services / user_impersonation** (for ai.azure.com)
    and **Dynamics CRM / user_impersonation** (for Dataverse) with admin
    consent (else AADSTS65001). Work IQ itself is still handled by Foundry's
    OAuth-passthrough connection, driven by the user-delegated ai.azure.com
    token — so the bridge only OBO-exchanges those two scopes.
    """
    ensure_os_trust()
    if not (
        settings.entra_tenant_id
        and settings.impactiq_workiq_client_id
        and settings.impactiq_workiq_client_secret
    ):
        raise RuntimeError(
            "OBO needs ENTRA_TENANT_ID + IMPACTIQ_WORKIQ_CLIENT_ID + "
            "IMPACTIQ_WORKIQ_CLIENT_SECRET (the middle-tier app)"
        )
    return OnBehalfOfCredential(
        tenant_id=settings.entra_tenant_id,
        client_id=settings.impactiq_workiq_client_id,
        client_secret=settings.impactiq_workiq_client_secret,
        user_assertion=user_assertion,
    )


def delegated_credential(
    settings: Settings, user_assertion: str | None = None
) -> TokenCredential:
    """The acts-as-the-user credential. OBO when a Teams token is supplied
    (production / surface), browser sign-in when not (local ``cli ask
    --as-user``). Every content read and validated write goes through this —
    never the read-only service identity."""
    return (
        obo_credential(settings, user_assertion)
        if user_assertion
        else user_credential(settings)
    )


def make_project_client(
    settings: Settings, *, as_user: bool = False, user_assertion: str | None = None
) -> AIProjectClient:
    """Build an ``AIProjectClient`` for the Foundry project.

    Used to: create prompt agents, get the OpenAI client for ``responses``,
    list deployments / connections (the KB connection lookup).

    ``as_user=True`` swaps the service principal for the signed-in user's
    delegated credential — required whenever the agent carries the Work IQ
    tool (OBO binds to the caller of ``responses.create``). Pass
    ``user_assertion`` (the Teams user's token) in production for the
    On-Behalf-Of exchange; omit it for the local browser sign-in.
    """
    if not settings.foundry_project_endpoint:
        raise RuntimeError("FOUNDRY_PROJECT_ENDPOINT is not set in .env")
    credential = (
        delegated_credential(settings, user_assertion)
        if as_user
        else _foundry_credential(settings)
    )
    return AIProjectClient(
        endpoint=settings.foundry_project_endpoint,
        credential=credential,
    )


def search_bearer_token(settings: Settings) -> str:
    """Acquire a bearer token for ``https://search.azure.com/.default``.

    Used for the SharePoint remote-source ``x-ms-query-source-authorization``
    header on the Foundry IQ KB MCP tool. Foundry Agent Service preview
    doesn't support per-request headers on MCP tools, so this token is
    captured **once** at agent-definition time and stays static for the
    agent version's lifetime.
    """
    cred = _foundry_credential(settings)
    token = cred.get_token("https://search.azure.com/.default")
    return token.token
