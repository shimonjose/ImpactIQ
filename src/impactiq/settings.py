"""Configuration loader for ImpactIQ.

Values come from the local ``.env`` file (or the real environment). Secrets live
only in ``.env`` (gitignored); ``.env.example`` carries empty placeholders.

Safety: this module never logs or echoes a secret value. Secret fields are
excluded from the dataclass ``repr`` and only ever surfaced through
:func:`masked`, which reports presence — not content.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import find_dotenv, load_dotenv

# Load the nearest .env up from the CWD. Real environment variables win over
# .env so shell/CI exports take precedence (override=False).
load_dotenv(find_dotenv(usecwd=True), override=False)


def _get(name: str) -> str | None:
    val = os.getenv(name)
    if val is not None:
        val = val.strip()
    return val or None


def masked(value: str | None) -> str:
    """Presence-only rendering of a secret. Never returns the actual value."""
    return "**** (set)" if value else "(unset)"


@dataclass(frozen=True)
class Settings:
    # ── Read-only service identity (client credentials) ──────────────────────
    dataverse_url: str | None = field(default_factory=lambda: _get("DATAVERSE_URL"))
    # The solution to scope the estate analysis to. Tenant-specific config — set
    # IMPACTIQ_SOLUTION in .env. The fallback is only a convenience for the
    # reference sample; production tenants set their own (the code never hardcodes
    # a solution name anywhere else — request models / CLI read this).
    solution: str = field(
        default_factory=lambda: _get("IMPACTIQ_SOLUTION") or "Enterprise CRM"
    )
    # Optional: model-driven app id for "Open in Power Apps" deep links on record
    # cards. Without it the link opens the default app experience.
    powerapps_app_id: str | None = field(default_factory=lambda: _get("POWERAPPS_APP_ID"))
    entra_tenant_id: str | None = field(default_factory=lambda: _get("ENTRA_TENANT_ID"))
    impactiq_client_id: str | None = field(default_factory=lambda: _get("IMPACTIQ_CLIENT_ID"))
    # repr=False: keep the secret out of any accidental print(settings).
    impactiq_client_secret: str | None = field(
        default_factory=lambda: _get("IMPACTIQ_CLIENT_SECRET"), repr=False
    )

    # ── Azure AI Foundry project + chat model ────────────────────────────────
    foundry_project_endpoint: str | None = field(
        default_factory=lambda: _get("FOUNDRY_PROJECT_ENDPOINT")
    )
    foundry_model_deployment: str | None = field(
        default_factory=lambda: _get("FOUNDRY_MODEL_DEPLOYMENT")
    )
    foundry_specialist_deployment: str | None = field(
        default_factory=lambda: _get("FOUNDRY_SPECIALIST_DEPLOYMENT")
    )
    # High-throughput / long-context deployment for the HEAVY reasoning loops
    # (the unified agent and the deep-pipeline specialists), which re-send the
    # full instruction + tool schemas on every hop and so burn most tokens.
    # Small single-purpose turns (ack, bounded-write writer, mail drafter) stay
    # on foundry_model_deployment — separate quota pools, and the bounded write
    # path keeps the known-good model. Unset => everything uses the default
    # deployment (one-line rollback).
    foundry_heavy_model_deployment: str | None = field(
        default_factory=lambda: _get("FOUNDRY_HEAVY_MODEL_DEPLOYMENT")
    )

    @property
    def heavy_model_deployment(self) -> str | None:
        return self.foundry_heavy_model_deployment or self.foundry_model_deployment

    # ── Builder (sandbox fix carve-out) ──────────────────────────────────────
    # A SEPARATE environment; the builder module refuses to run against the
    # analysis env. Fix-only, dedicated solution, role-gated.
    build_dataverse_url: str | None = field(
        default_factory=lambda: _get("BUILD_DATAVERSE_URL")
    )
    impactiq_build_solution: str | None = field(
        default_factory=lambda: _get("IMPACTIQ_BUILD_SOLUTION")
    )
    impactiq_builder_role: str | None = field(
        default_factory=lambda: _get("IMPACTIQ_BUILDER_ROLE") or "ImpactIQ Builder"
    )

    # ── Foundry IQ knowledge base (MCP-attached KB) ──────────────────────────
    # AISEARCH_ENDPOINT is the AI Search service URL (used to build the KB MCP
    # endpoint `{endpoint}/knowledgebases/{kb}/mcp?...`).
    # FOUNDRY_KB_NAME is the knowledge base name on the search service.
    # FOUNDRY_KB_CONNECTION_NAME is the Foundry project `RemoteTool` connection
    # name (the project MI authenticates via this connection to the MCP endpoint).
    aisearch_endpoint: str | None = field(default_factory=lambda: _get("AISEARCH_ENDPOINT"))
    foundry_kb_name: str | None = field(default_factory=lambda: _get("FOUNDRY_KB_NAME"))
    foundry_kb_connection_name: str | None = field(
        default_factory=lambda: _get("FOUNDRY_KB_CONNECTION_NAME")
    )

    # ── Work IQ (A2A, delegated user identity) ───────────────────────────────
    # FOUNDRY_WORKIQ_CONNECTION_ID is the full ARM resource ID of the project's
    # Work IQ connection (category RemoteA2A). The impactiq-workiq Entra app's
    # client id/secret also live INSIDE that connection (for connection
    # rebuilds) — AND are read at runtime for the production On-Behalf-Of flow:
    # the bridge uses impactiq-workiq as the OBO middle-tier app to exchange a
    # Teams user's token for ai.azure.com + Dataverse tokens (see runtime.py
    # obo_credential). Requires the app to hold delegated "Azure Machine
    # Learning Services / user_impersonation" + "Dynamics CRM / user_impersonation"
    # with admin consent.
    foundry_workiq_connection_id: str | None = field(
        default_factory=lambda: _get("FOUNDRY_WORKIQ_CONNECTION_ID")
    )
    impactiq_workiq_client_id: str | None = field(
        default_factory=lambda: _get("IMPACTIQ_WORKIQ_CLIENT_ID")
    )
    impactiq_workiq_client_secret: str | None = field(
        default_factory=lambda: _get("IMPACTIQ_WORKIQ_CLIENT_SECRET")
    )
    # Work IQ MCP server connections (one per surface). Each is a
    # Foundry connection id/name; tools are allow-listed in agents/workiq.py.
    # Mail = draft-only; User = read-only; Dataverse = records-only (no
    # schema/delete); Calendar/Word/Teams mutations are confirm-gated.
    foundry_workiq_mail_connection_id: str | None = field(
        default_factory=lambda: _get("FOUNDRY_WORKIQ_MAIL_CONNECTION_ID")
    )
    foundry_workiq_user_connection_id: str | None = field(
        default_factory=lambda: _get("FOUNDRY_WORKIQ_USER_CONNECTION_ID")
    )
    foundry_workiq_dataverse_connection_id: str | None = field(
        default_factory=lambda: _get("FOUNDRY_WORKIQ_DATAVERSE_CONNECTION_ID")
    )
    # The Dataverse MCP server is per-environment: its endpoint is
    # .../servers/Dataverse/{env_id}, unlike the fixed mcp_* servers.
    foundry_workiq_dataverse_env_id: str | None = field(
        default_factory=lambda: _get("FOUNDRY_WORKIQ_DATAVERSE_ENV_ID")
    )
    foundry_workiq_calendar_connection_id: str | None = field(
        default_factory=lambda: _get("FOUNDRY_WORKIQ_CALENDAR_CONNECTION_ID")
    )
    foundry_workiq_word_connection_id: str | None = field(
        default_factory=lambda: _get("FOUNDRY_WORKIQ_WORD_CONNECTION_ID")
    )
    foundry_workiq_teams_connection_id: str | None = field(
        default_factory=lambda: _get("FOUNDRY_WORKIQ_TEAMS_CONNECTION_ID")
    )

    # The .env keys that back the read-only service identity.
    SERVICE_IDENTITY_VARS = (
        "DATAVERSE_URL",
        "ENTRA_TENANT_ID",
        "IMPACTIQ_CLIENT_ID",
        "IMPACTIQ_CLIENT_SECRET",
    )

    def missing_service_vars(self) -> list[str]:
        """Names of service-identity .env vars that are still unset."""
        current = {
            "DATAVERSE_URL": self.dataverse_url,
            "ENTRA_TENANT_ID": self.entra_tenant_id,
            "IMPACTIQ_CLIENT_ID": self.impactiq_client_id,
            "IMPACTIQ_CLIENT_SECRET": self.impactiq_client_secret,
        }
        return [name for name in self.SERVICE_IDENTITY_VARS if not current[name]]

    def has_service_identity(self) -> bool:
        return not self.missing_service_vars()


def get_settings() -> Settings:
    """Build a fresh Settings snapshot from the current environment."""
    return Settings()
