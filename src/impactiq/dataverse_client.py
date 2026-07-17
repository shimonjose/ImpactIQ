"""Minimal, read-only Dataverse Web API client + the read-only privilege audit.

Provides client-credentials auth for the structure service identity, a small
GET helper, and the safety assertion that the bound app user has NO write
privileges. The connectors build on this same client.

Read-only by construction: this module exposes only GET. There is no POST/PATCH/
DELETE path here, so it cannot mutate the tenant even if mis-called.

Verified against the Dataverse Web API:
  - WhoAmI (unbound function) -> UserId / BusinessUnitId / OrganizationId
  - RetrieveUserPrivileges (bound to systemuser) -> RolePrivileges[] with
    PrivilegeName + Depth
  - confidential-client token scope = "<env-url>/.default"
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from azure.identity import ClientSecretCredential

from .settings import Settings

_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


def _encode_function_param(value: object) -> str:
    """Encode a Web API unbound-function parameter for the URL path.

    Bare for GUIDs/ints/bools, single-quoted + URL-escaped for strings (per
    Dataverse Web API v9.2). Doubles inner single quotes per OData rules.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        if _GUID_RE.match(value):
            return value
        return "'" + quote(value.replace("'", "''"), safe="") + "'"
    raise TypeError(f"Unsupported function parameter type: {type(value).__name__}")

API_VERSION = "v9.2"

_TRUST_INJECTED = False


def ensure_os_trust() -> None:
    """Route TLS verification through the OS cert store (idempotent).

    Lets corporate/AV TLS-interception roots that live in the Windows store be
    trusted by both azure-identity and httpx without shipping a custom CA file.
    """
    global _TRUST_INJECTED
    if _TRUST_INJECTED:
        return
    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception:
        # truststore optional/unavailable -> fall back to certifi defaults.
        pass
    _TRUST_INJECTED = True

# Privilege-name prefixes that mean "can change data". A correctly configured
# read-only role yields only prvRead* entries; any of these means write access.
WRITE_PRIVILEGE_PREFIXES = (
    "prvCreate",
    "prvWrite",
    "prvDelete",
    "prvAppend",  # also covers prvAppendTo
    "prvAssign",
    "prvShare",
)


class DataverseError(RuntimeError):
    """A non-2xx Web API response (message extracted, never secrets)."""


@dataclass
class ReadOnlyAudit:
    total_privileges: int
    read_privileges: int
    write_privileges: list[str]  # offending prvCreate/Write/Delete/... names

    @property
    def is_read_only(self) -> bool:
        return not self.write_privileges


class DataverseClient:
    """Authenticated, GET-only Web API client for the service identity."""

    def __init__(self, settings: Settings):
        missing = settings.missing_service_vars()
        if missing:
            raise DataverseError(
                "Service identity not configured; unset .env: " + ", ".join(missing)
            )
        ensure_os_trust()
        # mypy/readers: these are non-None past the guard above.
        self.base_url = settings.dataverse_url.rstrip("/")  # type: ignore[union-attr]
        self.api_base = f"{self.base_url}/api/data/{API_VERSION}"
        self._scope = f"{self.base_url}/.default"
        self._credential = ClientSecretCredential(
            tenant_id=settings.entra_tenant_id,  # type: ignore[arg-type]
            client_id=settings.impactiq_client_id,  # type: ignore[arg-type]
            client_secret=settings.impactiq_client_secret,  # type: ignore[arg-type]
        )
        self._token: str | None = None
        self._token_expiry: float = 0.0
        self._http = httpx.Client(timeout=30.0)

    # -- context manager -----------------------------------------------------
    def __enter__(self) -> "DataverseClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    # -- auth ----------------------------------------------------------------
    def _bearer(self) -> str:
        # Refresh ~1 min before expiry. Token value is never logged.
        if self._token is None or time.time() >= self._token_expiry - 60:
            tok = self._credential.get_token(self._scope)
            self._token = tok.token
            self._token_expiry = float(tok.expires_on)
        return self._token

    # -- low-level GET (the only verb this client supports) ------------------
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._bearer()}",
            "Accept": "application/json",
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
        }

    def get(self, path: str, params: dict | None = None) -> dict:
        resp = self._http.get(
            f"{self.api_base}/{path}", params=params, headers=self._headers()
        )
        if resp.status_code >= 400:
            raise DataverseError(self._error_message(resp))
        return resp.json()

    def get_all(self, path: str, params: dict | None = None) -> list[dict]:
        """Paginated GET; follows @odata.nextLink to exhaust the collection."""
        data = self.get(path, params)
        rows: list[dict] = list(data.get("value", []))
        next_link = data.get("@odata.nextLink")
        while next_link:
            resp = self._http.get(next_link, headers=self._headers())
            if resp.status_code >= 400:
                raise DataverseError(self._error_message(resp))
            data = resp.json()
            rows.extend(data.get("value", []))
            next_link = data.get("@odata.nextLink")
        return rows

    def call_function(self, name: str, **params: object) -> dict:
        """Invoke an unbound Web API function with inline path parameters.

        Example: client.call_function("RetrieveDependentComponents",
                                     ObjectId="<guid>", ComponentType=29)
        """
        if params:
            encoded = ",".join(f"{k}={_encode_function_param(v)}" for k, v in params.items())
            path = f"{name}({encoded})"
        else:
            path = name
        return self.get(path)

    @staticmethod
    def _error_message(resp: httpx.Response) -> str:
        detail = resp.text
        try:
            body = resp.json()
            if isinstance(body, dict) and "error" in body:
                err = body["error"]
                detail = err.get("message", detail)
        except Exception:
            pass
        return f"HTTP {resp.status_code} from Dataverse: {detail[:500]}"

    # -- read helpers --------------------------------------------------------
    def whoami(self) -> dict:
        """UserId / BusinessUnitId / OrganizationId for the calling identity."""
        return self.get("WhoAmI")

    def organization(self) -> dict | None:
        """The org's unique name (proves the environment)."""
        data = self.get("organizations", {"$select": "name"})
        rows = data.get("value", [])
        return rows[0] if rows else None

    def first_table(self) -> str | None:
        """One table logical name (proves metadata read works).

        EntityDefinitions does not support $top, so fetch the lean projection
        and take the first row.
        """
        data = self.get("EntityDefinitions", {"$select": "LogicalName"})
        rows = data.get("value", [])
        return rows[0]["LogicalName"] if rows else None

    def user_role_privileges(self, user_id: str) -> list[dict]:
        """RolePrivileges[] the app user holds (via roles + team membership)."""
        data = self.get(
            f"systemusers({user_id})/Microsoft.Dynamics.CRM.RetrieveUserPrivileges()"
        )
        return data.get("RolePrivileges", [])

    def audit_read_only(self, user_id: str) -> ReadOnlyAudit:
        """Assert the service identity has no write privileges."""
        privs = self.user_role_privileges(user_id)
        names = [p.get("PrivilegeName", "") for p in privs]
        writes = sorted({n for n in names if n.startswith(WRITE_PRIVILEGE_PREFIXES)})
        reads = sum(1 for n in names if n.startswith("prvRead"))
        return ReadOnlyAudit(
            total_privileges=len(privs),
            read_privileges=reads,
            write_privileges=writes,
        )
