"""Caller identity from the forwarded Teams user token.

The surface forwards each user's Entra token as ``X-ImpactIQ-User-Token``.
This module extracts the identity claims (tenant id, object id, UPN) that
every security decision and audit row must be keyed by - display names are
neither unique nor immutable and are never used as identity.

Two levels are provided:

* :func:`token_identity` / :func:`token_owner` decode the JWT payload WITHOUT
  signature verification. They are used for best-effort labelling and as the
  claim source AFTER a token has already been verified upstream.
* :func:`verify_token` cryptographically verifies the token (signature against
  the tenant's published signing keys, plus issuer, audience, and expiry)
  before its claims may be trusted for proposal ownership or audit
  attribution. The bridge calls this on every path that carries a user token,
  so a forged or tampered assertion is rejected rather than merely failing the
  downstream On-Behalf-Of exchange later.
"""

from __future__ import annotations

import base64
import json
import threading

import jwt
from jwt import InvalidTokenError, PyJWKClient


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def token_identity(user_assertion: str | None) -> dict:
    """Best-effort claim extraction. Returns {} for a missing/garbled token.

    This does not verify the token; call :func:`verify_token` first on any path
    where the claims drive an authorization or attribution decision.
    """
    if not user_assertion:
        return {}
    try:
        payload = user_assertion.split(".")[1]
        claims = json.loads(_b64url_decode(payload))
    except Exception:  # noqa: BLE001 - malformed token == no identity
        return {}
    if not isinstance(claims, dict):
        return {}
    return {
        "tenant_id": claims.get("tid"),
        "object_id": claims.get("oid"),
        "upn": claims.get("preferred_username") or claims.get("upn"),
        "name": claims.get("name"),
        "app_id": claims.get("appid") or claims.get("azp"),
    }


def token_owner(user_assertion: str | None) -> tuple[str, str] | None:
    """The (tenant_id, object_id) pair that owner-binds pending state, or
    None when there is no token (local CLI / F5 development, single-user)."""
    ident = token_identity(user_assertion)
    tid, oid = ident.get("tenant_id"), ident.get("object_id")
    if tid and oid:
        return (str(tid), str(oid))
    return None


class TokenVerificationError(Exception):
    """The forwarded user token failed cryptographic or claim verification."""


# One JWKS client per tenant. PyJWKClient caches the fetched signing keys and
# refreshes them by key id, so verification does not hit the network per call.
_JWKS_CLIENTS: dict[str, PyJWKClient] = {}
_JWKS_LOCK = threading.Lock()


def _jwks_client(tenant_id: str) -> PyJWKClient:
    with _JWKS_LOCK:
        client = _JWKS_CLIENTS.get(tenant_id)
        if client is None:
            url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
            client = PyJWKClient(url, cache_keys=True)
            _JWKS_CLIENTS[tenant_id] = client
        return client


def verify_token(
    user_assertion: str,
    *,
    tenant_id: str,
    audiences: list[str] | None = None,
    leeway: int = 60,
) -> dict:
    """Verify the token and return its claims, or raise TokenVerificationError.

    Checks the RS256 signature against the tenant's published keys and enforces
    expiry / not-before (with a small clock-skew ``leeway``). The token's ``tid``
    must match the configured tenant. When ``audiences`` is given, the ``aud``
    claim must be one of them, which binds the token to this API and prevents a
    token minted for a different resource from being replayed here.
    """
    if not user_assertion:
        raise TokenVerificationError("no token presented")
    try:
        signing_key = _jwks_client(tenant_id).get_signing_key_from_jwt(user_assertion)
        options = {"require": ["exp", "iat"], "verify_aud": bool(audiences)}
        claims = jwt.decode(
            user_assertion,
            signing_key.key,
            algorithms=["RS256"],
            audience=audiences if audiences else None,
            leeway=leeway,
            options=options,
        )
    except InvalidTokenError as exc:
        raise TokenVerificationError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - JWKS fetch / key errors are failures too
        raise TokenVerificationError(f"could not verify token: {exc}") from exc

    claim_tid = str(claims.get("tid") or "")
    if claim_tid != str(tenant_id):
        raise TokenVerificationError("token tenant does not match the configured tenant")
    return claims
