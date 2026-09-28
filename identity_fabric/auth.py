"""Caller authentication: Logto access tokens (JWT) or the operator agent secret."""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from functools import lru_cache

import jwt
from fastapi import HTTPException, Request

from .config import get_settings

SCOPE_READ = "identity:read"
SCOPE_ADMIN = "identity:admin"


@dataclass(frozen=True)
class Caller:
    actor: str
    operator: bool = False
    sub: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    token_tenant: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.operator or SCOPE_ADMIN in self.scopes

    @property
    def can_read(self) -> bool:
        return self.is_admin or SCOPE_READ in self.scopes


class AuthError(Exception):
    pass


@lru_cache(maxsize=1)
def _jwks_client(endpoint: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(f"{endpoint}/oidc/jwks", cache_keys=True, lifespan=3600)


def verify_logto_token(token: str) -> dict:
    s = get_settings()
    if not s.logto_endpoint or not s.logto_audience:
        raise AuthError("Logto is not configured (LOGTO_ENDPOINT / LOGTO_AUDIENCE)")
    try:
        key = _jwks_client(s.logto_endpoint).get_signing_key_from_jwt(token)
        return jwt.decode(
            token, key.key,
            algorithms=["ES384", "ES256", "RS256"],
            issuer=f"{s.logto_endpoint}/oidc",
            audience=s.logto_audience,
            options={"require": ["exp", "iss", "sub"]},
        )
    except jwt.PyJWTError as e:
        raise AuthError(f"Invalid token: {e}") from e


def authenticate(request: Request) -> Caller:
    """FastAPI dependency (sync: JWKS fetch runs in the threadpool)."""
    s = get_settings()
    secret = request.headers.get("x-agent-secret")
    if secret:
        if s.agent_secret and hmac.compare_digest(secret, s.agent_secret):
            return Caller(actor="operator", operator=True)
        raise HTTPException(401, "Invalid agent secret")

    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = verify_logto_token(header[7:].strip())
    except AuthError as e:
        raise HTTPException(401, str(e), headers={"WWW-Authenticate": "Bearer"}) from e

    scopes = frozenset(str(claims.get("scope", "")).split())
    return Caller(
        actor=f"logto:{claims['sub']}",
        sub=claims["sub"],
        scopes=scopes,
        token_tenant=claims.get(s.tenant_claim) or None,
    )


def tenant_for(caller: Caller, requested: str | None) -> str:
    """Operators name the tenant; token callers are pinned to their token's tenant."""
    if caller.operator:
        if not requested:
            raise HTTPException(400, "tenant_id is required for operator calls")
        return requested
    tenant = caller.token_tenant or get_settings().default_tenant_id
    if not tenant:
        raise HTTPException(403, "Token carries no tenant and DEFAULT_TENANT_ID is not set")
    if requested and requested != tenant:
        raise HTTPException(403, "tenant_id does not match the caller's tenant")
    return tenant
