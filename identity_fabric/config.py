"""Runtime settings, read once from the environment.

Nothing is read at import time so modules stay importable in tests and tooling;
call get_settings() where a value is needed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


class ConfigError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"Missing required environment variable {name}")
    return value


@dataclass(frozen=True)
class Settings:
    surreal_url: str
    surreal_user: str
    surreal_pass: str
    surreal_ns: str
    surreal_db: str
    enc_key: bytes
    hmac_key: bytes
    agent_secret: str | None
    logto_endpoint: str | None
    logto_audience: str | None
    tenant_claim: str
    default_tenant_id: str | None
    max_edge_depth: int
    ttl_hours: int


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    enc_hex = _required("IDENTITY_FABRIC_ENC_KEY")
    try:
        enc_key = bytes.fromhex(enc_hex)
    except ValueError as e:
        raise ConfigError("IDENTITY_FABRIC_ENC_KEY must be hex (openssl rand -hex 32)") from e
    if len(enc_key) != 32:
        raise ConfigError("IDENTITY_FABRIC_ENC_KEY must decode to 32 bytes (AES-256)")

    logto = os.environ.get("LOGTO_ENDPOINT", "").strip().rstrip("/") or None
    return Settings(
        surreal_url=os.environ.get("SURREAL_URL", "ws://surrealdb:8000/rpc"),
        surreal_user=os.environ.get("SURREAL_USER", "root"),
        surreal_pass=_required("SURREAL_PASS"),
        surreal_ns=os.environ.get("SURREAL_NS", "autonomyx"),
        surreal_db=os.environ.get("SURREAL_DB", "identity_fabric"),
        enc_key=enc_key,
        hmac_key=_required("IDENTITY_FABRIC_HMAC_KEY").encode(),
        agent_secret=os.environ.get("AUTONOMYX_AGENT_SECRET") or None,
        logto_endpoint=logto,
        logto_audience=os.environ.get("LOGTO_AUDIENCE") or None,
        tenant_claim=os.environ.get("TENANT_CLAIM", "tenant_id"),
        default_tenant_id=os.environ.get("DEFAULT_TENANT_ID") or None,
        max_edge_depth=int(os.environ.get("MAX_EDGE_DEPTH", "3")),
        ttl_hours=int(os.environ.get("ENRICH_TTL_HOURS", "24")),
    )
