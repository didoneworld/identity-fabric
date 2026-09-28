"""HTTP API for the Identity Fabric."""

from __future__ import annotations

import logging
from typing import Annotated, Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import __version__, modes
from .auth import Caller, authenticate, tenant_for
from .connectors import run_health_checks
from .connectors.base import ConnectorError, TokenExpiredError
from .db import DatabaseError, connect
from .graph import is_owned_by, write_audit

log = logging.getLogger("identity_fabric")

app = FastAPI(title="Identity Fabric", version=__version__)
CallerDep = Annotated[Caller, Depends(authenticate)]


@app.exception_handler(DatabaseError)
async def _db_error(_: Request, exc: DatabaseError) -> JSONResponse:
    log.error("database error: %s", exc)
    return JSONResponse({"detail": "database_error"}, status_code=503)


@app.exception_handler(ConnectorError)
async def _connector_error(_: Request, exc: ConnectorError) -> JSONResponse:
    status = 422 if isinstance(exc, TokenExpiredError) else 502
    return JSONResponse({"detail": "provider_error", "provider": exc.provider,
                         "message": str(exc)}, status_code=status)


@app.exception_handler(httpx.HTTPError)
async def _provider_unreachable(_: Request, exc: httpx.HTTPError) -> JSONResponse:
    log.warning("provider request failed: %s", exc)
    return JSONResponse({"detail": "provider_unreachable"}, status_code=502)


@app.middleware("http")
async def _audit_unauthorized(request: Request, call_next):
    """Record rejected callers in audit_log, as the compliance posture requires."""
    response = await call_next(request)
    if response.status_code == 401 and request.url.path.startswith("/v1/"):
        try:
            async with connect() as db:
                await write_audit(db, "unknown", "AUTH_FAILED", "anonymous",
                                  detail=f"{request.method} {request.url.path}")
        except Exception:  # never mask the 401 because the audit write failed
            log.exception("could not write AUTH_FAILED audit entry")
    return response


def _require_admin(caller: Caller) -> None:
    if not caller.is_admin:
        raise HTTPException(403, "identity:admin scope required")


def _require_read(caller: Caller) -> None:
    if not caller.can_read:
        raise HTTPException(403, "identity:read scope required")


# ── health ───────────────────────────────────────────────────────────────────

@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/readyz", include_in_schema=False)
async def readyz() -> dict:
    async with connect() as db:
        await db.query("RETURN 1")
    return {"status": "ready"}


# ── RESOLVE ──────────────────────────────────────────────────────────────────

class ResolveIn(BaseModel):
    identifier: str = Field(min_length=1, max_length=320)
    tenant_id: str | None = None


@app.post("/v1/resolve")
async def resolve(body: ResolveIn, caller: CallerDep) -> dict:
    _require_read(caller)
    tenant = tenant_for(caller, body.tenant_id)
    async with connect() as db:
        result = await modes.resolve(db, body.identifier, tenant, caller.actor)
    if not caller.is_admin and result["resolution_status"] == "found":
        if not is_owned_by(result["accounts"], "logto", caller.sub or ""):
            raise HTTPException(403, "identity:read may only resolve the caller's own identity")
    return result


# ── INGEST / ENRICH ──────────────────────────────────────────────────────────

class IngestIn(BaseModel):
    provider: str
    token: str | None = None
    identifier: str = ""
    tenant_id: str | None = None
    consent: bool = Field(description="Caller confirms the data subject consented to linkage")


@app.post("/v1/accounts", status_code=201)
async def ingest(body: IngestIn, caller: CallerDep) -> dict:
    _require_admin(caller)
    if not body.consent:
        raise HTTPException(400, "consent must be true")
    if not body.token and not body.identifier:
        raise HTTPException(400, "token or identifier is required")
    tenant = tenant_for(caller, body.tenant_id)
    async with connect() as db:
        return await modes.ingest(db, tenant, body.provider, caller.actor,
                                  token=body.token, identifier=body.identifier)


class EnrichIn(BaseModel):
    tokens: dict[str, str] = Field(description="{account_id: provider access token}", min_length=1)
    tenant_id: str | None = None
    consent: bool


@app.post("/v1/enrich")
async def enrich(body: EnrichIn, caller: CallerDep) -> dict:
    _require_read(caller)
    if not body.consent:
        raise HTTPException(400, "consent must be true")
    tenant = tenant_for(caller, body.tenant_id)
    async with connect() as db:
        if not caller.is_admin:
            own = await modes.resolve(db, f"logto:{caller.sub}", tenant, caller.actor)
            own_ids = {a["id"] for a in own["accounts"]}
            if not set(body.tokens) <= own_ids:
                raise HTTPException(403, "identity:read may only enrich the caller's own accounts")
        return await modes.enrich(db, tenant, body.tokens, caller.actor)


# ── AUDIT / ERASE ────────────────────────────────────────────────────────────

@app.get("/v1/persons/{person_id}/audit", response_model=None)
async def audit(person_id: str, caller: CallerDep, tenant_id: str | None = None,
                format: Literal["json", "markdown"] = "json") -> dict | PlainTextResponse:
    _require_admin(caller)
    tenant = tenant_for(caller, tenant_id)
    async with connect() as db:
        report = await modes.audit(db, person_id, tenant, caller.actor)
    if report is None:
        raise HTTPException(404, "person_not_found")
    if format == "markdown":
        return PlainTextResponse(report["markdown"], media_type="text/markdown")
    return report


@app.delete("/v1/persons/{person_id}")
async def erase(person_id: str, caller: CallerDep, tenant_id: str | None = None) -> dict:
    _require_admin(caller)
    tenant = tenant_for(caller, tenant_id)
    async with connect() as db:
        result = await modes.erase(db, person_id, tenant, caller.actor)
    if result is None:
        raise HTTPException(404, "person_not_found")
    return result


@app.get("/v1/connectors/health")
async def connectors_health(caller: CallerDep) -> dict:
    _require_admin(caller)
    return await run_health_checks()
