"""API tests: auth (agent secret + Logto JWT), scopes, tenant pinning, audit of 401s."""

from __future__ import annotations

import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from identity_fabric import auth
from identity_fabric.api import app
from identity_fabric.config import get_settings
from identity_fabric.connectors import register_connector
from tests.test_graph import GITHUB, GOOGLE, LOGTO, FakeConnector

ISSUER_BASE = "https://auth.example.test"
AUDIENCE = "https://identity.example.test"
KEY = ec.generate_private_key(ec.SECP384R1())
OP = {"x-agent-secret": "test-agent-secret"}


class _Key:
    key = KEY.public_key()


class _FakeJWKS:
    def get_signing_key_from_jwt(self, token):
        return _Key()


@pytest.fixture(autouse=True)
def logto(monkeypatch, db):
    monkeypatch.setenv("LOGTO_ENDPOINT", ISSUER_BASE)
    monkeypatch.setenv("LOGTO_AUDIENCE", AUDIENCE)
    get_settings.cache_clear()
    monkeypatch.setattr(auth, "_jwks_client", lambda endpoint: _FakeJWKS())
    register_connector("google", FakeConnector("google", {"tok-g": GOOGLE}))
    register_connector("github", FakeConnector("github", {"tok-gh": GITHUB}))
    register_connector("logto", FakeConnector("logto", {"tok-lt": LOGTO}))


def token(sub="lt-9", scope="identity:read", tenant="t1", **overrides) -> str:
    claims = {"sub": sub, "scope": scope, "tenant_id": tenant, "iss": f"{ISSUER_BASE}/oidc",
              "aud": AUDIENCE, "exp": int(time.time()) + 300, **overrides}
    return jwt.encode(claims, KEY, algorithm="ES384")


def bearer(**kw) -> dict:
    return {"authorization": f"Bearer {token(**kw)}"}


@pytest.fixture
async def client():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _seed(client):
    for provider, tok in (("google", "tok-g"), ("github", "tok-gh"), ("logto", "tok-lt")):
        r = await client.post("/v1/accounts", headers=OP, json={
            "provider": provider, "token": tok, "tenant_id": "t1", "consent": True})
        assert r.status_code == 201, r.text
    return r.json()["person_id"]


async def test_health(client):
    assert (await client.get("/healthz")).json()["status"] == "ok"
    assert (await client.get("/readyz")).json() == {"status": "ready"}


async def test_rejects_and_audits_unauthenticated(client, db):
    assert (await client.post("/v1/resolve", json={"identifier": "x"})).status_code == 401
    assert (await client.post("/v1/resolve", json={"identifier": "x"},
                              headers={"x-agent-secret": "wrong"})).status_code == 401
    bad = token(aud="https://someone-else")
    assert (await client.post("/v1/resolve", json={"identifier": "x"},
                              headers={"authorization": f"Bearer {bad}"})).status_code == 401
    expired = token(exp=int(time.time()) - 10)
    assert (await client.post("/v1/resolve", json={"identifier": "x"},
                              headers={"authorization": f"Bearer {expired}"})).status_code == 401
    assert len(await db.query("SELECT * FROM audit_log WHERE action = 'AUTH_FAILED'")) == 4


async def test_operator_requires_tenant_and_consent(client):
    r = await client.post("/v1/resolve", headers=OP, json={"identifier": "ada@example.com"})
    assert r.status_code == 400
    r = await client.post("/v1/accounts", headers=OP, json={
        "provider": "google", "token": "tok-g", "tenant_id": "t1", "consent": False})
    assert r.status_code == 400


async def test_read_scope_limited_to_own_identity(client):
    await _seed(client)
    # lt-9 owns the graph that contains ada@example.com
    r = await client.post("/v1/resolve", headers=bearer(), json={"identifier": "ada@example.com"})
    assert r.status_code == 200 and len(r.json()["accounts"]) == 3
    # a different user may not resolve it
    r = await client.post("/v1/resolve", headers=bearer(sub="someone-else"),
                          json={"identifier": "ada@example.com"})
    assert r.status_code == 403
    # nor reach into another tenant
    r = await client.post("/v1/resolve", headers=bearer(),
                          json={"identifier": "ada@example.com", "tenant_id": "t2"})
    assert r.status_code == 403
    # nor use admin endpoints
    assert (await client.post("/v1/accounts", headers=bearer(), json={
        "provider": "google", "token": "tok-g", "consent": True})).status_code == 403


async def test_read_scope_enrich_own_accounts_only(client):
    await _seed(client)
    own = {"account:t1|google|g-1": "tok-g"}
    r = await client.post("/v1/enrich", headers=bearer(), json={"tokens": own, "consent": True})
    assert r.status_code == 200 and r.json()["enriched_count"] == 1
    r = await client.post("/v1/enrich", headers=bearer(sub="someone-else"),
                          json={"tokens": own, "consent": True})
    assert r.status_code == 403


async def test_admin_audit_and_erase(client):
    person_id = await _seed(client)
    admin = bearer(sub="admin-1", scope="identity:admin")
    r = await client.get(f"/v1/persons/{person_id}/audit", headers=admin)
    assert r.status_code == 200 and len(r.json()["accounts"]) == 3
    r = await client.get(f"/v1/persons/{person_id}/audit?format=markdown", headers=admin)
    assert r.headers["content-type"].startswith("text/markdown")
    assert (await client.delete(f"/v1/persons/{person_id}", headers=admin)).json()["accounts_erased"] == 3
    assert (await client.get(f"/v1/persons/{person_id}/audit", headers=admin)).status_code == 404


async def test_provider_token_expired_maps_to_422(client):
    r = await client.post("/v1/accounts", headers=OP, json={
        "provider": "google", "token": "expired", "tenant_id": "t1", "consent": True})
    assert r.status_code == 422 and r.json()["provider"] == "google"


class _Unreachable(FakeConnector):
    async def resolve(self, identifier, token=None):
        raise httpx.ConnectError("boom")


async def test_provider_network_failure_maps_to_502(client):
    register_connector("okta", _Unreachable("okta", {}))
    r = await client.post("/v1/accounts", headers=OP, json={
        "provider": "okta", "token": "t", "tenant_id": "t1", "consent": True})
    assert r.status_code == 502 and r.json() == {"detail": "provider_unreachable"}
