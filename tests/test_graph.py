"""Integration tests: RESOLVE / INGEST / ENRICH / AUDIT / ERASE against real SurrealDB."""

from __future__ import annotations

from typing import Optional

import pytest

from identity_fabric import modes
from identity_fabric.connectors import register_connector
from identity_fabric.connectors.base import BaseConnector, IdentityNode, TokenExpiredError


class FakeConnector(BaseConnector):
    """Returns canned nodes keyed by token; 'expired' raises TokenExpiredError."""

    def __init__(self, provider: str, nodes: dict[str, IdentityNode]):
        self.provider_name = provider
        self.nodes = nodes

    async def resolve(self, identifier: str, token: Optional[str] = None) -> Optional[IdentityNode]:
        if token == "expired":
            raise TokenExpiredError(self.provider_name, "expired")
        return self.nodes.get(token or identifier)

    async def health_check(self) -> bool:
        return True


GOOGLE = IdentityNode(provider="google", provider_sub="g-1", email="Ada@Example.com",
                      email_verified=True, display_name="Ada Lovelace", raw_profile={"sub": "g-1"})
GITHUB = IdentityNode(provider="github", provider_sub="gh-7", email="ada@example.com",
                      email_verified=False, username="ada", org="Analytical Engines")
LOGTO = IdentityNode(provider="logto", provider_sub="lt-9", phone="+44 20 7946 0000",
                     linked_account_stubs=[{"provider": "github", "provider_sub": "gh-7"}])


@pytest.fixture(autouse=True)
def fakes():
    register_connector("google", FakeConnector("google", {"tok-g": GOOGLE}))
    register_connector("github", FakeConnector("github", {"tok-gh": GITHUB}))
    register_connector("logto", FakeConnector("logto", {"tok-lt": LOGTO}))


async def _seed(db, tenant="t1"):
    a = await modes.ingest(db, tenant, "google", "test", token="tok-g")
    b = await modes.ingest(db, tenant, "github", "test", token="tok-gh")
    c = await modes.ingest(db, tenant, "logto", "test", token="tok-lt")
    return a, b, c


async def test_ingest_links_accounts_into_one_person(db):
    a, b, c = await _seed(db)
    assert a["status"] == "ingested"
    assert a["person_id"] == b["person_id"] == c["person_id"]
    # GitHub email unverified -> MEDIUM; Logto stub -> HIGH logto_session
    assert [(e["confidence"], e["signal"]) for e in b["new_edges"]] == [("MEDIUM", "unverified_email_match")]
    assert [(e["confidence"], e["signal"]) for e in c["new_edges"]] == [("HIGH", "logto_session")]


async def test_pii_encrypted_at_rest(db):
    await _seed(db)
    rows = await db.query("SELECT * FROM account WHERE provider = 'google'")
    assert rows[0]["email"] != "ada@example.com"
    assert rows[0]["display_name"] != "Ada Lovelace"
    person = (await db.query("SELECT * FROM person"))[0]
    assert person["canonical_email"] != "ada@example.com"


@pytest.mark.parametrize("identifier", ["ADA@example.com", "google:g-1", "ada", "+44 (20) 7946-0000"])
async def test_resolve_by_any_identifier(db, identifier):
    await _seed(db)
    r = await modes.resolve(db, identifier, "t1", "test")
    assert r["resolution_status"] == "found"
    assert {a["provider"] for a in r["accounts"]} == {"google", "github", "logto"}
    assert r["person"]["canonical_email"] == "ada@example.com"
    google = next(a for a in r["accounts"] if a["provider"] == "google")
    assert google["email"] == "ada@example.com"  # decrypted on the way out
    assert "hashed_email" not in google and "raw_profile_enc" not in google
    kinds = sorted(e["type"] for e in r["edges"])
    assert kinds == ["linked_via", "linked_via", "owns", "owns", "owns"]
    assert {f["code"] for f in r["audit_flags"]} == {"UNVERIFIED_EMAIL"}


async def test_tenants_are_isolated(db):
    await _seed(db, "t1")
    other = await modes.ingest(db, "t2", "google", "test", token="tok-g")
    t1 = await modes.resolve(db, "ada@example.com", "t1", "test")
    t2 = await modes.resolve(db, "ada@example.com", "t2", "test")
    assert len(t1["accounts"]) == 3
    assert [a["id"] for a in t2["accounts"]] == [other["account_id"]]
    assert other["account_id"] == "account:t2|google|g-1"
    assert (await modes.resolve(db, "nobody@example.com", "t1", "test"))["resolution_status"] == "not_found"


async def test_reingest_is_idempotent(db):
    await _seed(db)
    await _seed(db)
    assert len(await db.query("SELECT * FROM linked_via")) == 2
    assert len(await db.query("SELECT * FROM owns")) == 3
    assert len(await db.query("SELECT * FROM person")) == 1


async def test_enrich_refreshes_and_marks_stale(db):
    a, b, _ = await _seed(db)
    r = await modes.enrich(db, "t1", {a["account_id"]: "tok-g", b["account_id"]: "expired",
                                      "account:t1|x|missing": "tok"}, "test")
    status = {d["account_id"]: d["status"] for d in r["details"]}
    assert status == {a["account_id"]: "enriched", b["account_id"]: "token_expired",
                      "account:t1|x|missing": "not_found"}
    stale = await db.query("SELECT VALUE stale FROM account WHERE provider = 'github'")
    assert stale == [True]
    events = await db.query("SELECT VALUE action FROM audit_log WHERE action = 'ACCOUNT_STALE'")
    assert events == ["ACCOUNT_STALE"]


async def test_audit_report(db):
    a, _, _ = await _seed(db)
    r = await modes.audit(db, a["person_id"], "t1", "test")
    assert len(r["accounts"]) == 3
    assert len(r["edges"]["owns"]) == 3 and len(r["edges"]["linked_via"]) == 2
    assert r["mermaid"].startswith("graph LR")
    assert "# Identity Audit Report" in r["markdown"] and "Ada Lovelace" in r["markdown"]
    assert await modes.audit(db, a["person_id"], "t2", "test") is None  # other tenant


async def test_erase_cascades(db):
    a, _, _ = await _seed(db)
    other = await modes.ingest(db, "t2", "google", "test", token="tok-g")
    r = await modes.erase(db, a["person_id"], "t1", "test")
    assert r == {"status": "erased", "person_id": a["person_id"], "accounts_erased": 3}
    assert await db.query("SELECT VALUE id FROM account WHERE tenant_id = 't1'") == []
    assert await db.query("SELECT * FROM linked_via") == []
    assert len(await db.query("SELECT * FROM owns")) == 1  # t2's edge only
    remaining = await db.query("SELECT VALUE tenant_id FROM person")
    assert remaining == ["t2"]  # other tenant untouched
    assert (await modes.resolve(db, "ada@example.com", "t2", "test"))["accounts"][0]["id"] == other["account_id"]
    assert await db.query("SELECT VALUE action FROM audit_log WHERE action = 'ERASE'") == ["ERASE"]
