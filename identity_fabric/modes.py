"""RESOLVE, INGEST/ENRICH, AUDIT and ERASE operations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .connectors import get_connector
from .connectors.base import ConnectorError, IdentityNode, RateLimitedError, TokenExpiredError
from .db import DB, rid, rid_str
from .graph import (
    discover_links, ensure_owner, owns_edges, persons_owning, public_account, public_edge,
    public_person, traverse_linked_via, upsert_account, write_audit,
)
from .crypto import hmac_hash
from .normalize import IdentifierType, normalize
from .report import build_markdown_report, build_mermaid


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_stale(account: dict) -> bool:
    ttl = account.get("ttl_refresh_at")
    return bool(account.get("stale")) or not isinstance(ttl, datetime) or ttl < datetime.now(timezone.utc)


def _flags(accounts: list[dict], link_edges: list[dict], owned: set[str] | None = None) -> list[dict]:
    flags: list[dict] = []
    for a in accounts:
        aid = rid_str(a["id"])
        if a.get("stale"):
            flags.append({"code": "STALE_ACCOUNT", "account_id": aid, "provider": a.get("provider")})
        if a.get("email") and not a.get("email_verified"):
            flags.append({"code": "UNVERIFIED_EMAIL", "account_id": aid, "provider": a.get("provider")})
        if owned is not None and aid not in owned:
            flags.append({"code": "ORPHANED_ACCOUNT", "account_id": aid})
    for e in link_edges:
        if e.get("confidence") == "LOW":
            flags.append({"code": "LOW_CONFIDENCE_LINK", "from": rid_str(e["in"]),
                          "to": rid_str(e["out"]), "signal": e.get("signal")})
    return flags


async def _seed_accounts(db: DB, identifier: str, tenant_id: str) -> list[dict]:
    ident = normalize(identifier)
    t = tenant_id
    if ident.kind == IdentifierType.EMAIL:
        return await db.query("SELECT * FROM account WHERE hashed_email = $h AND tenant_id = $t",
                              {"h": hmac_hash(ident.value, t), "t": t})
    if ident.kind == IdentifierType.PHONE:
        return await db.query("SELECT * FROM account WHERE hashed_phone = $h AND tenant_id = $t",
                              {"h": hmac_hash(ident.value, t), "t": t})
    if ident.kind == IdentifierType.PROVIDER_SUB:
        provider, _, sub = ident.value.partition(":")
        return await db.query(
            "SELECT * FROM account WHERE provider = $p AND provider_sub = $s AND tenant_id = $t",
            {"p": provider, "s": sub, "t": t})
    if ident.kind == IdentifierType.USERNAME:
        return await db.query(
            "SELECT * FROM account WHERE string::lowercase(username ?? '') = $u AND tenant_id = $t",
            {"u": ident.value, "t": t})
    if ident.kind == IdentifierType.EMPLOYEE_ID:
        return await db.query("SELECT * FROM account WHERE provider_sub = $s AND tenant_id = $t",
                              {"s": ident.value, "t": t})
    return []


# ── RESOLVE ──────────────────────────────────────────────────────────────────

async def resolve(db: DB, identifier: str, tenant_id: str, caller: str) -> dict[str, Any]:
    seeds = await _seed_accounts(db, identifier, tenant_id)
    if not seeds:
        await write_audit(db, tenant_id, "RESOLVE", caller, detail="not_found")
        return {"resolution_status": "not_found", "person": None, "accounts": [], "edges": [],
                "audit_flags": [], "stale_account_ids": [], "resolved_at": _now()}

    accounts, links = await traverse_linked_via(db, [rid_str(a["id"]) for a in seeds], tenant_id)
    account_ids = [rid_str(a["id"]) for a in accounts]
    persons = await persons_owning(db, account_ids, tenant_id)
    person = persons[0] if persons else None
    owns = await owns_edges(db, rid_str(person["id"])) if person else []

    flags = _flags(accounts, links)
    if len(persons) > 1:
        flags.append({"code": "MULTIPLE_PERSONS", "person_ids": [rid_str(p["id"]) for p in persons]})

    await write_audit(db, tenant_id, "RESOLVE", caller,
                      target_id=rid_str(person["id"]) if person else None,
                      detail=f"{len(accounts)} accounts")
    return {
        "resolution_status": "found",
        "person": public_person(person) if person else None,
        "accounts": [public_account(a) for a in accounts],
        "edges": [public_edge(e, "owns") for e in owns] + [public_edge(e, "linked_via") for e in links],
        "audit_flags": flags,
        "stale_account_ids": [rid_str(a["id"]) for a in accounts if _is_stale(a)],
        "resolved_at": _now(),
    }


# ── INGEST (new account from a provider) ─────────────────────────────────────

async def _store(db: DB, tenant_id: str, node: IdentityNode) -> tuple[str, str, list[dict]]:
    account_id = await upsert_account(db, tenant_id, node)
    edges = await discover_links(db, tenant_id, account_id, node)
    person_id = await ensure_owner(db, tenant_id, account_id, node)
    return account_id, person_id, edges


async def ingest(db: DB, tenant_id: str, provider: str, caller: str,
                 token: str | None = None, identifier: str = "") -> dict[str, Any]:
    """Fetch an identity from a provider and merge it into the graph."""
    node = await get_connector(provider).resolve(identifier, token=token)
    if node is None:
        return {"status": "not_found_at_provider", "provider": provider}
    account_id, person_id, edges = await _store(db, tenant_id, node)
    await write_audit(db, tenant_id, "LINK", caller, target_id=account_id,
                      detail=f"provider={provider}, new_edges={len(edges)}")
    return {"status": "ingested", "account_id": account_id, "person_id": person_id, "new_edges": edges}


# ── ENRICH (refresh existing accounts) ───────────────────────────────────────

async def enrich(db: DB, tenant_id: str, tokens: dict[str, str], caller: str) -> dict[str, Any]:
    """tokens: {account_id: provider access token}. Accounts without a token are marked stale."""
    rows = await db.query("SELECT * FROM account WHERE id IN $ids AND tenant_id = $t",
                          {"ids": [rid(i) for i in tokens], "t": tenant_id})
    found = {rid_str(r["id"]): r for r in rows}
    details: list[dict] = []
    new_edges: list[dict] = []

    async def _mark_stale(aid: str) -> None:
        await db.query("UPDATE $id SET stale = true", {"id": rid(aid)})

    for aid, token in tokens.items():
        row = found.get(aid)
        if row is None:
            details.append({"account_id": aid, "status": "not_found"})
            continue
        if not token:
            await _mark_stale(aid)
            details.append({"account_id": aid, "status": "skipped_no_token"})
            continue
        try:
            node = await get_connector(row["provider"]).resolve(row["provider_sub"], token=token)
        except TokenExpiredError:
            await _mark_stale(aid)
            details.append({"account_id": aid, "status": "token_expired"})
            continue
        except RateLimitedError as e:
            await _mark_stale(aid)
            details.append({"account_id": aid, "status": "rate_limited", "retry_after": e.retry_after})
            continue
        except ConnectorError as e:
            await _mark_stale(aid)
            details.append({"account_id": aid, "status": "fetch_error", "error": str(e)})
            continue
        if node is None:
            details.append({"account_id": aid, "status": "not_found_at_provider"})
            continue
        _, _, edges = await _store(db, tenant_id, node)
        new_edges.extend(edges)
        details.append({"account_id": aid, "status": "enriched", "new_edges": len(edges)})

    enriched = sum(1 for d in details if d["status"] == "enriched")
    await write_audit(db, tenant_id, "ENRICH", caller,
                      detail=f"enriched={enriched}/{len(details)}, new_edges={len(new_edges)}")
    return {"enriched_count": enriched, "skipped_count": len(details) - enriched,
            "new_edges": new_edges, "details": details}


# ── AUDIT ────────────────────────────────────────────────────────────────────

async def audit(db: DB, person_id: str, tenant_id: str, caller: str) -> dict[str, Any] | None:
    rows = await db.query("SELECT * FROM person WHERE id = $id AND tenant_id = $t",
                          {"id": rid(person_id), "t": tenant_id})
    if not rows:
        return None
    person = rows[0]
    owns = await owns_edges(db, person_id)
    owned = [rid_str(e["out"]) for e in owns]
    accounts, links = await traverse_linked_via(db, owned, tenant_id)
    ids = [rid(rid_str(a["id"])) for a in accounts]
    auth = await db.query("SELECT * FROM authenticated_by WHERE in IN $ids", {"ids": ids})
    sessions = await db.query("SELECT * FROM accessed_from WHERE in IN $ids", {"ids": ids})

    flags = _flags(accounts, links, owned=set(owned))
    pub_person = public_person(person)
    pub_accounts = [public_account(a) for a in accounts]
    edges = {
        "owns": [public_edge(e, "owns") for e in owns],
        "linked_via": [public_edge(e, "linked_via") for e in links],
        "authenticated_by": [public_edge(e, "authenticated_by") for e in auth],
        "accessed_from": [public_edge(e, "accessed_from") for e in sessions],
    }
    await write_audit(db, tenant_id, "AUDIT", caller, target_id=person_id,
                      detail=f"{len(accounts)} accounts, {len(flags)} flags")
    return {
        "person": pub_person,
        "accounts": pub_accounts,
        "edges": edges,
        "anomaly_flags": flags,
        "mermaid": build_mermaid(pub_person, pub_accounts, edges),
        "markdown": build_markdown_report(pub_person, pub_accounts, edges, flags, tenant_id),
        "audited_at": _now(),
    }


# ── ERASE (right to erasure, DPDP/GDPR) ──────────────────────────────────────

async def erase(db: DB, person_id: str, tenant_id: str, caller: str) -> dict[str, Any] | None:
    rows = await db.query("SELECT id FROM person WHERE id = $id AND tenant_id = $t",
                          {"id": rid(person_id), "t": tenant_id})
    if not rows:
        return None
    pid = rid(person_id)
    accounts = await db.query("SELECT VALUE out FROM owns WHERE in = $p", {"p": pid})
    await db.query_all(
        """
        BEGIN TRANSACTION;
        DELETE linked_via WHERE in IN $accs OR out IN $accs;
        DELETE authenticated_by WHERE in IN $accs;
        DELETE accessed_from WHERE in IN $accs;
        DELETE owns WHERE in = $p;
        DELETE account WHERE id IN $accs AND tenant_id = $t;
        DELETE $p;
        COMMIT TRANSACTION;
        """,
        {"accs": accounts, "p": pid, "t": tenant_id},
    )
    await write_audit(db, tenant_id, "ERASE", caller, target_id=person_id,
                      detail=f"Erased {len(accounts)} account nodes")
    return {"status": "erased", "person_id": person_id, "accounts_erased": len(accounts)}
