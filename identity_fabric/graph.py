"""Shared graph reads/writes used by RESOLVE, ENRICH, AUDIT and ERASE."""

from __future__ import annotations

import json
from typing import Any

from .config import get_settings
from .connectors.base import IdentityNode
from .crypto import ACCOUNT_PII_FIELDS, PERSON_PII_FIELDS, encrypt, hmac_hash, seal, unseal
from .db import DB, account_rid, plain, rid, rid_str
from .normalize import normalize_email, normalize_phone

HIDDEN_ACCOUNT_FIELDS = ("raw_profile_enc", "hashed_email", "hashed_phone")


# ── serialization ────────────────────────────────────────────────────────────

def public_account(row: dict) -> dict:
    """Decrypt PII and drop internal fields for API output."""
    out = {k: v for k, v in row.items() if k not in HIDDEN_ACCOUNT_FIELDS}
    return plain(unseal(out, ACCOUNT_PII_FIELDS))


def public_person(row: dict) -> dict:
    return plain(unseal(row, PERSON_PII_FIELDS))


def public_edge(edge: dict, kind: str) -> dict:
    out: dict[str, Any] = {"type": kind, "from": rid_str(edge["in"]), "to": rid_str(edge["out"])}
    for k in ("confidence", "signal", "asserted_at", "asserted_by", "source"):
        if k in edge:
            out[k] = plain(edge[k])
    return out


# ── reads ────────────────────────────────────────────────────────────────────

async def traverse_linked_via(
    db: DB, seed_ids: list[str], tenant_id: str
) -> tuple[list[dict], list[dict]]:
    """BFS over linked_via (both directions) up to MAX_EDGE_DEPTH hops."""
    visited = set(seed_ids)
    frontier = list(seed_ids)
    edges: dict[str, dict] = {}

    for _ in range(get_settings().max_edge_depth):
        if not frontier:
            break
        rows = await db.query(
            "SELECT * FROM linked_via WHERE in IN $ids OR out IN $ids",
            {"ids": [rid(i) for i in frontier]},
        )
        nxt: list[str] = []
        for e in rows:
            edges[rid_str(e["id"])] = e
            for peer in (rid_str(e["in"]), rid_str(e["out"])):
                if peer not in visited:
                    visited.add(peer)
                    nxt.append(peer)
        frontier = nxt

    accounts = await db.query(
        "SELECT * FROM account WHERE id IN $ids AND tenant_id = $t",
        {"ids": [rid(i) for i in visited], "t": tenant_id},
    )
    return accounts, list(edges.values())


async def persons_owning(db: DB, account_ids: list[str], tenant_id: str) -> list[dict]:
    if not account_ids:
        return []
    return await db.query(
        "SELECT * FROM person WHERE tenant_id = $t "
        "AND id IN (SELECT VALUE in FROM owns WHERE out IN $ids)",
        {"ids": [rid(i) for i in account_ids], "t": tenant_id},
    )


async def owns_edges(db: DB, person_id: str) -> list[dict]:
    return await db.query("SELECT * FROM owns WHERE in = $p", {"p": rid(person_id)})


async def write_audit(
    db: DB, tenant_id: str, action: str, actor: str,
    target_id: str | None = None, detail: str | None = None,
) -> None:
    await db.query(
        "CREATE audit_log SET tenant_id = $t, action = $a, actor = $actor, "
        "target_id = $tid, detail = $d",
        {"t": tenant_id, "a": action, "actor": actor, "tid": target_id, "d": detail},
    )


# ── writes ───────────────────────────────────────────────────────────────────

async def upsert_account(db: DB, tenant_id: str, node: IdentityNode) -> str:
    """Upsert an IdentityNode as a tenant-scoped account record. Returns its id."""
    record = account_rid(tenant_id, node.provider, node.provider_sub)
    email = normalize_email(node.email) if node.email else None
    phone = normalize_phone(node.phone) if node.phone else None

    fields = seal(
        {
            "email": email,
            "phone": phone,
            "display_name": node.display_name,
            "bio": node.bio,
            "org": node.org,
            "location": node.location,
        },
        ACCOUNT_PII_FIELDS,
    )
    await db.query(
        """
        UPSERT $id SET
          tenant_id         = $tenant,
          provider          = $provider,
          provider_sub      = $sub,
          email             = $email,
          email_verified    = $ev,
          phone             = $phone,
          username          = $username,
          display_name      = $display_name,
          profile_photo_url = $photo,
          bio               = $bio,
          org               = $org,
          location          = $location,
          hashed_email      = $he,
          hashed_phone      = $hp,
          raw_profile_enc   = $enc,
          stale             = false,
          ttl_refresh_at    = time::now() + type::duration($ttl),
          last_seen         = time::now()
        """,
        {
            "id": record,
            "tenant": tenant_id,
            "provider": node.provider,
            "sub": node.provider_sub,
            "ev": bool(node.email_verified),
            "username": node.username,
            "photo": node.profile_photo_url,
            "he": hmac_hash(email, tenant_id) if email else None,
            "hp": hmac_hash(phone, tenant_id) if phone else None,
            "enc": encrypt(json.dumps(node.raw_profile or {}, default=str)),
            "ttl": f"{get_settings().ttl_hours}h",
            **fields,
        },
    )
    return rid_str(record)


async def relate_link(db: DB, a: str, b: str, confidence: str, signal: str, by: str = "system") -> None:
    """Create a linked_via edge unless one already exists in either direction."""
    await db.query(
        """
        IF array::len((SELECT id FROM linked_via
                       WHERE (in = $a AND out = $b) OR (in = $b AND out = $a))) = 0 {
          RELATE $a->linked_via->$b SET confidence = $c, signal = $s, asserted_by = $by;
        };
        """,
        {"a": rid(a), "b": rid(b), "c": confidence, "s": signal, "by": by},
    )


async def discover_links(db: DB, tenant_id: str, account_id: str, node: IdentityNode) -> list[dict]:
    """Link this account to peers sharing email/phone hash or provider stubs."""
    new_edges: list[dict] = []
    me = rid(account_id)

    async def _link(peers: list[dict], confidence: str, signal: str) -> None:
        for peer in peers:
            pid = rid_str(peer["id"])
            await relate_link(db, account_id, pid, confidence, signal)
            new_edges.append({"type": "linked_via", "from": account_id, "to": pid,
                              "confidence": confidence, "signal": signal})

    if node.email and not node.is_private_relay_email():
        h = hmac_hash(normalize_email(node.email), tenant_id)
        peers = await db.query(
            "SELECT id FROM account WHERE hashed_email = $h AND id != $me AND tenant_id = $t",
            {"h": h, "me": me, "t": tenant_id},
        )
        if node.email_verified:
            await _link(peers, "HIGH", "verified_email_match")
        else:
            await _link(peers, "MEDIUM", "unverified_email_match")

    if node.phone:
        h = hmac_hash(normalize_phone(node.phone), tenant_id)
        peers = await db.query(
            "SELECT id FROM account WHERE hashed_phone = $h AND id != $me AND tenant_id = $t",
            {"h": h, "me": me, "t": tenant_id},
        )
        await _link(peers, "HIGH", "phone_match")

    for stub in node.linked_account_stubs or []:
        p, s = stub.get("provider"), stub.get("provider_sub")
        if not p or not s:
            continue
        peers = await db.query(
            "SELECT id FROM account WHERE provider = $p AND provider_sub = $s AND tenant_id = $t",
            {"p": p, "s": s, "t": tenant_id},
        )
        await _link(peers, "HIGH", "logto_session")

    return new_edges


async def ensure_owner(db: DB, tenant_id: str, account_id: str, node: IdentityNode) -> str:
    """Attach the account to the person owning any linked peer, or a new person."""
    existing = await persons_owning(db, [account_id], tenant_id)
    if existing:
        return rid_str(existing[0]["id"])

    _, edges = await traverse_linked_via(db, [account_id], tenant_id)
    peer_ids = {rid_str(e["in"]) for e in edges} | {rid_str(e["out"]) for e in edges}
    peer_ids.discard(account_id)
    owners = await persons_owning(db, sorted(peer_ids), tenant_id)

    if owners:
        person_id = rid_str(owners[0]["id"])
    else:
        email = normalize_email(node.email) if node.email and not node.is_private_relay_email() else None
        phone = normalize_phone(node.phone) if node.phone else None
        created = await db.query(
            "CREATE person SET tenant_id = $t, canonical_email = $ce, "
            "canonical_phone = $cp, display_name = $dn",
            {"t": tenant_id, **seal({"ce": email, "cp": phone, "dn": node.display_name},
                                    ("ce", "cp", "dn"))},
        )
        person_id = rid_str(created[0]["id"])

    await db.query(
        "RELATE $p->owns->$a SET source = 'system'",
        {"p": rid(person_id), "a": rid(account_id)},
    )
    return person_id


def is_owned_by(accounts: list[dict], provider: str, provider_sub: str) -> bool:
    return any(a.get("provider") == provider and a.get("provider_sub") == provider_sub for a in accounts)

