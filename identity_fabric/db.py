"""Thin SurrealDB adapter over the official SDK (surrealdb>=1.0).

- Statement errors raise DatabaseError instead of silently returning [].
- Record IDs cross the API boundary as strings ("account:t1|google|123") and are
  converted to RecordID before being bound into queries.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from surrealdb import AsyncSurreal, RecordID

from .config import get_settings


class DatabaseError(RuntimeError):
    pass


class DB:
    def __init__(self, conn: AsyncSurreal):
        self._conn = conn

    async def query_all(self, sql: str, params: dict[str, Any] | None = None) -> list[Any]:
        """Run one or more statements; return each statement's result."""
        raw = await self._conn.query_raw(sql, params or {})
        if "error" in raw:
            raise DatabaseError(str(raw["error"]))
        results = []
        for stmt in raw.get("result", []):
            if stmt.get("status") != "OK":
                raise DatabaseError(str(stmt.get("result")))
            results.append(stmt.get("result"))
        return results

    async def query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict]:
        """Run a single statement and return its rows as a list."""
        results = await self.query_all(sql, params)
        last = results[-1] if results else None
        if last is None:
            return []
        return last if isinstance(last, list) else [last]


@asynccontextmanager
async def connect() -> AsyncIterator[DB]:
    s = get_settings()
    conn = AsyncSurreal(s.surreal_url)
    await conn.connect()
    try:
        await conn.signin({"username": s.surreal_user, "password": s.surreal_pass})
        await conn.use(s.surreal_ns, s.surreal_db)
        yield DB(conn)
    finally:
        await conn.close()


def rid(value: str | RecordID) -> RecordID:
    """'account:t1|google|1' -> RecordID('account', 't1|google|1')."""
    if isinstance(value, RecordID):
        return value
    table, sep, key = str(value).partition(":")
    if not sep or not table or not key:
        raise ValueError(f"Invalid record id: {value!r}")
    return RecordID(table, key.strip("⟨⟩`"))


def rid_str(value: Any) -> str:
    """RecordID -> 'table:key' without SurrealQL escaping brackets."""
    if isinstance(value, RecordID):
        return f"{value.table_name}:{value.id}"
    return str(value)


def plain(value: Any) -> Any:
    """Recursively convert RecordIDs to strings so rows are JSON-serializable."""
    if isinstance(value, RecordID):
        return rid_str(value)
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


def account_rid(tenant_id: str, provider: str, provider_sub: str) -> RecordID:
    return RecordID("account", f"{tenant_id}|{provider}|{provider_sub}")
