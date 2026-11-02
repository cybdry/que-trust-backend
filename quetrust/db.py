"""Tenant-bound transactions: every statement runs with app.tenant_id set, so row security applies."""

import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from quetrust.config import get_settings

_engines: dict[str, AsyncEngine] = {}


def engine(role: str = "app") -> AsyncEngine:
    if role not in _engines:
        s = get_settings()
        _engines[role] = create_async_engine(
            s.database_url if role == "app" else s.worker_database_url,
            pool_pre_ping=True,
            connect_args={"server_settings": {"search_path": "trust,public"}},
        )
    return _engines[role]


async def dispose() -> None:
    for e in list(_engines.values()):
        await e.dispose()
    _engines.clear()


@asynccontextmanager
async def tenant_tx(tenant_id: uuid.UUID) -> AsyncIterator[AsyncConnection]:
    """A transaction bound to the verified caller's tenant: row security applies to every statement."""
    async with engine("app").begin() as conn:
        await conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})
        yield conn


@asynccontextmanager
async def worker_tx() -> AsyncIterator[AsyncConnection]:
    """The worker's cross-tenant transaction (outbox delivery, approval expiry only)."""
    async with engine("worker").begin() as conn:
        yield conn


async def one(conn: AsyncConnection, sql: str, **params: Any) -> dict[str, Any] | None:
    row = (await conn.execute(text(sql), params)).mappings().first()
    return dict(row) if row else None


async def all_(conn: AsyncConnection, sql: str, **params: Any) -> list[dict[str, Any]]:
    return [dict(r) for r in (await conn.execute(text(sql), params)).mappings().all()]


async def val(conn: AsyncConnection, sql: str, **params: Any) -> Any:
    return (await conn.execute(text(sql), params)).scalar()


async def run(conn: AsyncConnection, sql: str, **params: Any) -> None:
    await conn.execute(text(sql), params)


def as_params(m: Mapping[str, Any]) -> dict[str, Any]:
    return dict(m)
