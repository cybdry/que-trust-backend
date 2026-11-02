"""Idempotency-Key handling: the same key and request replay the first answer; another request with
the key is 409 idempotency_conflict (Technical Docs 2)."""

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncConnection

from quetrust import db
from quetrust.errors import Problem


def digest(body: Any) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


async def replay(
    conn: AsyncConnection, tenant: uuid.UUID, scope: str, key: str | None, body: Any
) -> tuple[int, dict[str, Any]] | None:
    if not key:
        return None
    row = await db.one(
        conn,
        "SELECT request_digest, status, response FROM idempotency_record WHERE tenant_id = :t AND scope = :s AND key = :k",
        t=tenant,
        s=scope,
        k=key,
    )
    if row is None:
        return None
    if row["request_digest"] != digest(body):
        raise Problem(409, "idempotency_conflict", "This Idempotency-Key was used for another request.")
    return int(row["status"]), dict(row["response"])


async def remember(
    conn: AsyncConnection, tenant: uuid.UUID, scope: str, key: str | None, body: Any, status: int, response: Any
) -> None:
    if not key:
        return
    await db.run(
        conn,
        """
        INSERT INTO idempotency_record (tenant_id, scope, key, request_digest, status, response)
        VALUES (:t, :s, :k, :d, :st, CAST(:r AS jsonb)) ON CONFLICT DO NOTHING""",
        t=tenant,
        s=scope,
        k=key,
        d=digest(body),
        st=status,
        r=json.dumps(response, default=str),
    )
