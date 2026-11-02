"""Events Trust owns (`que.trust.*`, Technical Docs 2 "Event owners"): recorded in the outbox in the same
transaction as the change, then delivered signed (03 §D.2: Que-Signature: t=<unix>, kid=<key>,
v1=<hmac-sha256 of "<t>." + body>). Approval events go to Nexus; resource-policy events to Connect; a feature
flag's event to the product whose feature it is (DEC-198)."""

import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncConnection

from quetrust import db
from quetrust.config import get_settings
from quetrust.useragent import HEADERS

log = logging.getLogger("quetrust.events")

STAGE_OPENED = "que.trust.approval.stage_opened.v2"
APPROVAL_DECIDED = "que.trust.approval.decided.v2"
RESOURCE_POLICY_CHANGED = "que.trust.resource_policy.changed.v2"
FEATURE_FLAG_CHANGED = "que.trust.feature_flag.changed.v2"
PRODUCT_TARGETS = {"que-connect": "connect", "que-amphi": "amphi"}


def target_of(event_type: str, data: dict[str, Any]) -> str:
    if event_type == RESOURCE_POLICY_CHANGED:
        return "connect"
    if event_type == FEATURE_FLAG_CHANGED:
        return PRODUCT_TARGETS[str(data["product"])]
    return "nexus"


async def emit(conn: AsyncConnection, tenant: uuid.UUID, event_id: str, event_type: str, data: dict[str, Any]) -> None:
    """Queue one event; the id is stable (the same change never becomes two events)."""
    target = target_of(event_type, data)
    await db.run(
        conn,
        """
        INSERT INTO outbox_event (tenant_id, id, type, target, data)
        VALUES (:t, :i, :ty, :tg, CAST(:d AS jsonb)) ON CONFLICT DO NOTHING""",
        t=tenant,
        i=event_id,
        ty=event_type,
        tg=target,
        d=json.dumps(data, default=str),
    )


def sign(body: bytes, kid: str, secret: str) -> str:
    ts = int(time.time())
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts}, kid={kid}, v1={mac}"


async def deliver_pending(limit: int = 50, transport: Any = None) -> int:
    """Deliver due events once; failures stay pending (retried with the same event id)."""
    s = get_settings()
    if not s.deliver_events:
        return 0
    urls = {"nexus": s.event_subscribers, "connect": s.connect_inbound, "amphi": s.amphi_inbound}
    delivered = 0
    async with db.worker_tx() as conn:
        rows = await db.all_(
            conn,
            """
            SELECT tenant_id, id, type, target, data, created_at FROM trust.outbox_event
            WHERE delivered_at IS NULL AND attempts < 20 ORDER BY created_at LIMIT :l FOR UPDATE SKIP LOCKED""",
            l=limit,
        )
        async with httpx.AsyncClient(timeout=10, transport=transport, headers=HEADERS) as client:
            for ev in rows:
                body = json.dumps(
                    {
                        "specversion": "1.0",
                        "id": str(ev["id"]),
                        "source": "que-trust",
                        "type": ev["type"],
                        "time": ev["created_at"].isoformat(),
                        "quetenant": str(ev["tenant_id"]),
                        "data": ev["data"],
                    }
                ).encode()
                headers = {
                    "Content-Type": "application/cloudevents+json",
                    "Que-Signature": sign(body, s.event_signing_kid, s.event_signing_secret),
                }
                error = None
                for url in urls[str(ev["target"])]:
                    try:
                        r = await client.post(url, content=body, headers=headers)
                        if r.status_code not in (200, 202):
                            error = f"{url}: {r.status_code} {r.text[:200]}"
                    except httpx.HTTPError as exc:
                        error = f"{url}: {type(exc).__name__}"
                done = error is None
                if not done:
                    log.warning("event %s not delivered: %s", ev["id"], error)
                else:
                    delivered += 1
                await db.run(
                    conn,
                    "UPDATE trust.outbox_event SET attempts = attempts + 1, last_error = :e,"
                    " delivered_at = CASE WHEN :ok THEN now() ELSE NULL END WHERE tenant_id = :t AND id = :i",
                    e=error,
                    ok=done,
                    t=ev["tenant_id"],
                    i=ev["id"],
                )
    return delivered
