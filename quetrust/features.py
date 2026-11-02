"""Feature flags (DEC-198): whether the tenant lets Nexus use each feature the other products define. Every feature
is on unless a Trust admin switched it off — the default is true, so a tenant gets all of Que Connect and AMPHI
Que until it decides otherwise. The catalog matches what each product publishes at `GET /api/v2/features`; a change
is announced to that product (`que.trust.feature_flag.changed.v2`), which enforces it."""

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncConnection

from quetrust import db, events
from quetrust.errors import Problem

CATALOG: dict[str, dict[str, tuple[str, str]]] = {
    "que-connect": {
        "knowledge": ("Knowledge bases", "Documents and websites agents search and cite."),
        "tools": ("Tools & MCP servers", "Connected MCP servers and the tools agents call through them."),
        "models": ("Models", "Language, embedding, voice and video models agents run on."),
        "skills": ("Skills", "Reusable instructions and procedures agents load."),
        "remote_agents": ("A2A agents", "Remote agents reached over the A2A protocol."),
    },
    "que-amphi": {
        "registry": ("Asset registry", "Released agents and apps registered with their profiles."),
        "releases": ("Releases", "Release requests, reviews and approvals."),
        "deployments": ("Deployments", "Where released versions run, and their observed state."),
        "budgets": ("Budgets", "Spending limits reserved and settled per run."),
    },
}


def known(product: str, feature: str) -> tuple[str, str]:
    entry = CATALOG.get(product, {}).get(feature)
    if entry is None:
        raise Problem(404, "resource_not_found", "Unknown product or feature.")
    return entry


async def listing(conn: AsyncConnection, product: str | None = None) -> list[dict[str, Any]]:
    if product is not None and product not in CATALOG:
        raise Problem(404, "resource_not_found", "Unknown product.")
    rows = await db.all_(conn, "SELECT product, feature, enabled, version, updated_by, updated_at FROM feature_flag")
    saved = {(r["product"], r["feature"]): r for r in rows}
    items = []
    for p, features in CATALOG.items():
        if product is not None and p != product:
            continue
        for f, (label, description) in features.items():
            row = saved.get((p, f))
            items.append(
                {
                    "product": p,
                    "feature": f,
                    "label": label,
                    "description": description,
                    "enabled": bool(row["enabled"]) if row else True,  # default true
                    "version": int(row["version"]) if row else 0,
                    "updated_by": row["updated_by"] if row else None,
                    "updated_at": row["updated_at"].isoformat() if row else None,
                }
            )
    return items


async def set_flag(
    conn: AsyncConnection, tenant_id: uuid.UUID, product: str, feature: str, enabled: bool, by: str
) -> dict[str, Any]:
    known(product, feature)
    row = await db.one(
        conn,
        """
        INSERT INTO feature_flag (tenant_id, product, feature, enabled, version, updated_by)
        VALUES (:t, :p, :f, :e, 1, :b)
        ON CONFLICT (tenant_id, product, feature) DO UPDATE SET enabled = EXCLUDED.enabled,
               version = feature_flag.version + 1, updated_by = EXCLUDED.updated_by, updated_at = now()
        RETURNING version""",
        t=tenant_id,
        p=product,
        f=feature,
        e=enabled,
        b=by,
    )
    assert row is not None
    version = int(row["version"])
    data = {"product": product, "feature": feature, "enabled": enabled, "version": version}
    await events.emit(conn, tenant_id, f"trust-ff-{product}-{feature}-v{version}", events.FEATURE_FLAG_CHANGED, data)
    return next(i for i in await listing(conn, product) if i["feature"] == feature)
