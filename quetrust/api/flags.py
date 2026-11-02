"""Feature flags (DEC-198): which of the other products' features Nexus may use in this tenant. Default true."""

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict

from quetrust import db, features
from quetrust.api.console import READERS
from quetrust.auth import CallerDep
from quetrust.errors import Problem

router = APIRouter()


class FlagPut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


@router.get("/feature-flags")
async def list_flags(caller: CallerDep, product: str | None = None) -> dict[str, Any]:
    """Services (Connect, AMPHI, Nexus) and anyone with a Trust role read them."""
    if not caller.is_service and not (caller.kind == "human" and caller.roles & READERS):
        raise Problem(403, "permission_denied", "Feature flags are read by Que services and Trust roles.")
    async with db.tenant_tx(caller.tenant_id) as conn:
        return {"items": await features.listing(conn, product)}


@router.put("/feature-flags/{product}/{feature}")
async def put_flag(product: str, feature: str, body: FlagPut, caller: CallerDep) -> dict[str, Any]:
    caller.require_admin()
    async with db.tenant_tx(caller.tenant_id) as conn:
        return await features.set_flag(conn, caller.tenant_id, product, feature, body.enabled, caller.subject)
