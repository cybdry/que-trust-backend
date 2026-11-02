"""Trust's owner contract (03-API-CONTRACTS §C.4, Technical Docs 2 p. 10-12): decisions, approvals, stage
decisions, voids, evidence, agent profiles, approval preview and policy resolution, resource policies.

Nexus calls with its service credential (aud que-trust) and, when it calls for a person, their Que.IS token as
`Que-Subject-Token` (verified, recorded as `on_behalf_of`; DEC-198). A stage decision is made as whoever presents the
Bearer credential — a person's QCT (their roles decide eligibility) or an AI approver's NHIAM credential (its
subject and attested asset) — never as someone the body names.
"""

import json
from typing import Any

from fastapi import APIRouter, Header

from quetrust import db, keys, manage, service
from quetrust.auth import CallerDep
from quetrust.errors import Problem

router = APIRouter()
wellknown = APIRouter()


@wellknown.get("/.well-known/jwks.json")
async def jwks() -> dict[str, Any]:
    return keys.jwks()


@router.post("/decisions")
async def create_decision(body: dict[str, Any], caller: CallerDep) -> dict[str, Any]:
    caller.require_service()
    async with db.tenant_tx(caller.tenant_id) as conn:
        return await service.create_decision(conn, caller.tenant_id, body, caller.on_behalf_of)


@router.post("/decisions:simulate")
async def simulate(body: dict[str, Any], caller: CallerDep) -> dict[str, Any]:
    caller.require_service()
    async with db.tenant_tx(caller.tenant_id) as conn:
        return {"stages": await service.simulate(conn, caller.tenant_id, body)}


@router.post("/approvals", status_code=201)
async def request_approval(
    body: dict[str, Any], caller: CallerDep, idempotency_key: str | None = Header(default=None)
) -> dict[str, Any]:
    caller.require_service()
    if not body.get("decision_ref"):
        raise Problem(422, "validation_failed", "decision_ref is required.")
    async with db.tenant_tx(caller.tenant_id) as conn:
        return await service.request_approval(conn, caller.tenant_id, body, idempotency_key or "", caller.on_behalf_of)


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str, caller: CallerDep) -> dict[str, Any]:
    async with db.tenant_tx(caller.tenant_id) as conn:
        return await service.get_approval(conn, caller.tenant_id, approval_id)


@router.post("/approvals/{approval_id}/stages/{stage_id}/decisions", status_code=201)
async def decide_stage(approval_id: str, stage_id: str, body: dict[str, Any], caller: CallerDep) -> dict[str, Any]:
    if caller.kind == "human":
        approver: dict[str, Any] = {
            "principal": caller.subject,
            "principal_kind": "human",
            "roles": sorted(caller.roles),
        }
    elif caller.kind == "workload":  # an AI approver presents its own NHIAM credential
        attested = caller.claims.get("attestation") or {}
        version = body.get("approver_version_ref") or {}
        approver = {
            "principal": caller.subject,
            "principal_kind": "ai_agent",
            "asset_id": attested.get("resource_ref"),
            "version_id": version.get("resource_key"),
        }
    else:
        raise Problem(403, "approver_ineligible", "A service doesn't approve: people and AI approvers do.")
    if body.get("evidence_refs"):
        approver["evidence_refs"] = body["evidence_refs"]
    async with db.tenant_tx(caller.tenant_id) as conn:
        return await service.decide_stage(
            conn,
            caller.tenant_id,
            approval_id,
            stage_id,
            str(body.get("decision", "")),
            str(body.get("reason", "")),
            approver,
            body.get("approver_run_ref"),
        )


@router.post("/approvals/{approval_id}/voids")
async def void(approval_id: str, body: dict[str, Any], caller: CallerDep) -> dict[str, Any]:
    caller.require_service()
    async with db.tenant_tx(caller.tenant_id) as conn:
        return await service.void_approval(conn, caller.tenant_id, approval_id, str(body.get("reason", "")))


@router.post("/evidence-packages", status_code=202)
async def evidence(body: dict[str, Any], caller: CallerDep) -> dict[str, Any]:
    caller.require_service()
    ref = f"evd_{service.sha256_hex([str(caller.tenant_id), body.get('manifest_digest'), body])[:20]}"
    async with db.tenant_tx(caller.tenant_id) as conn:
        await db.run(
            conn,
            """
            INSERT INTO evidence_package (tenant_id, id, manifest_digest, package)
            VALUES (:t, :i, :m, CAST(:p AS jsonb)) ON CONFLICT DO NOTHING""",
            t=caller.tenant_id,
            i=ref,
            m=body.get("manifest_digest"),
            p=json.dumps(body, default=str),
        )
    return {"evidence_id": ref, "status_url": f"/api/v2/evidence-packages/{ref}"}


@router.post("/agent-profiles", status_code=201)
async def agent_profile(body: dict[str, Any], caller: CallerDep) -> dict[str, Any]:
    """The tools and data sources a released agent may use (DEC-145): what decisions read as `input.agent`."""
    caller.require_service()
    version = (body.get("version_ref") or {}).get("resource_key")
    if not version:
        raise Problem(422, "validation_failed", "version_ref is required.")
    digest = str(body.get("manifest_digest", ""))[:12]
    profile = dict(body.get("profile") or {})
    async with db.tenant_tx(caller.tenant_id) as conn:
        await db.run(
            conn,
            """
            INSERT INTO agent_profile (tenant_id, version_key, asset_id, profile, digest)
            VALUES (:t, :v, :a, CAST(:p AS jsonb), :d)
            ON CONFLICT (tenant_id, version_key) DO UPDATE SET asset_id = EXCLUDED.asset_id,
                   profile = EXCLUDED.profile, digest = EXCLUDED.digest, registered_at = now()""",
            t=caller.tenant_id,
            v=str(version),
            a=str(profile["asset_id"]) if profile.get("asset_id") else None,
            p=json.dumps({**profile, "digest": digest}, default=str),
            d=digest,
        )
    return {"profile_id": f"agent-profile:{version}:{digest}"}


@router.get("/approval-policies:resolve")
async def resolve(caller: CallerDep, action_class: str, agent_asset_id: str | None = None) -> dict[str, Any]:
    """Which Trust policy applies (coverage, DEC-154)."""
    caller.require_service()
    async with db.tenant_tx(caller.tenant_id) as conn:
        return {
            "policy": await service.policy_for(conn, {"agent_asset_id": agent_asset_id, "action_class": action_class})
        }


# ---- resource policies (DEC-172): who sees Que Connect's resources on the other platforms ----------------


@router.get("/resource-policies")
async def list_resource_policies(caller: CallerDep, product: str = manage.PRODUCT) -> dict[str, Any]:
    caller.require_policy_admin()
    async with db.tenant_tx(caller.tenant_id) as conn:
        # A resource without a policy is open to everyone in the tenant (DEC-198); a policy narrows it.
        return {"items": await manage.resource_policies(conn, product), "default": manage.DEFAULT_ACCESS}


def _product(product: str) -> None:
    if product != manage.PRODUCT:
        raise Problem(404, "resource_not_found", "Unknown product.")


@router.put("/resource-policies/{product}/{kind}/{ref:path}")
async def put_resource_policy(
    product: str, kind: str, ref: str, body: dict[str, Any], caller: CallerDep
) -> dict[str, Any]:
    caller.require_policy_admin()
    _product(product)
    rules, tool_rules = body.get("rules") or [], body.get("tool_rules") or []
    if not isinstance(rules, list) or not isinstance(tool_rules, list):
        raise Problem(422, "validation_failed", "rules and tool_rules are lists.")
    _check_rules(rules)
    for tr in tool_rules:
        if not isinstance(tr, dict) or not tr.get("tools"):
            raise Problem(422, "validation_failed", "Each tool rule names its tools.")
        _check_rules(tr.get("rules") or [])
    async with db.tenant_tx(caller.tenant_id) as conn:
        return await manage.assign_resource_policy(conn, caller.tenant_id, kind, ref, rules, tool_rules, caller.subject)


def _check_rules(rules: list[Any]) -> None:
    for r in rules:
        if not isinstance(r, dict) or r.get("type") not in ("role", "group", "team", "user", "everyone"):
            raise Problem(422, "validation_failed", "A rule's type is role, group, team, user or everyone.")
        if r.get("access", "use") not in ("view", "use"):
            raise Problem(422, "validation_failed", "A rule gives view or use.")


@router.delete("/resource-policies/{product}/{kind}/{ref:path}")
async def delete_resource_policy(product: str, kind: str, ref: str, caller: CallerDep) -> dict[str, Any]:
    caller.require_policy_admin()
    _product(product)
    async with db.tenant_tx(caller.tenant_id) as conn:
        return await manage.remove_resource_policy(conn, caller.tenant_id, kind, ref, caller.subject)
