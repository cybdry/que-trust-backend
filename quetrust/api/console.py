"""The Trust console's API (docs/08-QUE-TRUST.md §5): people of the tenant, signed in through Que.IS. Anyone with a
Trust role reads; tenant_admin or trust_admin change policy."""

from typing import Any, Literal

from fastapi import APIRouter, Header
from pydantic import BaseModel, Field

from quetrust import db, manage, service
from quetrust.auth import Caller, CallerDep
from quetrust.engine import PLATFORM_REGO, tenant_package
from quetrust.errors import Problem
from quetrust.policies import ApprovalConfig
from quetrust.rules import RuleSet, ToolScope, compile_rules

router = APIRouter()

READERS = frozenset({"tenant_admin", "trust_admin", "approver"})


def _reader(caller: Caller) -> None:
    caller.require_person()
    if not caller.roles & READERS:
        raise Problem(403, "permission_denied", "The Trust console needs a Trust role (approver or admin).")


@router.get("/me")
async def me(caller: CallerDep) -> dict[str, Any]:
    caller.require_person()
    return {
        "subject": caller.subject,
        "tenant_id": str(caller.tenant_id),
        "roles": sorted(caller.roles),
        "can_admin": caller.is_admin,
        "can_read": bool(caller.roles & READERS),
        "email": caller.claims.get("email"),
    }


@router.get("/overview")
async def overview(caller: CallerDep) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        outcomes = await db.all_(
            conn,
            "SELECT decision, count(*) AS n FROM decision WHERE created_at > now() - interval '24 hours' GROUP BY decision",
        )
        config, revision = await service.approval_config(conn)
        policy = await service.tenant_policy(conn)
        rules = (policy or {}).get("rules") or {}
        return {
            "decisions_24h": {
                "allow": 0,
                "deny": 0,
                "approval_required": 0,
                **{str(r["decision"]): int(r["n"]) for r in outcomes},
            },
            "open_approvals": int(await db.val(conn, "SELECT count(*) FROM approval WHERE status = 'pending'") or 0),
            "policies": len(config.policies),
            "assignments": len(config.assignments),
            "approval_config_revision": revision,
            "rules": len([r for r in rules.get("rules", []) if r.get("enabled", True)]),
            "scopes": len(rules.get("scopes", [])),
            "hand_written_policy": bool(policy and policy.get("rules") is None),
            "resource_policies": len(await manage.resource_policies(conn)),
            "agent_profiles": int(await db.val(conn, "SELECT count(*) FROM agent_profile") or 0),
            "groups": int(await db.val(conn, "SELECT count(DISTINCT grp) FROM tenant_group") or 0),
            "features_off": int(await db.val(conn, "SELECT count(*) FROM feature_flag WHERE NOT enabled") or 0),
        }


# ---- rules ----------------------------------------------------------------------------------------------


class RulesPut(BaseModel):
    timezone: str = "UTC"
    rules: list[dict[str, Any]] = Field(default_factory=list)
    scopes: list[dict[str, Any]] | None = Field(default=None, description="Omitted: the saved data scopes stay")


def _rule_set(body: RulesPut, saved: RuleSet) -> RuleSet:
    raw = body.model_dump(exclude_none=True)
    if body.scopes is None:
        raw["scopes"] = [s.model_dump(mode="json") for s in saved.scopes]
    try:
        return RuleSet.model_validate(raw)
    except ValueError as exc:
        raise Problem(422, "validation_failed", str(exc)) from exc


@router.get("/rules")
async def get_rules(caller: CallerDep) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        return await manage.rules_state(conn, caller.tenant_id)


@router.put("/rules")
async def put_rules(body: RulesPut, caller: CallerDep) -> dict[str, Any]:
    caller.require_admin()
    async with db.tenant_tx(caller.tenant_id) as conn:
        rule_set = _rule_set(body, await manage.saved_rules(conn))
        if errors := await manage.save_rules(conn, caller.tenant_id, rule_set, caller.subject):
            raise Problem(422, "tenant_policy_rejected", "The rules don't compile.", errors=errors)
        return await manage.rules_state(conn, caller.tenant_id)


@router.delete("/rules")
async def clear_rules(caller: CallerDep) -> dict[str, Any]:
    caller.require_admin()
    async with db.tenant_tx(caller.tenant_id) as conn:
        await manage.clear_rules(conn, caller.tenant_id)
        return await manage.rules_state(conn, caller.tenant_id)


class RegoPut(BaseModel):
    rego: str = Field(min_length=1, max_length=200_000)


@router.put("/rules/rego")
async def put_rego(body: RegoPut, caller: CallerDep) -> dict[str, Any]:
    """Hand-written Rego in the tenant's package (replaces graphical rules)."""
    caller.require_admin()
    async with db.tenant_tx(caller.tenant_id) as conn:
        if errors := await manage.save_rego(conn, caller.tenant_id, body.rego, None, caller.subject):
            raise Problem(422, "tenant_policy_rejected", "The policy was refused.", errors=errors)
        return await manage.rules_state(conn, caller.tenant_id)


def _draft(raw: Any) -> RulesPut:
    """A rule set as the console sends it: the RuleSet itself, or wrapped as {rules: RuleSet}."""
    if isinstance(raw, dict) and isinstance(raw.get("rules"), dict):
        raw = raw["rules"]
    try:
        return RulesPut.model_validate(raw)
    except ValueError as exc:
        raise Problem(422, "validation_failed", str(exc)) from exc


@router.post("/rules:preview")
async def preview_rules(body: dict[str, Any], caller: CallerDep) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        rule_set = _rule_set(_draft(body), await manage.saved_rules(conn))
    return {"rego": compile_rules(tenant_package(caller.tenant_id), rule_set)}


class TryBody(BaseModel):
    sample: dict[str, Any] = Field(description="The action Nexus would send (action_class, effect, arguments …)")
    rules: RulesPut | None = Field(default=None, description="A draft to try instead of the saved policy")


@router.post("/rules:try")
async def try_rules(body: TryBody, caller: CallerDep) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        draft = None
        if body.rules is not None:
            draft = compile_rules(
                tenant_package(caller.tenant_id), _rule_set(body.rules, await manage.saved_rules(conn))
            )
        tried = await manage.try_rules(conn, caller.tenant_id, body.sample, draft)
    return {"status": "error" if tried["errors"] else "ok", **tried}


class ScopesPut(BaseModel):
    scopes: list[dict[str, Any]] = Field(default_factory=list, max_length=500)


@router.put("/agent-scopes/{agent_asset_id}")
async def put_scopes(agent_asset_id: str, body: ScopesPut, caller: CallerDep) -> dict[str, Any]:
    """An agent's data scopes (DEC-152): which data each of its tools may act on."""
    caller.require_admin()
    try:
        scopes = [ToolScope.model_validate(s) for s in body.scopes]
    except ValueError as exc:
        raise Problem(422, "validation_failed", str(exc)) from exc
    if any(s.agent_asset_id != agent_asset_id for s in scopes):
        raise Problem(422, "validation_failed", "Every scope must belong to the agent being saved.")
    async with db.tenant_tx(caller.tenant_id) as conn:
        saved = await manage.saved_rules(conn)
        others = [s for s in saved.scopes if s.agent_asset_id != agent_asset_id]
        rule_set = saved.model_copy(update={"scopes": others + scopes})
        if errors := await manage.save_rules(conn, caller.tenant_id, rule_set, caller.subject):
            raise Problem(422, "tenant_policy_rejected", "The scopes don't compile.", errors=errors)
        return await manage.rules_state(conn, caller.tenant_id)


# ---- approval policies ----------------------------------------------------------------------------------


@router.get("/approval-config")
async def get_approval_config(caller: CallerDep) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        config, revision = await service.approval_config(conn)
    return {**config.model_dump(mode="json"), "revision": revision}


@router.put("/approval-config")
async def put_approval_config(
    body: dict[str, Any], caller: CallerDep, if_match: str | None = Header(default=None)
) -> dict[str, Any]:
    caller.require_admin()
    try:
        config = ApprovalConfig.model_validate({k: v for k, v in body.items() if k != "revision"})
    except ValueError as exc:
        raise Problem(422, "validation_failed", str(exc)) from exc
    revision = int(if_match.strip('"')) if if_match and if_match.strip('"').isdigit() else None
    async with db.tenant_tx(caller.tenant_id) as conn:
        new = await manage.save_approval_config(conn, config, revision, caller.subject)
    return {**config.model_dump(mode="json"), "revision": new}


class SimulateBody(BaseModel):
    action_class: str = Field(min_length=1, max_length=200)
    agent_asset_id: str | None = None
    agent_version_id: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    requester: str | None = None


@router.post("/approval-config:simulate")
async def simulate(body: SimulateBody, caller: CallerDep) -> dict[str, Any]:
    """The stages an approval for this sample action would open, and the policy chosen."""
    _reader(caller)
    action = {
        "action_class": body.action_class,
        "effect": "write",
        "oversight_mode": "hitl",
        "arguments": body.arguments,
        "agent_asset_id": body.agent_asset_id,
        "agent_version_id": body.agent_version_id,
        "requester": body.requester,
        "action_digest": "",
    }
    async with db.tenant_tx(caller.tenant_id) as conn:
        return {
            "policy": await service.policy_for(conn, action),
            "stages": await service.effective_stages(conn, caller.tenant_id, action),
        }


# ---- groups ---------------------------------------------------------------------------------------------


@router.get("/groups")
async def list_groups(caller: CallerDep) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        return {"groups": await manage.groups(conn)}


def _name(value: str, what: str) -> str:
    value = value.strip()
    if not value or len(value) > 200:
        raise Problem(422, "validation_failed", f"Give the {what} (1-200 characters).")
    return value


@router.put("/groups/{group}/members/{member}")
async def add_member(group: str, member: str, caller: CallerDep) -> dict[str, Any]:
    caller.require_admin()
    async with db.tenant_tx(caller.tenant_id) as conn:
        await db.run(
            conn,
            """
            INSERT INTO tenant_group (tenant_id, grp, member, added_by)
            VALUES (current_setting('app.tenant_id')::uuid, :g, :m, :b) ON CONFLICT DO NOTHING""",
            g=_name(group, "group"),
            m=_name(member, "member"),
            b=caller.subject,
        )
        return {"groups": await manage.groups(conn)}


@router.delete("/groups/{group}/members/{member}")
async def remove_member(group: str, member: str, caller: CallerDep) -> dict[str, Any]:
    caller.require_admin()
    async with db.tenant_tx(caller.tenant_id) as conn:
        await db.run(conn, "DELETE FROM tenant_group WHERE grp = :g AND member = :m", g=group, m=member)
        return {"groups": await manage.groups(conn)}


# ---- what Trust decided and holds -----------------------------------------------------------------------


def _limit(limit: int) -> int:
    return max(1, min(limit, 200))


@router.get("/decisions")
async def decisions(
    caller: CallerDep, limit: int = 50, outcome: Literal["allow", "deny", "approval_required"] | None = None
) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        rows = await db.all_(
            conn,
            """
            SELECT id, action, decision, reasons, obligations, policy_ref, input, approval_ref, expires_at, created_at,
                   on_behalf_of
            FROM decision WHERE (CAST(:o AS text) IS NULL OR decision = :o) ORDER BY created_at DESC LIMIT :l""",
            o=outcome,
            l=_limit(limit),
        )
    return {
        "items": [
            {
                "decision_id": r["id"],
                "at": r["created_at"].isoformat(),
                "decision": r["decision"],
                "action_class": r["action"].get("action_class"),
                "tool_ref": r["action"].get("tool_ref"),
                "effect": r["action"].get("effect"),
                "oversight_mode": r["action"].get("oversight_mode"),
                "requester": r["action"].get("requester"),
                "on_behalf_of": r["on_behalf_of"],
                "agent_asset_id": r["action"].get("agent_asset_id"),
                "with_approval": bool(r["approval_ref"]),
                "reasons": r["reasons"],
                "obligations": r["obligations"],
                "policy_ref": r["policy_ref"],
                "input": r["input"],
            }
            for r in rows
        ]
    }


@router.get("/approvals")
async def approvals(
    caller: CallerDep,
    limit: int = 50,
    status: Literal["pending", "approved", "rejected", "changes_requested", "expired", "voided"] | None = None,
) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        rows = await db.all_(
            conn,
            """
            SELECT id, status, action, action_digest, business_reason, stages, void_reason, created_at, updated_at,
                   on_behalf_of
            FROM approval WHERE (CAST(:s AS text) IS NULL OR status = :s) ORDER BY created_at DESC LIMIT :l""",
            s=status,
            l=_limit(limit),
        )
    return {
        "items": [
            {
                "approval_id": r["id"],
                "status": r["status"],
                "action_class": r["action"].get("action_class"),
                "tool_ref": r["action"].get("tool_ref"),
                "requester": r["action"].get("requester"),
                "on_behalf_of": r["on_behalf_of"],
                "arguments": r["action"].get("arguments"),
                "business_reason": r["business_reason"],
                "void_reason": r["void_reason"],
                "stages": r["stages"],
                "created_at": r["created_at"].isoformat(),
                "updated_at": r["updated_at"].isoformat(),
            }
            for r in rows
        ]
    }


@router.get("/agent-profiles")
async def agent_profiles(caller: CallerDep) -> dict[str, Any]:
    """Released agents as Trust registered them: what rules, scopes and assignments refer to."""
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        rows = await db.all_(
            conn,
            "SELECT version_key, asset_id, profile, digest, registered_at FROM agent_profile ORDER BY registered_at DESC",
        )
    return {
        "items": [
            {
                **(r["profile"] or {}),
                "version_id": r["version_key"],
                "asset_id": r["asset_id"],
                "digest": r["digest"],
                "registered_at": r["registered_at"].isoformat(),
            }
            for r in rows
        ]
    }


@router.get("/evidence-packages")
async def evidence(caller: CallerDep, limit: int = 50) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        rows = await db.all_(
            conn,
            "SELECT id, manifest_digest, package, created_at FROM evidence_package ORDER BY created_at DESC LIMIT :l",
            l=_limit(limit),
        )
    return {
        "items": [
            {
                "ref": r["id"],
                "manifest_digest": r["manifest_digest"],
                "items": len((r["package"] or {}).get("items") or []),
                "received_at": r["created_at"].isoformat(),
            }
            for r in rows
        ]
    }


@router.get("/evidence-packages/{ref}")
async def evidence_package(ref: str, caller: CallerDep) -> dict[str, Any]:
    _reader(caller)
    async with db.tenant_tx(caller.tenant_id) as conn:
        row = await db.one(
            conn, "SELECT id, manifest_digest, package, created_at FROM evidence_package WHERE id = :i", i=ref
        )
    if row is None:
        raise Problem(404, "resource_not_found", "No such evidence package.")
    return {
        "ref": row["id"],
        "manifest_digest": row["manifest_digest"],
        "package": row["package"],
        "received_at": row["created_at"].isoformat(),
    }


@router.get("/platform-policy")
async def platform_policy(caller: CallerDep) -> dict[str, Any]:
    _reader(caller)
    return {"package": "que.trust", "rego": PLATFORM_REGO, "digest": service.PLATFORM_DIGEST}
