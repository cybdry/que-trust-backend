"""What tenants configure in Trust (DEC-151, DEC-154, DEC-172): their rules (compiled to their Rego package),
hand-written Rego, approval policies and assignments, approver groups, and who sees each Que Connect resource
on the other platforms. Rules and Rego are compiled by OPA before they are saved: a policy that doesn't compile
is never stored."""

import json
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncConnection

from quetrust import db, events, service
from quetrust.engine import ENGINE, as_draft, check_tenant_rego, module_id, tenant_package
from quetrust.errors import Problem
from quetrust.policies import ApprovalConfig
from quetrust.rules import RuleSet, catalog, compile_rules

PRODUCT = "que-connect"
RESOURCE_KINDS = ("mcp_server", "tool", "knowledge_base", "skill", "model", "remote_agent")
# Who sees a Connect resource that has no policy (DEC-198): everyone in the tenant. A policy narrows it.
DEFAULT_ACCESS = {"type": "everyone", "access": "use", "label": "Everyone in the tenant (default)"}


# ---- rules and Rego ------------------------------------------------------------------------------------


async def saved_rules(conn: AsyncConnection) -> RuleSet:
    policy = await service.tenant_policy(conn)
    rules = (policy or {}).get("rules")
    return RuleSet.model_validate(rules) if rules else RuleSet()


async def data_sources(conn: AsyncConnection) -> list[dict[str, Any]]:
    """The tenant's data sources Trust knows of, from the agent profiles it holds."""
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for row in await db.all_(conn, "SELECT profile FROM agent_profile"):
        for d in (row["profile"] or {}).get("data_sources", []):
            found[(d["kind"], d["ref"])] = {k: d.get(k) for k in ("kind", "ref", "name", "classification")}
    return sorted(found.values(), key=lambda d: (d["kind"], str(d["name"])))


async def rules_state(conn: AsyncConnection, tenant_id: uuid.UUID) -> dict[str, Any]:
    policy = await service.tenant_policy(conn)
    return {
        "engine": "opa",
        "package": tenant_package(tenant_id),
        "rules": policy.get("rules") if policy else None,
        "hand_written": bool(policy and policy.get("rules") is None),
        "rego": policy["rego"] if policy else None,
        "digest": policy["digest"] if policy else None,
        "saved_by": policy["saved_by"] if policy else None,
        "saved_at": policy["saved_at"].isoformat() if policy else None,
        "catalog": catalog(await data_sources(conn)),
    }


async def save_rego(
    conn: AsyncConnection, tenant_id: uuid.UUID, rego: str, rules: RuleSet | None, by: str
) -> list[dict[str, Any]]:
    """Check and compile the tenant's Rego in OPA, then save it; returns the problems (none = saved)."""
    if problems := check_tenant_rego(tenant_id, rego):
        return problems
    if errors := await ENGINE.put_module(module_id(tenant_id), rego):
        old = await service.tenant_policy(conn)
        if old:  # OPA keeps what was saved, not the rejected text
            await ENGINE.put_module(module_id(tenant_id), str(old["rego"]))
        return errors
    digest = service.sha256_hex(rego)[:12]
    await db.run(
        conn,
        """
        INSERT INTO tenant_policy (tenant_id, rego, rules, digest, saved_by)
        VALUES (current_setting('app.tenant_id')::uuid, :r, CAST(:ru AS jsonb), :d, :b)
        ON CONFLICT (tenant_id) DO UPDATE SET rego = EXCLUDED.rego, rules = EXCLUDED.rules,
               digest = EXCLUDED.digest, saved_by = EXCLUDED.saved_by, saved_at = now()""",
        r=rego,
        ru=json.dumps(rules.model_dump(mode="json")) if rules is not None else None,
        d=digest,
        b=by,
    )
    ENGINE.installed[tenant_id] = digest
    return []


async def save_rules(conn: AsyncConnection, tenant_id: uuid.UUID, rule_set: RuleSet, by: str) -> list[dict[str, Any]]:
    """The tenant's graphical rules (DEC-151): compiled to its Rego package and installed."""
    return await save_rego(conn, tenant_id, compile_rules(tenant_package(tenant_id), rule_set), rule_set, by)


async def clear_rules(conn: AsyncConnection, tenant_id: uuid.UUID) -> None:
    if await service.tenant_policy(conn) is not None:
        await db.run(conn, "DELETE FROM tenant_policy")
        await ENGINE.delete_module(module_id(tenant_id))
        ENGINE.installed.pop(tenant_id, None)


async def try_rules(
    conn: AsyncConnection, tenant_id: uuid.UUID, sample: dict[str, Any], rego: str | None
) -> dict[str, Any]:
    """Evaluate a sample action against the saved policy, or against a draft without saving it."""
    action = {"arguments": {}, "effect": "write", "oversight_mode": "hitl", "action_digest": "", **sample}
    if rego is None:
        out = await service.decide(conn, tenant_id, action)
        return {"result": out, "errors": []}
    if problems := check_tenant_rego(tenant_id, rego):
        return {"result": None, "errors": problems}
    draft = module_id(tenant_id, "drafts")
    if errors := await ENGINE.put_module(draft, as_draft(tenant_id, rego)):
        return {"result": None, "errors": errors}
    try:
        out = await service.decide(conn, tenant_id, action, namespace="drafts")
    finally:
        await ENGINE.delete_module(draft)
    return {"result": out, "errors": []}


# ---- approval policies and groups ----------------------------------------------------------------------


async def save_approval_config(conn: AsyncConnection, config: ApprovalConfig, revision: int | None, by: str) -> int:
    """Replace the tenant's approval policies and assignments; `revision` guards against lost updates."""
    _, current = await service.approval_config(conn)
    if revision is not None and revision != current:
        raise Problem(412, "precondition_failed", "Someone else changed the approval policies; reload them.")
    await db.run(
        conn,
        """
        INSERT INTO approval_config (tenant_id, config, revision, updated_by)
        VALUES (current_setting('app.tenant_id')::uuid, CAST(:c AS jsonb), 1, :b)
        ON CONFLICT (tenant_id) DO UPDATE SET config = EXCLUDED.config,
               revision = approval_config.revision + 1, updated_by = EXCLUDED.updated_by, updated_at = now()""",
        c=json.dumps(config.model_dump(mode="json")),
        b=by,
    )
    return current + 1


async def groups(conn: AsyncConnection) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for r in await db.all_(conn, "SELECT grp, member FROM tenant_group ORDER BY grp, member"):
        out.setdefault(str(r["grp"]), []).append(str(r["member"]))
    return out


# ---- resource policies (DEC-172): who sees Que Connect's resources --------------------------------------


def _policy(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_id": row["policy_id"],
        "product": row["product"],
        "kind": row["kind"],
        "ref": row["ref"],
        "rules": row["rules"],
        "tool_rules": row["tool_rules"] or [],
        "version": int(row["version"]),
        "assigned_by": row["assigned_by"],
        "assigned_at": row["assigned_at"].isoformat(),
    }


def event_data(policy: dict[str, Any]) -> dict[str, Any]:
    """The payload of `que.trust.resource_policy.changed.v2` (06 §3.2a)."""
    return {k: policy[k] for k in ("product", "kind", "ref", "policy_id", "version", "rules", "tool_rules")}


async def resource_policies(conn: AsyncConnection, product: str = PRODUCT) -> list[dict[str, Any]]:
    rows = await db.all_(
        conn,
        "SELECT * FROM resource_policy WHERE product = :p AND rules IS NOT NULL ORDER BY kind, ref",
        p=product,
    )
    return [_policy(r) for r in rows]


async def _write_policy(
    conn: AsyncConnection, tenant_id: uuid.UUID, kind: str, ref: str, rules: Any, tool_rules: list[Any], by: str
) -> dict[str, Any]:
    had = await db.one(
        conn,
        "SELECT policy_id, version, rules FROM resource_policy WHERE product = :p AND kind = :k AND ref = :r FOR UPDATE",
        p=PRODUCT,
        k=kind,
        r=ref,
    )
    row = await db.one(
        conn,
        """
        INSERT INTO resource_policy (tenant_id, product, kind, ref, policy_id, rules, tool_rules, version, assigned_by)
        VALUES (current_setting('app.tenant_id')::uuid, :p, :k, :r, :id, CAST(:ru AS jsonb), CAST(:tr AS jsonb), :v, :b)
        ON CONFLICT (tenant_id, product, kind, ref) DO UPDATE SET rules = EXCLUDED.rules,
               tool_rules = EXCLUDED.tool_rules, version = EXCLUDED.version, assigned_by = EXCLUDED.assigned_by,
               assigned_at = now()
        RETURNING *""",
        p=PRODUCT,
        k=kind,
        r=ref,
        id=(had or {}).get("policy_id") or f"rp_{uuid.uuid4().hex[:16]}",
        ru=json.dumps(rules) if rules is not None else None,
        tr=json.dumps(tool_rules if kind == "mcp_server" else []),
        v=int((had or {}).get("version") or 0) + 1,
        b=by,
    )
    assert row is not None
    policy = _policy(row)
    await events.emit(
        conn,
        tenant_id,
        f"trust-rp-{policy['policy_id']}-v{policy['version']}",
        events.RESOURCE_POLICY_CHANGED,
        event_data(policy),
    )
    return policy


async def assign_resource_policy(
    conn: AsyncConnection,
    tenant_id: uuid.UUID,
    kind: str,
    ref: str,
    rules: list[dict[str, Any]],
    tool_rules: list[dict[str, Any]],
    by: str,
) -> dict[str, Any]:
    if kind not in RESOURCE_KINDS:
        raise Problem(422, "unknown_resource_kind", "Unknown resource kind.")
    return await _write_policy(conn, tenant_id, kind, ref, rules, tool_rules, by)


async def remove_resource_policy(
    conn: AsyncConnection, tenant_id: uuid.UUID, kind: str, ref: str, by: str
) -> dict[str, Any]:
    """Rules become null (a tombstone, so the next policy keeps counting versions up): the resource is back to the
    default, everyone in the tenant (DEC-198)."""
    had = await db.one(
        conn,
        "SELECT rules FROM resource_policy WHERE product = :p AND kind = :k AND ref = :r",
        p=PRODUCT,
        k=kind,
        r=ref,
    )
    if had is None or had["rules"] is None:
        raise Problem(404, "resource_not_found", "No policy on this resource.")
    return await _write_policy(conn, tenant_id, kind, ref, None, [], by)
