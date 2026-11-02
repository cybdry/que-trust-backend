"""Que Trust's decisions and approvals (DEC-144, DEC-154, DEC-197). Port of the stand-in Nexus was built against
(backend/nexus/ports/dev/trust.py), persisted in Trust's database:

- Decisions run on OPA: Trust's platform policy plus the tenant's own package, which can only strengthen
  (deny, require approval, add human stages, force human-only, add obligations). Writes in HITL mode need
  approval, reads are allowed; HOTL writes are allowed with the `oversight` obligation naming the overseers.
- Approvals follow the tenant's approval policy (most specific assignment, else Trust's built-in stage):
  stages in ordinal order (equal ordinals in parallel), quorum any/all/n_of_m, conditions computed from the
  actual arguments, expiry with one escalation, separation of duties, one vote per principal, AI votes only
  on ai_allowed/mixed stages with a current NHIAM mandate and never in a human quorum.
- Every stage binds the action digest; a void voids every stage. A decision token is issued only for an
  allow — after an approval only when the approval is approved for exactly this action.
"""

import hashlib
import json
import math
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncConnection

from quetrust import db, events, keys
from quetrust.config import get_settings
from quetrust.engine import ENGINE, PLATFORM_REGO, tenant_package
from quetrust.errors import Problem
from quetrust.policies import ApprovalConfig
from quetrust.policies import resolve as resolve_policy
from quetrust.useragent import HEADERS

_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

clock: Callable[[], datetime] = lambda: datetime.now(UTC)  # noqa: E731 - tests move time
nhiam_transport: Any = None  # tests play NHIAM


def sha256_hex(value: Any) -> str:
    """Canonical JSON digests (03 §A.2), as Nexus computes them."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


PLATFORM_DIGEST = sha256_hex(PLATFORM_REGO)[:12]


def action_digest(action: dict[str, Any]) -> str:
    """ActionContext.action_digest: over what the dispatching owner can see — target, arguments, schema."""
    args = action.get("args")
    return sha256_hex(
        {
            "target_ref": str(action.get("target_ref", "")),
            "args": args if isinstance(args, dict) else {},
            "schema": str(action.get("schema_digest", "")),
        }
    )


def _key(ref: Any) -> str | None:
    return str(ref["resource_key"]) if isinstance(ref, dict) and ref.get("resource_key") else None


def as_action(body: dict[str, Any]) -> dict[str, Any]:
    """A POST /decisions body (DecisionRequest.as_dict) as the action document the policy reads."""
    a = body.get("action") or {}
    args = a.get("args")
    out: dict[str, Any] = {
        "action_class": a.get("operation") or None,
        "tool_ref": a.get("target_ref") or None,  # an approval step targets no tool (absent, not "")
        "connection_ref": body.get("connection_ref"),
        "effect": str(body.get("effect") or "write"),
        "oversight_mode": str(body.get("oversight_mode") or "hitl"),
        "arguments": args if isinstance(args, dict) else {},
        "environment": str(body.get("environment") or "test"),
        "run_ref": a.get("run_ref"),
        "agent_asset_id": _key(body.get("agent_asset_ref")),
        "agent_version_id": _key(body.get("agent_version_ref")),
        "acting_agent": body.get("acting_workload_ref"),
        "requester": body.get("initiator_ref"),
        "agent_type": body.get("agent_type"),
        "data_used": list(body.get("data_used") or []),
        "action_digest": action_digest(a),
    }
    approval_ref = (body.get("authority") or {}).get("approval_ref")
    if approval_ref:
        out["approval_id"] = approval_ref
    return out


# ---- what Trust holds for a tenant ---------------------------------------------------------------------


async def tenant_policy(conn: AsyncConnection) -> dict[str, Any] | None:
    return await db.one(conn, "SELECT rego, rules, digest, saved_by, saved_at FROM tenant_policy")


async def approval_config(conn: AsyncConnection) -> tuple[ApprovalConfig, int]:
    row = await db.one(conn, "SELECT config, revision FROM approval_config")
    if row is None:
        return ApprovalConfig(), 0
    return ApprovalConfig.model_validate(row["config"]), int(row["revision"])


async def groups_of(conn: AsyncConnection, member: str | None) -> list[str]:
    if not member:
        return []
    rows = await db.all_(conn, "SELECT grp FROM tenant_group WHERE member = :m ORDER BY grp", m=member)
    return [str(r["grp"]) for r in rows]


async def group_members(conn: AsyncConnection, group: str) -> set[str]:
    rows = await db.all_(conn, "SELECT member FROM tenant_group WHERE grp = :g", g=group)
    return {str(r["member"]) for r in rows}


async def agent_profile(conn: AsyncConnection, version: Any) -> dict[str, Any] | None:
    if not version:
        return None
    row = await db.one(conn, "SELECT profile FROM agent_profile WHERE version_key = :v", v=str(version))
    return dict(row["profile"]) if row else None


# ---- the decision engine --------------------------------------------------------------------------------


async def input_document(
    conn: AsyncConnection, tenant_id: uuid.UUID, action: dict[str, Any], approval: dict[str, Any] | None
) -> dict[str, Any]:
    """The input document Trust gives OPA for one protected action."""
    keys_ = (
        "action_class",
        "tool_ref",
        "connection_ref",
        "operation",
        "effect",
        "oversight_mode",
        "arguments",
        "environment",
        "agent_asset_id",
        "run_ref",
    )
    requester = action.get("requester")
    version = action.get("agent_version_id")
    # The acting non-human identity as Trust registered it at release (DEC-145), not as the caller describes it.
    profile = await agent_profile(conn, version)
    agent = {"identity": action.get("acting_agent") or None, "version_id": version, "registered": bool(profile)}
    # The data this run read before the action (DEC-152), described as the profile knows it.
    known = {(d["kind"], d["ref"]): d for d in (profile or {}).get("data_sources", [])}
    used = [
        {**known.get((u["kind"], u["ref"]), {"name": None, "classification": None}), "kind": u["kind"], "ref": u["ref"]}
        for u in action.get("data_used") or []
        if isinstance(u, dict) and "kind" in u and "ref" in u
    ]
    levels = [u["classification"] for u in used if u.get("classification") in _RANK]
    doc: dict[str, Any] = {
        "tenant": str(tenant_id),
        "action": {k: action[k] for k in keys_ if action.get(k) is not None},
        "run": {"data_used": used, "max_classification": max(levels, key=_RANK.__getitem__) if levels else None},
        "requester": requester,
        "agent": {**agent, **(profile or {})},
        "requester_groups": await groups_of(conn, requester),
        "time": clock().isoformat(),
    }
    if approval is not None:
        doc["approval"] = approval
    normalized: dict[str, Any] = json.loads(json.dumps(doc, default=str))
    return normalized


async def decide(
    conn: AsyncConnection,
    tenant_id: uuid.UUID,
    action: dict[str, Any],
    approval: dict[str, Any] | None = None,
    namespace: str = "tenants",
) -> dict[str, Any]:
    doc = await input_document(conn, tenant_id, action, approval)
    policy = await tenant_policy(conn)
    out = await ENGINE.evaluate(tenant_id, doc, policy, namespace)
    return {**out, "input": doc, "policy_digest": policy["digest"] if policy else None}


def policy_ref(tenant_id: uuid.UUID, out: dict[str, Any]) -> str:
    ref = f"opa:que.trust@{PLATFORM_DIGEST}"
    if out.get("policy_digest") and out.get("tenant_policy"):
        ref += f"+{tenant_package(tenant_id)}@{out['policy_digest']}"
    return ref


async def _agent_asset(conn: AsyncConnection, action: dict[str, Any]) -> str | None:
    """The acting agent as Trust registered it at release (else as Nexus names it: previews)."""
    profile = await agent_profile(conn, action.get("agent_version_id"))
    return str((profile or {}).get("asset_id") or action.get("agent_asset_id") or "") or None


async def policy_for(conn: AsyncConnection, action: dict[str, Any]) -> dict[str, Any] | None:
    config, _ = await approval_config(conn)
    found = resolve_policy(config, await _agent_asset(conn, action), str(action.get("action_class") or ""))
    return found.model_dump(mode="json", exclude_none=True) if found else None


def _condition(cond: dict[str, Any] | None, arguments: dict[str, Any]) -> bool:
    """Trust computes conditions from the actual arguments (Nexus labels are advisory)."""
    if not cond:
        return True
    left, right, op = arguments.get(str(cond.get("field"))), cond.get("value"), str(cond.get("operation", "equals"))

    def num(v: Any) -> float:
        try:
            return float(v)
        except (TypeError, ValueError):
            return math.nan

    return {
        "equals": str(left) == str(right),
        "notEquals": str(left) != str(right),
        "larger": num(left) > num(right),
        "smaller": num(left) < num(right),
        "contains": str(right) in str(left),
    }.get(op, False)


async def effective_stages(
    conn: AsyncConnection, tenant_id: uuid.UUID, action: dict[str, Any], decided: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """The stages an approval for this action opens: the assigned policy's (else Trust's built-in stage), then
    the stages the tenant's rules add; a tenant rule may force every stage human-only."""
    policy = await policy_for(conn, action)
    decided = decided or await decide(conn, tenant_id, action)
    raw_args = action.get("arguments")
    args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
    profile = await agent_profile(conn, action.get("agent_version_id")) or {}
    genie = (profile.get("agent_type") or action.get("agent_type")) == "genie"
    raw = (policy or {}).get("stages") or [
        # A Genie works for one person, who confirms its actions in the conversation (Nexus DEC-217). Others: a role.
        owner_confirms(str(action["requester"]))
        if genie and action.get("requester")
        else {
            "stage_key": "default",
            "ordinal": 1,
            "approver_kind": "human_only",
            "quorum": "any",
            "approvers": [{"type": "role", "ref": "approver"}],
        }
    ]
    stages = []
    for s in raw:
        kind = s["approver_kind"]
        if decided.get("human_only") and kind != "human_only":
            kind = "human_only"  # the tenant policy may strengthen, never weaken
        stages.append(
            {
                "stage_id": s["stage_key"],
                "ordinal": int(s["ordinal"]),
                "approver_kind": kind,
                "quorum": s["quorum"],
                "quorum_n": s.get("quorum_n"),
                "approvers": list(s["approvers"]),
                "expires_after_seconds": s.get("expires_after_seconds"),
                "escalation": dict(s.get("escalation") or {}),
                "sod_rules": dict(s.get("sod_rules") or {}),
                "source": "policy",
                "status": "pending" if _condition(s.get("condition"), args) else "skipped",
            }
        )
    after = max((s["ordinal"] for s in stages), default=0)
    for i, extra in enumerate(decided.get("approval_stages") or []):
        # Stages the tenant's rules add: human-only, after the policy's stages.
        approvers = [
            {"type": a["type"], "ref": str(a["ref"])}
            for a in (extra.get("approvers") or [])
            if isinstance(a, dict) and a.get("type") in ("role", "group", "user") and a.get("ref")
        ]
        if not approvers:
            continue
        stage_id = str(extra.get("stage_key") or f"tenant-{i + 1}")
        if any(s["stage_id"] == stage_id for s in stages):
            stage_id = f"tenant-{stage_id}"
        quorum = extra.get("quorum") if extra.get("quorum") in ("any", "all", "n_of_m") else "any"
        stages.append(
            {
                "stage_id": stage_id,
                "ordinal": after + max(1, int(extra.get("ordinal") or 1)),
                "approver_kind": "human_only",
                "quorum": quorum,
                "quorum_n": extra.get("quorum_n") if quorum == "n_of_m" else None,
                "approvers": approvers,
                "expires_after_seconds": extra.get("expires_after_seconds"),
                "escalation": {},
                "sod_rules": {},
                "source": "tenant_floor",
                "status": "pending",
            }
        )
    for s in stages:
        s.update({"human_votes": 0, "ai_votes": 0, "decisions": [], "expires_at": None, "escalated": False})
    return stages


def _obligations_wire(d: dict[str, Any]) -> list[Any]:
    out: list[Any] = []
    for o in d["obligations"]:
        if o == "oversight":
            out.append(
                {"kind": "oversight", "overseers": d["overseers"], "review_window_seconds": d["review_window_seconds"]}
            )
        else:
            out.append(o)
    return out


async def create_decision(
    conn: AsyncConnection, tenant_id: uuid.UUID, body: dict[str, Any], on_behalf_of: str | None = None
) -> dict[str, Any]:
    """POST /decisions: every attempt, including after an approval. `on_behalf_of`: the person the service called
    for (their verified token, DEC-198)."""
    action = as_action(body)
    approval = None
    if approval_id := action.get("approval_id"):
        a = await db.one(conn, "SELECT status, action_digest FROM approval WHERE id = :i", i=approval_id)
        approval = {
            "id": approval_id,
            "status": a["status"] if a else "unknown",
            "matches_action": bool(a and a["action_digest"] == action["action_digest"]),
        }
    out = await decide(conn, tenant_id, action, approval)
    ref, reasons = policy_ref(tenant_id, out), list(out["reasons"])
    result: dict[str, Any] = {
        "decision": out["decision"],
        "reasons": reasons,
        "stages": [],
        "obligations": [],
        "overseers": [],
        "review_window_seconds": None,
    }
    if out["decision"] == "approval_required":
        result["stages"] = await effective_stages(conn, tenant_id, action, decided=out)
    elif out["decision"] == "allow":
        result["obligations"] = list(out["obligations"])
        if "oversight" in result["obligations"]:  # HOTL: proceeds; the policy's approvers review it afterwards
            policy = await policy_for(conn, action) or {}
            overseers = [a for st in policy.get("stages", []) for a in st.get("approvers", [])]
            result["overseers"] = overseers or [{"type": "role", "ref": "overseer"}]
            result["review_window_seconds"] = int(policy.get("hotl_window_seconds") or 900)
    expires = clock() + timedelta(seconds=get_settings().decision_ttl_seconds)
    decision_id = f"dec_{uuid.uuid4().hex[:24]}"
    await db.run(
        conn,
        """
        INSERT INTO decision (tenant_id, id, action, action_digest, decision, reasons, obligations, policy_ref,
                              input, approval_ref, expires_at, on_behalf_of)
        VALUES (:t, :i, CAST(:a AS jsonb), :d, :dec, CAST(:r AS jsonb), CAST(:o AS jsonb), :p, CAST(:inp AS jsonb),
                :ap, :e, :obo)""",
        t=tenant_id,
        i=decision_id,
        a=json.dumps(action, default=str),
        d=action["action_digest"],
        dec=out["decision"],
        r=json.dumps(reasons),
        o=json.dumps(result["obligations"]),
        p=ref,
        inp=json.dumps(out["input"], default=str),
        ap=action.get("approval_id"),
        e=expires,
        obo=on_behalf_of,
    )
    token = None
    if out["decision"] == "allow":
        # The relying owner verifies this offline (03 §C.8 (6)): exactly this action, this tenant, now.
        token = keys.decision_token(
            audience=str(body.get("audience") or "que-connect"),
            tenant=str(tenant_id),
            decision_id=decision_id,
            action_digest=action["action_digest"],
            policy_ref=ref,
            expires=expires,
        )
    return {
        "decision_id": decision_id,
        "decision": out["decision"],
        "decision_token": token,
        "policy_ref": ref,
        "stages": result["stages"],
        "obligations": _obligations_wire(result),
        "reasons": reasons,
        "expires_at": expires.isoformat(),
    }


async def simulate(conn: AsyncConnection, tenant_id: uuid.UUID, body: dict[str, Any]) -> list[dict[str, Any]]:
    """POST /decisions:simulate — the stages Trust would open, without deciding (DEC-131)."""
    return await effective_stages(conn, tenant_id, as_action(body))


# ---- approvals ------------------------------------------------------------------------------------------


def _open_next(a: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """Open the next ordinal's stages; returns the events to emit (stages naming AI approvers)."""
    out: list[tuple[str, str, dict[str, Any]]] = []
    live = [s for s in a["stages"] if s["status"] in ("pending", "open")]
    if not live:
        a["status"] = "approved"
        return out
    first = min(s["ordinal"] for s in live)
    for s in live:
        if s["ordinal"] == first and s["status"] == "pending":
            s["status"] = "open"
            if s.get("expires_after_seconds"):
                s["expires_at"] = (clock() + timedelta(seconds=int(s["expires_after_seconds"]))).isoformat()
            ai = [ap for ap in s["approvers"] if ap.get("type") == "ai_agent"]
            if ai:
                out.append(
                    (
                        f"trust-{a['approval_id']}-opened-{s['stage_id']}",
                        events.STAGE_OPENED,
                        {
                            "approval_id": a["approval_id"],
                            "stage_id": s["stage_id"],
                            "approver_kind": s["approver_kind"],
                            "ai_approvers": ai,
                            "action_digest": a["action_digest"],
                            "action": a["action"],
                        },
                    )
                )
    return out


def _expire(a: dict[str, Any]) -> bool:
    """Open stages past their expiry escalate once, then expire the approval. True when something changed."""
    if a["status"] != "pending":
        return False
    now, changed = clock(), False
    for s in a["stages"]:
        if s["status"] == "open" and s["expires_at"] and datetime.fromisoformat(s["expires_at"]) <= now:
            changed = True
            esc = s.get("escalation") or {}
            if esc.get("approvers") and not s["escalated"]:
                s["approvers"] = s["approvers"] + list(esc["approvers"])
                s["escalated"] = True
                after = int(esc.get("after_seconds") or s.get("expires_after_seconds") or 3600)
                s["expires_at"] = (now + timedelta(seconds=after)).isoformat()
            else:
                s["status"] = "expired"
                a["status"] = "expired"
    return changed


def _next_expiry(a: dict[str, Any]) -> datetime | None:
    if a["status"] != "pending":
        return None
    due = [datetime.fromisoformat(s["expires_at"]) for s in a["stages"] if s["status"] == "open" and s["expires_at"]]
    return min(due) if due else None


def _row_to_approval(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": row["id"],
        "tenant": str(row["tenant_id"]),
        "decision_ref": row["decision_ref"],
        "business_reason": row["business_reason"],
        "status": row["status"],
        "action": row["action"],
        "action_digest": row["action_digest"],
        "stages": row["stages"],
        "void_reason": row.get("void_reason"),
        "created_at": row.get("created_at"),
    }


async def _load(conn: AsyncConnection, approval_id: str, lock: bool = False) -> dict[str, Any] | None:
    sql = "SELECT * FROM approval WHERE id = :i FOR UPDATE" if lock else "SELECT * FROM approval WHERE id = :i"
    row = await db.one(conn, sql, i=approval_id)
    return _row_to_approval(row) if row else None


async def _save(conn: AsyncConnection, tenant_id: uuid.UUID, a: dict[str, Any]) -> None:
    await db.run(
        conn,
        """
        UPDATE approval SET status = :s, stages = CAST(:st AS jsonb), void_reason = :v, next_expiry = :n,
               revision = revision + 1, updated_at = now() WHERE id = :i""",
        s=a["status"],
        st=json.dumps(a["stages"], default=str),
        v=a.get("void_reason"),
        n=_next_expiry(a),
        i=a["approval_id"],
    )
    if a["status"] in ("approved", "rejected", "changes_requested", "expired"):
        await events.emit(
            conn,
            tenant_id,
            f"trust-{a['approval_id']}-{a['status']}",
            events.APPROVAL_DECIDED,
            {
                "approval_id": a["approval_id"],
                "status": a["status"],
                "action_digest": a["action_digest"],
                "stage_id": a.get("decided_stage"),
            },
        )


def approval_wire(a: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": a["approval_id"],
        "state": a["status"],
        "action_digest": a["action_digest"],
        "stages": a["stages"],
        "expires_at": None,
    }


async def request_approval(
    conn: AsyncConnection,
    tenant_id: uuid.UUID,
    body: dict[str, Any],
    idempotency_key: str,
    on_behalf_of: str | None = None,
) -> dict[str, Any]:
    """POST /approvals: for a decision that required one, for exactly the decided action."""
    key = idempotency_key or uuid.uuid4().hex
    existing = await db.one(conn, "SELECT id FROM approval WHERE idempotency_key = :k", k=key)
    if existing is None:
        decision_ref = str(body.get("decision_ref") or "")
        d = await db.one(conn, "SELECT decision, action, action_digest FROM decision WHERE id = :i", i=decision_ref)
        if d is None or d["decision"] != "approval_required":
            raise Problem(409, "decision_stale", "No open approval-required decision with that reference.")
        if d["action_digest"] != action_digest(body.get("action") or {}):
            raise Problem(422, "action_mismatch", "The action differs from the decided one.")
        approval_id = f"apr_{sha256_hex([str(tenant_id), key])[:24]}"
        action = dict(d["action"])
        a = {
            "approval_id": approval_id,
            "status": "pending",
            "action": action,
            "action_digest": d["action_digest"],
            "stages": await effective_stages(conn, tenant_id, action),
        }
        opened = _open_next(a)
        await db.run(
            conn,
            """
            INSERT INTO approval (tenant_id, id, idempotency_key, decision_ref, action, action_digest,
                                  business_reason, status, stages, next_expiry, on_behalf_of)
            VALUES (:t, :i, :k, :d, CAST(:a AS jsonb), :dg, :r, :s, CAST(:st AS jsonb), :n, :obo)""",
            t=tenant_id,
            i=approval_id,
            k=key,
            d=decision_ref,
            a=json.dumps(action, default=str),
            dg=a["action_digest"],
            r=str(body.get("business_reason") or ""),
            s=a["status"],
            st=json.dumps(a["stages"], default=str),
            n=_next_expiry(a),
            obo=on_behalf_of,
        )
        for event_id, event_type, data in opened:
            await events.emit(conn, tenant_id, event_id, event_type, data)
        if a["status"] == "approved":  # every stage skipped by its condition
            await _save(conn, tenant_id, a)
        existing = {"id": approval_id}
    return await get_approval(conn, tenant_id, str(existing["id"]))


async def get_approval(conn: AsyncConnection, tenant_id: uuid.UUID, approval_id: str) -> dict[str, Any]:
    a = await _load(conn, approval_id, lock=True)
    if a is None:  # Trust answers "not found"; callers decide what that means
        raise Problem(404, "approval_not_found", "No such approval.")
    if _expire(a):
        await _save(conn, tenant_id, a)
    return approval_wire(a)


async def _mandate(tenant_id: uuid.UUID, principal: str, action_class: str, amount: Any) -> tuple[str | None, str]:
    """An AI approver's approval grant (its mandate) for this action, from NHIAM."""
    s = get_settings()
    if not s.nhiam_url:
        return None, "nhiam_not_configured"
    headers = {**HEADERS, **({"Authorization": f"Bearer {s.nhiam_token}"} if s.nhiam_token else {})}
    try:
        async with httpx.AsyncClient(timeout=5, headers=headers, transport=nhiam_transport) as client:
            r = await client.post(
                f"{s.nhiam_url.rstrip('/')}/approval-mandates:evaluate",
                json={
                    "tenant_id": str(tenant_id),
                    "principal": principal,
                    "action_class": action_class,
                    "amount": amount,
                },
            )
    except httpx.HTTPError:
        return None, "nhiam_unavailable"
    if r.status_code != 200:
        return None, f"nhiam_refused_{r.status_code}"
    body = r.json()
    return (
        (str(body["mandate_ref"]), "") if body.get("mandate_ref") else (None, str(body.get("reason") or "no_mandate"))
    )


def _eligible(stage: dict[str, Any], decider: dict[str, Any], groups: dict[str, set[str]]) -> list[str]:
    """Approver entries the decider satisfies (hierarchy nominates; membership authorizes)."""
    who, roles = decider.get("principal"), set(decider.get("roles") or [])
    hits = []
    for ap in stage["approvers"]:
        key = f"{ap['type']}:{ap['ref']}"
        if ap["type"] == "user" and ap["ref"] == who:
            hits.append(key)
        elif ap["type"] == "role" and ap["ref"] in roles:
            hits.append(key)
        elif ap["type"] in ("group", "team") and (key in roles or who in groups.get(ap["ref"], set())):
            hits.append(key)
        elif ap["type"] == "ai_agent" and ap["ref"] in (who, decider.get("asset_id")):
            if ap.get("version_id") in (None, decider.get("version_id")):
                hits.append(key)
        elif ap["type"] == "initiator" and ap["ref"] == who:
            hits.append(key)
    return hits


def _satisfied(stage: dict[str, Any], groups: dict[str, set[str]]) -> bool:
    approvals = [d for d in stage["decisions"] if d["decision"] == "approve"]
    counted = [d for d in approvals if d["principal_kind"] == "human" or stage["approver_kind"] != "human_only"]
    humans = [d for d in counted if d["principal_kind"] == "human"]
    if stage["approver_kind"] == "mixed" and not humans:
        return False
    if stage["quorum"] == "any":
        return len(counted) >= 1
    if stage["quorum"] == "n_of_m":
        return len(counted) >= int(stage.get("quorum_n") or 1)
    # all: every listed approver entry is satisfied (a group entry by every known member)
    for ap in stage["approvers"]:
        key = f"{ap['type']}:{ap['ref']}"
        if ap["type"] in ("group", "team") and groups.get(ap["ref"]):
            voters = {d["principal"] for d in counted if key in d["entries"]}
            if not groups[ap["ref"]] <= voters:
                return False
        elif not any(key in d["entries"] for d in counted):
            return False
    return True


async def decide_stage(
    conn: AsyncConnection,
    tenant_id: uuid.UUID,
    approval_id: str,
    stage_id: str,
    decision: str,
    reason: str,
    approver: dict[str, Any],
    approver_run_ref: str | None = None,
) -> dict[str, Any]:
    """Eligibility, separation of duties, quorum and expiry are checked at decision time. An AI approver needs
    an AI-capable stage and a current approval mandate from NHIAM."""
    if decision not in ("approve", "reject", "request_changes"):
        raise Problem(422, "validation_failed", "decision is approve, reject or request_changes.")
    a = await _load(conn, approval_id, lock=True)
    if a is None:
        raise Problem(404, "approval_not_found", "No such approval.")
    expired = _expire(a)
    stage = next((s for s in a["stages"] if s["stage_id"] == stage_id), None)
    if a["status"] == "expired":
        if expired:
            await _save(conn, tenant_id, a)
        raise Problem(410, "approval_expired", "The approval expired.")
    mandate_ref = None
    if a["status"] == "pending":
        who = approver.get("principal")
        kind = "human" if approver.get("principal_kind", "human") == "human" else "ai_agent"
        if stage is None or stage["status"] != "open":
            raise Problem(409, "approval_state_conflict", "stage_not_open")
        confirms = any(ap["type"] == "initiator" and ap["ref"] == who for ap in stage["approvers"])
        if (who == a["action"].get("requester") and not confirms) or who == a["action"].get("acting_agent"):
            # Nobody approves their own — except the person a Genie works for, confirming what it does for them.
            raise Problem(403, "separation_of_duties_violation", "own action")
        sod = stage.get("sod_rules") or {}
        if sod.get("exclude_maker") and who == a["action"].get("maker"):
            raise Problem(403, "separation_of_duties_violation", "maker excluded")
        if sod.get("distinct_from_previous_stages") and any(
            d["principal"] == who for s in a["stages"] if s is not stage for d in s["decisions"]
        ):
            raise Problem(403, "separation_of_duties_violation", "decided an earlier stage")
        if kind == "ai_agent":
            if stage["approver_kind"] == "human_only":
                raise Problem(403, "approver_ineligible", "ai_not_allowed")
            args = a["action"].get("arguments") or {}
            mandate_ref, why = await _mandate(
                tenant_id, str(who), str(a["action"].get("action_class", "")), args.get("amount")
            )
            if mandate_ref is None:
                raise Problem(403, "approver_ineligible", why)
        groups = {
            ap["ref"]: await group_members(conn, ap["ref"])
            for ap in stage["approvers"]
            if ap["type"] in ("group", "team")
        }
        entries = _eligible(stage, approver, groups)
        if not entries:
            raise Problem(403, "approver_ineligible", "not_eligible")
        if any(d["principal"] == who for d in stage["decisions"]):
            raise Problem(403, "approver_ineligible", "duplicate_vote")  # one vote per principal
        stage["decisions"].append(
            {
                "principal": who,
                "principal_kind": kind,
                "version_id": approver.get("version_id"),
                "mandate_ref": mandate_ref,
                "approver_run_ref": approver_run_ref,
                "evidence_refs": approver.get("evidence_refs") or [],
                "decision": decision,
                "reason": reason,
                "entries": entries,
                "at": clock().isoformat(),
            }
        )
        stage["human_votes" if kind == "human" else "ai_votes"] += 1
        opened: list[tuple[str, str, dict[str, Any]]] = []
        if decision == "reject":
            stage["status"] = "rejected"
            a["status"] = "rejected"
        elif decision == "request_changes":
            stage["status"] = "rejected"
            a["status"] = "changes_requested"
        elif _satisfied(stage, groups):
            stage["status"] = "satisfied"
            opened = _open_next(a)
        a["decided_stage"] = stage_id
        await _save(conn, tenant_id, a)
        for event_id, event_type, data in opened:
            await events.emit(conn, tenant_id, event_id, event_type, data)
    elif expired:
        await _save(conn, tenant_id, a)
    return {
        "stage_decision_id": "sdc_" + sha256_hex([approval_id, stage_id, approver.get("principal")])[:16],
        "approval_state": a["status"],
        "mandate_ref": mandate_ref,
        "approval_id": approval_id,
        "status": a["status"],
        "action_digest": a["action_digest"],
        "stage_id": stage_id,
        "stage_state": stage["status"] if stage else None,
    }


async def void_approval(conn: AsyncConnection, tenant_id: uuid.UUID, approval_id: str, reason: str) -> dict[str, Any]:
    a = await _load(conn, approval_id, lock=True)
    if a is None:
        raise Problem(404, "approval_not_found", "No such approval.")
    if a["status"] == "pending":
        a["status"] = "voided"
        a["void_reason"] = reason
        for s in a["stages"]:
            if s["status"] in ("pending", "open", "satisfied"):
                s["status"] = "voided"
        await _save(conn, tenant_id, a)
    return {"approval_id": approval_id, "state": a["status"]}


async def expire_due() -> int:
    """Worker: expire (or escalate) approvals whose open stage is past due, across tenants."""
    done = 0
    async with db.worker_tx() as conn:
        rows = await db.all_(
            conn,
            """
            SELECT tenant_id, id FROM trust.approval
            WHERE status = 'pending' AND next_expiry IS NOT NULL AND next_expiry <= :now ORDER BY next_expiry LIMIT 50""",
            now=clock(),
        )
    for row in rows:  # each in its tenant's transaction, so row security applies to what it changes
        async with db.tenant_tx(row["tenant_id"]) as conn:
            a = await _load(conn, str(row["id"]), lock=True)
            if a and _expire(a):
                await _save(conn, row["tenant_id"], a)
                done += 1
    return done


def owner_confirms(person: str) -> dict[str, Any]:
    """The stage a Genie's action waits on: the person it acts for confirms it, in the conversation."""
    return {
        "stage_key": "owner-confirms",
        "ordinal": 1,
        "approver_kind": "human_only",
        "quorum": "any",
        "approvers": [{"type": "initiator", "ref": person}],
    }
