"""Approvals (AC17, NX-APR-001…007): stages in ordinal order, quorum any/all/n_of_m, conditions from the actual
arguments, one vote per principal, separation of duties, expiry with one escalation, voids, the tenant floor,
and the signed events Nexus waits on."""

import uuid
from datetime import UTC, datetime, timedelta

from quetrust import service
from tests.conftest import Tenant

TWO_STAGES = {
    "id": "spend",
    "name": "Spend",
    "stages": [
        {"stage_key": "finance", "ordinal": 1, "quorum": "any", "approvers": [{"type": "role", "ref": "finance"}]},
        {
            "stage_key": "ops",
            "ordinal": 2,
            "quorum": "n_of_m",
            "quorum_n": 2,
            "approvers": [{"type": "group", "ref": "ops"}],
        },
    ],
}


def _stage(a: dict[str, object], key: str) -> dict[str, object]:
    return next(s for s in a["stages"] if s["stage_id"] == key)  # type: ignore[index, union-attr, attr-defined]


async def test_two_stages_complete_in_order_and_wake_nexus(t: Tenant) -> None:
    await t.policies(TWO_STAGES)
    for member in ("ops-1", "ops-2", "ops-3"):
        await t.req("PUT", f"/groups/ops/members/{member}", t.admin, expect=200)
    body = t.body(args={"amount": 500})
    a = await t.approval(body)
    assert a["state"] == "pending"
    assert (_stage(a, "finance")["status"], _stage(a, "ops")["status"]) == ("open", "pending")

    early = await t.vote(a, "ops", t.person("ops-1"))
    assert early.status_code == 409 and early.json()["code"] == "approval_state_conflict"  # stage 2 isn't open yet
    assert (await t.vote(a, "finance", t.person("fin-1", "finance"))).status_code == 201
    assert (await t.vote(a, "ops", t.person("ops-1"))).json()["approval_state"] == "pending"
    dup = await t.vote(a, "ops", t.person("ops-1"))
    assert dup.status_code == 403 and dup.json()["detail"] == "duplicate_vote"
    outsider = await t.vote(a, "ops", t.person("eve", "employee"))
    assert outsider.status_code == 403 and outsider.json()["code"] == "approver_ineligible"
    done = (await t.vote(a, "ops", t.person("ops-2"))).json()
    assert done["approval_state"] == "approved"

    decided = [e for e in await t.outbox() if e["type"] == "que.trust.approval.decided.v2"]
    assert [(e["target"], e["data"]["status"], e["data"]["approval_id"]) for e in decided] == [
        ("nexus", "approved", a["approval_id"])
    ]
    assert decided[0]["data"]["action_digest"] == a["action_digest"]

    # Re-validation: allowed with a token for exactly this action; changed arguments are not covered.
    again = await t.decide(t.body(args={"amount": 500}, approval_ref=a["approval_id"]))
    assert again["decision"] == "allow" and again["decision_token"]
    changed = await t.decide(t.body(args={"amount": 900}, approval_ref=a["approval_id"]))
    assert (changed["decision"], changed["reasons"]) == ("deny", ["approval_invalid"])


async def test_quorum_all_needs_every_listed_approver(t: Tenant) -> None:
    policy = {
        "id": "both",
        "name": "Both",
        "stages": [
            {
                "stage_key": "both",
                "quorum": "all",
                "approvers": [{"type": "user", "ref": "ann"}, {"type": "role", "ref": "legal"}],
            }
        ],
    }
    await t.policies(policy)
    a = await t.approval(t.body())
    assert (await t.vote(a, "both", t.person("ann", "employee"))).json()["approval_state"] == "pending"
    assert (await t.vote(a, "both", t.person("lee", "legal"))).json()["approval_state"] == "approved"


async def test_conditions_and_the_tenant_floor(t: Tenant) -> None:
    policy = {
        "id": "cond",
        "name": "Conditional",
        "stages": [
            {"stage_key": "anyone", "ordinal": 1, "approvers": [{"type": "role", "ref": "approver"}]},
            {
                "stage_key": "cfo",
                "ordinal": 2,
                "approvers": [{"type": "user", "ref": "cfo"}],
                "condition": {"field": "amount", "operation": "larger", "value": 1000},
            },
        ],
    }
    await t.policies(policy)
    small = await t.approval(t.body(args={"amount": 20}))
    assert _stage(small, "cfo")["status"] == "skipped"  # computed from the actual arguments
    rules = {
        "rules": [
            {
                "name": "Board sees big ones",
                "when": [{"field": "action.argument", "argument": "amount", "op": "gte", "value": 5000}],
                "then": {"kind": "add_stage", "stage_key": "board", "approvers": [{"type": "group", "ref": "board"}]},
            }
        ]
    }
    await t.req("PUT", "/rules", t.admin, rules, expect=200)
    big = await t.approval(t.body(args={"amount": 9000}))
    assert [(s["stage_id"], s["status"], s["source"]) for s in big["stages"]] == [
        ("anyone", "open", "policy"),
        ("cfo", "pending", "policy"),
        ("board", "pending", "tenant_floor"),
    ]


async def test_separation_of_duties(t: Tenant) -> None:
    policy = {
        "id": "sod",
        "name": "SoD",
        "stages": [
            {"stage_key": "one", "ordinal": 1, "approvers": [{"type": "role", "ref": "approver"}]},
            {
                "stage_key": "two",
                "ordinal": 2,
                "approvers": [{"type": "role", "ref": "approver"}],
                "sod_rules": {"distinct_from_previous_stages": True},
            },
        ],
    }
    await t.policies(policy)
    a = await t.approval(t.body(requester="req-1"))
    own = await t.vote(a, "one", t.person("req-1", "approver"))
    assert own.status_code == 403 and own.json()["code"] == "separation_of_duties_violation"
    await t.vote(a, "one", t.person("amy", "approver"))
    again = await t.vote(a, "two", t.person("amy", "approver"))
    assert again.status_code == 403 and again.json()["detail"] == "decided an earlier stage"
    assert (await t.vote(a, "two", t.person("bob", "approver"))).json()["approval_state"] == "approved"


async def test_reject_and_request_changes_end_the_approval(t: Tenant) -> None:
    a = await t.approval(t.body())
    r = (await t.vote(a, "default", t.person("amy", "approver"), "reject")).json()
    assert (r["approval_state"], r["stage_state"]) == ("rejected", "rejected")
    b = await t.approval(t.body(args={"x": 1}))
    assert (await t.vote(b, "default", t.person("amy", "approver"), "request_changes")).json()["approval_state"] == (
        "changes_requested"
    )
    statuses = {e["data"]["status"] for e in await t.outbox() if e["type"].endswith("approval.decided.v2")}
    assert statuses == {"rejected", "changes_requested"}


async def test_expiry_escalates_once_then_expires(t: Tenant) -> None:
    policy = {
        "id": "timed",
        "name": "Timed",
        "stages": [
            {
                "stage_key": "lead",
                "approvers": [{"type": "user", "ref": "lead"}],
                "expires_after_seconds": 60,
                "escalation": {"approvers": [{"type": "user", "ref": "boss"}], "after_seconds": 60},
            }
        ],
    }
    await t.policies(policy)
    a = await t.approval(t.body())
    start = datetime.now(UTC)
    service.clock = lambda: start + timedelta(seconds=90)
    escalated = (await t.req("GET", f"/approvals/{a['approval_id']}", t.nexus, expect=200)).json()
    assert escalated["state"] == "pending" and _stage(escalated, "lead")["escalated"] is True
    service.clock = lambda: start + timedelta(seconds=200)
    assert await service.expire_due() >= 1  # the worker expires it without anyone asking
    expired = (await t.req("GET", f"/approvals/{a['approval_id']}", t.nexus, expect=200)).json()
    assert expired["state"] == "expired"
    late = await t.vote(a, "lead", t.person("boss"))
    assert late.status_code == 410 and late.json()["code"] == "approval_expired"
    assert any(e["data"].get("status") == "expired" for e in await t.outbox())


async def test_voiding_voids_every_stage(t: Tenant) -> None:
    await t.policies(TWO_STAGES)
    a = await t.approval(t.body())
    r = await t.req(
        "POST", f"/approvals/{a['approval_id']}/voids", t.nexus, {"reason": "arguments changed"}, expect=200
    )
    assert r.json() == {"approval_id": a["approval_id"], "state": "voided"}
    after = (await t.req("GET", f"/approvals/{a['approval_id']}", t.nexus, expect=200)).json()
    assert {s["status"] for s in after["stages"]} == {"voided"}


async def test_approval_requests_are_idempotent_and_bound_to_the_decision(t: Tenant) -> None:
    body = t.body(args={"amount": 3})
    d = await t.decide(body)
    req = {"decision_ref": d["decision_id"], "action": body["action"], "business_reason": "why"}
    one = (await t.req("POST", "/approvals", t.nexus, req, key="k-1", expect=201)).json()
    two = (await t.req("POST", "/approvals", t.nexus, req, key="k-1", expect=201)).json()
    assert one["approval_id"] == two["approval_id"]
    other = {**req, "action": {**body["action"], "args": {"amount": 4}}}
    assert (await t.req("POST", "/approvals", t.nexus, other, key="k-2")).json()["code"] == "action_mismatch"
    allow = await t.decide(t.body("refund.lookup", effect="read"))
    stale = {**req, "decision_ref": allow["decision_id"]}
    assert (await t.req("POST", "/approvals", t.nexus, stale, key="k-3")).status_code == 409


async def test_tenants_never_see_each_other(t: Tenant, client: object) -> None:
    a = await t.approval(t.body())
    other = Tenant(t.c)
    r = await other.req("GET", f"/approvals/{a['approval_id']}", other.nexus)
    assert r.status_code == 404  # row security: another tenant's approval doesn't exist for them
    assert (await other.req("GET", "/approvals", other.admin, expect=200)).json()["items"] == []
    mine = (await t.req("GET", "/approvals", t.admin, expect=200)).json()["items"]
    assert [x["approval_id"] for x in mine] == [a["approval_id"]]
    assert uuid.UUID(str(other.id)) != t.id


async def test_a_genies_action_is_confirmed_by_the_person_it_works_for(t: Tenant) -> None:
    """With no policy covering it, a Genie's action waits on its owner — the person it acts for — not a role:
    they confirm it in the conversation. Nobody else can, and a Marid's action still goes to the approver role."""
    a = await t.approval({**t.body(requester="uma"), "agent_type": "genie"})
    [stage] = a["stages"]
    assert stage["stage_id"] == "owner-confirms" and stage["approvers"] == [{"type": "initiator", "ref": "uma"}]
    other = await t.vote(a, "owner-confirms", t.person("bob", "approver"))
    assert other.status_code == 403 and other.json()["code"] == "approver_ineligible"
    done = await t.vote(a, "owner-confirms", t.person("uma", "employee"))
    assert done.status_code == 201 and done.json()["approval_state"] == "approved"

    marid = await t.approval({**t.body(requester="uma"), "agent_type": "marid"})
    assert marid["stages"][0]["approvers"] == [{"type": "role", "ref": "approver"}]
    own = await t.vote(marid, marid["stages"][0]["stage_id"], t.person("uma", "approver"))
    assert own.status_code == 403 and own.json()["code"] == "separation_of_duties_violation"
