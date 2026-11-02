"""The Trust console's API: who may read and change policy, people signed in through Que.IS (QCT), rules drafts,
approval policies guarded by revision, groups, the decisions log, and resource policies for Connect."""

import uuid

from tests.conftest import Tenant, auth, qct


async def test_people_signed_in_through_que_is(t: Tenant) -> None:
    owner = auth(qct(t.id, "olga", permissions=("*",)))
    me = (await t.req("GET", "/me", owner, expect=200)).json()
    assert me["tenant_id"] == str(t.id) and me["can_admin"] is True
    assert {"tenant_admin", "trust_admin", "approver", "finance_lead"} <= set(me["roles"])  # Que.IS roles kept
    builder = (await t.req("GET", "/me", auth(qct(t.id, "bo", permissions=("nexus.asset.create",))), expect=200)).json()
    assert builder["can_admin"] is True
    licensed = (await t.req("GET", "/me", auth(qct(t.id, "lu", licensed=("nexus",))), expect=200)).json()
    assert (licensed["can_admin"], "approver" in licensed["roles"]) == (False, True)
    # Que.IS's system admin role has no nexus.* or trust.* permission, yet administers as the owner does (DEC-218).
    admin = auth(qct(t.id, "ada", permissions=("users.*", "roles.*", "workspace.*"), roles=("admin",)))
    assert (await t.req("GET", "/me", admin, expect=200)).json()["can_admin"] is True
    nobody = auth(qct(t.id, "no"))
    assert (await t.req("GET", "/overview", nobody)).status_code == 403
    forged = qct(t.id, "x", permissions=("*",))[:-4] + "AAAA"
    assert (await t.req("GET", "/me", auth(forged))).status_code == 401


async def test_reading_and_changing_policy(t: Tenant) -> None:
    approver = t.person("amy", "approver")
    assert (await t.req("GET", "/overview", approver, expect=200)).json()["decisions_24h"] == {
        "allow": 0,
        "deny": 0,
        "approval_required": 0,
    }
    assert (await t.req("GET", "/overview", t.viewer)).status_code == 403
    rules = {"rules": [{"name": "x", "when": [], "then": {"kind": "obligation", "obligation": "log"}}]}
    assert (await t.req("PUT", "/rules", approver, rules)).status_code == 403
    assert (await t.req("PUT", "/rules", t.admin, rules, expect=200)).json()["rules"]["rules"][0]["name"] == "x"
    assert (await t.req("GET", "/rules", approver, expect=200)).json()["catalog"]["fields"]
    cleared = (await t.req("DELETE", "/rules", t.admin, expect=200)).json()
    assert cleared["rego"] is None


async def test_rules_drafts_are_tried_without_saving(t: Tenant) -> None:
    draft = {
        "rules": [
            {
                "id": "night",
                "name": "Night",
                "when": [{"field": "action.action_class", "op": "equals", "value": "refund.create"}],
                "then": {"kind": "deny", "reason": "not tonight"},
            }
        ]
    }
    preview = (await t.req("POST", "/rules:preview", t.admin, {"rules": draft}, expect=200)).json()
    assert f"package tenants.t_{t.id.hex}" in preview["rego"]
    flat = (await t.req("POST", "/rules:preview", t.admin, draft, expect=200)).json()
    assert flat == preview
    sample = {"action_class": "refund.create", "effect": "read", "arguments": {}}
    tried = (await t.req("POST", "/rules:try", t.admin, {"sample": sample, "rules": draft}, expect=200)).json()
    assert tried["result"]["decision"] == "deny" and tried["result"]["reasons"] == ["not tonight"]
    saved = (await t.req("POST", "/rules:try", t.admin, {"sample": sample}, expect=200)).json()
    assert saved["result"]["decision"] == "allow"  # the draft was never saved
    bad = await t.req("PUT", "/rules/rego", t.admin, {"rego": "package other\nallow := true"})
    assert bad.status_code == 422 and bad.json()["errors"][0]["code"] == "tenant_policy_rejected"
    sneaky = f"package tenants.t_{t.id.hex}\ndeny contains x if {{ x := data.secrets }}"
    assert (
        "other documents"
        in (await t.req("PUT", "/rules/rego", t.admin, {"rego": sneaky})).json()["errors"][0]["message"]
    )


async def test_approval_config_is_guarded_by_its_revision(t: Tenant) -> None:
    empty = (await t.req("GET", "/approval-config", t.admin, expect=200)).json()
    assert empty == {"policies": [], "assignments": [], "revision": 0}
    config = {
        "policies": [
            {"id": "p", "name": "P", "stages": [{"stage_key": "s", "approvers": [{"type": "role", "ref": "r"}]}]}
        ],
        "assignments": [{"id": "1", "policy_id": "p"}],
    }
    first = await t.c.put("/api/v2/approval-config", json=config, headers={**t.admin, "If-Match": "0"})
    assert first.json()["revision"] == 1
    stale = await t.c.put("/api/v2/approval-config", json=config, headers={**t.admin, "If-Match": "0"})
    assert stale.status_code == 412
    invalid = {**config, "assignments": [{"id": "1", "policy_id": "missing"}]}
    assert (await t.req("PUT", "/approval-config", t.admin, invalid)).status_code == 422
    sim = (await t.req("POST", "/approval-config:simulate", t.admin, {"action_class": "x"}, expect=200)).json()
    assert sim["policy"]["id"] == "p" and [s["stage_id"] for s in sim["stages"]] == ["s"]


async def test_groups_and_the_decisions_log(t: Tenant) -> None:
    await t.req("PUT", "/groups/ops/members/ann", t.admin, expect=200)
    both = (await t.req("PUT", "/groups/ops/members/bob", t.admin, expect=200)).json()
    assert both == {"groups": {"ops": ["ann", "bob"]}}
    gone = (await t.req("DELETE", "/groups/ops/members/ann", t.admin, expect=200)).json()
    assert gone == {"groups": {"ops": ["bob"]}}
    await t.decide(t.body("refund.lookup", effect="read"))
    await t.decide(t.body())
    log = (await t.req("GET", "/decisions", t.admin, expect=200)).json()["items"]
    assert [d["decision"] for d in log] == ["approval_required", "allow"]
    assert log[0]["input"]["tenant"] == str(t.id)
    only = (await t.req("GET", "/decisions?outcome=allow", t.admin, expect=200)).json()["items"]
    assert [d["decision"] for d in only] == ["allow"]
    platform = (await t.req("GET", "/platform-policy", t.admin, expect=200)).json()
    assert platform["package"] == "que.trust" and "package que.trust" in platform["rego"]


async def test_resource_policies_reach_connect(t: Tenant) -> None:
    rules = {
        "rules": [{"type": "role", "ref": "nurse", "access": "use"}],
        "tool_rules": [{"tools": ["t1"], "rules": []}],
    }
    put = (await t.req("PUT", "/resource-policies/que-connect/mcp_server/srv-1", t.admin, rules, expect=200)).json()
    assert (put["version"], put["kind"], put["tool_rules"][0]["tools"]) == (1, "mcp_server", ["t1"])
    again = (await t.req("PUT", "/resource-policies/que-connect/mcp_server/srv-1", t.nexus, rules, expect=200)).json()
    assert again["version"] == 2 and again["policy_id"] == put["policy_id"]
    assert (await t.req("PUT", "/resource-policies/que-connect/mcp_server/srv-1", t.viewer, rules)).status_code == 403
    assert (await t.req("PUT", "/resource-policies/que-connect/nope/x", t.admin, rules)).status_code == 422
    listed = (await t.req("GET", "/resource-policies", t.admin, expect=200)).json()["items"]
    assert [p["ref"] for p in listed] == ["srv-1"]
    removed = (await t.req("DELETE", "/resource-policies/que-connect/mcp_server/srv-1", t.admin, expect=200)).json()
    assert (removed["rules"], removed["version"]) == (None, 3)
    assert (await t.req("GET", "/resource-policies", t.admin, expect=200)).json()["items"] == []
    events = [e for e in await t.outbox() if e["type"] == "que.trust.resource_policy.changed.v2"]
    assert [(e["target"], e["data"]["version"]) for e in events] == [("connect", 1), ("connect", 2), ("connect", 3)]
    assert (await t.req("DELETE", "/resource-policies/que-connect/mcp_server/srv-1", t.admin)).status_code == 404


async def test_another_tenant_sees_nothing(t: Tenant) -> None:
    await t.req("PUT", "/groups/ops/members/ann", t.admin, expect=200)
    other = Tenant(t.c)
    assert (await other.req("GET", "/groups", other.admin, expect=200)).json() == {"groups": {}}
    assert uuid.UUID(str(other.id)) != t.id
