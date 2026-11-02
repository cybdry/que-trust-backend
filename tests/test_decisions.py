"""Decisions on OPA (DEC-144): the platform policy, tenant rules that only strengthen, agent profiles, and the
signed decision token a relying owner verifies offline."""

import uuid
from typing import Any

import httpx
import jwt

from tests.conftest import Tenant, digest_of


async def _verify(c: httpx.AsyncClient, token: str, audience: str = "que-connect") -> dict[str, Any]:
    keys = (await c.get("/.well-known/jwks.json")).json()
    assert (await c.get("/api/v2/.well-known/jwks.json")).json() == keys
    header = jwt.get_unverified_header(token)
    assert header["typ"] == "que-trust-decision+jwt"
    key = next(k.key for k in jwt.PyJWKSet.from_dict(keys).keys if k.key_id == header["kid"])
    return dict(jwt.decode(token, key, algorithms=["RS256"], audience=audience, issuer="https://dev.que.local/trust"))


async def test_reads_are_allowed_and_hitl_writes_need_approval(t: Tenant) -> None:
    read = await t.decide(t.body("refund.lookup", effect="read"))
    assert read["decision"] == "allow" and read["decision_token"]
    write = await t.decide(t.body("refund.create", {"amount": 10}))
    assert write["decision"] == "approval_required" and write["decision_token"] is None
    assert [s["stage_id"] for s in write["stages"]] == ["default"]  # nothing assigned: Trust's built-in stage
    assert write["policy_ref"].startswith("opa:que.trust@")


async def test_the_decision_token_binds_exactly_this_action(t: Tenant) -> None:
    body = t.body("refund.lookup", {"id": 7}, effect="read")
    d = await t.decide(body)
    claims = await _verify(t.c, d["decision_token"])
    assert claims["tid"] == str(t.id) and claims["decision"] == "allow" and claims["jti"] == d["decision_id"]
    assert claims["action_digest"] == digest_of(body["action"])  # what Connect recomputes from what it dispatches
    workspace = await t.decide({**body, "audience": "que-workspace"})
    assert (await _verify(t.c, workspace["decision_token"], "que-workspace"))["aud"] == "que-workspace"


async def test_hotl_writes_proceed_with_oversight_and_hootl_is_refused(t: Tenant) -> None:
    await t.policies(
        {"id": "ops", "name": "Ops", "stages": [{"stage_key": "ops", "approvers": [{"type": "role", "ref": "ops"}]}]}
    )
    hotl = await t.decide(t.body(mode="hotl"))
    assert hotl["decision"] == "allow"
    assert hotl["obligations"] == [
        {"kind": "oversight", "overseers": [{"type": "role", "ref": "ops"}], "review_window_seconds": 900}
    ]
    hootl = await t.decide(t.body(mode="hootl"))
    assert hootl == {**hootl, "decision": "deny", "reasons": ["hootl_not_available"]}


async def test_tenant_rules_only_strengthen(t: Tenant) -> None:
    rules = {
        "rules": [
            {
                "name": "Big refunds",
                "when": [
                    {"field": "action.action_class", "op": "starts_with", "value": "refund."},
                    {"field": "action.argument", "argument": "amount", "op": "gt", "value": 100},
                ],
                "then": {"kind": "require_approval", "reason": "refunds over 100"},
            },
            {
                "name": "No deletes",
                "when": [{"field": "action.action_class", "op": "equals", "value": "account.delete"}],
                "then": {"kind": "deny", "reason": "accounts are never deleted by agents"},
            },
        ]
    }
    saved = (await t.req("PUT", "/rules", t.admin, rules, expect=200)).json()
    assert saved["digest"] and "refunds over 100" in saved["rego"]
    big = await t.decide(t.body(mode="not_applicable", args={"amount": "250"}))
    assert (big["decision"], big["reasons"]) == (
        "approval_required",
        ["refunds over 100"],
    )  # not_applicable can't skip it
    small = await t.decide(t.body(mode="not_applicable", args={"amount": 50}))
    assert small["decision"] == "allow" and "+tenants.t_" in small["policy_ref"]
    denied = await t.decide(t.body("account.delete", effect="read"))
    assert (denied["decision"], denied["reasons"]) == ("deny", ["accounts are never deleted by agents"])


async def test_a_released_agent_acts_only_through_its_profile(t: Tenant) -> None:
    version, asset = str(uuid.uuid4()), str(uuid.uuid4())
    profile = {
        "asset_id": asset,
        "name": "Billing agent",
        "tools": [{"tool_ref": "billing.refund.create", "action_classes": ["refund.create"], "effect": "write"}],
        "data_sources": [{"kind": "knowledge", "ref": "kb-secret", "name": "Payroll", "classification": "restricted"}],
    }
    body = {"version_ref": {"owner_product": "nexus", "resource_kind": "asset_version", "resource_key": version}}
    r = await t.req(
        "POST", "/agent-profiles", t.nexus, {**body, "manifest_digest": "abc123def4567", "profile": profile}
    )
    assert r.status_code == 201 and r.json()["profile_id"] == f"agent-profile:{version}:abc123def456"
    other = await t.decide(t.body("mail.send", tool="mail.send", effect="read", version=version, asset=asset))
    assert other["reasons"] == ["tool_not_in_agent_profile"]
    model = t.body(
        "model.invoke", {"model_max_classification": "internal"}, tool="model.chat", effect="read", version=version
    )
    egress = await t.decide({**model, "data_used": [{"kind": "knowledge", "ref": "kb-secret"}]})
    assert egress["reasons"] == ["data_class_exceeds_model"]  # Trust knows the data's class from the profile
    listed = (await t.req("GET", "/agent-profiles", t.admin, expect=200)).json()["items"]
    assert listed[0]["name"] == "Billing agent" and listed[0]["version_id"] == version


async def test_owner_routes_are_for_services(t: Tenant) -> None:
    r = await t.req("POST", "/decisions", t.admin, t.body())
    assert r.status_code == 403 and r.json()["code"] == "permission_denied"
    assert (await t.c.post("/api/v2/decisions", json=t.body())).status_code == 401


async def test_simulation_and_policy_resolution(t: Tenant) -> None:
    await t.policies(
        {
            "id": "finance",
            "name": "Finance",
            "stages": [{"stage_key": "finance", "approvers": [{"type": "role", "ref": "finance"}]}],
        },
        assignments=[{"id": "1", "action": "refund.*", "policy_id": "finance"}],
    )
    sim = (await t.req("POST", "/decisions:simulate", t.nexus, t.body(), expect=200)).json()
    assert [s["stage_id"] for s in sim["stages"]] == ["finance"]
    found = (await t.req("GET", "/approval-policies:resolve?action_class=refund.create", t.nexus, expect=200)).json()
    assert found["policy"]["id"] == "finance"
    none = (await t.req("GET", "/approval-policies:resolve?action_class=invoice.send", t.nexus, expect=200)).json()
    assert none["policy"] is None


async def test_evidence_packages_are_kept(t: Tenant) -> None:
    pkg = {"manifest_digest": "m1", "items": [{"kind": "run", "ref": "r1"}]}
    first = (await t.req("POST", "/evidence-packages", t.nexus, pkg, expect=202)).json()
    again = (await t.req("POST", "/evidence-packages", t.nexus, pkg, expect=202)).json()
    assert first == again  # the same package is one record
    listed = (await t.req("GET", "/evidence-packages", t.admin, expect=200)).json()["items"]
    assert [(e["ref"], e["items"]) for e in listed] == [(first["evidence_id"], 1)]
