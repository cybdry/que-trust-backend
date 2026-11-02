"""DEC-198: feature flags (every feature of Que Connect and AMPHI Que is on unless a Trust admin switches it off),
resource policies defaulting to everyone in the tenant, and the person behind a service's call
(`Que-Subject-Token`, verified, recorded as on_behalf_of)."""

import uuid

from tests.conftest import Tenant, auth, qct, token

CONNECT = {"knowledge", "tools", "models", "skills", "remote_agents"}
AMPHI = {"registry", "releases", "deployments", "budgets"}


async def test_every_feature_is_on_by_default(t: Tenant) -> None:
    items = (await t.req("GET", "/feature-flags", t.nexus, expect=200)).json()["items"]
    assert {(i["product"], i["feature"]) for i in items} == {("que-connect", f) for f in CONNECT} | {
        ("que-amphi", f) for f in AMPHI
    }
    assert all(i["enabled"] and i["version"] == 0 and i["updated_by"] is None and i["label"] for i in items)
    connect = (await t.req("GET", "/feature-flags?product=que-connect", t.admin, expect=200)).json()["items"]
    assert {i["feature"] for i in connect} == CONNECT
    await t.req("GET", "/feature-flags?product=que-unknown", t.admin, expect=404)


async def test_admins_switch_features_and_the_product_is_told(t: Tenant) -> None:
    off = (await t.req("PUT", "/feature-flags/que-connect/models", t.admin, {"enabled": False}, expect=200)).json()
    assert (off["enabled"], off["version"], off["updated_by"]) == (False, 1, "ada")
    on = (await t.req("PUT", "/feature-flags/que-connect/models", t.admin, {"enabled": True}, expect=200)).json()
    assert (on["enabled"], on["version"]) == (True, 2)
    await t.req("PUT", "/feature-flags/que-amphi/budgets", t.admin, {"enabled": False}, expect=200)

    flags = [(e["target"], e["data"]) for e in await t.outbox() if e["type"] == "que.trust.feature_flag.changed.v2"]
    assert flags == [
        ("connect", {"product": "que-connect", "feature": "models", "enabled": False, "version": 1}),
        ("connect", {"product": "que-connect", "feature": "models", "enabled": True, "version": 2}),
        ("amphi", {"product": "que-amphi", "feature": "budgets", "enabled": False, "version": 1}),
    ]
    seen = {i["feature"]: i["enabled"] for i in (await t.req("GET", "/feature-flags", t.nexus)).json()["items"]}
    assert seen["budgets"] is False and seen["models"] is True
    assert (await t.req("GET", "/overview", t.admin, expect=200)).json()["features_off"] == 1


async def test_only_trust_admins_change_flags(t: Tenant) -> None:
    await t.req("PUT", "/feature-flags/que-connect/tools", t.nexus, {"enabled": False}, expect=403)
    await t.req("PUT", "/feature-flags/que-connect/tools", t.person("amy", "approver"), {"enabled": False}, expect=403)
    await t.req(
        "PUT", "/feature-flags/que-connect/tools", t.person("tia", "trust_admin"), {"enabled": False}, expect=200
    )
    await t.req("PUT", "/feature-flags/que-connect/unknown", t.admin, {"enabled": False}, expect=404)
    await t.req("PUT", "/feature-flags/que-unknown/tools", t.admin, {"enabled": False}, expect=404)
    await t.req("PUT", "/feature-flags/que-connect/tools", t.admin, {"enabled": "maybe"}, expect=422)
    # Readers: services and Trust roles; someone without one doesn't.
    await t.req("GET", "/feature-flags", t.person("amy", "approver"), expect=200)
    await t.req("GET", "/feature-flags", t.viewer, expect=403)


async def test_a_tenants_flags_are_its_own(t: Tenant, client: object) -> None:
    other = Tenant(t.c)
    await t.req("PUT", "/feature-flags/que-connect/skills", t.admin, {"enabled": False}, expect=200)
    mine = {i["feature"]: i["enabled"] for i in (await t.req("GET", "/feature-flags", t.nexus)).json()["items"]}
    theirs = {
        i["feature"]: i["enabled"] for i in (await other.req("GET", "/feature-flags", other.nexus)).json()["items"]
    }
    assert mine["skills"] is False and theirs["skills"] is True


async def test_resources_without_a_policy_are_open_to_the_tenant(t: Tenant) -> None:
    listing = (await t.req("GET", "/resource-policies?product=que-connect", t.admin, expect=200)).json()
    assert listing["items"] == [] and listing["default"]["type"] == "everyone"


async def test_a_service_calls_for_a_verified_person(t: Tenant) -> None:
    person = qct(t.id, "user-77", licensed=("nexus",))
    body = t.body("report.read", effect="read")
    r = await t.req("POST", "/decisions", {**t.nexus, "Que-Subject-Token": person}, body, expect=200)
    decided = r.json()["decision_id"]
    log = (await t.req("GET", "/decisions", t.admin, expect=200)).json()["items"]
    assert next(d for d in log if d["decision_id"] == decided)["on_behalf_of"] == "user-77"

    # An approval asked for a person records them too.
    write = t.body()
    d = (await t.req("POST", "/decisions", {**t.nexus, "Que-Subject-Token": person}, write, expect=200)).json()
    await t.req(
        "POST",
        "/approvals",
        {**t.nexus, "Que-Subject-Token": person},
        {"decision_ref": d["decision_id"], "action": write["action"]},
        key="obo-1",
        expect=201,
    )
    approvals = (await t.req("GET", "/approvals", t.admin, expect=200)).json()["items"]
    assert approvals[0]["on_behalf_of"] == "user-77"

    # No header: unchanged.
    plain = (await t.req("POST", "/decisions", t.nexus, body, expect=200)).json()["decision_id"]
    log = (await t.req("GET", "/decisions", t.admin)).json()["items"]
    assert next(x for x in log if x["decision_id"] == plain)["on_behalf_of"] is None


async def test_a_bad_subject_token_is_refused(t: Tenant) -> None:
    body = t.body("report.read", effect="read")
    other_tenant = qct(uuid.uuid4(), "user-77")
    workload = token(t.id, "wl:agent-1", workload=True)
    for bad in ("not-a-token", other_tenant, workload):
        r = await t.req("POST", "/decisions", {**t.nexus, "Que-Subject-Token": bad}, body)
        assert r.status_code == 401 and r.json()["code"] == "subject_token_invalid", r.text
    # A person's own call ignores the header: the bearer is already the person.
    me = (await t.req("GET", "/me", {**auth(qct(t.id, "user-77")), "Que-Subject-Token": "junk"}, expect=200)).json()
    assert me["subject"] == "user-77"
