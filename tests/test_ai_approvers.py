"""AI approvers (02 §5.8): only on ai_allowed/mixed stages, with their own NHIAM credential and a current approval
mandate from NHIAM; never counted in a human quorum; a mixed stage still needs a person."""

import json
import uuid

import httpx

from quetrust import service
from tests.conftest import Tenant, auth, token


def _nhiam(mandated: set[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2/approval-mandates:evaluate"
        body = json.loads(request.content)
        if body["principal"] in mandated and body["action_class"] == "refund.create":
            return httpx.Response(200, json={"mandate_ref": f"mandate:{body['principal']}"})
        return httpx.Response(200, json={"mandate_ref": None, "reason": "no_mandate"})

    return httpx.MockTransport(handler)


def _ai(t: Tenant, subject: str, asset: str) -> dict[str, str]:
    return auth(token(t.id, subject, workload=True, claims={"attestation": {"resource_ref": asset}}))


def _policy(kind: str, asset: str, version: str) -> dict[str, object]:
    approvers: list[dict[str, str]] = [{"type": "ai_agent", "ref": asset, "version_id": version}]
    if kind == "mixed":
        approvers.append({"type": "role", "ref": "finance"})
    return {
        "id": kind.replace("_", "-"),
        "name": kind,
        "stages": [{"stage_key": "review", "approver_kind": kind, "quorum": "any", "approvers": approvers}],
    }


async def test_an_ai_approver_with_a_mandate_decides_an_ai_allowed_stage(t: Tenant) -> None:
    asset, version = str(uuid.uuid4()), str(uuid.uuid4())
    await t.policies(_policy("ai_allowed", asset, version))
    service.nhiam_transport = _nhiam({"wl:reviewer"})
    a = await t.approval(t.body(args={"amount": 80}))
    opened = [e for e in await t.outbox() if e["type"] == "que.trust.approval.stage_opened.v2"]
    assert [e["data"]["ai_approvers"][0]["ref"] for e in opened] == [asset]  # Nexus starts the approver's run

    version_ref = {"owner_product": "nexus", "resource_kind": "asset_version", "resource_key": version}
    r = await t.vote(
        a, "review", _ai(t, "wl:reviewer", asset), approver_version_ref=version_ref, approver_run_ref="run-9"
    )
    assert r.status_code == 201, r.text
    assert (r.json()["approval_state"], r.json()["mandate_ref"]) == ("approved", "mandate:wl:reviewer")


async def test_ai_approvers_are_refused_without_mandate_or_on_human_stages(t: Tenant) -> None:
    asset, version = str(uuid.uuid4()), str(uuid.uuid4())
    version_ref = {"owner_product": "nexus", "resource_kind": "asset_version", "resource_key": version}
    service.nhiam_transport = _nhiam(set())
    await t.policies(_policy("ai_allowed", asset, version))
    a = await t.approval(t.body())
    r = await t.vote(a, "review", _ai(t, "wl:reviewer", asset), approver_version_ref=version_ref)
    assert (r.status_code, r.json()["code"], r.json()["detail"]) == (403, "approver_ineligible", "no_mandate")

    b = await t.approval(t.body(args={"other": 1}), key="k-human")  # (the default policy is human-only)
    await t.policies(
        {"id": "h", "name": "h", "stages": [{"stage_key": "review", "approvers": [{"type": "role", "ref": "x"}]}]}
    )
    c = await t.approval(t.body(args={"third": 1}))
    r = await t.vote(c, "review", _ai(t, "wl:reviewer", asset), approver_version_ref=version_ref)
    assert r.json()["detail"] == "ai_not_allowed"
    assert b["state"] == "pending"


async def test_a_mixed_stage_needs_a_person_too(t: Tenant) -> None:
    asset, version = str(uuid.uuid4()), str(uuid.uuid4())
    version_ref = {"owner_product": "nexus", "resource_kind": "asset_version", "resource_key": version}
    service.nhiam_transport = _nhiam({"wl:reviewer"})
    await t.policies(_policy("mixed", asset, version))
    a = await t.approval(t.body())
    ai = (await t.vote(a, "review", _ai(t, "wl:reviewer", asset), approver_version_ref=version_ref)).json()
    assert ai["approval_state"] == "pending"  # an AI vote alone doesn't satisfy a mixed stage
    human = (await t.vote(a, "review", t.person("fay", "finance"))).json()
    assert human["approval_state"] == "approved"


async def test_services_do_not_approve(t: Tenant) -> None:
    a = await t.approval(t.body())
    r = await t.vote(a, "default", t.nexus)
    assert r.status_code == 403 and r.json()["code"] == "approver_ineligible"
