# ruff: noqa: E402  (settings come from the environment, set before quetrust is imported)
"""Que Trust tests: their own database (trust_test), keys of their own (static JWKS for callers and QCTs), the
dev compose OPA (:58181, `docker compose up -d opa`), no event delivery and no Que.IS."""

import hashlib
import json
import os
import pathlib
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_PG = "localhost:55432"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
QCT_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SIGNING = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(key: rsa.RSAPrivateKey, kid: str) -> str:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return json.dumps({"keys": [{**jwk, "kid": kid, "alg": "RS256", "use": "sig"}]})


os.environ.update(
    {
        "TRUST_DATABASE_URL": f"postgresql+asyncpg://trust_app:trust_app_dev@{_PG}/trust_test",
        "TRUST_WORKER_DATABASE_URL": f"postgresql+asyncpg://trust_worker:trust_worker_dev@{_PG}/trust_test",
        "TRUST_MIGRATION_DATABASE_URL": f"postgresql+asyncpg://trust_owner:trust_owner_dev@{_PG}/trust_test",
        "TRUST_OPA_URL": os.environ.get("TRUST_TEST_OPA_URL", "http://127.0.0.1:58181"),
        "TRUST_QUE_IS_URL": "",
        "TRUST_DELIVER_EVENTS": "false",
        "TRUST_JWKS": _jwks(KEY, "test-1"),
        "TRUST_QCT_ISSUER": "https://staging.que.is",
        "TRUST_QCT_JWKS": _jwks(QCT_KEY, "qct-1"),
        "TRUST_NHIAM_URL": "https://nhiam.test/api/v2",
        "TRUST_SIGNING_KEY": SIGNING.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
    }
)

import httpx
import pytest

from quetrust import db, service
from quetrust.app import create_app

NHIAM = "https://dev.que.local/nhiam"
PEOPLE = "https://dev.que.local/issuer"


def pytest_sessionstart(session: pytest.Session) -> None:
    import asyncio
    import subprocess
    import sys

    import asyncpg

    roles = (pathlib.Path(__file__).resolve().parents[4] / "infra/postgres/30-trust.sql").read_text()

    async def ensure() -> None:
        admin = await asyncpg.connect(f"postgresql://postgres:postgres_dev@{_PG}/postgres")
        try:
            await admin.execute(roles)  # idempotent: the roles the migration grants to
            if not await admin.fetchval("SELECT 1 FROM pg_database WHERE datname = 'trust_test'"):
                await admin.execute("CREATE DATABASE trust_test OWNER trust_owner")
                await admin.execute("GRANT CONNECT ON DATABASE trust_test TO trust_app, trust_worker")
        finally:
            await admin.close()

    asyncio.run(ensure())
    done = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"], capture_output=True, text=True, check=False
    )
    if done.returncode:
        pytest.exit(f"Migrating trust_test failed:\n{done.stderr[-2000:]}", 2)
    try:
        httpx.get(f"{os.environ['TRUST_OPA_URL']}/health", timeout=3).raise_for_status()
    except httpx.HTTPError:
        pytest.exit("Que Trust's tests need OPA: `docker compose up -d opa` (from v2/)", 2)


def token(
    tenant: uuid.UUID,
    subject: str,
    *,
    roles: tuple[str, ...] = (),
    service: bool = False,
    workload: bool = False,
    aud: str = "que-trust",
    claims: dict[str, Any] | None = None,
) -> str:
    now = int(time.time())
    body: dict[str, Any] = {"sub": subject, "tid": str(tenant), "iat": now, "exp": now + 600}
    if service or workload:
        body.update({"iss": NHIAM, "aud": aud, "kind": "workload"})
    else:
        body.update({"iss": PEOPLE, "kind": "human", "roles": list(roles)})
    body.update(claims or {})
    return jwt.encode(body, KEY, algorithm="RS256", headers={"kid": "test-1"})


def qct(
    tenant: uuid.UUID,
    subject: str,
    *,
    permissions: tuple[str, ...] = (),
    licensed: tuple[str, ...] = (),
    roles: tuple[str, ...] = ("Finance Lead",),
) -> str:
    now = int(time.time())
    body = {
        "sub": subject,
        "iss": "https://staging.que.is",
        "aud": "queis",
        "customerTenantId": str(tenant),
        "tenantSubdomain": "acme",
        "permissions": list(permissions),
        "licensed": list(licensed),
        "roles": list(roles),
        "email": f"{subject}@acme.test",
        "iat": now,
        "exp": now + 300,
    }
    return jwt.encode(body, QCT_KEY, algorithm="RS256", headers={"kid": "qct-1"})


def auth(tok: str, key: str | None = None) -> dict[str, str]:
    h = {"Authorization": f"Bearer {tok}"}
    if key:
        h["Idempotency-Key"] = key
    return h


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    app = create_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://trust") as c:
        yield c
    await db.dispose()


def digest_of(action: dict[str, Any]) -> str:
    raw = json.dumps(
        {
            "target_ref": action.get("target_ref", ""),
            "args": action.get("args", {}),
            "schema": action.get("schema_digest", ""),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


class Tenant:
    """One tenant: Nexus (svc:que-nexus), an admin, a requester and approvers."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.c = client
        self.id = uuid.uuid4()
        self.nexus = auth(token(self.id, "svc:que-nexus", service=True))
        self.admin = auth(token(self.id, "ada", roles=("tenant_admin",)))
        self.viewer = auth(token(self.id, "vic", roles=("employee",)))

    def person(self, subject: str, *roles: str) -> dict[str, str]:
        return auth(token(self.id, subject, roles=roles))

    async def req(
        self,
        method: str,
        path: str,
        who: dict[str, str],
        body: Any = None,
        key: str | None = None,
        expect: int | None = None,
    ) -> httpx.Response:
        h = {**who, **({"Idempotency-Key": key} if key else {})}
        r = await self.c.request(method, f"/api/v2{path}", json=body, headers=h)
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    def body(
        self,
        action_class: str = "refund.create",
        args: dict[str, Any] | None = None,
        *,
        tool: str = "billing.refund.create",
        effect: str = "write",
        mode: str = "hitl",
        requester: str = "req-1",
        approval_ref: str | None = None,
        version: str | None = None,
        asset: str | None = None,
        data_used: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        b: dict[str, Any] = {
            "audience": "que-connect",
            "action": {"target_ref": tool, "operation": action_class, "args": args or {}, "schema_digest": "s1"},
            "authority": {"approval_ref": approval_ref} if approval_ref else {},
            "effect": effect,
            "oversight_mode": mode,
            "environment": "test",
            "data_used": data_used or [],
            "data_classes": [],
            "initiator_ref": requester,
        }
        if version:
            b["agent_version_ref"] = {
                "owner_product": "nexus",
                "resource_kind": "asset_version",
                "resource_key": version,
            }
        if asset:
            b["agent_asset_ref"] = {"owner_product": "nexus", "resource_kind": "asset", "resource_key": asset}
        return b

    async def decide(self, body: dict[str, Any]) -> dict[str, Any]:
        return dict((await self.req("POST", "/decisions", self.nexus, body, expect=200)).json())

    async def approval(self, body: dict[str, Any], key: str | None = None) -> dict[str, Any]:
        d = await self.decide(body)
        assert d["decision"] == "approval_required", d
        r = await self.req(
            "POST",
            "/approvals",
            self.nexus,
            {"decision_ref": d["decision_id"], "action": body["action"], "business_reason": "test"},
            key=key or uuid.uuid4().hex,
            expect=201,
        )
        return dict(r.json())

    async def vote(
        self, approval: dict[str, Any], stage: str, who: dict[str, str], decision: str = "approve", **extra: Any
    ) -> httpx.Response:
        return await self.req(
            "POST",
            f"/approvals/{approval['approval_id']}/stages/{stage}/decisions",
            who,
            {"decision": decision, "reason": "ok", **extra},
        )

    async def policies(self, *policies: dict[str, Any], assignments: list[dict[str, Any]] | None = None) -> None:
        config = {
            "policies": list(policies),
            "assignments": assignments
            if assignments is not None
            else [{"id": "default", "policy_id": policies[0]["id"]}],
        }
        await self.req("PUT", "/approval-config", self.admin, config, expect=200)

    async def outbox(self) -> list[dict[str, Any]]:
        async with db.tenant_tx(self.id) as conn:
            return await db.all_(conn, "SELECT id, type, target, data FROM outbox_event ORDER BY created_at, id")


@pytest.fixture
def t(client: httpx.AsyncClient) -> Tenant:
    return Tenant(client)


@pytest.fixture(autouse=True)
def _reset() -> Any:
    clock = service.clock
    yield
    service.clock = clock
    service.nhiam_transport = None
