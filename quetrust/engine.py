"""The decision engine: OPA (DEC-144). Trust's platform policy (rego/que_trust.rego, package que.trust) plus each
tenant's package `tenants.t_<tenant hex>`, which can only strengthen a decision. Trust's database is the source
of truth for tenant modules; OPA holds them in memory, so Trust (re)installs a tenant's module whenever OPA
doesn't have the version Trust saved — after an OPA restart, or a change made by another Trust replica."""

import re
import uuid
from pathlib import Path
from typing import Any

import httpx

from quetrust.config import get_settings
from quetrust.errors import Problem
from quetrust.useragent import HEADERS

PLATFORM_REGO = (Path(__file__).parent / "rego" / "que_trust.rego").read_text()
PLATFORM_MODULE = "que/trust"

_PACKAGE_LINE = re.compile(r"^[ \t]*package[ \t]+(\S+)", re.M)
_FORBIDDEN_REGO = (
    (re.compile(r"\bdata\s*[.\[]"), "a tenant policy can't read other documents (data.…)"),
    (re.compile(r"\bimport\s+data\b"), "a tenant policy can't import other documents"),
    (re.compile(r"\bhttp\.send\b|\bnet\.[a-z_]+\b"), "a tenant policy can't make network calls"),
    (re.compile(r"\bopa\.runtime\b"), "a tenant policy can't read the engine's runtime"),
)


def tenant_package(tenant_id: uuid.UUID, namespace: str = "tenants") -> str:
    """Each tenant's rules live in their own OPA package (DEC-144)."""
    return f"{namespace}.t_{tenant_id.hex}"


def module_id(tenant_id: uuid.UUID, namespace: str = "tenants") -> str:
    return tenant_package(tenant_id, namespace).replace(".", "/")


def as_draft(tenant_id: uuid.UUID, rego: str) -> str:
    return _PACKAGE_LINE.sub(f"package {tenant_package(tenant_id, 'drafts')}", rego, count=1)


def check_tenant_rego(tenant_id: uuid.UUID, text: str) -> list[dict[str, Any]]:
    """What Trust refuses before compiling: another package, reading other documents, network calls."""
    problems = []
    found = _PACKAGE_LINE.search(text)
    if not found or found[1] != tenant_package(tenant_id):
        problems.append(f"the policy must start with `package {tenant_package(tenant_id)}`")
    if len(_PACKAGE_LINE.findall(text)) > 1:
        problems.append("one package per policy")
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    problems += [why for pattern, why in _FORBIDDEN_REGO if pattern.search(code)]
    return [{"code": "tenant_policy_rejected", "message": m} for m in problems]


class Engine:
    """One per process. `installed` remembers which tenant module version OPA holds (as far as we know)."""

    def __init__(self, transport: Any = None) -> None:
        self.transport = transport  # tests may route OPA calls
        self.platform_ready = False
        self.installed: dict[uuid.UUID, str] = {}

    async def _call(self, method: str, path: str, **kw: Any) -> httpx.Response:
        url = f"{get_settings().opa_url.rstrip('/')}{path}"
        try:
            async with httpx.AsyncClient(timeout=5, transport=self.transport, headers=HEADERS) as client:
                return await client.request(method, url, **kw)
        except httpx.HTTPError as exc:
            self.forget()
            raise Problem(503, "decision_engine_unavailable", "Trust's decision engine is unavailable.") from exc

    def forget(self) -> None:
        self.platform_ready = False
        self.installed.clear()

    async def put_module(self, module: str, text: str) -> list[dict[str, Any]]:
        r = await self._call("PUT", f"/v1/policies/{module}", content=text.encode())
        if r.status_code == 200:
            return []
        body = r.json()
        return [
            {"code": e.get("code"), "message": e.get("message"), "row": (e.get("location") or {}).get("row")}
            for e in body.get("errors") or [body]
        ]

    async def delete_module(self, module: str) -> None:
        await self._call("DELETE", f"/v1/policies/{module}")

    async def _ensure(self, tenant_id: uuid.UUID, policy: dict[str, Any] | None) -> None:
        if not self.platform_ready:
            if errors := await self.put_module(PLATFORM_MODULE, PLATFORM_REGO):
                raise Problem(503, "platform_policy_invalid", str(errors[0]["message"]))
            self.platform_ready = True
        if policy and self.installed.get(tenant_id) != policy["digest"]:
            if errors := await self.put_module(module_id(tenant_id), str(policy["rego"])):
                raise Problem(503, "tenant_policy_invalid", str(errors[0]["message"]))
            self.installed[tenant_id] = str(policy["digest"])
        elif policy is None and tenant_id in self.installed:
            await self.delete_module(module_id(tenant_id))  # cleared elsewhere: OPA must not keep it
            self.installed.pop(tenant_id, None)

    async def evaluate(
        self, tenant_id: uuid.UUID, doc: dict[str, Any], policy: dict[str, Any] | None, namespace: str = "tenants"
    ) -> dict[str, Any]:
        """data.que.trust.result for one input document. A tenant rule that fails while evaluating fails
        closed (deny `policy_error`); OPA that lost its modules gets them again."""
        query = {**doc, "_trust": {"namespace": namespace}} if namespace != "tenants" else doc
        expect_tenant = namespace != "tenants" or policy is not None
        for _ in range(2):
            await self._ensure(tenant_id, policy)
            r = await self._call("POST", "/v1/data/que/trust/result", json={"input": query})
            if r.status_code != 200:
                return {
                    "decision": "deny",
                    "reasons": ["policy_error"],
                    "error": str(r.json().get("message", "evaluation failed")),
                    "obligations": [],
                    "approval_stages": [],
                    "human_only": False,
                    "tenant_policy": True,
                }
            result = r.json().get("result")
            if result is not None and (result["tenant_policy"] or not expect_tenant):
                return dict(result)
            self.forget()  # OPA restarted and lost its modules: load them again
        raise Problem(503, "platform_policy_missing", "Trust's decision engine lost its policies.")


ENGINE = Engine()
