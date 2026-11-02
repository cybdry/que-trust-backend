"""Who is calling Trust — verified offline, never taken from the body (Technical Docs 2 "Shared contracts").

- Services, workloads and AI approvers present NHIAM credentials (audience que-trust); Nexus is `svc:que-nexus`.
- People present a Que.IS QCT (Trust console; Studio and Workspace forward it for stage decisions) or, in
  development and tests, a token from the dev people issuer.
- A service calling for a person also sends that person's QCT as `Que-Subject-Token` (DEC-198): Trust verifies it
  like any person's token and requires the same tenant; the person is recorded as `on_behalf_of`.
The tenant is the credential's (`tid`, a QCT's `customerTenantId`). Roles come from the credential.
"""

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Annotated, Any

import httpx
import jwt
from fastapi import Depends, Header, Request

from quetrust.config import get_settings
from quetrust.errors import Problem
from quetrust.useragent import HEADERS

ADMINS = frozenset({"tenant_admin", "trust_admin"})
# A Que.IS owner (`*`), or anyone holding a Nexus or Trust permission, administers Trust (DEC-197).
QCT_ADMIN_ROLES = ("tenant_admin", "trust_admin", "approver")
# The tenant's owner and admin get the same access (DEC-218): Que.IS's system `admin` role carries no `nexus.*` or
# `trust.*` permission, so it is recognized by its role name.
TENANT_ADMIN_ROLES = frozenset({"owner", "admin"})

_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_aaa_cache: dict[str, float] = {}


@dataclass(frozen=True)
class Caller:
    tenant_id: uuid.UUID
    subject: str
    kind: str  # service | workload | human
    token: str
    roles: frozenset[str] = field(default_factory=frozenset)
    claims: dict[str, Any] = field(default_factory=dict)
    # The person a service is calling for (their verified Que-Subject-Token), or None.
    on_behalf_of: str | None = None

    @property
    def is_service(self) -> bool:
        return self.kind == "service"

    @property
    def is_admin(self) -> bool:
        return self.kind == "human" and bool(self.roles & ADMINS)

    def require_service(self) -> None:
        if not self.is_service:
            raise Problem(403, "permission_denied", "Only a Que service may do this.")

    def require_person(self) -> None:
        if self.kind != "human":
            raise Problem(403, "permission_denied", "The Trust console is for people.")

    def require_admin(self) -> None:
        if not self.is_admin:
            raise Problem(403, "permission_denied", "Trust admins (tenant_admin, trust_admin) change policy.")

    def require_policy_admin(self) -> None:
        """Resource policies: Trust admins, or a Que service acting for one."""
        if not (self.is_service or self.is_admin):
            raise Problem(403, "permission_denied", "Trust admins assign resource policies.")


async def jwks_at(url: str, static: dict[str, Any] | None) -> dict[str, Any]:
    if static is not None:
        return static
    hit = _jwks_cache.get(url)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    try:
        async with httpx.AsyncClient(timeout=5, headers=HEADERS) as client:
            r = await client.get(url)
            r.raise_for_status()
            keys = dict(r.json())
    except httpx.HTTPError as exc:
        raise Problem(503, "dependency_unavailable", "Signing keys unavailable.") from exc
    _jwks_cache[url] = (time.monotonic() + 300, keys)
    return keys


async def _key(token: str, url: str, static: dict[str, Any] | None) -> Any:
    kid = jwt.get_unverified_header(token).get("kid")
    for k in jwt.PyJWKSet.from_dict(await jwks_at(url, static)).keys:
        if k.key_id == kid:
            return k.key
    raise Problem(401, "unauthenticated", "Unknown signing key.")


def qct_roles(claims: dict[str, Any]) -> list[str]:
    """A QCT's Trust roles: an owner or admin (DEC-218), or a Nexus/Trust permission holder, administers; a Nexus or
    Trust licence approves. Que.IS role names are kept too, so approval stages may name them."""
    held = [str(p) for p in claims.get("permissions") or []]
    named = [str(r).strip().lower().replace(" ", "_") for r in claims.get("roles") or [] if str(r).strip()]
    admin = bool(set(named) & TENANT_ADMIN_ROLES) or any(
        p == "*" or p in ("nexus", "trust") or p.startswith(("nexus.", "trust.")) for p in held
    )
    licensed = {str(x) for x in claims.get("licensed") or []}
    roles = list(QCT_ADMIN_ROLES) if admin else (["approver"] if licensed & {"nexus", "trust"} else [])
    return roles + [r for r in named if r not in roles]


async def _verify_qct(token: str) -> dict[str, Any]:
    s = get_settings()
    claims: dict[str, Any] = jwt.decode(
        token,
        await _key(token, s.qct_jwks_url, s.qct_jwks),
        algorithms=["RS256"],
        issuer=s.qct_issuer,
        audience=s.qct_audience,
        options={"require": ["exp", "sub", "customerTenantId"]},
        leeway=s.clock_skew_seconds,
    )
    return {**claims, "tid": claims["customerTenantId"], "kind": "human", "roles": qct_roles(claims)}


async def verify(token: str) -> dict[str, Any]:
    s = get_settings()
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        if s.qct_issuer and unverified.get("iss") == s.qct_issuer:
            return await _verify_qct(token)
        if unverified.get("iss") not in s.issuers:
            raise Problem(401, "unauthenticated", "Untrusted issuer.")
        human = unverified.get("kind") == "human"
        return dict(
            jwt.decode(
                token,
                await _key(token, s.jwks_url, s.jwks),
                algorithms=["RS256"],
                issuer=unverified["iss"],
                audience=None if human else s.audience,
                options={"verify_aud": not human, "require": ["exp", "sub"]},
                leeway=s.clock_skew_seconds,
            )
        )
    except jwt.PyJWTError as exc:
        raise Problem(401, "unauthenticated", f"Credential rejected: {type(exc).__name__}") from exc


async def _base_aaa(caller: Caller, read_only: bool) -> None:
    """Que.IS base authorization for people (cached for reads only)."""
    s = get_settings()
    if not s.que_is_url:
        return
    key = hashlib.sha256(caller.token.encode()).hexdigest()
    if read_only and _aaa_cache.get(key, 0) > time.monotonic():
        return
    try:
        async with httpx.AsyncClient(timeout=5, headers=HEADERS) as client:
            r = await client.post(
                f"{s.que_is_url}/aaa/authorization-decisions",
                json={
                    "action": "trust.access",
                    "target_ref": f"tenant:{caller.tenant_id}",
                    "environment": "production",
                },
                headers={"Authorization": f"Bearer {caller.token}"},
            )
    except httpx.HTTPError as exc:
        raise Problem(503, "dependency_unavailable", "Que.IS unavailable.") from exc
    if r.status_code != 200 or r.json().get("decision") != "allow":
        raise Problem(403, "tenant_scope_denied", "Que.IS denied access to this tenant.")
    _aaa_cache[key] = time.monotonic() + 60


def _tenant(claims: dict[str, Any]) -> uuid.UUID:
    raw = claims.get("tid")
    if not raw:
        for scope in str(claims.get("scope", "")).split():
            if scope.startswith("tenant:"):
                raw = scope[7:]
    if not raw:
        raise Problem(403, "tenant_scope_denied", "No tenant in the credential.")
    try:
        return uuid.UUID(str(raw))
    except ValueError as exc:
        raise Problem(401, "unauthenticated", "The credential's tenant is not a UUID.") from exc


async def subject_of(token: str, tenant_id: uuid.UUID) -> str:
    """The person in a service's `Que-Subject-Token`: a valid person's token (a QCT; the dev people issuer outside
    production) of the caller's own tenant. Anything else is refused, never ignored."""
    try:
        claims = await verify(token)
        if claims.get("kind") != "human" or _tenant(claims) != tenant_id:
            raise Problem(401, "subject_token_invalid", "The subject token is not a person of this tenant.")
    except Problem as exc:
        if exc.code == "subject_token_invalid":
            raise
        raise Problem(401, "subject_token_invalid", f"The subject token was rejected: {exc.detail}") from exc
    return str(claims["sub"])


async def current_caller(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    que_subject_token: Annotated[str | None, Header()] = None,
) -> Caller:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise Problem(401, "unauthenticated", "Bearer credential required.")
    token = authorization.split(" ", 1)[1].strip()
    claims = await verify(token)
    sub = str(claims["sub"])
    kind = "human" if claims.get("kind") == "human" else ("service" if sub.startswith("svc:") else "workload")
    tenant = _tenant(claims)
    person = await subject_of(que_subject_token, tenant) if que_subject_token and kind == "service" else None
    caller = Caller(tenant, sub, kind, token, frozenset(str(r) for r in claims.get("roles", [])), claims, person)
    if kind == "human":
        await _base_aaa(caller, request.method in ("GET", "HEAD"))
    return caller


CallerDep = Annotated[Caller, Depends(current_caller)]
