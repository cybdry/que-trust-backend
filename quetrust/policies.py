"""Que Trust approval policies and their assignments (DEC-154, DEC-197).

Trust owns approval policies (stages, approvers, quorum, conditions, expiry, escalation, separation of
duties) and assigns them: to an agent and an action class, to an agent, to an action class pattern
(exact, `refund.*`, `*`) across agents, or as the tenant default. At decision time Trust picks the most
specific matching assignment; Nexus only declares each action's oversight mode and never names a
policy. Without any assignment Trust's built-in default stage applies (any one `approver`).
"""

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_KEY = r"^[a-z0-9][a-z0-9-]{0,39}$"


class Approver(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["user", "group", "team", "role", "ai_agent"]
    ref: str = Field(min_length=1, max_length=200)
    version_id: str | None = Field(default=None, description="ai_agent: the approving experience version")


class Condition(BaseModel):
    """The stage applies only when the action's argument compares as given (Trust computes it from the
    actual arguments)."""

    model_config = ConfigDict(extra="forbid")
    field: str = Field(min_length=1, max_length=64)
    operation: Literal["equals", "notEquals", "larger", "smaller", "contains"] = "equals"
    value: str | int | float


class Stage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage_key: str = Field(pattern=_KEY)
    ordinal: int = Field(default=1, ge=1, le=20, description="Equal ordinals run in parallel")
    approver_kind: Literal["human_only", "ai_allowed", "mixed"] = "human_only"
    approvers: list[Approver] = Field(min_length=1, max_length=50)
    quorum: Literal["any", "all", "n_of_m"] = "any"
    quorum_n: int | None = Field(default=None, ge=1)
    condition: Condition | None = None
    expires_after_seconds: int | None = Field(default=None, gt=0)
    escalation: dict[str, Any] = Field(default_factory=dict, description="{approvers: [...]} added on expiry")
    sod_rules: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> "Stage":
        if self.quorum == "n_of_m" and not self.quorum_n:
            raise ValueError(f"{self.stage_key}: N-of-M quorum needs N")
        has_ai = any(a.type == "ai_agent" for a in self.approvers)
        if self.approver_kind == "human_only" and has_ai:
            raise ValueError(f"{self.stage_key}: a human-only stage can't list AI approvers")
        if any(a.type == "ai_agent" and not a.version_id for a in self.approvers):
            raise ValueError(f"{self.stage_key}: AI approvers are named by principal and experience version")
        return self


class ApprovalPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=_KEY)
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    stages: list[Stage] = Field(min_length=1, max_length=20)
    hotl_window_seconds: int = Field(default=900, ge=60, le=86_400, description="HOTL review window")

    @model_validator(mode="after")
    def _check(self) -> "ApprovalPolicy":
        keys = [s.stage_key for s in self.stages]
        if len(keys) != len(set(keys)):
            raise ValueError(f"{self.name}: stage keys must be unique")
        return self


class Assignment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=40)
    agent_asset_id: str | None = Field(default=None, description="None = any agent")
    agent_name: str | None = Field(default=None, max_length=200)
    action: str | None = Field(
        default=None,
        pattern=r"^([A-Za-z0-9_.-]+(\.\*)?|\*)$",
        description="Action class, a prefix pattern like refund.*, or None/* = any",
    )
    policy_id: str = Field(pattern=_KEY)


class ApprovalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policies: list[ApprovalPolicy] = Field(default_factory=list, max_length=200)
    assignments: list[Assignment] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def _check(self) -> "ApprovalConfig":
        ids = [p.id for p in self.policies]
        if len(ids) != len(set(ids)):
            raise ValueError("policy ids must be unique")
        missing = {a.policy_id for a in self.assignments} - set(ids)
        if missing:
            raise ValueError(f"assigned policies don't exist: {', '.join(sorted(missing))}")
        return self


def _action_score(pattern: str | None, action_class: str) -> int | None:
    """How specifically a pattern matches: exact 3, prefix (refund.*) 2, any 1; None = no match."""
    if pattern in (None, "*"):
        return 1
    if pattern.endswith(".*"):
        return 2 if action_class.startswith(pattern[:-1]) else None
    return 3 if pattern == action_class else None


def resolve(config: ApprovalConfig, agent_asset_id: str | None, action_class: str) -> ApprovalPolicy | None:
    """The policy of the most specific matching assignment (an agent match outranks any action match)."""
    best: tuple[int, int, int] | None = None
    chosen = None
    for i, a in enumerate(config.assignments):
        if a.agent_asset_id and a.agent_asset_id != agent_asset_id:
            continue
        score = _action_score(a.action, action_class)
        if score is None:
            continue
        rank = (1 if a.agent_asset_id else 0, score, -i)  # earlier assignments win ties
        if best is None or rank > best:
            best, chosen = rank, a
    if chosen is None:
        return None
    return next(p for p in config.policies if p.id == chosen.policy_id)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "policy"
