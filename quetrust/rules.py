"""Que Trust tenant rules, configured graphically and compiled to Rego (DEC-151).

A tenant's rule set is structured data: each rule has conditions (all must hold) on known fields of
the decision input and one effect — deny, require approval, add an approval stage, make every stage
human-only, or add an obligation. Trust validates it and compiles it to the tenant's Rego package
(DEC-144), which OPA evaluates with Trust's platform policy. Values are only ever emitted as JSON
literals and fields come from a fixed catalog, so a rule set can't inject Rego.
"""

import json
import re
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"]
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

# Field catalog: what a condition can look at, its type, its Rego expression and (for enums) values.
# `argument` takes the argument's name from the condition (input.action.arguments[name]).
FIELDS: dict[str, dict[str, Any]] = {
    "action.action_class": {"label": "Action class", "type": "string", "rego": "input.action.action_class"},
    "action.tool_ref": {"label": "Tool", "type": "string", "rego": "input.action.tool_ref"},
    "action.effect": {"label": "Effect", "type": "enum", "values": ["read", "write"], "rego": "input.action.effect"},
    "action.oversight_mode": {
        "label": "Oversight mode",
        "type": "enum",
        "values": ["hitl", "hotl", "hootl", "not_applicable"],
        "rego": "input.action.oversight_mode",
    },
    "action.environment": {
        "label": "Environment",
        "type": "enum",
        "values": ["test", "staging", "production"],
        "rego": "input.action.environment",
    },
    "action.argument": {"label": "Argument", "type": "argument", "rego": "input.action.arguments"},
    "requester": {"label": "Requester", "type": "string", "rego": "input.requester"},
    "requester_groups": {"label": "Requester's groups", "type": "set", "rego": "input.requester_groups"},
    "agent.registered": {"label": "Agent is released", "type": "bool", "rego": "input.agent.registered"},
    "agent.name": {"label": "Agent name", "type": "string", "rego": "input.agent.name"},
    "agent.kind": {
        "label": "Agent kind",
        "type": "enum",
        "values": ["agent", "system", "workflow", "team", "minie", "generative", "prediction"],
        "rego": "input.agent.kind",
    },
    "agent.agent_type": {
        "label": "Agent type",
        "type": "enum",
        "values": ["genie", "marid"],
        "rego": "input.agent.agent_type",
    },
    "agent.max_classification": {
        "label": "Most sensitive data the agent reads",
        "type": "classification",
        "values": CLASSIFICATIONS,
        "rego": "input.agent.max_classification",
    },
    "run.data_used": {"label": "Data used in this run", "type": "data", "rego": "input.run.data_used"},
    "run.max_classification": {
        "label": "Most sensitive data used in this run",
        "type": "classification",
        "values": CLASSIFICATIONS,
        "rego": "input.run.max_classification",
    },
    "time.hour": {"label": "Hour of day", "type": "number", "rego": "_hour"},
    "time.weekday": {"label": "Weekday", "type": "enum", "values": WEEKDAYS, "rego": "_weekday"},
}

OPERATORS: dict[str, list[str]] = {
    "string": ["equals", "not_equals", "starts_with", "ends_with", "contains", "in", "not_in"],
    "enum": ["equals", "not_equals", "in", "not_in"],
    "number": ["eq", "ne", "gt", "gte", "lt", "lte"],
    "argument": ["equals", "not_equals", "contains", "in", "not_in", "eq", "ne", "gt", "gte", "lt", "lte", "present"],
    "bool": ["is_true", "is_false"],
    "set": ["contains", "not_contains"],
    "data": ["contains", "not_contains"],
    "classification": ["equals", "at_least", "below"],
}
_NUMERIC = {"eq": "==", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
_ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    op: str
    value: Any = None
    argument: str | None = Field(default=None, description="For field action.argument: the argument's name")

    @model_validator(mode="before")
    @classmethod
    def _renamed(cls, data: Any) -> Any:
        if isinstance(data, dict) and data.get("field") == "agent.experience":  # saved before DEC-157
            return {**data, "field": "agent.agent_type"}
        return data

    @model_validator(mode="after")
    def _check(self) -> "Condition":
        spec = FIELDS.get(self.field)
        if spec is None:
            raise ValueError(f"unknown field {self.field!r}")
        if self.op not in OPERATORS[spec["type"]]:
            raise ValueError(f"{self.op!r} doesn't apply to {spec['label']}")
        if spec["type"] == "argument" and not (self.argument and _ARG_NAME.match(self.argument)):
            raise ValueError("name the argument (letters, digits, _ . -)")
        if self.op in ("is_true", "is_false", "present"):
            return self
        if self.op in ("in", "not_in"):
            if not isinstance(self.value, list) or not self.value:
                raise ValueError(f"{spec['label']}: give at least one value")
        elif self.op in _NUMERIC:
            if isinstance(self.value, bool) or not isinstance(self.value, int | float):
                raise ValueError(f"{spec['label']}: give a number")
        elif not isinstance(self.value, str) or not self.value:
            raise ValueError(f"{spec['label']}: give a value")
        allowed = spec.get("values")
        if allowed:
            given = self.value if isinstance(self.value, list) else [self.value]
            if any(v not in allowed for v in given):
                raise ValueError(f"{spec['label']}: one of {', '.join(allowed)}")
        return self


class Approver(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["role", "group", "user"]
    ref: str = Field(min_length=1, max_length=200)


class Effect(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["deny", "require_approval", "add_stage", "human_only", "obligation"]
    reason: str | None = Field(default=None, max_length=300, description="deny / require_approval: shown on the run")
    stage_key: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,39}$")
    approvers: list[Approver] = Field(default_factory=list)
    quorum: Literal["any", "all"] = "any"
    obligation: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.-]{0,59}$")

    @model_validator(mode="after")
    def _check(self) -> "Effect":
        if self.kind in ("deny", "require_approval") and not (self.reason or "").strip():
            raise ValueError("give the reason people will see")
        if self.kind == "add_stage" and not (self.stage_key and self.approvers):
            raise ValueError("an added stage needs a key and at least one approver")
        if self.kind == "obligation" and not self.obligation:
            raise ValueError("name the obligation")
        return self


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8], pattern=r"^[A-Za-z0-9_-]{1,40}$")
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    when: list[Condition] = Field(default_factory=list, max_length=20, description="All must hold")
    then: Effect


class DataRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["knowledge", "mcp_server"]
    ref: str = Field(min_length=1, max_length=200)
    name: str | None = Field(default=None, max_length=200)


class ToolScope(BaseModel):
    """DEC-152: an agent's tool may act only when the run used no data outside `allowed`."""

    model_config = ConfigDict(extra="forbid")
    agent_asset_id: str = Field(pattern=r"^[0-9a-f-]{36}$", description="Every version of this agent")
    agent_name: str | None = Field(default=None, max_length=200)
    tool_ref: str = Field(min_length=1, max_length=300)
    allowed: list[DataRef] = Field(default_factory=list, max_length=100)
    otherwise: Literal["deny", "require_approval"] = "deny"


class RuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timezone: str = Field(default="UTC", pattern=r"^[A-Za-z_]+(/[A-Za-z0-9_+-]+){0,2}$")
    rules: list[Rule] = Field(default_factory=list, max_length=100)
    scopes: list[ToolScope] = Field(default_factory=list, max_length=500)


def catalog(data_sources: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """What the graphical editor offers: fields with their types and values, and operators per type;
    data fields offer the tenant's data sources (from the agent profiles Trust holds)."""
    fields = []
    for k, spec in FIELDS.items():
        entry = {"key": k, **{f: v for f, v in spec.items() if f != "rego"}}
        if spec["type"] == "data":
            entry["options"] = data_sources or []
        fields.append(entry)
    return {"fields": fields, "operators": OPERATORS}


def _lit(value: Any) -> str:
    return json.dumps(value)  # JSON literals are Rego literals


def _condition(c: Condition) -> str:
    spec = FIELDS[c.field]
    ref = spec["rego"]
    kind = spec["type"]
    if kind == "argument":
        ref = f"input.action.arguments[{_lit(c.argument)}]"
        if c.op == "present":
            return f"{ref} != null"
        if c.op in _NUMERIC:
            return f"_num({ref}) {_NUMERIC[c.op]} {_lit(c.value)}"
    if kind == "number" and c.op in _NUMERIC:
        return f"{ref} {_NUMERIC[c.op]} {_lit(c.value)}"
    if kind == "bool":
        return ref if c.op == "is_true" else f"not {ref}"
    if kind == "data":
        used = f"{{d.ref | some d in {ref}}}"
        return f"{_lit(c.value)} in {used}" if c.op == "contains" else f"not {_lit(c.value)} in {used}"
    if kind == "set":
        return f"{_lit(c.value)} in {ref}" if c.op == "contains" else f"not {_lit(c.value)} in {ref}"
    if kind == "classification":
        level = CLASSIFICATIONS.index(c.value)
        if c.op == "equals":
            return f"{ref} == {_lit(c.value)}"
        return f"_rank[{ref}] {'>=' if c.op == 'at_least' else '<'} {level}"
    return {
        "equals": f"{ref} == {_lit(c.value)}",
        "not_equals": f"{ref} != {_lit(c.value)}",
        "starts_with": f"startswith({ref}, {_lit(c.value)})",
        "ends_with": f"endswith({ref}, {_lit(c.value)})",
        "contains": f"contains({ref}, {_lit(c.value)})",
        "in": f"{ref} in {{{', '.join(_lit(v) for v in c.value or [])}}}",
        "not_in": f"not {ref} in {{{', '.join(_lit(v) for v in c.value or [])}}}",
    }[c.op]


def _head(e: Effect) -> str:
    if e.kind == "deny":
        return f"deny contains {_lit(e.reason)}"
    if e.kind == "require_approval":
        return f"require_approval contains {_lit(e.reason)}"
    if e.kind == "add_stage":
        stage = {"stage_key": e.stage_key, "approvers": [a.model_dump() for a in e.approvers], "quorum": e.quorum}
        return f"approval_stages contains {json.dumps(stage, sort_keys=True)}"
    if e.kind == "human_only":
        return "human_only"
    return f"obligations contains {_lit(e.obligation)}"


def compile_rules(tenant_package: str, rule_set: RuleSet) -> str:
    """The tenant's Rego module for a rule set (deterministic: same rules, same text)."""
    lines = [
        "# Generated by Que Trust from the tenant's rules (Que Trust console). Don't edit:",
        "# saving the rules replaces this module.",
        f"package {tenant_package}",
        "",
        "default human_only := false",
        "",
        '_rank := {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}',
        "",
        "_num(x) := x if is_number(x)",
        "",
        "_num(x) := to_number(x) if {",
        "\tis_string(x)",
        "\tregex.match(`^-?[0-9]+(\\.[0-9]+)?$`, x)",
        "}",
        "",
        f"_clock := time.clock([time.parse_rfc3339_ns(input.time), {_lit(rule_set.timezone)}])",
        "",
        "_hour := _clock[0]",
        "",
        f"_weekday := time.weekday([time.parse_rfc3339_ns(input.time), {_lit(rule_set.timezone)}])",
    ]
    for scope in rule_set.scopes:
        allowed = ", ".join(_lit(d.ref) for d in scope.allowed)
        names = ", ".join(d.name or d.ref for d in scope.allowed) or "no data"
        head = "deny" if scope.otherwise == "deny" else "require_approval"
        reason = f"{scope.tool_ref} may only act on data from {names}"
        lines += [
            "",
            f"# Data scope: {(scope.agent_name or scope.agent_asset_id).replace(chr(10), ' ')} · {scope.tool_ref}",
            f"{head} contains {_lit(reason)} if {{",
            f"\tinput.agent.asset_id == {_lit(scope.agent_asset_id)}",
            f"\tinput.action.tool_ref == {_lit(scope.tool_ref)}",
            "\tsome used in input.run.data_used",
            f"\tnot used.ref in {{{allowed}}}" if allowed else "\tused",
            "}",
        ]
    for rule in rule_set.rules:
        if not rule.enabled:
            continue
        body = [_condition(c) for c in rule.when] or ["true"]
        lines += ["", f"# {rule.name.replace(chr(10), ' ')} [{rule.id}]", f"{_head(rule.then)} if {{"]
        lines += [f"\t{b}" for b in body]
        lines.append("}")
    return "\n".join(lines) + "\n"
