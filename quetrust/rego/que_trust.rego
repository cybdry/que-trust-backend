# Que Trust — platform decision policy (DEC-144, DEC-197). Trust owns this module.
#
# Nexus asks Trust before every protected action; Trust builds the input document below and asks OPA for
# data.que.trust.result. Each tenant adds rules in its own package, tenants.t_<tenant id without
# dashes>. Tenant rules can only strengthen the decision — deny, require approval, add approval stages,
# make every stage human-only, add obligations. Nothing a tenant writes can allow what this policy denies.
#
# input := {
#   "tenant": "<uuid>",
#   "action": {action_class, tool_ref, connection_ref, operation, effect, oversight_mode, arguments,
#              environment, run_ref},
#   "agent": {identity, version_id, registered,       # the acting non-human identity (DEC-145), from
#             name, kind, experience, autonomy,       # the profile Nexus registered at release — not
#             tools: [{tool_ref, action_classes, effect, server, identity_mode}],   # from the caller
#             data_sources: [{kind: knowledge|mcp_server, ref, name, classification, acl_mode, source_kinds}],
#             max_classification},
#   "run": {data_used: [{kind, ref, name, classification}], max_classification},  # data read so far (DEC-152)
#   "requester": "<subject>", "requester_groups": ["managers", ...],
#   "approval": {"id", "status", "matches_action"},   # only when Nexus re-validates an approved action
#   "time": "<RFC 3339>",
# }
package que.trust

action := input.action

_namespace := object.get(input, ["_trust", "namespace"], "tenants")

_package := concat("", ["t_", replace(input.tenant, "-", "")])

# Saved tenant policies live under data.tenants; a draft being tried under data.drafts.
_tenant_document := data.tenants[_package] if _namespace == "tenants"

else := data.drafts[_package] if _namespace == "drafts"

tenant := t if {
	t := _tenant_document
} else := {}

default tenant_policy_loaded := false

tenant_policy_loaded if _tenant_document

# A released agent acts only through the tools it was released with (its registered profile). An
# unreleased version (preview) has no profile; tenants decide what it may do (input.agent.registered).
profile_tools := {t.tool_ref: t | some t in input.agent.tools}

denials contains "tool_not_in_agent_profile" if {
	input.agent.registered
	action.action_class != "model.invoke"
	action.tool_ref
	not profile_tools[action.tool_ref]
}

denials contains "action_class_not_in_agent_profile" if {
	input.agent.registered
	classes := profile_tools[action.tool_ref].action_classes
	count(classes) > 0
	not action.action_class in classes
}

# Model egress (03 §C.8 (7)): a model only receives data up to the class the tenant allows for it
# (Connect's label on the model). The run's data class is what Trust computed from data_used.
_rank := {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

denials contains "data_class_exceeds_model" if {
	action.action_class == "model.invoke"
	used := input.run.max_classification
	used != null
	allowed := object.get(action.arguments, "model_max_classification", "confidential")
	_rank[used] > _rank[allowed]
}

# A rule may be a set of reasons (deny contains "…" if …) or a plain boolean (deny if …).
denials contains reason if some reason in object.get(tenant, "deny", set())

denials contains "denied_by_tenant_policy" if object.get(tenant, "deny", false) == true

approval_reasons contains reason if some reason in object.get(tenant, "require_approval", set())

approval_reasons contains "required_by_tenant_policy" if object.get(tenant, "require_approval", false) == true

tenant_stages contains stage if some stage in object.get(tenant, "approval_stages", set())

human_only := object.get(tenant, "human_only", false) == true

obligations contains o if some o in object.get(tenant, "obligations", set())

obligations contains "oversight" if {
	action.effect == "write"
	action.oversight_mode == "hotl"
}

approval_valid if {
	input.approval.status == "approved"
	input.approval.matches_action == true
}

needs_approval if {
	action.effect == "write"
	action.oversight_mode == "hitl"
}

needs_approval if count(approval_reasons) > 0

# An approval step the maker authored in a workflow (effect "approval") always opens an approval.
needs_approval if action.effect == "approval"

decision := {"decision": "deny", "reasons": sort(denials)} if {
	count(denials) > 0
} else := {"decision": "allow", "reasons": []} if {
	approval_valid
} else := {"decision": "deny", "reasons": ["approval_invalid"]} if {
	input.approval
} else := {"decision": "approval_required", "reasons": sort(approval_reasons)} if {
	needs_approval
} else := {"decision": "deny", "reasons": ["hootl_not_available"]} if {
	action.oversight_mode == "hootl"
} else := {"decision": "allow", "reasons": []}

allowed_obligations := sort(obligations) if decision.decision == "allow"

else := []

# What Trust reads back. Obligations ride on an allow; stages and human_only shape an approval.
result := object.union(decision, {
	"obligations": allowed_obligations,
	"approval_stages": sort(tenant_stages),
	"human_only": human_only,
	"tenant_policy": tenant_policy_loaded,
})
