"""授权范围校验，以及把政策提议编译成可叠加的政策增量。

管理员能做出的变更同时受三类约束：
1. 可编辑的政策项类型（admin_scopes.may_edit）；
2. 其获准管理的资源与账号范围（所属机构 / 名下账号 / 名下资源）；
3. 试用与撤回可操作的用途范围（admin_scopes.stages）。

继承带来的额外能力不在这里物化成新规则：它由 Policy 的继承闭包在求值时给出，
这样一旦继承关系被新的目录事实或另一项提议改变，旧能力不会残留在规则表里。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .model import (
    AdminScope,
    Edge,
    FixtureSet,
    Overlay,
    Proposal,
    Rule,
    split_csv,
)


# 提议操作所需的政策项编辑权限。空集合表示只需试用范围（stages）。
EDIT_PERMISSIONS: dict[str, set[str]] = {
    "add_edge": {"tenant_edges"},
    "change_edge": {"tenant_edges"},
    "tag_resource": {"own_labels", "labels"},
    "expand_rule": {"rules"},
    "disable_rule": {"rules"},
    "assign_role": {"own_users"},
    "pilot": set(),
    "withdraw": set(),
}

POLICY_OPERATIONS = {
    "add_edge", "change_edge", "tag_resource", "expand_rule",
    "disable_rule", "assign_role",
}


@dataclass
class ProposalCheck:
    proposal: Proposal
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    scope: Optional[AdminScope] = None
    overlay: Overlay = field(default_factory=lambda: Overlay(proposal_id=""))
    kind: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "proposal": self.proposal.id,
            "kind": self.kind,
            "allowed": self.allowed,
            "reasons": self.reasons,
            "notes": self.notes,
            "actor": self.proposal.actor,
            "company": self.scope.company if self.scope else None,
            "operation": self.proposal.operation,
            "target": self.proposal.target,
            "detail": self.proposal.detail,
            "at": self.proposal.at,
        }


class ScopeResolver:
    def __init__(self, fixtures: FixtureSet) -> None:
        self.fixtures = fixtures
        self._scopes = {scope.actor: scope for scope in fixtures.scopes}

    def scope_for(self, actor: str) -> Optional[AdminScope]:
        return self._scopes.get(actor)

    # ------------------------------------------------------------------ #

    def check(self, proposal: Proposal) -> ProposalCheck:
        check = ProposalCheck(proposal=proposal, allowed=False, kind="unknown")
        scope = self.scope_for(proposal.actor)
        check.scope = scope
        if scope is None:
            check.reasons.append("actor_not_authorized")
            return check

        operation = proposal.operation
        if operation not in EDIT_PERMISSIONS:
            check.reasons.append("unsupported_operation")
            return check

        # 试用/撤回按用途范围判定，其余按政策项类型判定。
        if operation in ("pilot", "withdraw"):
            check.kind = "pilot"
            tenant, purpose = self._pilot_fields(proposal, check)
            if purpose is None:
                return check
            if purpose not in scope.stages:
                check.reasons.append(f"purpose_not_in_stages:{purpose}")
            self._check_pilot_target(proposal, tenant, check)
            check.allowed = not check.reasons
            return check

        check.kind = "policy"
        required = EDIT_PERMISSIONS[operation]
        if not required & set(scope.may_edit):
            check.reasons.append(
                "may_not_edit:" + ",".join(sorted(required))
            )
            return check

        builder = getattr(self, f"_build_{operation}", None)
        if builder is None:
            check.reasons.append("unsupported_operation")
            return check
        builder(proposal, scope, check)
        check.allowed = not check.reasons
        return check

    # -- 各操作的叠加构造与范围校验 -------------------------------------- #

    def _build_add_edge(self, proposal: Proposal, scope: AdminScope,
                        check: ProposalCheck) -> None:
        child, parent = proposal.target, proposal.detail
        if not child or not parent:
            check.reasons.append("malformed_edge")
            return
        existing = {(edge.child, edge.parent) for edge in self.fixtures.edges}
        if (child, parent) in existing:
            check.notes.append("edge_already_declared")
        check.overlay = Overlay(
            proposal_id=proposal.id,
            added_edges=(Edge(
                id=f"{proposal.id}:edge",
                child=child,
                parent=parent,
                owner=scope.company,
            ),),
        )

    def _build_change_edge(self, proposal: Proposal, scope: AdminScope,
                           check: ProposalCheck) -> None:
        edge = next((e for e in self.fixtures.edges if e.id == proposal.target), None)
        if edge is None:
            check.reasons.append("edge_not_found")
            return
        if edge.owner != scope.company:
            check.reasons.append("edge_outside_company")
            return
        if not proposal.detail:
            check.reasons.append("malformed_edge")
            return
        check.overlay = Overlay(
            proposal_id=proposal.id,
            replaced_edges=(Edge(
                id=edge.id,
                child=edge.child,
                parent=proposal.detail,
                owner=edge.owner,
            ),),
        )
        check.notes.append(f"replace_parent:{edge.parent}->{proposal.detail}")

    def _build_tag_resource(self, proposal: Proposal, scope: AdminScope,
                            check: ProposalCheck) -> None:
        resource = self.fixtures.directory_view.resource(proposal.target)
        if resource is None:
            check.reasons.append("resource_not_found")
            return
        label, owner = self._label_and_owner(proposal.detail, check)
        if label is None:
            return
        # 资源归属以报表接口实际登记为准；提议不得借此改写归属。
        if owner is not None and owner != resource.owner:
            check.reasons.append(
                f"owner_mismatch:{owner}!={resource.owner}"
            )
        if "own_labels" in scope.may_edit and "labels" not in scope.may_edit:
            if resource.owner != scope.company:
                check.reasons.append("resource_outside_company")
        # 标签提议改变的是资源归属标签这一事实；它是否扩大能力由后续求值判定，
        # 不在提议里伪造授权规则。
        check.overlay = Overlay(
            proposal_id=proposal.id,
            relabels=((resource.id, label),),
        )
        check.notes.append(f"tag:{proposal.target}={label}")

    def _build_expand_rule(self, proposal: Proposal, scope: AdminScope,
                           check: ProposalCheck) -> None:
        rule = next((r for r in self.fixtures.rules if r.id == proposal.target), None)
        if rule is None:
            check.reasons.append("rule_not_found")
            return
        label, owner_class = self._label_and_owner(proposal.detail, check)
        if label is None:
            return
        owner_class = owner_class or "other_org"
        if not self._declared(rule.operation, rule.purpose, label, owner_class):
            check.reasons.append(
                f"outside_condition_domain:{rule.operation}/{rule.purpose}/"
                f"{label}/{owner_class}"
            )
        if rule.effect == "deny":
            check.reasons.append("cannot_expand_deny_rule")
        check.overlay = Overlay(
            proposal_id=proposal.id,
            added_rules=(Rule(
                id=f"{proposal.id}:rule",
                role=rule.role,
                operation=rule.operation,
                purpose=rule.purpose,
                label=label,
                owner_class=owner_class,
                effect="allow",
            ),),
        )
        check.notes.append(
            f"expand:{rule.role}/{rule.operation}/{rule.purpose}->{label}/{owner_class}"
        )

    def _build_disable_rule(self, proposal: Proposal, scope: AdminScope,
                            check: ProposalCheck) -> None:
        rule = next((r for r in self.fixtures.rules if r.id == proposal.target), None)
        if rule is None:
            check.reasons.append("rule_not_found")
            return
        check.overlay = Overlay(
            proposal_id=proposal.id,
            removed_rule_ids=(rule.id,),
        )
        check.notes.append(f"disable:{rule.id}")

    def _build_assign_role(self, proposal: Proposal, scope: AdminScope,
                           check: ProposalCheck) -> None:
        entry = self.fixtures.directory_view.person(proposal.target)
        if entry is None:
            check.reasons.append("person_not_found")
            return
        if entry.company != scope.company:
            check.reasons.append("person_outside_company")
            return
        role = proposal.detail
        if not role:
            check.reasons.append("malformed_role")
            return
        # 只能把本机构账号改成本机构实际存在的角色；把账号变成另一家企业
        # 专有的角色（例如别家的报表管理员）属于扩大授权，拒绝。
        owners = {
            person.company for person in self.fixtures.directory
            if person.role == role
        }
        if owners and scope.company not in owners:
            check.reasons.append(
                "cross_company_role:" + ",".join(sorted(owners))
            )
            return
        # 角色变更本身不进入政策叠加；由目录事实提供，留作后续事实。
        check.notes.append(f"assign:{entry.person}->{role}")

    # -- 辅助 ------------------------------------------------------------- #

    def _pilot_fields(self, proposal: Proposal, check: ProposalCheck):
        parts = split_csv(proposal.detail)
        if len(parts) < 2:
            check.reasons.append("malformed_pilot")
            return None, None
        return parts[0], parts[1]

    def _check_pilot_target(self, proposal: Proposal, tenant: Optional[str],
                            check: ProposalCheck) -> None:
        target = self.fixtures.proposal(proposal.target)
        if target is None:
            check.reasons.append("pilot_target_not_found")
            return
        if proposal.target == proposal.id:
            check.reasons.append("pilot_target_self")
        target_check = self.check(target)
        if target_check.kind == "pilot":
            check.reasons.append("pilot_target_must_be_policy")
        if not target_check.allowed:
            check.reasons.append("pilot_target_not_approved")
        known_tenants = {entry.company for entry in self.fixtures.directory}
        known_tenants |= {activation.tenant for activation in self.fixtures.activations}
        if tenant is not None and tenant not in known_tenants:
            check.reasons.append(f"unknown_tenant:{tenant}")

    def _label_and_owner(self, detail: str, check: ProposalCheck):
        parts = split_csv(detail)
        if not parts:
            check.reasons.append("malformed_detail")
            return None, None
        label = parts[0]
        owner = parts[1] if len(parts) > 1 else None
        return label, owner

    def _declared(self, operation: str, purpose: str, label: str,
                  owner_class: str) -> bool:
        return any(
            condition.operation == operation
            and condition.purpose == purpose
            and condition.label == label
            and condition.owner_class == owner_class
            for condition in self.fixtures.conditions
        )

    # ------------------------------------------------------------------ #

    def compile_all(self) -> list[ProposalCheck]:
        return [self.check(proposal) for proposal in self.fixtures.proposals]
