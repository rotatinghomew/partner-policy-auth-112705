"""查询视图：主管、值班员与合作社各自只看得到与自身范围相关的结果。

- 主管：提交新提议并查看「属于自己范围」的影响（其获准管理资源/账号内的
  角色能力变化与叠加风险）。
- 值班员：按角色与接口决定定位权限变化来源 —— 提议自身、两条提议叠加、
  还是新的目录事实。
- 合作社：用本地请求查询获准的业务资料，只返回自己租户的访问结果。
"""

from __future__ import annotations

from typing import Iterable, Optional

from .impact import combined_analysis, single_impact
from .model import FixtureSet, Proposal
from .requests import AuditLog, Decision, RequestContext, RequestEngine
from .scope import ProposalCheck, ScopeResolver
from .trial import Setup


class Project:
    """把资料、检查器、试用状态、请求引擎与审计装到一起的可操作项目。"""

    def __init__(self, fixtures: FixtureSet) -> None:
        self.fixtures = fixtures
        self.resolver = ScopeResolver(fixtures)
        self.setup = Setup(fixtures, self.resolver)
        self.audit = AuditLog()
        self.engine = RequestEngine(fixtures, self.resolver, self.audit, self.setup)

    # -- 主管 ------------------------------------------------------------- #

    def supervisor(self, actor: str) -> "SupervisorView":
        return SupervisorView(self, actor)

    # -- 值班员 ----------------------------------------------------------- #

    def duty_officer(self, actor: str) -> "DutyOfficerView":
        return DutyOfficerView(self, actor)

    # -- 合作社 ----------------------------------------------------------- #

    def cooperative(self, tenant: str) -> "CooperativeView":
        return CooperativeView(self, tenant)

    # -- 请求 ------------------------------------------------------------- #

    def request(self, person: str, tenant: str, resource: str, operation: str,
                purpose: str, at: int = 0) -> Decision:
        return self.engine.evaluate(
            RequestContext(person=person, tenant=tenant, resource=resource,
                           operation=operation, purpose=purpose, at=at),
            now=at,
        )


class SupervisorView:
    def __init__(self, project: Project, actor: str) -> None:
        self.project = project
        self.actor = actor
        self.scope = project.resolver.scope_for(actor)

    def _in_scope(self, check: ProposalCheck) -> bool:
        """影响是否落在主管获准管理的资源/账号范围内。"""
        if self.scope is None:
            return False
        if check.proposal.actor == self.actor:
            return True
        # 同一机构内的提议视为在范围内。
        return check.scope is not None and check.scope.company == self.scope.company

    def visible_checks(self) -> list[ProposalCheck]:
        return [
            check for check in self.project.setup.checks.values()
            if self._in_scope(check)
        ]

    def submit(self, actor: str, operation: str, target: str, detail: str,
               at: int = 0) -> ProposalCheck:
        """提交新提议并立即做范围与影响检查。

        提议归入项目历史；只有 actor 本人的权限才决定它是否可被核准。
        """
        proposal = Proposal(
            id=f"pp-{len(self.project.fixtures.proposals) + 1}",
            actor=actor, operation=operation, target=target, detail=detail, at=at,
        )
        check = self.project.resolver.check(proposal)
        self.project.setup.checks[proposal.id] = check
        self.project.fixtures.proposals.append(proposal)
        return check

    def impact(self, proposal_id: str) -> dict:
        check = self.project.setup.check(proposal_id)
        if not self._in_scope(check) and check.proposal.actor != self.actor:
            raise PermissionError("proposal outside supervisor scope")
        return single_impact(self.project.fixtures, check)

    def stacked_impact(self, proposal_ids: Optional[Iterable[str]] = None) -> list[dict]:
        checks = self.visible_checks()
        if proposal_ids is not None:
            wanted = set(proposal_ids)
            checks = [c for c in checks if c.proposal.id in wanted]
        return combined_analysis(self.project.fixtures, checks)


class DutyOfficerView:
    def __init__(self, project: Project, actor: str) -> None:
        self.project = project
        self.actor = actor

    def _checks(self) -> list[ProposalCheck]:
        return list(self.project.setup.checks.values())

    def stacked_risks(self) -> list[dict]:
        return combined_analysis(self.project.fixtures, self._checks())

    def locate(self, role: str, decision: Optional[Decision] = None,
               proposal_ids: Optional[Iterable[str]] = None) -> dict:
        """按角色与接口决定定位权限变化来源。

        依次判断：是否有单一提议自身上就让该角色获得了能力；是否有两条提议
        叠加后打开能力；当前目录事实是否已经让该角色持有相关能力。
        """
        base = self.project.fixtures.base_policy()
        role_caps = base.capability_tuples(role)
        proposed = self._checks()
        if proposal_ids is not None:
            wanted = set(proposal_ids)
            proposed = [c for c in proposed if c.proposal.id in wanted]

        solo: list[dict] = []
        for check in proposed:
            if not check.allowed or check.overlay.empty:
                continue
            stacked = base.with_overlays(check.overlay)
            gained = stacked.capability_tuples(role) - role_caps
            if gained:
                solo.append({
                    "proposal": check.proposal.id,
                    "capabilities": sorted(gained),
                })

        stacked_findings = []
        for finding in combined_analysis(self.project.fixtures, proposed):
            roles = {
                role
                for capability in finding["new_capabilities"]
                for role_ in capability["roles"]
                if role_ == role
            }
            if roles:
                stacked_findings.append(finding)

        facts = self._facts_for(role, decision)
        source = _classify(solo, stacked_findings, facts)
        return {
            "role": role,
            "decision": decision.as_dict() if decision else None,
            "classification": source,
            "single_proposal": solo,
            "stacked_proposals": stacked_findings,
            "directory_facts": facts,
        }

    def _facts_for(self, role: str, decision: Optional[Decision]) -> list[dict]:
        entries = [
            entry for entry in self.project.fixtures.directory
            if entry.role == role
        ]
        facts = [
            {
                "person": entry.person,
                "company": entry.company,
                "site": entry.site,
                "role": entry.role,
            }
            for entry in entries
        ]
        if decision is not None:
            facts.append({
                "event": "decision_identity",
                "person": decision.request.person,
                "company": decision.company,
                "role": decision.role,
                "resource": decision.request.resource,
                "resource_label": decision.resource_label,
                "revision": decision.revision,
            })
        return facts

    def decisions_for(self, role: Optional[str] = None, **criteria) -> list[Decision]:
        records = self.project.audit.records()
        if role is not None:
            records = tuple(d for d in records if d.role == role)
        if criteria:
            records = tuple(
                d for d in records
                if all(d.as_dict().get(k) == v for k, v in criteria.items())
            )
        return list(records)


class CooperativeView:
    def __init__(self, project: Project, tenant: str) -> None:
        self.project = project
        self.tenant = tenant

    def query(self, person: str, resource: str, operation: str, purpose: str,
              at: int = 0) -> dict:
        """以本机构身份查询业务资料；只返回本租户的访问结果。"""
        entry = self.project.fixtures.directory_view.person(person)
        if entry is None or entry.company != self.tenant:
            raise PermissionError("person does not belong to this tenant")
        decision = self.project.request(
            person=person, tenant=self.tenant, resource=resource,
            operation=operation, purpose=purpose, at=at,
        )
        # 只回显本租户可见的字段，不泄露其他租户的目录或政策内部。
        return {
            "tenant": self.tenant,
            "person": person,
            "resource": resource,
            "operation": operation,
            "purpose": purpose,
            "allowed": decision.allowed,
            "effect": decision.effect,
            "reason": decision.reason,
            "role": decision.role,
            "resource_label": decision.resource_label,
            "revision": decision.revision,
            "proposals": list(decision.proposals),
        }

    def my_decisions(self) -> list[dict]:
        return [
            decision.as_dict()
            for decision in self.project.audit.records()
            if decision.request.tenant == self.tenant
        ]


def _classify(solo: list[dict], stacked: list[dict], facts: list[dict]) -> str:
    if stacked:
        return "proposal_stack"
    if solo:
        return "single_proposal"
    if facts:
        return "directory_facts"
    return "no_change_found"
