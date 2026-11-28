"""接口请求求值。

一次请求的求值身份与政策来自同一条链路：
- 身份及所属机构/站点取自机构身份目录；
- 请求声明的租户必须与身份所属机构一致，不能借租户声明在两边政策间各取一半；
- 政策由该租户基础政策（含独立批准的变更）与其当前生效、且用途匹配的试用叠加；
  未获试用的租户与用途继续使用原政策。
- 已经产生的决定写入追加式审计，保留当时的身份、所用政策修订与结果；后来的
  政策变化不会改写历史决定。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

from .model import FixtureSet, Policy, owner_class_for
from .scope import ScopeResolver


@dataclass(frozen=True)
class RequestContext:
    person: str
    tenant: str
    resource: str
    operation: str
    purpose: str
    at: int = 0


@dataclass(frozen=True)
class Decision:
    request: RequestContext
    allowed: bool
    effect: str
    reason: str
    role: Optional[str]
    company: Optional[str]
    site: Optional[str]
    resource_owner: Optional[str]
    resource_label: Optional[str]
    owner_class: Optional[str]
    revision: Optional[str]
    proposals: tuple[str, ...]
    policy_digest: str
    recorded_at: int

    def as_dict(self) -> dict:
        return {
            "person": self.request.person,
            "tenant": self.request.tenant,
            "resource": self.request.resource,
            "operation": self.request.operation,
            "purpose": self.request.purpose,
            "at": self.request.at,
            "allowed": self.allowed,
            "effect": self.effect,
            "reason": self.reason,
            "role": self.role,
            "company": self.company,
            "site": self.site,
            "resource_owner": self.resource_owner,
            "resource_label": self.resource_label,
            "owner_class": self.owner_class,
            "revision": self.revision,
            "proposals": list(self.proposals),
            "policy_digest": self.policy_digest,
            "recorded_at": self.recorded_at,
        }


class AuditLog:
    """追加式决定日志；只写不改。"""

    def __init__(self) -> None:
        self._records: list[Decision] = []

    def record(self, decision: Decision) -> None:
        self._records.append(decision)

    def __len__(self) -> int:
        return len(self._records)

    def records(self) -> tuple[Decision, ...]:
        return tuple(self._records)

    def at(self, index: int) -> Decision:
        return self._records[index]

    def find(self, **criteria) -> list[Decision]:
        def match(decision: Decision) -> bool:
            payload = decision.as_dict()
            return all(payload.get(key) == value for key, value in criteria.items())
        return [decision for decision in self._records if match(decision)]

    def to_dicts(self) -> list[dict]:
        return [decision.as_dict() for decision in self._records]


class RequestEngine:
    def __init__(self, fixtures: FixtureSet, resolver: ScopeResolver,
                 audit: AuditLog, setup) -> None:
        self.fixtures = fixtures
        self.resolver = resolver
        self.audit = audit
        self.setup = setup

    def evaluate(self, context: RequestContext, now: int) -> Decision:
        entry = self.fixtures.directory_view.person(context.person)
        revision = self.setup.revision_of(context.tenant)
        policy, proposals = self.setup.policy_for(
            context.tenant, purpose=context.purpose, at=context.at
        )

        role = company = site = None
        resource_owner = label = owner_class = None

        if entry is None:
            effect, allowed, reason = "deny", False, "unknown_person"
        elif entry.company != context.tenant:
            # 身份所属机构与请求租户不一致：拒绝，避免一人跨两边取权限。
            effect, allowed, reason = "deny", False, "tenant_mismatch"
        elif revision is None:
            effect, allowed, reason = "deny", False, "tenant_not_activated"
        else:
            role, company, site = entry.role, entry.company, entry.site
            resource = self.fixtures.directory_view.resource(context.resource)
            if resource is None:
                effect, allowed, reason = "deny", False, "unknown_resource"
            else:
                resource_owner = resource.owner
                label = policy.effective_label(resource.id, resource.label)
                owner_class = owner_class_for(company, resource_owner)
                if self._site_scoped_block(policy, context, label, owner_class,
                                           site, resource.site):
                    effect, allowed, reason = "deny", False, "site_scope_mismatch"
                elif self.setup.paused_capability(
                    context.tenant, context.purpose, role,
                    (context.operation, context.purpose, label, owner_class),
                    resource_id=resource.id,
                ) is not None:
                    # 该能力超出试用核准约定，已暂停复核；其余能力照常办理。
                    effect, allowed, reason = "deny", False, "trial_scope_paused"
                else:
                    effect = policy.evaluate(
                        role, context.operation, context.purpose, label, owner_class
                    )
                    allowed = effect == "allow"
                    reason = effect

        decision = Decision(
            request=context, allowed=allowed, effect=effect, reason=reason,
            role=role, company=company, site=site, resource_owner=resource_owner,
            resource_label=label, owner_class=owner_class, revision=revision,
            proposals=proposals,
            policy_digest=_digest(context, revision, proposals, effect, role),
            recorded_at=now,
        )
        self.audit.record(decision)
        return decision

    def replay_observations(self, now: Optional[int] = None) -> list[Decision]:
        decisions: list[Decision] = []
        for observation in self.fixtures.observations:
            context = RequestContext(
                person=observation.person, tenant=observation.tenant,
                resource=observation.resource, operation=observation.operation,
                purpose=observation.purpose, at=observation.at,
            )
            decisions.append(
                self.evaluate(context, now if now is not None else observation.at)
            )
        return decisions

    def _site_scoped_block(self, policy: Policy, context: RequestContext, label: str,
                           owner_class: str, site: Optional[str],
                           resource_site: str) -> bool:
        if site is None or resource_site == site:
            return False
        conditions = policy.conditions_for(
            (context.operation, context.purpose, label, owner_class)
        )
        # 仅当全部相关条件都要求站点作用域时才阻断；组织级条件不受站点局限。
        return bool(conditions) and all(
            condition.scope == "site" for condition in conditions
        )


def _digest(context: RequestContext, revision: Optional[str],
            proposals: tuple[str, ...], effect: str,
            role: Optional[str]) -> str:
    payload = json.dumps(
        {
            "person": context.person, "tenant": context.tenant,
            "resource": context.resource, "operation": context.operation,
            "purpose": context.purpose, "revision": revision,
            "proposals": proposals, "effect": effect, "role": role,
        },
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
