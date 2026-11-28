"""受控试用：核准、按租户与用途放量、漂移复核与撤回。

关键约束：
- 已核定的政策提议不会全局生效。只有当前生效试用覆盖的「租户 + 用途」
  获得其新增权利；其余租户和用途继续使用原政策。
- 核准时记录约定范围：每个角色当时获得的能力集合与目录/标签事实指纹。
  事实后来被独立修改时，按能力重算试用作用范围，超出约定的能力进入复核，
  仍落在约定内的能力继续办理。漂移判定只看事实与能力，不参考是否观察到
  访问——没被访问过不等于仍然安全。
- 撤回只摘除该试用自身的叠加，不清除独立批准的政策变化；因此一项独立
  决定要停用的访问不会随撤回恢复。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .model import FixtureSet, Overlay, Policy
from .scope import ProposalCheck, ScopeResolver


Capability = tuple[str, str, str, str]  # operation, purpose, label, owner_class
ResourceAccess = tuple[str, str]        # resource_id, operation


@dataclass
class Trial:
    id: str
    proposal: str
    target: str
    tenant: str
    purpose: str
    state: str
    revision: str
    at: int
    approved_capabilities: dict[str, set[Capability]] = field(default_factory=dict)
    approved_surface: dict[str, set[ResourceAccess]] = field(default_factory=dict)
    approved_roles: tuple[str, ...] = ()
    facts_version: tuple = ()
    paused_reason: Optional[str] = None
    paused_capabilities: dict[str, set[Capability]] = field(default_factory=dict)
    paused_surface: dict[str, set[ResourceAccess]] = field(default_factory=dict)

    @property
    def running(self) -> bool:
        return self.state == "active"

    @property
    def partly_paused(self) -> bool:
        return self.state == "paused" and bool(
            self.paused_capabilities or self.paused_surface
        )

    def within_agreement(self, role: Optional[str], capability: Capability,
                         resource_id: Optional[str] = None) -> bool:
        if role is None:
            return False
        if role not in self.approved_roles:
            return False
        if capability not in self.approved_capabilities.get(role, set()):
            # 能力的 label/owner_class 可能未变，但具体资源是新落入的。
            if resource_id is None:
                return False
            access = (resource_id, capability[0])
            if access not in self.approved_surface.get(role, set()):
                return False
        return True


class Setup:
    """一个可继续操作的项目：核准、试用、复核、撤回都记录在同一历史里。"""

    def __init__(self, fixtures: FixtureSet, resolver: ScopeResolver) -> None:
        self.fixtures = fixtures
        self.resolver = resolver
        self.checks: dict[str, ProposalCheck] = {}
        self.trials: dict[str, Trial] = {}
        self.independent: list[tuple[str, Overlay]] = []
        self.history: list[dict] = []
        self._revisions: dict[str, str] = {}
        self._seed_revisions()
        for proposal in fixtures.proposals:
            self.checks[proposal.id] = resolver.check(proposal)

    # -- 基础政策 --------------------------------------------------------- #

    def _seed_revisions(self) -> None:
        for activation in sorted(self.fixtures.activations, key=lambda a: a.at):
            self._revisions[activation.tenant] = activation.revision

    def revision_of(self, tenant: str) -> Optional[str]:
        return self._revisions.get(tenant)

    def independent_overlays(self) -> tuple[Overlay, ...]:
        return tuple(overlay for _, overlay in self.independent)

    def base_policy(self) -> Policy:
        return self.fixtures.base_policy().with_overlays(*self.independent_overlays())

    # -- 政策提议 --------------------------------------------------------- #

    def check(self, proposal_id: str) -> ProposalCheck:
        check = self.checks.get(proposal_id)
        if check is None:
            raise KeyError(f"unknown proposal: {proposal_id}")
        return check

    def approve(self, proposal_id: str, now: int = 0) -> ProposalCheck:
        check = self.check(proposal_id)
        if check.kind == "pilot":
            raise ValueError("pilot proposals go through request_trial")
        if check.allowed:
            self.history.append({
                "event": "approve", "proposal": proposal_id,
                "actor": check.proposal.actor, "at": now,
            })
        return check

    def apply_independent(self, proposal_id: str, now: int = 0) -> ProposalCheck:
        """把独立核准的政策变更并入基础政策；已有试用的约定范围保持不变。"""
        check = self.check(proposal_id)
        if not check.allowed:
            raise ValueError(f"proposal not authorized: {proposal_id}")
        if check.overlay.empty:
            raise ValueError(f"proposal has no policy effect: {proposal_id}")
        if proposal_id in [pid for pid, _ in self.independent]:
            return check
        self.independent.append((proposal_id, check.overlay))
        self.history.append({
            "event": "independent_change", "proposal": proposal_id,
            "actor": check.proposal.actor, "at": now,
        })
        return check

    def advance_verified(self, proposal_ids, now: int = 0) -> dict:
        """只推进经过核定的部分。

        先做两两叠加分析；参与任何叠加放大能力的提议转入单独复核，
        不并入政策。其余可核准的提议照常推进。
        """
        from .impact import combined_analysis

        wanted = list(proposal_ids)
        checks = [self.checks[pid] for pid in wanted if pid in self.checks]
        findings = combined_analysis(self.fixtures, checks)
        flagged: set[str] = set()
        for finding in findings:
            flagged.update(finding["proposals"])
        advanced: list[str] = []
        blocked: dict[str, str] = {}
        for check in checks:
            pid = check.proposal.id
            if not check.allowed or check.overlay.empty:
                blocked[pid] = "not_authorized_or_no_effect"
                continue
            if pid in flagged:
                blocked[pid] = "stacked_risk_requires_review"
                continue
            self.apply_independent(pid, now=now)
            advanced.append(pid)
        self.history.append({
            "event": "advance_verified", "at": now,
            "advanced": advanced, "blocked": blocked,
        })
        return {
            "advanced": advanced,
            "blocked": blocked,
            "stacked_findings": findings,
        }

    # -- 试用 ------------------------------------------------------------- #

    def request_trial(self, pilot_id: str, tenant: str, purpose: str,
                      now: int = 0) -> Trial:
        check = self.check(pilot_id)
        if check.kind != "pilot":
            raise ValueError(f"{pilot_id} is not a pilot proposal")
        if not check.allowed:
            raise PermissionError(f"pilot not authorized: {check.reasons}")
        trial_id = f"trial:{pilot_id}:{tenant}:{purpose}"
        if trial_id in self.trials:
            return self.trials[trial_id]
        trial = Trial(
            id=trial_id, proposal=pilot_id, target=check.proposal.target,
            tenant=tenant, purpose=purpose, state="requested",
            revision=self.revision_of(tenant) or "unknown", at=now,
        )
        self.trials[trial_id] = trial
        self.history.append({
            "event": "trial_requested", "trial": trial_id, "proposal": pilot_id,
            "tenant": tenant, "purpose": purpose, "at": now,
        })
        return trial

    def start_trial(self, trial_id: str, now: int = 0) -> Trial:
        trial = self.trials[trial_id]
        if trial.state not in ("requested", "paused"):
            raise ValueError(f"cannot start trial in state {trial.state}")
        if not self.base_policy().edge_ids() and not self.fixtures.base_policy().edge_ids():
            raise ValueError("no policy basis")
        self._snapshot_agreement(trial)
        trial.state = "active"
        trial.paused_reason = None
        self.history.append({
            "event": "trial_started", "trial": trial.id, "at": now,
            "approved_roles": list(trial.approved_roles),
        })
        return trial

    def _snapshot_agreement(self, trial: Trial) -> None:
        policy = self.base_policy().with_overlays(self._target_overlay(trial))
        roles = policy.all_roles()
        trial.approved_roles = tuple(sorted(roles))
        trial.approved_capabilities = {
            role: policy.capability_tuples(role) for role in roles
        }
        trial.approved_surface = {
            role: self._surface_of(policy, role,
                                   trial.approved_capabilities[role],
                                   trial.tenant)
            for role in roles
        }
        trial.facts_version = self.fixtures.directory_view.facts_version()

    def _surface_of(self, policy: Policy, role: str,
                    capabilities: set[Capability], tenant: str) -> set[ResourceAccess]:
        """把抽象能力落实到当前目录与标签下的具体资源访问面。"""
        surface: set[ResourceAccess] = set()
        for resource in self.fixtures.directory_view.resources:
            label = policy.effective_label(resource.id, resource.label)
            owner_class = "request_org" if resource.owner == tenant else (
                "other_org" if resource.owner else "unknown"
            )
            for capability in capabilities:
                operation, purpose, cap_label, cap_owner = capability
                if (label, owner_class) != (cap_label, cap_owner):
                    continue
                if policy.evaluate(role, operation, purpose, label, owner_class) != "allow":
                    continue
                surface.add((resource.id, operation))
        return surface

    def _target_overlay(self, trial: Trial) -> Overlay:
        target = self.checks.get(trial.target)
        return target.overlay if target else Overlay(proposal_id=trial.target)

    def active_trials(self, tenant: str, purpose: Optional[str] = None,
                      at: Optional[int] = None) -> list[Trial]:
        """当前仍对租户应用试用的记录。

        部分暂停的试用仍在名单里：它依旧提供核准时落在约定内的能力，
        只有作用发生变化的能力会在请求求值时被单独暂停。
        """
        result = []
        for trial in self.trials.values():
            if trial.tenant != tenant:
                continue
            if trial.state not in ("active", "paused"):
                continue
            if trial.state == "paused" and not trial.paused_capabilities:
                continue
            if purpose is not None and trial.purpose != purpose:
                continue
            if at is not None and at < trial.at:
                continue
            result.append(trial)
        return sorted(result, key=lambda t: t.at)

    def paused_capability(self, tenant: str, purpose: str, role: str,
                          capability: Capability,
                          resource_id: Optional[str] = None) -> Optional[Trial]:
        """若该访问落在某试用已暂停的能力或具体资源上，返回对应试用。"""
        for trial in self.trials.values():
            if trial.tenant != tenant or trial.purpose != purpose:
                continue
            if trial.state != "paused":
                continue
            if capability in trial.paused_capabilities.get(role, set()):
                return trial
            if resource_id is not None and (
                resource_id, capability[0]
            ) in trial.paused_surface.get(role, set()):
                return trial
        return None

    def trial_for(self, trial_id: str) -> Trial:
        return self.trials[trial_id]

    def policy_for(self, tenant: str, purpose: Optional[str] = None,
                   at: Optional[int] = None) -> tuple[Policy, tuple[str, ...]]:
        """租户作用域内的政策：基础政策（含独立变更）+ 匹配租户与用途的生效试用。

        同一份政策不会跨租户或跨用途给出一半权限：非试用租户/用途只拿到
        基础政策，试用也只作用于其被核准的那个用途。
        """
        overlays = list(self.independent_overlays())
        applied: list[str] = []
        for trial in self.active_trials(tenant, purpose=purpose, at=at):
            overlays.append(self._target_overlay(trial))
            applied.append(trial.target)
        return self.fixtures.base_policy().with_overlays(*overlays), tuple(applied)

    # -- 漂移复核 --------------------------------------------------------- #

    def drift_check(self, now: int = 0) -> list[dict]:
        """按能力重算试用作用范围，只暂停超出核准约定的部分。

        落在约定内的能力继续办理；新出现、原约定未涵盖的能力进入暂停复核。
        判定只比较事实与能力，不参考是否观察到访问。
        """
        reports: list[dict] = []
        for trial in self.trials.values():
            if trial.state not in ("active", "paused"):
                continue
            current = self.base_policy().with_overlays(self._target_overlay(trial))
            exceeded: dict[str, list[dict]] = {}
            exceeded_caps: dict[str, set[Capability]] = {}
            exceeded_surface: dict[str, set[ResourceAccess]] = {}
            for role in current.all_roles():
                caps = current.capability_tuples(role)
                extra = caps - trial.approved_capabilities.get(role, set())
                surface = self._surface_of(current, role, caps, trial.tenant)
                new_surface = surface - trial.approved_surface.get(role, set())
                if extra:
                    exceeded_caps[role] = extra
                if new_surface:
                    exceeded_surface[role] = new_surface
                if extra or new_surface:
                    exceeded[role] = {
                        "new_capabilities": [
                            _capability_payload(current, cap) for cap in sorted(extra)
                        ],
                        "new_resource_access": [
                            {"resource": resource, "operation": operation}
                            for resource, operation in sorted(new_surface)
                        ],
                    }
            facts_changed = (
                trial.facts_version != self.fixtures.directory_view.facts_version()
            )
            report = {
                "trial": trial.id,
                "tenant": trial.tenant,
                "purpose": trial.purpose,
                "target": trial.target,
                "facts_changed": facts_changed,
                "exceeded": exceeded,
                "within_agreement": not exceeded,
                "basis": "facts_and_capabilities",
            }
            if exceeded:
                # 只暂停变化的部分；其余能力仍按约定放量。
                trial.state = "paused"
                trial.paused_reason = "scope_exceeded"
                trial.paused_capabilities = exceeded_caps
                trial.paused_surface = exceeded_surface
                self.history.append({
                    "event": "trial_partially_paused", "trial": trial.id,
                    "at": now, "roles": sorted(exceeded),
                })
                report["decision"] = "pause_changed_portion"
            else:
                if trial.state == "paused":
                    trial.state = "active"
                    trial.paused_reason = None
                    trial.paused_capabilities = {}
                    trial.paused_surface = {}
                    self.history.append({
                        "event": "trial_resumed", "trial": trial.id, "at": now,
                    })
                report["decision"] = "continue"
            reports.append(report)
        return reports

    # -- 撤回 ------------------------------------------------------------- #

    def withdraw(self, trial_id: str, now: int = 0) -> dict:
        """撤回试用：只移除该提议自身带来的新增权利。

        独立批准且要停用的访问不随撤回恢复；撤回前后都保存这些停用项。
        """
        trial = self.trials[trial_id]
        if trial.state == "withdrawn":
            raise ValueError("trial already withdrawn")

        # 撤回前：叠加了试用时该角色能力；撤回后：只留独立变更。
        with_trial = self.base_policy().with_overlays(self._target_overlay(trial))
        without_trial = self.base_policy()
        removed_rights: dict[str, list[dict]] = {}
        for role in with_trial.all_roles():
            lost = (with_trial.capability_tuples(role)
                    - without_trial.capability_tuples(role))
            if lost:
                removed_rights[role] = [
                    _capability_payload(with_trial, cap) for cap in sorted(lost)
                ]

        trial.state = "withdrawn"
        trial.paused_capabilities = {}
        trial.paused_surface = {}
        # 独立停用的规则在撤回后仍保持停用；撤回不恢复它们。
        stops = sorted(
            rule.id for rule in self.fixtures.rules
            if with_trial.rule(rule.id) is None and without_trial.rule(rule.id) is None
        )
        self.history.append({
            "event": "trial_withdrawn", "trial": trial.id, "at": now,
            "removed_rights": removed_rights,
            "independent_stops_preserved": stops,
        })
        return {
            "trial": trial.id,
            "state": trial.state,
            "removed_overlay_of": trial.target,
            "removed_rights": removed_rights,
            "independent_stops_preserved": stops,
        }

    # -- 记录 ------------------------------------------------------------- #

    def state(self) -> dict:
        return {
            "proposals": {
                pid: check.as_dict() for pid, check in self.checks.items()
            },
            "trials": {
                trial_id: {
                    "proposal": trial.proposal,
                    "target": trial.target,
                    "tenant": trial.tenant,
                    "purpose": trial.purpose,
                    "state": trial.state,
                    "revision": trial.revision,
                    "paused_reason": trial.paused_reason,
                    "approved_roles": list(trial.approved_roles),
                }
                for trial_id, trial in self.trials.items()
            },
            "independent_changes": [pid for pid, _ in self.independent],
            "history": list(self.history),
        }


def _capability_payload(policy: Policy, key: Capability) -> dict:
    operation, purpose, label, owner_class = key
    conditions = policy.conditions_for(key)
    return {
        "operation": operation,
        "purpose": purpose,
        "label": label,
        "owner_class": owner_class,
        "scopes": sorted({condition.scope for condition in conditions}),
    }
