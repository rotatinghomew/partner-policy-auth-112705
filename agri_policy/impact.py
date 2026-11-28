"""提议影响分析。

两项判断与「当前恰好谁在用」解耦：

- 角色视角差异：遍历政策里的全部角色，比较基线与叠加后的能力集合。
  即使当下没有任何人持有某角色，或某个资源还没贴某个标签，只要提议让
  获准角色在已声明的条件域里取得原本没有的能力，就必须报出来。
- 叠加分析：对两两独立提交的政策提议，比较「各自单独 + 合并」三种结果。
  合并后新出现、而任一单独提议都不产生的能力，即为依赖同一条继承关系才
  打开的叠加授权，报告它指向的角色、操作与资源类别。
"""

from __future__ import annotations

from itertools import combinations
from typing import Iterable, Optional

from .model import FixtureSet, Policy
from .scope import ProposalCheck


Capability = tuple[str, str, str, str]  # operation, purpose, label, owner_class


def _capability_dict(policy: Policy, key: Capability) -> dict:
    operation, purpose, label, owner_class = key
    conditions = policy.conditions_for(key)
    return {
        "operation": operation,
        "purpose": purpose,
        "label": label,
        "owner_class": owner_class,
        "declared": bool(conditions),
        "scopes": sorted({condition.scope for condition in conditions}),
    }


def role_capability_diff(base: Policy, stacked: Policy) -> dict[str, dict]:
    """比较全部角色在基线与叠加后的能力差异。"""
    roles = set(base.all_roles()) | set(stacked.all_roles())
    added: dict[str, set[Capability]] = {}
    removed: dict[str, set[Capability]] = {}
    for role in roles:
        before = base.capability_tuples(role)
        after = stacked.capability_tuples(role)
        if after - before:
            added[role] = after - before
        if before - after:
            removed[role] = before - after

    def pack(bucket: dict[str, set[Capability]]) -> dict:
        result: dict[str, list[dict]] = {}
        for role, capabilities in sorted(bucket.items()):
            result[role] = [
                _capability_dict(stacked, key) for key in sorted(capabilities)
            ]
        return result

    return {"added": pack(added), "removed": pack(removed)}


def _roles_with(policy: Policy, key: Capability) -> list[str]:
    return list(policy.roles_allowing(key))


def combined_analysis(
    fixtures: FixtureSet,
    checks: Iterable[ProposalCheck],
    limit: Optional[int] = None,
) -> list[dict]:
    """找出两两叠加后才打开的授权。"""
    base = fixtures.base_policy()
    baseline = {role: base.capability_tuples(role) for role in base.all_roles()}
    candidates = [
        check for check in checks
        if check.allowed and check.kind == "policy" and not check.overlay.empty
    ]
    findings: list[dict] = []
    for left, right in combinations(candidates, 2):
        if limit is not None and len(findings) >= limit:
            break
        solo_left = base.with_overlays(left.overlay)
        solo_right = base.with_overlays(right.overlay)
        together = base.with_overlays(left.overlay, right.overlay)

        gained_left: dict[str, set[Capability]] = {}
        gained_right: dict[str, set[Capability]] = {}
        gained_both: dict[str, set[Capability]] = {}
        roles = set(base.all_roles()) | set(together.all_roles())
        for role in roles:
            before = baseline.get(role, set())
            gained_left[role] = solo_left.capability_tuples(role) - before
            gained_right[role] = solo_right.capability_tuples(role) - before
            gained_both[role] = together.capability_tuples(role) - before

        new_caps: dict[Capability, list[str]] = {}
        for role, capabilities in gained_both.items():
            solo = gained_left.get(role, set()) | gained_right.get(role, set())
            for capability in capabilities - solo:
                new_caps.setdefault(capability, []).append(role)

        if not new_caps:
            continue
        findings.append({
            "proposals": [left.proposal.id, right.proposal.id],
            "shared_basis": _shared_basis(left, right),
            "new_capabilities": [
                {
                    **_capability_dict(together, capability),
                    "roles": sorted(new_caps[capability]),
                    "solo_roles": {
                        left.proposal.id: sorted(
                            r for r, caps in gained_left.items()
                            if capability in caps
                        ),
                        right.proposal.id: sorted(
                            r for r, caps in gained_right.items()
                            if capability in caps
                        ),
                    },
                }
                for capability in sorted(new_caps)
            ],
        })
    return findings


def _shared_basis(left: ProposalCheck, right: ProposalCheck) -> list[str]:
    """说明两项提议为何会叠加：共同涉及的继承边或角色链。"""
    reasons: list[str] = []

    def edge_roles(check: ProposalCheck) -> set[str]:
        roles: set[str] = set()
        for edge in check.overlay.added_edges:
            roles.add(edge.child)
            roles.add(edge.parent)
        return roles

    left_roles = edge_roles(left)
    right_roles = edge_roles(right)
    shared = left_roles & right_roles
    if shared:
        reasons.append("common_edge_role:" + ",".join(sorted(shared)))

    # 一项提议新增的继承边指向的角色，恰是另一项提议新增/扩展规则的角色。
    def rule_roles(check: ProposalCheck) -> set[str]:
        return {rule.role for rule in check.overlay.added_rules}

    if rule_roles(right) & left_roles:
        reasons.append(
            "rule_targets_edge_child:" + ",".join(sorted(rule_roles(right) & left_roles))
        )
    if rule_roles(left) & right_roles:
        reasons.append(
            "rule_targets_edge_child:" + ",".join(sorted(rule_roles(left) & right_roles))
        )
    if not reasons:
        reasons.append("independent_overlays_combine")
    return reasons


def undeclared_capabilities(base: Policy, stacked: Policy) -> list[dict]:
    """报告叠加后出现、但不在条件域登记内的能力（应为空）。"""
    result: list[dict] = []
    roles = set(base.all_roles()) | set(stacked.all_roles())
    for role in sorted(roles):
        for key in sorted(stacked.capability_tuples(role) - base.capability_tuples(role)):
            if not stacked.declared(*key):
                result.append({"role": role, **_capability_dict(stacked, key)})
    return result


def current_user_diff(fixtures: FixtureSet, base: Policy, stacked: Policy) -> dict:
    """当前实际用户视角的差异：他们现在能做什么、提议后会多做什么。

    这只是一个辅助视角，不能替代角色视角——没人使用的角色、尚未贴标签的
    资源同样可能在提议后取得能力。
    """
    added: dict[str, list[dict]] = {}
    removed: dict[str, list[dict]] = {}
    for entry in fixtures.directory:
        before = base.capability_tuples(entry.role)
        after = stacked.capability_tuples(entry.role)
        gained = after - before
        lost = before - after
        if gained:
            added[entry.person] = [
                {"role": entry.role, **_capability_dict(stacked, cap)}
                for cap in sorted(gained)
            ]
        if lost:
            removed[entry.person] = [
                {"role": entry.role, **_capability_dict(stacked, cap)}
                for cap in sorted(lost)
            ]
    return {"added": added, "removed": removed}


def single_impact(fixtures: FixtureSet, check: ProposalCheck) -> dict:
    """一项提议的角色视角影响、当前用户差异，以及条件域验证结果。"""
    base = fixtures.base_policy()
    stacked = base.with_overlays(check.overlay)
    diff = role_capability_diff(base, stacked)
    users = current_user_diff(fixtures, base, stacked)
    undeclared = undeclared_capabilities(base, stacked)
    return {
        "proposal": check.proposal.id,
        "allowed": check.allowed,
        "reasons": check.reasons,
        "notes": check.notes,
        "roles_added": diff["added"],
        "roles_removed": diff["removed"],
        "current_users_added": users["added"],
        "current_users_removed": users["removed"],
        "undeclared_capabilities": undeclared,
        "role_view_is_authoritative": True,
    }
