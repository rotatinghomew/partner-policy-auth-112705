"""领域模型：把各路联调资料装载为可求值的结构化对象。

设计要点：
- 目录（directory）与资源标签（resource_labels）都按来源给出的先后顺序保存，
  取「某一时刻生效」的事实时以 at 为界回放，数组位置只用于同一时刻的陈列顺序。
- 规则、条件域、继承边都是「当前政策资料」的一部分；提议通过叠加层改变它们，
  原始资料不被就地修改，便于比较基线与叠加后的差异。
- 明确的拒绝优先于任何允许（见 Policy.evaluate）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #

def split_csv(value: Any) -> tuple[str, ...]:
    """把来源里逗号连接的字段拆成有序元组；None 表示来源未提供。"""
    if value is None:
        return ()
    if isinstance(value, (tuple, list)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return tuple(part.strip() for part in str(value).split(",") if part.strip())


def owner_class_for(actor_company: Optional[str], resource_owner: Optional[str]) -> str:
    """把资源归属映射到规则使用的 owner_class。未知归属统一视为 unknown。"""
    if resource_owner is None:
        return "unknown"
    if actor_company is not None and resource_owner == actor_company:
        return "request_org"
    return "other_org"


# --------------------------------------------------------------------------- #
# 当前政策资料
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Rule:
    id: str
    role: str
    operation: str
    purpose: str
    label: str
    owner_class: str
    effect: str

    @classmethod
    def from_row(cls, row: dict) -> "Rule":
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class Condition:
    id: str
    operation: str
    purpose: str
    label: str
    owner_class: str
    scope: str

    @classmethod
    def from_row(cls, row: dict) -> "Condition":
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class Edge:
    id: str
    child: str
    parent: str
    owner: str

    @classmethod
    def from_row(cls, row: dict) -> "Edge":
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class DirectoryEntry:
    id: str
    person: str
    company: str
    site: str
    role: str

    @classmethod
    def from_row(cls, row: dict) -> "DirectoryEntry":
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class Resource:
    id: str
    owner: str
    site: str
    label: str

    @classmethod
    def from_row(cls, row: dict) -> "Resource":
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class AdminScope:
    id: str
    actor: str
    company: str
    may_edit: tuple[str, ...]
    stages: tuple[str, ...]

    @classmethod
    def from_row(cls, row: dict) -> "AdminScope":
        return cls(
            id=row["id"],
            actor=row["actor"],
            company=row["company"],
            may_edit=split_csv(row["may_edit"]),
            stages=split_csv(row["stages"]),
        )


@dataclass(frozen=True)
class Proposal:
    id: str
    actor: str
    operation: str
    target: str
    detail: str
    at: int

    @classmethod
    def from_row(cls, row: dict) -> "Proposal":
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class Observation:
    id: str
    person: str
    tenant: str
    resource: str
    operation: str
    purpose: str
    at: int

    @classmethod
    def from_row(cls, row: dict) -> "Observation":
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True)
class Activation:
    id: str
    proposal: str
    tenant: str
    purpose: str
    state: str
    revision: str
    at: int

    @classmethod
    def from_row(cls, row: dict) -> "Activation":
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


# --------------------------------------------------------------------------- #
# 叠加层 --- 提议对政策资料的拟定变化
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Overlay:
    """一项提议对当前政策资料的增量。

    不同提议的同一类增量互相独立地生效；若两项提议依赖同一条继承关系，
    合并时会把两边的新增边一并计入，从而暴露叠加后新打开的能力。
    relabels 是资源标签事实的变更（resource id -> 新标签），不伪造政策规则。
    """

    proposal_id: str
    added_edges: tuple[Edge, ...] = ()
    replaced_edges: tuple[Edge, ...] = ()
    removed_edge_ids: tuple[str, ...] = ()
    added_rules: tuple[Rule, ...] = ()
    removed_rule_ids: tuple[str, ...] = ()
    relabels: tuple[tuple[str, str], ...] = ()

    @property
    def empty(self) -> bool:
        return not (self.added_edges or self.replaced_edges or self.removed_edge_ids
                    or self.added_rules or self.removed_rule_ids or self.relabels)


# --------------------------------------------------------------------------- #
# 政策（基线 + 可选叠加）
# --------------------------------------------------------------------------- #

class Policy:
    """由当前政策资料加上零到多项叠加得到的可求值政策。"""

    def __init__(
        self,
        rules: Iterable[Rule],
        conditions: Iterable[Condition],
        edges: Iterable[Edge],
        overlays: Iterable[Overlay] = (),
    ) -> None:
        self.rules: tuple[Rule, ...] = tuple(rules)
        self.conditions: tuple[Condition, ...] = tuple(conditions)
        self.edges: tuple[Edge, ...] = tuple(edges)
        self.overlays: tuple[Overlay, ...] = tuple(overlays)
        self._index()

    # -- 构建 ------------------------------------------------------------- #

    def _index(self) -> None:
        removed_edges: set[str] = set()
        removed_rules: set[str] = set()
        relabels: dict[str, str] = {}
        edges = list(self.edges)
        replaced: dict[str, Edge] = {}
        rules = list(self.rules)
        seen_edges = {edge.id for edge in edges}
        seen_rules = {rule.id for rule in rules}

        for overlay in self.overlays:
            removed_edges.update(overlay.removed_edge_ids)
            removed_rules.update(overlay.removed_rule_ids)
            for resource_id, label in overlay.relabels:
                relabels[resource_id] = label
            for edge in overlay.replaced_edges:
                replaced[edge.id] = edge
            for edge in overlay.added_edges:
                # 同一 id 的边重复加入时以最先声明为准，避免叠加造成伪影。
                if edge.id not in seen_edges:
                    edges.append(edge)
                    seen_edges.add(edge.id)
            for rule in overlay.added_rules:
                if rule.id not in seen_rules:
                    rules.append(rule)
                    seen_rules.add(rule.id)

        self._relabels: dict[str, str] = dict(relabels)

        self._edges: tuple[Edge, ...] = tuple(
            replaced.get(edge.id, edge)
            for edge in edges
            if edge.id not in removed_edges
        )
        self._rules: tuple[Rule, ...] = tuple(
            rule for rule in rules if rule.id not in removed_rules
        )

        # 继承闭包：role -> 它可直接或间接继承到的祖先角色集合。
        parents: dict[str, set[str]] = {}
        for edge in self._edges:
            parents.setdefault(edge.child, set()).add(edge.parent)
        closure: dict[str, set[str]] = {}

        def ancestors(role: str, stack: tuple[str, ...] = ()) -> set[str]:
            if role in closure:
                return closure[role]
            if role in stack:  # 防御环；正常资料不会有环
                return set()
            result: set[str] = set()
            for parent in parents.get(role, ()):
                result.add(parent)
                result |= ancestors(parent, stack + (role,))
            closure[role] = result
            return result

        for edge in self._edges:
            ancestors(edge.child)
        self._parents = parents
        self._ancestors = closure

        # 规则按 role 索引（包含自身角色）。
        self._rules_by_role: dict[str, list[Rule]] = {}
        for rule in self._rules:
            self._rules_by_role.setdefault(rule.role, []).append(rule)

    # -- 查询 ------------------------------------------------------------- #

    def with_overlays(self, *overlays: Overlay) -> "Policy":
        return Policy(self.rules, self.conditions, self.edges,
                      self.overlays + tuple(overlays))

    def roles_of(self, role: str) -> tuple[str, ...]:
        """一个角色在继承闭包下实际获得其规则的角色集合（含自身）。"""
        return (role,) + tuple(sorted(self._ancestors.get(role, set())))

    def effective_rules(self, role: str) -> tuple[Rule, ...]:
        collected: list[Rule] = []
        for effective in self.roles_of(role):
            collected.extend(self._rules_by_role.get(effective, ()))
        return tuple(collected)

    def declared(self, operation: str, purpose: str, label: str,
                 owner_class: str) -> bool:
        return any(
            condition.operation == operation
            and condition.purpose == purpose
            and condition.label == label
            and condition.owner_class == owner_class
            for condition in self.conditions
        )

    def evaluate(
        self,
        role: str,
        operation: str,
        purpose: str,
        label: str,
        owner_class: str,
    ) -> str:
        """返回 allow / deny / undefined。

        - 任何一条生效的 deny 都压过 allow（明确拒绝优先）。
        - 没有命中任何规则，或未落在已登记的条件域中，均为 undefined。
        - unknown 标签只有在明确为 unknown 状态授权（即存在对应 allow 规则）时才可用；
          条件域只把这种情况登记为合法，不会替它补出授权。
        """
        if not self.declared(operation, purpose, label, owner_class):
            return "undefined"
        matched = [
            rule for rule in self.effective_rules(role)
            if rule.operation == operation
            and rule.purpose == purpose
            and rule.label == label
            and rule.owner_class == owner_class
        ]
        if any(rule.effect == "deny" for rule in matched):
            return "deny"
        if any(rule.effect == "allow" for rule in matched):
            return "allow"
        return "undefined"

    # -- 能力枚举 --------------------------------------------------------- #

    def capability_tuples(self, role: str) -> set[tuple[str, str, str, str]]:
        """角色在当前政策下被允许的 (operation, purpose, label, owner_class) 集合。"""
        allowed: set[tuple[str, str, str, str]] = set()
        for rule in self.effective_rules(role):
            if rule.effect != "allow":
                continue
            key = (rule.operation, rule.purpose, rule.label, rule.owner_class)
            if self.evaluate(role, *key) == "allow":
                allowed.add(key)
        return allowed

    def conditions_for(
        self, key: tuple[str, str, str, str]
    ) -> tuple[Condition, ...]:
        operation, purpose, label, owner_class = key
        return tuple(
            condition for condition in self.conditions
            if condition.operation == operation
            and condition.purpose == purpose
            and condition.label == label
            and condition.owner_class == owner_class
        )

    def rule_ids(self) -> set[str]:
        return {rule.id for rule in self._rules}

    def effective_label(self, resource_id: str, current_label: str) -> str:
        """叠加层带来的资源标签变化优先于接口实际登记的标签。"""
        return self._relabels.get(resource_id, current_label)

    def has_relabel(self, resource_id: str) -> bool:
        return resource_id in self._relabels

    def roles_allowing(self, key: tuple[str, str, str, str]) -> tuple[str, ...]:
        """在当前政策下，哪些角色实际获得该能力。"""
        return tuple(
            role for role in self.all_roles()
            if self.evaluate(role, *key) == "allow"
        )

    def edge_ids(self) -> set[str]:
        return {edge.id for edge in self._edges}

    def rule(self, rule_id: str) -> Optional[Rule]:
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    def edge(self, edge_id: str) -> Optional[Edge]:
        for edge in self._edges:
            if edge.id == edge_id:
                return edge
        return None

    def all_roles(self) -> tuple[str, ...]:
        roles: set[str] = set()
        for rule in self._rules:
            roles.add(rule.role)
        for edge in self._edges:
            roles.add(edge.child)
            roles.add(edge.parent)
        return tuple(sorted(roles))


# --------------------------------------------------------------------------- #
# 目录视图 --- 某一时刻的事实快照
# --------------------------------------------------------------------------- #

class DirectoryView:
    """按时刻回放目录与资源标签，回答「当时谁是哪个角色、资源归属给谁」。

    支持追加新的目录事实（新人员、新资源、标签变更）。追加不会改写既有条目，
    但会改变事实指纹，从而让已核准试用的漂移复核感知到「新的目录事实」。
    """

    def __init__(self, entries: Iterable[DirectoryEntry],
                 resources: Iterable[Resource]) -> None:
        self.entries: list[DirectoryEntry] = list(entries)
        self.resources: list[Resource] = list(resources)
        self._reindex()

    def _reindex(self) -> None:
        self._by_person = {entry.person: entry for entry in self.entries}
        self._by_id = {entry.id: entry for entry in self.entries}
        self._resource_by_id = {resource.id: resource for resource in self.resources}

    def person(self, person: str) -> Optional[DirectoryEntry]:
        return self._by_person.get(person)

    def entry(self, entry_id: str) -> Optional[DirectoryEntry]:
        return self._by_id.get(entry_id)

    def resource(self, resource_id: str) -> Optional[Resource]:
        return self._resource_by_id.get(resource_id)

    # -- 追加事实 --------------------------------------------------------- #

    def add_entry(self, entry: DirectoryEntry) -> DirectoryEntry:
        if entry.person in self._by_person:
            raise ValueError(f"person already present: {entry.person}")
        self.entries.append(entry)
        self._reindex()
        return entry

    def add_resource(self, resource: Resource) -> Resource:
        if resource.id in self._resource_by_id:
            raise ValueError(f"resource already present: {resource.id}")
        self.resources.append(resource)
        self._reindex()
        return resource

    def set_label(self, resource_id: str, label: str) -> Resource:
        resource = self._resource_by_id.get(resource_id)
        if resource is None:
            raise KeyError(f"unknown resource: {resource_id}")
        updated = Resource(id=resource.id, owner=resource.owner,
                           site=resource.site, label=label)
        index = self.resources.index(resource)
        self.resources[index] = updated
        self._reindex()
        return updated

    def at(self, minute: int) -> "Snapshot":
        return Snapshot(self, minute)

    def facts_version(self) -> tuple:
        """用于判定目录事实是否变化的内容指纹。"""
        return tuple(
            (entry.id, entry.person, entry.company, entry.site, entry.role)
            for entry in self.entries
        ) + tuple(
            (resource.id, resource.owner, resource.site, resource.label)
            for resource in self.resources
        )


class Snapshot:
    """某一时刻的只读事实视图。"""

    def __init__(self, view: DirectoryView, minute: int) -> None:
        self.view = view
        self.minute = minute

    def person(self, person: str) -> Optional[DirectoryEntry]:
        return self.view.person(person)

    def entry(self, entry_id: str) -> Optional[DirectoryEntry]:
        return self.view.entry(entry_id)

    def resource(self, resource_id: str) -> Optional[Resource]:
        return self.view.resource(resource_id)


# --------------------------------------------------------------------------- #
# 装载
# --------------------------------------------------------------------------- #

class FixtureSet:
    """一套装载好的联调资料及其原始行。"""

    def __init__(self, rows: dict[str, list[dict]]) -> None:
        self.rows = rows
        self.rules = [Rule.from_row(row) for row in rows["rules"]]
        self.conditions = [Condition.from_row(row) for row in rows["condition_domain"]]
        self.edges = [Edge.from_row(row) for row in rows["edges"]]
        self.scopes = [AdminScope.from_row(row) for row in rows["admin_scopes"]]
        self.proposals = [Proposal.from_row(row) for row in rows["proposals"]]
        self.observations = [Observation.from_row(row) for row in rows["observations"]]
        self.activations = [Activation.from_row(row) for row in rows["activations"]]
        self.index = rows.get("index", {})
        self.directory_view = DirectoryView(
            [DirectoryEntry.from_row(row) for row in rows["directory"]],
            [Resource.from_row(row) for row in rows["resource_labels"]],
        )

    @property
    def directory(self) -> list[DirectoryEntry]:
        return self.directory_view.entries

    @property
    def resources(self) -> list[Resource]:
        return self.directory_view.resources

    def base_policy(self) -> Policy:
        return Policy(self.rules, self.conditions, self.edges)

    def proposal(self, proposal_id: str) -> Optional[Proposal]:
        for proposal in self.proposals:
            if proposal.id == proposal_id:
                return proposal
        return None


def load_fixtures(directory: str | Path) -> FixtureSet:
    directory = Path(directory)
    rows: dict[str, list[dict]] = {}
    for name in (
        "directory", "condition_domain", "rules", "edges", "admin_scopes",
        "proposals", "resource_labels", "observations", "activations",
    ):
        path = directory / f"{name}.json"
        rows[name] = json.loads(path.read_text(encoding="utf-8"))
    index_path = directory / "index.json"
    rows["index"] = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else {}
    return FixtureSet(rows)
