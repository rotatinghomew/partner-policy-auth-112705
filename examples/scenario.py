"""端到端演练：拟定变更 -> 验证 -> 叠加发现 -> 受控试用 -> 漂移复核 -> 撤回。

运行：
    python3 examples/scenario.py
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agri_policy.model import DirectoryEntry, load_fixtures
from agri_policy.views import Project


def line(title):
    print(f"\n=== {title} ===")


def main() -> None:
    fixtures = load_fixtures(Path(__file__).resolve().parents[1] / "feeds")
    project = Project(fixtures)
    setup = project.setup

    line("拟定变更的授权范围检查")
    for pid, check in setup.checks.items():
        status = "可核准" if check.allowed else "拒绝"
        print(f"{pid} {check.proposal.operation:14s} {status:4s} "
              f"reasons={check.reasons} notes={check.notes}")

    line("主管视角：扩展规则的角色影响（与当前是否有人使用无关）")
    impact = project.supervisor("d-5").impact("pp-2")
    for role, caps in impact["roles_added"].items():
        print(f"{role}: +{[(c['operation'], c['label'], c['owner_class']) for c in caps]}")

    line("安全值班员：两项独立提议叠加后新打开的能力")
    for finding in project.duty_officer("d-5").stacked_risks():
        print("proposals:", finding["proposals"], "basis:", finding["shared_basis"])
        for cap in finding["new_capabilities"]:
            print("  ", cap["operation"], cap["purpose"], cap["label"],
                  cap["owner_class"], "->", cap["roles"])

    line("受控试用：只对 coop-a 的 settle 用途放量")
    setup.approve("pp-1")
    trial = setup.request_trial("pp-4", "coop-a", "settle", now=27)
    setup.start_trial(trial.id, now=29)
    print("trial state:", trial.state)
    for tenant, purpose in (("coop-a", "settle"), ("coop-b", "settle"),
                            ("coop-a", "inspect")):
        _, applied = setup.policy_for(tenant, purpose=purpose, at=30)
        print(f"  tenant={tenant} purpose={purpose} applied={applied}")

    line("接口请求与决定留存")
    for person, tenant, resource, operation, purpose in (
        ("u4", "coop-a", "rs-1", "read", "settle"),
        ("u4", "coop-b", "rs-1", "read", "settle"),   # 身份与租户不一致
        ("u7", "coop-b", "rs-2", "read", "settle"),
    ):
        decision = project.request(person, tenant, resource, operation, purpose, at=30)
        print(f"  {person}/{tenant} {resource} {operation}/{purpose} "
              f"-> {decision.effect} ({decision.reason}) rev={decision.revision}")

    line("独立修改标签后的漂移复核：只暂停变化的部分")
    fixtures.directory_view.set_label("rs-3", "own")
    for report in setup.drift_check(now=34):
        print("  decision:", report["decision"], "exceeded roles:",
              list(report["exceeded"]))
    paused = project.request("u4", "coop-a", "rs-3", "read", "settle", at=35)
    running = project.request("u4", "coop-a", "rs-1", "read", "settle", at=35)
    print("  rs-3（新落入）:", paused.effect, paused.reason)
    print("  rs-1（约定内）:", running.effect, running.reason)

    line("新的目录事实")
    fixtures.directory_view.add_entry(DirectoryEntry(
        id="d-9", person="u99", company="coop-a", site="east",
        role="staged-analyst",
    ))
    report = setup.drift_check(now=36)[0]
    print("  facts_changed:", report["facts_changed"], "decision:", report["decision"])

    line("值班员按角色定位变化来源")
    located = project.duty_officer("d-5").locate("staged-analyst")
    print("  classification:", located["classification"])

    line("撤回：只移除试用新增权利，独立停用保留")
    if setup.checks["pp-5"].allowed:
        setup.apply_independent("pp-5", now=37)
    result = setup.withdraw(trial.id, now=38)
    print("  removed_rights:", result["removed_rights"])
    print("  independent_stops_preserved:", result["independent_stops_preserved"])

    line("已产生的接口决定保留当时的身份、政策与结果")
    for record in project.audit.to_dicts():
        print(f"  {record['person']} {record['resource']} {record['operation']} "
              f"-> {record['effect']} rev={record['revision']} "
              f"digest={record['policy_digest']}")


if __name__ == "__main__":
    main()
