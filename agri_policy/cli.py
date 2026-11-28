"""命令行入口：把拟定变更、验证与接口实际授权接进一个可继续操作的项目。

用法示例：
    python3 -m agri_policy.cli summary
    python3 -m agri_policy.cli stacked
    python3 -m agri_policy.cli locate --role staged-analyst
    python3 -m agri_policy.cli trial --proposal pp-1 --pilot pp-4 \
        --tenant coop-a --purpose settle
    python3 -m agri_policy.cli request --person u4 --tenant coop-a \
        --resource rs-1 --operation read --purpose settle
"""

from __future__ import annotations

import argparse
import json

from .model import load_fixtures
from .views import Project


def _print(payload) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False))


def build(project: Project, args) -> dict:
    """按命令行给出的顺序推进项目状态，返回需要附加展示的结果。"""
    setup = project.setup
    artifacts: dict = {}
    for proposal_id in args.approve or []:
        setup.approve(proposal_id, now=args.now)
    for proposal_id in args.apply or []:
        setup.apply_independent(proposal_id, now=args.now)
    if args.advance:
        artifacts["advance_verified"] = setup.advance_verified(
            args.advance, now=args.now
        )
    for spec in args.trial or []:
        # spec: pilot_id:tenant:purpose
        pilot_id, tenant, purpose = spec.split(":", 2)
        trial = setup.request_trial(pilot_id, tenant, purpose, now=args.now)
        if not args.request_only:
            setup.start_trial(trial.id, now=args.now)
    for trial_id in args.withdraw or []:
        artifacts["withdraw"] = setup.withdraw(trial_id, now=args.now)
    if args.drift:
        artifacts["drift"] = setup.drift_check(now=args.now)
    return artifacts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agri_policy")
    parser.add_argument("--feeds", default="feeds", help="资料目录")
    parser.add_argument("--now", type=int, default=0)
    parser.add_argument("--approve", action="append", help="核准一项政策提议")
    parser.add_argument("--apply", action="append", help="把独立核准的变更并入政策")
    parser.add_argument("--advance", action="append",
                        help="只推进经过核定的提议（叠加风险项转复核）")
    parser.add_argument("--trial", action="append",
                        help="发起试用 pilot:tenant:purpose")
    parser.add_argument("--request-only", action="store_true",
                        help="只登记试用申请，不开始")
    parser.add_argument("--withdraw", action="append", help="撤回试用 id")
    parser.add_argument("--drift", action="store_true", help="执行漂移复核")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("summary", help="列出提议检查与项目状态")
    sub.add_parser("stacked", help="列出两项提议叠加后打开的授权")

    p_imp = sub.add_parser("impact", help="单项提议的角色视角影响")
    p_imp.add_argument("proposal")

    p_loc = sub.add_parser("locate", help="按角色定位权限变化来源")
    p_loc.add_argument("--role", required=True)
    p_loc.add_argument("--person", help="可选：以某人身份发起一次决定后定位")
    p_loc.add_argument("--tenant")
    p_loc.add_argument("--resource")
    p_loc.add_argument("--operation", default="read")
    p_loc.add_argument("--purpose", default="settle")

    p_req = sub.add_parser("request", help="以合作社身份查询一次业务资料")
    p_req.add_argument("--person", required=True)
    p_req.add_argument("--tenant", required=True)
    p_req.add_argument("--resource", required=True)
    p_req.add_argument("--operation", default="read")
    p_req.add_argument("--purpose", default="settle")

    sub.add_parser("replay", help="回放报表入口的观测记录")
    sub.add_parser("audit", help="导出接口决定审计记录")

    args = parser.parse_args(argv)
    fixtures = load_fixtures(args.feeds)
    project = Project(fixtures)
    artifacts = build(project, args)
    setup = project.setup

    if args.command == "summary":
        _print({
            "proposals": {
                pid: check.as_dict() for pid, check in setup.checks.items()
            },
            "state": setup.state(),
            "operations": artifacts,
        })
    elif args.command == "stacked":
        _print(project.duty_officer("d-5").stacked_risks())
    elif args.command == "impact":
        _print(project.supervisor(setup.check(args.proposal).proposal.actor)
               .impact(args.proposal))
    elif args.command == "locate":
        decision = None
        if args.person:
            decision = project.request(
                args.person, args.tenant, args.resource,
                args.operation, args.purpose, at=args.now,
            )
        _print(project.duty_officer("d-5").locate(args.role, decision))
    elif args.command == "request":
        _print(project.cooperative(args.tenant).query(
            args.person, args.resource, args.operation, args.purpose, at=args.now,
        ))
    elif args.command == "replay":
        _print([d.as_dict() for d in project.engine.replay_observations(now=args.now)])
    elif args.command == "audit":
        _print(project.audit.to_dicts())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
