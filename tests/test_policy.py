"""政策求值、管理员范围、叠加分析、试用与请求链路的回归测试。"""

import json
import unittest
from pathlib import Path

from agri_policy.impact import combined_analysis, single_impact
from agri_policy.model import (
    DirectoryEntry,
    Proposal,
    Resource,
    load_fixtures,
)
from agri_policy.scope import ScopeResolver
from agri_policy.views import Project

ROOT = Path(__file__).resolve().parents[1]
FEEDS = ROOT / "feeds"


class PolicyEvaluationTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = load_fixtures(FEEDS)
        self.policy = self.fixtures.base_policy()

    def test_explicit_deny_beats_allow(self):
        # ru-4 拒绝 regional-auditor 的 approve/settle/partner；
        # 既使有权继承的允许规则也不能越过显式拒绝。
        self.assertEqual(
            self.policy.evaluate(
                "regional-auditor", "approve", "settle", "partner", "other_org"
            ),
            "deny",
        )

    def test_inheritance_grants_parent_rules(self):
        self.assertEqual(
            self.policy.evaluate("report-editor", "read", "settle", "own", "request_org"),
            "allow",
        )

    def test_unknown_label_only_with_explicit_authorization(self):
        # public-list 明确被授予 unknown 状态；report-reader 没有。
        self.assertEqual(
            self.policy.evaluate("public-list", "read", "settle", "unknown", "unknown"),
            "allow",
        )
        self.assertEqual(
            self.policy.evaluate("report-reader", "read", "settle", "unknown", "unknown"),
            "undefined",
        )

    def test_undeclared_condition_is_undefined(self):
        self.assertEqual(
            self.policy.evaluate("report-reader", "approve", "settle", "own", "request_org"),
            "undefined",
        )


class AdminScopeTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = load_fixtures(FEEDS)
        self.resolver = ScopeResolver(self.fixtures)

    def _check(self, actor, operation, target, detail):
        return self.resolver.check(Proposal(
            id="px", actor=actor, operation=operation, target=target, detail=detail, at=0,
        ))

    def test_admin_edits_users_and_labels(self):
        allowed = self._check("d-3", "assign_role", "u4", "report-editor")
        self.assertTrue(allowed.allowed, allowed.reasons)
        denied = self._check("d-3", "tag_resource", "rs-1", "own,coop-a")
        self.assertTrue(denied.allowed, denied.reasons)

    def test_admin_cannot_cross_company_role(self):
        # 把 coop-a 的报表账号变成 coop-b 的报表管理员，必须拒绝。
        denied = self._check("d-3", "assign_role", "u4", "admin-b")
        self.assertFalse(denied.allowed)
        self.assertTrue(any(r.startswith("cross_company_role") for r in denied.reasons))

    def test_admin_cannot_edit_foreign_resource(self):
        denied = self._check("d-3", "tag_resource", "rs-2", "own,coop-a")
        self.assertFalse(denied.allowed)

    def test_admin_cannot_edit_rules(self):
        denied = self._check("d-3", "expand_rule", "ru-2", "partner,other_org")
        self.assertFalse(denied.allowed)
        self.assertTrue(any(r.startswith("may_not_edit") for r in denied.reasons))

    def test_security_can_edit_but_respects_condition_domain(self):
        ok = self._check("d-5", "expand_rule", "ru-2", "partner,other_org")
        self.assertTrue(ok.allowed, ok.reasons)
        bad = self._check("d-5", "expand_rule", "ru-2", "secret,other_org")
        self.assertFalse(bad.allowed)
        self.assertTrue(any(r.startswith("outside_condition_domain") for r in bad.reasons))


class ImpactTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = load_fixtures(FEEDS)
        self.resolver = ScopeResolver(self.fixtures)

    def test_expand_rule_seen_from_role_not_current_users(self):
        # 条件域里的 partner 标签当前还没贴到 coop-b 的资源上，但扩展规则仍
        # 让 report-editor 取得原本没有的能力，必须报告，与当前是否有人使用无关。
        check = self.resolver.check(self.fixtures.proposal("pp-2"))
        impact = single_impact(self.fixtures, check)
        added = impact["roles_added"]
        self.assertIn("report-editor", added)
        caps = {(c["operation"], c["purpose"], c["label"]) for c in added["report-editor"]}
        self.assertIn(("approve", "settle", "partner"), caps)
        # 当前实际用户差异是辅助视角：u4（report-reader）不应被误报获得该扩展。
        self.assertNotIn("u4", impact["current_users_added"])

    def test_stacked_capability_from_shared_inheritance(self):
        checks = [self.resolver.check(p) for p in self.fixtures.proposals]
        findings = combined_analysis(self.fixtures, checks)
        pair = next(f for f in findings if set(f["proposals"]) == {"pp-1", "pp-2"})
        caps = pair["new_capabilities"]
        self.assertTrue(caps)
        cap = caps[0]
        self.assertEqual(
            (cap["operation"], cap["purpose"], cap["label"], cap["owner_class"]),
            ("approve", "settle", "partner", "other_org"),
        )
        self.assertIn("staged-analyst", cap["roles"])
        # 单独提交时覆盖率不同：pp-2 只让 report-editor 获得。
        self.assertNotIn("staged-analyst", cap["solo_roles"]["pp-2"])

    def test_stacked_findings_are_declared_conditions(self):
        checks = [self.resolver.check(p) for p in self.fixtures.proposals]
        for finding in combined_analysis(self.fixtures, checks):
            for cap in finding["new_capabilities"]:
                self.assertTrue(cap["declared"])


class AdvanceVerifiedTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = load_fixtures(FEEDS)
        self.project = Project(self.fixtures)
        self.setup = self.project.setup

    def test_only_verified_parts_advance(self):
        # pp-1 与 pp-2 叠加会放大，二者转入复核；pp-5 与它们无叠加，照常推进。
        result = self.setup.advance_verified(["pp-1", "pp-2", "pp-5"], now=40)
        self.assertEqual(result["blocked"]["pp-1"], "stacked_risk_requires_review")
        self.assertEqual(result["blocked"]["pp-2"], "stacked_risk_requires_review")
        self.assertIn("pp-5", result["advanced"])
        applied = [pid for pid, _ in self.setup.independent]
        self.assertIn("pp-5", applied)
        self.assertNotIn("pp-1", applied)
        self.assertNotIn("pp-2", applied)

    def test_rejected_proposal_never_advances(self):
        result = self.setup.advance_verified(["pp-3"], now=40)
        self.assertEqual(result["blocked"]["pp-3"], "not_authorized_or_no_effect")


class TrialTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = load_fixtures(FEEDS)
        self.project = Project(self.fixtures)
        self.setup = self.project.setup
        self.setup.approve("pp-1")
        self.trial = self.setup.request_trial("pp-4", "coop-a", "settle", now=27)
        self.setup.start_trial(self.trial.id, now=29)

    def test_trial_only_affects_approved_tenant_and_purpose(self):
        base = self.fixtures.base_policy()
        # coop-a 的 settle 试用借由新增继承边放量；coop-b 不变。
        self.assertTrue(base.evaluate("staged-analyst", "approve", "settle", "own",
                                      "request_org"))
        # coop-b 没有试用，其政策仍为基线。
        policy_b, applied_b = self.setup.policy_for("coop-b", purpose="settle", at=30)
        self.assertEqual(applied_b, ())
        self.assertEqual(
            policy_b.evaluate("staged-analyst", "approve", "settle", "own", "request_org"),
            base.evaluate("staged-analyst", "approve", "settle", "own", "request_org"),
        )
        # 同一租户、非试用用途不加试用。
        _, applied_other = self.setup.policy_for("coop-a", purpose="inspect", at=30)
        self.assertEqual(applied_other, ())

    def test_request_identity_and_tenant_must_agree(self):
        decision = self.project.request("u4", "coop-b", "rs-1", "read", "settle", at=30)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "tenant_mismatch")

    def test_partial_pause_leaves_other_access_running(self):
        # 新标签让 rs-3 落入已核准能力，只暂停该资源；rs-1 继续办理。
        self.fixtures.directory_view.set_label("rs-3", "own")
        reports = self.setup.drift_check(now=34)
        report = next(r for r in reports if r["trial"] == self.trial.id)
        self.assertEqual(report["decision"], "pause_changed_portion")
        self.assertIn("report-reader", report["exceeded"])

        paused = self.project.request("u4", "coop-a", "rs-3", "read", "settle", at=35)
        self.assertFalse(paused.allowed)
        self.assertEqual(paused.reason, "trial_scope_paused")
        running = self.project.request("u4", "coop-a", "rs-1", "read", "settle", at=35)
        self.assertTrue(running.allowed)

    def test_drift_ignores_observations_absence(self):
        # 没有记录到任何访问也要按事实检出超范围。
        self.assertEqual(len(self.project.audit), 0)
        self.fixtures.directory_view.set_label("rs-3", "own")
        reports = self.setup.drift_check(now=34)
        self.assertTrue(any(r["decision"] == "pause_changed_portion" for r in reports))
        self.assertEqual(len(self.project.audit), 0)

    def test_new_directory_fact_is_detected_as_drift_basis(self):
        self.fixtures.directory_view.add_entry(DirectoryEntry(
            id="d-9", person="u99", company="coop-a", site="east",
            role="staged-analyst",
        ))
        reports = self.setup.drift_check(now=34)
        report = next(r for r in reports if r["trial"] == self.trial.id)
        self.assertTrue(report["facts_changed"])

    def test_withdraw_keeps_independent_stop(self):
        self.setup.apply_independent("pp-5", now=30)
        self.assertIsNone(self.setup.base_policy().rule("ru-2"))
        result = self.setup.withdraw(self.trial.id, now=33)
        self.assertIn("ru-2", result["independent_stops_preserved"])
        # 撤回后试用新增的继承能力消失，独立停用仍在。
        base = self.setup.base_policy()
        self.assertIsNone(base.rule("ru-2"))
        self.assertNotIn("pp-1:edge", base.edge_ids())

    def test_withdraw_removes_only_trial_rights(self):
        result = self.setup.withdraw(self.trial.id, now=33)
        self.assertIn("staged-analyst", result["removed_rights"])
        removed = {
            (c["operation"], c["label"]) for c in result["removed_rights"]["staged-analyst"]
        }
        self.assertIn(("read", "own"), removed)


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = load_fixtures(FEEDS)
        self.project = Project(self.fixtures)

    def test_decisions_retain_identity_policy_and_result(self):
        decision = self.project.request("u4", "coop-a", "rs-1", "read", "settle", at=28)
        self.assertTrue(decision.allowed)
        payload = decision.as_dict()
        self.assertEqual(payload["person"], "u4")
        self.assertEqual(payload["role"], "report-reader")
        self.assertEqual(payload["revision"], "rev-2")
        self.assertTrue(payload["policy_digest"])
        self.assertTrue(payload["proposals"] == [])

    def test_historical_decision_not_rewritten(self):
        first = self.project.request("u4", "coop-a", "rs-3", "read", "settle", at=28)
        self.assertFalse(first.allowed)
        # 后来的政策变化不应改写已记录的决定。
        self.fixtures.directory_view.set_label("rs-3", "own")
        stored = self.project.audit.at(0)
        self.assertEqual(stored.resource_label, "unknown")
        self.assertEqual(stored.effect, first.effect)

    def test_replay_uses_source_order_not_position(self):
        decisions = self.project.engine.replay_observations()
        self.assertEqual(len(decisions), len(self.fixtures.observations))
        self.assertEqual(
            [d.request.person for d in decisions],
            [o.person for o in self.fixtures.observations],
        )


class ViewsTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = load_fixtures(FEEDS)
        self.project = Project(self.fixtures)

    def test_supervisor_sees_own_scope_only(self):
        view = self.project.supervisor("d-3")
        ids = {c.proposal.id for c in view.visible_checks()}
        self.assertIn("pp-3", ids)      # 自己的标签提议
        self.assertNotIn("pp-1", ids)   # 协会的继承提议
        self.assertNotIn("pp-2", ids)

    def test_supervisor_can_submit_new_proposal(self):
        view = self.project.supervisor("d-3")
        check = view.submit("d-3", "tag_resource", "rs-1", "own,coop-a", at=50)
        self.assertTrue(check.allowed, check.reasons)
        self.assertIn(check.proposal.id, self.project.setup.checks)

    def test_duty_officer_locates_stacked_source(self):
        view = self.project.duty_officer("d-5")
        result = view.locate("staged-analyst")
        self.assertEqual(result["classification"], "proposal_stack")
        self.assertTrue(result["stacked_proposals"])

    def test_duty_officer_locates_single_proposal_source(self):
        view = self.project.duty_officer("d-5")
        result = view.locate("report-editor")
        self.assertIn(result["classification"], ("single_proposal", "proposal_stack"))
        self.assertTrue(result["single_proposal"])

    def test_duty_officer_locates_directory_fact(self):
        # 新目录事实让某角色出现在目录里，但没有任何提议打开新能力。
        self.fixtures.directory_view.add_entry(DirectoryEntry(
            id="d-9", person="u99", company="coop-a", site="east",
            role="report-reader",
        ))
        view = self.project.duty_officer("d-5")
        result = view.locate("report-reader", proposal_ids=[])
        self.assertEqual(result["classification"], "directory_facts")

    def test_cooperative_only_sees_own_results(self):
        view = self.project.cooperative("coop-a")
        result = view.query("u4", "rs-1", "read", "settle", at=30)
        self.assertEqual(result["tenant"], "coop-a")
        self.assertTrue(result["allowed"])
        with self.assertRaises(PermissionError):
            view.query("u7", "rs-2", "read", "settle", at=30)

    def test_cooperative_decisions_scoped_to_tenant(self):
        self.project.request("u4", "coop-a", "rs-1", "read", "settle", at=30)
        self.project.request("u7", "coop-b", "rs-2", "read", "settle", at=31)
        view = self.project.cooperative("coop-a")
        decisions = view.my_decisions()
        self.assertTrue(all(d["tenant"] == "coop-a" for d in decisions))


class FeedIntegrityTest(unittest.TestCase):
    def test_fixture_files_still_parse(self):
        for path in FEEDS.glob("*.json"):
            with self.subTest(feed=path.name):
                json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
