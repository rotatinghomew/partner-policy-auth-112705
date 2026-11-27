import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = {'directory': ('id', 'person', 'company', 'site', 'role'), 'condition_domain': ('id', 'operation', 'purpose', 'label', 'owner_class', 'scope'), 'rules': ('id', 'role', 'operation', 'purpose', 'label', 'owner_class', 'effect'), 'edges': ('id', 'child', 'parent', 'owner'), 'admin_scopes': ('id', 'actor', 'company', 'may_edit', 'stages'), 'proposals': ('id', 'actor', 'operation', 'target', 'detail', 'at'), 'resource_labels': ('id', 'owner', 'site', 'label'), 'observations': ('id', 'person', 'tenant', 'resource', 'operation', 'purpose', 'at'), 'activations': ('id', 'proposal', 'tenant', 'purpose', 'state', 'revision', 'at')}
RELATIONS = [('observations', ('resource',), 'resource_labels', ('id',)), ('admin_scopes', ('actor', 'company'), 'directory', ('id', 'company')), ('activations', ('proposal',), 'proposals', ('id',))]


class FixtureContract(unittest.TestCase):
    """检查联调资料的字段和公开引用。"""

    def test_feed_shapes(self):
        for name, fields in SCHEMA.items():
            with self.subTest(feed=name):
                rows = json.loads((ROOT / "feeds" / (name + ".json")).read_text())
                self.assertTrue(rows)
                self.assertTrue(all(set(row) == set(fields) for row in rows))
                for row in rows:
                    for field in set(row) & {"occurred", "received", "trusted_time"}:
                        self.assertIs(type(row[field]), int)
                    if "occurred" in row and "received" in row:
                        self.assertLessEqual(row["occurred"], row["received"])

    def test_cross_source_references(self):
        feeds = {
            name: json.loads((ROOT / "feeds" / (name + ".json")).read_text())
            for name in SCHEMA
        }
        for source, fields, target, target_fields in RELATIONS:
            with self.subTest(source=source, target=target, link=fields):
                keys = {tuple(row[key] for key in target_fields) for row in feeds[target]}
                for row in feeds[source]:
                    ref = tuple(row[key] for key in fields)
                    if None not in ref:
                        self.assertIn(ref, keys)

    def test_reference_from_service_directory(self):
        catalog = json.loads((ROOT / "feeds" / "index.json").read_text())
        feed, ref = catalog["sample_ref"].split("/")
        self.assertEqual(set(SCHEMA), set(catalog["sources"]))
        rows = json.loads((ROOT / "feeds" / (feed + ".json")).read_text())
        self.assertEqual(sum(row.get("id", row.get("ref")) == ref for row in rows), 1)
