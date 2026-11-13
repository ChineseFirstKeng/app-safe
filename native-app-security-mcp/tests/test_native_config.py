import sqlite3
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from native_security.errors import AnalysisError
from native_security.native_config import parse_tree, visit
from native_security.storage import Store
from native_security.evidence import EvidenceBuilder, public_excerpt
from native_security.provider_projection import project_mobsf


class NativeConfigTests(unittest.TestCase):
    def test_current_aapt2_namespace_boolean_and_component_hierarchy(self):
        # Format observed from the actual installed aapt2 2.20 fixture compilation.
        text = '''N: android=http://schemas.android.com/apk/res/android (line=1)
  E: manifest (line=1)
    A: package="example.fixture" (Raw: "example.fixture")
      E: application (line=3)
        A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=true
        A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=false
          E: activity (line=4)
            A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true
              E: intent-filter (line=5)
                  E: data (line=6)
                    A: http://schemas.android.com/apk/res/android:scheme(0x01010027)="nativefixture" (Raw: "nativefixture")'''
        nodes = list(visit(parse_tree(text)))
        self.assertEqual(["manifest", "application", "activity", "intent-filter", "data"], [n["name"] for n in nodes])
        self.assertIs(True, nodes[1]["attrs"]["android:debuggable"]["value"])
        self.assertIs(False, nodes[1]["attrs"]["android:allowBackup"]["value"])
        self.assertEqual("nativefixture", nodes[-1]["attrs"]["android:scheme"]["value"])

    def test_legacy_typed_boolean_and_unresolved_reference(self):
        text = '''E: manifest
  E: application
    A: android:debuggable(0x0101000f)=(type 0x12)0xffffffff
    A: android:allowBackup(0x01010280)=(type 0x12)0x0
    A: android:usesCleartextTraffic(0x010104ec)=@0x7f010001'''
        app = list(visit(parse_tree(text)))[1]["attrs"]
        self.assertIs(True, app["android:debuggable"]["value"])
        self.assertIs(False, app["android:allowBackup"]["value"])
        self.assertIsNone(app["android:usesCleartextTraffic"]["value"])

    def test_future_storage_schema_is_not_downgraded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root)
            with store.connection() as db:
                db.execute("PRAGMA user_version=9")
            with self.assertRaises(AnalysisError) as caught:
                Store(root)
            self.assertEqual("unsupported_storage_schema", caught.exception.code)
            with sqlite3.connect(store.database) as db:
                self.assertEqual(9, db.execute("PRAGMA user_version").fetchone()[0])

    def test_provider_secure_and_info_rules_are_not_risk_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "provider").mkdir()
            job = {"analysis_id": "an_" + "0" * 32, "artifact_sha256": "a" * 64}
            obj = {"sha256": job["artifact_sha256"], "code_analysis": {"findings": {
                "safe_rule": {"metadata": {"severity": "secure"}},
                "info_rule": {"metadata": {"severity": "info"}},
                "candidate_rule": {"metadata": {"severity": "warning"}}}}}
            (root / "provider/report.json").write_text(json.dumps(obj))
            builder = EvidenceBuilder(job)
            self.assertEqual("recognized_shapes_only", project_mobsf(job, root, builder))
            self.assertEqual(["MOBSF:candidate_rule"], [r["rule_id"] for r in builder.results if r["kind"] == "finding"])
            self.assertEqual(3, sum(r["kind"] == "observation" for r in builder.results))

    def test_missing_provider_sections_and_projection_limit_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "provider").mkdir()
            job = {"analysis_id": "an_" + "0" * 32, "artifact_sha256": "a" * 64}
            (root / "provider/report.json").write_text(json.dumps({"sha256": job["artifact_sha256"]}))
            builder = EvidenceBuilder(job)
            self.assertEqual("no_recognized_finding_sections", project_mobsf(job, root, builder))
            for i in range(2100):
                builder.add("observation", str(i), {"kind": "inventory"}, [str(i)], i)
            self.assertEqual(2000, len(builder.results))
            self.assertTrue(builder.truncated)

    def test_public_configuration_excerpt_is_useful_without_revealing_arbitrary_strings(self):
        evidence = {"source": {"kind": "text", "producer": "aapt2 dump xmltree"}, "selector": [1]}
        value = '    A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=true'
        self.assertEqual({"attribute": "android:debuggable", "value": True}, public_excerpt(evidence, value))
        secret = '    A: secret="private-test-secret"'
        self.assertNotIn("private-test-secret", json.dumps(public_excerpt(evidence, secret)))
