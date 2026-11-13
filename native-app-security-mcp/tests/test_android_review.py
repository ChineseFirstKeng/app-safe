import hashlib
import json
import plistlib
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from native_security.android_review import trace
from native_security.artifacts import import_artifact
from native_security.errors import AnalysisError
from native_security.evidence import checked_source
from native_security.jobs_store import JobStore
from native_security.storage import Store


class AndroidReviewTests(unittest.TestCase):
    def manifest(self, exported='true', component='activity', callback='Entry', enabled='true'):
        return f'''E: manifest
  A: package="example"
  E: application
    E: {component}
      A: android:name=".{callback}"
      A: android:exported={exported}
      A: android:enabled={enabled}
'''

    def graph(self):
        units = [{"unit_id": "root", "identity": "example.Entry.onCreate(Landroid/os/Bundle;)V"},
                 {"unit_id": "helper", "identity": "example.Entry.helper()V"}]
        edges = [{"from_id": "root", "to_id": "helper", "target_identity": units[1]["identity"]},
                 {"from_id": "helper", "to_id": "root", "target_identity": units[0]["identity"]},
                 {"from_id": "helper", "to_id": None, "target_identity": "android.webkit.WebView.loadUrl(Ljava/lang/String;)V"}]
        return units, edges

    def test_cycle_bound_and_explicit_export_enabled_controls(self):
        units, edges = self.graph()
        obj = trace(self.manifest(), units, edges, time.monotonic()+5)
        self.assertEqual(1, len(obj["paths"]))
        self.assertEqual(["root", "helper"], obj["paths"][0]["code_path"])
        self.assertFalse(obj["coverage"]["data_flow_performed"])
        for document in [self.manifest(exported='false'), self.manifest(exported='(type 0x01)0x1234'),
                         self.manifest(enabled='false'), self.manifest(component='activity-alias')]:
            self.assertFalse(trace(document, units, edges, time.monotonic()+5)["paths"])

    def test_wrong_overload_ambiguous_callback_and_deadline_remain_gaps(self):
        units, edges = self.graph()
        overload = [dict(units[0], identity="example.Entry.onCreate()V"), units[1]]
        self.assertFalse(trace(self.manifest(), overload, edges, time.monotonic()+5)["paths"])
        duplicate = [*units, dict(units[0], unit_id="another_dex")]
        result = trace(self.manifest(), duplicate, edges, time.monotonic()+5)
        self.assertFalse(result["paths"])
        self.assertIn("ambiguous_callback_identity", result["gaps"])
        result = trace(self.manifest(), units, edges, time.monotonic()-1)
        self.assertFalse(result["paths"])
        self.assertTrue(result["coverage"]["truncated"])

    def test_derived_evidence_checks_origin_and_rejects_nested_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "fixture.ipa"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("Payload/App.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example"}))
            store = Store(root / "data")
            artifact = import_artifact(store, str(package))
            job = JobStore(store).create(artifact["artifact_id"])
            directory = store.root / "analyses" / job["analysis_id"]
            directory.mkdir(parents=True)
            origin, review = directory / "origin.json", directory / "review.json"
            origin.write_bytes(b'{"methods": []}'); review.write_bytes(b'{"paths": []}')
            dependency = {"kind": "json", "path": origin.name, "producer": "jadx-indexer", "sha256": hashlib.sha256(origin.read_bytes()).hexdigest()}
            source = {"kind": "json", "path": review.name, "producer": "android-entry-review", "sha256": hashlib.sha256(review.read_bytes()).hexdigest(), "dependencies": [dependency]}
            evidence = {"artifact_sha256": job["artifact_sha256"], "source": source}
            self.assertEqual({"paths": []}, checked_source(store, job, evidence))
            origin.write_bytes(b'{}')
            with self.assertRaises(AnalysisError):checked_source(store, job, evidence)
            source["dependencies"] = [dict(dependency, dependencies=[])]
            with self.assertRaises(AnalysisError) as caught:checked_source(store, job, evidence)
            self.assertEqual("invalid_review_dependencies", caught.exception.code)
