import hashlib
import json
import os
import plistlib
import stat
import tempfile
import threading
import time
import unittest
import zipfile
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from native_security.artifacts import import_artifact
from native_security.errors import AnalysisError
from native_security.evidence import read_checked_evidence
from native_security.jobs_store import JobStore, TERMINAL
from native_security.reporting import export_report
from native_security.scheduler import Scheduler
from native_security.storage import Store


def wait_for(jobs, analysis_id, timeout=10):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = jobs.get(analysis_id)
        if result["state"] in TERMINAL:
            return result
        time.sleep(.03)
    raise AssertionError("analysis did not terminate")


@contextmanager
def controlled_provider(snapshot, sha, slow=False):
    entered, release = threading.Event(), threading.Event()
    data = snapshot.read_bytes()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            if self.path.endswith("upload"):
                obj = {"hash": hashlib.md5(data, usedforsecurity=False).hexdigest(), "scan_type": "ipa"}
            elif self.path.endswith("scan"):
                entered.set()
                if slow:
                    release.wait(5)
                obj = {"status": "success"}
            else:
                obj = {"sha256": sha, "code_analysis": {"findings": {"ios_test_rule": {
                    "metadata": {"description": "private-provider-secret ``` <script>alert(1)</script>"},
                    "files": {"private-source.m": "1"}}}}}
            raw = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with patch.dict(os.environ, {"NATIVE_SECURITY_MOBSF_URL": f"http://127.0.0.1:{server.server_port}",
                                     "NATIVE_SECURITY_MOBSF_API_KEY": "controlled-key"}):
            yield entered, release
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "data")
        self.jobs = JobStore(self.store)
        package = self.root / "fixture.ipa"
        config = {"CFBundleIdentifier": "example.native.fixture", "CFBundleExecutable": "Demo",
                  "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
                  "CFBundleURLTypes": [{"CFBundleURLSchemes": ["native-demo"]}],
                  "PrivateKeyValue": "private-plist-secret"}
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(config, fmt=plistlib.FMT_BINARY))
        self.artifact = import_artifact(self.store, str(package))
        self.snapshot = self.store.artifact_path(self.artifact["artifact_id"]) / "package.bin"
        self.scheduler = Scheduler(self.store.root)
        self.addCleanup(self.scheduler.close)

    def submit(self, seconds=10):
        return self.scheduler.submit(self.artifact["artifact_id"], seconds)["analysis_id"]

    def test_persisted_config_results_no_mobsf_and_report_redaction(self):
        with patch.dict(os.environ, {"NATIVE_SECURITY_MOBSF_URL": "", "NATIVE_SECURITY_MOBSF_API_KEY": ""}):
            aid = self.submit()
            record = wait_for(self.jobs, aid)
        self.assertEqual("partial", record["state"])
        self.assertIn("mobsf_not_configured", record["coverage"]["mobsf"])
        self.assertEqual(1, record["counts"]["finding"])
        self.assertEqual(1, record["counts"]["surface"])
        self.assertIn("explicit-native-configuration", record["effective_profile"])
        self.assertNotIn("mobsf", record["effective_profile"])
        items = self.jobs.results(aid)["items"]
        self.assertNotIn("private-plist-secret", json.dumps(items))
        for result in items:
            self.assertEqual(result, self.jobs.result(aid, result["result_id"]))
            for eid in result["evidence_ids"]:
                checked = read_checked_evidence(self.store, self.jobs, aid, eid)
                self.assertEqual("verified", checked["source_integrity"])
                self.assertNotIn("private-plist-secret", json.dumps(checked))
        default = export_report(self.store, self.jobs, aid)
        self.assertNotIn("private-plist-secret", Path(default["path"]).read_text())
        sensitive = export_report(self.store, self.jobs, aid, "json", True)
        self.assertIn("private-plist-secret", Path(sensitive["path"]).read_text())
        self.assertEqual(0o600, stat.S_IMODE(Path(sensitive["path"]).stat().st_mode))
        self.scheduler.close()
        self.assertEqual(record, JobStore(Store(self.store.root)).get(aid))

    def test_controlled_provider_candidates_remain_unverified_and_source_checked(self):
        with controlled_provider(self.snapshot, self.artifact["sha256"]):
            aid = self.submit()
            record = wait_for(self.jobs, aid)
        self.assertEqual("partial", record["state"])
        self.assertIn("mobsf-recognized-projection", record["effective_profile"])
        results = self.jobs.results(aid, "finding")["items"]
        provider = next(r for r in results if r["rule_id"] == "MOBSF:ios_test_rule")
        self.assertEqual("static_candidate", provider["verification_level"])
        self.assertNotIn("private-provider-secret", json.dumps(results))
        eid = provider["evidence_ids"][0]
        self.assertNotIn("private-provider-secret", json.dumps(read_checked_evidence(self.store, self.jobs, aid, eid)))
        report = export_report(self.store, self.jobs, aid, include_sensitive_values=True)
        text = Path(report["path"]).read_text()
        self.assertIn("private-provider-secret", text)
        self.assertNotIn("<script>", text)
        self.assertNotIn("secret ```", text)
        raw = self.store.root / "analyses" / aid / "provider/report.json"
        raw.write_bytes(b"{}")
        for operation in [lambda: read_checked_evidence(self.store, self.jobs, aid, eid),
                          lambda: export_report(self.store, self.jobs, aid)]:
            with self.assertRaises(AnalysisError) as caught:
                operation()
            self.assertEqual("evidence_source_integrity_failed", caught.exception.code)

    def test_cancel_owned_process_and_no_late_overwrite(self):
        self.scheduler.concurrency = 1
        with controlled_provider(self.snapshot, self.artifact["sha256"], slow=True) as (entered, release):
            aid = self.submit()
            self.assertTrue(entered.wait(5))
            queued = self.submit()
            self.assertEqual("cancelled", self.scheduler.cancel(queued)["state"])
            self.assertEqual("cancelled_before_start", self.jobs.get(queued)["reason"])
            cancelled = self.scheduler.cancel(aid)
            self.assertEqual("cancelled", cancelled["state"])
            self.assertNotIn(aid, self.scheduler._active)
            release.set()
            time.sleep(.1)
            self.assertEqual("cancelled", self.jobs.get(aid)["state"])
            self.assertGreater(self.jobs.results(aid)["total"], 0)

    def test_real_process_wall_timeout_retains_checkpoint(self):
        with controlled_provider(self.snapshot, self.artifact["sha256"], slow=True) as (entered, release):
            started = time.monotonic()
            aid = self.submit(1)
            self.assertTrue(entered.wait(5))
            record = wait_for(self.jobs, aid)
            self.assertEqual("timed_out", record["state"])
            self.assertLess(time.monotonic() - started, 4)
            release.set()
        self.assertGreater(self.jobs.results(aid)["total"], 0)

    def test_shutdown_interrupts_running_and_restart_dispatches_queue(self):
        self.scheduler.concurrency = 1
        with controlled_provider(self.snapshot, self.artifact["sha256"], slow=True) as (entered, release):
            first = self.submit()
            self.assertTrue(entered.wait(5))
            second = self.submit()
            self.assertEqual("queued", self.jobs.get(second)["state"])
            self.scheduler.close()
            self.assertEqual("interrupted", self.jobs.get(first)["state"])
            self.assertEqual("queued", self.jobs.get(second)["state"])
            release.set()
            self.scheduler.start()
            self.assertEqual("partial", wait_for(self.jobs, second)["state"])

    def test_controller_lock_recovery_and_revoked_owner(self):
        stale = self.jobs.create(self.artifact["artifact_id"])
        self.jobs.claim("old-controller")
        self.scheduler.start()
        self.assertEqual("interrupted", self.jobs.get(stale["analysis_id"])["state"])
        self.assertFalse(self.jobs.publish(stale["analysis_id"], "old-controller", [], [], {}))
        other = Scheduler(self.store.root)
        self.addCleanup(other.close)
        with self.assertRaises(AnalysisError) as caught:
            other.start()
        self.assertEqual("analysis_controller_busy", caught.exception.code)
        self.scheduler.close()
        other.start()

    def test_cancel_queued_terminal_and_validation(self):
        job = self.jobs.create(self.artifact["artifact_id"])
        cancelled = self.jobs.transition(job["analysis_id"], "cancelled", "test_cancel", {"queued"})
        self.assertEqual("cancelled", self.scheduler.cancel(job["analysis_id"])["state"])
        with self.assertRaises(AnalysisError):
            self.jobs.get("../../bad")
        for budget in [False, 0, 3601]:
            with self.assertRaises(AnalysisError):
                self.jobs.create(self.artifact["artifact_id"], budget)
        for kind, offset, limit in [("unknown", 0, 1), (None, -1, 1), (None, 0, 201)]:
            with self.assertRaises(AnalysisError):
                self.jobs.results(cancelled["analysis_id"], kind, offset, limit)

    def test_export_refuses_running_and_snapshot_tamper(self):
        job = self.jobs.create(self.artifact["artifact_id"])
        with self.assertRaises(AnalysisError) as caught:
            export_report(self.store, self.jobs, job["analysis_id"])
        self.assertEqual("analysis_not_finished", caught.exception.code)
        self.jobs.transition(job["analysis_id"], "cancelled", "test", {"queued"})
        self.snapshot.write_bytes(b"tampered")
        with self.assertRaises(AnalysisError) as caught:
            export_report(self.store, self.jobs, job["analysis_id"])
        self.assertEqual("snapshot_integrity_failed", caught.exception.code)

    def test_queue_bound_result_publication_identity_and_revision(self):
        job = self.jobs.create(self.artifact["artifact_id"])
        self.jobs.claim("owner")
        from native_security.evidence import EvidenceBuilder
        builder = EvidenceBuilder(job)
        builder.add("observation", "fixture", {"kind": "inventory"}, [], {})
        invalid = dict(builder.evidence[0], artifact_sha256="0" * 64)
        with self.assertRaises(AnalysisError):
            self.jobs.publish(job["analysis_id"], "owner", builder.results, [invalid], {})
        self.assertTrue(self.jobs.publish(job["analysis_id"], "owner", builder.results, builder.evidence, job["coverage"]))
        page = self.jobs.results(job["analysis_id"], limit=1)
        self.assertFalse(page["result_set_complete"])
        self.jobs.transition(job["analysis_id"], "cancelled", "test", {"running"})
        with self.assertRaises(AnalysisError) as caught:
            self.jobs.results(job["analysis_id"], revision=page["revision"])
        self.assertEqual("results_changed_restart_pagination", caught.exception.code)
        for _ in range(16):
            self.jobs.create(self.artifact["artifact_id"])
        with self.assertRaises(AnalysisError) as caught:
            self.jobs.create(self.artifact["artifact_id"])
        self.assertEqual("analysis_queue_full", caught.exception.code)

    def test_framework_ats_is_not_treated_as_host_configuration(self):
        package = self.root / "framework-only.ipa"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.safe"}))
            archive.writestr("Payload/Demo.app/Frameworks/Lib.framework/Info.plist", plistlib.dumps({
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}, "UIFileSharingEnabled": True}))
        artifact = import_artifact(self.store, str(package))
        with patch.dict(os.environ, {"NATIVE_SECURITY_MOBSF_URL": "", "NATIVE_SECURITY_MOBSF_API_KEY": ""}):
            job = self.scheduler.submit(artifact["artifact_id"], 10)
            record = wait_for(self.jobs, job["analysis_id"])
        self.assertEqual(0, record["counts"]["finding"])
        self.assertEqual(0, record["counts"]["surface"])
        self.assertEqual(3, record["counts"]["observation"])


if __name__ == "__main__":
    unittest.main()
