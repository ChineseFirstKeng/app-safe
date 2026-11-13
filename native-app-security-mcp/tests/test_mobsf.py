import hashlib
import json
import stat
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from native_security.adapters.mobsf import MobSFAdapter
from native_security.errors import AnalysisError
from native_security.artifacts import import_artifact
from native_security.baseline import run_baseline
from native_security.storage import Store


class AdapterTests(unittest.TestCase):
    """A controlled HTTP peer verifies the adapter, never a real engine verdict."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.snapshot = self.root / "package.bin"
        self.snapshot.write_bytes(b"synthetic package bytes")
        self.sha = hashlib.sha256(self.snapshot.read_bytes()).hexdigest()
        self.mode = "ok"
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.requests.append((self.path, dict(self.headers), body))
                status = 200
                if owner.mode == "auth":
                    status, value = 401, {"error": "credential-should-not-leak"}
                elif owner.mode == "redirect":
                    status, value = 302, {}
                elif owner.mode == "invalid":
                    value = ["unexpected list"]
                elif owner.mode == "oversized":
                    value = {"padding": "x" * 2000}
                elif self.path.endswith("/upload"):
                    value = {"hash": hashlib.md5(owner.snapshot.read_bytes(), usedforsecurity=False).hexdigest(), "scan_type": "apk"}
                    if owner.mode == "wrong-upload":
                        value["hash"] = "0" * 32
                elif self.path.endswith("/scan"):
                    value = {"status": "queued"} if owner.mode == "async" else {"status": "success"}
                else:
                    value = {"sha256": "0" * 64 if owner.mode == "wrong-report" else owner.sha,
                             "code_analysis": {"synthetic": True}, "secrets": ["private-test-secret"]}
                payload = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.url = f"http://127.0.0.1:{self.http.server_port}"

    def close_server(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=3)

    def adapter(self, **kwargs):
        return MobSFAdapter(self.url, "synthetic-api-key", **kwargs)

    def test_upload_scan_report_and_private_receipts(self):
        output = self.root / "receipt"
        result = self.adapter().scan(self.snapshot, "apk", self.sha, output)
        self.assertEqual("baseline_report_received", result["status"])
        self.assertFalse(result["independent_verification"])
        self.assertEqual(["/api/v1/upload", "/api/v1/scan", "/api/v1/report_json"], [r[0] for r in self.requests])
        self.assertIn(self.snapshot.read_bytes(), self.requests[0][2])
        self.assertIn(b'filename="artifact.apk"', self.requests[0][2])
        self.assertEqual("synthetic-api-key", self.requests[0][1]["X-Mobsf-Api-Key"])
        self.assertNotIn("private-test-secret", json.dumps(result))
        for receipt in result["receipts"]:
            path = output / receipt["file"]
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(receipt["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_reject_remote_credentials_query_and_header_injection(self):
        for url, key in [("http://example.com", "key"), (self.url + "/?token=secret", "key"),
                         ("http://name:secret@localhost", "key"), (self.url, "key\r\nInjected: yes")]:
            with self.assertRaises(AnalysisError) as caught:
                MobSFAdapter(url, key)
            self.assertEqual("invalid_mobsf_configuration", caught.exception.code)
        self.assertEqual([], self.requests)

    def test_missing_configuration(self):
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(AnalysisError) as caught:
            MobSFAdapter()
        self.assertEqual("mobsf_not_configured", caught.exception.code)

    def test_errors_identity_redirect_async_and_response_bounds(self):
        cases = {"auth": "mobsf_authentication_failed", "redirect": "mobsf_http_error",
                 "invalid": "mobsf_invalid_or_error_response", "oversized": "mobsf_response_limit_exceeded",
                 "wrong-upload": "mobsf_upload_identity_mismatch", "async": "mobsf_async_mode_not_supported",
                 "wrong-report": "mobsf_report_identity_mismatch_or_unavailable"}
        for mode, code in cases.items():
            self.mode = mode
            with self.subTest(mode=mode), self.assertRaises(AnalysisError) as caught:
                self.adapter(response_limit=1024).scan(self.snapshot, "apk", self.sha, self.root / mode)
            self.assertEqual(code, caught.exception.code)
            self.assertNotIn("credential", str(caught.exception))

    def test_snapshot_integrity_checked_before_network(self):
        with self.assertRaises(AnalysisError) as caught:
            self.adapter().scan(self.snapshot, "apk", "0" * 64, self.root / "result")
        self.assertEqual("snapshot_integrity_failed", caught.exception.code)
        self.assertEqual([], self.requests)

    def test_baseline_command_receipt_and_missing_provider(self):
        package = self.root / "fixture.apk"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("AndroidManifest.xml", "synthetic")
        store = Store(self.root / "data")
        artifact = import_artifact(store, str(package))
        self.snapshot = store.artifact_path(artifact["artifact_id"]) / "package.bin"
        self.sha = artifact["sha256"]
        with patch.dict("os.environ", {"NATIVE_SECURITY_MOBSF_URL": self.url,
                                      "NATIVE_SECURITY_MOBSF_API_KEY": "synthetic-api-key"}):
            result = run_baseline(store, artifact["artifact_id"])
        self.assertEqual("baseline_report_received", result["state"])
        self.assertFalse(result["security_assessment_complete"])
        self.assertTrue(Path(result["receipt_path"]).is_file())
        self.assertNotIn("private-test-secret", json.dumps(result))
        with patch.dict("os.environ", {}, clear=True):
            blocked = run_baseline(store, artifact["artifact_id"])
        self.assertEqual("blocked", blocked["state"])
        self.assertEqual("mobsf_not_configured", blocked["error"])
        self.assertFalse(blocked["ok"])


if __name__ == "__main__":
    unittest.main()
