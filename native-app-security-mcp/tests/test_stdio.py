import json
import asyncio
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from mcp import Client, StdioServerParameters

from native_security.storage import Store

PROJECT = Path(__file__).resolve().parents[1]


class StdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_stdio_discovery_import_pagination_and_safe_error(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifact = root / "synthetic.apk"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("AndroidManifest.xml", "synthetic")
                archive.writestr("classes.dex", b"dex\n035\x00synthetic")
            data = root / "data"
            params = StdioServerParameters(command=sys.executable,
                args=["-m", "native_security", "--data-dir", str(data), "serve"], cwd=PROJECT)
            async with Client(params, read_timeout_seconds=15) as client:
                discovery = await client.list_tools()
                self.assertEqual({"health_check", "import_artifact", "list_artifact_members", "start_analysis",
                                  "get_analysis_status", "list_results", "get_result", "read_evidence",
                                  "cancel_analysis", "export_report", "list_code_symbols", "get_code",
                                  "get_code_references", "export_code"},
                                 {tool.name for tool in discovery.tools})
                health = await client.call_tool("health_check", {})
                self.assertFalse(health.is_error)
                self.assertIn("complete_security_scan", health.structured_content["not_implemented"])
                imported = await client.call_tool("import_artifact", {"path": str(artifact)})
                self.assertFalse(imported.is_error)
                self.assertTrue(imported.structured_content["ok"])
                record = imported.structured_content["artifact"]
                self.assertFalse(record["security_analysis_performed"])
                page = await client.call_tool("list_artifact_members", {
                    "artifact_id": record["artifact_id"], "limit": 1})
                self.assertEqual(1, page.structured_content["next_offset"])
                bad = await client.call_tool("import_artifact", {"path": str(root / "secret-token-missing.apk")})
                self.assertEqual({"ok": False, "error": "source_unavailable_or_symlink"}, bad.structured_content)
                self.assertNotIn("secret-token", str(bad))
                started = await client.call_tool("start_analysis", {"artifact_id": record["artifact_id"], "wall_seconds": 10})
                self.assertTrue(started.structured_content["ok"])
                aid = started.structured_content["analysis_id"]
                for _ in range(200):
                    current = await client.call_tool("get_analysis_status", {"analysis_id": aid})
                    if current.structured_content["state"] not in {"queued", "running"}:
                        break
                    await asyncio.sleep(.05)
                self.assertIn(current.structured_content["state"], {"partial", "blocked"})
                listed = await client.call_tool("list_results", {"analysis_id": aid})
                first = listed.structured_content["items"][0]
                detail = await client.call_tool("get_result", {"analysis_id": aid, "result_id": first["result_id"]})
                self.assertEqual(first["result_id"], detail.structured_content["result_id"])
                evidence = await client.call_tool("read_evidence", {"analysis_id": aid, "evidence_id": first["evidence_ids"][0]})
                self.assertEqual("verified", evidence.structured_content["source_integrity"])
                exported = await client.call_tool("export_report", {"analysis_id": aid})
                self.assertTrue(Path(exported.structured_content["path"]).is_file())
                self.assertFalse(exported.structured_content["security_assessment_complete"])
            self.assertEqual(record, Store(data).get(record["artifact_id"]))


class CliTests(unittest.TestCase):
    def test_health_cli_and_exit_code(self):
        result = subprocess.run([sys.executable, "-m", "native_security", "health"],
                                cwd=PROJECT, capture_output=True, text=True, timeout=15)
        self.assertEqual(0, result.returncode)
        self.assertEqual("native-app-security-mcp", json.loads(result.stdout)["service"])

    def test_import_failure_has_nonzero_exit_and_no_path_leak(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, "-m", "native_security", "--data-dir", folder,
                                     "import", "/nonexistent/private-secret-source.apk"],
                                    cwd=PROJECT, capture_output=True, text=True, timeout=15)
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual({"error": "source_unavailable_or_symlink"}, json.loads(result.stderr))


if __name__ == "__main__":
    unittest.main()
