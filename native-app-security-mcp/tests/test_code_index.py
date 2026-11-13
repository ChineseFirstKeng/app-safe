import hashlib
import json
import plistlib
import stat
import struct
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from native_security.artifacts import import_artifact
from native_security.code_index import index_package, project_index
from native_security.code_store import CodeStore, redact_code
from native_security.errors import AnalysisError
from native_security.evidence import EvidenceBuilder
from native_security.jobs_store import JobStore
from native_security.llvm_index import parse
from native_security.native_slices import slices
from native_security.storage import Store


def macho(encrypted=False, cpu=0x100000c):
    header = struct.pack("<8I", 0xfeedfacf, cpu, 0, 2, 1 if encrypted else 0, 24 if encrypted else 0, 0, 0)
    command = struct.pack("<6I", 0x2c, 24, 64, 32, 1, 0) if encrypted else b""
    return (header + command).ljust(128, b"\0")


class CodeIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "data")
        package = self.root / "fixture.ipa"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("Payload/App.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.test"}))
            archive.writestr("Payload/App.app/App", macho(True))
        self.artifact = import_artifact(self.store, str(package))
        self.jobs = JobStore(self.store)
        self.job = self.jobs.create(self.artifact["artifact_id"])
        self.jobs.claim("owner")
        self.code = CodeStore(self.store)

    def index(self):
        directory = self.store.root / "analyses" / self.job["analysis_id"]
        (directory / "code").mkdir(parents=True)
        obj = {"methods": [
            {"identity": "LExample;->helper(I)I", "name": "helper", "class_name": "Example", "body": "int helper(int x) { return x + 123456; }"},
            {"identity": "LExample;->helper(Ljava/lang/String;)V", "name": "helper", "class_name": "Example", "body": 'void helper(String s) { sink("private-string"); /* private-comment */ }'}],
            "edges": [{"from": "LExample;->helper(I)I", "to": "LExample;->helper(Ljava/lang/String;)V", "kind": "static_method_use", "site": None}]}
        raw = json.dumps(obj).encode()
        path = directory / "code/index.json"
        path.write_bytes(raw)
        source = {"kind": "json", "path": "code/index.json", "sha256": hashlib.sha256(raw).hexdigest()}
        units, edges = [], []
        project_index(self.job, {"path": "classes.dex", "carrier_sha256": "a"*64}, obj, source, units, edges)
        self.assertTrue(self.code.publish(self.job["analysis_id"], "owner", units, edges, []))
        return units, edges, path

    def test_overload_queries_references_redaction_and_raw_export(self):
        units, edges, path = self.index()
        aid = self.job["analysis_id"]
        self.assertEqual(2, self.code.list(aid, "helper", "method")["total"])
        self.assertNotEqual(units[0]["unit_id"], units[1]["unit_id"])
        self.assertEqual(1, self.code.references(aid, units[0]["unit_id"], "outgoing")["total"])
        self.assertEqual(1, self.code.references(aid, units[1]["unit_id"], "incoming")["total"])
        for unit in units:
            value = self.code.read(aid, unit["unit_id"])
            self.assertNotIn("private-string", value["body"])
            self.assertNotIn("private-comment", value["body"])
            self.assertNotIn("123456", value["body"])
        exported = self.code.export(aid, units[1]["unit_id"])
        self.assertIn("private-string", Path(exported["path"]).read_text())
        self.assertEqual(0o600, stat.S_IMODE(Path(exported["path"]).stat().st_mode))

    def test_source_tamper_foreign_units_and_revoked_publication(self):
        units, edges, path = self.index()
        path.write_text("{}")
        with self.assertRaises(AnalysisError) as caught:
            self.code.read(self.job["analysis_id"], units[0]["unit_id"])
        self.assertEqual("evidence_source_integrity_failed", caught.exception.code)
        other = self.jobs.create(self.artifact["artifact_id"])
        with self.assertRaises(AnalysisError):
            self.code.read(other["analysis_id"], units[0]["unit_id"])
        self.jobs.transition(self.job["analysis_id"], "cancelled", "test", {"running"})
        self.assertFalse(self.code.publish(self.job["analysis_id"], "owner", units, edges, []))

    def test_reject_missing_reference_targets_and_invalid_filters(self):
        units, edges, _ = self.index()
        for kind, limit in [("unknown", 1), (None, 201)]:
            with self.assertRaises(AnalysisError):
                self.code.list(self.job["analysis_id"], kind=kind, limit=limit)
        with self.assertRaises(AnalysisError):
            self.code.references(self.job["analysis_id"], units[0]["unit_id"], "both")
        with self.assertRaises(AnalysisError):
            self.code.publish(self.job["analysis_id"], "owner", units, [dict(edges[0], to_id="cu_missing")], [])

    def test_encrypted_slice_never_reaches_an_engine(self):
        directory = self.store.root / "analyses" / self.job["analysis_id"]
        directory.mkdir(parents=True)
        builder = EvidenceBuilder(self.job)
        with patch("native_security.code_index.ghidra_index") as ghidra, patch("native_security.code_index.llvm_index") as llvm:
            result = index_package(self.store, self.job, directory, builder, "owner", time.monotonic()+10)
        self.assertEqual("blocked_no_component_indexed", result)
        self.assertFalse(ghidra.called)
        self.assertFalse(llvm.called)
        self.assertEqual("blocked_encrypted_slice", self.code.summary(self.job["analysis_id"])["components"][0]["status"])

    def test_macho_thin_fat_encryption_ranges_and_overlap(self):
        self.assertTrue(slices(macho(True))[0]["encrypted"])
        self.assertFalse(slices(macho())[0]["encrypted"])
        header = struct.pack(">II", 0xcafebabe, 2)
        table = struct.pack(">5I", 0x100000c, 0, 64, 128, 0) + struct.pack(">5I", 0x1000007, 0, 192, 128, 0)
        data = (header+table).ljust(64,b"\0")+macho()+macho(cpu=0x1000007)
        result = slices(data)
        self.assertEqual(["arm64", "x86_64"], [r["architecture"] for r in result])
        mismatched = bytearray(data)
        struct.pack_into(">I", mismatched, 12, 2)
        with self.assertRaises(AnalysisError) as caught:slices(mismatched)
        self.assertEqual("fat_cpu_subtype_mismatch", caught.exception.code)
        malformed = bytearray(data)
        struct.pack_into(">I", malformed, 8+20+8, 64)
        with self.assertRaises(AnalysisError):slices(malformed)
        with self.assertRaises(AnalysisError):slices(macho()[:20])

    def test_llvm_unknown_calls_do_not_resolve_to_an_arbitrary_symbol(self):
        symbols = "00000010 g F .text 00000008 caller\n00000020 g F .text 00000004 helper"
        assembly = "Disassembly of section .text:\n00000010 <caller>:\n10: bl 0x20 <helper>\n14: blr x0\n00000020 <helper>:\n20: ret\n"
        obj = parse(symbols, assembly)
        self.assertEqual(2, len(obj["functions"]))
        self.assertEqual("20", obj["edges"][0]["to"])
        self.assertIsNone(obj["edges"][1]["to"])
        self.assertFalse(obj["coverage"]["decompilation_performed"])
        self.assertEqual([], parse("", assembly)["functions"])

    def test_redactor_handles_escaped_quotes_chars_hex_and_unterminated_literals(self):
        for source, forbidden in [('sink("secret\\\"value");', "secret"), ("char c='Z';", "'Z'"),
                                  ("key=0xdeadbeef; // credential", "deadbeef"), ('sink("unfinished', "unfinished")]:
            self.assertNotIn(forbidden, redact_code(source))
        self.assertIn("FUN_10000123", redact_code("FUN_10000123(123);"))

    def test_arm64e_authenticated_branches_stay_unresolved(self):
        symbols = "00000010 g F .text 00000010 caller"
        assembly = "00000010 <caller>:\n10: blraa x8, x9\n14: braaz x10\n18: blrab x0, x1\n"
        obj = parse(symbols, assembly)
        self.assertEqual(3, obj["coverage"]["computed_branches"])
        self.assertTrue(all(edge["to"] is None for edge in obj["edges"]))

    def test_auto_backend_fallback_records_ghidra_failure(self):
        package = self.root / "unencrypted.ipa"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("Payload/App.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "example.test"}))
            archive.writestr("Payload/App.app/App", macho(False))
        artifact = import_artifact(self.store, str(package))
        job = self.jobs.create(artifact["artifact_id"])
        self.jobs.transition(self.job["analysis_id"], "cancelled", "test", {"running"})
        self.jobs.claim("owner")
        directory = self.store.root / "analyses" / job["analysis_id"]
        directory.mkdir(parents=True)
        fake_tools = self.root / "tools"
        (fake_tools / "ghidra/support").mkdir(parents=True)
        (fake_tools / "ghidra/support/analyzeHeadless").write_text("not executed")
        def controlled_llvm(binary, work, deadline):
            path = work / "index.json"
            path.write_text(json.dumps({"schema": "llvm-index/1", "functions": [], "edges": [], "coverage": {}}))
            return path
        with patch.dict("os.environ", {"NATIVE_SECURITY_NATIVE_ENGINE": "auto"}), \
             patch("native_security.code_index.tools_root", return_value=fake_tools), \
             patch("native_security.code_index.ghidra_index", side_effect=AnalysisError("controlled_failure")), \
             patch("native_security.code_index.llvm_index", side_effect=controlled_llvm):
            result = index_package(self.store, job, directory, EvidenceBuilder(job), "owner", time.monotonic()+10)
        component = self.code.summary(job["analysis_id"])["components"][0]
        self.assertEqual("partial_no_code_units_recovered", result)
        self.assertEqual("no_code_units_recovered", component["status"])
        self.assertEqual("failed:controlled_failure", component["engine_attempts"][0]["status"])
        self.assertEqual("llvm-indexer", component["source"]["producer"])
