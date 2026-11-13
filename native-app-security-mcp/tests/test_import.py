import hashlib
import io
import os
import plistlib
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from native_security.artifacts import ImportLimits, import_artifact
from native_security.errors import AnalysisError
from native_security.storage import Store


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "data")

    def package(self, entries, name="fixture.apk", compression=zipfile.ZIP_STORED):
        path = self.root / name
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w", compression=compression) as archive:
                for key, value in entries:
                    archive.writestr(key, value)
        return path

    def apk(self, extras=()):
        return self.package([("AndroidManifest.xml", b"synthetic manifest"),
                             ("classes.dex", b"dex\n035\x00synthetic"), *extras])

    def reject(self, entries, code, limits=None):
        path = self.package(entries)
        with self.assertRaises(AnalysisError) as caught:
            import_artifact(self.store, str(path), limits)
        self.assertEqual(code, caught.exception.code)
        self.assertEqual([], list((self.store.root / "staging").iterdir()))
        self.assertEqual([], list((self.store.root / "artifacts").iterdir()))

    def test_apk_identity_digest_persistence_and_permissions(self):
        path = self.apk()
        original = path.read_bytes()
        record = import_artifact(self.store, str(path))
        self.assertEqual(hashlib.sha256(original).hexdigest(), record["sha256"])
        self.assertEqual("apk", record["package_type"])
        self.assertFalse(record["security_analysis_performed"])
        self.assertEqual("structural_only", record["identity_status"])
        self.assertEqual(record, Store(self.store.root).get(record["artifact_id"]))
        snapshot = self.store.artifact_path(record["artifact_id"]) / "package.bin"
        self.assertEqual(original, snapshot.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(snapshot.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(snapshot.parent.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.store.database.stat().st_mode))
        self.assertEqual(original, path.read_bytes())

    def test_ipa_identified_from_structure_not_suffix(self):
        info = plistlib.dumps({"CFBundleIdentifier": "example.synthetic", "CFBundleVersion": "1",
                              "arbitrarySecret": "do-not-persist"}, fmt=plistlib.FMT_BINARY)
        path = self.package([("Payload/Demo.app/Info.plist", info),
                             ("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe" + b"synthetic")], "sample.bin")
        result = import_artifact(self.store, str(path))
        self.assertEqual("ipa", result["package_type"])
        self.assertEqual("example.synthetic", result["package_identity"]["CFBundleIdentifier"])
        self.assertNotIn("arbitrarySecret", result["package_identity"])
        self.assertEqual(1, result["category_counts"]["macho_candidate"])

    def test_members_pagination_digest_and_empty_page(self):
        path = self.apk([("assets/value.txt", b"example")])
        result = import_artifact(self.store, str(path))
        page = self.store.members(result["artifact_id"], 0, 2)
        self.assertEqual(2, page["next_offset"])
        last = self.store.members(result["artifact_id"], 2, 2)
        self.assertIsNone(last["next_offset"])
        self.assertEqual(hashlib.sha256(b"example").hexdigest(), last["items"][0]["sha256"])
        self.assertEqual([], self.store.members(result["artifact_id"], 999)["items"])
        for offset, limit in [(-1, 2), (0, 201), (0, 0), (False, 1)]:
            with self.assertRaises(AnalysisError):
                self.store.members(result["artifact_id"], offset, limit)

    def test_duplicate_import_and_source_removal(self):
        path = self.apk()
        first = import_artifact(self.store, str(path))
        second = import_artifact(self.store, str(path))
        self.assertEqual(first, second)
        path.unlink()
        self.assertEqual(2, self.store.members(first["artifact_id"])["total"])

    def test_concurrent_import_deduplicates(self):
        path = self.apk()
        with ThreadPoolExecutor(max_workers=2) as pool:
            values = list(pool.map(lambda _: import_artifact(self.store, str(path)), range(2)))
        self.assertEqual(values[0], values[1])
        self.assertEqual(1, len(list((self.store.root / "artifacts").iterdir())))

    def test_tampered_existing_snapshot_rejected(self):
        path = self.apk()
        record = import_artifact(self.store, str(path))
        (self.store.artifact_path(record["artifact_id"]) / "package.bin").write_bytes(b"tampered")
        with self.assertRaises(AnalysisError) as caught:
            import_artifact(self.store, str(path))
        self.assertEqual("snapshot_integrity_failed", caught.exception.code)

    def test_source_symlink_and_directory_rejected(self):
        path = self.apk()
        link = self.root / "link.apk"
        link.symlink_to(path)
        for value in [link, self.root]:
            with self.assertRaises(AnalysisError):
                import_artifact(self.store, str(value))

    def test_store_symlink_rejected(self):
        link = self.root / "data-link"
        link.symlink_to(self.store.root)
        with self.assertRaises(AnalysisError):
            Store(link)

    def test_path_traversal_absolute_backslash_and_control(self):
        for name in ["../escape", "/absolute", "assets/../escape", "assets\\escape", "a//b", "a/./b", "x\ny"]:
            with self.subTest(name=name):
                self.reject([("AndroidManifest.xml", b"x"), (name, b"y")], "unsafe_archive_path")

    def test_duplicate_member(self):
        self.reject([("AndroidManifest.xml", b"x"), ("AndroidManifest.xml", b"y")], "duplicate_archive_path")

    def test_file_directory_collisions_in_both_orders(self):
        for values in [[("assets", b"x"), ("assets/file", b"y")],
                       [("assets/file", b"y"), ("assets", b"x")]]:
            self.reject([("AndroidManifest.xml", b"x"), *values], "archive_path_type_conflict")

    def test_symlink_member_rejected(self):
        link = zipfile.ZipInfo("assets/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.reject([("AndroidManifest.xml", b"x"), (link, b"/etc/passwd")], "unsupported_archive_entry_type")

    def test_ambiguous_and_unsupported_types(self):
        self.reject([("unrelated.txt", b"x")], "unsupported_package_structure")
        self.reject([("AndroidManifest.xml", b"x"), ("Payload/A.app/Info.plist", b"x")], "ambiguous_package_type")
        self.reject([("Payload/A.app/Info.plist", b"x"), ("Payload/B.app/Info.plist", b"x")], "ambiguous_ios_main_bundle")

    def test_limits_package_member_count_size_total_time(self):
        path = self.apk()
        for limits, code in [(replace(ImportLimits(), package_bytes=1), "package_size_exceeded"),
                             (replace(ImportLimits(), member_count=1), "archive_member_count_exceeded"),
                             (replace(ImportLimits(), member_bytes=1), "archive_member_size_exceeded"),
                             (replace(ImportLimits(), total_bytes=20), "archive_total_size_exceeded"),
                             (replace(ImportLimits(), wall_seconds=0), "import_time_budget_exceeded")]:
            with self.subTest(code=code), self.assertRaises(AnalysisError) as caught:
                import_artifact(self.store, str(path), limits)
            self.assertEqual(code, caught.exception.code)

    def test_compression_ratio(self):
        path = self.package([("AndroidManifest.xml", b"A" * 100000)], compression=zipfile.ZIP_DEFLATED)
        with self.assertRaises(AnalysisError) as caught:
            import_artifact(self.store, str(path))
        self.assertEqual("archive_compression_ratio_exceeded", caught.exception.code)

    def test_crc_corruption(self):
        path = self.apk()
        data = bytearray(path.read_bytes())
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entry = archive.infolist()[0]
            name_len, extra_len = struct.unpack_from("<HH", data, entry.header_offset + 26)
            data[entry.header_offset + 30 + name_len + extra_len] ^= 1
        path.write_bytes(data)
        with self.assertRaises(AnalysisError) as caught:
            import_artifact(self.store, str(path))
        self.assertEqual("invalid_or_unsupported_archive", caught.exception.code)

    def test_framework_marker_is_not_native_semantics(self):
        record = import_artifact(self.store, str(self.apk([("lib/arm64-v8a/libflutter.so", b"\x7fELFsynthetic")])))
        self.assertEqual(["flutter"], record["framework_indicators"])
        self.assertFalse(record["security_analysis_performed"])

    def test_ids_and_missing_records(self):
        for artifact_id in ["../../bad", "pkg_" + "g" * 64, "pkg_" + "0" * 64]:
            with self.assertRaises(AnalysisError):
                self.store.get(artifact_id)


if __name__ == "__main__":
    unittest.main()
