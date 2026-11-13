from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import struct
import tempfile
import time
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .errors import AnalysisError
from .storage import Store

CHUNK = 128 * 1024


@dataclass(frozen=True)
class ImportLimits:
    package_bytes: int = 1024 * 1024 * 1024
    member_count: int = 30000
    member_bytes: int = 512 * 1024 * 1024
    total_bytes: int = 4 * 1024 * 1024 * 1024
    compression_ratio: int = 300
    wall_seconds: float = 120


def check_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise AnalysisError("import_time_budget_exceeded")


def digest_file(path: Path, deadline: float) -> str:
    if path.is_symlink():
        raise AnalysisError("snapshot_integrity_failed")
    digest = hashlib.sha256()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise AnalysisError("snapshot_integrity_failed") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise AnalysisError("snapshot_integrity_failed")
    with os.fdopen(fd, "rb") as stream:
        while block := stream.read(CHUNK):
            check_time(deadline)
            digest.update(block)
    return digest.hexdigest()


def member_name(info: zipfile.ZipInfo) -> str:
    name = info.orig_filename
    if (not name or "\x00" in name or "\\" in name or name.startswith("/")
            or ":" in name or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise AnalysisError("unsafe_archive_path")
    parts = name.rstrip("/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise AnalysisError("unsafe_archive_path")
    if len(name.encode("utf-8")) > 4096:
        raise AnalysisError("archive_path_too_long")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise AnalysisError("unsupported_archive_entry_type")
    if kind == stat.S_IFDIR and not info.is_dir():
        raise AnalysisError("archive_entry_type_conflict")
    if info.flag_bits & 1:
        raise AnalysisError("encrypted_archive_entry")
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        raise AnalysisError("unsupported_archive_compression")
    return "/".join(parts)


def categorize(name: str, head: bytes, directory: bool) -> str:
    if directory:
        return "directory"
    if name == "AndroidManifest.xml":
        return "android_manifest"
    if re.fullmatch(r"classes\d*\.dex", name):
        return "dex" if head.startswith(b"dex\n") else "dex_named_unverified"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                    b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}:
        return "macho_candidate"
    if name.endswith(".plist"):
        return "plist"
    if name == "resources.arsc":
        return "android_resources"
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    return "resource"


def preflight_directory(snapshot: Path, limits: ImportLimits) -> None:
    """Bound central-directory allocation before ZipFile parses entry objects."""
    with snapshot.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
    position = len(tail)
    while True:
        position = tail.rfind(b"PK\x05\x06", 0, position)
        if position < 0:
            raise AnalysisError("invalid_archive_directory")
        if len(tail) - position >= 22:
            _, disk, start, count_here, count, length, offset, comment = struct.unpack_from("<4s4H2LH", tail, position)
            if position + 22 + comment == len(tail):
                break
    if disk or start or count != count_here:
        raise AnalysisError("unsupported_multidisk_archive")
    if count == 65535 or length == 0xffffffff or offset == 0xffffffff:
        raise AnalysisError("unsupported_zip64_directory")
    if count > limits.member_count:
        raise AnalysisError("archive_member_count_exceeded")
    if length > 32 * 1024 * 1024:
        raise AnalysisError("archive_directory_size_exceeded")
    if offset + length > size - len(tail) + position:
        raise AnalysisError("invalid_archive_directory")


def inspect_archive(snapshot: Path, limits: ImportLimits, deadline: float) -> tuple[dict, list[dict]]:
    preflight_directory(snapshot, limits)
    members = []
    plist_records = {}
    seen = {}
    parents = set()
    total = 0
    with zipfile.ZipFile(snapshot) as archive:
        infos = archive.infolist()
        if len(infos) > limits.member_count:
            raise AnalysisError("archive_member_count_exceeded")
        for info in infos:
            check_time(deadline)
            name = member_name(info)
            if name in seen:
                raise AnalysisError("duplicate_archive_path")
            if name in parents and not info.is_dir():
                raise AnalysisError("archive_path_type_conflict")
            parts = name.split("/")
            for i in range(1, len(parts)):
                parent = "/".join(parts[:i])
                if parent in seen and not seen[parent]:
                    raise AnalysisError("archive_path_type_conflict")
                parents.add(parent)
            seen[name] = info.is_dir()
            if info.file_size > limits.member_bytes:
                raise AnalysisError("archive_member_size_exceeded")
            if info.file_size > max(info.compress_size, 1) * limits.compression_ratio:
                raise AnalysisError("archive_compression_ratio_exceeded")
            total += info.file_size
            if total > limits.total_bytes:
                raise AnalysisError("archive_total_size_exceeded")
            digest = hashlib.sha256()
            size = 0
            head = b""
            collect_plist = name.endswith("/Info.plist") and info.file_size <= 2 * 1024 * 1024
            plist_bytes = bytearray()
            with archive.open(info) as stream:
                while block := stream.read(CHUNK):
                    check_time(deadline)
                    size += len(block)
                    if size > limits.member_bytes or size > info.file_size:
                        raise AnalysisError("archive_member_size_exceeded")
                    digest.update(block)
                    if len(head) < 128:
                        head += block[:128 - len(head)]
                    if collect_plist:
                        plist_bytes.extend(block)
            if size != info.file_size or info.is_dir() and size:
                raise AnalysisError("archive_member_size_mismatch")
            if collect_plist:
                try:
                    obj = plistlib.loads(plist_bytes)
                    if isinstance(obj, dict):
                        # Do not persist arbitrary configuration values or secrets.
                        plist_records[name] = {k: v for k, v in obj.items()
                            if k in {"CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion", "CFBundleExecutable"}
                            and isinstance(v, str) and len(v) <= 1024}
                except (ValueError, TypeError, OverflowError, plistlib.InvalidFileException):
                    pass
            members.append({"path": name, "size": size, "compressed_size": info.compress_size,
                            "sha256": digest.hexdigest(), "category": categorize(name, head, info.is_dir()),
                            "directory": info.is_dir()})
    apk = seen.get("AndroidManifest.xml") is False
    mains = [name for name in seen if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name) and not seen[name]]
    if apk and mains:
        raise AnalysisError("ambiguous_package_type")
    if apk:
        kind, identity = "apk", {}
    elif len(mains) == 1:
        kind, identity = "ipa", plist_records.get(mains[0], {})
    elif len(mains) > 1:
        raise AnalysisError("ambiguous_ios_main_bundle")
    else:
        raise AnalysisError("unsupported_package_structure")
    frameworks = set()
    for m in members:
        name = m["path"]
        if name.endswith(("/libflutter.so", "/Flutter.framework/Flutter")):
            frameworks.add("flutter")
        if name.endswith(("/index.android.bundle", "/main.jsbundle", "/libreactnative.so", "/libhermes.so")):
            frameworks.add("react_native_or_javascript")
        if name.endswith(("/libil2cpp.so", "/UnityFramework.framework/UnityFramework")):
            frameworks.add("unity")
    counts = {}
    for m in members:
        counts[m["category"]] = counts.get(m["category"], 0) + 1
    return {"package_type": kind, "platform": "android" if kind == "apk" else "ios",
            "package_identity": identity, "member_count": len(members), "expanded_bytes": total,
            "category_counts": counts, "framework_indicators": sorted(frameworks),
            "identity_status": "structural_only", "inventory_complete": True,
            "security_analysis_performed": False,
            "limitations": ["结构识别与成员校验不证明可安装、签名有效或包安全。",
                            "尚未执行代码分析；未检出框架标记也不证明全部为原生业务。"]}, members


def import_artifact(store: Store, source: str, limits: ImportLimits | None = None) -> dict:
    limits = limits or ImportLimits()
    deadline = time.monotonic() + limits.wall_seconds
    path = Path(os.path.abspath(Path(source).expanduser()))
    staging = Path(tempfile.mkdtemp(prefix="import-", dir=store.root / "staging"))
    try:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise AnalysisError("source_unavailable_or_symlink") from None
        snapshot = staging / "package.bin"
        digest = hashlib.sha256()
        size = 0
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            os.close(fd)
            raise AnalysisError("source_not_regular_file")
        with os.fdopen(fd, "rb") as incoming:
            if before.st_size > limits.package_bytes:
                raise AnalysisError("package_size_exceeded")
            outfd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(outfd, "wb") as outgoing:
                while block := incoming.read(CHUNK):
                    check_time(deadline)
                    size += len(block)
                    if size > limits.package_bytes:
                        raise AnalysisError("package_size_exceeded")
                    digest.update(block)
                    outgoing.write(block)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            after = os.fstat(incoming.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise AnalysisError("source_changed_during_import")
        metadata, members = inspect_archive(snapshot, limits, deadline)
        sha256 = digest.hexdigest()
        artifact_id = "pkg_" + sha256
        record = {"artifact_id": artifact_id, "sha256": sha256, "size": size,
                  "imported_at": datetime.now(timezone.utc).isoformat(),
                  "import_limits": asdict(limits), **metadata}
        dest = store.artifact_path(artifact_id)
        if dest.exists() or dest.is_symlink():
            if dest.is_symlink() or not dest.is_dir() or digest_file(dest / "package.bin", deadline) != sha256:
                raise AnalysisError("snapshot_integrity_failed")
        else:
            try:
                os.rename(staging, dest)
            except OSError:
                if dest.is_symlink() or not dest.is_dir() or digest_file(dest / "package.bin", deadline) != sha256:
                    raise AnalysisError("snapshot_integrity_failed") from None
        return store.put(record, members)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, NotImplementedError, RuntimeError):
        raise AnalysisError("invalid_or_unsupported_archive") from None
    finally:
        if staging.exists():
            shutil.rmtree(staging)
