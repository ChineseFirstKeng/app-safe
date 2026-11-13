"""Build the macOS arm64 decompiler from the verified official distribution.

Uses the included Makefile and generated parsers; no Gradle/network download or
global installation. This builds the analysis engine, never the analysis target.
"""
import hashlib
import json
import os
import platform
import shutil
import subprocess
import zipfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def build():
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise RuntimeError("native_build_host_not_validated")
    engine = json.loads((PROJECT / "engines.lock.json").read_text())["engines"]["ghidra"]
    installed = PROJECT / ".tools/ghidra"
    if json.loads((installed / ".installed.json").read_text()) != engine:
        raise RuntimeError("native_build_installation_identity_mismatch")
    archive = PROJECT / ".tools" / engine["file"]
    with archive.open("rb") as incoming:
        if hashlib.file_digest(incoming, "sha256").hexdigest() != engine["sha256"]:
            raise RuntimeError("native_build_archive_digest_mismatch")
    relative = "Ghidra/Features/Decompiler/src/decompile/cpp/"
    source = installed / relative
    inputs, digest = [], hashlib.sha256()
    with zipfile.ZipFile(archive) as package:
        for member in sorted(package.namelist()):
            marker = "/" + relative
            if marker not in member:continue
            name = member.split(marker, 1)[1]
            if "/" in name or not (name.endswith((".cc", ".hh", ".h")) or name == "Makefile"):continue
            raw = package.read(member)
            if (source / name).read_bytes() != raw:
                raise RuntimeError("native_build_source_digest_mismatch")
            item = {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}
            inputs.append(item)
            digest.update(name.encode()+b"\0"+bytes.fromhex(item["sha256"]))
    if len(inputs) < 100:raise RuntimeError("native_build_sources_missing")
    compiler = "/usr/bin/clang++"
    compiler_version = subprocess.run([compiler, "--version"], check=True, capture_output=True, text=True).stdout.splitlines()[0]
    arguments = ["/usr/bin/make", "-j4", "-o", "grammar.cc", "-o", "xml.cc", "ghidra_opt",
                 "CXX="+compiler+" -std=c++11", "ARCH_TYPE=-arch arm64",
                 "ADDITIONAL_FLAGS=-mmacosx-version-min=11.0 -w", "OSDIR=mac_arm_64"]
    output = PROJECT / "runtime/setup"
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    log = output / "ghidra-native-build.log"
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    print("building official decompiler sources for macOS arm64", flush=True)
    with os.fdopen(fd, "wb") as stream:
        result = subprocess.run(arguments, cwd=source, stdin=subprocess.DEVNULL, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=600)
    if result.returncode:raise RuntimeError("native_decompiler_build_failed_see_private_log")
    built = source / "ghidra_opt"
    filetype = subprocess.run(["/usr/bin/file", "-b", str(built)], check=True, capture_output=True, text=True).stdout.strip()
    if "Mach-O" not in filetype or "arm64" not in filetype:raise RuntimeError("native_decompiler_wrong_architecture")
    target = installed / "Ghidra/Features/Decompiler/build/os/mac_arm_64/decompile"
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(built, target)
    target.chmod(0o755)
    metadata = {"status": "built", "engine_version": engine["version"], "archive_sha256": engine["sha256"],
        "source_tree_sha256": digest.hexdigest(), "source_count": len(inputs), "compiler": compiler_version,
        "arguments": arguments, "binary_path": str(target.relative_to(PROJECT)), "binary_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "filetype": filetype, "network_used": False, "target_application_executed": False}
    (output / "ghidra-native-build.json").write_text(json.dumps(metadata, indent=2))
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":build()
