"""Install hash-pinned engines inside this project; never edit shell/client settings."""
import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
import argparse
import platform
from pathlib import Path

project = Path(__file__).resolve().parents[1]
lock = json.loads((project / "engines.lock.json").read_text())
host = "macos-arm64" if platform.system() == "Darwin" and platform.machine() == "arm64" else platform.system().lower()+"-"+platform.machine()
if host != lock["host"]:
    raise SystemExit("This engine lock targets " + lock["host"] + "; prepare and review a host-specific lock first.")
parser = argparse.ArgumentParser()
parser.add_argument("--engines", nargs="+", choices=["jdk", "jadx", "ghidra"], default=["jdk", "jadx", "ghidra"])
options = parser.parse_args()
root = project / ".tools"
root.mkdir(mode=0o700, exist_ok=True)
for name, engine in lock["engines"].items():
    if name not in options.engines:
        continue
    destination = root / name
    if (destination / ".installed.json").is_file():
        if json.loads((destination / ".installed.json").read_text()) == engine:
            print(name + ": already installed", flush=True)
            continue
        raise SystemExit(name + ": existing installation differs; preserve it and review explicitly")
    archive = root / engine["file"]
    if not archive.exists():
        from engine_download import download, DownloadError
        print(name + ": resolving pinned official release and resuming chunks", flush=True)
        try:download(engine, archive)
        except DownloadError as error:raise SystemExit(name + ": " + str(error)) from None
    digest = hashlib.sha256()
    with archive.open("rb") as incoming:
        while block := incoming.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != engine["sha256"] or archive.stat().st_size != engine["size"]:
        raise SystemExit(name + ": checksum or size mismatch")
    staging = Path(tempfile.mkdtemp(dir=root, prefix="install-"))
    try:
        if engine["file"].endswith(".tar.gz"):
            with tarfile.open(archive) as source:
                source.extractall(staging, filter="data")
        else:
            with zipfile.ZipFile(archive) as source:
                for member in source.infolist():
                    path = Path(member.filename)
                    if path.is_absolute() or ".." in path.parts or stat.S_ISLNK(member.external_attr >> 16):
                        raise SystemExit(name + ": unsafe official archive entry")
                source.extractall(staging)
                for member in source.infolist():
                    target = staging / member.filename
                    if not member.is_dir() and member.external_attr >> 16 & 0o111:
                        target.chmod(0o755)
        children = list(staging.iterdir())
        payload = children[0] if len(children) == 1 and children[0].is_dir() else staging
        os.rename(payload, destination)
        (destination / ".installed.json").write_text(json.dumps(engine, indent=2))
        print(name + ": checksum verified, project-local installation complete", flush=True)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
