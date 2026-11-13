"""Resolve an official asset once, resume ranged chunks, verify before activation."""
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse


class DownloadError(RuntimeError):
    pass


def resolve_asset(engine):
    curl = shutil.which("curl")
    if not curl:
        raise DownloadError("curl_missing")
    url = engine.get("api_asset_url", engine["url"])
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {"api.github.com", "github.com"} or parsed.username:
        raise DownloadError("unapproved_official_asset_url")
    result = subprocess.run([curl, "--disable", "--ipv4", "--silent", "--show-error", "--fail", "--location",
        "--proto", "=https", "--proto-redir", "=https", "--max-redirs", "3",
        "--header", "Accept: application/octet-stream", "--range", "0-0",
        "--connect-timeout", "8", "--max-time", "30", "--output", os.devnull,
        "--write-out", "%{http_code}\n%{url_effective}", url], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    if result.returncode or len(lines) != 2 or lines[0] not in {"200", "206"}:
        raise DownloadError("official_asset_resolve_failed_http_" + (lines[0] if lines else "unknown"))
    location = urlparse(lines[1])
    if location.scheme != "https" or location.hostname not in {"release-assets.githubusercontent.com", "objects.githubusercontent.com"} or location.username:
        raise DownloadError("unapproved_official_asset_redirect")
    # Do not print or persist the signed download URL. Subsequent chunks use CDN
    # directly, without consuming another GitHub REST request for every chunk.
    return lines[1]


def fetch_chunk(url, directory, index, start, stop, total, attempts=3):
    location = urlparse(url)
    if location.scheme != "https" and not (location.scheme == "http" and location.hostname in {"127.0.0.1", "::1", "localhost"}):
        raise DownloadError("unapproved_download_transport")
    destination = directory / str(index)
    length = stop - start + 1
    if destination.is_file() and not destination.is_symlink() and destination.stat().st_size == length:
        return
    temporary, headers = directory / (str(index) + ".part"), directory / (str(index) + ".headers")
    for attempt in range(attempts):
        for path in (temporary, headers):
            if path.is_symlink():raise DownloadError("unsafe_download_cache")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        result = subprocess.run([shutil.which("curl"), "--disable", "--ipv4", "--silent", "--show-error", "--fail",
            "--proto", "=https,http", "--range", f"{start}-{stop}", "--connect-timeout", "8", "--max-time", "30",
            "--max-filesize", str(length),
            "--dump-header", str(headers), "--output", str(temporary), "--write-out", "%{http_code}", url],
            capture_output=True, text=True)
        ranges = [line.split(":", 1)[1].strip() for line in headers.read_text(errors="replace").splitlines()
                  if line.lower().startswith("content-range:")]
        if not result.returncode and result.stdout == "206" and ranges and ranges[-1] == f"bytes {start}-{stop}/{total}" and temporary.stat().st_size == length:
            os.replace(temporary, destination)
            headers.unlink()
            return
        if result.stdout in {"403", "429"}:
            raise DownloadError("download_range_rejected_http_" + result.stdout)
        if attempt + 1 < attempts:
            time.sleep(1)
    raise DownloadError("download_range_failed_" + str(index))


def download(engine, archive, parallel=4, chunk_size=1024 * 1024, resolver=resolve_asset):
    archive = Path(archive)
    if archive.exists():
        if archive.is_symlink() or archive.stat().st_size != engine["size"]:
            raise DownloadError("existing_archive_mismatch")
        with archive.open("rb") as incoming:
            if hashlib.file_digest(incoming, "sha256").hexdigest() != engine["sha256"]:
                raise DownloadError("existing_archive_mismatch")
        return
    directory = archive.parent / (archive.name + ".chunks")
    if directory.is_symlink():raise DownloadError("unsafe_download_cache")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = {"sha256": engine["sha256"], "size": engine["size"], "chunk_size": chunk_size}
    statefile = directory / "state.json"
    if statefile.exists():
        if statefile.is_symlink() or json.loads(statefile.read_text()) != state:raise DownloadError("download_cache_identity_mismatch")
    else:
        fd = os.open(statefile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as out:json.dump(state, out)
    count = (engine["size"] + chunk_size - 1) // chunk_size
    pending = [i for i in range(count) if not (directory / str(i)).is_file() or (directory / str(i)).stat().st_size != min(chunk_size, engine["size"]-i*chunk_size)]
    if pending:
        url = resolver(engine)
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=parallel)
        futures = [pool.submit(fetch_chunk, url, directory, i, i*chunk_size,
                              min(engine["size"], (i+1)*chunk_size)-1, engine["size"]) for i in pending]
        try:
            for finished, future in enumerate(concurrent.futures.as_completed(futures), 1):
                future.result()
                if finished % 16 == 0:print("download: complete chunks", count-len(pending)+finished, "/", count, flush=True)
        finally:
            for future in futures:future.cancel()
            pool.shutdown(wait=True, cancel_futures=True)
    temporary = archive.parent / (archive.name + ".assembling")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    digest = hashlib.sha256()
    with os.fdopen(fd, "wb") as out:
        for i in range(count):
            part = directory / str(i)
            if part.is_symlink():raise DownloadError("unsafe_download_cache")
            block = part.read_bytes();digest.update(block);out.write(block)
        out.flush();os.fsync(out.fileno())
    if temporary.stat().st_size != engine["size"] or digest.hexdigest() != engine["sha256"]:
        raise DownloadError("download_checksum_mismatch")
    os.replace(temporary, archive)
    print("download: whole archive SHA-256 verified", flush=True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("engine", choices=["jdk", "jadx", "ghidra"])
    parser.add_argument("--parallel", type=int, choices=range(1, 17), default=4)
    options = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    engine = json.loads((project / "engines.lock.json").read_text())["engines"][options.engine]
    try:download(engine, project / ".tools" / engine["file"], options.parallel)
    except DownloadError as error:raise SystemExit(str(error)) from None
