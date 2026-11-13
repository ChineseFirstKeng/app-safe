from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from ..artifacts import CHUNK, digest_file
from ..errors import AnalysisError


class MobSFAdapter:
    """Local synchronous REST adapter. No redirects, ambient proxy or target URLs."""

    adapter_version = "0.1.0"

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 timeout: float = 600, response_limit: int = 20 * 1024 * 1024):
        base_url = base_url if base_url is not None else os.environ.get("NATIVE_SECURITY_MOBSF_URL", "")
        self.api_key = api_key if api_key is not None else os.environ.get("NATIVE_SECURITY_MOBSF_API_KEY", "")
        if not base_url or not self.api_key:
            raise AnalysisError("mobsf_not_configured")
        try:
            url = urlsplit(base_url)
            self.port = url.port
        except ValueError:
            raise AnalysisError("invalid_mobsf_configuration") from None
        if (url.scheme not in {"http", "https"} or url.hostname not in {"localhost", "127.0.0.1", "::1"}
                or url.username or url.password or url.path not in {"", "/"} or url.query or url.fragment
                or any(ord(c) < 32 or ord(c) > 126 for c in self.api_key)
                or not 1 <= timeout <= 3600 or not 1024 <= response_limit <= 100 * 1024 * 1024):
            raise AnalysisError("invalid_mobsf_configuration")
        self.host, self.scheme = url.hostname, url.scheme
        self.timeout, self.response_limit = timeout, response_limit

    def _post(self, endpoint: str, body, content_type: str, length: int, deadline: float) -> tuple[dict, bytes]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AnalysisError("mobsf_time_budget_exceeded")
        if self.scheme == "https":
            connection = http.client.HTTPSConnection(self.host, self.port, timeout=remaining,
                                                     context=ssl.create_default_context())
        else:
            connection = http.client.HTTPConnection(self.host, self.port, timeout=remaining)
        try:
            connection.request("POST", "/api/v1/" + endpoint, body=body, headers={
                "X-Mobsf-Api-Key": self.api_key, "Content-Type": content_type,
                "Content-Length": str(length), "Accept": "application/json"})
            response = connection.getresponse()
            if response.status in {401, 403}:
                raise AnalysisError("mobsf_authentication_failed")
            if response.status != 200:
                raise AnalysisError("mobsf_http_error")
            parts = []
            size = 0
            while True:
                if time.monotonic() >= deadline:
                    raise AnalysisError("mobsf_time_budget_exceeded")
                block = response.read1(min(CHUNK, self.response_limit - size + 1))
                if not block:
                    break
                size += len(block)
                if size > self.response_limit:
                    raise AnalysisError("mobsf_response_limit_exceeded")
                parts.append(block)
            raw = b"".join(parts)
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON key")
                    result[key] = value
                return result
            try:
                result = json.loads(raw, object_pairs_hook=unique_object)
            except (ValueError, RecursionError):
                raise AnalysisError("mobsf_invalid_json") from None
            if not isinstance(result, dict) or "error" in result:
                raise AnalysisError("mobsf_invalid_or_error_response")
            return result, raw
        except (socket.timeout, TimeoutError):
            raise AnalysisError("mobsf_time_budget_exceeded") from None
        except (OSError, http.client.HTTPException):
            raise AnalysisError("mobsf_connection_failed") from None
        finally:
            connection.close()

    @staticmethod
    def _save(directory: Path, name: str, raw: bytes) -> dict:
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                "representation": "http_response_body"}

    def scan(self, snapshot: Path, package_type: str, artifact_sha256: str, output: Path) -> dict:
        if package_type not in {"apk", "ipa"} or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256):
            raise AnalysisError("invalid_mobsf_input")
        deadline = time.monotonic() + self.timeout
        if digest_file(snapshot, deadline) != artifact_sha256:
            raise AnalysisError("snapshot_integrity_failed")
        if output.is_symlink():
            raise AnalysisError("unsafe_storage_path")
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        # Use a fixed synthetic upload name; source paths and names never leave the adapter.
        boundary = "native-security-" + secrets.token_hex(16)
        prefix = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                  f"filename=\"artifact.{package_type}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
        suffix = f"\r\n--{boundary}--\r\n".encode()
        md5 = hashlib.md5(usedforsecurity=False)
        uploaded_sha = hashlib.sha256()

        def upload_chunks():
            yield prefix
            with snapshot.open("rb") as stream:
                while block := stream.read(CHUNK):
                    if time.monotonic() >= deadline:
                        raise AnalysisError("mobsf_time_budget_exceeded")
                    md5.update(block)
                    uploaded_sha.update(block)
                    yield block
            yield suffix

        uploaded, raw = self._post("upload", upload_chunks(), f"multipart/form-data; boundary={boundary}",
                              len(prefix) + snapshot.stat().st_size + len(suffix), deadline)
        receipts = [self._save(output, "upload.json", raw)]
        if uploaded_sha.hexdigest() != artifact_sha256:
            raise AnalysisError("snapshot_changed_during_upload")
        if uploaded.get("hash") != md5.hexdigest() or uploaded.get("scan_type") != package_type:
            raise AnalysisError("mobsf_upload_identity_mismatch")
        fields = urlencode({"hash": uploaded["hash"], "scan_type": package_type,
                            "file_name": f"artifact.{package_type}", "re_scan": "1"}).encode()
        scanned, raw = self._post("scan", fields, "application/x-www-form-urlencoded", len(fields), deadline)
        receipts.append(self._save(output, "scan.json", raw))
        if "task_id" in scanned or scanned.get("status") in {"queued", "pending", "running"}:
            raise AnalysisError("mobsf_async_mode_not_supported")
        fields = urlencode({"hash": uploaded["hash"]}).encode()
        report, raw = self._post("report_json", fields, "application/x-www-form-urlencoded", len(fields), deadline)
        receipts.append(self._save(output, "report.json", raw))
        if report.get("sha256") != artifact_sha256:
            raise AnalysisError("mobsf_report_identity_mismatch_or_unavailable")
        return {"provider": "mobsf", "adapter_version": self.adapter_version,
                "engine_version": None, "artifact_sha256": artifact_sha256,
                "status": "baseline_report_received", "receipts": receipts,
                "independent_verification": False,
                "limitations": ["保存的是提供方报告；尚未独立证明漏洞用途、可达性或可利用性。",
                                "引擎版本及提供方完整覆盖未验证；仅支持本机同步扫描服务。",
                                "控制面连接仅指向本机；提供方容器网络隔离需单独配置和验收。"]}
