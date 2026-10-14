#!/usr/bin/env python3
"""Homewoo 二次打包测试用 Mock 服务，只返回伪造日历数据。"""

import json
import os
import urllib.error
import urllib.request
import ipaddress
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


UPSTREAM_BASE = os.environ.get("UPSTREAM_TEST_BASE", "https://xhome-dev.sdmc.tv:18443")


def validated_upstream_base():
    parsed = urllib.parse.urlparse(UPSTREAM_BASE)
    if parsed.scheme != "https" or parsed.hostname != "xhome-dev.sdmc.tv" or parsed.port != 18443:
        raise SystemExit(
            "UPSTREAM_TEST_BASE 只能是授权开发测试端点 https://xhome-dev.sdmc.tv:18443"
        )
    return UPSTREAM_BASE.rstrip("/")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        request_body = self.rfile.read(length)
        if "/calendar/event/list" not in self.path or os.environ.get("PASSTHROUGH_LIST") == "1":
            if os.environ.get("ALLOW_UPSTREAM_PROXY") != "1":
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                body = b'{"returnCode":502,"returnMsg":"upstream proxy disabled in lab mock"}'
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                print("MOCK_PROXY_BLOCKED", self.path, flush=True)
                return
            self.proxy_to_real_api(request_body)
            return
        payload = {
            "returnCode": 200,
            "returnMsg": "success",
            "data": {
                "events": [
                    {
                        "eventId": 999999,
                        "instanceId": 999999,
                        "title": "TAMPERED_BY_REPACKAGED_APP",
                        "description": "mock response",
                        "location": "local-mock",
                        "isAllDay": False,
                        "startDate": None,
                        "endDate": None,
                        "isCountdown": False,
                        "createTime": 1791788400,
                        "updateTime": 1791788400,
                        "reminder": None,
                        "externalSyncStatus": None,
                        "externalSyncErrorCode": None,
                        # 客户端按毫秒时间戳解析；对应 2026-10-12 15:00—16:00（Asia/Shanghai）。
                        "startTime": 1791788400,
                        "endTime": 1791792000,
                        "timezone": "Asia/Shanghai",
                        "participantProfileIds": [2099380671194898434],
                    }
                ],
                "total": 1,
            },
        }
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        marker = f"MOCK_RESPONSE_SENT marker=TAMPERED_BY_REPACKAGED_APP path={self.path}\n"
        print(marker.rstrip(), flush=True)
        evidence_file = os.environ.get("MOCK_EVIDENCE_FILE")
        if evidence_file:
            with open(evidence_file, "a", encoding="utf-8") as handle:
                handle.write(marker)

    def proxy_to_real_api(self, request_body):
        """将非目标接口转发到原开发环境，保持登录和页面加载能力。"""
        url = validated_upstream_base() + self.path
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"host", "content-length"}
        }
        request = urllib.request.Request(
            url, data=request_body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read()
                self.send_response(response.status)
                for key in ("Content-Type", "Content-Length"):
                    if response.headers.get(key):
                        self.send_header(key, response.headers[key])
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as error:
            body = error.read()
            self.send_response(error.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        print("MOCK_PROXY", self.path, flush=True)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    validated_upstream_base()
    host = os.environ.get("MOCK_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("MOCK_PORT", "18443"))
    try:
        address = ipaddress.ip_address(host)
        if not (address.is_private or address.is_loopback):
            raise ValueError
    except ValueError:
        if host != "localhost":
            raise SystemExit("MOCK_BIND_HOST 必须是 localhost 或私有 IP")
    print(f"MOCK_LISTENING={host}:{port}", flush=True)
    HTTPServer((host, port), Handler).serve_forever()
