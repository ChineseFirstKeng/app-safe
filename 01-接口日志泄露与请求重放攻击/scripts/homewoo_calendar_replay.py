#!/usr/bin/env python3
"""
Homewoo 日历接口重放工具（授权测试用途）

用法：
  python3 homewoo_calendar_replay.py list
  python3 homewoo_calendar_replay.py create
  python3 homewoo_calendar_replay.py update
  python3 homewoo_calendar_replay.py delete

前提：
  1. Android 设备已通过 adb 连接；
  2. App 已登录；
  3. 目标请求已经由 App 发起并出现在 logcat 中。

脚本不会保存或打印密码、AccessToken、签名和完整响应内容。
它只重放日志中已经存在的完整请求，因此 create/update/delete 的请求体
必须先由测试 App 生成。
"""

import json
import hashlib
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from time import strftime

BASE = os.environ.get("HOMEWOO_TEST_BASE", "https://xhome-dev.sdmc.tv:18443/aihome/cloud-api/awp")
SUPPORTED = {
    "list": "/calendar/event/list",
    "verify": "/calendar/event/list",
    "create": "/calendar/event/create",
    "update": "/calendar/event/update",
    "delete": "/calendar/event/delete",
}


def get_log():
    raw = subprocess.check_output(
        ["adb", "logcat", "-d", "-b", "main", "-v", "brief"],
        text=True,
        errors="ignore",
    )
    lines = []
    for line in raw.splitlines():
        match = re.match(r"^[A-Z]/[^:]+:\s?(.*)$", line)
        lines.append(match.group(1) if match else line)
    return "\n".join(lines)


def field(block, name):
    match = re.search(r'"' + re.escape(name) + r'"\s*:\s*"([^"]*)"', block)
    return match.group(1) if match else ""


def digest(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def parse_request(action):
    log = get_log()
    endpoint = SUPPORTED[action]
    blocks = re.findall(r"XHOME_API .*?====================================", log, re.S)
    candidates = [
        block for block in reversed(blocks)
        if endpoint in block and "[requestBody]" in block
    ]
    if not candidates:
        raise RuntimeError("未找到对应接口日志，请先在 App 中发起该操作")

    block = candidates[0]
    body_section = block.split("[requestBody]", 1)[1].split(
        "====================================", 1
    )[0]
    start = body_section.find("{")
    if start < 0:
        raise RuntimeError("请求体解析失败")
    body, _ = json.JSONDecoder().raw_decode(body_section[start:])

    headers = {
        key: field(block, key)
        for key in (
            "signature",
            "signMethod",
            "encryptMethod",
            "timestamp",
            "clientId",
            "appVersion",
            "appType",
            "deviceModel",
            "osType",
            "osVersion",
            "countryCode",
            "langCode",
            "accessToken",
        )
    }
    headers["content-type"] = "application/json"
    if not headers["signature"] or not headers["accessToken"]:
        raise RuntimeError("日志中缺少签名或令牌")
    return endpoint, headers, body


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in SUPPORTED:
        print("用法：python3 homewoo_calendar_replay.py [list|create|update|delete|verify]")
        return 2

    action = sys.argv[1]
    parsed_base = urllib.parse.urlparse(BASE)
    if parsed_base.hostname != "xhome-dev.sdmc.tv" or parsed_base.port != 18443:
        raise RuntimeError("HOMEWOO_TEST_BASE 必须指向声明的授权开发端点")
    endpoint, headers, body = parse_request(action)
    request = urllib.request.Request(
        BASE + endpoint,
        data=json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode(),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read()
            result = json.loads(data)
            print(f"ACTION={action}")
            print(f"HTTP_STATUS={response.status}")
            print(f"RETURN_CODE={result.get('returnCode')}")
            if action in {"list", "verify"}:
                events = result.get("data", {}).get("events", [])
                print(f"EVENT_COUNT={len(events)}")
            elif action == "create":
                print(f"EVENT_ID_PRESENT={('eventId' in result.get('data', {}))}")
            else:
                print(f"RESPONSE_BYTES={len(data)}")
            if str(result.get("returnCode")) not in {"0", "200"}:
                print("BUSINESS_SUCCESS=false")
                return 1
            evidence = {
                "action": action,
                "http_status": response.status,
                "return_code": result.get("returnCode"),
            }
            if action in {"list", "verify"}:
                evidence["events"] = [
                    {
                        "event_key": digest(event.get("eventId")),
                        "state_hash": digest(json.dumps({
                            "title": event.get("title"),
                            "startTime": event.get("startTime"),
                            "endTime": event.get("endTime"),
                        }, sort_keys=True, ensure_ascii=False)),
                    }
                    for event in result.get("data", {}).get("events", [])
                ]
            elif action == "create":
                evidence["event_key"] = digest(result.get("data", {}).get("eventId"))
            evidence_dir = os.environ.get("EVIDENCE_DIR")
            if evidence_dir:
                path = Path(evidence_dir)
                path.mkdir(parents=True, exist_ok=True)
                output = path / f"replay-{action}-{strftime('%Y%m%d-%H%M%S')}.json"
                output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
                print(f"EVIDENCE_FILE={output}")
            print("BUSINESS_SUCCESS=true")
            return 0
    except urllib.error.HTTPError as error:
        print(f"ACTION={action}")
        print(f"HTTP_STATUS=HTTP_{error.code}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
