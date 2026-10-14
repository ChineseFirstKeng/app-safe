#!/usr/bin/env python3
"""Read-only evidence triage for Homewoo iOS security review.

This script never sends network requests or prints API keys, tokens, log lines,
HAR bodies, or container file contents.
"""

import argparse
import collections
import json
import pathlib
import plistlib
import re
import urllib.parse
import zipfile


MARKERS = {
    "1 日志路径": ("_logApiRequest", "_logApiExchange", "redactedLogFields"),
    "2 OAuth 回调": ("CalendarGoogleOAuthCallbackBridge", "oauthCallback"),
    "3 环境切换": ("xhome-dev.sdmc.tv", "xhome-test.sdmc.tv", "xhome-uat.sdmc.tv", "Switch environment"),
    "4 AES 配置": ("XHOME_SECRET_KEY",),
    "6 测试路径": ("mock-oauth-attempt-", "mock-google-oauth-", "IntegrationTestPlugin"),
}

LOG_PATTERNS = {
    "Authorization 字段": re.compile(r"\bauthorization\s*[:=]", re.I),
    "Cookie 字段": re.compile(r"\b(?:cookie|set-cookie)\s*[:=]", re.I),
    "令牌字段": re.compile(r"\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token)\s*[:=]", re.I),
    "密码/验证码字段": re.compile(r"\b(?:password|passwd|otp|verification[_-]?code)\s*[:=]", re.I),
}


def inspect_ipa(path: pathlib.Path) -> None:
    with zipfile.ZipFile(path) as archive:
        app = archive.read("Payload/Runner.app/Frameworks/App.framework/App")
        runner = archive.read("Payload/Runner.app/Runner")
        info = plistlib.loads(archive.read("Payload/Runner.app/Info.plist"))
        firebase = plistlib.loads(archive.read("Payload/Runner.app/GoogleService-Info.plist"))
        names = archive.namelist()

    print("IPA 本地证据；只报告存在性，不显示密钥或业务数据")
    print("Bundle ID:", info.get("CFBundleIdentifier", "未知"))
    print("ATS 全局放宽:", bool(info.get("NSAppTransportSecurity", {}).get("NSAllowsArbitraryLoads")))
    schemes = sorted({scheme for item in info.get("CFBundleURLTypes", []) for scheme in item.get("CFBundleURLSchemes", [])})
    print("URL Scheme 数量:", len(schemes))
    print("homewoo Scheme:", "homewoo" in schemes)
    print("Google 回调 Scheme:", any(s.startswith("com.googleusercontent.apps.") for s in schemes))
    print("Maps Key 已配置:", bool(info.get("GOOGLE_MAPS_API_KEY")))
    print("Firebase Key 已配置:", bool(firebase.get("API_KEY")))
    for name in ("flutter_debug_kit", "integration_test", "flutter_secure_storage_darwin", "sqflite_darwin", "AppCheckCore"):
        prefix = f"Payload/Runner.app/Frameworks/{name}.framework/{name}"
        print(f"框架 {name}:", prefix in names)
    for issue, markers in MARKERS.items():
        found = sum(marker.encode() in app or marker.encode() in runner for marker in markers)
        print(f"线索 {issue}: {found}/{len(markers)} 个标记可见")
    print("说明：字符串和框架存在不证明代码可达或服务端存在漏洞。")


def inspect_logs(path: pathlib.Path) -> None:
    counts = collections.Counter()
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            for label, pattern in LOG_PATTERNS.items():
                if pattern.search(line):
                    counts[label] += 1
    print("日志敏感字段命中次数；不输出原文和值")
    for label in LOG_PATTERNS:
        print(f"{label}: {counts[label]}")
    print("命中只表示需人工核对脱敏情况；零命中不代表所有字段都安全。")


def inspect_har(path: pathlib.Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    origins = collections.Counter()
    for entry in entries:
        raw_url = entry.get("request", {}).get("url", "")
        parsed = urllib.parse.urlsplit(raw_url)
        if parsed.scheme in ("http", "https"):
            origins[(parsed.scheme, parsed.hostname or "未知")] += 1
    print("HAR 请求目的地；不显示路径、查询参数、请求头或响应内容")
    for (scheme, host), count in sorted(origins.items()):
        print(f"{scheme}://{host}: {count}")
    print("注意：仅能检查 HAR 已捕获的流量；代理未捕获的 Dart Socket 请求需另查。")


def inspect_container(path: pathlib.Path) -> None:
    counts = collections.Counter()
    for item in path.rglob("*"):
        if item.is_file() and not item.is_symlink():
            counts[item.suffix.lower() or "无扩展名"] += 1
    print("测试 App 容器文件类型计数；不显示文件名、路径或内容")
    for extension, count in sorted(counts.items()):
        print(f"{extension}: {count}")
    print("注意：容器清单不包含 Keychain，也不能证明文件保护级别或备份策略。")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("ipa", "logs", "har", "container"))
    parser.add_argument("path", type=pathlib.Path)
    args = parser.parse_args()
    if not args.path.exists():
        parser.error("输入路径不存在")
    {"ipa": inspect_ipa, "logs": inspect_logs, "har": inspect_har, "container": inspect_container}[args.mode](args.path)


if __name__ == "__main__":
    main()
