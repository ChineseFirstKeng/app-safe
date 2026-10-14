#!/usr/bin/env python3
"""Read-only evidence triage for Homewoo Android security review.

No network requests are made. The script does not print API keys, tokens,
log lines, HAR bodies, or app data file contents.
"""

import argparse
import collections
import json
import pathlib
import re
import shutil
import subprocess
import urllib.parse
import zipfile


MARKERS = {
    "1 API 日志": ("_logApiRequest", "_logApiExchange", "redactedLogFields"),
    "3 环境切换": ("xhome-dev.sdmc.tv", "xhome-test.sdmc.tv", "xhome-uat.sdmc.tv", "Switch environment"),
    "4 AES 配置": ("XHOME_SECRET_KEY",),
    "5 模拟通路": ("CalendarMockHttpClient", "MockCalendarRepository", "wall_planner_calendar_mock_enabled"),
}

# 第 4 项：32 位 ASCII 常量筛查。
# 自动区分“Dart 标识符”与“随机密钥”并不可靠，因此这里不做启发式分类，
# 改为对已确认的 4 个密钥做“首尾片段指纹”比对，作为回归检查。
# 仅保存首尾各 4 位，不含完整值。
KEY_LENGTH = 32
KEY_FINGERPRINTS = (
    ("JCcn", "Iucz"),
    ("LNIa", "YdyJ"),
    ("gplw", "MLgXW"),
    ("iiqI", "LfZP"),
)

LOG_PATTERNS = {
    "Authorization 字段": re.compile(r"\bauthorization\s*[:=]", re.I),
    "Cookie 字段": re.compile(r"\b(?:cookie|set-cookie)\s*[:=]", re.I),
    "令牌字段": re.compile(r"\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token)\s*[:=]", re.I),
    "密码/验证码字段": re.compile(r"\b(?:password|passwd|otp|verification[_-]?code)\s*[:=]", re.I),
}


def find_aapt():
    direct = shutil.which("aapt")
    if direct:
        return direct
    candidates = sorted(
        pathlib.Path.home().glob("Library/Android/sdk/build-tools/*/aapt"),
        reverse=True,
    )
    return str(candidates[0]) if candidates else None


def inspect_key_candidates(app: bytes) -> None:
    """第 4 项回归检查：按首尾片段指纹确认 4 个共享密钥是否仍在包内。"""
    pattern = re.compile(rb"(?<![A-Za-z0-9])[A-Za-z0-9]{%d}(?![A-Za-z0-9])" % KEY_LENGTH)
    tokens = {match.group().decode() for match in pattern.finditer(app)}
    print(f"32 位 ASCII 常量候选：{len(tokens)} 个（含 Dart 标识符，完整清单需人工核对）")
    for head, tail in KEY_FINGERPRINTS:
        hit = any(t.startswith(head) and t.endswith(tail) for t in tokens)
        state = "仍存在 ← 需处置" if hit else "未见"
        print(f"  第 4 项密钥指纹 {head}…{tail}: {state}")
    print("说明：只比对首尾片段，不输出完整值；'未见' 仅代表本包不再携带该密钥。")


def inspect_apk(path: pathlib.Path) -> None:
    with zipfile.ZipFile(path) as archive:
        app = archive.read("lib/arm64-v8a/libapp.so")
        resources = archive.read("resources.arsc")
    print("APK 本地证据；只报告存在性，不显示密钥或业务数据")
    for issue, markers in MARKERS.items():
        found = sum(marker.encode() in app for marker in markers)
        print(f"线索 {issue}: {found}/{len(markers)} 个标记可见")
    inspect_key_candidates(app)
    for name in ("google_api_key", "google_maps_api_key", "google_crash_reporting_api_key"):
        print(f"资源名 {name}:", name.encode() in resources)

    aapt = find_aapt()
    if not aapt:
        print("未找到 Android SDK aapt；Manifest 属性与权限需用 Android Studio APK Analyzer 核对。")
        return
    manifest = subprocess.run(
        [aapt, "dump", "xmltree", str(path), "AndroidManifest.xml"],
        capture_output=True, text=True, check=True,
    ).stdout
    badging = subprocess.run(
        [aapt, "dump", "badging", str(path)],
        capture_output=True, text=True, check=True,
    ).stdout
    package = re.search(r"package: name='([^']+)'", badging)
    target = re.search(r"targetSdkVersion:'([^']+)'", badging)
    print("包名:", package.group(1) if package else "未知")
    print("target SDK:", target.group(1) if target else "未知")
    for attr in ("allowBackup", "fullBackupContent", "dataExtractionRules", "networkSecurityConfig"):
        print(f"Manifest 显式设置 {attr}:", f"android:{attr}" in manifest)
    main = re.search(r'android:name[^\n]*="com\.sdmc\.homewoo\.MainActivity"[^\n]*\n([^\n]*)', manifest)
    print("MainActivity exported=true:", bool(main and "android:exported" in main.group(1) and "0xffffffff" in main.group(1)))
    permissions = re.findall(r"uses-permission: name='([^']+)'", badging)
    print("已声明权限:", ", ".join(permissions))
    print("说明：Manifest 属性缺省、字符串和资源名存在均不能证明运行时漏洞。")


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
    print("命中需人工核对脱敏情况；零命中不代表所有字段都安全。")


def inspect_har(path: pathlib.Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    origins = collections.Counter()
    for entry in data.get("log", {}).get("entries", []):
        parsed = urllib.parse.urlsplit(entry.get("request", {}).get("url", ""))
        if parsed.scheme in ("http", "https"):
            origins[(parsed.scheme, parsed.hostname or "未知")] += 1
    print("HAR 请求目的地；不显示路径、查询参数、请求头或响应内容")
    for (scheme, host), count in sorted(origins.items()):
        print(f"{scheme}://{host}: {count}")
    print("只覆盖 HAR 已捕获的流量；代理未捕获的请求需另查。")


def inspect_container(path: pathlib.Path) -> None:
    counts = collections.Counter()
    for item in path.rglob("*"):
        if item.is_file() and not item.is_symlink():
            counts[item.suffix.lower() or "无扩展名"] += 1
    print("测试 App 容器文件类型计数；不显示文件名、路径或内容")
    for extension, count in sorted(counts.items()):
        print(f"{extension}: {count}")
    print("文件清单不能证明内容、备份范围或 Keystore 密钥可迁移性。")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("apk", "logs", "har", "container"))
    parser.add_argument("path", type=pathlib.Path)
    args = parser.parse_args()
    if not args.path.exists():
        parser.error("输入路径不存在")
    {"apk": inspect_apk, "logs": inspect_logs, "har": inspect_har, "container": inspect_container}[args.mode](args.path)


if __name__ == "__main__":
    main()
