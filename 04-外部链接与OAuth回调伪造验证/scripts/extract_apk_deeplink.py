#!/usr/bin/env python3
"""只读提取 APK Manifest 中 MainActivity 的导出和深链配置。"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def find_aapt():
    if os.environ.get("AAPT"):
        return os.environ["AAPT"]
    direct = shutil.which("aapt")
    if direct:
        return direct
    sdk = Path.home() / "Library/Android/sdk/build-tools"
    matches = sorted(sdk.glob("*/aapt"), reverse=True)
    if matches:
        return str(matches[0])
    raise RuntimeError("找不到 aapt；设置 AAPT=/path/to/aapt 后重试")


def main():
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} /path/to/app.apk", file=sys.stderr)
        return 2
    apk = Path(sys.argv[1]).resolve()
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        raise RuntimeError(f"APK 不存在或后缀不正确: {apk}")
    aapt = find_aapt()
    badging = subprocess.run([aapt, "dump", "badging", str(apk)], check=True, capture_output=True, text=True).stdout
    manifest = subprocess.run([aapt, "dump", "xmltree", str(apk), "AndroidManifest.xml"], check=True, capture_output=True, text=True).stdout
    package = re.search(r"^package: name='([^']+)'", badging, re.M)
    print(f"APK={apk}")
    print(f"SHA256={hashlib.sha256(apk.read_bytes()).hexdigest()}")
    print(f"PACKAGE={package.group(1) if package else 'UNKNOWN'}")
    print("SOURCE=AndroidManifest.xml (aapt dump xmltree)")

    lines = manifest.splitlines()
    target = '"com.sdmc.homewoo.MainActivity"'
    name_index = next((i for i, line in enumerate(lines) if target in line), None)
    if name_index is None:
        raise RuntimeError("未在 Manifest 中找到 com.sdmc.homewoo.MainActivity")
    start = next((i for i in range(name_index, -1, -1) if re.match(r"^      E: activity ", lines[i])), None)
    if start is None:
        raise RuntimeError("无法定位 MainActivity 所属 activity 区块")
    end = next((i for i in range(start + 1, len(lines)) if re.match(r"^      E: (activity|service|receiver|provider|meta-data|uses-library) ", lines[i])), len(lines))
    block = lines[start:end]
    keys = (
        "MainActivity", "android:exported", "android.intent.action.VIEW",
        "android.intent.category.BROWSABLE", "android:scheme", "android:host",
        "android:pathPrefix", "android.intent.action.MAIN", "android.intent.category.LAUNCHER",
    )
    for line in block:
        if any(key in line for key in keys):
            print(line.strip())
    print("说明：exported=0xffffffff 表示 true；这些配置只证明外部入口存在，不证明 OAuth 可被绕过。")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        raise SystemExit(1)
