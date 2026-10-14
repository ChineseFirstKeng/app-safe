#!/usr/bin/env python3
"""点击篡改首页中的测试按钮，证明落地页请求由篡改页面触发。"""

import re
import subprocess
import sys


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=True)
    return result.stdout


def main() -> int:
    label = "打开测试落地页"
    run("adb", "shell", "uiautomator", "dump", "/sdcard/homewoo-click.xml")
    xml = run("adb", "shell", "cat", "/sdcard/homewoo-click.xml")
    match = re.search(rf'text="{re.escape(label)}"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml)
    if not match:
        print(f"CLICK_FAILED: 未找到按钮 {label}", file=sys.stderr)
        return 1
    x1, y1, x2, y2 = map(int, match.groups())
    x = (x1 + x2) // 2
    y = (y1 + y2) // 2
    run("adb", "shell", "su", "-c", f"input tap {x} {y}")
    print(f"CLICKED_TEST_LANDING_BUTTON=true x={x} y={y}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
