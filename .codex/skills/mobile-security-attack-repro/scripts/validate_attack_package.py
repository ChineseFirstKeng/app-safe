#!/usr/bin/env python3
"""Validate a generated authorized mobile attack reproduction directory."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_SECTIONS = (
    "攻击目标与范围",
    "前置条件",
    "攻击手段",
    "攻击获得信息",
    "攻击流程和操作",
    "工具、脚本和参数",
    "攻击成功判据",
    "实际验证结果",
    "可能造成的后果",
    "防护方案",
    "清理和恢复",
    "局限和未验证事项",
)

SECRET_PATTERNS = (
    re.compile(r"(?i)password\s*[:=]\s*[^\s`]+"),
    re.compile(r"(?i)(access[_-]?token|bearer|cookie)\s*[:=]\s*[^\s`]+"),
    re.compile(r"(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

FORBIDDEN_EXTERNAL = re.compile(r"https?://(?:www\.)?baidu\.com", re.IGNORECASE)


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"用法: {Path(sys.argv[0]).name} <攻击目录>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1]).resolve()
    errors: list[str] = []
    if not root.is_dir():
        print(f"ERROR: 目录不存在: {root}", file=sys.stderr)
        return 2

    reports = sorted(root.glob("*.md"))
    if not reports:
        fail(errors, "缺少 Markdown 攻击报告")
    else:
        report = reports[0]
        text = report.read_text(encoding="utf-8", errors="replace")
        for section in REQUIRED_SECTIONS:
            if section not in text:
                fail(errors, f"报告缺少章节: {section}")
            if len(re.findall(rf"^###+ {re.escape(section)}$", text, re.MULTILINE)) > 1:
                fail(errors, f"报告重复章节: {section}")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                fail(errors, f"报告疑似包含敏感凭据模式: {pattern.pattern}")
        if FORBIDDEN_EXTERNAL.search(text):
            fail(errors, "报告包含未声明的第三方外部地址")

    mains = sorted(root.glob("run_*.sh"))
    if not mains:
        fail(errors, "缺少 run_*.sh 主流程脚本")
    else:
        for main in mains:
            main_text = main.read_text(encoding="utf-8", errors="replace")
            if not main.stat().st_mode & 0o111:
                fail(errors, f"主流程脚本不可执行: {main.name}")
            if "help" not in main_text:
                fail(errors, f"主流程脚本缺少 help: {main.name}")
            for command in ("preflight", "verify", "restore"):
                if command not in main_text and command == "preflight":
                    fail(errors, f"主流程脚本缺少 {command} 检查入口: {main.name}")
            if "verify" not in main_text:
                fail(errors, f"主流程脚本缺少 verify 入口: {main.name}")
            if "restore" not in main_text:
                fail(errors, f"主流程脚本缺少 restore 入口: {main.name}")
            verify_block = re.search(r"\n\s*verify\)\n(?P<body>.*?)(?:\n\s*;;)", main_text, re.DOTALL)
            if verify_block and "|| true" in verify_block.group("body"):
                fail(errors, f"verify 分支允许失败后继续返回: {main.name}")
            if verify_block and not re.search(r"EVIDENCE|VERIFY|sha256", verify_block.group("body"), re.IGNORECASE):
                fail(errors, f"verify 分支缺少可检查证据或成功判据: {main.name}")

    referenced = set()
    for report in reports:
        text = report.read_text(encoding="utf-8", errors="replace")
        referenced.update(re.findall(r"(?:scripts/|\./)([A-Za-z0-9_.-]+\.(?:sh|py))", text))
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                fail(errors, f"报告疑似包含敏感凭据模式: {report.name}")

    for name in sorted(referenced):
        candidates = [root / name, root / "scripts" / name]
        if not any(path.is_file() for path in candidates):
            fail(errors, f"报告引用的脚本不存在: {name}")

    all_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".md", ".sh", ".py"}
    )
    if "restore" not in all_text and "恢复" not in all_text:
        fail(errors, "缺少恢复/清理流程")

    if errors:
        print("VALIDATION_FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print("VALIDATION_PASSED")
    print(f"ATTACK_DIR={root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
