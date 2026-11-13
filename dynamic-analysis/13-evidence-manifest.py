#!/usr/bin/env python3
#
# 13-evidence-manifest.py —— 通用动态分析：证据清单与完整性校验
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   把一次动态分析产生的证据文件汇总成可复核的 manifest：
#     - 记录生成时间、主机、Git commit、工具版本；
#     - 可选记录连接的 Android 设备信息；
#     - 对每个证据文件计算 SHA-256、大小和修改时间；
#     - 生成 manifest.json，供他人独立校验证据是否被改动。
#
#   本脚本只读取证据文件，不修改证据内容；manifest 只保存元数据，
#   不保存文件正文，因此不会把 Token / 请求体写进清单。
#
# 参数：
#   --input <目录>        可选。默认 evidence。示例：--input ./evidence
#   --output <文件>       可选。默认 <input>/manifest.json。示例：./evidence/manifest.json
#   --label <标签>        可选，默认 dynamic-analysis。示例：--label lab-run-01
#   --artifact <路径>     可选，可重复。示例：--artifact ./app.apk
#   --command <命令>      可选，可重复。示例：--command 'adb shell am start ...'
#   --exclude <glob>      可选，可重复。默认排除 manifest.json、*.tmp、*.part。
#                          示例：--exclude '*.log'
#   --device              可选布尔开关；通过 adb 记录设备信息。
#   --serial <序列号>     可选。示例：--serial ABC123
#   --verify <manifest>   可选；按已生成的 manifest 复核文件哈希。
#                          示例：--verify ./evidence/manifest.json
#   -h, --help            显示本帮助。
#
# 依赖：
#   python3；--device 需要 adb。缺少 adb 时只跳过设备信息，不阻断清单生成。
#
# 用法：
#   ./13-evidence-manifest.py --input evidence
#   ./13-evidence-manifest.py --input evidence --artifact ./app.apk --device
#   ./13-evidence-manifest.py --verify evidence/manifest.json
#   ./13-evidence-manifest.py --verify evidence/manifest.json --input /new/evidence/path
#
# 输出：
#   创建：MANIFEST_PATH、MANIFEST_SHA256、ARTIFACT_COUNT、TOTAL_BYTES。
#   校验：逐文件 [PASS]/[FAIL]，以及 VERIFY_PASSED、VERIFY_FAILURES。
#
# 退出码：
#   0 = manifest 创建成功，或校验全部通过
#   1 = 校验发现文件缺失、大小变化或哈希不一致
#   2 = 参数、依赖或 I/O 错误
#
import argparse
import fnmatch
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA = "app-safe/dynamic-evidence-manifest/v1"
DEFAULT_EXCLUDES = ["manifest.json", "*.tmp", "*.part"]

REDACT_PATTERNS = [
    (re.compile(r"(?i)((?:proxy-)?authorization\s*[:=]\s*)[^,;]*"),
     r"\1<REDACTED>"),
    (re.compile(r"(?i)(\bBearer\s+)\S+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(\b(?:set-cookie|cookie)\s*:\s*)[^;]*"),
     r"\1<REDACTED>"),
    (re.compile(
        r"(?i)((?:access[_-]?token|refresh[_-]?token|id[_-]?token|"
        r"password|passwd|cookie|signature)\s*[:=]\s*)([^\s&;]+)"
    ), r"\1<REDACTED>"),
]


def sha256_file(path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def iso_utc(timestamp=None):
    if timestamp is None:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)\
        .replace(microsecond=0).isoformat()


def redact(text):
    for pattern, replacement in REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def tool_version(command):
    if not shutil.which(command[0]):
        return None
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "error: {}".format(exc)
    output = (proc.stdout or "") + (proc.stderr or "")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines:
        return lines[0]
    return "exit {}".format(proc.returncode)


def git_info():
    if not shutil.which("git"):
        return {}
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            timeout=5, check=False,
        ).stdout.strip()
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True,
            text=True, timeout=5, check=False,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, text=True,
            timeout=5, check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if not commit:
        return {}
    return {
        "commit": commit,
        "branch": branch,
        "dirty": bool(status.strip()),
    }


def device_info(serial):
    if not shutil.which("adb"):
        return {"available": False, "reason": "adb not found"}

    base = ["adb"]
    if serial:
        base += ["-s", serial]

    try:
        state = subprocess.run(
            base + ["get-state"], capture_output=True, text=True,
            timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "reason": "adb error: {}".format(exc)}

    if state.returncode != 0 or state.stdout.strip() != "device":
        return {
            "available": False,
            "reason": (state.stderr or state.stdout or "no device").strip(),
        }

    try:
        props_out = subprocess.run(
            base + ["shell", "getprop"], capture_output=True, text=True,
            timeout=8, check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "reason": "getprop error: {}".format(exc)}

    props = {}
    for line in props_out.splitlines():
        match = re.match(r"\[([^\]]+)\]: \[([^\]]*)\]", line)
        if match:
            props[match.group(1)] = match.group(2)

    keys = [
        "ro.product.manufacturer",
        "ro.product.model",
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.build.fingerprint",
        "ro.build.tags",
        "ro.build.type",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
    ]
    try:
        serial_out = subprocess.run(
            base + ["get-serialno"], capture_output=True, text=True,
            timeout=5, check=False,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        serial_out = ""

    return {
        "available": True,
        "serial": serial_out or serial or "",
        "props": {key: props.get(key) for key in keys},
    }


def iter_regular_files(root, excludes, skip_abs=None):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if skip_abs and os.path.abspath(full) == skip_abs:
                continue
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, root)
            if any(
                fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern)
                for pattern in excludes
            ):
                continue
            yield full, rel


def add_artifact(artifacts, full, root):
    stat = os.stat(full)
    artifacts.append({
        "root": os.path.abspath(root),
        "path": os.path.relpath(full, root),
        "sha256": sha256_file(full),
        "size": stat.st_size,
        "mtime_utc": iso_utc(stat.st_mtime),
    })


def create_manifest(args):
    input_root = os.path.abspath(args.input or "evidence")
    if not os.path.isdir(input_root):
        print("[FAIL] 证据目录不存在: {}".format(input_root), file=sys.stderr)
        return 2

    output = args.output or os.path.join(input_root, "manifest.json")
    output = os.path.abspath(output)
    output_dir = os.path.dirname(output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    excludes = DEFAULT_EXCLUDES + list(args.exclude or [])
    artifacts = []
    seen = set()

    print("[loading] 正在计算证据文件哈希...", file=sys.stderr)

    for full, rel in iter_regular_files(input_root, excludes, skip_abs=output):
        key = os.path.realpath(full)
        if key in seen:
            continue
        seen.add(key)
        add_artifact(artifacts, full, input_root)

    for item in args.artifact or []:
        item = os.path.abspath(item)
        if not os.path.exists(item):
            print("[FAIL] --artifact 不存在: {}".format(item), file=sys.stderr)
            return 2
        if os.path.isdir(item):
            for full, _rel in iter_regular_files(item, excludes):
                key = os.path.realpath(full)
                if key in seen:
                    continue
                seen.add(key)
                add_artifact(artifacts, full, item)
        elif os.path.isfile(item):
            key = os.path.realpath(item)
            if key in seen:
                continue
            seen.add(key)
            add_artifact(artifacts, item, os.path.dirname(item))

    artifacts.sort(key=lambda entry: (entry["root"], entry["path"]))
    print("[done] 哈希计算完成：{} 个文件".format(len(artifacts)),
          file=sys.stderr)

    manifest = {
        "schema": SCHEMA,
        "created_at": iso_utc(),
        "label": args.label,
        "input_root": input_root,
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "git": git_info(),
        "tools": {
            "adb": tool_version(["adb", "version"]),
            "frida": tool_version(["frida", "--version"]),
            "mitmproxy": tool_version(["mitmproxy", "--version"]),
            "apksigner": tool_version(["apksigner", "version"]),
            "aapt": tool_version(["aapt", "version"]),
            "python3": tool_version(["python3", "--version"]),
        },
        "device": device_info(args.serial) if args.device else None,
        "commands": [redact(command) for command in (args.command or [])],
        "generator_argv": [redact(arg) for arg in sys.argv],
        "artifacts": artifacts,
        "summary": {
            "artifact_count": len(artifacts),
            "total_bytes": sum(entry["size"] for entry in artifacts),
        },
    }

    temp_path = output + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")
    os.replace(temp_path, output)

    manifest_sha = sha256_file(output)

    print("============================================================")
    print("动态分析 13：证据清单")
    print("输入目录：{}".format(input_root))
    print("清单文件：{}".format(output))
    print("============================================================")
    print("[PASS] 已记录 {} 个证据文件".format(len(artifacts)))
    for entry in artifacts:
        print("  - {}  {}  {} bytes".format(
            entry["path"], entry["sha256"], entry["size"]
        ))
    print("------------------------------------------------------------")
    print("MANIFEST_PATH={}".format(output))
    print("MANIFEST_SHA256={}".format(manifest_sha))
    print("ARTIFACT_COUNT={}".format(len(artifacts)))
    print("TOTAL_BYTES={}".format(manifest["summary"]["total_bytes"]))
    print("MANIFEST_CREATED=true")
    print("------------------------------------------------------------")
    print("【结论】")
    print("已生成证据清单，记录了 {} 个文件的 SHA-256。".format(len(artifacts)))
    print("使用 --verify 可复核证据是否被改动。")

    if not artifacts:
        print("[WARN] 证据目录为空；请确认分析确实产生了证据。", file=sys.stderr)
    return 0


def verify_manifest(args):
    manifest_path = os.path.abspath(args.verify)
    if not os.path.isfile(manifest_path):
        print("[FAIL] manifest 不存在: {}".format(manifest_path), file=sys.stderr)
        return 2

    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print("[FAIL] 无法读取 manifest: {}".format(exc), file=sys.stderr)
        return 2

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        print("[FAIL] manifest 缺少 artifacts 数组", file=sys.stderr)
        return 2

    manifest_root = os.path.dirname(manifest_path)
    default_root = os.path.abspath(args.input) if args.input else None
    failures = 0

    print("============================================================")
    print("动态分析 13：证据校验")
    print("清单文件：{}".format(manifest_path))
    print("============================================================")
    print("[loading] 正在校验证据文件哈希...", file=sys.stderr)

    for entry in artifacts:
        rel = entry.get("path", "")
        root = default_root or entry.get("root") or manifest_root
        full = os.path.join(root, rel)
        expected = entry.get("sha256", "")
        expected_size = entry.get("size")

        if not os.path.isfile(full):
            print("[FAIL] {}: 文件缺失 ({})".format(rel, full))
            failures += 1
            continue

        actual_size = os.path.getsize(full)
        if expected_size is not None and actual_size != expected_size:
            print("[FAIL] {}: 大小变化 {} -> {}".format(
                rel, expected_size, actual_size
            ))
            failures += 1
            continue

        actual = sha256_file(full)
        if actual != expected:
            print("[FAIL] {}: SHA-256 不一致".format(rel))
            print("       期望: {}".format(expected))
            print("       实际: {}".format(actual))
            failures += 1
            continue

        print("[PASS] {}: {}".format(rel, actual))

    total = len(artifacts)
    print("[done] 校验完成：{} 个文件，{} 个失败".format(total, failures),
          file=sys.stderr)
    print("------------------------------------------------------------")
    print("VERIFY_TOTAL={}".format(total))
    print("VERIFY_FAILURES={}".format(failures))
    print("------------------------------------------------------------")
    print("【结论】")
    if failures == 0:
        print("所有证据文件与 manifest 记录一致。")
        print("VERIFY_PASSED=true")
        return 0
    print("发现 {} 个文件缺失、大小变化或哈希不一致。".format(failures))
    print("VERIFY_PASSED=false")
    return 1


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="生成或校验动态分析证据 manifest。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  ./13-evidence-manifest.py --input evidence\n"
            "  ./13-evidence-manifest.py --input evidence --artifact ./app.apk --device\n"
            "  ./13-evidence-manifest.py --verify evidence/manifest.json\n"
            "\n退出码:\n"
            "  0 = manifest 创建成功 / 校验全部通过\n"
            "  1 = 校验发现文件缺失或哈希不一致\n"
            "  2 = 参数、依赖或 I/O 错误"
        ),
    )
    parser.add_argument("--input", default=None,
                        help="证据目录，创建模式默认 evidence；校验模式默认使用 manifest 中记录的路径")
    parser.add_argument("--output", default=None,
                        help="manifest 输出路径，默认 <input>/manifest.json")
    parser.add_argument("--label", default="dynamic-analysis",
                        help="本次分析的标签")
    parser.add_argument("--artifact", action="append", default=[],
                        help="额外纳入的产物路径，可重复")
    parser.add_argument("--command", action="append", default=[],
                        help="记录本次执行的关键命令，可重复")
    parser.add_argument("--exclude", action="append", default=[],
                        help="排除模式，可重复")
    parser.add_argument("--device", action="store_true",
                        help="记录 adb 设备信息")
    parser.add_argument("--serial", default="",
                        help="配合 --device 指定设备序列号")
    parser.add_argument("--verify", default=None,
                        help="校验模式：指定已生成的 manifest.json")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    try:
        if args.verify:
            return verify_manifest(args)
        return create_manifest(args)
    except KeyboardInterrupt:
        print("\n[FAIL] 用户中断", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print("[FAIL] {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
