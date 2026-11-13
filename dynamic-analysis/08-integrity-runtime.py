#!/usr/bin/env python3
#
# 08-integrity-runtime.py —— 通用动态分析：原包与改包的完整性/对抗行为对比
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   对比原始 APK 与改包（重打包、重签名或注入包）的运行时行为：
#     - 原包能否安装、启动、保持前台？
#     - 改包能否安装、启动、保持前台？
#     - 改包启动后日志里是否出现签名 / Root / Hook / 调试 / 模拟器检测信号？
#     - 改包被拦截时，是完整性校验生效，还是改包本身构建有问题？
#
#   重要：本脚本只能给出"行为差异 + 日志信号"，不能证明完整性校验一定生效。
#   改包闪退也可能来自代码注入错误、资源不完整或签名问题。
#
#   本脚本会卸载 / 安装 / 启动应用，属于写操作。compare 必须显式 --confirm；
#   结束后默认恢复原始 APK（除非 --keep-test 或 --skip-restore）。
#
# 子命令：
#   preflight        只读检查 adb、设备、两个 APK、包名、当前安装状态
#   compare          安装原包并记录行为，再安装改包并记录行为，最后恢复原包
#   help             显示帮助
#
# 用法：
#   ./08-integrity-runtime.py preflight --package com.example.app \
#     --original ./orig.apk --test ./test.apk
#   ./08-integrity-runtime.py compare --package com.example.app \
#     --original ./orig.apk --test ./test.apk --dry-run
#   ./08-integrity-runtime.py compare --package com.example.app \
#     --original ./orig.apk --test ./test.apk --confirm
#   ./08-integrity-runtime.py --help
#
#   错误输入示例：
#     缺少 --original / --test → exit 2；compare 未加 --confirm → exit 2。
#
# 输出：
#   ORIGINAL_INSTALL_OK / ORIGINAL_LAUNCH_OK、TEST_*、TEST_BLOCKED、
#   COMPARE_RESULT、【结论】、证据 JSON 路径。
#
# 参数：
#   --package <包名>      必填（或从 --original 推断）。示例：com.example.app
#   --original <APK>      preflight / compare 必填。示例：./orig.apk
#   --test <APK>          preflight / compare 必填。示例：./repackaged.apk
#   --serial <序列号>     可选。示例：ABC123
#   --wait <秒>           可选，默认 5。示例：--wait 10
#   --log-lines <N>       可选，默认 4000。示例：--log-lines 8000
#   --evidence-dir <目录> 可选，默认 evidence。示例：./evidence
#   --confirm             可选布尔开关；compare 必须显式确认。
#   --keep-test           可选布尔开关；保留改包，不恢复原包。
#   --skip-restore        可选布尔开关；同 --keep-test。
#   --dry-run             可选布尔开关；只打印计划。
#   -h, --help            显示帮助。
#
# 依赖：
#   python3、adb；从 APK 推断包名时需要 aapt（否则显式 --package）。
#
# 退出码：
#   0 = 对比完成（无论改包是否被拦截）
#   1 = 安装 / 启动 / 恢复流程未能完成
#   2 = 参数、依赖或设备错误
#
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import shutil
from datetime import datetime, timezone

SCHEMA = "app-safe/integrity-runtime/v1"
SIGNAL_PATTERNS = [
    ("signature", re.compile(r"(?i)(signature|tamper|integrity|checksum|digest)")),
    ("root", re.compile(r"(?i)(\broot\b|magisk|supersu|superuser|su binary)")),
    ("hook", re.compile(r"(?i)(frida|xposed|substrate|\bhook\b)")),
    ("debug", re.compile(r"(?i)(debugger|ptrace|debuggable|waiting for debugger)")),
    ("emulator", re.compile(r"(?i)(emulator|goldfish|ranchu|qemu)")),
]


def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def adb_base(serial):
    base = ["adb"]
    if serial:
        base += ["-s", serial]
    return base


def need_adb():
    if not shutil.which("adb"):
        print("[FAIL] 缺少工具: adb", file=sys.stderr)
        print("       macOS: brew install android-platform-tools", file=sys.stderr)
        print("       Linux: sudo apt install android-tools-adb", file=sys.stderr)
        return False
    return True


def run_command(command, timeout=180):
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return 127, "command not found: {}".format(command[0])
    except subprocess.TimeoutExpired:
        return 124, "timeout after {}s".format(timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def sha256_file(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact(text):
    text = re.sub(
        r"(?i)((?:proxy-)?authorization\s*[:=]\s*)[^,;]*",
        r"\1<REDACTED>", text,
    )
    text = re.sub(r"(?i)(\bBearer\s+)\S+", r"\1<REDACTED>", text)
    text = re.sub(
        r"(?i)((?:access[_-]?token|refresh[_-]?token|token|password|secret|"
        r"signature)\s*[:=]\s*)[^\s&;]+",
        r"\1<REDACTED>", text,
    )
    return text


def package_from_apk(apk):
    if not apk or not os.path.isfile(apk):
        return ""
    if not subprocess.run(["which", "aapt"], capture_output=True).returncode == 0:
        return ""
    rc, out = run_command(["aapt", "dump", "badging", apk], timeout=30)
    if rc != 0:
        return ""
    match = re.search(r"package: name='([^']+)'", out)
    return match.group(1) if match else ""


def device_ready(adb):
    rc, out = run_command(adb + ["get-state"], timeout=8)
    return rc == 0 and out.strip() == "device"


def package_installed(adb, package):
    rc, out = run_command(adb + ["shell", "pm", "path", package], timeout=8)
    return rc == 0 and out.strip().startswith("package:")


def installed_sha(adb, package):
    rc, out = run_command(adb + ["shell", "pm", "path", package], timeout=8)
    if rc != 0 or not out.strip().startswith("package:"):
        return ""
    paths = [line.strip().replace("package:", "", 1)
             for line in out.splitlines() if line.strip().startswith("package:")]
    base = next((path for path in paths if path.endswith("/base.apk")), paths[0])
    rc, sha_out = run_command(adb + ["shell", "sha256sum", base], timeout=120)
    if rc == 0:
        token = sha_out.strip().split()[0] if sha_out.strip() else ""
        if re.fullmatch(r"[0-9a-fA-F]{64}", token):
            return token.lower()

    temp = tempfile.mkdtemp(prefix="integrity-")
    try:
        local = os.path.join(temp, "base.apk")
        rc, _out = run_command(adb + ["pull", base, local], timeout=300)
        if rc == 0 and os.path.isfile(local):
            return sha256_file(local)
    finally:
        shutil.rmtree(temp, ignore_errors=True)
    return ""


def resolve_launcher(adb, package):
    rc, out = run_command(
        adb + [
            "shell", "cmd", "package", "resolve-activity", "--brief",
            "-a", "android.intent.action.MAIN",
            "-c", "android.intent.category.LAUNCHER", package,
        ],
        timeout=20,
    )
    if rc != 0:
        return ""
    for line in reversed(out.splitlines()):
        line = line.strip()
        if re.match(r"^[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+$", line):
            return line
    match = re.search(r"([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)", out)
    return match.group(1) if match else ""


def get_pid(adb, package):
    rc, out = run_command(adb + ["shell", "pidof", package], timeout=8)
    if rc == 0:
        parts = out.split()
        if parts and parts[0].isdigit():
            return parts[0]
    return ""


def get_foreground(adb):
    rc, out = run_command(adb + ["shell", "dumpsys", "activity", "activities"],
                          timeout=15)
    if rc == 0:
        for line in out.splitlines():
            if "mResumedActivity" in line or "topResumedActivity" in line:
                match = re.search(r"([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)", line)
                if match:
                    return match.group(1)
    rc, out = run_command(adb + ["shell", "dumpsys", "window"], timeout=15)
    if rc == 0:
        for line in out.splitlines():
            if "mCurrentFocus" in line or "mFocusedApp" in line:
                match = re.search(r"([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)", line)
                if match:
                    return match.group(1)
    return ""


def install_apk(adb, apk, package):
    run_command(adb + ["uninstall", package], timeout=60)
    rc, out = run_command(adb + ["install", "-r", apk], timeout=300)
    if rc != 0:
        return False, out
    return package_installed(adb, package), out


def scan_signals(log_text):
    counts = {}
    samples = {}
    for line in log_text.splitlines():
        for category, pattern in SIGNAL_PATTERNS:
            if pattern.search(line):
                counts[category] = counts.get(category, 0) + 1
                bucket = samples.setdefault(category, [])
                if len(bucket) < 5:
                    bucket.append(redact(line.strip())[:400])
    return counts, samples


def run_side(adb, apk, package, wait_seconds, log_lines):
    record = {
        "apk": apk,
        "sha256": sha256_file(apk),
        "install_ok": False,
        "launch_ok": False,
        "crash": False,
        "anr": False,
        "pid": "",
        "foreground": "",
        "signals": {},
        "signal_samples": {},
        "log_lines": 0,
    }
    ok, install_output = install_apk(adb, apk, package)
    record["install_ok"] = ok
    record["install_output"] = redact(install_output.strip())[-800:]
    if not ok:
        return record

    launcher = resolve_launcher(adb, package)
    record["launcher"] = launcher
    if not launcher:
        return record

    run_command(adb + ["logcat", "-c"], timeout=15)
    rc, start_output = run_command(
        adb + ["shell", "am", "start", "-W", "-n", launcher], timeout=60
    )
    record["start_exit_code"] = rc
    record["start_output"] = redact(start_output.strip())[-800:]

    import time
    time.sleep(wait_seconds)

    record["pid"] = get_pid(adb, package)
    record["foreground"] = get_foreground(adb)
    rc_log, log_text = run_command(
        adb + ["shell", "logcat", "-d", "-v", "brief", "-t", str(log_lines)],
        timeout=60,
    )
    log_text = log_text if rc_log == 0 else ""
    record["log_lines"] = len(log_text.splitlines())
    package_re = re.escape(package)
    record["crash"] = bool(
        re.search(r"FATAL EXCEPTION|Process: {}([[:space:],]|$)".format(package_re),
                  log_text)
    )
    record["anr"] = bool(
        re.search(r"ANR in {}([[:space:]]|$)".format(package_re), log_text)
    )
    record["signals"], record["signal_samples"] = scan_signals(log_text)
    record["launch_ok"] = bool(
        rc == 0
        and record["pid"]
        and record["foreground"].startswith(package + "/")
        and not record["crash"]
        and not record["anr"]
        and not re.search(r"^\s*Error:", start_output, re.M)
    )
    return record


def write_json(path, data):
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(temp, path)
    os.chmod(path, 0o600)


def cmd_preflight(args):
    if not need_adb():
        return 2
    adb = adb_base(args.serial)
    if not device_ready(adb):
        print("[FAIL] 没有在线 Android 设备", file=sys.stderr)
        return 1
    for label, path in (("original", args.original), ("test", args.test)):
        if not path or not os.path.isfile(path):
            print("[FAIL] {} APK 不存在: {}".format(label, path), file=sys.stderr)
            return 2

    package = args.package or package_from_apk(args.original)
    if not package:
        print("[FAIL] 无法推断包名；请显式 --package", file=sys.stderr)
        return 2

    print("ADB_STATE=device")
    print("PACKAGE_NAME={}".format(package))
    print("PACKAGE_INSTALLED={}".format(str(package_installed(adb, package)).lower()))
    print("[loading] 正在计算两个 APK 的 SHA-256...", file=sys.stderr)
    original_sha = sha256_file(args.original)
    test_sha = sha256_file(args.test)
    print("[done] SHA-256 计算完成", file=sys.stderr)
    print("ORIGINAL_APK_SHA256={}".format(original_sha))
    print("TEST_APK_SHA256={}".format(test_sha))
    print("AAPT_AVAILABLE={}".format(
        str(subprocess.run(["which", "aapt"], capture_output=True).returncode == 0).lower()
    ))
    print("PREFLIGHT_PASSED=true")
    return 0


def cmd_compare(args):
    if not need_adb():
        return 2
    package = args.package or package_from_apk(args.original)
    if not package:
        print("[FAIL] 无法推断包名；请显式 --package", file=sys.stderr)
        return 2
    adb = adb_base(args.serial)
    if not device_ready(adb):
        print("[FAIL] 没有在线 Android 设备", file=sys.stderr)
        return 1
    for label, path in (("original", args.original), ("test", args.test)):
        if not path or not os.path.isfile(path):
            print("[FAIL] {} APK 不存在: {}".format(label, path), file=sys.stderr)
            return 2

    if args.dry_run:
        print("[DRY-RUN] 1) adb uninstall {}".format(package))
        print("[DRY-RUN] 2) adb install -r {}".format(args.original))
        print("[DRY-RUN] 3) 启动原包并记录 PID / 前台 / 日志")
        print("[DRY-RUN] 4) adb uninstall {}".format(package))
        print("[DRY-RUN] 5) adb install -r {}".format(args.test))
        print("[DRY-RUN] 6) 启动改包并记录 PID / 前台 / 日志")
        print("[DRY-RUN] 7) 恢复原始 APK")
        print("DRY_RUN=true")
        return 0

    if not args.confirm:
        print("[FAIL] compare 会卸载并安装应用；请加 --confirm 确认这是测试设备。",
              file=sys.stderr)
        print("       或先加 --dry-run 查看计划。", file=sys.stderr)
        return 2

    print("[loading] 正在安装并观察原始 APK...", file=sys.stderr)
    original = run_side(adb, args.original, package, args.wait, args.log_lines)
    print("[done] 原始 APK：install_ok={} launch_ok={}".format(
        original["install_ok"], original["launch_ok"]
    ), file=sys.stderr)

    print("[loading] 正在安装并观察改包...", file=sys.stderr)
    test = run_side(adb, args.test, package, args.wait, args.log_lines)
    print("[done] 改包：install_ok={} launch_ok={}".format(
        test["install_ok"], test["launch_ok"]
    ), file=sys.stderr)

    test_blocked = original["launch_ok"] and not test["launch_ok"]
    test_signals = sum(test["signals"].values())
    compare_result = "INCONCLUSIVE"
    if original["launch_ok"] and test["launch_ok"]:
        compare_result = "TEST_RUNS"
    elif test_blocked:
        compare_result = "TEST_BLOCKED"

    restore_verified = None
    if not (args.keep_test or args.skip_restore):
        print("[loading] 正在恢复原始 APK...", file=sys.stderr)
        restore_ok, _restore_output = install_apk(adb, args.original, package)
        restored_sha = installed_sha(adb, package)
        restore_verified = bool(
            restore_ok and restored_sha and restored_sha == sha256_file(args.original)
        )
        print("[done] 恢复原包：{}".format(restore_verified), file=sys.stderr)

    os.makedirs(args.evidence_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence_path = os.path.join(
        args.evidence_dir, "08-integrity-runtime-{}.json".format(stamp)
    )
    result = {
        "schema": SCHEMA,
        "captured_at": iso_now(),
        "package": package,
        "original": original,
        "test": test,
        "test_blocked": test_blocked,
        "test_signal_total": test_signals,
        "compare_result": compare_result,
        "restore_verified": restore_verified,
        "notes": [
            "改包被拦截不等于完整性校验生效；也可能是注入/重打包错误。",
            "日志信号是线索，不是防护生效的证明。",
        ],
    }
    write_json(evidence_path, result)

    print("============================================================")
    print("动态分析 08：原包 vs 改包运行行为对比")
    print("目标包：{}".format(package))
    print("============================================================")
    print("ORIGINAL_INSTALL_OK={}".format(str(original["install_ok"]).lower()))
    print("ORIGINAL_LAUNCH_OK={}".format(str(original["launch_ok"]).lower()))
    print("ORIGINAL_CRASH={}".format(str(original["crash"]).lower()))
    print("ORIGINAL_ANR={}".format(str(original["anr"]).lower()))
    print("TEST_INSTALL_OK={}".format(str(test["install_ok"]).lower()))
    print("TEST_LAUNCH_OK={}".format(str(test["launch_ok"]).lower()))
    print("TEST_CRASH={}".format(str(test["crash"]).lower()))
    print("TEST_ANR={}".format(str(test["anr"]).lower()))
    print("TEST_SIGNAL_TOTAL={}".format(test_signals))
    for category, _pattern in SIGNAL_PATTERNS:
        print("TEST_SIGNAL_{}={}".format(
            category.upper(), test["signals"].get(category, 0)
        ))
    print("TEST_BLOCKED={}".format(str(test_blocked).lower()))
    print("COMPARE_RESULT={}".format(compare_result))
    print("RESTORE_VERIFIED={}".format(
        "not-run" if restore_verified is None else str(restore_verified).lower()
    ))
    print("------------------------------------------------------------")
    print("【结论】")
    if compare_result == "TEST_RUNS":
        print("原始包和改包都能启动；未观察到改包被拦截。")
    elif compare_result == "TEST_BLOCKED":
        print("原始包可启动、改包不可启动；这可能是完整性校验，"
              "也可能是改包本身构建/签名问题，需结合日志确认。")
    else:
        print("对比不完整：至少一侧未能安装或启动，不能据此判断完整性校验。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))

    if not original["install_ok"] or not test["install_ok"]:
        return 1
    if restore_verified is False:
        return 1
    return 0


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="对比原始 APK 与改包的运行时安装/启动/检测信号。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  ./08-integrity-runtime.py preflight --package com.example.app "
            "--original ./orig.apk --test ./test.apk\n"
            "  ./08-integrity-runtime.py compare --package com.example.app "
            "--original ./orig.apk --test ./test.apk --dry-run\n"
            "  ./08-integrity-runtime.py compare --package com.example.app "
            "--original ./orig.apk --test ./test.apk --confirm\n"
            "\n退出码:\n"
            "  0 = 对比完成\n"
            "  1 = 安装/启动/恢复流程未能完成\n"
            "  2 = 参数、依赖或设备错误"
        ),
    )
    parser.add_argument("mode", choices=["preflight", "compare", "help"], help="操作")
    parser.add_argument("--package", default="", help="目标 Android 包名")
    parser.add_argument("--original", default="", help="原始 APK")
    parser.add_argument("--test", default="", help="改包 APK")
    parser.add_argument("--serial", default="", help="设备序列号")
    parser.add_argument("--wait", type=int, default=5, help="启动后等待秒数，默认 5")
    parser.add_argument("--log-lines", type=int, default=4000,
                        help="读取最近 N 行日志，默认 4000")
    parser.add_argument("--evidence-dir", default="evidence", help="证据目录，默认 evidence")
    parser.add_argument("--confirm", action="store_true", help="确认执行卸载/安装")
    parser.add_argument("--keep-test", action="store_true", help="保留改包，不恢复原包")
    parser.add_argument("--skip-restore", action="store_true", help="同 --keep-test")
    parser.add_argument("--dry-run", action="store_true", help="只打印计划")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.mode == "help":
        parse_args(["--help"])
        return 0
    if args.wait < 0 or args.log_lines <= 0:
        print("[FAIL] --wait 不能为负，--log-lines 必须为正", file=sys.stderr)
        return 2
    if args.mode == "preflight":
        return cmd_preflight(args)
    return cmd_compare(args)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[FAIL] 用户中断", file=sys.stderr)
        sys.exit(2)
