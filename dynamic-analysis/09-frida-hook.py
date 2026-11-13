#!/usr/bin/env python3
#
# 09-frida-hook.py —— 通用动态分析：Frida 运行时 Hook 模板
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   在已授权的测试设备上，用 Frida 观察运行时行为：
#     - HTTP：URL.openConnection、OkHttp Request URL / 方法；
#     - Log：android.util.Log.println 的 tag / message；
#     - Crypto：Cipher.init 使用的算法（不记录密钥）；
#     - SSL：OkHttp CertificatePinner.check 的调用（只观察，不绕过）。
#
#   重要：
#     - 这些模板是观察用途，不修改证书校验结果，不注入业务逻辑；
#     - 输出可能包含 URL / 日志中的敏感信息，脚本在落盘前做脱敏；
#     - 仅用于已授权的测试设备、测试账号与测试环境。
#
# 子命令：
#   preflight        只读检查 frida / frida-ps / 设备 / 目标进程
#   list             列出设备上的进程（可过滤包名）
#   spawn            启动应用并注入模板
#   attach           附加到已运行进程并注入模板
#   help             显示帮助
#
# 用法：
#   ./09-frida-hook.py preflight --package com.example.app
#   ./09-frida-hook.py list --package com.example.app
#   ./09-frida-hook.py spawn --package com.example.app --template http --confirm
#   ./09-frida-hook.py attach --package com.example.app --template log --confirm
#   ./09-frida-hook.py --help
#
#   错误输入示例：
#     缺少 frida → exit 2；spawn / attach 未加 --confirm → exit 2。
#
# 输出：
#   FRIDA_STATUS、OUTPUT_LINES、脱敏输出、【结论】、证据 JSON 路径。
#
# 参数：
#   --package <包名>       spawn 必填；attach 与 --pid 二选一。
#                          示例：--package com.example.app
#   --pid <PID>             attach 可选。示例：--pid 12345
#   --template <名称>       可选，默认 http。枚举：http | log | crypto | ssl。
#                          示例：--template log
#   --script <路径>         可选；自定义 Frida JS，提供后忽略 --template。
#                          示例：--script ./hook.js
#   --seconds <秒>          可选，默认 10，范围 1–300。示例：--seconds 30
#   --serial <序列号>       可选。示例：ABC123
#   --evidence-dir <目录>   可选，默认 evidence。示例：./evidence
#   --confirm               可选布尔开关；spawn / attach 必须显式确认。
#   --dry-run               可选布尔开关；只打印命令。
#   -h, --help              显示帮助。
#
# 依赖：
#   frida、frida-ps、adb。设备端需要 frida-server 已启动（或已 root 并可运行）。
#   缺失时明确提示安装方式并 exit 2。
#
# 退出码：
#   0 = Frida 会话已运行（即使没有输出）
#   1 = 设备 / frida-server / 进程不可用，或 frida 退出异常
#   2 = 参数、依赖或输入错误
#
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

SCHEMA = "app-safe/frida-hook/v1"

TEMPLATES = {
    "http": r"""
Java.perform(function () {
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overloads.forEach(function (overload) {
      overload.implementation = function () {
        try { console.log('[HTTP] URL ' + this.toString()); } catch (e) {}
        return overload.apply(this, arguments);
      };
    });
  } catch (e) { console.log('[HTTP] URL hook skipped: ' + e); }
  try {
    var Builder = Java.use('okhttp3.Request$Builder');
    Builder.build.implementation = function () {
      var request = this.build();
      try { console.log('[HTTP] ' + request.method() + ' ' + request.url().toString()); } catch (e) {}
      return request;
    };
  } catch (e) { console.log('[HTTP] OkHttp hook skipped: ' + e); }
});
""",
    "log": r"""
Java.perform(function () {
  try {
    var Log = Java.use('android.util.Log');
    var println = Log.println.overload('int', 'java.lang.String', 'java.lang.String');
    println.implementation = function (priority, tag, message) {
      try { console.log('[LOG] ' + tag + ': ' + message); } catch (e) {}
      return println.call(this, priority, tag, message);
    };
  } catch (e) { console.log('[LOG] hook skipped: ' + e); }
});
""",
    "crypto": r"""
Java.perform(function () {
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        try { console.log('[CRYPTO] init ' + this.getAlgorithm()); } catch (e) {}
        return overload.apply(this, arguments);
      };
    });
  } catch (e) { console.log('[CRYPTO] hook skipped: ' + e); }
});
""",
    "ssl": r"""
Java.perform(function () {
  try {
    var Pinner = Java.use('okhttp3.CertificatePinner');
    Pinner.check.overloads.forEach(function (overload) {
      overload.implementation = function () {
        try { console.log('[SSL] CertificatePinner.check ' + arguments[0]); } catch (e) {}
        return overload.apply(this, arguments);
      };
    });
  } catch (e) { console.log('[SSL] CertificatePinner not found: ' + e); }
});
""",
}


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


def run_command(command, timeout=30):
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return 127, "command not found: {}".format(command[0])
    except subprocess.TimeoutExpired:
        return 124, "timeout after {}s".format(timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def redact(text):
    text = re.sub(
        r"(?i)([?&](?:code|state|token|access_token|refresh_token|"
        r"signature|sig|password)=)[^&\s]+",
        r"\1<REDACTED>", text,
    )
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


def frida_device_args(serial):
    return ["-D", serial] if serial else ["-U"]


def frida_ps(serial, timeout=15):
    return run_command(["frida-ps"] + frida_device_args(serial), timeout=timeout)


def find_pid(serial, package):
    rc, out = frida_ps(serial)
    if rc != 0:
        return ""
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0].isdigit():
            if any(part == package for part in parts[1:]):
                return parts[0]
        if package in line and parts[0].isdigit():
            return parts[0]
    return ""


def cmd_preflight(args):
    if not shutil.which("frida"):
        print("[FAIL] 缺少工具: frida", file=sys.stderr)
        print("       安装提示: python3 -m pip install --user frida-tools", file=sys.stderr)
        print("       设备端还需要 frida-server（需 Root 或已授权的测试设备）", file=sys.stderr)
        return 2
    if not shutil.which("frida-ps"):
        print("[FAIL] 缺少工具: frida-ps", file=sys.stderr)
        print("       安装提示: python3 -m pip install --user frida-tools", file=sys.stderr)
        return 2
    if not need_adb():
        return 2

    adb = adb_base(args.serial)
    rc, out = run_command(adb + ["get-state"], timeout=8)
    if rc != 0 or out.strip() != "device":
        print("[FAIL] 没有在线 Android 设备", file=sys.stderr)
        return 1

    rc_version, version = run_command(["frida", "--version"], timeout=10)
    print("FRIDA_VERSION={}".format(version.strip().splitlines()[0] if version.strip() else "?"))
    rc_ps, ps_out = frida_ps(args.serial)
    print("FRIDA_DEVICE_READY={}".format(str(rc_ps == 0).lower()))
    if rc_ps != 0:
        print("[FAIL] frida 无法连接设备；确认 frida-server 已启动且版本匹配",
              file=sys.stderr)
        print(redact(ps_out.strip())[:800], file=sys.stderr)
        print("PREFLIGHT_PASSED=false")
        return 1

    if args.package:
        pid = find_pid(args.serial, args.package)
        print("PACKAGE_NAME={}".format(args.package))
        print("PROCESS_RUNNING={}".format(str(bool(pid)).lower()))
        print("PID={}".format(pid))
    print("PREFLIGHT_PASSED=true")
    return 0


def cmd_list(args):
    if not shutil.which("frida-ps"):
        print("[FAIL] 缺少工具: frida-ps", file=sys.stderr)
        print("       安装提示: python3 -m pip install --user frida-tools", file=sys.stderr)
        return 2
    rc, out = frida_ps(args.serial)
    if rc != 0:
        print("[FAIL] frida-ps 失败：{}".format(redact(out.strip())), file=sys.stderr)
        return 1
    print("PROCESS_COUNT={}".format(len(out.splitlines())))
    for line in out.splitlines():
        if args.package and args.package not in line:
            continue
        print(line)
    return 0


def prepare_script(args, workdir):
    if args.script:
        if not os.path.isfile(args.script):
            raise ValueError("脚本不存在: {}".format(args.script))
        return args.script, "custom"
    if args.template not in TEMPLATES:
        raise ValueError("未知模板: {}".format(args.template))
    path = os.path.join(workdir, "template-{}.js".format(args.template))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(TEMPLATES[args.template].strip() + "\n")
    return path, args.template


def run_frida(args):
    if not args.confirm and not args.dry_run:
        print("[FAIL] spawn / attach 会注入运行时脚本；请加 --confirm 确认授权。",
              file=sys.stderr)
        print("       或先加 --dry-run 查看命令。", file=sys.stderr)
        return 2

    workdir = tempfile.mkdtemp(prefix="frida-hook-")
    try:
        script_path, template = prepare_script(args, workdir)
        device_args = frida_device_args(args.serial)
        if args.mode == "spawn":
            if not args.package:
                print("[FAIL] spawn 需要 --package", file=sys.stderr)
                return 2
            command = ["frida"] + device_args + [
                "-f", args.package, "-l", script_path, "--no-pause", "-q"
            ]
            target = args.package
            pid = ""
        else:
            if args.pid:
                pid = str(args.pid)
            elif args.package:
                pid = find_pid(args.serial, args.package)
                if not pid:
                    print("[FAIL] 未找到目标进程: {}".format(args.package),
                          file=sys.stderr)
                    return 1
            else:
                print("[FAIL] attach 需要 --package 或 --pid", file=sys.stderr)
                return 2
            command = ["frida"] + device_args + ["-p", pid, "-l", script_path, "-q"]
            target = args.package or pid

        os.makedirs(args.evidence_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        evidence_path = os.path.join(
            args.evidence_dir,
            "09-frida-hook-{}-{}.json".format(args.mode, stamp),
        )

        print("============================================================")
        print("动态分析 09：Frida 运行时 Hook")
        print("模式：{}".format(args.mode))
        print("目标：{}".format(target))
        print("模板：{}".format(template))
        print("============================================================")
        print("FRIDA_COMMAND={}".format(" ".join(command)))
        print("SCRIPT_PATH={}".format(script_path))

        if args.dry_run:
            print("DRY_RUN=true")
            return 0

        print("[loading] 正在运行 Frida 会话（最多 {} 秒）...".format(args.seconds),
              file=sys.stderr)
        try:
            proc = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="replace",
            )
        except OSError as exc:
            print("[FAIL] 无法启动 frida: {}".format(exc), file=sys.stderr)
            return 1

        timed_out = False
        try:
            output, _ = proc.communicate(timeout=args.seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.terminate()
            try:
                output, _ = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                output, _ = proc.communicate()

        output = output or ""
        redacted_lines = [redact(line) for line in output.splitlines()]
        print("[done] Frida 会话结束：{} 行输出".format(len(redacted_lines)),
              file=sys.stderr)
        for line in redacted_lines[-200:]:
            print(line)

        status = "ran"
        if not timed_out and proc.returncode not in (0, None):
            status = "failed"
        result = {
            "schema": SCHEMA,
            "captured_at": iso_now(),
            "mode": args.mode,
            "target": target,
            "package": args.package,
            "pid": pid,
            "template": template,
            "script_path": script_path,
            "command": redact(" ".join(command)),
            "duration_seconds": args.seconds,
            "timed_out": timed_out,
            "exit_code": proc.returncode,
            "status": status,
            "output_lines": redacted_lines[-200:],
            "notes": [
                "模板只做观察，不绕过证书校验，不修改业务逻辑。",
                "输出可能包含 URL/日志中的敏感信息，已做基础脱敏。",
            ],
        }
        temp_path = evidence_path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(temp_path, evidence_path)
        os.chmod(evidence_path, 0o600)

        print("FRIDA_STATUS={}".format(status))
        print("FRIDA_TIMED_OUT={}".format(str(timed_out).lower()))
        print("OUTPUT_LINES={}".format(len(redacted_lines)))
        print("EVIDENCE_JSON={}".format(evidence_path))
        print("------------------------------------------------------------")
        print("【结论】")
        if status == "ran":
            print("Frida 会话已运行；输出仅代表观察到的运行时行为，"
                  "需人工判断是否与安全结论相关。")
        else:
            print("Frida 会话异常退出；检查 frida-server 版本、进程状态和脚本错误。")
        return 0 if status == "ran" else 1
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="用 Frida 模板观察 Android 运行时行为。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  ./09-frida-hook.py preflight --package com.example.app\n"
            "  ./09-frida-hook.py list --package com.example.app\n"
            "  ./09-frida-hook.py spawn --package com.example.app --template http --confirm\n"
            "  ./09-frida-hook.py attach --package com.example.app --template log --confirm\n"
            "\n退出码:\n"
            "  0 = Frida 会话已运行\n"
            "  1 = 设备/frida-server/进程不可用，或 frida 退出异常\n"
            "  2 = 参数、依赖或输入错误"
        ),
    )
    parser.add_argument("mode", choices=["preflight", "list", "spawn", "attach", "help"],
                        help="操作")
    parser.add_argument("--package", default="", help="目标 Android 包名")
    parser.add_argument("--pid", default="", help="attach 的进程 PID")
    parser.add_argument("--template", choices=sorted(TEMPLATES), default="http",
                        help="内置模板，默认 http")
    parser.add_argument("--script", default="", help="自定义 Frida JS 脚本")
    parser.add_argument("--seconds", type=int, default=10,
                        help="会话持续时间，默认 10")
    parser.add_argument("--serial", default="", help="设备序列号")
    parser.add_argument("--evidence-dir", default="evidence", help="证据目录，默认 evidence")
    parser.add_argument("--confirm", action="store_true", help="确认执行注入")
    parser.add_argument("--dry-run", action="store_true", help="只打印命令")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.mode == "help":
        parse_args(["--help"])
        return 0
    if not 1 <= args.seconds <= 300:
        print("[FAIL] --seconds 必须在 1–300 之间", file=sys.stderr)
        return 2
    if args.mode == "preflight":
        return cmd_preflight(args)
    if args.mode == "list":
        return cmd_list(args)
    return run_frida(args)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[FAIL] 用户中断", file=sys.stderr)
        sys.exit(2)
