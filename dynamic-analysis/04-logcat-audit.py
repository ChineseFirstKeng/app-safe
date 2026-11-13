#!/usr/bin/env python3
#
# 04-logcat-audit.py —— 通用动态分析：运行日志采集与敏感信息审计
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   采集 Android 应用运行期间的 logcat，检查是否把本不该落日志的材料
#   打印出来，回答：
#     - 日志里是否出现 Authorization / Bearer / Token / Cookie？
#     - 是否出现签名、密码、API Key、私钥？
#     - 是否出现完整请求行、URL 查询参数中的密钥？
#     - 是否出现邮箱、手机号等个人信息？
#
#   默认只保存脱敏后的审计结果，不保存原始日志；确需保留原始日志时
#   必须显式 --keep-raw，脚本会以 0600 权限写入并打印警告。
#
# 子命令：
#   preflight        只读检查 adb、设备、包安装状态、进程与 logcat 可用性
#   capture          采集指定时长的日志并审计
#   analyze          审计已有日志文件（不连接设备）
#   help             显示帮助
#
# 用法：
#   ./04-logcat-audit.py preflight --package com.example.app
#   ./04-logcat-audit.py capture --package com.example.app --seconds 10 --clear
#   ./04-logcat-audit.py analyze --file ./logcat.txt
#   ./04-logcat-audit.py --help
#
#   错误输入示例：
#     缺少 --package，或 --seconds 超出 1–300 → 打印用法并 exit 2。
#
# 输出：
#   LOG_LINE_COUNT、HITS_TOTAL、HITS_<类别>、脱敏样例、【结论】、
#   证据 JSON 路径。默认不保存原始日志。
#
# 参数：
#   --package <包名>      capture / preflight 必填。格式：Android 包名。
#                         示例：--package com.example.app
#   --seconds <秒>        capture 采集时长，可选，默认 10，范围 1–300。
#                         示例：--seconds 30
#   --file <路径>         analyze 必填。格式：文本日志路径，或 - 表示 stdin。
#                         示例：--file ./logcat.txt
#   --evidence-dir <目录> 可选，默认 evidence。示例：--evidence-dir ./evidence
#   --serial <序列号>     可选，多设备时指定。示例：--serial ABC123
#   --clear               可选布尔开关；capture 前清空 logcat。
#   --keep-raw            可选布尔开关；保存原始日志（含敏感数据）。
#   --max-hits <N>        可选，默认 5。示例：--max-hits 10
#   -h, --help            显示帮助。
#
# 依赖：
#   python3；capture / preflight 需要 adb。analyze 不依赖 adb。
#
# 退出码：
#   0 = 采集 / 分析完成，未命中敏感模式
#   1 = 命中敏感模式，或采集结果为空 / 不可判定
#   2 = 参数、依赖或设备错误
#
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA = "app-safe/logcat-audit/v1"

# item: (类别, 正则, 说明)
PATTERNS = [
    ("authorization", re.compile(r"(?i)\b(?:proxy-)?authorization\s*[:=]\s*\S+"),
     "Authorization 请求头"),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
     "Bearer Token"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "JWT"),
    ("token", re.compile(
        r"(?i)\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token)"
        r"\s*[\"']?\s*[:=]\s*[\"']?[^\s\"'&,;}]+"), "Token 字段"),
    ("signature", re.compile(
        r"(?i)\b(?:x[-_]?signature|signature)\s*[\"']?\s*[:=]\s*[\"']?[^\s\"'&,;}]+"),
     "签名字段"),
    ("cookie", re.compile(r"(?i)\b(?:set-cookie|cookie)\s*:\s*\S+"),
     "Cookie"),
    ("credential", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey)"
        r"\s*[\"']?\s*[:=]\s*[\"']?[^\s\"'&,;}]+"), "密码 / 密钥"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "私钥标记"),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
     "邮箱"),
    ("phone_cn", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "中国大陆手机号"),
    ("url_query_secret", re.compile(
        r"(?i)[?&](?:token|access_token|refresh_token|signature|sig|password)=[^&\s]+"),
     "URL 查询参数中的密钥"),
    ("request_line", re.compile(r"(?i)\b(?:GET|POST|PUT|PATCH|DELETE)\s+https?://\S+"),
     "完整请求行"),
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


def run_command(command, timeout=10):
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return 127, "command not found: {}".format(command[0])
    except subprocess.TimeoutExpired:
        return 124, "timeout after {}s".format(timeout)
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output


def get_pid(adb, package):
    rc, out = run_command(adb + ["shell", "pidof", package], timeout=8)
    if rc == 0:
        parts = out.split()
        if parts and parts[0].isdigit():
            return parts[0]

    rc, out = run_command(adb + ["shell", "ps", "-A"], timeout=8)
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1] == package and parts[1].isdigit():
                return parts[1]
    return ""


def package_installed(adb, package):
    rc, out = run_command(adb + ["shell", "pm", "path", package], timeout=8)
    return rc == 0 and out.strip().startswith("package:")


def capture_logs(adb, pid, seconds):
    command = adb + ["logcat", "-v", "threadtime"]
    if pid:
        command.append("--pid={}".format(pid))

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
    except OSError as exc:
        return "", str(exc)

    timed_out = False
    try:
        out, _ = proc.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()

    if not timed_out and proc.returncode not in (0, None):
        return out or "", "logcat exited with code {}".format(proc.returncode)
    return out or "", None


def redact_line(line):
    text = line.rstrip("\r\n")
    text = re.sub(
        r"(?i)((?:proxy-)?authorization\s*[:=]\s*)[^,;]*",
        r"\1<REDACTED>", text,
    )
    text = re.sub(r"(?i)(\bBearer\s+)\S+", r"\1<REDACTED>", text)
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "<REDACTED_JWT>", text,
    )
    text = re.sub(
        r"(?i)(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
        r"password|passwd|pwd|secret|api[_-]?key|apikey|signature|x[-_]?signature)"
        r"\s*[\"']?\s*[:=]\s*[\"']?)[^\s\"'&,;}]+",
        r"\1<REDACTED>", text,
    )
    text = re.sub(r"(?i)(\b(?:set-cookie|cookie)\s*:\s*)[^;]*", r"\1<REDACTED>", text)
    text = re.sub(
        r"(?i)([?&](?:token|access_token|refresh_token|signature|sig|password)=)[^&\s]+",
        r"\1<REDACTED>", text,
    )
    text = re.sub(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "<REDACTED_EMAIL>", text,
    )
    text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", "<REDACTED_PHONE>", text)
    return text


def scan_lines(lines, max_hits):
    counts = {}
    samples = {}
    for line in lines:
        matched = []
        for category, pattern, _description in PATTERNS:
            if pattern.search(line):
                matched.append(category)
        if not matched:
            continue

        redacted = redact_line(line)
        for category in matched:
            counts[category] = counts.get(category, 0) + 1
            bucket = samples.setdefault(category, [])
            if len(bucket) < max_hits and redacted not in bucket:
                bucket.append(redacted)
    return counts, samples


def unique_path(directory, stem, suffix):
    candidate = os.path.join(directory, stem + suffix)
    index = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, "{}-{}{}".format(stem, index, suffix))
        index += 1
    return candidate


def write_json(path, data):
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(temp, path)
    os.chmod(path, 0o600)


def write_raw(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def emit_result(result, counts, samples, evidence_path, raw_path):
    total = sum(counts.values())
    print("============================================================")
    print("动态分析 04：日志敏感信息审计")
    print("目标包：{}".format(result.get("package") or "（未指定）"))
    print("采集时间：{}".format(result.get("captured_at", "")))
    print("============================================================")
    print("LOG_LINE_COUNT={}".format(result["line_count"]))
    print("LOG_EMPTY={}".format(str(result["empty"]).lower()))
    print("HITS_TOTAL={}".format(total))
    for category, _pattern, description in PATTERNS:
        print("HITS_{}={}".format(category.upper(), counts.get(category, 0)))
    print("------------------------------------------------------------")
    if total == 0:
        print("未命中敏感模式。")
        print("注意：没有命中不等于没有泄露；需确认采集期间确实触发了目标业务。")
    else:
        print("命中类别与脱敏样例：")
        for category, _pattern, description in PATTERNS:
            bucket = samples.get(category, [])
            if not bucket:
                continue
            print("[{}] {}（{} 次）".format(category, description, counts.get(category, 0)))
            for line in bucket:
                print("  {}".format(line))
    print("------------------------------------------------------------")
    print("【结论】")
    if result["empty"]:
        print("采集结果为空，无法判定是否存在日志泄露。")
    elif total == 0:
        print("未发现敏感信息泄露线索。")
    else:
        print("发现 {} 处敏感信息线索；需人工确认是否来自目标应用、"
              "是否为真实凭证。".format(total))
        print("不要把“命中模式”直接写成“确认泄露”。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))
    if raw_path:
        print("RAW_LOG={}".format(raw_path))
        print("RAW_LOG_WARNING=原始日志未脱敏，可能包含 Token/请求体，请按授权范围保管。")
    print("AUDIT_PASSED={}".format("true" if total == 0 and not result["empty"] else "false"))


def cmd_preflight(args):
    if not need_adb():
        return 2
    if not re.fullmatch(r"[A-Za-z0-9_.]+", args.package):
        print("[FAIL] --package 格式不合法: {}".format(args.package), file=sys.stderr)
        return 2

    adb = adb_base(args.serial)
    rc, out = run_command(adb + ["get-state"], timeout=8)
    if rc != 0 or out.strip() != "device":
        print("[FAIL] 没有在线 Android 设备: {}".format(out.strip()), file=sys.stderr)
        return 1

    installed = package_installed(adb, args.package)
    pid = get_pid(adb, args.package)
    rc_logcat, out_logcat = run_command(adb + ["logcat", "-d", "-t", "1"], timeout=8)
    rc_buffer, out_buffer = run_command(adb + ["logcat", "-g"], timeout=8)
    buffer_line = out_buffer.strip().splitlines()[0] if out_buffer.strip() else ""

    print("ADB_STATE=device")
    print("PACKAGE_NAME={}".format(args.package))
    print("PACKAGE_INSTALLED={}".format(str(installed).lower()))
    print("PROCESS_RUNNING={}".format(str(bool(pid)).lower()))
    print("PID={}".format(pid))
    print("LOGCAT_ACCESSIBLE={}".format(str(rc_logcat == 0).lower()))
    print("LOGCAT_BUFFER={}".format(buffer_line))

    if not installed:
        print("[FAIL] 目标包未安装，无法进行按包采集", file=sys.stderr)
        print("PREFLIGHT_PASSED=false")
        return 1
    if rc_logcat != 0:
        print("[FAIL] logcat 不可用: {}".format(out_logcat.strip()), file=sys.stderr)
        print("PREFLIGHT_PASSED=false")
        return 1

    if not pid:
        print("[WARN] 目标进程未运行；capture 将捕获全部日志或需要先启动应用", file=sys.stderr)
    print("PREFLIGHT_PASSED=true")
    return 0


def cmd_capture(args):
    if not need_adb():
        return 2
    if not re.fullmatch(r"[A-Za-z0-9_.]+", args.package):
        print("[FAIL] --package 格式不合法: {}".format(args.package), file=sys.stderr)
        return 2
    if not 1 <= args.seconds <= 300:
        print("[FAIL] --seconds 必须在 1–300 之间", file=sys.stderr)
        return 2
    if args.max_hits < 0:
        print("[FAIL] --max-hits 必须是非负整数", file=sys.stderr)
        return 2

    adb = adb_base(args.serial)
    rc, out = run_command(adb + ["get-state"], timeout=8)
    if rc != 0 or out.strip() != "device":
        print("[FAIL] 没有在线 Android 设备: {}".format(out.strip()), file=sys.stderr)
        return 1
    if not package_installed(adb, args.package):
        print("[FAIL] 目标包未安装: {}".format(args.package), file=sys.stderr)
        return 1

    if args.clear:
        run_command(adb + ["logcat", "-c"], timeout=8)

    pid = get_pid(adb, args.package)
    print("[loading] 正在采集 logcat（{} 秒）...".format(args.seconds), file=sys.stderr)
    log_text, error = capture_logs(adb, pid, args.seconds)
    print("[done] 采集完成：{} 行".format(len(log_text.splitlines())),
          file=sys.stderr)
    if error:
        print("[FAIL] 无法启动 logcat: {}".format(error), file=sys.stderr)
        return 2

    lines = log_text.splitlines()
    counts, samples = scan_lines(lines, args.max_hits)
    empty = len(lines) == 0
    print("PID={}".format(pid or "（未找到，已捕获全部日志）"))

    os.makedirs(args.evidence_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence_path = unique_path(
        args.evidence_dir, "04-logcat-audit-{}".format(stamp), ".json"
    )
    raw_path = ""
    if args.keep_raw:
        raw_path = unique_path(
            args.evidence_dir, "04-logcat-audit-{}-raw".format(stamp), ".log"
        )
        write_raw(raw_path, log_text)
        print("[WARN] 已保存原始日志（未脱敏）：{}".format(raw_path), file=sys.stderr)

    result = {
        "schema": SCHEMA,
        "captured_at": iso_now(),
        "package": args.package,
        "pid": pid,
        "seconds": args.seconds,
        "line_count": len(lines),
        "empty": empty,
        "hits": {
            "total": sum(counts.values()),
            "by_category": counts,
        },
        "samples": samples,
        "raw_kept": bool(raw_path),
        "redaction": "values masked; raw log is not written unless --keep-raw",
    }
    write_json(evidence_path, result)
    emit_result(result, counts, samples, evidence_path, raw_path)

    if empty:
        print("[WARN] 采集结果为空：可能是应用没有输出日志，或采集期间没有触发业务。",
              file=sys.stderr)
        return 1
    if sum(counts.values()) > 0:
        return 1
    return 0


def cmd_analyze(args):
    if not args.file:
        print("[FAIL] analyze 需要 --file", file=sys.stderr)
        return 2
    if args.max_hits < 0:
        print("[FAIL] --max-hits 必须是非负整数", file=sys.stderr)
        return 2

    try:
        print("[loading] 正在读取日志文件...", file=sys.stderr)
        if args.file == "-":
            text = sys.stdin.read()
        else:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        print("[done] 读取完成：{} 行".format(len(text.splitlines())),
              file=sys.stderr)
    except OSError as exc:
        print("[FAIL] 无法读取日志: {}".format(exc), file=sys.stderr)
        return 2

    lines = text.splitlines()
    counts, samples = scan_lines(lines, args.max_hits)
    empty = len(lines) == 0

    os.makedirs(args.evidence_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence_path = unique_path(
        args.evidence_dir, "04-logcat-audit-{}-analyze".format(stamp), ".json"
    )
    result = {
        "schema": SCHEMA,
        "captured_at": iso_now(),
        "package": "",
        "source_file": args.file,
        "pid": "",
        "seconds": 0,
        "line_count": len(lines),
        "empty": empty,
        "hits": {
            "total": sum(counts.values()),
            "by_category": counts,
        },
        "samples": samples,
        "raw_kept": False,
        "redaction": "values masked; input file is not modified",
    }
    write_json(evidence_path, result)
    emit_result(result, counts, samples, evidence_path, "")

    if empty:
        print("[WARN] 输入日志为空。", file=sys.stderr)
        return 1
    if sum(counts.values()) > 0:
        return 1
    return 0


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="采集 / 审计 Android logcat 中的敏感信息。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  ./04-logcat-audit.py preflight --package com.example.app\n"
            "  ./04-logcat-audit.py capture --package com.example.app --seconds 10 --clear\n"
            "  ./04-logcat-audit.py analyze --file ./logcat.txt\n"
            "\n退出码:\n"
            "  0 = 未命中或分析完成\n"
            "  1 = 命中敏感模式，或采集结果为空\n"
            "  2 = 参数、依赖或设备错误"
        ),
    )
    parser.add_argument("action", choices=["preflight", "capture", "analyze", "help"],
                        help="操作")
    parser.add_argument("--package", default="", help="目标 Android 包名")
    parser.add_argument("--seconds", type=int, default=10, help="capture 采集时长，默认 10")
    parser.add_argument("--file", default="", help="analyze 输入文件；- 表示 stdin")
    parser.add_argument("--evidence-dir", default="evidence", help="证据目录，默认 evidence")
    parser.add_argument("--serial", default="", help="设备序列号")
    parser.add_argument("--clear", action="store_true", help="capture 前清空 logcat")
    parser.add_argument("--keep-raw", action="store_true",
                        help="保存原始日志（含敏感数据，默认不保存）")
    parser.add_argument("--max-hits", type=int, default=5,
                        help="每个类别最多保留的样例数，默认 5")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.action == "help":
        parse_args(["--help"])
        return 0
    if args.action in ("preflight", "capture") and not args.package:
        print("[FAIL] {} 需要 --package".format(args.action), file=sys.stderr)
        return 2
    if args.action == "preflight":
        return cmd_preflight(args)
    if args.action == "capture":
        return cmd_capture(args)
    return cmd_analyze(args)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[FAIL] 用户中断", file=sys.stderr)
        sys.exit(2)
