#!/usr/bin/env python3
#
# 11-memory-secret-audit.py —— 通用动态分析：进程内存敏感字符串审计
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   检查进程内存或内存 dump 中是否出现明文敏感材料：
#     - Token / Authorization / Bearer / Cookie / 签名；
#     - 密码 / Secret / API Key / 私钥标记；
#     - JWT、邮箱、中国大陆手机号。
#
#   两种工作方式：
#     scan    扫描已有的内存 dump 文件（不需要设备）；
#     capture 通过 Frida 在授权测试设备上枚举可读内存范围并扫描模式。
#
#   重要：
#     - capture 只读取内存，不修改进程、不绕过保护、不写回数据；
#     - 内存扫描结果可能包含大量误报，必须人工确认；
#     - 输出默认脱敏，不保存完整密钥 / Token；
#     - 仅在已授权的测试设备与测试账号上使用。
#
# 子命令：
#   preflight        只读检查 adb、设备、包 / 进程、frida
#   scan             扫描本地内存 dump 文件
#   capture          用 Frida 扫描目标进程内存
#   help             显示帮助
#
# 用法：
#   ./11-memory-secret-audit.py scan --file ./mem.dump
#   ./11-memory-secret-audit.py preflight --package com.example.app
#   ./11-memory-secret-audit.py capture --package com.example.app --confirm
#   ./11-memory-secret-audit.py --help
#
#   错误输入示例：
#     scan 文件不存在 → exit 2；capture 未加 --confirm → exit 2。
#
# 输出：
#   HITS_TOTAL、HITS_<类别>、MEM_HIT 脱敏样例、【结论】、证据 JSON 路径。
#
# 参数：
#   --file <路径>      scan 必填。格式：内存 dump 或二进制文件。
#                      示例：--file ./mem.dump
#   --package <包名>   capture / preflight 必填。示例：com.example.app
#   --pid <PID>        capture 可选。示例：--pid 12345
#   --seconds <秒>     capture 可选，默认 20，范围 1–300。示例：--seconds 30
#   --serial <序列号>  可选。示例：ABC123
#   --max-bytes <N>    scan 可选，默认 67108864（64 MiB）。
#                      示例：--max-bytes 134217728
#   --max-hits <N>     可选，默认 200。示例：--max-hits 50
#   --evidence-dir <目录> 可选，默认 evidence。示例：./evidence
#   --confirm          capture 必须显式确认。
#   --dry-run          可选布尔开关；只打印命令。
#   -h, --help         显示帮助。
#
# 依赖：
#   scan：python3；capture：frida、frida-ps、adb，设备端需要 frida-server。
#
# 退出码：
#   0 = 未发现敏感命中 / 扫描完成
#   1 = 发现敏感命中，或 capture 未能运行
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

SCHEMA = "app-safe/memory-secret-audit/v1"

MEMORY_JS = r"""
function toHex(text) {
  return text.split('').map(function (ch) {
    return ('0' + ch.charCodeAt(0).toString(16)).slice(-2);
  }).join(' ');
}
const patterns = ['token', 'password', 'secret', 'authorization', 'bearer', 'access_token'];
const ranges = Process.enumerateRanges('r--');
let total = 0;
const limit = 200;
patterns.forEach(function (pattern) {
  if (total >= limit) return;
  const hex = toHex(pattern);
  ranges.forEach(function (range) {
    if (total >= limit) return;
    try {
      Memory.scanSync(range.base, range.size, hex).forEach(function (match) {
        if (total >= limit) return;
        let context = '';
        try {
          context = Memory.readUtf8String(match.address.sub(16), 96) || '';
        } catch (e) {}
        console.log('MEM_HIT ' + JSON.stringify({
          pattern: pattern,
          address: match.address.toString(),
          context: context
        }));
        total += 1;
      });
    } catch (e) {}
  });
});
console.log('MEM_SCAN_DONE ' + total);
"""

PATTERNS = [
    ("authorization", re.compile(r"(?i)\b(?:proxy-)?authorization\s*[:=]\s*[^\s,;]+")),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("token", re.compile(
        r"(?i)\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
        r"password|passwd|pwd|secret|api[_-]?key|apikey|signature)"
        r"\s*[\"']?\s*[:=]\s*[\"']?[^\s\"'&,;}]+")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("phone_cn", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
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
        r"(?i)((?:proxy-)?authorization\s*[:=]\s*)[^,;]*",
        r"\1<REDACTED>", text,
    )
    text = re.sub(r"(?i)(\bBearer\s+)\S+", r"\1<REDACTED>", text)
    text = re.sub(
        r"(?i)((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
        r"password|passwd|pwd|secret|api[_-]?key|apikey|signature)"
        r"\s*[\"']?\s*[:=]\s*[\"']?)[^\s\"'&,;}]+",
        r"\1<REDACTED>", text,
    )
    text = re.sub(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "<REDACTED_EMAIL>", text,
    )
    text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", "<REDACTED_PHONE>", text)
    return text


def scan_bytes(data, max_hits):
    counts = {}
    samples = {}
    text = data.decode("latin-1", errors="replace")
    for category, pattern in PATTERNS:
        for match in pattern.finditer(text):
            counts[category] = counts.get(category, 0) + 1
            bucket = samples.setdefault(category, [])
            if len(bucket) < max_hits:
                start = max(0, match.start() - 32)
                end = min(len(text), match.end() + 32)
                context = re.sub(r"[^\x20-\x7e]", ".", text[start:end])
                bucket.append({
                    "offset": match.start(),
                    "preview": redact(context),
                })
    return counts, samples


def write_json(path, data):
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(temp, path)
    os.chmod(path, 0o600)


def cmd_scan(args):
    if not args.file or not os.path.isfile(args.file):
        print("[FAIL] 文件不存在: {}".format(args.file), file=sys.stderr)
        return 2
    if args.max_bytes <= 0 or args.max_hits <= 0:
        print("[FAIL] --max-bytes / --max-hits 必须为正整数", file=sys.stderr)
        return 2

    try:
        with open(args.file, "rb") as fh:
            data = fh.read(args.max_bytes)
    except OSError as exc:
        print("[FAIL] 无法读取文件: {}".format(exc), file=sys.stderr)
        return 2

    print("[loading] 正在扫描内存 dump（{} 字节）...".format(len(data)),
          file=sys.stderr)
    counts, samples = scan_bytes(data, args.max_hits)
    total = sum(counts.values())
    print("[done] 扫描完成：{} 处命中".format(total), file=sys.stderr)

    os.makedirs(args.evidence_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence_path = os.path.join(
        args.evidence_dir, "11-memory-secret-audit-scan-{}.json".format(stamp)
    )
    result = {
        "schema": SCHEMA,
        "captured_at": iso_now(),
        "mode": "scan",
        "source_file": args.file,
        "bytes_read": len(data),
        "truncated": os.path.getsize(args.file) > len(data),
        "hits": {"total": total, "by_category": counts},
        "samples": samples,
        "notes": [
            "内存扫描命中不等于可用凭证；需人工确认。",
            "只扫描前 --max-bytes 字节。",
        ],
    }
    write_json(evidence_path, result)

    print("============================================================")
    print("动态分析 11：内存敏感字符串审计（scan）")
    print("文件：{}".format(args.file))
    print("============================================================")
    print("BYTES_READ={}".format(len(data)))
    print("HITS_TOTAL={}".format(total))
    for category, _pattern in PATTERNS:
        print("HITS_{}={}".format(category.upper(), counts.get(category, 0)))
    if total:
        print("------------------------------------------------------------")
        print("脱敏样例：")
        for category, _pattern in PATTERNS:
            for item in samples.get(category, [])[:args.max_hits]:
                print("[{}] offset={} {}".format(
                    category, item["offset"], item["preview"]
                ))
    print("------------------------------------------------------------")
    print("【结论】")
    if total:
        print("发现 {} 处敏感字符串线索；需人工确认是否为真实凭证。".format(total))
    else:
        print("未发现敏感字符串线索。")
    print("说明：内存扫描误报率较高，且只覆盖有限的模式与字节范围。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))
    return 0 if total == 0 else 1


def cmd_preflight(args):
    if not args.package and not args.pid:
        print("[FAIL] preflight 需要 --package 或 --pid", file=sys.stderr)
        return 2
    if not shutil.which("frida"):
        print("[FAIL] 缺少工具: frida", file=sys.stderr)
        print("       安装提示: python3 -m pip install --user frida-tools", file=sys.stderr)
        return 2
    if not need_adb():
        return 2
    adb = adb_base(args.serial)
    rc, out = run_command(adb + ["get-state"], timeout=8)
    if rc != 0 or out.strip() != "device":
        print("[FAIL] 没有在线 Android 设备", file=sys.stderr)
        return 1
    print("ADB_STATE=device")
    print("PACKAGE_NAME={}".format(args.package))
    if args.package:
        rc_pkg, out_pkg = run_command(adb + ["shell", "pm", "path", args.package],
                                      timeout=8)
        print("PACKAGE_INSTALLED={}".format(
            str(rc_pkg == 0 and out_pkg.strip().startswith("package:")).lower()
        ))
    if args.pid:
        print("PID={}".format(args.pid))
    rc_ps, ps_out = run_command(["frida-ps", "-U"], timeout=15)
    print("FRIDA_DEVICE_READY={}".format(str(rc_ps == 0).lower()))
    if rc_ps != 0:
        print("[FAIL] frida 无法连接设备；确认 frida-server 已启动", file=sys.stderr)
        print("PREFLIGHT_PASSED=false")
        return 1
    print("PREFLIGHT_PASSED=true")
    return 0


def cmd_capture(args):
    if not args.package and not args.pid:
        print("[FAIL] capture 需要 --package 或 --pid", file=sys.stderr)
        return 2
    if not args.confirm and not args.dry_run:
        print("[FAIL] capture 会注入 Frida 脚本；请加 --confirm 确认授权。",
              file=sys.stderr)
        return 2
    if not shutil.which("frida"):
        print("[FAIL] 缺少工具: frida", file=sys.stderr)
        print("       安装提示: python3 -m pip install --user frida-tools", file=sys.stderr)
        return 2
    if not need_adb():
        return 2

    workdir = tempfile.mkdtemp(prefix="memory-scan-")
    script_path = os.path.join(workdir, "memory-scan.js")
    with open(script_path, "w", encoding="utf-8") as fh:
        fh.write(MEMORY_JS.strip() + "\n")

    device_args = ["-D", args.serial] if args.serial else ["-U"]
    if args.pid:
        command = ["frida"] + device_args + ["-p", str(args.pid), "-l", script_path, "-q"]
    else:
        command = ["frida"] + device_args + [
            "-f", args.package, "-l", script_path, "--no-pause", "-q"
        ]

    print("FRIDA_COMMAND={}".format(" ".join(command)))
    if args.dry_run:
        print("DRY_RUN=true")
        shutil.rmtree(workdir, ignore_errors=True)
        return 0

    print("[loading] 正在扫描进程内存（最多 {} 秒）...".format(args.seconds),
          file=sys.stderr)
    try:
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace",
        )
    except OSError as exc:
        print("[FAIL] 无法启动 frida: {}".format(exc), file=sys.stderr)
        shutil.rmtree(workdir, ignore_errors=True)
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
    shutil.rmtree(workdir, ignore_errors=True)
    print("[done] 内存扫描结束：{} 行输出".format(len((output or "").splitlines())),
          file=sys.stderr)

    hits = []
    for line in (output or "").splitlines():
        if not line.startswith("MEM_HIT "):
            continue
        try:
            payload = json.loads(line[len("MEM_HIT "):])
        except json.JSONDecodeError:
            continue
        hits.append({
            "pattern": payload.get("pattern", ""),
            "address": payload.get("address", ""),
            "context": redact(payload.get("context", ""))[:240],
        })

    counts = {}
    for hit in hits:
        counts[hit["pattern"]] = counts.get(hit["pattern"], 0) + 1

    os.makedirs(args.evidence_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence_path = os.path.join(
        args.evidence_dir, "11-memory-secret-audit-capture-{}.json".format(stamp)
    )
    result = {
        "schema": SCHEMA,
        "captured_at": iso_now(),
        "mode": "capture",
        "package": args.package,
        "pid": args.pid,
        "timed_out": timed_out,
        "exit_code": proc.returncode,
        "hit_count": len(hits),
        "hits_by_pattern": counts,
        "hits": hits[:args.max_hits],
        "notes": [
            "capture 只读取内存，不修改进程。",
            "命中不等于可用凭证；内存扫描误报率较高。",
        ],
    }
    write_json(evidence_path, result)

    print("============================================================")
    print("动态分析 11：内存敏感字符串审计（capture）")
    print("目标包：{}".format(args.package))
    print("============================================================")
    print("MEMORY_HIT_COUNT={}".format(len(hits)))
    for pattern, count in sorted(counts.items()):
        print("HITS_{}={}".format(pattern.upper(), count))
    print("TIMED_OUT={}".format(str(timed_out).lower()))
    for hit in hits[:args.max_hits]:
        print("MEM_HIT pattern={} address={} context={}".format(
            hit["pattern"], hit["address"], hit["context"]
        ))
    print("------------------------------------------------------------")
    print("【结论】")
    if hits:
        print("发现 {} 处内存敏感字符串线索；需人工确认是否为真实凭证。".format(len(hits)))
    else:
        print("未发现内存敏感字符串线索；这可能意味着没有明文凭证，"
              "也可能是扫描范围/模式不足。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))

    status_ok = timed_out or (proc.returncode in (0, None))
    return 0 if status_ok else 1


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="扫描内存 dump 或 Frida 进程内存中的敏感字符串。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  ./11-memory-secret-audit.py scan --file ./mem.dump\n"
            "  ./11-memory-secret-audit.py preflight --package com.example.app\n"
            "  ./11-memory-secret-audit.py capture --package com.example.app --confirm\n"
            "\n退出码:\n"
            "  0 = 未发现敏感命中 / 扫描完成\n"
            "  1 = 发现敏感命中，或 capture 未能运行\n"
            "  2 = 参数、依赖或输入错误"
        ),
    )
    parser.add_argument("mode", choices=["preflight", "scan", "capture", "help"],
                        help="操作")
    parser.add_argument("--file", default="", help="scan 的输入文件")
    parser.add_argument("--package", default="", help="目标 Android 包名")
    parser.add_argument("--pid", default="", help="capture 附加的 PID")
    parser.add_argument("--seconds", type=int, default=20,
                        help="capture 持续时间，默认 20")
    parser.add_argument("--serial", default="", help="设备序列号")
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024,
                        help="scan 最多读取字节数，默认 64 MiB")
    parser.add_argument("--max-hits", type=int, default=200,
                        help="最多保留命中数，默认 200")
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
    if args.mode == "scan":
        return cmd_scan(args)
    if args.mode == "preflight":
        return cmd_preflight(args)
    return cmd_capture(args)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[FAIL] 用户中断", file=sys.stderr)
        sys.exit(2)
