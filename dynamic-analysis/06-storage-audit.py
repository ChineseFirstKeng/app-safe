#!/usr/bin/env python3
#
# 06-storage-audit.py —— 通用动态分析：应用私有存储与落盘敏感数据审计
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   检查应用在设备上实际落盘的数据，回答：
#     - 应用私有目录里有哪些文件？大小和类别如何？
#     - SharedPreferences / SQLite / files / cache 中是否出现
#       Token、密码、签名、API Key、邮箱、手机号、私钥？
#     - 外部存储目录是否可读？是否包含敏感文件？
#
#   访问方式：
#     - 优先 run-as（应用 debuggable 或设备 ro.debuggable=1）；
#     - 不可用时回退到 Root（su -c）；
#     - 两者都不可用则退出，不静默跳过。
#
#   本脚本只读取有限字节用于模式匹配，不复制原始文件，不修改应用数据。
#
# 子命令：
#   preflight        只读检查 adb、设备、包安装状态、run-as / Root 可用性
#   list             列出应用数据文件（路径、大小、类别），不读取内容
#   audit            列出并扫描敏感模式，输出脱敏结果和证据 JSON
#   help             显示帮助
#
# 用法：
#   ./06-storage-audit.py preflight --package com.example.app
#   ./06-storage-audit.py list --package com.example.app --max-files 50
#   ./06-storage-audit.py audit --package com.example.app --max-bytes 262144
#   ./06-storage-audit.py --help
#
#   错误输入示例：
#     缺少 --package，或 --max-files 不是正整数 → 打印用法并 exit 2。
#
# 输出：
#   ACCESS_MODE、FILE_COUNT、SCANNED_FILES、HITS_<类别>、【结论】、
#   证据 JSON 路径；不保存文件内容。
#
# 参数：
#   --package <包名>      必填。格式：Android 包名。示例：com.example.app
#   --serial <序列号>     可选，多设备时指定。示例：ABC123
#   --max-files <N>       可选，默认 100。示例：--max-files 50
#   --max-bytes <N>       可选，默认 262144。示例：--max-bytes 1048576
#   --max-hits <N>        可选，默认 5。示例：--max-hits 10
#   --no-external         可选布尔开关；不扫描外部存储目录。
#   --evidence-dir <目录> 可选，默认 evidence。示例：./evidence
#   -h, --help            显示帮助。
#
# 依赖：
#   python3、adb。
#
# 退出码：
#   0 = 未发现敏感落盘线索
#   1 = 发现敏感线索，或无法访问应用数据 / 数据目录为空
#   2 = 参数、依赖或设备错误
#
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA = "app-safe/storage-audit/v1"
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:token|password|passwd|pwd|secret|api[_-]?key|apikey|"
    r"signature|authorization|cookie|credential|private[_-]?key)"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
XML_STRING_RE = re.compile(
    r"<string\s+name=[\"']([^\"']+)[\"'][^>]*>([^<]{1,1024})</string>",
    re.IGNORECASE | re.DOTALL,
)
JSON_KV_RE = re.compile(r"\"([^\"]{1,80})\"\s*:\s*\"([^\"]{1,1024})\"")
KV_RE = re.compile(
    r"(?i)\b([A-Za-z0-9_.-]*(?:token|password|passwd|pwd|secret|api[_-]?key|"
    r"signature|authorization|cookie)[A-Za-z0-9_.-]*)\s*[:=]\s*"
    r"([^\s,;<>\"']{1,512})"
)

PATTERN_LABELS = [
    ("private_key", "私钥标记"),
    ("jwt", "JWT"),
    ("email", "邮箱"),
    ("phone_cn", "中国大陆手机号"),
    ("token", "Token / 密码 / 密钥字段"),
    ("xml_secret", "SharedPreferences 敏感键"),
    ("json_secret", "JSON 敏感键"),
    ("kv_secret", "key=value 敏感字段"),
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


def run_command(command, timeout=20, binary=False):
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
            text=not binary,
        )
    except FileNotFoundError:
        return 127, b"" if binary else "command not found: {}".format(command[0])
    except subprocess.TimeoutExpired:
        return 124, b"" if binary else "timeout after {}s".format(timeout)
    if binary:
        return proc.returncode, (proc.stdout or b"") + (proc.stderr or b"")
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output


def detect_access(adb, package):
    rc, out = run_command(adb + ["shell", "run-as", package, "id"], timeout=8)
    if rc == 0 and "uid=" in out:
        return "run-as"
    rc, out = run_command(adb + ["shell", "su", "-c", "id"], timeout=8)
    if rc == 0 and "uid=0" in out:
        return "root"
    return ""


def app_command(adb, package, access, command):
    if access == "run-as":
        return adb + [
            "shell",
            "run-as {} sh -c {}".format(package, shlex.quote(command)),
        ]
    if access == "root":
        return adb + ["shell", "su -c {}".format(shlex.quote(command))]
    raise ValueError("no access mode")


def app_run(adb, package, access, command, timeout=20, binary=False):
    return run_command(
        app_command(adb, package, access, command), timeout=timeout, binary=binary
    )


def dir_exists(adb, package, access, path):
    rc, out = app_run(
        adb, package, access, "test -d {} && echo yes".format(shlex.quote(path)),
        timeout=8,
    )
    return rc == 0 and out.strip().endswith("yes")


def find_files(adb, package, access, root):
    rc, out = app_run(
        adb, package, access,
        "find {} -type f 2>/dev/null".format(shlex.quote(root)),
        timeout=60,
    )
    if rc != 0:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def file_size(adb, package, access, path):
    rc, out = app_run(
        adb, package, access,
        "stat -c %s {} 2>/dev/null".format(shlex.quote(path)),
        timeout=8,
    )
    value = out.strip().splitlines()[0] if out.strip() else ""
    return int(value) if value.isdigit() else -1


def read_prefix(adb, package, access, path, max_bytes):
    command = "head -c {} {} 2>/dev/null".format(max_bytes, shlex.quote(path))
    rc, data = app_run(adb, package, access, command, timeout=30, binary=True)
    if rc == 0 and data:
        return data
    command = "dd if={} bs=1 count={} 2>/dev/null".format(
        shlex.quote(path), max_bytes
    )
    rc, data = app_run(adb, package, access, command, timeout=30, binary=True)
    return data if rc == 0 else b""


def file_category(path, external_root):
    if external_root and path.startswith(external_root):
        return "external"
    if "/shared_prefs/" in path:
        return "shared_prefs"
    if "/databases/" in path:
        return "databases"
    if "/cache/" in path:
        return "cache"
    if "/files/" in path:
        return "files"
    return "other"


def add_hit(hits, counters, category, path, key=""):
    counters[category] = counters.get(category, 0) + 1
    bucket = hits.setdefault(category, [])
    signature = (path, key, category)
    if len(bucket) < 100 and signature not in {
        (item["file"], item["key"], item["category"]) for item in bucket
    }:
        bucket.append({
            "category": category,
            "file": path,
            "key": key,
            "value": "<REDACTED>",
        })


def scan_text(text, path, hits, counters):
    for match in XML_STRING_RE.finditer(text):
        key = match.group(1)
        if SENSITIVE_KEY_RE.search(key):
            add_hit(hits, counters, "xml_secret", path, key)

    for match in JSON_KV_RE.finditer(text):
        key = match.group(1)
        if SENSITIVE_KEY_RE.search(key):
            add_hit(hits, counters, "json_secret", path, key)

    for match in KV_RE.finditer(text):
        add_hit(hits, counters, "kv_secret", path, match.group(1))

    for match in PRIVATE_KEY_RE.finditer(text):
        add_hit(hits, counters, "private_key", path)

    for match in JWT_RE.finditer(text):
        add_hit(hits, counters, "jwt", path)

    for match in EMAIL_RE.finditer(text):
        add_hit(hits, counters, "email", path)

    for match in PHONE_RE.finditer(text):
        add_hit(hits, counters, "phone_cn", path)


def collect_files(adb, package, access, data_dirs, external_dir, include_external,
                  max_files):
    roots = [(directory, False) for directory in data_dirs]
    if include_external and external_dir and dir_exists(
        adb, package, access, external_dir
    ):
        roots.append((external_dir, True))

    files = []
    for root, is_external in roots:
        for path in find_files(adb, package, access, root):
            category = file_category(path, external_dir if is_external else "")
            files.append({
                "path": path,
                "root": root,
                "category": category,
                "external": is_external,
            })
            if len(files) >= max_files:
                return files
    return files


def write_json(path, data):
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(temp, path)
    os.chmod(path, 0o600)


def unique_path(directory, stem, suffix):
    candidate = os.path.join(directory, stem + suffix)
    index = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, "{}-{}{}".format(stem, index, suffix))
        index += 1
    return candidate


def resolve_dirs(adb, package, access):
    candidates = [
        "/data/user/0/{}".format(package),
        "/data/user_de/0/{}".format(package),
        "/data/data/{}".format(package),
    ]
    found = []
    for candidate in candidates:
        if dir_exists(adb, package, access, candidate):
            found.append(candidate)
    if found:
        return found[0], found
    return candidates[-1], []


def cmd_preflight(args):
    if not need_adb():
        return 2
    adb = adb_base(args.serial)
    rc, out = run_command(adb + ["get-state"], timeout=8)
    if rc != 0 or out.strip() != "device":
        print("[FAIL] 没有在线 Android 设备: {}".format(out.strip()), file=sys.stderr)
        return 1

    rc_pkg, out_pkg = run_command(adb + ["shell", "pm", "path", args.package],
                                  timeout=8)
    installed = rc_pkg == 0 and out_pkg.strip().startswith("package:")
    access = detect_access(adb, args.package) if installed else ""
    data_dir = ""
    data_dirs = []
    if access:
        data_dir, data_dirs = resolve_dirs(adb, args.package, access)
    external_dir = "/sdcard/Android/data/{}".format(args.package)
    external_ok = bool(access) and dir_exists(adb, args.package, access, external_dir)
    file_count = 0
    if access:
        for directory in data_dirs:
            file_count += len(find_files(adb, args.package, access, directory))

    print("ADB_STATE=device")
    print("PACKAGE_NAME={}".format(args.package))
    print("PACKAGE_INSTALLED={}".format(str(installed).lower()))
    print("ACCESS_MODE={}".format(access or "none"))
    print("DATA_DIR={}".format(data_dir))
    print("DATA_DIRS={}".format(", ".join(data_dirs)))
    print("DATA_FILE_COUNT={}".format(file_count))
    print("EXTERNAL_DIR={}".format(external_dir))
    print("EXTERNAL_ACCESSIBLE={}".format(str(external_ok).lower()))

    if not installed:
        print("PREFLIGHT_PASSED=false")
        return 1
    if not access:
        print("[FAIL] run-as 和 Root 都不可用，无法读取应用私有数据",
              file=sys.stderr)
        print("PREFLIGHT_PASSED=false")
        return 1
    print("PREFLIGHT_PASSED=true")
    return 0


def cmd_list(args):
    if not need_adb():
        return 2
    adb = adb_base(args.serial)
    rc_pkg, out_pkg = run_command(adb + ["shell", "pm", "path", args.package],
                                  timeout=8)
    if rc_pkg != 0 or not out_pkg.strip().startswith("package:"):
        print("[FAIL] 目标包未安装: {}".format(args.package), file=sys.stderr)
        return 1
    access = detect_access(adb, args.package)
    if not access:
        print("[FAIL] 无法访问应用数据：run-as 和 Root 都不可用", file=sys.stderr)
        return 1
    data_dir, data_dirs = resolve_dirs(adb, args.package, access)
    external_dir = "/sdcard/Android/data/{}".format(args.package)
    include_external = not args.no_external
    files = collect_files(
        adb, args.package, access, data_dirs, external_dir, include_external,
        args.max_files,
    )

    print("ACCESS_MODE={}".format(access))
    print("DATA_DIR={}".format(data_dir))
    print("DATA_DIRS={}".format(", ".join(data_dirs)))
    print("FILE_COUNT={}".format(len(files)))
    for item in files:
        size = file_size(adb, args.package, access, item["path"])
        item["size"] = size
        print("FILE={} size={} category={}".format(
            item["path"], size, item["category"]
        ))
    return 0


def cmd_audit(args):
    if not need_adb():
        return 2
    adb = adb_base(args.serial)
    rc_pkg, out_pkg = run_command(adb + ["shell", "pm", "path", args.package],
                                  timeout=8)
    if rc_pkg != 0 or not out_pkg.strip().startswith("package:"):
        print("[FAIL] 目标包未安装: {}".format(args.package), file=sys.stderr)
        return 1
    access = detect_access(adb, args.package)
    if not access:
        print("[FAIL] 无法访问应用数据：run-as 和 Root 都不可用", file=sys.stderr)
        return 1

    data_dir, data_dirs = resolve_dirs(adb, args.package, access)
    external_dir = "/sdcard/Android/data/{}".format(args.package)
    include_external = not args.no_external

    print("[loading] 正在枚举应用数据文件...", file=sys.stderr)
    files = collect_files(
        adb, args.package, access, data_dirs, external_dir, include_external,
        args.max_files,
    )
    print("[done] 找到 {} 个候选文件（上限 {}）".format(len(files), args.max_files),
          file=sys.stderr)
    if not files:
        print("[WARN] 应用数据目录没有找到文件；可能是新安装或数据为空。",
              file=sys.stderr)

    hits = {}
    counters = {}
    scanned = 0
    total_bytes = 0
    file_records = []

    print("[loading] 正在读取并扫描 {} 个文件（每个最多 {} 字节）...".format(
        len(files), args.max_bytes
    ), file=sys.stderr)
    for item in files:
        size = file_size(adb, args.package, access, item["path"])
        item["size"] = size
        data = read_prefix(adb, args.package, access, item["path"], args.max_bytes)
        scanned += 1
        total_bytes += len(data)
        scan_text(data.decode("latin-1", errors="replace"), item["path"],
                  hits, counters)
        file_records.append({
            "path": item["path"],
            "size": size,
            "category": item["category"],
            "scanned_bytes": len(data),
            "truncated": size > len(data) if size >= 0 else None,
        })
    print("[done] 扫描完成：{} 个文件，{} 字节".format(scanned, total_bytes),
          file=sys.stderr)

    hit_total = sum(counters.values())
    os.makedirs(args.evidence_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence_path = unique_path(
        args.evidence_dir, "06-storage-audit-{}".format(stamp), ".json"
    )
    result = {
        "schema": SCHEMA,
        "captured_at": iso_now(),
        "package": args.package,
        "access_mode": access,
        "data_dir": data_dir,
        "external_dir": external_dir,
        "include_external": include_external,
        "file_count": len(files),
        "scanned_files": scanned,
        "scanned_bytes": total_bytes,
        "hits": {
            "total": hit_total,
            "by_category": counters,
        },
        "samples": hits,
        "files": file_records,
        "notes": [
            "只扫描每个文件的前若干字节，可能漏掉更深位置的数据。",
            "命中模式不等于确认泄露；需结合文件用途和业务判断。",
            "未复制原始文件，证据只保存路径、大小和脱敏样例。",
        ],
    }
    write_json(evidence_path, result)

    print("============================================================")
    print("动态分析 06：应用私有存储审计")
    print("目标包：{}".format(args.package))
    print("访问方式：{}".format(access))
    print("数据目录：{}".format(data_dir))
    print("============================================================")
    print("FILE_COUNT={}".format(len(files)))
    print("SCANNED_FILES={}".format(scanned))
    print("SCANNED_BYTES={}".format(total_bytes))
    print("HITS_TOTAL={}".format(hit_total))
    for category, label in PATTERN_LABELS:
        print("HITS_{}={}".format(category.upper(), counters.get(category, 0)))
    print("------------------------------------------------------------")
    if hit_total:
        print("命中样例（值已脱敏）：")
        for category, label in PATTERN_LABELS:
            bucket = hits.get(category, [])
            if not bucket:
                continue
            print("[{}] {}".format(category, label))
            for item in bucket[:args.max_hits]:
                key = " key={}".format(item["key"]) if item["key"] else ""
                print("  {} {}".format(item["file"], key))
    print("------------------------------------------------------------")
    print("【结论】")
    if hit_total:
        print("发现 {} 处敏感落盘线索；需人工确认是否为真实凭证、"
              "是否属于目标应用。".format(hit_total))
        print("不要把“命中模式”直接写成“确认泄露”。")
    else:
        print("未发现敏感落盘线索。")
    print("说明：只扫描有限字节；未覆盖的文件、深层数据或加密数据库可能漏报。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))
    print("STORAGE_AUDIT_PASSED={}".format(str(hit_total == 0).lower()))

    if not files:
        return 1
    return 0 if hit_total == 0 else 1


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="审计 Android 应用私有存储中的敏感落盘数据。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  ./06-storage-audit.py preflight --package com.example.app\n"
            "  ./06-storage-audit.py list --package com.example.app --max-files 50\n"
            "  ./06-storage-audit.py audit --package com.example.app --max-bytes 262144\n"
            "\n退出码:\n"
            "  0 = 未发现敏感落盘线索\n"
            "  1 = 发现线索，或无法访问应用数据\n"
            "  2 = 参数、依赖或设备错误"
        ),
    )
    parser.add_argument("mode", choices=["preflight", "list", "audit", "help"],
                        help="操作")
    parser.add_argument("--package", default="", help="目标 Android 包名")
    parser.add_argument("--serial", default="", help="设备序列号")
    parser.add_argument("--max-files", type=int, default=100,
                        help="最多扫描文件数，默认 100")
    parser.add_argument("--max-bytes", type=int, default=262144,
                        help="每个文件最多读取字节数，默认 262144")
    parser.add_argument("--max-hits", type=int, default=5,
                        help="每个类别最多保留样例数，默认 5")
    parser.add_argument("--no-external", action="store_true",
                        help="不扫描 /sdcard/Android/data/<包名>")
    parser.add_argument("--evidence-dir", default="evidence",
                        help="证据目录，默认 evidence")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.mode == "help":
        parse_args(["--help"])
        return 0
    if not args.package:
        print("[FAIL] {} 需要 --package".format(args.mode), file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9_.]+", args.package):
        print("[FAIL] --package 格式不合法: {}".format(args.package), file=sys.stderr)
        return 2
    if args.max_files <= 0 or args.max_bytes <= 0 or args.max_hits < 0:
        print("[FAIL] --max-files / --max-bytes 必须为正整数，--max-hits 不能为负",
              file=sys.stderr)
        return 2
    if args.mode == "preflight":
        return cmd_preflight(args)
    if args.mode == "list":
        return cmd_list(args)
    return cmd_audit(args)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[FAIL] 用户中断", file=sys.stderr)
        sys.exit(2)
