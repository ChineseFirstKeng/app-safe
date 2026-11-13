#!/usr/bin/env python3
#
# 07-component-runtime.py —— 通用动态分析：导出组件与深链运行时可达性
#
# 说明：本脚本可独立运行，不依赖其他脚本，也不假设特定应用或样本。
#
# 用途：
#   把静态分析里的"Manifest 声明了 exported / 深链"推进到运行时：
#     - 外部 Intent 能否解析到目标包？
#     - deeplink 能否启动目标 Activity？
#     - 显式 Activity / Service / Broadcast / ContentProvider 是否可达？
#
#   重要：入口可达本身不是漏洞。本脚本只证明"Android 把 Intent 送到了
#   哪个组件"，不证明业务层接受了参数，也不证明 OAuth / 授权被绕过。
#   因此证据里始终输出 EXPLOIT_PROVEN=false。
#
#   本脚本会向设备发送 Intent，可能改变前台页面或触发组件逻辑。
#   默认使用明显无效的测试参数；不要传入真实授权码或生产数据。
#
# 子命令：
#   preflight        只读检查 adb、设备、包安装状态、deeplink 解析结果
#   deeplink         发送 VIEW / BROWSABLE Intent，验证深链入口
#   activity         向指定 Activity 发送显式 Intent
#   service          向指定 Service 发送启动请求
#   broadcast        向指定 Receiver 发送广播
#   provider         对指定 ContentProvider 执行只读 query，统计行数
#   help             显示帮助
#
# 用法：
#   ./07-component-runtime.py preflight --component com.example/.MainActivity
#   ./07-component-runtime.py deeplink --uri 'myapp://callback?code=lab-invalid'
#   ./07-component-runtime.py activity --component com.example/.MainActivity
#   ./07-component-runtime.py provider --uri content://com.example.provider/items
#   ./07-component-runtime.py --help
#
#   错误输入示例：
#     缺少 --uri / --component，或 component 格式不是 包名/.Activity → exit 2。
#
# 输出：
#   RESOLVED_COMPONENT、AM_EXIT_CODE、ENTRY_REACHABLE、EXPLOIT_PROVEN=false、
#   【结论】、证据 JSON 路径。
#
# 参数：
#   --package <包名>          可选；未提供时从 component 或 deeplink 推断。
#                             格式：Android 包名。示例：com.example.app
#   --component <包/组件>      activity / service / broadcast 必填；
#                              deeplink 可选。格式：包名/.组件名。
#                              示例：com.example/.MainActivity
#   --uri <URI>               deeplink 必填；provider 必填（content://）。
#                              示例：myapp://callback?code=lab-invalid
#   --intent-action <ACTION>  可选。示例：android.intent.action.VIEW
#   --category <CATEGORY>     可选。示例：android.intent.category.BROWSABLE
#   --extra <key=value>       可选，可重复。示例：--extra token=lab-invalid
#   --projection <列名>       可选。示例：--projection _id,title
#   --show-data               可选布尔开关；provider 输出脱敏行内容。
#   --serial <序列号>         可选。示例：ABC123
#   --evidence-dir <目录>     可选，默认 evidence。示例：./evidence
#   --dry-run                 可选布尔开关；只打印命令。
#   -h, --help                显示帮助。
#
# 依赖：
#   python3、adb。
#
# 退出码：
#   0 = 入口可达 / preflight 通过
#   1 = 入口不可达，或 preflight 未通过
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

SCHEMA = "app-safe/component-runtime/v1"
COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.]+$")
SENSITIVE_EXTRA_RE = re.compile(
    r"(?i)(?:token|password|passwd|secret|signature|sig|authorization|cookie|api[_-]?key)"
)


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
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output


def redact_text(text):
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
    text = re.sub(r"(?i)(\b(?:set-cookie|cookie)\s*:\s*)[^;]*", r"\1<REDACTED>", text)
    text = re.sub(
        r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)\S+",
        r"\1<REDACTED>", text,
    )
    return text


def redact_command(command):
    redacted = []
    index = 0
    while index < len(command):
        argument = command[index]
        if argument == "-e" and index + 2 < len(command):
            key = command[index + 1]
            value = command[index + 2]
            redacted += [
                "-e",
                key,
                "<REDACTED>" if SENSITIVE_EXTRA_RE.search(key) else redact_text(value),
            ]
            index += 3
            continue
        redacted.append(redact_text(argument))
        index += 1
    return redacted


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


def package_from_component(component):
    if "/" not in component:
        return ""
    return component.split("/", 1)[0]


def parse_resolved_component(output):
    for line in reversed(output.splitlines()):
        line = line.strip()
        if COMPONENT_RE.match(line):
            return line
    match = re.search(r"([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)", output)
    return match.group(1) if match else ""


def parse_activity(output):
    match = re.search(r"^\s*Activity:\s*(\S+)", output, re.M)
    return match.group(1) if match else ""


def parse_cmp(output):
    match = re.search(r"cmp=([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)", output)
    return match.group(1) if match else ""


def status_ok(output):
    if re.search(r"^\s*Error:", output, re.M):
        return False
    if re.search(r"^\s*Status:\s*ok\s*$", output, re.M):
        return True
    return bool(re.search(r"^\s*Activity:", output, re.M))


def build_extras(extras):
    args = []
    for item in extras:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        args += ["-e", key, value]
    return args


def write_evidence(args, mode, info, evidence_path):
    os.makedirs(args.evidence_dir, exist_ok=True)
    data = {
        "schema": SCHEMA,
        "captured_at": iso_now(),
        "mode": mode,
        "package": info.get("package", ""),
        "component": info.get("component", ""),
        "uri_redacted": redact_text(info.get("uri", "")),
        "resolve_command": redact_command(info.get("resolve_command", [])),
        "resolve_output": redact_text(info.get("resolve_output", "")),
        "command": redact_command(info.get("command", [])),
        "exit_code": info.get("exit_code"),
        "status_ok": info.get("status_ok"),
        "activity": info.get("activity", ""),
        "entry_reachable": info.get("entry_reachable"),
        "exploit_proven": False,
        "dry_run": info.get("dry_run", False),
        "notes": info.get("notes", []),
    }
    write_json(evidence_path, data)


def resolve_deeplink(adb, uri, intent_action, category):
    command = adb + [
        "shell", "cmd", "package", "resolve-activity", "--brief",
        "-a", intent_action, "-c", category, "-d", uri,
    ]
    rc, output = run_command(command, timeout=20)
    return command, rc, output, parse_resolved_component(output)


def cmd_preflight(args):
    if not need_adb():
        return 2
    adb = adb_base(args.serial)
    rc, out = run_command(adb + ["get-state"], timeout=8)
    if rc != 0 or out.strip() != "device":
        print("[FAIL] 没有在线 Android 设备: {}".format(out.strip()), file=sys.stderr)
        return 1

    package = args.package
    if not package and args.component:
        package = package_from_component(args.component)
    if not package and args.uri and not args.uri.startswith("content://"):
        _cmd, _rc, _out, component = resolve_deeplink(
            adb, args.uri,
            args.intent_action or "android.intent.action.VIEW",
            args.category or "android.intent.category.BROWSABLE",
        )
        package = package_from_component(component)

    installed = False
    if package:
        rc_pkg, out_pkg = run_command(
            adb + ["shell", "pm", "path", package], timeout=8
        )
        installed = rc_pkg == 0 and out_pkg.strip().startswith("package:")

    print("ADB_STATE=device")
    print("PACKAGE_NAME={}".format(package))
    print("PACKAGE_INSTALLED={}".format(str(installed).lower()))
    print("COMPONENT={}".format(args.component))

    if args.uri and not args.uri.startswith("content://"):
        intent_action = args.intent_action or "android.intent.action.VIEW"
        category = args.category or "android.intent.category.BROWSABLE"
        _cmd, res_rc, res_out, component = resolve_deeplink(
            adb, args.uri, intent_action, category
        )
        print("DEEPLINK_RESOLVE_EXIT_CODE={}".format(res_rc))
        print("DEEPLINK_RESOLVED_COMPONENT={}".format(component or args.component))
        print("DEEPLINK_OUTPUT={}".format(redact_text(res_out.strip())))
        if not component and not args.component:
            print("PREFLIGHT_PASSED=false")
            return 1

    if args.component and not COMPONENT_RE.match(args.component):
        print("[FAIL] --component 格式应为 包名/.Activity: {}".format(args.component),
              file=sys.stderr)
        print("PREFLIGHT_PASSED=false")
        return 2

    if package and not installed:
        print("[FAIL] 目标包未安装: {}".format(package), file=sys.stderr)
        print("PREFLIGHT_PASSED=false")
        return 1

    print("PREFLIGHT_PASSED=true")
    return 0


def cmd_deeplink(args):
    if not need_adb():
        return 2
    if not args.uri:
        print("[FAIL] deeplink 需要 --uri", file=sys.stderr)
        return 2
    if "://" not in args.uri:
        print("[FAIL] --uri 需要包含 scheme，例如 myapp://...", file=sys.stderr)
        return 2

    adb = adb_base(args.serial)
    rc, out = run_command(adb + ["get-state"], timeout=8)
    if rc != 0 or out.strip() != "device":
        print("[FAIL] 没有在线 Android 设备: {}".format(out.strip()), file=sys.stderr)
        return 1

    intent_action = args.intent_action or "android.intent.action.VIEW"
    category = args.category or "android.intent.category.BROWSABLE"

    resolve_command, _resolve_rc, resolve_output, resolved_component = resolve_deeplink(
        adb, args.uri, intent_action, category
    )
    component = args.component or resolved_component
    package = args.package or package_from_component(component)

    command = adb + ["shell", "am", "start", "-W"]
    if args.component:
        command += ["-n", args.component]
    command += ["-a", intent_action, "-c", category, "-d", args.uri]
    command += build_extras(args.extra)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(args.evidence_dir, exist_ok=True)
    evidence_path = unique_path(
        args.evidence_dir, "07-component-runtime-deeplink-{}".format(timestamp), ".json"
    )

    info = {
        "package": package,
        "component": component,
        "uri": args.uri,
        "resolve_command": resolve_command,
        "resolve_output": resolve_output,
        "command": command,
        "dry_run": args.dry_run,
        "notes": ["入口可达不等于漏洞；EXPLOIT_PROVEN 始终为 false。"],
    }

    print("============================================================")
    print("动态分析 07：深链入口可达性")
    print("目标包：{}".format(package or "（未解析）"))
    print("URI：{}".format(redact_text(args.uri)))
    print("============================================================")
    print("RESOLVE_COMMAND={}".format(" ".join(redact_command(resolve_command))))
    print("RESOLVE_EXIT_CODE={}".format(_resolve_rc))
    print("RESOLVED_COMPONENT={}".format(resolved_component))
    print("AM_COMMAND={}".format(" ".join(redact_command(command))))

    if args.dry_run:
        info["entry_reachable"] = False
        info["notes"].append("dry-run：未发送 Intent")
        write_evidence(args, "deeplink", info, evidence_path)
        print("DRY_RUN=true")
        print("ENTRY_REACHABLE=false")
        print("EXPLOIT_PROVEN=false")
        print("EVIDENCE_JSON={}".format(evidence_path))
        return 0

    am_rc, am_output = run_command(command, timeout=30)
    activity = parse_activity(am_output) or parse_cmp(am_output) or resolved_component
    ok = status_ok(am_output)
    reachable = bool(
        am_rc == 0
        and ok
        and activity
        and (not package or activity.startswith(package + "/"))
    )

    info.update({
        "exit_code": am_rc,
        "status_ok": ok,
        "activity": activity,
        "entry_reachable": reachable,
    })
    write_evidence(args, "deeplink", info, evidence_path)

    print("AM_EXIT_CODE={}".format(am_rc))
    print("AM_STATUS_OK={}".format(str(ok).lower()))
    print("FOREGROUND_ACTIVITY={}".format(activity))
    print("ENTRY_REACHABLE={}".format(str(reachable).lower()))
    print("EXPLOIT_PROVEN=false")
    print("------------------------------------------------------------")
    print("【结论】")
    if reachable:
        print("外部 Intent 已到达目标组件；这不证明业务层接受参数，"
              "也不证明 OAuth / 授权被绕过。")
    else:
        print("未证明外部 Intent 到达目标组件；检查应用是否安装、"
              "URI / component 是否正确、系统是否有默认处理者。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))
    print("------------------------------------------------------------")
    print(redact_text(am_output.strip()) or "（am start 无输出）")

    return 0 if reachable else 1


def _run_component_action(args, mode):
    if not need_adb():
        return 2
    if not args.component:
        print("[FAIL] {} 需要 --component".format(mode), file=sys.stderr)
        return 2
    if not COMPONENT_RE.match(args.component):
        print("[FAIL] --component 格式应为 包名/.Activity: {}".format(args.component),
              file=sys.stderr)
        return 2

    adb = adb_base(args.serial)
    rc, out = run_command(adb + ["get-state"], timeout=8)
    if rc != 0 or out.strip() != "device":
        print("[FAIL] 没有在线 Android 设备: {}".format(out.strip()), file=sys.stderr)
        return 1

    package = args.package or package_from_component(args.component)
    if mode == "activity":
        command = adb + ["shell", "am", "start", "-W", "-n", args.component]
        if args.intent_action:
            command += ["-a", args.intent_action]
        if args.category:
            command += ["-c", args.category]
        if args.uri:
            command += ["-d", args.uri]
    elif mode == "service":
        command = adb + ["shell", "am", "startservice", "-n", args.component]
        if args.intent_action:
            command += ["-a", args.intent_action]
    else:
        command = adb + ["shell", "am", "broadcast", "-n", args.component]
        if args.intent_action:
            command += ["-a", args.intent_action]
    command += build_extras(args.extra)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(args.evidence_dir, exist_ok=True)
    evidence_path = unique_path(
        args.evidence_dir,
        "07-component-runtime-{}-{}".format(mode, timestamp), ".json",
    )
    info = {
        "package": package,
        "component": args.component,
        "uri": args.uri,
        "command": command,
        "dry_run": args.dry_run,
        "notes": ["入口可达不等于漏洞；EXPLOIT_PROVEN 始终为 false。"],
    }

    print("============================================================")
    print("动态分析 07：{} 入口可达性".format(mode))
    print("目标包：{}".format(package))
    print("组件：{}".format(args.component))
    print("============================================================")
    print("AM_COMMAND={}".format(" ".join(redact_command(command))))

    if args.dry_run:
        info["entry_reachable"] = False
        info["notes"].append("dry-run：未发送 Intent")
        write_evidence(args, mode, info, evidence_path)
        print("DRY_RUN=true")
        print("ENTRY_REACHABLE=false")
        print("EXPLOIT_PROVEN=false")
        print("EVIDENCE_JSON={}".format(evidence_path))
        return 0

    am_rc, am_output = run_command(command, timeout=30)
    ok = status_ok(am_output)
    if mode == "broadcast":
        reachable = am_rc == 0 and not re.search(r"^\s*Error:", am_output, re.M)
    elif mode == "service":
        reachable = am_rc == 0 and not re.search(
            r"(?i)Error:|Unable to start service|does not exist", am_output
        )
    else:
        activity = parse_activity(am_output) or parse_cmp(am_output) or args.component
        reachable = am_rc == 0 and ok and bool(
            activity and activity.startswith(package + "/")
        )

    info.update({
        "exit_code": am_rc,
        "status_ok": ok,
        "activity": parse_activity(am_output) or parse_cmp(am_output),
        "entry_reachable": reachable,
    })
    write_evidence(args, mode, info, evidence_path)

    print("AM_EXIT_CODE={}".format(am_rc))
    print("AM_STATUS_OK={}".format(str(ok).lower()))
    print("FOREGROUND_ACTIVITY={}".format(parse_activity(am_output) or parse_cmp(am_output)))
    print("ENTRY_REACHABLE={}".format(str(reachable).lower()))
    print("EXPLOIT_PROVEN=false")
    print("------------------------------------------------------------")
    print("【结论】")
    if reachable:
        print("外部 Intent 已到达目标组件；这不证明组件内部逻辑接受了参数，"
              "也不证明存在漏洞。")
    else:
        print("未证明目标组件可达；检查组件名、权限保护、exported 状态"
              "和系统版本限制。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))
    print("------------------------------------------------------------")
    print(redact_text(am_output.strip()) or "（命令无输出）")

    return 0 if reachable else 1


def cmd_provider(args):
    if not need_adb():
        return 2
    if not args.uri or not args.uri.startswith("content://"):
        print("[FAIL] provider 需要 content:// 形式的 --uri", file=sys.stderr)
        return 2

    adb = adb_base(args.serial)
    rc, out = run_command(adb + ["get-state"], timeout=8)
    if rc != 0 or out.strip() != "device":
        print("[FAIL] 没有在线 Android 设备: {}".format(out.strip()), file=sys.stderr)
        return 1

    command = adb + ["shell", "content", "query", "--uri", args.uri]
    if args.projection:
        command += ["--projection", args.projection]

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(args.evidence_dir, exist_ok=True)
    evidence_path = unique_path(
        args.evidence_dir, "07-component-runtime-provider-{}".format(timestamp), ".json"
    )
    info = {
        "package": args.package,
        "component": args.uri,
        "uri": args.uri,
        "command": command,
        "dry_run": args.dry_run,
        "notes": ["provider 查询为只读；默认不打印行内容。"],
    }

    print("============================================================")
    print("动态分析 07：ContentProvider 运行时可达性")
    print("URI：{}".format(redact_text(args.uri)))
    print("============================================================")
    print("CONTENT_COMMAND={}".format(" ".join(redact_command(command))))

    if args.dry_run:
        info["entry_reachable"] = False
        write_evidence(args, "provider", info, evidence_path)
        print("DRY_RUN=true")
        print("ENTRY_REACHABLE=false")
        print("EVIDENCE_JSON={}".format(evidence_path))
        return 0

    print("[loading] 正在查询 ContentProvider...", file=sys.stderr)
    query_rc, query_output = run_command(command, timeout=20)
    lowered = query_output.lower()
    reachable = bool(
        query_rc == 0
        and "unable to find provider" not in lowered
        and not re.search(r"^\s*Error:", query_output, re.M)
    )
    row_lines = [line for line in query_output.splitlines() if line.startswith("Row:")]
    print("[done] 查询完成：{} 行".format(len(row_lines)), file=sys.stderr)

    info.update({
        "exit_code": query_rc,
        "status_ok": reachable,
        "entry_reachable": reachable,
        "row_count": len(row_lines),
    })
    write_evidence(args, "provider", info, evidence_path)

    print("CONTENT_EXIT_CODE={}".format(query_rc))
    print("ROW_COUNT={}".format(len(row_lines)))
    print("ENTRY_REACHABLE={}".format(str(reachable).lower()))
    print("EXPLOIT_PROVEN=false")
    print("------------------------------------------------------------")
    print("【结论】")
    if reachable:
        print("ContentProvider 可被当前调用方查询；这不证明返回数据敏感，"
              "也不证明越权成立。")
    else:
        print("未证明 ContentProvider 可查询；检查 authority、权限保护"
              "和 URI 是否正确。")
    print("------------------------------------------------------------")
    print("EVIDENCE_JSON={}".format(evidence_path))
    if args.show_data:
        print("------------------------------------------------------------")
        for line in row_lines[:5]:
            print(redact_text(line))
    else:
        print("（未打印行内容；使用 --show-data 可查看脱敏后的前 5 行）")

    return 0 if reachable else 1


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="验证导出组件 / 深链 / Provider 的运行时可达性。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  ./07-component-runtime.py preflight --component com.example/.MainActivity\n"
            "  ./07-component-runtime.py deeplink --uri 'myapp://callback?code=lab-invalid'\n"
            "  ./07-component-runtime.py activity --component com.example/.MainActivity\n"
            "  ./07-component-runtime.py provider --uri content://com.example.provider/items\n"
            "\n退出码:\n"
            "  0 = 入口可达 / preflight 通过\n"
            "  1 = 入口不可达或 preflight 未通过\n"
            "  2 = 参数、依赖或设备错误"
        ),
    )
    parser.add_argument("mode",
                        choices=["preflight", "deeplink", "activity", "service",
                                 "broadcast", "provider", "help"],
                        help="操作")
    parser.add_argument("--package", default="", help="目标 Android 包名")
    parser.add_argument("--component", default="", help="组件，例如 pkg/.Activity")
    parser.add_argument("--uri", default="", help="deeplink URI 或 content:// URI")
    parser.add_argument("--intent-action", default="", help="Intent action")
    parser.add_argument("--category", default="", help="Intent category")
    parser.add_argument("--extra", action="append", default=[],
                        help="附加 extra，格式 key=value，可重复")
    parser.add_argument("--projection", default="", help="provider query 的 projection")
    parser.add_argument("--show-data", action="store_true",
                        help="provider 输出脱敏后的前 5 行")
    parser.add_argument("--serial", default="", help="设备序列号")
    parser.add_argument("--evidence-dir", default="evidence", help="证据目录，默认 evidence")
    parser.add_argument("--dry-run", action="store_true", help="只打印命令，不发送 Intent")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.mode == "help":
        parse_args(["--help"])
        return 0
    if args.mode == "preflight":
        return cmd_preflight(args)
    if args.mode == "deeplink":
        return cmd_deeplink(args)
    if args.mode == "activity":
        return _run_component_action(args, "activity")
    if args.mode == "service":
        return _run_component_action(args, "service")
    if args.mode == "broadcast":
        return _run_component_action(args, "broadcast")
    return cmd_provider(args)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[FAIL] 用户中断", file=sys.stderr)
        sys.exit(2)
