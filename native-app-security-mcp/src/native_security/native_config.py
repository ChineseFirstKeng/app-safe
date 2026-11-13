"""Small explicit configuration checks, independent of a vulnerability scanner."""
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

from .errors import AnalysisError
from .evidence import private_write


def sdk_tool(name):
    if located := shutil.which(name):
        return Path(located)
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             str(Path.home() / "Library/Android/sdk"), str(Path.home() / "Android/Sdk")]
    for root in roots:
        if not root:
            continue
        candidates = sorted((Path(root) / "build-tools").glob("*/" + name), reverse=True)
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    return None


def run_tool(arguments, stdout_path, stderr_path, deadline, limit=4 * 1024 * 1024, env=None):
    for path in (stdout_path, stderr_path):
        private_write(path, b"")
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   close_fds=True, env=env)  # shares the owned worker process group
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise AnalysisError("configuration_tool_timeout")
                if stdout_path.stat().st_size + stderr_path.stat().st_size > limit:
                    raise AnalysisError("configuration_tool_output_limit")
                time.sleep(.02)
            if process.returncode:
                raise AnalysisError("configuration_tool_failed")
            if stdout_path.stat().st_size + stderr_path.stat().st_size > limit:
                raise AnalysisError("configuration_tool_output_limit")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def parse_tree(text):
    roots, stack = [], []
    for line_index, line in enumerate(text.splitlines()):
        match = re.match(r"^(\s*)E: ([\w:.-]+)", line)
        if match:
            indent = len(match[1])
            node = {"name": match[2], "attrs": {}, "children": [], "line": line_index}
            while stack and stack[-1][0] >= indent:
                stack.pop()
            (stack[-1][1]["children"] if stack else roots).append(node)
            stack.append((indent, node))
            continue
        match = re.match(r"^\s*A: ([^\s(=]+)(?:\(0x[0-9a-fA-F]+\))?=(.*)$", line)
        if not match or not stack:
            continue
        raw = match[2].strip()
        value = None
        quoted = re.match(r'"(?:[^"\\]|\\.)*"', raw)
        if raw in {"true", "false"}:
            value = raw == "true"
        elif re.fullmatch(r"-?\d+", raw):
            value = int(raw)
        elif quoted:
            try:
                value = json.loads(quoted[0])
            except ValueError:
                pass
        elif typed := re.fullmatch(r"\(type 0x([0-9a-fA-F]+)\)0x([0-9a-fA-F]+)", raw):
            kind, number = int(typed[1], 16), int(typed[2], 16)
            value = bool(number) if kind == 0x12 else number if kind in {0x10, 0x11} else None
        key = match[1].replace("http://schemas.android.com/apk/res/android:", "android:")
        stack[-1][1]["attrs"][key] = {"value": value, "line": line_index}
    return roots


def visit(nodes):
    for node in nodes:
        yield node
        yield from visit(node["children"])


def android_config(store, job, directory, builder, deadline):
    tool = sdk_tool("aapt2")
    if not tool:
        return "blocked_aapt2_missing"
    output = directory / "native/manifest.txt"
    engine_version = None
    try:
        version_path = directory / "native/aapt2.version"
        run_tool([str(tool), "version"], version_path, directory / "native/aapt2.version.stderr",
                 min(deadline, time.monotonic() + 5), 65536)
        version = (version_path.read_text(errors="replace") or
                   (directory / "native/aapt2.version.stderr").read_text(errors="replace")).strip()
        if version.startswith("Android Asset Packaging Tool") and len(version) < 256:
            engine_version = version
    except AnalysisError:
        pass
    run_tool([str(tool), "dump", "xmltree", "--file", "AndroidManifest.xml",
              str(store.artifact_path(job["artifact_id"]) / "package.bin")],
             output, directory / "native/aapt2.stderr", min(deadline, time.monotonic() + 30))
    raw = output.read_bytes()
    source = {"kind": "text", "path": "native/manifest.txt", "sha256": hashlib.sha256(raw).hexdigest(),
              "producer": "aapt2 dump xmltree", "engine_version": engine_version}
    nodes = parse_tree(raw.decode("utf-8", errors="replace"))
    if not nodes or nodes[0]["name"] != "manifest":
        raise AnalysisError("manifest_tree_unrecognized")
    builder.add("observation", "Android Manifest 已解码", source, [nodes[0]["line"]], "manifest",
                summary="来源为实际 aapt2 输出；本条仅涉及配置，代码覆盖另见代码索引阶段。")
    unresolved = False
    for node in visit(nodes):
        attrs = node["attrs"]
        if any(v["value"] is None for k, v in attrs.items() if k in {
            "android:debuggable", "android:usesCleartextTraffic", "android:exported", "android:allowBackup", "android:scheme"}):
            unresolved = True
        if node["name"] == "application":
            for key, rule, title in [("android:debuggable", "AND-CONFIG-001", "声明开启 Android 调试"),
                                     ("android:usesCleartextTraffic", "AND-CONFIG-002", "声明允许明文网络流量")]:
                if attrs.get(key, {}).get("value") is True:
                    builder.add("finding", title, source, [attrs[key]["line"]], True, rule_id=rule,
                                summary="明确配置命中；是否生效及实际业务影响仍需确认。",
                                unknowns=["未验证发行环境、其他网络配置、代码可达性或实际网络行为。"],
                                remediation="核对发行构建与业务必要性，移除不必要的宽松配置并复测。")
            if "android:allowBackup" in attrs:
                attr = attrs["android:allowBackup"]
                builder.add("observation", "Android 备份配置声明", source, [attr["line"]], attr["value"],
                            summary="仅记录声明；不据此确认敏感数据可以被提取。")
        if node["name"] in {"activity", "activity-alias", "service", "receiver", "provider"}:
            if attrs.get("android:exported", {}).get("value") is True:
                builder.add("surface", "显式导出的 Android 组件", source,
                            [attrs["android:exported"]["line"]], True,
                            summary="需结合权限、输入处理及业务鉴权检查；导出本身不是漏洞。",
                            unknowns=["尚未追踪组件处理方法及系统实际访问限制。"])
        if node["name"] == "data" and "android:scheme" in attrs:
            attr = attrs["android:scheme"]
            builder.add("surface", "Android 深链 scheme 声明", source, [attr["line"]], attr["value"],
                        summary="声明不证明 App Links 验证成功，也不证明回调可被利用。")
    return "partial_manifest_values_unresolved" if unresolved else "complete_within_explicit_manifest_checks"


def ios_config(store, job, directory, builder, deadline):
    snapshot = store.artifact_path(job["artifact_id"]) / "package.bin"
    checked, omitted = 0, 0
    with zipfile.ZipFile(snapshot) as archive:
        for info in archive.infolist():
            if not info.filename.endswith("/Info.plist"):
                continue
            if time.monotonic() >= deadline:
                raise AnalysisError("configuration_time_budget_exceeded")
            if checked >= 200 or info.file_size > 2 * 1024 * 1024:
                omitted += 1
                continue
            raw = archive.read(info)
            try:
                obj = plistlib.loads(raw)
            except Exception:
                omitted += 1
                continue
            if not isinstance(obj, dict):
                omitted += 1
                continue
            checked += 1
            source = {"kind": "member", "path": info.filename, "sha256": hashlib.sha256(raw).hexdigest(),
                      "producer": "plistlib", "engine_version": "python_stdlib"}
            builder.add("observation", "iOS 组件配置已解析", source, [], obj,
                        summary="检查 Info.plist 配置；未恢复该组件的原生函数或运行行为。")
            parent = info.filename.rsplit("/", 2)[-2]
            if not parent.endswith((".app", ".appex")):
                # Framework/resource-bundle plist keys do not configure the host application's ATS.
                continue
            ats = obj.get("NSAppTransportSecurity")
            if "NSAppTransportSecurity" in obj and not isinstance(ats, dict):
                omitted += 1
            if isinstance(ats, dict):
                for key, rule in [("NSAllowsArbitraryLoads", "IOS-CONFIG-001"),
                                  ("NSAllowsArbitraryLoadsInWebContent", "IOS-CONFIG-002")]:
                    if key in ats and type(ats[key]) is not bool:
                        omitted += 1
                    if ats.get(key) is True:
                        builder.add("finding", "iOS ATS 宽松配置声明", source,
                                    ["NSAppTransportSecurity", key], True, rule_id=rule,
                                    summary="配置候选；需结合系统版本、其他 ATS 键及网络栈判断效果。",
                                    unknowns=["未确认应用实际使用明文连接或暴露敏感数据。"],
                                    remediation="核查网络需求，收紧不必要的全局放行并验证业务兼容。")
            if parent.endswith(".app") and obj.get("UIFileSharingEnabled") is True:
                builder.add("surface", "iOS 文件共享配置开启", source, ["UIFileSharingEnabled"], True,
                            summary="是否涉及敏感 Documents 数据需检查实际写入内容。")
            url_types = obj.get("CFBundleURLTypes", [])
            if not isinstance(url_types, list):
                omitted += 1
            if isinstance(url_types, list):
                for i, item in enumerate(url_types[:100]):
                    schemes = item.get("CFBundleURLSchemes", []) if isinstance(item, dict) else []
                    if not isinstance(item, dict) or not isinstance(schemes, list):
                        omitted += 1
                    if isinstance(schemes, list):
                        for j, scheme in enumerate(schemes[:100]):
                            if isinstance(scheme, str):
                                builder.add("surface", "iOS URL scheme 声明", source,
                                            ["CFBundleURLTypes", i, "CFBundleURLSchemes", j], scheme,
                                            summary="仅记录入口声明；参数处理及来源验证未追踪。")
                            else:
                                omitted += 1
                        omitted += max(0, len(schemes) - 100)
                omitted += max(0, len(url_types) - 100)
    return "partial_configuration_items_omitted" if omitted else "complete_within_explicit_plist_checks" if checked else "blocked_no_readable_plist"


def configuration(store, job, directory, builder, deadline):
    if job["platform"] == "android":
        return android_config(store, job, directory, builder, deadline)
    return ios_config(store, job, directory, builder, deadline)
