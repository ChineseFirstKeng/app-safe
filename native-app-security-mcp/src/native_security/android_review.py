"""Explicit exported entry -> bounded method-use paths; no taint/vulnerability claim."""
import hashlib
import json
import time
from pathlib import Path

from .errors import AnalysisError
from .evidence import private_write, checked_source
from .native_config import parse_tree
from .android_origins import argument_trace

CALLBACKS = {
    "activity": ("onCreate(Landroid/os/Bundle;)V", "onNewIntent(Landroid/content/Intent;)V"),
    "service": ("onStartCommand(Landroid/content/Intent;II)I", "onBind(Landroid/content/Intent;)Landroid/os/IBinder;"),
    "receiver": ("onReceive(Landroid/content/Context;Landroid/content/Intent;)V",),
    "provider": ("query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
                 "insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;",
                 "update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I",
                 "delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I",
                 "openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;"),
}
SINKS = {
    "android.webkit.WebView.loadUrl(Ljava/lang/String;)V": "webview_url",
    "android.webkit.WebView.loadUrl(Ljava/lang/String;Ljava/util/Map;)V": "webview_url",
    "android.webkit.WebView.loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V": "webview_content",
    "android.webkit.WebView.addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V": "javascript_bridge",
    "java.lang.System.load(Ljava/lang/String;)V": "native_library_load",
    "java.lang.System.loadLibrary(Ljava/lang/String;)V": "native_library_load",
    "dalvik.system.DexClassLoader.<init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V": "dex_loader",
}
for signature in ("Ljava/lang/String;", "[Ljava/lang/String;", "Ljava/lang/String;[Ljava/lang/String;",
                  "[Ljava/lang/String;[Ljava/lang/String;", "Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;",
                  "[Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;"):
    SINKS["java.lang.Runtime.exec(" + signature + ")Ljava/lang/Process;"] = "process_execution"
INPUT_APIS = {
    "android.content.Intent.getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
    "android.content.Intent.getData()Landroid/net/Uri;",
    "android.content.Intent.getDataString()Ljava/lang/String;",
    "android.content.Intent.getExtras()Landroid/os/Bundle;",
}
API_LABELS = {"webview_url": "WebView URL 加载", "webview_content": "WebView 内容加载",
              "javascript_bridge": "JavaScript 桥接注册", "native_library_load": "本机库加载",
              "dex_loader": "DEX 代码加载", "process_execution": "进程命令执行"}


def attr(node, name, default=None):
    return node.get("attrs", {}).get(name, {}).get("value", default)


def qualify(name, package):
    if not isinstance(name, str) or not name or len(name) > 512 or not isinstance(package, str):
        return None
    return package + name if name.startswith(".") else name if "." in name else package + "." + name


def trace(manifest, units, edges, deadline):
    roots = parse_tree(manifest)
    if len(roots) != 1 or roots[0]["name"] != "manifest":
        raise AnalysisError("review_manifest_unrecognized")
    root = roots[0]
    package = attr(root, "package")
    by_identity, adjacency = {}, {}
    unit_by_id = {u["unit_id"]: u for u in units}
    for unit in units:
        by_identity.setdefault(unit["identity"], []).append(unit)
    for edge in edges:
        adjacency.setdefault(edge["from_id"], []).append(edge)
    paths, entries, reasons, expanded, callbacks = [], 0, [], 0, 0
    truncated = False
    for app in [c for c in root["children"] if c["name"] == "application"]:
        if attr(app, "android:enabled", True) is False:
            continue
        for node in app["children"]:
            if node["name"] == "activity-alias" and attr(node, "android:exported") is True:
                reasons.append("activity_alias_not_traced")
                continue
            kind = node["name"]
            if kind not in CALLBACKS or attr(node, "android:exported") is not True or attr(node, "android:enabled", True) is False:
                continue
            entries += 1
            if entries > 32:
                truncated = True; break
            name = qualify(attr(node, "android:targetActivity" if node["name"] == "activity-alias" else "android:name"), package)
            if not name:
                reasons.append("component_name_unresolved"); continue
            found = False
            permission = attr(node, "android:permission", attr(app, "android:permission", ""))
            for callback in CALLBACKS[kind]:
                matched = by_identity.get(name + "." + callback, [])
                if len(matched) != 1:
                    if len(matched) > 1:reasons.append("ambiguous_callback_identity")
                    continue
                found = True
                callbacks += 1
                start = matched[0]
                queue, seen, scheduled, cursor = [(start["unit_id"], [start["unit_id"]])], set(), {start["unit_id"]}, 0
                while cursor < len(queue):
                    if time.monotonic() >= deadline or expanded >= 2000 or len(paths) >= 50:
                        truncated = True; break
                    uid, chain = queue[cursor]; cursor += 1
                    if uid in seen:continue
                    seen.add(uid); expanded += 1
                    links = adjacency.get(uid, [])
                    for edge in links:
                        target = edge.get("target_identity")
                        if target in SINKS:
                            if any(len(unit_by_id[u]["identity"]) > 2048 for u in chain):
                                reasons.append("method_identity_metadata_budget"); continue
                            inputs = sorted({e.get("target_identity") for member in chain for e in adjacency.get(member, [])
                                             if e.get("target_identity") in INPUT_APIS})
                            paths.append({"component": name, "component_kind": node["name"], "entry_method": start["identity"],
                                "code_path": chain, "method_path": [unit_by_id[u]["identity"] for u in chain],
                                "api": target, "api_category": SINKS[target],
                                "intent_read_api_uses": inputs, "permission_declared": None if permission is None else bool(permission),
                                "method_use_only": True, "parameter_provenance": "not_analyzed",
                                "guard_effectiveness": "not_analyzed", "runtime_observed": False,
                                "manifest_line": node["line"]})
                            if len(paths) >= 50:truncated = True; break
                        if edge.get("to_id") and edge["to_id"] not in scheduled:
                            if len(chain) < 7:
                                scheduled.add(edge["to_id"])
                                queue.append((edge["to_id"], [*chain, edge["to_id"]]))
                            else:reasons.append("path_depth_limit")
                    if truncated:break
                if truncated:break
            if not found:reasons.append("declared_callback_not_indexed_or_inherited")
            if truncated:break
    return {"schema": "android-entry-review/1", "paths": paths, "coverage": {
        "explicit_exported_entries_seen": entries, "callbacks_indexed": callbacks, "nodes_expanded": expanded,
        "paths_found": len(paths), "truncated": truncated, "relationship_coverage": "partial",
        "data_flow_performed": False, "runtime_observed": False}, "gaps": sorted(set(reasons)),
        "limitations": ["Only explicit exported=true, enabled components and listed exact callbacks are considered.",
            "Same-component JADX using edges are candidate method-use paths, not instruction-level control flow.",
            "Implicit export, activity aliases, inherited callbacks, cross-DEX dispatch, reflection, JNI and dynamic dispatch remain incomplete.",
            "Intent API use does not prove attacker input reaches the API argument; permissions and guards are not evaluated.",
            "No path is a vulnerability confirmation; no path does not establish safety."]}


def android_entry_review(store, job, directory, builder, deadline):
    if job["platform"] != "android":
        return "not_implemented_ios"
    manifest = directory / "native/manifest.txt"
    if not manifest.is_file():
        return "blocked_manifest_unavailable"
    with store.connection() as db:
        units = [json.loads(r[0]) for r in db.execute("SELECT record_json FROM analysis_code_units WHERE analysis_id=? AND kind='method' LIMIT 8001", (job["analysis_id"],))]
        edges = [json.loads(r[0]) for r in db.execute("SELECT e.record_json FROM analysis_code_edges e JOIN analysis_code_units u ON u.analysis_id=e.analysis_id AND u.unit_id=e.from_id WHERE e.analysis_id=? AND u.kind='method' LIMIT 48001", (job["analysis_id"],))]
    if not units:
        return "blocked_method_index_unavailable"
    if len(units) > 8000 or len(edges) > 48000:
        return "blocked_review_graph_budget"
    manifest_sources = [e["source"] for e in builder.evidence if e["source"].get("producer") == "aapt2 dump xmltree"]
    if not manifest_sources:
        return "blocked_manifest_provenance_unavailable"
    manifest_source = manifest_sources[0]
    manifest_text = "\n".join(checked_source(store, job, {"artifact_sha256": job["artifact_sha256"], "source": manifest_source}))
    sources = {json.dumps(u["source"], sort_keys=True): u["source"] for u in units}
    dependencies = [manifest_source, *sources.values()]
    if len(dependencies) > 5:
        return "blocked_review_dependency_budget"
    indexes = {key: checked_source(store, job, {"artifact_sha256": job["artifact_sha256"], "source": dependency})
               for key, dependency in sources.items()}
    result = trace(manifest_text, units, edges, deadline)
    flows = {}
    for unit in units:
        data = indexes[json.dumps(unit["source"], sort_keys=True)]
        selector = unit["selector"]
        method = data[selector[0]][selector[1]]
        if method.get("identity") != unit["identity"]:
            raise AnalysisError("review_method_identity_mismatch")
        flows[unit["unit_id"]] = method.get("argument_flow", {})
    unit_by_id = {u["unit_id"]: u for u in units}
    attempted = resolved = 0
    for item in result["paths"]:
        details = argument_trace(item, unit_by_id, flows, deadline)
        item["argument_trace"] = details
        if details["status"] != "unavailable":
            attempted += 1
            item["parameter_provenance"] = "partial_ssa_argument_origins"
        if details["contexts"]:resolved += 1
    result["coverage"].update({"argument_paths_attempted": attempted, "argument_paths_with_contexts": resolved,
                               "data_flow_performed": attempted > 0, "complete_data_flow": False})
    path = directory / "android-review/index.json"
    raw = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()
    if len(raw) > 8 * 1024 * 1024:
        return "blocked_review_output_budget"
    private_write(path, raw)
    source = {"kind": "json", "path": "android-review/index.json", "sha256": hashlib.sha256(raw).hexdigest(),
              "producer": "android-entry-review", "engine_version": "0.2", "dependencies": dependencies,
              "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "origin_adapter_sha256": hashlib.sha256(Path(__file__).with_name("android_origins.py").read_bytes()).hexdigest()}
    builder.add("observation", "Android 导出入口代码关联检查已执行", source, ["coverage"], result["coverage"],
                summary=f"恢复 {len(result['paths'])} 条待核查的方法使用路径；其中 {resolved} 条包含部分 SSA 参数来源，未执行完整数据流或运行验证。",
                unknowns=[*result["limitations"], *result["gaps"]])
    for index, item in enumerate(result["paths"]):
        details = item.get("argument_trace", {})
        kinds = details.get("observed_origin_kinds", [])
        if kinds == ["constant"]:
            origin_summary = "已观察上下文中的目标参数来自常量；不据此证明所有路径安全。"
        elif kinds == ["intent_api_return"]:
            origin_summary = "已恢复参数与 Intent 读取返回值的部分 SSA 定义关系；外部可控和权限保护仍未证明。"
        elif "constant" in kinds and "intent_api_return" in kinds:
            origin_summary = "在调用上下文或分支合流中观察到常量和 Intent 返回值两类来源；分支可达性未验证。"
        elif details.get("contexts"):
            origin_summary = "已检查的参数包含未知或其他来源，尚不能确认其外部控制与保护条件。"
        else:
            origin_summary = "未恢复可核查的 SSA 参数上下文，方法使用关系仍待复核。"
        builder.add("surface", "导出入口关联敏感 API 使用路径", source, ["paths", index], item,
                    assertion_kind="inference", verification_level="static_ssa_origin_candidate" if item.get("argument_trace", {}).get("contexts") else "static_method_use_candidate",
                    rule_id="AND-ENTRY-001", summary=f"{item['component']} 的已索引回调存在通向{API_LABELS[item['api_category']]} API 的静态方法使用路径。{origin_summary}",
                    unknowns=["方法使用关系不证明控制流可达；未验证入口权限、鉴权与参数校验。",
                              "参数来源仅按已恢复 SSA 与有界精确调用绑定；未证明运行路径、外部控制或校验有效性。常量参数也列为攻击面，不据此认定漏洞。"],
                    remediation="核对入口访问权限、身份校验及敏感 API 的参数来源；有外部输入时验证允许范围与失败分支。")
    if attempted:return "partial_method_use_paths_and_ssa_arguments"
    return "partial_method_use_paths_ssa_unavailable" if result["paths"] else "partial_method_use_paths"
