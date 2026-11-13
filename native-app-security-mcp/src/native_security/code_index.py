"""Index code carried by the APK/IPA, with bounded per-component engine work."""
import hashlib
import time
import zipfile

from .code_store import CodeStore
from .engine_runtime import checked_index, ghidra_index, jadx_index, SCRIPTS
from .errors import AnalysisError
from .evidence import private_write, stable_id
from .native_slices import slices
from .llvm_index import llvm_index
from .engine_runtime import tools_root
import os


def members(store, artifact_id):
    offset = 0
    while True:
        page = store.members(artifact_id, offset, 200)
        yield from page["items"]
        if page["next_offset"] is None:
            return
        offset = page["next_offset"]


def project_index(job, component, obj, source, units, edges):
    local = {}
    projected_edges, omitted_edges = 0, 0
    collections = [("methods", "method"), ("functions", "function"), ("strings", "string")]
    for collection, kind in collections:
        values = obj.get(collection, [])
        if not isinstance(values, list) or len(values) > 3000:
            raise AnalysisError("index_collection_over_budget")
        for i, value in enumerate(values):
            if not isinstance(value, dict) or not isinstance(value.get("identity"), str):
                raise AnalysisError("invalid_index_identity")
            if value["identity"] in local:
                raise AnalysisError("ambiguous_engine_identity")
            uid = stable_id("cu_", [job["artifact_sha256"], component, kind, value["identity"]])
            record = {"unit_id": uid, "kind": kind, "name": str(value.get("class_name", "")) + ("." if kind == "method" else "") + str(value.get("name", value["identity"])),
                      "identity": value["identity"], "artifact_sha256": job["artifact_sha256"],
                      "component": component, "source": source, "selector": [collection, i],
                      "body_available": bool(value.get("body")), "body_truncated": bool(value.get("body_truncated")),
                      "address": value.get("address"), "file_offset": value.get("file_offset"),
                      "dex_code_offset": value.get("dex_code_offset"), "untrusted_target_content": True}
            record["body_format"] = value.get("body_format", "java_like" if kind == "method" else "c_like" if kind == "function" else "not_applicable")
            if kind == "method":
                record["argument_flow_status"] = value.get("argument_flow", {}).get("status", "not_captured")
            units.append(record)
            local[value["identity"]] = uid
    raw_edges = obj.get("edges", [])
    if not isinstance(raw_edges, list) or len(raw_edges) > 12000:
        raise AnalysisError("index_reference_budget_exceeded")
    for item in raw_edges:
        if not isinstance(item, dict) or item.get("from") not in local:
            omitted_edges += 1
            continue
        edges.append({"from_id": local[item["from"]], "to_id": local.get(item.get("to")),
                      "target_identity": item.get("to"), "target_label": item.get("target_name"),
                      "site": item.get("site"), "kind": item.get("kind"),
                      "target_resolution": "same_component" if item.get("to") in local else "unresolved_or_external",
                      "component": component, "runtime_observed": False})
        projected_edges += 1
    return {"units_indexed": len(local), "edges_indexed": projected_edges, "edges_omitted_unknown_source": omitted_edges}


def index_package(store, job, directory, builder, owner, deadline):
    inputs = [m for m in members(store, job["artifact_id"]) if m["category"] in {"dex", "dex_named_unverified", "macho_candidate", "elf"}]
    units, edges, components = [], [], []
    dex_count = native_count = 0
    snapshot = store.artifact_path(job["artifact_id"]) / "package.bin"
    with zipfile.ZipFile(snapshot) as archive:
        for ordinal, entry in enumerate(inputs):
            component = {"path": entry["path"], "carrier_sha256": entry["sha256"]}
            if time.monotonic() + 3 >= deadline:
                components.append({**component, "status": "omitted_stage_budget"})
                continue
            if entry["size"] > 128 * 1024 * 1024:
                components.append({**component, "status": "omitted_carrier_size"})
                continue
            if entry["path"].endswith(("/libapp.so", "/libflutter.so", "/Flutter.framework/Flutter", "/UnityFramework.framework/UnityFramework", "/libil2cpp.so", "/libhermes.so")):
                components.append({**component, "status": "out_of_scope_framework_runtime"})
                continue
            raw = archive.read(entry["path"])
            if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                raise AnalysisError("code_carrier_integrity_failed")
            if entry["category"] in {"dex", "dex_named_unverified"}:
                if dex_count >= 4:
                    components.append({**component, "status": "omitted_dex_count_limit"})
                    continue
                dex_count += 1
                tasks = [(component, raw, "dex")]
            else:
                try:
                    parts = slices(raw)
                except AnalysisError as error:
                    components.append({**component, "status": "blocked:" + error.code})
                    continue
                tasks = [({**component, "slice_index": i, "slice_sha256": part["sha256"],
                           "slice_offset": part["offset"], "architecture": part["architecture"], "encrypted": part["encrypted"]},
                          raw[part["offset"]:part["offset"] + part["size"]], part["format"])
                         for i, part in enumerate(parts)]
                for task, part in zip(tasks, parts):
                    task[0]["cpu"] = part["cpu"]
                    task[0]["cpu_subtype"] = part.get("cpu_subtype")
                    task[0]["architecture_variant"] = part.get("architecture_variant")
            for slice_ordinal, (identity, payload, format) in enumerate(tasks):
                if format != "dex":
                    if identity["encrypted"]:
                        components.append({**identity, "status": "blocked_encrypted_slice"}); continue
                    if identity["architecture"] == "unsupported":
                        components.append({**identity, "status": "blocked_unsupported_architecture"}); continue
                    if native_count >= 4:
                        components.append({**identity, "status": "omitted_native_slice_limit"}); continue
                    native_count += 1
                if time.monotonic() + 3 >= deadline:
                    components.append({**identity, "status": "omitted_stage_budget"}); continue
                work = directory / "code" / f"c{ordinal}-s{slice_ordinal}"
                work.mkdir(mode=0o700, parents=True, exist_ok=True)
                binary = work / ("input.dex" if format == "dex" else "input.bin")
                private_write(binary, payload)
                attempts = []
                try:
                    if format == "dex":
                        path = jadx_index(binary, work, min(deadline, time.monotonic() + 60))
                        schema, producer = "jadx-index/1", "jadx-indexer"
                    else:
                        selected = os.environ.get("NATIVE_SECURITY_NATIVE_ENGINE", "auto")
                        if selected not in {"auto", "llvm", "ghidra"}:
                            raise AnalysisError("invalid_native_index_engine")
                        use_ghidra = selected == "ghidra" or selected == "auto" and (tools_root()/"ghidra/support/analyzeHeadless").is_file()
                        if use_ghidra:
                            ghidra_work = work / "ghidra"
                            ghidra_work.mkdir(mode=0o700)
                            try:
                                path = ghidra_index(binary, ghidra_work, min(deadline, time.monotonic() + 90))
                                checked_index(path, "ghidra-index/1")
                                schema, producer = "ghidra-index/1", "ghidra-indexer"
                            except AnalysisError as error:
                                if selected == "ghidra":
                                    raise
                                attempts.append({"engine": "ghidra", "status": "failed:" + error.code})
                                use_ghidra = False
                        if not use_ghidra:
                            llvm_work = work / "llvm"
                            llvm_work.mkdir(mode=0o700)
                            path = llvm_index(binary, llvm_work, min(deadline, time.monotonic() + 30))
                            schema, producer = "llvm-index/1", "llvm-indexer"
                    obj, digest = checked_index(path, schema)
                    source = {"kind": "json", "path": str(path.relative_to(directory)), "sha256": digest,
                              "producer": producer, "engine_version": obj.get("engine_version")}
                    if obj.get("java_version"):
                        source["java_version"] = obj["java_version"]
                    adapter = SCRIPTS / ("JadxIndex.java" if producer == "jadx-indexer" else "ExportNativeIndex.java")
                    if producer == "llvm-indexer":
                        from . import llvm_index as llvm_module
                        from pathlib import Path
                        adapter = Path(llvm_module.__file__)
                    source["adapter_sha256"] = hashlib.sha256(adapter.read_bytes()).hexdigest()
                    start_units, start_edges = len(units), len(edges)
                    try:
                        projection = project_index(job, identity, obj, source, units, edges)
                    except AnalysisError:
                        del units[start_units:]; del edges[start_edges:]
                        raise
                    has_units = len(units) > start_units
                    components.append({**identity, "status": "indexed_partial" if has_units else "no_code_units_recovered", "source": source,
                                       "engine_attempts": attempts, "projection": projection, "coverage": obj.get("coverage", {})})
                    title = ("Android 方法索引已建立" if format == "dex" else "原生函数索引已建立") if has_units else "代码索引引擎已执行，未恢复代码节点"
                    builder.add("observation", title,
                                source, ["coverage"], obj.get("coverage", {}),
                                summary=f"本组件索引 {len(units)-start_units} 个代码/字符串节点；静态关系为部分恢复，未观察运行行为。",
                                unknowns=obj.get("limitations", []))
                except AnalysisError as error:
                    components.append({**identity, "status": "blocked:" + error.code})
                except Exception:
                    components.append({**identity, "status": "failed_index_adapter"})
    if not CodeStore(store).publish(job["analysis_id"], owner, units, edges, components):
        return "publication_revoked"
    if not inputs:
        return "no_code_components"
    if any(c["status"] == "indexed_partial" for c in components):
        return "partial"
    if any(c["status"] == "no_code_units_recovered" for c in components):
        return "partial_no_code_units_recovered"
    return "blocked_no_component_indexed"
