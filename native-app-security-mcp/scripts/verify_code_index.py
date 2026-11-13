"""Real Java/D8/JADX and ObjC/Swift/ELF/LLVM verification; no target execution."""
import json
import os
import time
from pathlib import Path
from unittest.mock import patch

from build_code_fixtures import build, PROJECT
from native_security.artifacts import import_artifact
from native_security.code_store import CodeStore
from native_security.jobs_store import JobStore, TERMINAL
from native_security.reporting import export_report
from native_security.scheduler import Scheduler
from native_security.storage import Store


def wait(jobs, aid):
    deadline = time.monotonic() + 200
    while time.monotonic() < deadline:
        record = jobs.get(aid)
        if record["state"] in TERMINAL:
            return record
        time.sleep(.05)
    raise AssertionError("compiled fixture analysis did not terminate")


def one(code, aid, query, kind):
    values = code.list(aid, query, kind)["items"]
    if len(values) != 1:
        raise AssertionError(f"expected exactly one {query} ({kind}), got {len(values)}")
    return values[0]


def verify():
    packages = build()
    root = PROJECT / "runtime/code-index-verification"
    store = Store(root / "data")
    jobs, code, scheduler = JobStore(store), CodeStore(store), Scheduler(store.root)
    records = []
    try:
        with patch.dict(os.environ, {"NATIVE_SECURITY_NATIVE_ENGINE": "llvm", "NATIVE_SECURITY_MOBSF_URL": "", "NATIVE_SECURITY_MOBSF_API_KEY": ""}):
            for platform in ("apk", "ipa"):
                artifact = import_artifact(store, packages[platform])
                started = scheduler.submit(artifact["artifact_id"], 180)
                aid = started["analysis_id"]
                record = wait(jobs, aid)
                summary = code.summary(aid)
                if record["coverage"]["code_index"] != "partial":
                    raise AssertionError(json.dumps({"record": record, "index": summary}))
                if any(c["status"] != "indexed_partial" for c in summary["components"]):
                    raise AssertionError("compiled fixture has unexpectedly unindexed components: " + json.dumps(summary))
                if platform == "apk":
                    endpoint = one(code, aid, ".endpoint", "method")
                    helpers = code.list(aid, ".helper", "method")["items"]
                    if len(helpers) != 2 or len({u["identity"] for u in helpers}) != 2:
                        raise AssertionError("method overload identities are ambiguous")
                    calls = code.references(aid, endpoint["unit_id"], "outgoing")["items"]
                    if not any(e["to_id"] in {h["unit_id"] for h in helpers} for e in calls):
                        raise AssertionError("JADX static endpoint/helper relation not recovered")
                    body = code.read(aid, endpoint["unit_id"])
                    if not body["body"] or "fixture-java-literal" in body["body"]:
                        raise AssertionError("method body missing or literal not redacted")
                    raw = code.export(aid, endpoint["unit_id"])
                    if "fixture-java-literal" not in Path(raw["path"]).read_text():
                        raise AssertionError("raw method body was not preserved")
                    entry = one(code, aid, "fixture_elf_entry", "function")
                    helper = one(code, aid, "fixture_elf_helper", "function")
                else:
                    entry = one(code, aid, "_fixture_native_entry", "function")
                    helper = one(code, aid, "_fixture_native_helper", "function")
                    swift = one(code, aid, "_fixture_swift_entry", "function")
                    objc = code.list(aid, "FixtureEcho", "function")["items"]
                    if not objc:
                        raise AssertionError("ObjC compiled method symbol not indexed")
                    frontier, seen, found = [swift["unit_id"]], set(), False
                    for _ in range(4):
                        next_frontier = []
                        for uid in frontier:
                            if uid in seen:continue
                            seen.add(uid)
                            if "Helper" in code.unit(aid, uid)["name"]:found = True
                            next_frontier.extend(e["to_id"] for e in code.references(aid, uid, "outgoing")["items"] if e.get("to_id"))
                        frontier = next_frontier
                    if not found:
                        raise AssertionError("Swift C entry/helper static path not recovered")
                refs = code.references(aid, entry["unit_id"], "outgoing")["items"]
                if not any(e["to_id"] == helper["unit_id"] for e in refs):
                    raise AssertionError("native direct call reference not recovered")
                if code.read(aid, entry["unit_id"])["body_format"] != "assembly":
                    raise AssertionError("LLVM assembly must not be labelled decompiled C")
                report = export_report(store, jobs, aid)
                records.append({"platform": platform, "artifact_sha256": artifact["sha256"], "analysis_id": aid,
                                "coverage": record["coverage"], "index": summary, "report_path": report["path"]})
    finally:
        scheduler.close()
    result = {"passed": True, "scope": "compiled_java_dex_elf_objc_swift_static_index",
              "target_executed": False, "ghidra_executed": False, "mobsf_executed": False,
              "records": records}
    root.mkdir(parents=True, exist_ok=True)
    (root / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    verify()
