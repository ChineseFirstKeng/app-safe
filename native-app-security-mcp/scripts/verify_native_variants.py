"""Check real stripped/fat/Extension carriers and truthful backend limitations."""
import argparse
import json
import os
from pathlib import Path
from unittest.mock import patch

from build_native_variants import build_variants, PROJECT
from verify_code_index import wait
from native_security.artifacts import import_artifact
from native_security.code_store import CodeStore
from native_security.jobs_store import JobStore
from native_security.reporting import export_report
from native_security.scheduler import Scheduler
from native_security.storage import Store


def verify(engine="llvm", rebuild=True):
    packages = build_variants() if rebuild else json.loads((PROJECT / "runtime/native-variants/build.json").read_text())
    root = PROJECT / ("runtime/native-variants-verification-" + engine)
    store = Store(root / "data")
    jobs, code, scheduler = JobStore(store), CodeStore(store), Scheduler(store.root)
    records = []
    try:
        with patch.dict(os.environ, {"NATIVE_SECURITY_NATIVE_ENGINE": engine, "NATIVE_SECURITY_MOBSF_URL": "", "NATIVE_SECURITY_MOBSF_API_KEY": ""}):
            for name in ("apk", "ipa", "fat_extension_ipa"):
                artifact = import_artifact(store, packages[name])
                aid = scheduler.submit(artifact["artifact_id"], 360)["analysis_id"]
                record = wait(jobs, aid)
                summary = code.summary(aid)
                components = summary["components"]
                assert components, "native components not discovered"
                assert all(c["status"] in {"indexed_partial", "no_code_units_recovered"} for c in components), components
                assert all(c["source"]["producer"] == engine + "-indexer" for c in components)
                symbols = code.list(aid, kind="function", limit=200)["items"]
                if name == "fat_extension_ipa":
                    app = [c for c in components if c["path"].endswith("/FatApp")]
                    assert len(app) == 2 and len({c["cpu_subtype"] for c in app}) == 2
                    assert len({c["slice_offset"] for c in app}) == 2 and len({c["slice_sha256"] for c in app}) == 2
                    entry_names = {"entry"} if engine == "ghidra" else {"_main", "main"}
                    mains = [u for u in symbols if u["name"] in entry_names and u["component"]["path"].endswith("/FatApp")]
                    assert len(mains) == 2 and len({u["unit_id"] for u in mains}) == 2, "fat slices conflated"
                    by_address = {}
                    for unit in symbols:
                        if unit["component"]["path"].endswith("/FatApp"):
                            by_address.setdefault(unit["identity"], []).append(unit)
                    shared = [group for group in by_address.values() if len({u["component"]["slice_index"] for u in group}) == 2]
                    assert shared and all(len({u["unit_id"] for u in group}) == len(group) for group in shared), "equal addresses across slices must retain distinct code identities"
                    assert any(".appex/" in c["path"] and c["projection"]["units_indexed"] > 0 for c in components)
                    assert any("FixtureExtension" in u["name"] for u in symbols), "Extension method missing"
                elif engine == "llvm":
                    assert not symbols and all(c["status"] == "no_code_units_recovered" for c in components)
                    assert record["coverage"]["code_index"] == "partial_no_code_units_recovered"
                else:
                    assert symbols, "Ghidra failed to recover stripped functions"
                    body_units = [u for u in symbols if u["body_available"]]
                    assert body_units, "no real pseudocode recovered"
                    assert all(code.read(aid, u["unit_id"])["body_format"] == "c_like" for u in body_units)
                    assert not any("fixture_private_helper" in u["name"] for u in symbols), "private symbol was not stripped"
                    strings = code.list(aid, kind="string", limit=200)["items"]
                    matched = [u for u in strings if "fixture-private-native-literal" in code.raw_unit(aid, u["unit_id"])[1].get("value", "")]
                    assert matched, "known stripped string not recovered"
                    assert any(code.references(aid, u["unit_id"], "incoming")["total"] for u in matched), "known string has no recovered data reference"
                report = export_report(store, jobs, aid)
                if name == "fat_extension_ipa":
                    report_text = Path(report["path"]).read_text()
                    assert "CPU 子类型 0" in report_text and "CPU 子类型 2147483650" in report_text
                records.append({"fixture": name, "artifact_sha256": artifact["sha256"], "analysis_id": aid,
                    "coverage": record["coverage"], "index": summary, "report_path": report["path"]})
    finally:
        scheduler.close()
    result = {"passed": True, "engine": engine, "target_executed": False, "mobsf_executed": False,
              "installability_verified": False, "scope": "stripped_native_fat_arm64_arm64e_extension_static_carriers", "records": records}
    (root / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({"passed": True, "engine": engine, "records": len(records), "path": str(root / "summary.json")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=["llvm", "ghidra"], default="llvm")
    parser.add_argument("--no-rebuild", action="store_true")
    args = parser.parse_args()
    verify(args.engine, not args.no_rebuild)
