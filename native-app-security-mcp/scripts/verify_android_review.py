"""Run compiled input/constant/private/disabled controls, including origin tamper."""
import json
import os
from pathlib import Path
from unittest.mock import patch

from build_android_review_fixtures import build, PROJECT
from verify_code_index import wait
from native_security.artifacts import import_artifact
from native_security.errors import AnalysisError
from native_security.evidence import read_checked_evidence
from native_security.jobs_store import JobStore
from native_security.reporting import export_report
from native_security.scheduler import Scheduler
from native_security.storage import Store


def verify():
    packages = build()
    root = PROJECT / "runtime/android-review-verification"
    store = Store(root / "data")
    jobs, scheduler = JobStore(store), Scheduler(store.root)
    records = []
    try:
        with patch.dict(os.environ, {"NATIVE_SECURITY_NATIVE_ENGINE": "llvm", "NATIVE_SECURITY_MOBSF_URL": "", "NATIVE_SECURITY_MOBSF_API_KEY": ""}):
            for name, package in packages.items():
                artifact = import_artifact(store, package)
                aid = scheduler.submit(artifact["artifact_id"], 120)["analysis_id"]
                record = wait(jobs, aid)
                assert record["coverage"]["entry_review"] == ("partial_method_use_paths" if name in {"private", "disabled"} else "partial_method_use_paths_and_ssa_arguments"), record
                results = jobs.results(aid)["items"]
                assert not [r for r in results if r["kind"] == "finding"], "method uses must not become confirmed risk findings"
                candidates = [r for r in results if r["rule_id"] == "AND-ENTRY-001"]
                assert len(candidates) == (0 if name in {"private", "disabled"} else 1), candidates
                for candidate in candidates:
                    assert candidate["assertion_kind"] == "inference"
                    checked = read_checked_evidence(store, jobs, aid, candidate["evidence_ids"][0])
                    excerpt = checked["excerpt"]
                    assert excerpt["api_category"] == "webview_url" and excerpt["method_use_only"]
                    assert excerpt["parameter_provenance"] == "partial_ssa_argument_origins"
                    details = excerpt["argument_trace"]
                    expected_kinds = {"external": ["intent_api_return"], "constant": ["constant"], "overwrite": ["constant"],
                                      "mixed": ["constant", "intent_api_return"], "merge": ["constant", "intent_api_return"],
                                      "unknown": ["unknown"], "non_exact": [], "internal_intent": ["intent_api_return"]}
                    assert details["observed_origin_kinds"] == expected_kinds[name], (name, details)
                    assert details["external_control"] == "not_proven"
                    if name == "mixed":assert len(details["contexts"]) == 2, details
                    if name == "mixed":assert len({c["call_chain"][0]["ir_offset"] for c in details["contexts"]}) == 2
                    if name == "overwrite":assert excerpt["intent_read_api_uses"], "overwrite control must still contain an unrelated Intent read"
                    if name == "internal_intent":assert details["contexts"][0]["origin"]["receiver"]["kind"] == "constructed_object"
                    if name == "non_exact":
                        assert "non_exact_interprocedural_dispatch" in details["unknowns"] and not details["contexts"]
                    else:assert candidate["verification_level"] == "static_ssa_origin_candidate"
                    if name == "external":
                        assert len(excerpt["code_path"]) == 2 and excerpt["intent_read_api_uses"], excerpt
                        origin = details["contexts"][0]["origin"]
                        assert origin["kind"] == "parameter_binding" and origin["parameter_index"] == 1
                        assert origin["value"]["kind"] == "intent_api_return"
                    elif name == "constant":
                        assert len(excerpt["code_path"]) == 1 and not excerpt["intent_read_api_uses"], excerpt
                report = export_report(store, jobs, aid)
                text = Path(report["path"]).read_text()
                assert "https://fixture.invalid/constant" not in text and "fixture-review-url" not in text
                tamper_rejected = False
                if candidates:
                    eid = candidates[0]["evidence_ids"][0]
                    evidence = jobs.evidence(aid, eid)
                    dependency = next(d for d in evidence["source"]["dependencies"] if d["producer"] == "jadx-indexer")
                    origin = store.root / "analyses" / aid / dependency["path"]
                    backup = origin.read_bytes()
                    try:
                        origin.write_bytes(b"{}")
                        for action in (lambda: read_checked_evidence(store, jobs, aid, eid), lambda: export_report(store, jobs, aid)):
                            try:action()
                            except AnalysisError as error:assert error.code == "evidence_source_integrity_failed"
                            else:raise AssertionError("derived evidence accepted a modified origin")
                        tamper_rejected = True
                    finally:origin.write_bytes(backup)
                records.append({"fixture": name, "analysis_id": aid, "artifact_sha256": artifact["sha256"],
                    "coverage": record["coverage"], "method_use_paths": len(candidates), "findings": 0,
                    "origin_tamper_rejected": tamper_rejected, "origin_kinds": candidates and details["observed_origin_kinds"] or [],
                    "report_path": report["path"]})
    finally:scheduler.close()
    result = {"passed": True, "target_executed": False, "mobsf_executed": False,
              "data_flow_performed": True, "data_flow_scope": "partial_ssa_argument_origins", "complete_data_flow": False, "records": records}
    (root / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({"passed": True, "fixtures": len(records), "path": str(root / "summary.json")}))


if __name__ == "__main__":verify()
