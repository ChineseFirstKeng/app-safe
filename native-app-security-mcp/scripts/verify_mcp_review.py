"""Verify exported-entry evidence and its code path through real MCP stdio."""
import asyncio
import json
import sys
import time
from pathlib import Path

from mcp import Client, StdioServerParameters
from build_android_review_fixtures import build, PROJECT


async def verify():
    fixtures = build()
    root = PROJECT / "runtime/mcp-review-verification"
    parameters = StdioServerParameters(command=sys.executable,
        args=["-m", "native_security", "--data-dir", str(root / "data"), "serve"], cwd=PROJECT,
        env={"NATIVE_SECURITY_NATIVE_ENGINE": "llvm", "NATIVE_SECURITY_MOBSF_URL": "", "NATIVE_SECURITY_MOBSF_API_KEY": ""})
    async with Client(parameters, read_timeout_seconds=30) as client:
        artifact = (await client.call_tool("import_artifact", {"path": fixtures["external"]})).structured_content["artifact"]
        aid = (await client.call_tool("start_analysis", {"artifact_id": artifact["artifact_id"], "wall_seconds": 120})).structured_content["analysis_id"]
        deadline = time.monotonic() + 130
        while True:
            status = (await client.call_tool("get_analysis_status", {"analysis_id": aid})).structured_content
            if status["state"] not in {"queued", "running"}:break
            assert time.monotonic() < deadline, "MCP entry review timed out"
            await asyncio.sleep(.05)
        assert status["coverage"]["entry_review"] == "partial_method_use_paths_and_ssa_arguments"
        assert status["coverage"]["data_flow"] == "partial_android_ssa_argument_origins"
        page = (await client.call_tool("list_results", {"analysis_id": aid, "kind": "surface"})).structured_content
        candidate = next(r for r in page["items"] if r["rule_id"] == "AND-ENTRY-001")
        assert candidate["assertion_kind"] == "inference" and candidate["verification_level"] == "static_ssa_origin_candidate"
        evidence = (await client.call_tool("read_evidence", {"analysis_id": aid, "evidence_id": candidate["evidence_ids"][0]})).structured_content
        public = evidence["excerpt"]
        assert public["method_use_only"] and public["parameter_provenance"] == "partial_ssa_argument_origins"
        assert public["argument_trace"]["observed_origin_kinds"] == ["intent_api_return"]
        assert len(public["code_path"]) == 2 and public["intent_read_api_uses"]
        for uid in public["code_path"]:
            result = (await client.call_tool("get_code", {"analysis_id": aid, "unit_id": uid})).structured_content
            assert result["source_integrity"] == "verified"
            assert "fixture-review-url" not in str(result)
        refs = (await client.call_tool("get_code_references", {"analysis_id": aid, "unit_id": public["code_path"][0], "direction": "outgoing"})).structured_content
        assert any(r["to_id"] == public["code_path"][1] for r in refs["items"])
        findings = (await client.call_tool("list_results", {"analysis_id": aid, "kind": "finding"})).structured_content
        assert findings["total"] == 0
        report = (await client.call_tool("export_report", {"analysis_id": aid})).structured_content
        result = {"passed": True, "analysis_id": aid, "artifact_sha256": artifact["sha256"], "code_path": public["code_path"],
                  "report_path": report["path"], "target_executed": False, "data_flow_performed": True,
                  "data_flow_scope": "partial_ssa_argument_origins", "complete_data_flow": False}
    root.mkdir(parents=True, exist_ok=True)
    (root / "summary.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":asyncio.run(verify())
