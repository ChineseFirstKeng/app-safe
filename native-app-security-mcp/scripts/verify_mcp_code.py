"""Compiled-fixture code lookup through a real SDK stdio client/server session."""
import asyncio
import json
import stat
import sys
import time
from pathlib import Path

from mcp import Client, StdioServerParameters

PROJECT = Path(__file__).resolve().parents[1]


async def verify():
    fixtures = json.loads((PROJECT / "runtime/code-fixtures/build.json").read_text())
    root = PROJECT / "runtime/mcp-code-verification"
    params = StdioServerParameters(command=sys.executable,
        args=["-m", "native_security", "--data-dir", str(root / "data"), "serve"], cwd=PROJECT,
        env={"NATIVE_SECURITY_NATIVE_ENGINE": "llvm", "NATIVE_SECURITY_MOBSF_URL": "", "NATIVE_SECURITY_MOBSF_API_KEY": ""})
    async with Client(params, read_timeout_seconds=30) as client:
        discovery = await client.list_tools()
        if len(discovery.tools) != 14:
            raise AssertionError("expected 14 implemented MCP tools")
        imported = await client.call_tool("import_artifact", {"path": fixtures["apk"]})
        artifact = imported.structured_content["artifact"]
        created = await client.call_tool("start_analysis", {"artifact_id": artifact["artifact_id"], "wall_seconds": 120})
        aid = created.structured_content["analysis_id"]
        deadline = time.monotonic() + 130
        while True:
            current = await client.call_tool("get_analysis_status", {"analysis_id": aid})
            if current.structured_content["state"] not in {"queued", "running"}:
                break
            if time.monotonic() >= deadline:
                raise AssertionError("MCP fixture analysis timeout")
            await asyncio.sleep(.05)
        found = await client.call_tool("list_code_symbols", {"analysis_id": aid, "query": ".endpoint", "kind": "method"})
        if found.structured_content.get("total") != 1:
            raise AssertionError("method symbol was not returned through MCP")
        uid = found.structured_content["items"][0]["unit_id"]
        body = await client.call_tool("get_code", {"analysis_id": aid, "unit_id": uid})
        if not body.structured_content["body"] or "fixture-java-literal" in str(body.structured_content):
            raise AssertionError("MCP method body unavailable or unredacted")
        refs = await client.call_tool("get_code_references", {"analysis_id": aid, "unit_id": uid, "direction": "outgoing"})
        if not refs.structured_content["total"]:
            raise AssertionError("MCP did not return the static using relationship")
        raw = await client.call_tool("export_code", {"analysis_id": aid, "unit_id": uid})
        exported = Path(raw.structured_content["path"])
        if "fixture-java-literal" not in exported.read_text() or stat.S_IMODE(exported.stat().st_mode) != 0o600:
            raise AssertionError("MCP private code export failed")
        report = await client.call_tool("export_report", {"analysis_id": aid})
        result = {"passed": True, "scope": "real_stdio_compiled_apk_code_queries",
                  "analysis_id": aid, "artifact_sha256": artifact["sha256"], "tool_count": len(discovery.tools),
                  "methods": found.structured_content["index"]["counts"], "method_id": uid,
                  "static_reference_count": refs.structured_content["total"],
                  "report_path": report.structured_content["path"], "target_executed": False}
    root.mkdir(parents=True, exist_ok=True)
    (root / "summary.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(verify())
