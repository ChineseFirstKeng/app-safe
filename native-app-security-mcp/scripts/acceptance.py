"""Run the real suite and preserve a machine-readable, non-skipping result."""
import io
import json
import os
import platform
import sys
import time
import unittest
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

project = Path(__file__).resolve().parents[1]
os.chdir(project)
output = project / "runtime" / "validation"
output.mkdir(mode=0o700, parents=True, exist_ok=True)
started = time.monotonic()
stream = io.StringIO()
suite = unittest.defaultTestLoader.discover(str(project / "tests"))
result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
summary = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "python": platform.python_version(), "mcp_sdk": version("mcp"),
    "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
    "skipped": len(result.skipped), "duration_seconds": round(time.monotonic() - started, 3),
    "passed": result.wasSuccessful() and not result.skipped,
    "scope": ["synthetic_archive_import", "real_stdio_client_server", "cli", "controlled_http_adapter",
              "real_owned_worker_lifecycle", "persisted_jobs_and_restart", "evidence_integrity_and_report_redaction",
              "explicit_native_configuration_checks", "owned_engine_helper_cleanup", "derived_review_evidence_integrity"],
    "code_index_contract_tests": ["overloads", "source_identity", "redaction", "slice_encryption", "llvm_relationship_bounds", "backend_fallback"],
    "android_entry_review_contract_tests": ["cycles", "exact_callbacks", "explicit_export", "enabled", "ambiguous_identity", "deadline", "origin_dependencies"],
    "android_ssa_origin_contract_tests": ["callsite_binding", "unknown_return", "non_exact_dispatch", "cross_dex", "phi", "internal_intent", "budgets"],
    "real_mobsf_scan_performed": False, "compiled_fixture_engine_validation_in_this_suite": False,
}
for name, value in [("acceptance.log", stream.getvalue()), ("acceptance.json", json.dumps(summary, ensure_ascii=False, indent=2))]:
    fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as target:
        target.write(value)
print(json.dumps(summary, ensure_ascii=False, indent=2))
raise SystemExit(0 if summary["passed"] else 1)
