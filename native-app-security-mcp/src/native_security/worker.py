"""Owned analysis process. Receives only validated IDs, not target-provided commands."""
import argparse
import os
import threading
import time
from pathlib import Path

from .adapters.mobsf import MobSFAdapter
from .artifacts import digest_file
from .errors import AnalysisError
from .evidence import EvidenceBuilder
from .jobs_store import JobStore
from .native_config import configuration
from .provider_projection import project_mobsf
from .storage import Store
from .code_index import index_package
from .android_review import android_entry_review


def execute(root, analysis_id, owner):
    store = Store(root)
    jobs = JobStore(store)
    job = jobs.get(analysis_id)
    if job["state"] != "running":
        return
    deadline = time.monotonic() + job["wall_seconds"]
    snapshot = store.artifact_path(job["artifact_id"]) / "package.bin"
    if digest_file(snapshot, deadline) != job["artifact_sha256"]:
        raise AnalysisError("snapshot_integrity_failed")
    directory = store.root / "analyses" / analysis_id
    store._directory(store.root / "analyses")
    store._directory(directory)
    builder = EvidenceBuilder(job)
    artifact = store.get(job["artifact_id"])
    builder.add("observation", "安装包结构与成员清点", {"kind": "inventory"}, ["category_counts"],
                artifact["category_counts"], summary="包快照身份已重新校验，成员摘要在导入阶段完整读取。")
    coverage = dict(job["coverage"])
    coverage["configuration"] = "running"
    if not jobs.publish(analysis_id, owner, builder.results, builder.evidence, coverage):
        return
    try:
        coverage["configuration"] = configuration(store, job, directory, builder, deadline)
    except AnalysisError as error:
        coverage["configuration"] = "blocked:" + error.code
    except Exception:
        coverage["configuration"] = "failed_configuration_parser"
    if artifact["framework_indicators"]:
        coverage["framework_business_semantics"] = "out_of_scope"
    coverage["code_index"] = "running"
    if not jobs.publish(analysis_id, owner, builder.results, builder.evidence, coverage):
        return
    try:
        coverage["code_index"] = index_package(store, job, directory, builder, owner,
                                               min(deadline, time.monotonic() + 180))
    except AnalysisError as error:
        coverage["code_index"] = "blocked:" + error.code
    except Exception:
        coverage["code_index"] = "failed_code_index"
    coverage["entry_review"] = "running"
    if not jobs.publish(analysis_id, owner, builder.results, builder.evidence, coverage):
        return
    try:
        coverage["entry_review"] = android_entry_review(store, job, directory, builder,
                                                        min(deadline, time.monotonic() + 15))
        if coverage["entry_review"] == "partial_method_use_paths_and_ssa_arguments":
            coverage["data_flow"] = "partial_android_ssa_argument_origins"
        elif coverage["entry_review"] == "not_implemented_ios":
            coverage["data_flow"] = "not_implemented_ios"
        elif coverage["entry_review"] == "partial_method_use_paths":
            coverage["data_flow"] = "not_run_no_entry_paths"
        else:
            coverage["data_flow"] = "not_run_ssa_or_entry_unavailable"
    except AnalysisError as error:
        coverage["entry_review"] = "blocked:" + error.code
        coverage["data_flow"] = "blocked:" + error.code
    except Exception:
        coverage["entry_review"] = "failed_entry_review"
        coverage["data_flow"] = "failed_entry_review"
    coverage["mobsf"] = "running"
    if not jobs.publish(analysis_id, owner, builder.results, builder.evidence, coverage):
        return
    reason = None
    try:
        if time.monotonic() >= deadline:
            jobs.transition(analysis_id, "timed_out", "analysis_wall_budget_exceeded", {"running"}, owner=owner)
            return
        MobSFAdapter(timeout=max(1, min(3600, deadline - time.monotonic()))).scan(
            snapshot, artifact["package_type"], artifact["sha256"], directory / "provider")
        coverage["mobsf"] = project_mobsf(job, directory, builder)
    except AnalysisError as error:
        coverage["mobsf"] = "blocked:" + error.code
        reason = error.code
    except Exception:
        coverage["mobsf"] = "failed_provider_adapter"
        reason = "provider_adapter_failed"
    if builder.truncated:
        coverage["result_projection"] = "partial_result_limit"
    if time.monotonic() >= deadline:
        jobs.transition(analysis_id, "timed_out", "analysis_wall_budget_exceeded", {"running"}, owner=owner)
        return
    # Configuration checks are a real partial result even if MobSF is unavailable.
    usable = any(r["title"] != "安装包结构与成员清点" for r in builder.results)
    jobs.publish(analysis_id, owner, builder.results, builder.evidence, coverage,
                 state="partial" if usable else "blocked", reason=reason)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--analysis-id", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    args = parser.parse_args()
    if os.getpgrp() != os.getpid() or os.getppid() != args.parent_pid:
        # The internal entry must never signal a caller's shell/process group.
        return 71

    def parent_watch():
        while True:
            if os.getppid() != args.parent_pid:
                # Also terminate tools in this isolated worker's process group.
                import signal
                os.killpg(os.getpgrp(), signal.SIGKILL)
            time.sleep(.2)

    threading.Thread(target=parent_watch, daemon=True).start()
    try:
        execute(args.data_dir, args.analysis_id, args.owner)
        return 0
    except AnalysisError as error:
        JobStore(Store(args.data_dir)).transition(args.analysis_id, "failed", error.code,
                                                {"running"}, owner=args.owner)
        return 2
    except Exception:
        JobStore(Store(args.data_dir)).transition(args.analysis_id, "failed", "worker_internal_error",
                                                {"running"}, owner=args.owner)
        return 3
    finally:
        # main's entry guard establishes that we lead this owned process group.
        # The durable job record is the result; terminate the entire group before
        # releasing its leader PID, including helpers left behind by an engine.
        import signal
        os.killpg(os.getpid(), signal.SIGKILL)


if __name__ == "__main__":
    raise SystemExit(main())
