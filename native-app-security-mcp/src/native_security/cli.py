from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .artifacts import import_artifact
from .capabilities import health_check
from .errors import AnalysisError
from .storage import Store


def default_root() -> Path:
    return Path(os.environ.get("NATIVE_APP_SECURITY_DATA_DIR", "~/.native-app-security")).expanduser()


def main() -> int:
    parser = argparse.ArgumentParser(description="Native mobile static analysis — implemented stages only")
    parser.add_argument("--data-dir", type=Path, default=default_root())
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("health")
    imp = commands.add_parser("import")
    imp.add_argument("path")
    members = commands.add_parser("members")
    members.add_argument("artifact_id")
    members.add_argument("--offset", type=int, default=0)
    members.add_argument("--limit", type=int, default=100)
    baseline = commands.add_parser("baseline", help="运行已配置的本机 MobSF 同步接口，不生成完整评估")
    baseline.add_argument("artifact_id")
    baseline.add_argument("--timeout", type=int, default=600)
    analyze = commands.add_parser("analyze", help="提交并等待阶段评估；Ctrl-C 终止本机工作进程")
    analyze.add_argument("artifact_id")
    analyze.add_argument("--timeout", type=int, default=600)
    status = commands.add_parser("status")
    status.add_argument("analysis_id")
    results = commands.add_parser("results")
    results.add_argument("analysis_id")
    results.add_argument("--kind", choices=["observation", "surface", "finding"])
    results.add_argument("--offset", type=int, default=0)
    results.add_argument("--limit", type=int, default=100)
    export = commands.add_parser("export")
    export.add_argument("analysis_id")
    export.add_argument("--format", choices=["markdown", "json"], default="markdown")
    export.add_argument("--include-sensitive-values", action="store_true")
    symbols = commands.add_parser("symbols", help="查询已恢复的方法或函数索引")
    symbols.add_argument("analysis_id")
    symbols.add_argument("--query", default="")
    symbols.add_argument("--kind", choices=["method", "function", "string"])
    symbols.add_argument("--offset", type=int, default=0)
    symbols.add_argument("--limit", type=int, default=100)
    for command in ("code", "references", "export-code"):
        sub = commands.add_parser(command)
        sub.add_argument("analysis_id")
        sub.add_argument("unit_id")
        if command == "references":
            sub.add_argument("--direction", choices=["incoming", "outgoing"], default="incoming")
            sub.add_argument("--offset", type=int, default=0)
            sub.add_argument("--limit", type=int, default=100)
    commands.add_parser("serve")
    args = parser.parse_args()
    try:
        if args.command == "health":
            result = health_check()
        elif args.command == "serve":
            from .server import serve
            serve(args.data_dir)
            return 0
        else:
            store = Store(args.data_dir)
            if args.command == "import":
                result = import_artifact(store, args.path)
            elif args.command == "baseline":
                from .baseline import run_baseline
                result = run_baseline(store, args.artifact_id, args.timeout)
            elif args.command in {"symbols", "code", "references", "export-code"}:
                from .code_store import CodeStore
                code = CodeStore(store)
                if args.command == "symbols":
                    result = {**code.list(args.analysis_id, args.query, args.kind, args.offset, args.limit),
                              "index": code.summary(args.analysis_id)}
                elif args.command == "code":
                    result = code.read(args.analysis_id, args.unit_id)
                elif args.command == "references":
                    result = code.references(args.analysis_id, args.unit_id, args.direction, args.offset, args.limit)
                else:
                    result = code.export(args.analysis_id, args.unit_id)
            elif args.command in {"analyze", "status", "results", "export"}:
                from .jobs_store import JobStore, TERMINAL
                jobs = JobStore(store)
                if args.command == "analyze":
                    from .scheduler import Scheduler
                    scheduler = Scheduler(args.data_dir)
                    try:
                        result = scheduler.submit(args.artifact_id, args.timeout)
                        while result["state"] not in TERMINAL:
                            time.sleep(.05)
                            result = jobs.get(result["analysis_id"])
                    finally:
                        scheduler.close()
                elif args.command == "status":
                    result = jobs.get(args.analysis_id)
                elif args.command == "results":
                    result = jobs.results(args.analysis_id, args.kind, args.offset, args.limit)
                else:
                    from .reporting import export_report
                    result = export_report(store, jobs, args.analysis_id, args.format, args.include_sensitive_values)
            else:
                result = store.members(args.artifact_id, args.offset, args.limit)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if result.get("ok") is False or result.get("state") in {"blocked", "failed", "timed_out", "interrupted", "cancelled"} else 0
    except AnalysisError as error:
        print(json.dumps({"error": error.code}), file=sys.stderr)
        return 2
    except Exception:
        print(json.dumps({"error": "internal_error"}), file=sys.stderr)
        return 3
