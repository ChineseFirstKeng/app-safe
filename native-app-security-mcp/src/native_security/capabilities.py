import platform
import os
import shutil
from importlib.metadata import PackageNotFoundError, version

from . import __version__
from .native_config import sdk_tool
from .engine_runtime import java_home, tools_root
from .llvm_index import objdump


def health_check() -> dict:
    try:
        sdk = version("mcp")
    except PackageNotFoundError:
        sdk = None
    tools = {}
    for name in ("docker", "java", "jadx", "aapt2", "analyzeHeadless"):
        tools[name] = "located_not_executed" if (sdk_tool(name) if name == "aapt2" else shutil.which(name)) else "not_located"
    try:
        llvm = str(objdump())
    except Exception:
        llvm = None
    return {"service": "native-app-security-mcp", "version": __version__,
            "python": platform.python_version(), "mcp_sdk": sdk,
            "implemented": ["package_import", "private_snapshot", "zip_integrity", "member_inventory", "sqlite_storage", "mobsf_sync_rest_adapter",
                            "async_scan_scheduler", "bounded_configuration_checks", "evidence_query", "partial_assessment_report",
                            "bounded_code_index", "code_symbol_query", "static_reference_query", "private_code_export",
                            "android_exported_entry_method_use_review", "android_partial_ssa_argument_origins"],
            "not_implemented": ["complete_security_scan", "complete_data_flow", "ai_investigation", "ios_entry_review"],
            "code_engines": {"java": "located_not_executed" if (java_home()/"bin/java").is_file() else "missing",
                             "jadx": "located_not_executed" if (tools_root()/"jadx/lib").is_dir() else "missing",
                             "ghidra": "located_not_executed" if (tools_root()/"ghidra/support/analyzeHeadless").is_file() else "missing",
                             "llvm_objdump": "located_not_executed" if llvm else "missing"},
            "mobsf_configuration": "configured_not_verified" if os.environ.get("NATIVE_SECURITY_MOBSF_URL") and os.environ.get("NATIVE_SECURITY_MOBSF_API_KEY") else "missing",
            "tool_discovery": tools, "target_execution": False,
            "limitations": ["路径发现不证明引擎可运行；Android 工具另检查已声明及常用 SDK 路径。",
                            "配置与提供方候选不证明完整代码覆盖或漏洞可利用性。"]}
