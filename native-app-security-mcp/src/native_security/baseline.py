import json
import os
import uuid
from datetime import datetime, timezone

from .adapters.mobsf import MobSFAdapter
from .errors import AnalysisError
from .storage import Store


def run_baseline(store: Store, artifact_id: str, timeout: int = 600) -> dict:
    """Synchronous provider-only entry; the scheduler runs the unified task pipeline."""
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise AnalysisError("invalid_baseline_timeout")
    artifact = store.get(artifact_id)
    base = store.root / "baselines"
    store._directory(base)
    run_id = "base_" + uuid.uuid4().hex
    directory = base / run_id
    directory.mkdir(mode=0o700)
    result = {"run_id": run_id, "artifact_id": artifact_id,
              "artifact_sha256": artifact["sha256"], "created_at": datetime.now(timezone.utc).isoformat(),
              "security_assessment_complete": False,
              "limitations": ["此开发入口仅执行 MobSF 接口；统一阶段评估使用 analyze 或 start_analysis。",
                              "提供方报告尚未独立复核，不表示完整评估。"]}
    try:
        receipt = MobSFAdapter(timeout=timeout).scan(
            store.artifact_path(artifact_id) / "package.bin", artifact["package_type"],
            artifact["sha256"], directory / "mobsf")
        result.update(ok=True, state="baseline_report_received", provider_receipt=receipt)
    except AnalysisError as error:
        result.update(ok=False, state="blocked" if error.code in {
            "mobsf_not_configured", "invalid_mobsf_configuration", "mobsf_authentication_failed",
            "mobsf_connection_failed", "mobsf_async_mode_not_supported"} else "failed", error=error.code)
    path = directory / "receipt.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
        output.flush()
        os.fsync(output.fileno())
    return {**result, "receipt_path": str(path)}
