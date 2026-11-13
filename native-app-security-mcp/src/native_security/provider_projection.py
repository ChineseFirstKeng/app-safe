"""Explicit MobSF report shapes. Findings remain unverified provider candidates."""
import hashlib
import re


def project_mobsf(job, directory, builder):
    import json
    path = directory / "provider/report.json"
    raw = path.read_bytes()
    report = json.loads(raw)
    if report.get("sha256") != job["artifact_sha256"]:
        from .errors import AnalysisError
        raise AnalysisError("mobsf_report_identity_mismatch_or_unavailable")
    source = {"kind": "json", "path": "provider/report.json", "sha256": hashlib.sha256(raw).hexdigest(),
              "producer": "mobsf", "engine_version": None}
    builder.add("observation", "收到身份匹配的 MobSF 报告", source, ["sha256"], report["sha256"],
                summary="提供方报告的包摘要匹配；引擎版本与覆盖尚未独立验证。")
    families = []
    code = report.get("code_analysis")
    if isinstance(code, dict) and isinstance(code.get("findings"), dict):
        families.append((["code_analysis", "findings"], list(code["findings"].items())))
    binary = report.get("binary_analysis")
    if isinstance(binary, dict) and isinstance(binary.get("findings"), dict):
        families.append((["binary_analysis", "findings"], list(binary["findings"].items())))
    manifest = report.get("manifest_analysis")
    if isinstance(manifest, dict) and isinstance(manifest.get("manifest_findings"), list):
        families.append((["manifest_analysis", "manifest_findings"], list(enumerate(manifest["manifest_findings"]))))
    emitted, omitted = 0, 0
    for prefix, items in families:
        for key, value in items:
            if not isinstance(value, dict):
                omitted += 1
                continue
            if emitted >= 500:
                omitted += 1
                continue
            raw_rule = str(value.get("rule", key))
            rule = raw_rule if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,99}", raw_rule) else hashlib.sha256(raw_rule.encode()).hexdigest()[:16]
            metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
            severity = metadata.get("severity", value.get("severity"))
            informational = severity in {"info", "informational", "secure"}
            builder.add("observation" if informational else "finding",
                        "MobSF 规则信息" if informational else "MobSF 安全规则候选", source, [*prefix, key], value,
                        rule_id="MOBSF:" + rule,
                        summary="提供方规则命中，尚未独立复核原始代码、用途或可达性。",
                        unknowns=["提供方证据定位、规则适用条件和实际可利用性待复核。"],
                        remediation="先核对原始提供方证据和业务上下文，再制定适用修复与复测。")
            emitted += 1
    return "partial_provider_projection" if omitted else "recognized_shapes_only" if families else "no_recognized_finding_sections"
