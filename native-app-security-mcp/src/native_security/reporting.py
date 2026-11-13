import base64
import hashlib
import html
import json
import re
import time
import uuid

from .artifacts import digest_file
from .errors import AnalysisError
from .evidence import checked_source, public_excerpt, private_write
from .jobs_store import TERMINAL
from .code_store import CodeStore


def label(value):
    text = html.escape(re.sub(r"[\x00-\x1f\x7f]", " ", str(value)))
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text)


def json_default(value):
    if isinstance(value, bytes):
        return {"encoding": "base64", "data": base64.b64encode(value).decode()}
    if hasattr(value, "isoformat"):
        return value.isoformat()
    raise TypeError("unsupported_evidence_value")


def build_document(store, jobs, analysis_id, include_sensitive_values=False):
    job = jobs.get(analysis_id)
    if job["state"] not in TERMINAL:
        raise AnalysisError("analysis_not_finished")
    artifact = store.get(job["artifact_id"])
    if artifact["sha256"] != job["artifact_sha256"] or digest_file(
            store.artifact_path(job["artifact_id"]) / "package.bin", time.monotonic() + 120) != job["artifact_sha256"]:
        raise AnalysisError("snapshot_integrity_failed")
    results, offset = [], 0
    while True:
        page = jobs.results(analysis_id, offset=offset, limit=200)
        results.extend(page["items"])
        if page["next_offset"] is None:
            break
        offset = page["next_offset"]
    evidence, cache = {}, {}
    for result in results:
        if not result.get("evidence_ids"):
            raise AnalysisError("invalid_result_evidence")
        for eid in result["evidence_ids"]:
            if eid in evidence:
                continue
            item = jobs.evidence(analysis_id, eid)
            key = json.dumps(item["source"], sort_keys=True)
            try:
                if key not in cache:
                    cache[key] = checked_source(store, job, item)
                if item["artifact_sha256"] != job["artifact_sha256"]:
                    raise AnalysisError("evidence_identity_mismatch")
                value = cache[key]
                for selector in item["selector"]:
                    value = value[selector]
            except AnalysisError:
                raise
            except Exception:
                raise AnalysisError("evidence_source_unavailable") from None
            evidence[eid] = {**item, "excerpt": value if include_sensitive_values else public_excerpt(item, value),
                             "source_integrity": "verified"}
    return {"schema_version": "0.5", "analysis": job, "code_index": CodeStore(store).summary(analysis_id),
            "artifact": artifact, "results": results, "evidence": list(evidence.values()),
            "contains_sensitive_values": include_sensitive_values,
            "comparison_with_rea": "not_evaluated"}


def markdown(document):
    job = document["analysis"]
    lines = ["# 原生应用静态评估阶段报告", "",
             f"- 分析：{label(job['analysis_id'])}",
             f"- 平台：{label(job['platform'])}；任务状态：{label(job['state'])}",
             f"- APK/IPA SHA-256：{job['artifact_sha256']}",
             f"- 服务：{label(job.get('service_version', '未知'))}；规则：{label(job.get('ruleset_version', '未知'))}",
             f"- 请求配置：{label(job['profile'])}；实际配置：{label(job.get('effective_profile', '未知'))}",
             f"- 完整评估：尚未完成；与 REA 的质量对比：尚未执行", "",
             "本报告包含本次实际完成的清点、配置检查、有界代码关联及可用的提供方候选。"
             "代码索引按覆盖记录判断；未执行完整数据流或动态验证，候选不等于漏洞确认。", "",
             "本机文件包含原始证据值，请按私有材料保管。" if document["contains_sensitive_values"] else
             "默认隐藏原始字符串和对象内容；可以另行导出包含原值的本机核查文件。", "",
             "## 样本与组件", "",
             f"成员：{document['artifact']['member_count']}；框架标记：{label(document['artifact']['framework_indicators'])}", "",
             "结构识别不证明签名、可安装性或安全；框架标记缺失不证明全部业务为原生。", "",
             "## 覆盖与未完成项", "", "| 阶段 | 实际状态 |", "| --- | --- |"]
    for stage, status in job["coverage"].items():
        lines.append(f"| {label(stage)} | {label(status)} |")
    if job.get("reason"):
        lines.extend(["", "任务原因：" + label(job["reason"])])
    index = document["code_index"]
    lines.extend(["", "## 代码索引", "",
                  "恢复节点：" + label(index["counts"]) + "；静态引用数：" + str(index["reference_count"]), "",
                  "关系覆盖为部分恢复；方法/函数身份绑定到组件与架构切片，未解析调用不能据此排除。", ""])
    for component in index["components"]:
        identity = component["path"]
        if "slice_index" in component:
            identity += f"；切片 {component['slice_index']}；架构 {component.get('architecture_variant') or component.get('architecture', '未知')}"
            identity += f"；CPU 子类型 {component.get('cpu_subtype')}；载体偏移 {component['slice_offset']}"
        lines.append("- " + label(identity) + "：" + label(component["status"]))
        source = component.get("source", {})
        if source:
            lines.append("  - 引擎：" + label(source.get("producer")) + "；版本：" + label(source.get("engine_version")))
            projection, coverage = component.get("projection", {}), component.get("coverage", {})
            lines.append("  - 恢复节点：" + str(projection.get("units_indexed", 0)) +
                         "；恢复正文：" + str(coverage.get("bodies_recovered", 0)) +
                         "；静态关系：" + str(projection.get("edges_indexed", 0)))
            lines.append("  - 原始索引 SHA-256：" + label(source.get("sha256")))
        for attempt in component.get("engine_attempts", []):
            lines.append("  - 前序引擎尝试：" + label(attempt.get("engine")) + "；" + label(attempt.get("status")))
    for kind, heading in [("observation", "已观察事实"), ("surface", "外部入口与攻击面"), ("finding", "待核查风险候选")]:
        lines.extend(["", "## " + heading, ""])
        items = [r for r in document["results"] if r["kind"] == kind]
        if not items:
            lines.extend(["本次没有可列出的该类结果；结合覆盖记录判断，不能据此排除问题。", ""])
        for result in items:
            lines.extend(["### " + label(result["title"]), "", label(result["summary"]), "",
                          f"- 结果：{result['result_id']}",
                          f"- 依据：{', '.join(result['evidence_ids'])}",
                          f"- 证据类型：{label(result['verification_level'])}"])
            if result.get("rule_id"):
                lines.append("- 规则：" + label(result["rule_id"]))
            for unknown in result.get("unknowns", []):
                lines.append("- 未知：" + label(unknown))
            if result.get("remediation"):
                lines.extend(["", "处理建议：" + label(result["remediation"])])
            lines.append("")
    lines.extend(["## 分析限制", ""])
    for limitation in job["limitations"]:
        lines.append("- " + label(limitation))
    lines.extend(["", "## 证据索引", ""])
    for item in document["evidence"]:
        source = item["source"]
        position = source.get("path", "安装包清点")
        if source["kind"] == "text" and item["selector"] and type(item["selector"][0]) is int:
            position += f"，输出第 {item['selector'][0] + 1} 行"
        elif item["selector"]:
            position += "，字段 /" + "/".join(str(k).replace("~", "~0").replace("/", "~1") for k in item["selector"])
        lines.extend(["### " + item["evidence_id"], "",
                      "位置：" + label(position), "",
                      "来源摘要：" + source.get("sha256", job["artifact_sha256"]), "",
                      "分析器：" + label(source.get("producer", "导入清点")) + "；版本：" + label(source.get("engine_version") or "未知"), "",
                      "```json", json.dumps(item["excerpt"], ensure_ascii=False, indent=2, default=json_default)
                      .replace("`", "\\u0060").replace("<", "\\u003c"), "```", ""])
        for dependency in source.get("dependencies", []):
            lines.append("- 依赖来源：" + label(dependency["path"]) + "；SHA-256：" + label(dependency["sha256"]))
    return "\n".join(lines)


def export_report(store, jobs, analysis_id, format="markdown", include_sensitive_values=False):
    if format not in {"markdown", "json"} or type(include_sensitive_values) is not bool:
        raise AnalysisError("invalid_report_options")
    document = build_document(store, jobs, analysis_id, include_sensitive_values)
    if format == "markdown":
        raw = markdown(document).encode()
    else:
        raw = json.dumps(document, ensure_ascii=False, indent=2, default=json_default).encode()
    base = store.root / "analyses" / analysis_id
    store._directory(store.root / "analyses")
    store._directory(base)
    store._directory(base / "reports")
    path = base / "reports" / (uuid.uuid4().hex + (".md" if format == "markdown" else ".json"))
    private_write(path, raw)
    return {"analysis_id": analysis_id, "path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw), "contains_sensitive_values": include_sensitive_values,
            "security_assessment_complete": False}
