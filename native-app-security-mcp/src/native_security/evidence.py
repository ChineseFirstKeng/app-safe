import hashlib
import json
import os
import re
import time
import zipfile
from pathlib import Path

from .artifacts import digest_file
from .errors import AnalysisError


def stable_id(prefix, value):
    return prefix + hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:32]


def private_write(path: Path, raw: bytes):
    if path.parent.is_symlink():
        raise AnalysisError("unsafe_storage_path")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def masked(value, depth=0):
    if depth > 8:
        return {"redacted": True, "reason": "depth_limit"}
    if isinstance(value, str):
        return {"redacted": True, "length": len(value)}
    if isinstance(value, dict):
        # Provider-supplied keys can contain secrets too. Keep them out of default excerpts.
        return {"type": "object", "field_count": len(value)}
    if isinstance(value, list):
        return {"type": "array", "item_count": len(value)}
    return value if isinstance(value, (bool, int, float)) or value is None else {"redacted": True}


def public_excerpt(evidence, value):
    """Expose known non-secret configuration facts while masking arbitrary content."""
    source, selector = evidence["source"], evidence["selector"]
    if source.get("producer") == "android-entry-review" and isinstance(value, dict):
        if selector == ["coverage"]:
            return {k: v for k, v in value.items() if type(v) in {bool, int} or v == "partial"}
        if len(selector) == 2 and selector[0] == "paths" and type(selector[1]) is int:
            return {k: value[k] for k in ("component", "component_kind", "entry_method", "code_path", "method_path", "api", "api_category",
                    "intent_read_api_uses", "permission_declared", "method_use_only", "parameter_provenance",
                    "guard_effectiveness", "runtime_observed", "argument_trace") if k in value}
    if source.get("producer") in {"jadx-indexer", "ghidra-indexer", "llvm-indexer"} and selector == ["coverage"] and isinstance(value, dict):
        return {k: v for k, v in value.items() if isinstance(k, str) and re.fullmatch(r"[a-z_]{1,64}", k)
                and (type(v) in {int, bool} or v in {"partial", "unknown"} if isinstance(v, (str, int, bool)) else False)}
    if source["kind"] == "inventory" and selector == ["category_counts"] and isinstance(value, dict):
        return {k: n for k, n in value.items() if k in {
            "directory", "android_manifest", "dex", "dex_named_unverified", "elf", "macho_candidate",
            "plist", "android_resources", "sqlite", "resource"} and type(n) is int and n >= 0}
    if source["kind"] == "json" and selector == ["sha256"] and isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    if source["kind"] == "text" and source.get("producer") == "aapt2 dump xmltree" and isinstance(value, str):
        from .native_config import parse_tree
        if re.match(r"\s*E: manifest\b", value):
            return {"element": "manifest"}
        roots = parse_tree("E: node\n" + value)
        for key, item in roots[0]["attrs"].items():
            if key in {"android:debuggable", "android:usesCleartextTraffic", "android:exported", "android:allowBackup"} and type(item["value"]) is bool:
                return {"attribute": key, "value": item["value"]}
            if key == "android:scheme" and isinstance(item["value"], str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]{0,63}", item["value"]):
                return {"scheme": item["value"]}
    if source["kind"] == "member" and "CFBundleURLSchemes" in selector and isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]{0,63}", value):
        return {"scheme": value}
    return masked(value)


class EvidenceBuilder:
    def __init__(self, job):
        self.job = job
        self.results = []
        self.evidence = []
        self.truncated = False
        self._result_ids = set()
        self._evidence_ids = set()

    def add(self, kind, title, source, selector, value, *, summary="", rule_id=None,
            unknowns=None, remediation=None, assertion_kind=None, verification_level=None):
        location = {"source": source, "selector": selector}
        eid = stable_id("ev_", [self.job["analysis_id"], location])
        rid = stable_id("r_", [eid, kind, rule_id, title])
        if rid in self._result_ids:
            return
        if len(self.results) >= 2000:
            self.truncated = True
            return
        self._result_ids.add(rid)
        if eid not in self._evidence_ids:
            self._evidence_ids.add(eid)
            self.evidence.append({"evidence_id": eid, "artifact_sha256": self.job["artifact_sha256"],
                                  **location, "excerpt": masked(value), "raw_value_available": True})
        self.results.append({"result_id": rid, "kind": kind, "title": title, "summary": summary,
                             "rule_id": rule_id, "assertion_kind": assertion_kind or ("inference" if kind == "finding" else "observation"),
                             "verification_level": verification_level or ("static_candidate" if kind == "finding" else "artifact_observation"),
                             "severity": "needs_review" if kind == "finding" else "informational",
                             "evidence_ids": [eid], "unknowns": unknowns or [],
                             "remediation": remediation, "untrusted_target_content": True})


def checked_source(store, job, evidence, _depth=0):
    """Check identity and read only a producer-selected source, never a client file path."""
    if evidence.get("artifact_sha256") != job["artifact_sha256"]:
        raise AnalysisError("evidence_identity_mismatch")
    source = evidence["source"]
    if source.get("producer") == "android-entry-review":
        dependencies = source.get("dependencies")
        if _depth or not isinstance(dependencies, list) or not 1 <= len(dependencies) <= 5:
            raise AnalysisError("invalid_review_dependencies")
        for dependency in dependencies:
            if dependency.get("producer") not in {"aapt2 dump xmltree", "jadx-indexer"} or "dependencies" in dependency:
                raise AnalysisError("invalid_review_dependencies")
            checked_source(store, job, {"artifact_sha256": job["artifact_sha256"], "source": dependency}, _depth=1)
    if source["kind"] == "inventory":
        return store.get(job["artifact_id"])
    if source["kind"] == "member":
        snapshot = store.artifact_path(job["artifact_id"]) / "package.bin"
        # Whole-package identity is checked by pipeline and on export. Exact member rechecked here.
        with zipfile.ZipFile(snapshot) as archive:
            info = archive.getinfo(source["path"])
            if info.file_size > 2 * 1024 * 1024:
                raise AnalysisError("evidence_source_limit_exceeded")
            raw = archive.read(info)
    elif source["kind"] in {"json", "text"}:
        relative = Path(source["path"])
        if relative.is_absolute() or any(p in {"..", "."} for p in relative.parts):
            raise AnalysisError("unsafe_evidence_path")
        base = store.root / "analyses" / job["analysis_id"]
        path = base / relative
        ancestry = [store.root, store.root / "analyses", base, path,
                    *[base / Path(*relative.parts[:i]) for i in range(1, len(relative.parts))]]
        if any(p.is_symlink() for p in ancestry):
            raise AnalysisError("unsafe_evidence_path")
        if path.stat().st_size > 20 * 1024 * 1024:
            raise AnalysisError("evidence_source_limit_exceeded")
        raw = path.read_bytes()
    else:
        raise AnalysisError("unsupported_evidence_source")
    if hashlib.sha256(raw).hexdigest() != source["sha256"]:
        raise AnalysisError("evidence_source_integrity_failed")
    if source["kind"] == "json":
        return json.loads(raw)
    if source["kind"] == "member":
        import plistlib
        return plistlib.loads(raw)
    return raw.decode("utf-8", errors="replace").splitlines()


def read_checked_evidence(store, jobs, analysis_id, evidence_id, include_raw=False):
    job = jobs.get(analysis_id)
    evidence = jobs.evidence(analysis_id, evidence_id)
    try:
        value = checked_source(store, job, evidence)
        for key in evidence["selector"]:
            value = value[key]
    except AnalysisError:
        raise
    except (OSError, KeyError, ValueError, IndexError, TypeError, zipfile.BadZipFile):
        raise AnalysisError("evidence_source_unavailable") from None
    return {**evidence, "excerpt": value if include_raw else public_excerpt(evidence, value), "source_integrity": "verified"}
