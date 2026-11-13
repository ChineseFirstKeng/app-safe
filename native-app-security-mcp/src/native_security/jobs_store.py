"""Atomic job transitions and evidence-bound result publication."""
import json
import re
import uuid
from datetime import datetime, timezone

from .errors import AnalysisError
from .storage import Store
from . import __version__

JOB_ID = re.compile(r"an_[0-9a-f]{32}\Z")
TERMINAL = {"partial", "blocked", "failed", "cancelled", "timed_out", "interrupted"}


def now():
    return datetime.now(timezone.utc).isoformat()


class JobStore:
    def __init__(self, store: Store):
        self.store = store

    @staticmethod
    def validate(analysis_id):
        if not isinstance(analysis_id, str) or not JOB_ID.fullmatch(analysis_id):
            raise AnalysisError("invalid_analysis_id")

    def create(self, artifact_id, wall_seconds=600):
        if type(wall_seconds) is not int or not 1 <= wall_seconds <= 3600:
            raise AnalysisError("invalid_time_budget")
        artifact = self.store.get(artifact_id)
        record = {"analysis_id": "an_" + uuid.uuid4().hex, "artifact_id": artifact_id,
                  "artifact_sha256": artifact["sha256"], "platform": artifact["platform"],
                  "profile": "native-security-review", "wall_seconds": wall_seconds,
                  "service_version": __version__, "ruleset_version": "native-config/0.2+android-entry/0.2",
                  "effective_profile": "package-inventory",
                  "state": "queued", "created_at": now(), "updated_at": now(),
                  "coverage": {"inventory": "complete", "configuration": "pending", "mobsf": "pending",
                               "code_index": "pending", "entry_review": "pending", "data_flow": "pending"},
                  "counts": {"observation": 0, "surface": 0, "finding": 0},
                  "security_assessment_complete": False,
                  "limitations": ["静态配置、方法使用关系和提供方候选不证明运行用途或可利用性。",
                                  "代码索引和关系恢复有界；完整数据流和 AI 调查尚未实现。",
                                  "尚未启用解析器容器隔离和内存/cgroup 限额；提供方出网隔离未验证。",
                                  "取消本机任务不保证终止 MobSF 服务端已接收的扫描。"]}
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute("SELECT COUNT(*) FROM analyses WHERE state IN ('queued','running','cancelling')").fetchone()[0]
            if active >= 16:
                raise AnalysisError("analysis_queue_full")
            db.execute("INSERT INTO analyses VALUES (?, ?, '', ?)",
                       (record["analysis_id"], "queued", json.dumps(record)))
        return record

    def get(self, analysis_id):
        self.validate(analysis_id)
        with self.store.connection() as db:
            row = db.execute("SELECT record_json FROM analyses WHERE analysis_id=?", (analysis_id,)).fetchone()
        if not row:
            raise AnalysisError("analysis_not_found")
        return json.loads(row[0])

    def claim(self, owner):
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT analysis_id,record_json FROM analyses WHERE state='queued' ORDER BY rowid LIMIT 1").fetchone()
            if not row:
                return None
            record = json.loads(row[1])
            record.update(state="running", updated_at=now())
            db.execute("UPDATE analyses SET state='running',owner=?,record_json=? WHERE analysis_id=?",
                       (owner, json.dumps(record), row[0]))
        return record

    def transition(self, analysis_id, state, reason, allowed, owner=None):
        self.validate(analysis_id)
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,owner,record_json FROM analyses WHERE analysis_id=?", (analysis_id,)).fetchone()
            if not row:
                raise AnalysisError("analysis_not_found")
            record = json.loads(row[2])
            if row[0] not in allowed or owner is not None and row[1] != owner:
                return record
            record.update(state=state, reason=reason, updated_at=now())
            if state in TERMINAL:
                record["coverage"] = {k: (state if v in {"pending", "running"} else v)
                                      for k, v in record["coverage"].items()}
            db.execute("UPDATE analyses SET state=?,record_json=? WHERE analysis_id=?",
                       (state, json.dumps(record), analysis_id))
        return record

    def recover(self):
        # Caller holds the kernel controller lock. Old workers cannot publish after revocation.
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            for analysis_id, raw in db.execute("SELECT analysis_id,record_json FROM analyses WHERE state IN ('running','cancelling')").fetchall():
                record = json.loads(raw)
                record.update(state="interrupted", reason="controller_restarted", updated_at=now())
                record["coverage"] = {k: ("interrupted" if v in {"running", "pending"} else v)
                                      for k, v in record["coverage"].items()}
                db.execute("UPDATE analyses SET state='interrupted',owner='',record_json=? WHERE analysis_id=?",
                           (json.dumps(record), analysis_id))

    def publish(self, analysis_id, owner, results, evidence, coverage, state="running", reason=None):
        if state not in {"running", "partial", "blocked"}:
            raise AnalysisError("invalid_publication_state")
        artifact_sha = self.get(analysis_id)["artifact_sha256"]
        evidence_map = {e["evidence_id"]: e for e in evidence}
        if len(evidence_map) != len(evidence) or any(e.get("artifact_sha256") != artifact_sha for e in evidence):
            raise AnalysisError("invalid_evidence_identity")
        if len({r["result_id"] for r in results}) != len(results) or any(
            r["kind"] not in {"observation", "surface", "finding"} or not r.get("evidence_ids")
            or any(e not in evidence_map for e in r["evidence_ids"]) for r in results):
            raise AnalysisError("invalid_result_evidence")
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,owner,record_json FROM analyses WHERE analysis_id=?", (analysis_id,)).fetchone()
            if not row or row[0] != "running" or row[1] != owner:
                return False
            record = json.loads(row[2])
            record.update(state=state, coverage=coverage, updated_at=now(),
                          counts={k: sum(r["kind"] == k for r in results) for k in ("observation", "surface", "finding")})
            active = ["package-inventory"]
            if any(e["source"]["kind"] in {"member", "text"} for e in evidence):
                active.append("explicit-native-configuration")
            if any(e["source"].get("producer") == "mobsf" for e in evidence):
                active.append("mobsf-recognized-projection")
            if any(e["source"].get("producer") in {"jadx-indexer", "ghidra-indexer", "llvm-indexer"} for e in evidence):
                active.append("bounded-code-index")
            if any(e["source"].get("producer") == "android-entry-review" for e in evidence):
                active.append("android-entry-method-use-review")
            record["effective_profile"] = "+".join(active)
            if reason:
                record["reason"] = reason
            for table in ("analysis_results", "analysis_evidence"):
                db.execute(f"DELETE FROM {table} WHERE analysis_id=?", (analysis_id,))
            db.executemany("INSERT INTO analysis_results VALUES (?,?,?,?)",
                           ((analysis_id, r["result_id"], r["kind"], json.dumps(r)) for r in results))
            db.executemany("INSERT INTO analysis_evidence VALUES (?,?,?)",
                           ((analysis_id, e["evidence_id"], json.dumps(e)) for e in evidence))
            db.execute("UPDATE analyses SET state=?,record_json=? WHERE analysis_id=?",
                       (state, json.dumps(record), analysis_id))
        return True

    def results(self, analysis_id, kind=None, offset=0, limit=100, revision=None):
        record = self.get(analysis_id)
        if kind is not None and kind not in {"observation", "surface", "finding"}:
            raise AnalysisError("invalid_result_kind")
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 200:
            raise AnalysisError("invalid_pagination")
        clause = "analysis_id=?" + (" AND kind=?" if kind else "")
        params = [analysis_id] + ([kind] if kind else [])
        with self.store.connection() as db:
            db.execute("BEGIN")
            record = json.loads(db.execute("SELECT record_json FROM analyses WHERE analysis_id=?", (analysis_id,)).fetchone()[0])
            if revision is not None and revision != record["updated_at"]:
                raise AnalysisError("results_changed_restart_pagination")
            total = db.execute("SELECT COUNT(*) FROM analysis_results WHERE " + clause, params).fetchone()[0]
            rows = db.execute("SELECT record_json FROM analysis_results WHERE " + clause + " ORDER BY result_id LIMIT ? OFFSET ?",
                              [*params, limit, offset]).fetchall()
        items = [json.loads(r[0]) for r in rows]
        return {"analysis_id": analysis_id, "state": record["state"], "total": total, "items": items,
                "revision": record["updated_at"], "result_set_complete": record["state"] in TERMINAL,
                "next_offset": offset + len(items) if offset + len(items) < total else None,
                "untrusted_target_content": True}

    def result(self, analysis_id, result_id):
        self.get(analysis_id)
        with self.store.connection() as db:
            row = db.execute("SELECT record_json FROM analysis_results WHERE analysis_id=? AND result_id=?",
                             (analysis_id, result_id)).fetchone()
        if not row:
            raise AnalysisError("result_not_found")
        return json.loads(row[0])

    def evidence(self, analysis_id, evidence_id):
        self.get(analysis_id)
        with self.store.connection() as db:
            row = db.execute("SELECT record_json FROM analysis_evidence WHERE analysis_id=? AND evidence_id=?",
                             (analysis_id, evidence_id)).fetchone()
        if not row:
            raise AnalysisError("evidence_not_found")
        return json.loads(row[0])
