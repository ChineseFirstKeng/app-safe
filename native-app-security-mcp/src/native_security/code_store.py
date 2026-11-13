"""Code metadata is queryable; raw engine bodies stay private and hash-bound."""
import hashlib
import json
import re
import uuid

from .errors import AnalysisError
from .evidence import checked_source, private_write
from .jobs_store import JobStore


def redact_code(text):
    if not isinstance(text, str):
        return None
    out, i = [], 0
    numeric = re.compile(r"(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?)[uUlLfFdD]*")
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            out.append("/* comment redacted */")
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            out.append("/* comment redacted */")
        elif text[i] in {'"', "'"}:
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            out.append('"[REDACTED]"' if quote == '"' else "'?'" )
        elif text[i].isdigit() and (i == 0 or not (text[i-1].isalnum() or text[i-1] in "_$")):
            match = numeric.match(text, i)
            if match:
                out.append("0 /* number redacted */")
                i = match.end()
            else:
                out.append(text[i]); i += 1
        else:
            out.append(text[i]); i += 1
    return "".join(out)


class CodeStore:
    def __init__(self, store):
        self.store, self.jobs = store, JobStore(store)

    def publish(self, analysis_id, owner, units, edges, components):
        job = self.jobs.get(analysis_id)
        known = {u["unit_id"] for u in units}
        if len(known) != len(units) or any(u["artifact_sha256"] != job["artifact_sha256"] for u in units):
            raise AnalysisError("code_identity_mismatch")
        if any(e["from_id"] not in known or e.get("to_id") is not None and e["to_id"] not in known for e in edges):
            raise AnalysisError("invalid_code_reference")
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,owner FROM analyses WHERE analysis_id=?", (analysis_id,)).fetchone()
            if not row or row != ("running", owner):
                return False
            for table in ("analysis_code_units", "analysis_code_edges", "analysis_code_components"):
                db.execute(f"DELETE FROM {table} WHERE analysis_id=?", (analysis_id,))
            db.executemany("INSERT INTO analysis_code_units VALUES (?,?,?,?,?)",
                           ((analysis_id, u["unit_id"], u["kind"], u["name"], json.dumps(u)) for u in units))
            db.executemany("INSERT INTO analysis_code_edges VALUES (?,?,?,?,?)",
                           ((analysis_id, i, e["from_id"], e.get("to_id"), json.dumps(e)) for i, e in enumerate(edges)))
            db.executemany("INSERT INTO analysis_code_components VALUES (?,?,?)",
                           ((analysis_id, i, json.dumps(c)) for i, c in enumerate(components)))
        return True

    def summary(self, analysis_id):
        self.jobs.get(analysis_id)
        with self.store.connection() as db:
            counts = dict(db.execute("SELECT kind,COUNT(*) FROM analysis_code_units WHERE analysis_id=? GROUP BY kind", (analysis_id,)).fetchall())
            refs = db.execute("SELECT COUNT(*) FROM analysis_code_edges WHERE analysis_id=?", (analysis_id,)).fetchone()[0]
            components = [json.loads(r[0]) for r in db.execute("SELECT record_json FROM analysis_code_components WHERE analysis_id=? ORDER BY ordinal", (analysis_id,))]
        return {"analysis_id": analysis_id, "counts": counts, "reference_count": refs,
                "components": components, "relationship_coverage": "partial", "runtime_observed": False}

    @staticmethod
    def pagination(offset, limit):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 200:
            raise AnalysisError("invalid_pagination")

    def list(self, analysis_id, query="", kind=None, offset=0, limit=100):
        self.jobs.get(analysis_id)
        self.pagination(offset, limit)
        if kind not in {None, "method", "function", "string"} or not isinstance(query, str) or len(query) > 256:
            raise AnalysisError("invalid_code_query")
        clause, params = "analysis_id=?", [analysis_id]
        if query:
            clause += " AND instr(name,?)>0"; params.append(query)
        if kind:
            clause += " AND kind=?"; params.append(kind)
        with self.store.connection() as db:
            db.execute("BEGIN")
            count = db.execute("SELECT COUNT(*) FROM analysis_code_units WHERE " + clause, params).fetchone()[0]
            rows = db.execute("SELECT record_json FROM analysis_code_units WHERE " + clause + " ORDER BY unit_id LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
        return {"analysis_id": analysis_id, "total": count, "items": [json.loads(r[0]) for r in rows],
                "next_offset": offset + len(rows) if offset + len(rows) < count else None,
                "untrusted_target_content": True, "relationship_coverage": "partial"}

    def unit(self, analysis_id, unit_id):
        self.jobs.get(analysis_id)
        with self.store.connection() as db:
            row = db.execute("SELECT record_json FROM analysis_code_units WHERE analysis_id=? AND unit_id=?", (analysis_id, unit_id)).fetchone()
        if not row:
            raise AnalysisError("code_unit_not_found")
        return json.loads(row[0])

    def raw_unit(self, analysis_id, unit_id):
        unit = self.unit(analysis_id, unit_id)
        job = self.jobs.get(analysis_id)
        try:
            obj = checked_source(self.store, job, unit)
            for key in unit["selector"]:
                obj = obj[key]
        except AnalysisError:
            raise
        except Exception:
            raise AnalysisError("code_source_unavailable") from None
        if not isinstance(obj, dict) or obj.get("identity") != unit["identity"]:
            raise AnalysisError("code_source_identity_mismatch")
        return unit, obj

    def read(self, analysis_id, unit_id):
        unit, obj = self.raw_unit(analysis_id, unit_id)
        body = obj.get("body")
        if body and unit["body_format"] == "assembly":
            body = "\n".join(line.split(";", 1)[0] for line in body.splitlines())
            if unit["component"].get("architecture") in {"x86", "x86_64"}:
                body = "\n".join(line.split("#", 1)[0] for line in body.splitlines())
        return {**unit, "body": redact_code(body),
                "body_status": "recovered_truncated" if obj.get("body_truncated") else "recovered" if obj.get("body") else "not_recovered_within_budget",
                "string_value": "[REDACTED]" if unit["kind"] == "string" else None,
                "source_integrity": "verified", "original_source": False,
                "redaction": "string_and_character_literals_comments_and_numbers",
                "limitations": ["反编译表达不等于原始源码或运行行为；符号名称仍属于不可信元数据。"]}

    def references(self, analysis_id, unit_id, direction="incoming", offset=0, limit=100):
        self.unit(analysis_id, unit_id)
        self.pagination(offset, limit)
        if direction not in {"incoming", "outgoing"}:
            raise AnalysisError("invalid_reference_direction")
        field = "to_id" if direction == "incoming" else "from_id"
        with self.store.connection() as db:
            count = db.execute(f"SELECT COUNT(*) FROM analysis_code_edges WHERE analysis_id=? AND {field}=?", (analysis_id, unit_id)).fetchone()[0]
            rows = db.execute(f"SELECT record_json FROM analysis_code_edges WHERE analysis_id=? AND {field}=? ORDER BY ordinal LIMIT ? OFFSET ?", (analysis_id, unit_id, limit, offset)).fetchall()
        return {"analysis_id": analysis_id, "unit_id": unit_id, "direction": direction, "total": count,
                "items": [json.loads(r[0]) for r in rows], "relationship_coverage": "partial",
                "next_offset": offset + len(rows) if offset + len(rows) < count else None}

    def export(self, analysis_id, unit_id):
        unit, obj = self.raw_unit(analysis_id, unit_id)
        if not obj.get("body") and unit["kind"] != "string":
            raise AnalysisError("code_body_not_recovered")
        base = self.store.root / "analyses" / analysis_id / "code-exports"
        self.store._directory(base)
        path = base / (uuid.uuid4().hex + ".json")
        raw = json.dumps({"unit": unit, "raw": obj, "contains_sensitive_values": True}, ensure_ascii=False, indent=2).encode()
        private_write(path, raw)
        return {"analysis_id": analysis_id, "unit_id": unit_id, "path": str(path),
                "sha256": hashlib.sha256(raw).hexdigest(), "contains_sensitive_values": True}
