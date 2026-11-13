from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .errors import AnalysisError

ARTIFACT_ID = re.compile(r"pkg_[0-9a-f]{64}\Z")


class Store:
    def __init__(self, root: Path, initialize=True):
        self.root = Path(os.path.abspath(root.expanduser()))
        self.database = self.root / "index.sqlite3"
        if not initialize:
            if self.root.is_symlink() or self.database.is_symlink() or not self.database.is_file():
                raise AnalysisError("storage_unavailable")
            return
        self._directory(self.root)
        self._directory(self.root / "artifacts")
        self._directory(self.root / "staging")
        if self.database.is_symlink():
            raise AnalysisError("unsafe_storage_path")
        fd = os.open(self.database, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(self.database, 0o600)
        with self.connection() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] not in {0, 1, 2, 3}:
                raise AnalysisError("unsupported_storage_schema")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL UNIQUE,
                    record_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS members (
                    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                    ordinal INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (artifact_id, ordinal)
                );
                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    owner TEXT NOT NULL DEFAULT '',
                    record_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS analysis_results (
                    analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id),
                    result_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (analysis_id, result_id)
                );
                CREATE TABLE IF NOT EXISTS analysis_evidence (
                    analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id),
                    evidence_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (analysis_id, evidence_id)
                );
                CREATE TABLE IF NOT EXISTS analysis_code_units (
                    analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id),
                    unit_id TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL,
                    record_json TEXT NOT NULL, PRIMARY KEY (analysis_id, unit_id)
                );
                CREATE TABLE IF NOT EXISTS analysis_code_edges (
                    analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id),
                    ordinal INTEGER NOT NULL, from_id TEXT, to_id TEXT, record_json TEXT NOT NULL,
                    PRIMARY KEY (analysis_id, ordinal)
                );
                CREATE TABLE IF NOT EXISTS analysis_code_components (
                    analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id),
                    ordinal INTEGER NOT NULL, record_json TEXT NOT NULL, PRIMARY KEY (analysis_id, ordinal)
                );
                PRAGMA user_version = 3;
            """)

    @staticmethod
    def _directory(path: Path) -> None:
        if path.is_symlink():
            raise AnalysisError("unsafe_storage_path")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not path.is_dir() or path.stat().st_uid != os.getuid():
            raise AnalysisError("unsafe_storage_path")
        os.chmod(path, 0o700)

    @contextmanager
    def connection(self):
        if self.database.is_symlink():
            raise AnalysisError("unsafe_storage_path")
        db = sqlite3.connect(self.database, timeout=15)
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def artifact_path(self, artifact_id: str) -> Path:
        self.validate_id(artifact_id)
        return self.root / "artifacts" / artifact_id

    @staticmethod
    def validate_id(artifact_id: str) -> None:
        if not ARTIFACT_ID.fullmatch(artifact_id):
            raise AnalysisError("invalid_artifact_id")

    def put(self, record: dict, members: list[dict]) -> dict:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT record_json FROM artifacts WHERE artifact_id = ?",
                             (record["artifact_id"],)).fetchone()
            if old:
                return json.loads(old[0])
            db.execute("INSERT INTO artifacts VALUES (?, ?, ?)",
                       (record["artifact_id"], record["sha256"], json.dumps(record)))
            db.executemany("INSERT INTO members VALUES (?, ?, ?)",
                           ((record["artifact_id"], i, json.dumps(m)) for i, m in enumerate(members)))
        return record

    def get(self, artifact_id: str) -> dict:
        self.validate_id(artifact_id)
        with self.connection() as db:
            row = db.execute("SELECT record_json FROM artifacts WHERE artifact_id = ?",
                             (artifact_id,)).fetchone()
        if row is None:
            raise AnalysisError("artifact_not_found")
        return json.loads(row[0])

    def members(self, artifact_id: str, offset: int = 0, limit: int = 100) -> dict:
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 200:
            raise AnalysisError("invalid_pagination")
        record = self.get(artifact_id)
        with self.connection() as db:
            rows = db.execute("SELECT record_json FROM members WHERE artifact_id = ? "
                              "ORDER BY ordinal LIMIT ? OFFSET ?", (artifact_id, limit, offset)).fetchall()
        items = [json.loads(r[0]) for r in rows]
        end = offset + len(items)
        return {"artifact_id": artifact_id, "artifact_sha256": record["sha256"],
                "offset": offset, "total": record["member_count"], "items": items,
                "next_offset": end if end < record["member_count"] else None,
                "inventory_complete": True, "security_analysis_performed": False,
                "untrusted_target_content": True}
