"""SQLite store with forward-only, numbered migrations (PATIENCE_MEMORY_DB, default ./patience_memory.db)."""
from __future__ import annotations
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

MIGRATIONS = [
    (1, "memory records, devices, capability grants", """
CREATE TABLE memory_records (
  memory_id TEXT PRIMARY KEY, record_type TEXT NOT NULL, content TEXT NOT NULL, source TEXT NOT NULL,
  confidence REAL NOT NULL, classification TEXT NOT NULL, sharing_scope TEXT NOT NULL, project_id TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, version INTEGER NOT NULL,
  review_required INTEGER NOT NULL, expires_at TEXT, provenance TEXT NOT NULL, owner TEXT NOT NULL,
  CHECK (record_type IN ('working','project','episodic','long_term','pattern','governance')),
  CHECK (sharing_scope IN ('device','user','project','team')),
  CHECK (classification IN ('public','internal','confidential','restricted')),
  CHECK (confidence >= 0 AND confidence <= 1), CHECK (version >= 1));
CREATE TABLE devices (
  device_id TEXT PRIMARY KEY, owner TEXT NOT NULL, label TEXT, key_sha256 TEXT NOT NULL,
  registered_by TEXT NOT NULL, registered_at TEXT NOT NULL, revoked_at TEXT, revoked_by TEXT);
CREATE TABLE capability_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, capability TEXT NOT NULL, subject TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('grant','revoke')), level INTEGER,
  actor TEXT NOT NULL, at TEXT NOT NULL, reason TEXT,
  CHECK (kind = 'revoke' OR (level BETWEEN 0 AND 4)));
CREATE INDEX capability_events_key ON capability_events(capability, subject, id);
"""),
]


def db_path() -> Path:
    return Path(os.environ.get("PATIENCE_MEMORY_DB", "patience_memory.db"))


def connect(path: Path | None = None) -> sqlite3.Connection:
    p = Path(path or db_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p), isolation_level=None, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    migrate(con)
    return con


def schema_version(con) -> int:
    con.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT, applied_at TEXT)")
    return con.execute("SELECT COALESCE(MAX(version),0) FROM schema_migrations").fetchone()[0]


def migrate(con) -> int:
    cur = schema_version(con)
    known = max(v for v, _, _ in MIGRATIONS)
    if cur > known:  # fail closed on a DB written by a newer build
        raise RuntimeError(f"memory DB schema v{cur} is newer than this build (v{known})")
    for v, name, sql in MIGRATIONS:
        if v > cur:
            con.execute("BEGIN IMMEDIATE")
            try:
                for stmt in [s for s in sql.split(";") if s.strip()]:
                    con.execute(stmt)
                con.execute("INSERT INTO schema_migrations VALUES (?,?,datetime('now'))", (v, name))
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise
    return schema_version(con)


@contextmanager
def tx(con):
    """One write transaction. Callers append the audit record inside it, so a failed audit
    append rolls the write back (fail closed). A crash after the append but before COMMIT
    can still leave an audit entry for a rolled-back write; see design doc."""
    con.execute("BEGIN IMMEDIATE")
    try:
        yield con
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
