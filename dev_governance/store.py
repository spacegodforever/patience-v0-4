"""Durable storage for dev-gate requests.

SqliteStore (default) persists to PATIENCE_DEV_GATE_DB (default patience_dev_gate.db, git-ignored).
MemoryStore is the fallback for tests and when PATIENCE_DEV_GATE_DB=":memory:".
Schema is versioned in table `meta`; MIGRATIONS[i] upgrades version i -> i+1.
"""
from __future__ import annotations
import json
import os
import sqlite3
import threading
from typing import Optional

SCHEMA_VERSION = 1
MIGRATIONS = [
    # 0 -> 1
    """CREATE TABLE IF NOT EXISTS dev_requests (
           request_id TEXT PRIMARY KEY,
           payload_hash TEXT NOT NULL,
           status TEXT NOT NULL,
           expires_at REAL NOT NULL,
           body TEXT NOT NULL)""",
]


class MemoryStore:
    def __init__(self):
        self._d: dict[str, str] = {}

    def get(self, rid: str) -> Optional[dict]:
        v = self._d.get(rid)
        return json.loads(v) if v else None

    def put(self, req: dict) -> None:
        self._d[req["request_id"]] = json.dumps(req, default=str)

    def claim(self, req: dict, from_status: str) -> bool:
        cur = self.get(req["request_id"])
        if not cur or cur["status"] != from_status:
            return False
        self.put(req)
        return True

    def schema_version(self) -> int:
        return SCHEMA_VERSION


class SqliteStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
            row = c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
            ver = int(row[0]) if row else 0
            if ver > SCHEMA_VERSION:
                raise RuntimeError(f"dev gate DB schema {ver} is newer than this code ({SCHEMA_VERSION})")
            for i in range(ver, SCHEMA_VERSION):
                c.executescript(MIGRATIONS[i])
            c.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))

    def _conn(self):
        return sqlite3.connect(self.path, timeout=30, isolation_level="DEFERRED")

    def get(self, rid: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT body, payload_hash FROM dev_requests WHERE request_id=?", (rid,)).fetchone()
        if not row:
            return None
        req = json.loads(row[0])
        if req.get("payload_hash") != row[1]:  # column and body must agree
            raise RuntimeError("dev gate record inconsistent; refusing to use it")
        return req

    def put(self, req: dict) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT OR REPLACE INTO dev_requests (request_id, payload_hash, status, expires_at, body) "
                      "VALUES (?, ?, ?, ?, ?)", (req["request_id"], req["payload_hash"], req["status"],
                                                 float(req["expires_at"]), json.dumps(req, default=str)))

    def claim(self, req: dict, from_status: str) -> bool:
        """Atomic compare-and-set on status: only one process can claim an execution."""
        with self._lock, self._conn() as c:
            cur = c.execute("UPDATE dev_requests SET status=?, body=? WHERE request_id=? AND status=? "
                            "AND payload_hash=?", (req["status"], json.dumps(req, default=str),
                                                   req["request_id"], from_status, req["payload_hash"]))
            return cur.rowcount == 1

    def schema_version(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()[0])


def default_store():
    path = os.environ.get("PATIENCE_DEV_GATE_DB", "patience_dev_gate.db")
    return MemoryStore() if path == ":memory:" else SqliteStore(path)
