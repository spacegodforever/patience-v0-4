"""Durable storage for dev-gate requests.

Writes are compare-and-swap on a per-row `version` (RT-01/RT-02): every update names the version it
read, so a stale writer can never overwrite a newer state (e.g. an execute claim). Rows in a
terminal state (executed / denied / expired) can never be changed. New rows are INSERTed, never
REPLACEd.

SqliteStore (default) persists to PATIENCE_DEV_GATE_DB (default patience_dev_gate.db, git-ignored).
MemoryStore is the fallback for tests and PATIENCE_DEV_GATE_DB=":memory:"; it is thread-safe.
Schema is versioned in table `meta`; MIGRATIONS[i] upgrades version i -> i+1.
"""
from __future__ import annotations
import json
import os
import sqlite3
import threading
from typing import Optional

from . import fsperm as _fsperm

SCHEMA_VERSION = 2
TERMINAL = ("executed", "denied", "expired")
MIGRATIONS = [
    # 0 -> 1
    """CREATE TABLE IF NOT EXISTS dev_requests (
           request_id TEXT PRIMARY KEY,
           payload_hash TEXT NOT NULL,
           status TEXT NOT NULL,
           expires_at REAL NOT NULL,
           body TEXT NOT NULL)""",
    # 1 -> 2: optimistic-concurrency version column
    "ALTER TABLE dev_requests ADD COLUMN version INTEGER NOT NULL DEFAULT 0",
]


def _body(req: dict) -> str:
    return json.dumps({k: v for k, v in req.items() if k != "_v"}, sort_keys=True)


class StoreConflict(Exception):
    pass


class MemoryStore:
    def __init__(self):
        self._d: dict[str, tuple[int, str]] = {}
        self._lock = threading.Lock()

    def insert(self, req: dict) -> None:
        with self._lock:
            if req["request_id"] in self._d:
                raise StoreConflict("request id exists")
            self._d[req["request_id"]] = (0, _body(req))
            req["_v"] = 0

    def get(self, rid: str) -> Optional[dict]:
        with self._lock:
            v = self._d.get(rid)
        if not v:
            return None
        req = json.loads(v[1]); req["_v"] = v[0]
        return req

    def cas(self, req: dict) -> bool:
        with self._lock:
            cur = self._d.get(req["request_id"])
            if not cur or cur[0] != req.get("_v"):
                return False
            old = json.loads(cur[1])
            if old["status"] in TERMINAL or old["payload_hash"] != req["payload_hash"]:
                return False
            self._d[req["request_id"]] = (cur[0] + 1, _body(req))
            req["_v"] = cur[0] + 1
            return True

    def list_by_status(self, status: str) -> list:
        with self._lock:
            return sorted(rid for rid, (_, b) in self._d.items() if json.loads(b)["status"] == status)

    def schema_version(self) -> int:
        return SCHEMA_VERSION


class SqliteStore:
    def __init__(self, path: str):
        self.path = path
        new = not os.path.exists(path)
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
            row = c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
            ver = int(row[0]) if row else 0
            if ver > SCHEMA_VERSION:
                c.execute("ROLLBACK")
                raise RuntimeError(f"dev gate DB schema {ver} is newer than this code ({SCHEMA_VERSION})")
            for i in range(ver, SCHEMA_VERSION):
                c.execute(MIGRATIONS[i])
            c.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            c.execute("COMMIT")
        # RT-09: tighten new AND pre-existing DB files (and WAL/SHM sidecars) to 0600
        self.permissions_fixed = _fsperm.secure_file(path)

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        return _Closing(c)

    def insert(self, req: dict) -> None:
        with self._conn() as c:
            try:
                c.execute("INSERT INTO dev_requests (request_id, payload_hash, status, expires_at, body, version) "
                          "VALUES (?, ?, ?, ?, ?, 0)", (req["request_id"], req["payload_hash"], req["status"],
                                                        float(req["expires_at"]), _body(req)))
            except sqlite3.IntegrityError:
                raise StoreConflict("request id exists")
        req["_v"] = 0

    def get(self, rid: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT body, payload_hash, status, version FROM dev_requests WHERE request_id=?",
                            (rid,)).fetchone()
        if not row:
            return None
        req = json.loads(row[0])
        if req.get("payload_hash") != row[1] or req.get("status") != row[2]:  # columns and body must agree
            raise RuntimeError("dev gate record inconsistent; refusing to use it")
        req["_v"] = int(row[3])
        return req

    def cas(self, req: dict) -> bool:
        """UPDATE only if nobody wrote since we read (version) and the row isn't terminal."""
        with self._conn() as c:
            cur = c.execute(
                "UPDATE dev_requests SET status=?, body=?, version=version+1 WHERE request_id=? AND version=? "
                "AND payload_hash=? AND status NOT IN ('executed','denied','expired')",
                (req["status"], _body(req), req["request_id"], int(req.get("_v", -1)), req["payload_hash"]))
            ok = cur.rowcount == 1
        if ok:
            req["_v"] = int(req["_v"]) + 1
        return ok

    def list_by_status(self, status: str) -> list:
        with self._conn() as c:
            return [r[0] for r in c.execute("SELECT request_id FROM dev_requests WHERE status=? "
                                            "ORDER BY request_id", (status,))]

    def schema_version(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()[0])


class _Closing:
    def __init__(self, c): self.c = c
    def __enter__(self): return self.c
    def __exit__(self, *a): self.c.close()


_SHARED: dict = {}
_SHARED_LOCK = threading.Lock()


def default_store():
    """One store per path per process (RT-01: no per-request store instances)."""
    path = os.environ.get("PATIENCE_DEV_GATE_DB", "patience_dev_gate.db")
    if path == ":memory:":
        return MemoryStore()
    with _SHARED_LOCK:
        s = _SHARED.get(path)
        if s is None or not os.path.exists(path):
            s = _SHARED[path] = SqliteStore(path)
        return s
