"""Durable single-use store for permit nonces (SQLite, 0600, append-only by trigger).

`burn()` is an atomic INSERT on a PRIMARY KEY, so two gateways/processes sharing the file cannot both
accept one permit. Any database error raises NonceStoreError and the gateway rejects (fail closed).
UPDATE and DELETE are blocked by triggers (guards against accidents and casual edits; the file owner
can still change the file, see docs). Rows are never pruned: a permit expires in minutes, rows are tiny.
"""
from __future__ import annotations
import os
import sqlite3
import stat
from typing import Optional


class NonceStoreError(Exception):
    pass


class NonceStore:
    def __init__(self, path: str):
        if not path or path == ":memory:":
            raise NonceStoreError("a file path is required (durability is part of the control)")
        self.path = path
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            os.close(fd)
            os.chmod(path, 0o600)
            with self._conn() as c:
                c.execute("CREATE TABLE IF NOT EXISTS used_permits (jti TEXT PRIMARY KEY, exp INTEGER NOT NULL, "
                          "used_at REAL NOT NULL, agent TEXT NOT NULL, request_id TEXT NOT NULL)")
                for op in ("UPDATE", "DELETE"):
                    c.execute(f"CREATE TRIGGER IF NOT EXISTS used_permits_no_{op.lower()} BEFORE {op} ON used_permits "
                              f"BEGIN SELECT RAISE(ABORT, 'used_permits is append-only'); END")
        except (OSError, sqlite3.Error) as e:
            raise NonceStoreError(f"nonce store unavailable ({type(e).__name__})") from None
        self.secure()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        return _Closing(c)

    def secure(self) -> None:
        for suffix in ("", "-wal", "-shm", "-journal"):
            p = self.path + suffix
            try:
                if stat.S_IMODE(os.stat(p).st_mode) & 0o077:
                    os.chmod(p, 0o600)
            except OSError:
                pass

    def burn(self, jti: str, exp: int, now: float, agent: str, request_id: str) -> bool:
        """True if this is the first use of `jti`; False if it was already used. Raises on DB error."""
        try:
            with self._conn() as c:
                c.execute("INSERT INTO used_permits (jti, exp, used_at, agent, request_id) VALUES (?,?,?,?,?)",
                          (jti, int(exp), float(now), agent[:128], request_id[:128]))
            self.secure()
            return True
        except sqlite3.IntegrityError:
            return False
        except sqlite3.Error as e:
            raise NonceStoreError(f"nonce store error ({type(e).__name__})") from None

    def count(self) -> int:
        try:
            with self._conn() as c:
                return c.execute("SELECT COUNT(*) FROM used_permits").fetchone()[0]
        except sqlite3.Error as e:
            raise NonceStoreError(f"nonce store error ({type(e).__name__})") from None


class _Closing:
    def __init__(self, c): self.c = c
    def __enter__(self): return self.c
    def __exit__(self, *a): self.c.close()
