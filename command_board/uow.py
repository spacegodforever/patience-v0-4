"""Unit of work: during a mutating board request every DB method shares one connection
whose commit is deferred until the route wrapper has appended the audit record.
If the audit append fails, the whole request is rolled back (fail closed)."""
from __future__ import annotations
import contextvars
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

_UOW: contextvars.ContextVar = contextvars.ContextVar("board_uow", default=None)
_SUSPEND: contextvars.ContextVar = contextvars.ContextVar("board_uow_suspend", default=False)


def db_path() -> Path:
    return Path(os.environ.get("PATIENCE_BOARD_DB", "patience_board.db"))


class _Deferred:
    """sqlite3.Connection proxy: `with conn:` and conn.commit() do not commit."""
    def __init__(self, real):
        self._real = real

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def commit(self):
        pass

    def close(self):
        pass

    def __getattr__(self, name):
        return getattr(self._real, name)

    def __setattr__(self, name, value):
        if name == "_real":
            object.__setattr__(self, name, value)
        else:
            setattr(self._real, name, value)


class UnitOfWork:
    def __init__(self):
        self.conns: dict = {}

    def connection(self, path) -> _Deferred:
        key = str(Path(path).resolve())
        if key not in self.conns:
            c = sqlite3.connect(path, check_same_thread=False, timeout=30)
            c.row_factory = sqlite3.Row
            self.conns[key] = c
        return _Deferred(self.conns[key])

    def commit(self):
        for c in self.conns.values():
            c.commit()

    def rollback(self):
        for c in self.conns.values():
            c.rollback()

    def close(self):
        for c in self.conns.values():
            c.close()


def connect(path) -> sqlite3.Connection:
    u = _UOW.get()
    if u is not None and not _SUSPEND.get():
        return u.connection(path)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    return c


@contextmanager
def suspended():
    tok = _SUSPEND.set(True)
    try:
        yield
    finally:
        _SUSPEND.reset(tok)


def begin() -> tuple:
    u = UnitOfWork()
    return u, _UOW.set(u)


def end(token):
    _UOW.reset(token)
