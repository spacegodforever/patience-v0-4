"""SQLite store for coordinator projects, events and submitted previews.

Every write is paired with an audit.append inside the same transaction; if the audit
append fails the transaction is rolled back and AuditUnavailable is raised (fail closed).
Env: PATIENCE_COORD_DB (default patience_coordinator.db, git-ignored).
"""
from __future__ import annotations
import hashlib
import hmac
import json
import time
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
import audit
from models import now_iso

STATUSES = {"active", "paused", "planned", "complete"}
PRIORITIES = {"critical", "high", "medium", "low"}
KINDS = {"note", "observation", "project", "status", "system", "preview"}


class AuditUnavailable(RuntimeError):
    pass


def db_path() -> Path:
    return Path(os.environ.get("PATIENCE_COORD_DB", "patience_coordinator.db"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS projects(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','planned','complete')),
  priority TEXT NOT NULL DEFAULT 'medium' CHECK(priority IN ('critical','high','medium','low')),
  next_step TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '', source TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS previews(
  id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER REFERENCES projects(id),
  request_id TEXT NOT NULL, tool TEXT, args_hash TEXT, decision TEXT NOT NULL,
  preview TEXT NOT NULL, source TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_events_id ON events(id);
CREATE TABLE IF NOT EXISTS sessions(
  token_sha256 TEXT PRIMARY KEY, user TEXT NOT NULL, role TEXT, csrf_sha256 TEXT NOT NULL,
  exp REAL NOT NULL, created_at TEXT NOT NULL);
"""


def connect() -> sqlite3.Connection:
    p = db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.executescript(SCHEMA)
    return c


@contextmanager
def audited(event: str, actor: str, **data):
    """Yield a connection; commit only if the audit append succeeds."""
    c = connect()
    try:
        yield c, data
        try:
            audit.append(event, actor, **data)
        except Exception as e:  # noqa: BLE001 - any audit failure refuses the write
            raise AuditUnavailable(f"audit log unavailable: {type(e).__name__}") from e
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def _row(c, table, rid):
    r = c.execute(f"SELECT * FROM {table} WHERE id=?", (rid,)).fetchone()
    return dict(r) if r else None


def list_projects():
    c = connect()
    try:
        return [dict(x) for x in c.execute("SELECT * FROM projects ORDER BY id DESC")]
    finally:
        c.close()


def list_events(limit=40):
    c = connect()
    try:
        return [dict(x) for x in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]
    finally:
        c.close()


def list_previews(limit=40):
    c = connect()
    try:
        return [dict(x) for x in c.execute("SELECT * FROM previews ORDER BY id DESC LIMIT ?", (limit,))]
    finally:
        c.close()


def _event(c, kind, title, detail, source):
    c.execute("INSERT INTO events(kind,title,detail,source,created_at) VALUES(?,?,?,?,?)",
              (kind, title, detail, source, now_iso()))


def add_project(name, priority, next_step, source, actor):
    if priority not in PRIORITIES:
        raise ValueError("Unsupported priority")
    with audited("coord.project.create", actor, name=name[:120], priority=priority, source=source) as (c, d):
        cur = c.execute("INSERT INTO projects(name,priority,next_step,created_by,created_at) VALUES(?,?,?,?,?)",
                        (name, priority, next_step, source, now_iso()))
        _event(c, "project", "Project created: " + name, next_step, source)
        d["project_id"] = cur.lastrowid
        row = _row(c, "projects", cur.lastrowid)
    return row


def set_status(pid, status, source, actor):
    if status not in STATUSES:
        raise ValueError("Unsupported status")
    with audited("coord.project.status", actor, project_id=pid, status=status, source=source) as (c, _):
        cur = c.execute("UPDATE projects SET status=? WHERE id=?", (status, pid))
        if cur.rowcount == 0:
            raise LookupError("Project not found")
        _event(c, "status", f"Project {pid} status changed", status, source)
        row = _row(c, "projects", pid)
    return row


def add_event(kind, title, detail, source, actor):
    if kind not in KINDS:
        raise ValueError("Unsupported kind")
    with audited("coord.event.add", actor, kind=kind, title=title[:180], source=source) as (c, d):
        cur = c.execute("INSERT INTO events(kind,title,detail,source,created_at) VALUES(?,?,?,?,?)",
                        (kind, title, detail, source, now_iso()))
        d["event_id"] = cur.lastrowid
        row = _row(c, "events", cur.lastrowid)
    return row


def add_preview(project_id, req, source, actor):
    with audited("coord.preview.submitted", actor, request_id=req["request_id"], decision=req["decision"],
                 tool=req.get("tool"), args_hash=req.get("args_hash"), project_id=project_id,
                 source=source) as (c, d):
        cur = c.execute("INSERT INTO previews(project_id,request_id,tool,args_hash,decision,preview,source,created_at)"
                        " VALUES(?,?,?,?,?,?,?,?)",
                        (project_id, req["request_id"], req.get("tool"), req.get("args_hash"), req["decision"],
                         json.dumps(req.get("preview"), default=str), source, now_iso()))
        _event(c, "preview", f"Action preview submitted for approval: {req.get('tool')}",
               f"request {req['request_id']} -> {req['decision']}", source)
        row = _row(c, "previews", cur.lastrowid)
    return row


# ---------- browser sessions (only SHA-256 of token and CSRF are stored) ----------
def _h(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def session_create(token: str, csrf: str, user: str, role, exp: float) -> None:
    c = connect()
    try:
        c.execute("DELETE FROM sessions WHERE exp < ?", (time.time(),))
        c.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",
                  (_h(token), user, role, _h(csrf), exp, now_iso()))
        c.commit()
    finally:
        c.close()


def session_get(token: str):
    if not token:
        return None
    c = connect()
    try:
        r = c.execute("SELECT * FROM sessions WHERE token_sha256=?", (_h(token),)).fetchone()
        if r and r["exp"] < time.time():
            c.execute("DELETE FROM sessions WHERE token_sha256=?", (_h(token),))
            c.commit()
            return None
        return dict(r) if r else None
    finally:
        c.close()


def session_delete(token: str) -> None:
    if not token:
        return
    c = connect()
    try:
        c.execute("DELETE FROM sessions WHERE token_sha256=?", (_h(token),))
        c.commit()
    finally:
        c.close()


def session_csrf_ok(sess: dict, csrf) -> bool:
    return bool(csrf) and hmac.compare_digest(_h(csrf), sess["csrf_sha256"])


def sessions_clear() -> None:
    c = connect()
    try:
        c.execute("DELETE FROM sessions")
        c.commit()
    finally:
        c.close()
