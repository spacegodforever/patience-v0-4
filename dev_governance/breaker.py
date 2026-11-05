"""Per-agent circuit breaker + global kill switch for the dev gate.

Counts each agent's high/critical proposals and anomalies (refused destructive proposals) in a
rolling window. Over the limit the breaker TRIPS: the agent is frozen (new proposals 423), its
pending/approved requests are held (approve/execute 423), the trip is audited, and only a human
approver can reset it (POST /v1/dev/breaker/{agent}/reset). Limits: policy `breaker:`.

Global kill switch: PATIENCE_DEV_KILL=1 halts every dev-gate propose/approve/execute (503).
State persists in the dev gate SQLite DB (table dev_breaker) or in memory for tests.
"""
from __future__ import annotations
import json
import os
import sqlite3
import threading
import time
from typing import Callable, Optional

DEFAULTS = {"window_seconds": 300, "max_high_proposals": 5, "max_anomalies": 3}


def kill_switch_on() -> bool:
    return os.environ.get("PATIENCE_DEV_KILL", "").strip().lower() in ("1", "true", "yes", "on")


class Breaker:
    def __init__(self, path: Optional[str] = None, cfg: Optional[dict] = None,
                 clock: Callable[[], float] = time.time):
        self.path, self.clock = path, clock
        self.cfg = {**DEFAULTS, **(cfg or {})}
        self._mem: dict[str, dict] = {}
        self._lock = threading.Lock()
        if path:
            with self._conn() as c:
                c.execute("CREATE TABLE IF NOT EXISTS dev_breaker (agent TEXT PRIMARY KEY, body TEXT NOT NULL)")
            from .fsperm import secure_file
            secure_file(path)  # RT-09

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        return _Closing(c)

    def _rmw(self, agent: str, fn):
        """Atomic read-modify-write of one agent's state; returns fn's result."""
        with self._lock:
            if not self.path:
                st = self._mem.setdefault(agent, _blank())
                return fn(st)
            with self._conn() as c:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute("SELECT body FROM dev_breaker WHERE agent=?", (agent,)).fetchone()
                st = json.loads(row[0]) if row else _blank()
                out = fn(st)
                c.execute("INSERT OR REPLACE INTO dev_breaker (agent, body) VALUES (?, ?)", (agent, json.dumps(st)))
                c.execute("COMMIT")
                return out

    def state(self, agent: str) -> dict:
        return self._rmw(agent, lambda st: dict(st))

    def frozen(self, agent: str) -> bool:
        return bool(self.state(agent)["frozen"])

    def record(self, agent: str, kind: str) -> Optional[str]:
        """kind: 'high' or 'anomaly'. Returns a trip reason if this event tripped the breaker."""
        now = self.clock()
        w = float(self.cfg["window_seconds"])

        def fn(st):
            key = "high" if kind == "high" else "anomalies"
            st[key] = [t for t in st[key] if t > now - w] + [now]
            st["high"] = [t for t in st["high"] if t > now - w]
            st["anomalies"] = [t for t in st["anomalies"] if t > now - w]
            if st["frozen"]:
                return None
            reason = None
            if len(st["high"]) > int(self.cfg["max_high_proposals"]):
                reason = f"{len(st['high'])} high/critical proposals in {int(w)}s (max {self.cfg['max_high_proposals']})"
            elif len(st["anomalies"]) >= int(self.cfg["max_anomalies"]):
                reason = f"{len(st['anomalies'])} refused/anomalous proposals in {int(w)}s (max {self.cfg['max_anomalies']})"
            if reason:
                st.update(frozen=True, reason=reason, tripped_at=now)
            return reason
        return self._rmw(agent, fn)

    def reset(self, agent: str, approver: str) -> dict:
        def fn(st):
            prev = dict(st)
            st.clear(); st.update(_blank()); st["last_reset_by"] = approver
            return prev
        return self._rmw(agent, fn)


def _blank() -> dict:
    return {"frozen": False, "reason": None, "tripped_at": None, "high": [], "anomalies": []}


class _Closing:
    def __init__(self, c): self.c = c
    def __enter__(self): return self.c
    def __exit__(self, *a): self.c.close()


_SHARED: dict = {}


def default_breaker(cfg: Optional[dict] = None) -> Breaker:
    path = os.environ.get("PATIENCE_DEV_GATE_DB", "patience_dev_gate.db")
    if path == ":memory:":
        return Breaker(None, cfg)
    b = _SHARED.get(path)
    if b is None or not os.path.exists(path):
        b = _SHARED[path] = Breaker(path, cfg)
    return b
