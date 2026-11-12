"""Destructive-action guard: stop a single action from irreversibly wiping data or infra.

Classifies a proposal as destructive (irreversible) by action name, by environment (anything that
is production or unrecognized, for deploy/migrate/infra), and by payload content (DROP/TRUNCATE,
DELETE without WHERE, rm -rf, --force ...). A destructive proposal:

  (a) must declare `rollback_plan` (text) and `backup` evidence ({snapshot_id | evidence}) in the
      payload, or it is refused (fail closed);
  (b) is forced to tier critical with at least two distinct approvers;
  (c) must declare `blast_radius` {rows, resources}; over the policy limit it needs split
      approval (an extra approver); over limit x hard_factor it is refused - split the work.

Rules are deterministic and declared in policies/dev/default.yaml under `catastrophe:`. This is a
safety net, not a guarantee: content scanning cannot see what an opaque script will do.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .policy import normalize_environment

ALWAYS = {
    "db.drop": "drops a database/table",
    "db.truncate": "truncates tables",
    "db.delete_rows": "deletes rows",
    "repo.delete": "deletes a repository",
    "code.force_push": "rewrites published history",
    "data.wipe": "wipes data",
    "infra.destroy": "destroys infrastructure",
    "secrets.rotate": "rotates secrets (can lock out running services)",
}
PROD_SENSITIVE = {"deploy.release", "deploy.rollback", "db.migrate", "infra.apply"}
PATTERNS = [
    (re.compile(r"\bdrop\s+(table|database|schema|index)\b", re.I), "DROP statement"),
    (re.compile(r"\btruncate\b", re.I), "TRUNCATE statement"),
    (re.compile(r"\bdelete\s+from\s+[\w.\"`]+\s*(;|$)", re.I), "DELETE without WHERE"),
    (re.compile(r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r", re.I), "rm -rf"),
    (re.compile(r"--force\b|\bpush\s+-f\b", re.I), "force flag"),
    (re.compile(r"\bterraform\s+destroy\b|\bdelete-stack\b|\bdrop_all\b", re.I), "destroy command"),
]
DEFAULTS = {"max_rows": 10_000, "max_resources": 10, "hard_factor": 10, "min_rollback_chars": 20}


@dataclass
class Guard:
    destructive: bool = False
    why: list = field(default_factory=list)
    refuse: Optional[str] = None
    min_approvals: int = 0
    blast: dict = field(default_factory=dict)


def _strings(o: Any):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for k, v in o.items():
            if k not in ("rollback_plan", "backup"):
                yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)


def _int(v) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int) and v >= 0:
        return v
    return None


def classify(action: str, payload: dict) -> list:
    why = []
    if action in ALWAYS:
        why.append(f"{action}: {ALWAYS[action]}")
    if action in PROD_SENSITIVE:
        env = normalize_environment(payload.get("environment"))
        if env in (None, "production"):
            why.append(f"{action} on {'production' if env else 'unrecognized environment'}")
    for s in _strings(payload):
        for rx, label in PATTERNS:
            if rx.search(s) and label not in [w.split(':')[0] for w in why]:
                why.append(f"{label}: payload contains a destructive command")
    return why


def check(action: str, payload: dict, cfg: Optional[dict] = None) -> Guard:
    c = {**DEFAULTS, **(cfg or {})}
    why = classify(action, payload or {})
    if not why:
        return Guard()
    g = Guard(destructive=True, why=why, min_approvals=2)
    plan = payload.get("rollback_plan")
    if not isinstance(plan, str) or len(plan.strip()) < int(c["min_rollback_chars"]):
        g.refuse = "destructive action needs a rollback_plan (text describing how to undo it)"
        return g
    b = payload.get("backup")
    if not isinstance(b, dict) or not any(isinstance(b.get(k), str) and b[k].strip()
                                          for k in ("snapshot_id", "evidence")):
        g.refuse = "destructive action needs backup evidence: backup.snapshot_id or backup.evidence"
        return g
    br = payload.get("blast_radius")
    rows = _int((br or {}).get("rows")) if isinstance(br, dict) else None
    res = _int((br or {}).get("resources")) if isinstance(br, dict) else None
    if rows is None or res is None:
        g.refuse = "destructive action needs blast_radius {rows: int>=0, resources: int>=0}"
        return g
    g.blast = {"rows": rows, "resources": res, "max_rows": int(c["max_rows"]),
               "max_resources": int(c["max_resources"])}
    over = rows > c["max_rows"] or res > c["max_resources"]
    hard = rows > c["max_rows"] * c["hard_factor"] or res > c["max_resources"] * c["hard_factor"]
    if hard:
        g.refuse = (f"blast radius rows={rows} resources={res} exceeds the hard limit "
                    f"({c['max_rows'] * c['hard_factor']} rows / {c['max_resources'] * c['hard_factor']} "
                    "resources); split it into smaller requests")
    elif over:
        g.min_approvals = 3
        g.why.append("blast radius over limit: split approval (3 distinct approvers)")
    return g
