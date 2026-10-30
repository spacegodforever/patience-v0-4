"""The single path for a human approve/deny (API, dashboard, signed links).

Records who decided, when, why and through which channel, on the request, in
state.approval_log, and in the tamper-evident audit log.
"""
from __future__ import annotations
from typing import Optional
import audit
from models import now_iso


class DecisionError(Exception):
    pass


def decide(p, key: str, approve: bool, approver: dict, reason: str = "", via: str = "api",
           request_id: Optional[str] = None) -> dict:
    if not approver or not approver.get("user") or approver.get("role") not in ("approver", "admin"):
        raise PermissionError("A logged-in approver is required.")
    reason = (reason or "").strip()[:1000]
    if not approve and not reason:
        reason = "(no reason given)"
    ok = (p.authorize if approve else p.deny)(key)
    if approve and ok is False:
        raise DecisionError("This entry can't be granted as a standing approval.")
    rec = {"approval_key": key, "request_id": request_id, "decision": "approved" if approve else "denied",
           "approver": approver["user"], "role": approver["role"], "at": now_iso(), "reason": reason, "via": via}
    with p.memory_store.locked():
        p.refresh()
        p.state.approval_log.append(rec)
        same = [r for r in p.state.requests.values() if r.get("approval_key") == key]
        anchor = next((r for r in same if r["request_id"] == request_id), None) or (same[0] if same else None)
        approved_hash = anchor.get("args_hash") if anchor else None
        for r in p.state.requests.values():
            if r.get("approval_key") == key and (request_id is None or r["request_id"] == request_id):
                r["decided"] = {k: rec[k] for k in ("decision", "approver", "at", "reason", "via")}
            # bind the approval to the exact payload the approver saw (per request)
            if approve and r.get("approval_key") == key and r.get("args_hash") == approved_hash:
                r["approved_args_hash"] = approved_hash
        p.memory_store.save(p.state)
    audit.append("approval." + rec["decision"], approver["user"],
                 **{k: rec[k] for k in ("approval_key", "request_id", "role", "reason", "via")})
    return rec
