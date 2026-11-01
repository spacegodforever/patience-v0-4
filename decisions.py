"""The single path for a human approve/deny (API, dashboard, signed links).

Records who decided, when, why and through which channel, on the request, in
state.approval_log, and in the tamper-evident audit log.
"""
from __future__ import annotations
from typing import Optional
from models import now_iso
from transaction import audited, state_txn


class DecisionError(Exception):
    pass


def _tier(req: dict) -> str:
    import risk_policy
    return req.get("risk_tier") or risk_policy.risk_tier(req.get("risk_categories", []), req.get("budget_usage"))


def decide(p, key: str, approve: bool, approver: dict, reason: str = "", via: str = "api",
           request_id: Optional[str] = None) -> dict:
    if not approver or not approver.get("user") or approver.get("role") not in ("approver", "admin"):
        raise PermissionError("A logged-in approver is required.")
    reason = (reason or "").strip()[:1000]
    if not approve and not reason:
        reason = "(no reason given)"
    rec = {"approval_key": key, "request_id": request_id, "decision": "approved" if approve else "denied",
           "approver": approver["user"], "role": approver["role"], "at": now_iso(), "reason": reason, "via": via}
    with state_txn(p):  # one lock for the state change and its audit record; rolled back if audit fails
        p.refresh()
        targets = [r for r in p.state.requests.values()
                   if r.get("approval_key") == key and (request_id is None or r["request_id"] == request_id)]
        for r in targets:  # never the requesting agent, whatever the tier
            if approver["user"] in {r.get("identity"), r.get("requester")} - {None, ""}:
                raise DecisionError("The requesting agent cannot decide its own request.")
        critical = [r for r in targets if _tier(r) == "critical"]
        if approve and critical:
            # C2 two-person rule: two distinct named human approvers; the shared legacy token never counts
            if approver.get("legacy") or approver["user"] == "legacy-token":
                raise DecisionError("Critical requests need named approver accounts (two-person rule).")
            prior = {a["approver"] for r in critical for a in r.get("approvals", [])}
            if approver["user"] in prior:
                raise DecisionError("Two-person rule: a second, different approver is required.")
            if not prior:
                first = {"approver": approver["user"], "role": approver["role"], "at": now_iso(),
                         "reason": reason, "via": via}
                for r in critical:
                    r.setdefault("approvals", []).append(first)
                p.state.approval_log.append({**rec, "decision": "first_approval"})
                p.memory_store.save(p.state)
                audited("approval.first", approver["user"], approval_key=key, request_id=request_id,
                        role=approver["role"], reason=reason, via=via, risk_tier="critical")
                return {**rec, "decision": "pending_second_approval"}
            second = {"approver": approver["user"], "role": approver["role"], "at": now_iso(),
                      "reason": reason, "via": via}
            for r in critical:
                r.setdefault("approvals", []).append(second)
            p.memory_store.save(p.state)
        ok = (p.authorize if approve else p.deny)(key)
        if approve and ok is False:
            raise DecisionError("This entry can't be granted as a standing approval.")
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
        audited("approval." + rec["decision"], approver["user"],
                **{k: rec[k] for k in ("approval_key", "request_id", "role", "reason", "via")})
    return rec
