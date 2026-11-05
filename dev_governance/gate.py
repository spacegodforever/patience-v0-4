"""The dev gate: propose -> policy -> approval -> execute -> audit.

Status codes mirror the main API: 202 = still needs approval, 409 = payload changed / reused /
expired, 403 = forbidden approver or denied, 501 = no adapter. State is in memory (per gate
instance); persistence is left for integration with engine state.
"""
from __future__ import annotations
import hashlib
import json
import secrets
import time
from typing import Any, Callable, Optional

import audit
from .policy import DevPolicy, load_policy
from .adapters import Adapter, default_adapters


class GateError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def payload_hash(action: str, payload: dict) -> str:
    canon = json.dumps({"action": (action or "").strip().lower(), "payload": payload or {}},
                       sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


class DevGate:
    def __init__(self, policy: Optional[DevPolicy] = None, adapters: Optional[list[Adapter]] = None,
                 clock: Callable[[], float] = time.time):
        self.policy = policy or load_policy()
        self.adapters: dict[str, Adapter] = {}
        for a in (adapters if adapters is not None else default_adapters()):
            for act in a.actions:
                self.adapters[act] = a
        self.clock = clock
        self.requests: dict[str, dict] = {}

    # 1. propose + 2. policy
    def propose(self, action: str, payload: dict, proposer: str, floor: Optional[str] = None) -> dict:
        action = (action or "").strip().lower()
        if not proposer:
            raise GateError(400, "proposer is required")
        ad = self.adapters.get(action)
        if ad is not None and hasattr(ad, "validate"):
            try:
                ad.validate(action, payload or {})
            except ValueError as e:
                raise GateError(422, str(e))
        a = self.policy.assess(action, payload or {}, floor)
        rid = "dev_" + secrets.token_hex(8)
        now = self.clock()
        req = {"request_id": rid, "action": action, "payload": json.loads(json.dumps(payload or {}, default=str)),
               "payload_hash": payload_hash(action, payload), "proposer": proposer, "tier": a.tier,
               "category": a.category, "known": a.known, "approvals_required": a.approvals_required,
               "reasons": a.reasons, "approvals": [], "status": "allowed" if a.approvals_required == 0 else "pending",
               "created_at": now, "expires_at": now + self.policy.ttl, "result": None}
        self.requests[rid] = req
        audit.append("dev.proposed", proposer, request_id=rid, action=action, tier=a.tier,
                     known=a.known, payload_hash=req["payload_hash"], reasons=a.reasons)
        return self._public(req)

    def _get(self, rid: str) -> dict:
        req = self.requests.get(rid)
        if req is None:
            raise GateError(404, "unknown request")
        return req

    def _expired(self, req: dict) -> bool:
        if req["status"] in ("pending", "approved") and self.clock() > req["expires_at"]:
            req["status"] = "expired"
            audit.append("dev.expired", None, request_id=req["request_id"])
        return req["status"] == "expired"

    # 3. approval
    def approve(self, rid: str, approver: str, reason: str = "") -> dict:
        req = self._get(rid)
        if self._expired(req):
            raise GateError(409, "approval window expired; submit a new proposal")
        if req["status"] != "pending":
            raise GateError(409, f"request is {req['status']}, not pending")
        if not approver or approver == req["proposer"]:
            audit.append("dev.self_approval_rejected", approver, request_id=rid)
            raise GateError(403, "the proposer cannot approve their own request")
        if approver in req["approvals"]:
            raise GateError(409, "this approver already approved; a different approver is required")
        req["approvals"].append(approver)
        audit.append("dev.approved", approver, request_id=rid, payload_hash=req["payload_hash"],
                     count=len(req["approvals"]), required=req["approvals_required"], reason=reason)
        if len(req["approvals"]) >= req["approvals_required"]:
            req["status"] = "approved"
        return self._public(req)

    def deny(self, rid: str, approver: str, reason: str = "") -> dict:
        req = self._get(rid)
        if req["status"] not in ("pending", "approved"):
            raise GateError(409, f"request is {req['status']}")
        req["status"] = "denied"
        audit.append("dev.denied", approver, request_id=rid, reason=reason)
        return self._public(req)

    # 4. execute (bound to the payload hash) + 5. audit
    def execute(self, rid: str, action: str, payload: dict, caller: str) -> tuple[int, dict]:
        req = self._get(rid)
        h = payload_hash(action, payload)
        if h != req["payload_hash"]:
            audit.append("dev.payload_mismatch", caller, request_id=rid, expected=req["payload_hash"], got=h)
            raise GateError(409, "action/payload differ from the approved request; a new approval is required")
        if self._expired(req):
            raise GateError(409, "approval window expired; submit a new proposal")
        if req["status"] == "denied":
            raise GateError(403, "request was denied")
        if req["status"] == "executed":
            raise GateError(409, "this approval was already used")
        if req["status"] == "pending":
            return 202, {"status": "pending_approval", "request_id": rid,
                         "approvals": len(req["approvals"]), "required": req["approvals_required"]}
        ad = self.adapters.get(req["action"])
        if ad is None:
            raise GateError(501, f"no adapter configured for {req['action']!r}")
        req["status"] = "executed"  # claim before running: at most once
        audit.append("dev.execute.claimed", caller, request_id=rid, payload_hash=h)
        try:
            result = ad.execute(req["action"], json.loads(json.dumps(req["payload"])),
                                {"request_id": rid, "caller": caller})
            err = None
        except Exception as e:
            result, err = None, f"adapter error ({type(e).__name__})"
        req["result"] = result
        audit.append("dev.executed" if err is None else "dev.execute.failed", caller, request_id=rid,
                     simulated=getattr(ad, "simulated", True), error=err)
        return 200, {"status": "executed" if err is None else "failed", "request_id": rid, "result": result, "error": err}

    def status(self, rid: str) -> dict:
        req = self._get(rid)
        self._expired(req)
        return self._public(req)

    @staticmethod
    def _public(req: dict) -> dict:
        return {k: req[k] for k in ("request_id", "action", "tier", "category", "known", "status",
                                    "approvals_required", "approvals", "payload_hash", "reasons", "expires_at")}
