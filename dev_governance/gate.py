"""The dev gate: propose -> policy -> approval -> execute -> audit.

Status codes mirror the main API: 202 = still needs approval, 409 = payload changed / reused /
expired, 403 = forbidden approver or denied, 501 = no adapter. All writes are
versioned compare-and-swap (store.py); the API uses one shared SQLite store per process.
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
from .store import MemoryStore, default_store


class GateError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def canonical_json(obj: Any) -> str:
    """Strict canonical JSON (RT-06): no default=str, no NaN/Infinity, string keys only."""
    def check(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if not isinstance(k, str):
                    raise GateError(422, "payload keys must be strings")
                check(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                check(v)
        elif o is None or isinstance(o, (str, bool, int, float)):
            pass
        else:
            raise GateError(422, f"payload contains a non-JSON value ({type(o).__name__})")
    check(obj)
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as e:
        raise GateError(422, f"payload is not canonical JSON ({e})")


def payload_hash(action: str, payload: dict) -> str:
    canon = canonical_json({"action": (action or "").strip().lower(), "payload": payload or {}})
    return hashlib.sha256(canon.encode()).hexdigest()


_MAX_CAS_RETRIES = 50


class DevGate:
    def __init__(self, policy: Optional[DevPolicy] = None, adapters: Optional[list[Adapter]] = None,
                 clock: Callable[[], float] = time.time, store=None):
        self.policy = policy or load_policy()
        self.adapters: dict[str, Adapter] = {}
        for a in (adapters if adapters is not None else default_adapters()):
            for act in a.actions:
                self.adapters[act] = a
        self.clock = clock
        self.store = store if store is not None else MemoryStore()

    # 1. propose + 2. policy
    def propose(self, action: str, payload: dict, proposer: str, floor: Optional[str] = None,
                owners: Optional[list] = None, require_owners: bool = False) -> dict:
        """owners: human approver usernames responsible for `proposer` (RT-03); they may not approve.
        require_owners: fail closed if a non-low request has no owner mapping."""
        action = (action or "").strip().lower()
        if not proposer:
            raise GateError(400, "proposer is required")
        stored = json.loads(canonical_json(payload or {}))  # 422 on non-JSON values (RT-06)
        ad = self.adapters.get(action)
        if ad is not None and hasattr(ad, "validate"):
            try:
                ad.validate(action, stored)
            except ValueError as e:
                raise GateError(422, str(e))
        a = self.policy.assess(action, stored, floor)
        owners = sorted({str(o).strip() for o in (owners or []) if str(o).strip()})
        if require_owners and not owners and a.approvals_required > 0:
            audit.append("dev.propose.rejected", proposer, action=action, reason="no_owner_mapping")
            raise GateError(403, "proposer has no owner mapping; non-low dev actions are refused (set owners)")
        rid = "dev_" + secrets.token_hex(8)
        now = self.clock()
        req = {"request_id": rid, "action": action, "payload": stored,
               "payload_hash": payload_hash(action, stored), "proposer": proposer, "owners": owners,
               "tier": a.tier, "category": a.category, "known": a.known,
               "approvals_required": a.approvals_required, "reasons": a.reasons, "approvals": [],
               "status": "allowed" if a.approvals_required == 0 else "pending",
               "created_at": now, "expires_at": now + self.policy.ttl, "result": None}
        self.store.insert(req)
        audit.append("dev.proposed", proposer, request_id=rid, action=action, tier=a.tier,
                     known=a.known, payload_hash=req["payload_hash"], reasons=a.reasons, owners=owners)
        return self._public(req)

    def _get(self, rid: str) -> dict:
        req = self.store.get(rid)
        if req is None:
            raise GateError(404, "unknown request")
        return req

    def _update(self, rid: str, mutate):
        """Optimistic CAS loop (RT-01/RT-02): re-read, re-validate, write only if unchanged since read.
        mutate(req) returns (changed, value) or raises GateError; post-commit hooks run once."""
        for _ in range(_MAX_CAS_RETRIES):
            req = self._get(rid)
            changed, value = mutate(req)
            if not changed or self.store.cas(req):
                return req, changed, value
        raise GateError(409, "request is under heavy contention; retry")

    def _expire_if_due(self, rid: str) -> dict:
        def m(req):
            if req["status"] in ("pending", "approved") and self.clock() > req["expires_at"]:
                req["status"] = "expired"
                return True, None
            return False, None
        req, changed, _ = self._update(rid, m)
        if changed:
            audit.append("dev.expired", None, request_id=rid)
        return req

    # 3. approval
    def approve(self, rid: str, approver: str, reason: str = "") -> dict:
        if self._expire_if_due(rid)["status"] == "expired":
            raise GateError(409, "approval window expired; submit a new proposal")

        def m(req):
            if req["status"] != "pending":
                raise GateError(409, f"request is {req['status']}, not pending")
            if not approver or approver == req["proposer"]:
                audit.append("dev.self_approval_rejected", approver, request_id=rid, reason="is_proposer")
                raise GateError(403, "the proposer cannot approve their own request")
            if approver in (req.get("owners") or []):
                audit.append("dev.self_approval_rejected", approver, request_id=rid, reason="owner_of_proposer")
                raise GateError(403, "an owner of the proposing agent cannot approve its request")
            if approver in req["approvals"]:
                raise GateError(409, "this approver already approved; a different approver is required")
            req["approvals"].append(approver)
            if len(req["approvals"]) >= req["approvals_required"]:
                req["status"] = "approved"
            return True, None
        req, _, _ = self._update(rid, m)
        audit.append("dev.approved", approver, request_id=rid, payload_hash=req["payload_hash"],
                     count=len(req["approvals"]), required=req["approvals_required"], reason=reason)
        return self._public(req)

    def deny(self, rid: str, approver: str, reason: str = "") -> dict:
        def m(req):
            if req["status"] not in ("pending", "approved"):
                raise GateError(409, f"request is {req['status']}")
            req["status"] = "denied"
            return True, None
        req, _, _ = self._update(rid, m)
        audit.append("dev.denied", approver, request_id=rid, reason=reason)
        return self._public(req)

    # 4. execute (bound to the payload hash) + 5. audit
    def execute(self, rid: str, action: str, payload: dict, caller: str) -> tuple[int, dict]:
        req = self._get(rid)
        try:
            h = payload_hash(action, payload)
        except GateError:
            h = "invalid"
        if h != req["payload_hash"]:
            audit.append("dev.payload_mismatch", caller, request_id=rid, expected=req["payload_hash"], got=h)
            raise GateError(409, "action/payload differ from the approved request; a new approval is required")
        allowed = {req["proposer"]}
        if self.policy.data.get("execute_by", "proposer_or_owner") == "proposer_or_owner":
            allowed |= set(req.get("owners") or [])
        if caller not in allowed:  # RT-07: an approval is bound to whoever proposed it
            audit.append("dev.execute.forbidden", caller, request_id=rid, proposer=req["proposer"])
            raise GateError(403, "only the proposer (or its owner) may execute this request")
        if self._expire_if_due(rid)["status"] == "expired":
            raise GateError(409, "approval window expired; submit a new proposal")

        def claim(req):
            s = req["status"]
            if s == "denied":
                raise GateError(403, "request was denied")
            if s in ("executed", "executing"):
                raise GateError(409, "this approval was already used")
            if s == "pending":
                return False, "pending"
            # RT-12: positive allowlist + approval count re-check
            ok = (s == "allowed" and req["approvals_required"] == 0) or \
                 (s == "approved" and len(set(req["approvals"])) >= req["approvals_required"])
            if not ok:
                raise GateError(409, f"request is not executable (status {s!r})")
            if self.adapters.get(req["action"]) is None:
                raise GateError(501, f"no adapter configured for {req['action']!r}")
            req["claimed_from"] = s
            req["status"] = "executing"
            return True, "claimed"
        req, _, what = self._update(rid, claim)
        if what == "pending":
            return 202, {"status": "pending_approval", "request_id": rid,
                         "approvals": len(req["approvals"]), "required": req["approvals_required"]}
        return self._run_claimed(req, h, caller)

    def _run_claimed(self, req: dict, h: str, caller: str) -> tuple[int, dict]:
        rid = req["request_id"]
        ad = self.adapters[req["action"]]
        audit.append("dev.execute.claimed", caller, request_id=rid, payload_hash=h)
        try:
            result = ad.execute(req["action"], json.loads(json.dumps(req["payload"])),
                                {"request_id": rid, "caller": caller})
            err = None
        except Exception as e:
            result, err = None, f"adapter error ({type(e).__name__})"
        req["result"], req["error"], req["status"] = result, err, "executed"
        if not self.store.cas(req):  # we hold the claim; nobody else can legally write
            audit.append("dev.execute.finalize_conflict", caller, request_id=rid)
        audit.append("dev.executed" if err is None else "dev.execute.failed", caller, request_id=rid,
                     simulated=getattr(ad, "simulated", True), error=err)
        return 200, {"status": "executed" if err is None else "failed", "request_id": rid, "result": result, "error": err}

    def status(self, rid: str) -> dict:
        return self._public(self._expire_if_due(rid))

    @staticmethod
    def _public(req: dict) -> dict:
        return {k: req[k] for k in ("request_id", "action", "tier", "category", "known", "status",
                                    "approvals_required", "approvals", "payload_hash", "reasons", "expires_at")}
