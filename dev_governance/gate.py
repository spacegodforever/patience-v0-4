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
from . import claims as _claims
from . import advisory as _advisory
from . import ambiguity as _ambiguity
from . import destructive as _destructive
from . import breaker as _breaker
import tiers as _tiers
from .store import MemoryStore, default_store
from .authority import AuthorityError
from execution_gateway import PERMIT_ACTIONS as _PERMIT_ACTIONS, validate_invoice_payload as _validate_invoice
from execution_gateway.issuer import PermitError as _PermitError, issuer_for_store as _issuer_for_store


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
                 clock: Callable[[], float] = time.time, store=None, breaker=None, authority=None,
                 permit_issuer=None):
        self.policy = policy or load_policy()
        self.adapters: dict[str, Adapter] = {}
        for a in (adapters if adapters is not None else default_adapters()):
            for act in a.actions:
                self.adapters[act] = a
        self.clock = clock
        self.authority = authority
        self._permit_issuer = permit_issuer
        self.store = store if store is not None else MemoryStore()
        spath = getattr(self.store, "path", None)
        if spath and spath != ":memory:":
            _claims.use_secret_file(spath + ".key")
        self.breaker = breaker if breaker is not None else _breaker.Breaker(None, self.policy.data.get("breaker"), clock)

    def _halt_checks(self, agent: str, what: str) -> None:
        if _breaker.kill_switch_on():
            audit.append("dev.kill_switch.blocked", agent, what=what)
            raise GateError(503, "PATIENCE_DEV_KILL is on: all dev actions are halted")
        if agent and self.breaker.frozen(agent):
            audit.append("dev.breaker.held", agent, what=what)
            raise GateError(423, f"agent {agent!r} is frozen by the circuit breaker; a human approver must reset it")

    def _trip_check(self, agent: str, kind: str) -> None:
        reason = self.breaker.record(agent, kind)
        if reason:
            audit.append("dev.breaker.tripped", agent, reason=reason)

    def reset_breaker(self, agent: str, approver: str, reason: str = "") -> dict:
        if not approver:
            raise GateError(403, "a human approver is required to reset the breaker")
        prev = self.breaker.reset(agent, approver)
        audit.append("dev.breaker.reset", approver, agent=agent, was_frozen=prev.get("frozen"),
                     prior_reason=prev.get("reason"), reason=reason)
        return {"agent": agent, "frozen": False, "was_frozen": bool(prev.get("frozen"))}

    def breaker_status(self, agent: str) -> dict:
        st = self.breaker.state(agent)
        return {"agent": agent, "frozen": st["frozen"], "reason": st["reason"], "tripped_at": st["tripped_at"],
                "kill_switch": _breaker.kill_switch_on()}

    # 1. propose + 2. policy
    def propose(self, action: str, payload: dict, proposer: str, floor: Optional[str] = None,
                owners: Optional[list] = None, require_owners: bool = False,
                text: Optional[str] = None, authority_grant: Optional[str] = None) -> dict:
        """owners: human approver usernames responsible for `proposer` (RT-03); they may not approve.
        require_owners: fail closed if a non-low request has no owner mapping."""
        action = (action or "").strip().lower()
        if not proposer:
            raise GateError(400, "proposer is required")
        self._halt_checks(proposer, "propose")
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise GateError(422, "payload must be a JSON object")
        owners = sorted({str(o).strip() for o in (owners or []) if str(o).strip()})
        # A risk tier classifies impact; it does not grant capability. Only this new isolated-test
        # action uses an explicit grant, leaving legacy CI policy unchanged pending human review.
        if action == "test.run_isolated":
            if self.authority is None:
                audit.append("dev.authority.refused", proposer, action=action, reason="no_authority_store")
                raise GateError(403, "a human-granted isolated test capability is required")
            try:
                self.authority.require(grant_id=authority_grant, actor=proposer, action=action,
                                       payload=payload, owners=owners,
                                       request_expires_at=self.clock() + self.policy.ttl)
            except AuthorityError as e:
                audit.append("dev.authority.refused", proposer, action=action, reason=e.message)
                raise GateError(e.status, e.message)
        stored = json.loads(canonical_json(payload))  # 422 on non-JSON values (RT-06)
        if authority_grant is not None:
            if action != "test.run_isolated" or not isinstance(authority_grant, str) or not authority_grant.strip():
                raise GateError(422, "authority_grant is accepted only for test.run_isolated")
            stored["authority_grant"] = authority_grant.strip()
        if action in _PERMIT_ACTIONS:  # permit-gated actions: strict payload shape, checked at propose time
            try:
                _validate_invoice(stored)
            except ValueError as e:
                raise GateError(422, str(e))
        ad = self.adapters.get(action)
        if ad is not None and hasattr(ad, "validate"):
            try:
                ad.validate(action, stored)
            except ValueError as e:
                raise GateError(422, str(e))
        a = self.policy.assess(action, stored, floor)
        guard = _destructive.check(action, stored, self.policy.data.get("catastrophe"))
        if guard.destructive:
            if guard.refuse:
                audit.append("dev.destructive.refused", proposer, action=action, reason=guard.refuse,
                             why=guard.why)
                self._on_refused(proposer)
                raise GateError(422, f"refused (fail closed): {guard.refuse}")
            a.tier = "critical"
            a.approvals_required = max(a.approvals_required, guard.min_approvals,
                                       _tiers.approvals_required("critical", self.policy.required_overrides))
            a.reasons = a.reasons + [f"destructive: {w}" for w in guard.why]
        amb = _ambiguity.analyze(text, action, stored) if text is not None else None
        adv = _advisory.build(action, stored, a.tier, a.known, guard, amb)
        raised = _tiers.raise_only(a.tier, adv["threat_floor"])
        if raised != a.tier:
            a.reasons = a.reasons + [f"advisory raised tier {a.tier}->{raised}"]
            a.tier = raised
            a.approvals_required = max(a.approvals_required,
                                       _tiers.approvals_required(raised, self.policy.required_overrides))
        if require_owners and not owners and a.approvals_required > 0:
            audit.append("dev.propose.rejected", proposer, action=action, reason="no_owner_mapping")
            raise GateError(403, "proposer has no owner mapping; non-low dev actions are refused (set owners)")
        if a.tier in ("high", "critical"):
            self._trip_check(proposer, "high")
            if self.breaker.frozen(proposer):
                raise GateError(423, f"agent {proposer!r} tripped the circuit breaker; a human approver must reset it")
        rid = "dev_" + secrets.token_hex(8)
        now = self.clock()
        req = {"request_id": rid, "action": action, "payload": stored,
               "payload_hash": payload_hash(action, stored), "proposer": proposer, "owners": owners,
               "tier": a.tier, "category": a.category, "known": a.known,
               "approvals_required": a.approvals_required, "reasons": a.reasons, "approvals": [],
               "destructive": guard.destructive, "blast_radius": guard.blast or None,
               "advisory": None,
               "status": "allowed" if a.approvals_required == 0 else "pending",
               "created_at": now, "expires_at": now + self.policy.ttl, "result": None}
        req["expiry_sig"] = self._expiry_sig(req)  # RT-08: expiry is bound to the request
        if req["approvals_required"] > 0 or (amb and amb["warnings"]):
            req["advisory"] = adv
        self.store.insert(req)
        audit.append("dev.proposed", proposer, request_id=rid, action=action, tier=a.tier,
                     known=a.known, payload_hash=req["payload_hash"], reasons=a.reasons, owners=owners)
        return self._public(req)

    def _on_refused(self, proposer: str) -> None:
        self._trip_check(proposer, "anomaly")  # refusals count as anomalies

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

    @staticmethod
    def _expiry_sig(req: dict) -> str:
        return _claims.sign_fields("expiry-v1", req["request_id"], req["payload_hash"],
                                   float(req["created_at"]), float(req["expires_at"]))

    def _expire_if_due(self, rid: str) -> dict:
        """RT-08: an expiry that does not match its signature (e.g. edited in the DB to extend the
        window) fails closed: the request is expired. The window may also never exceed policy TTL."""
        why = {}

        def m(req):
            if req["status"] not in ("pending", "approved"):
                return False, None
            tampered = not _claims.check_fields(req.get("expiry_sig"), "expiry-v1", req["request_id"],
                                                req["payload_hash"], float(req["created_at"]),
                                                float(req["expires_at"])) \
                or float(req["expires_at"]) - float(req["created_at"]) > self.policy.ttl
            if tampered or self.clock() > req["expires_at"]:
                req["status"] = "expired"
                why["tampered"] = tampered
                return True, None
            return False, None
        req, changed, _ = self._update(rid, m)
        if changed:
            if why.get("tampered"):
                audit.append("dev.expiry.tampered", None, request_id=rid)
            audit.append("dev.expired", None, request_id=rid)
        return req

    # 3. approval
    def approve(self, rid: str, approver: str, reason: str = "") -> dict:
        self._halt_checks(self._get(rid)["proposer"], "approve")
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
        self._halt_checks(req["proposer"], "execute")
        if req["action"] in _PERMIT_ACTIONS:
            raise GateError(409, f"{req['action']} is executed only by the execution gateway; request a permit")
        if req["action"] == "test.run_isolated":
            if self.authority is None:
                raise GateError(403, "a human-granted isolated test capability is required")
            try:
                self.authority.require(grant_id=req["payload"].get("authority_grant"),
                                       actor=req["proposer"], action=req["action"], payload=req["payload"],
                                       owners=req.get("owners") or [], request_expires_at=req["expires_at"])
            except AuthorityError as e:
                audit.append("dev.authority.refused", caller, request_id=rid, reason=e.message)
                raise GateError(e.status, e.message)
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
            req["claimed_at"] = self.clock()
            req["status"] = "executing"
            return True, "claimed"
        req, _, what = self._update(rid, claim)
        if what == "pending":
            return 202, {"status": "pending_approval", "request_id": rid,
                         "approvals": len(req["approvals"]), "required": req["approvals_required"]}
        return self._run_claimed(req, h, caller)

    # 4b. permit issuance (Execution Gateway v0): a signed single-action permit instead of execution
    def permit_issuer(self):
        if self._permit_issuer is None:
            try:
                self._permit_issuer = _issuer_for_store(getattr(self.store, "path", None), self.clock)
            except _PermitError as e:
                audit.append("dev.permit.refused", None, reason="issuer_unavailable")
                raise GateError(503, str(e))
        return self._permit_issuer

    def issue_permit(self, rid: str, action: str, payload: dict, caller: str,
                     ttl_seconds: Optional[int] = None) -> dict:
        """Mint ONE permit for an approved request. Same preconditions as execute(): payload hash must
        match the approval, caller must be the proposer (or owner), kill switch/breaker off, approval
        not expired and fully granted. Issuing consumes the approval (status 'permit_issued', terminal)
        so a request can never yield a second permit. The permit is bound to the proposer's id."""
        req = self._get(rid)
        try:
            h = payload_hash(action, payload)
        except GateError:
            h = "invalid"
        if h != req["payload_hash"]:
            audit.append("dev.payload_mismatch", caller, request_id=rid, expected=req["payload_hash"], got=h)
            raise GateError(409, "action/payload differ from the approved request; a new approval is required")
        if req["action"] not in _PERMIT_ACTIONS:
            raise GateError(422, f"{req['action']!r} is not a permit-gated action")
        self._halt_checks(req["proposer"], "permit")
        allowed = {req["proposer"]}
        if self.policy.data.get("execute_by", "proposer_or_owner") == "proposer_or_owner":
            allowed |= set(req.get("owners") or [])
        if caller not in allowed:
            audit.append("dev.permit.forbidden", caller, request_id=rid, proposer=req["proposer"])
            raise GateError(403, "only the proposer (or its owner) may request a permit")
        if self._expire_if_due(rid)["status"] == "expired":
            raise GateError(409, "approval window expired; submit a new proposal")
        out = {}

        def claim(req):
            s = req["status"]
            if s == "denied":
                raise GateError(403, "request was denied")
            if s in ("executed", "executing", "permit_issued"):
                raise GateError(409, "this approval was already used")
            ok = (s == "allowed" and req["approvals_required"] == 0) or \
                 (s == "approved" and len(set(req["approvals"])) >= req["approvals_required"])
            if not ok:
                raise GateError(409, f"request is not approved (status {s!r})")
            try:
                out["p"] = self.permit_issuer().issue(agent=req["proposer"], action=req["action"],
                                                      payload_hash=req["payload_hash"], request_id=rid,
                                                      ttl_seconds=ttl_seconds, not_after=req["expires_at"])
            except _PermitError as e:
                audit.append("dev.permit.refused", caller, request_id=rid, reason=str(e)[:200])
                raise GateError(503, str(e))
            req["claimed_from"], req["status"] = s, "permit_issued"
            req["permit"] = {k: out["p"][k] for k in ("jti", "kid", "iat", "exp")} | {"issued_to": caller}
            return True, None
        req, _, _ = self._update(rid, claim)
        p = out["p"]
        audit.append("dev.permit.issued", caller, request_id=rid, agent=req["proposer"], action=req["action"],
                     payload_hash=req["payload_hash"], permit_id=p["jti"], key_id=p["kid"],
                     issued_at=p["iat"], expires_at=p["exp"])
        return {"request_id": rid, "action": req["action"], "agent": req["proposer"], "permit": p["permit"],
                "key_id": p["kid"], "issued_at": p["iat"], "expires_at": p["exp"]}

    def _run_claimed(self, req: dict, h: str, caller: str) -> tuple[int, dict]:
        rid = req["request_id"]
        ad = self.adapters[req["action"]]
        audit.append("dev.execute.claimed", caller, request_id=rid, payload_hash=h)
        ctx = {"request_id": rid, "caller": caller, "payload_hash": h, "tier": req["tier"],
               "approved": req.get("claimed_from") in ("approved", "allowed")}
        if getattr(ad, "live", False):  # RT-10: live adapters need a fresh single-use claim token
            ctx["claim_token"] = _claims.mint(rid, h)
            spath = getattr(self.store, "path", None)
            if spath and spath != ":memory:":
                ctx["claim_nonce_db"] = spath  # shared across workers (used-nonce table)  # real time: adapters verify against real time
            ctx["payload_hash"] = h
        try:
            result = ad.execute(req["action"], json.loads(json.dumps(req["payload"])),
                                ctx)
            err = None
        except Exception as e:
            result, err = None, f"adapter error ({type(e).__name__})"
        req["result"], req["error"], req["status"] = result, err, "executed"
        if err is None and isinstance(result, dict) and result.get("dry_run"):
            req["status"] = req["claimed_from"]  # a dry run sends nothing, so it does not consume the approval
        if not self.store.cas(req):  # we hold the claim; nobody else can legally write
            audit.append("dev.execute.finalize_conflict", caller, request_id=rid)
        audit.append("dev.executed" if err is None else "dev.execute.failed", caller, request_id=rid,
                     simulated=getattr(ad, "simulated", True), error=err,
                     dry_run=bool(isinstance(result, dict) and result.get("dry_run")))
        return 200, {"status": "executed" if err is None else "failed", "request_id": rid, "result": result, "error": err}

    # 6. crash recovery: 'executing' left behind by a dead process becomes 'needs_review'
    def flag_stuck_executions(self, actor: str, min_age_seconds: float = 300,
                              request_ids: Optional[list] = None) -> list:
        """Move requests stuck in 'executing' for at least min_age_seconds to 'needs_review'.

        Never retries: the side effect may or may not have happened. Only a named human, via
        resolve_review(), can close the request. Each flagged request is audited. By default every
        request the store lists as 'executing' is inspected; pass request_ids to limit the sweep.
        Use a min age above the slowest adapter timeout so a live execution is not flagged.
        """
        if not actor:
            raise GateError(403, "a human approver is required to flag stuck executions")
        try:
            min_age = float(min_age_seconds)
        except (TypeError, ValueError):
            raise GateError(422, "min_age_seconds must be a number")
        if min_age < 0 or min_age != min_age:
            raise GateError(422, "min_age_seconds must be >= 0")
        ids = request_ids
        if ids is None:
            lister = getattr(self.store, "list_by_status", None)
            ids = lister("executing") if lister else []
        flagged = []
        for rid in ids:
            seen = {}

            def m(req):
                if req["status"] != "executing":
                    return False, None
                at = req.get("claimed_at")
                age = float("inf") if not isinstance(at, (int, float)) else self.clock() - at
                if age < min_age:
                    return False, None
                req["status"] = "needs_review"
                req["flagged_at"] = self.clock()
                req["flagged_by"] = actor
                seen["from"] = at
                return True, None
            try:
                req, changed, _ = self._update(rid, m)
            except GateError:
                continue  # unknown id or contention: leave it for the next sweep
            if changed:
                audit.append("dev.execute.needs_review", actor, request_id=rid, claimed_at=seen["from"],
                             payload_hash=req["payload_hash"])
                flagged.append(rid)
        return flagged

    def resolve_review(self, rid: str, approver: str, outcome: str, note: str = "") -> dict:
        """A named human records what really happened to a 'needs_review' request after checking the
        target system. The request ends 'executed' (terminal) either way; it can never run again.
        The proposer and the proposer's owners cannot resolve it (same separation as approval)."""
        if outcome not in ("executed", "failed"):
            raise GateError(422, "outcome must be 'executed' or 'failed'")
        if not isinstance(note, str) or not note.strip():
            raise GateError(422, "a note describing what was checked is required")

        def m(req):
            if req["status"] != "needs_review":
                raise GateError(409, f"request is {req['status']}, not needs_review")
            if not approver or approver == req["proposer"] or approver in (req.get("owners") or []):
                audit.append("dev.self_resolution_rejected", approver, request_id=rid)
                raise GateError(403, "the proposer or its owner cannot resolve its own interrupted request")
            req["status"] = "executed"
            req["resolution"] = {"outcome": outcome, "resolved_by": approver, "resolved_at": self.clock(),
                                 "note": note.strip()[:1000]}
            req["error"] = None if outcome == "executed" else "execution interrupted; human recorded that it failed"
            return True, None
        req, _, _ = self._update(rid, m)
        audit.append("dev.execute.resolved", approver, request_id=rid, outcome=outcome,
                     note=note.strip()[:1000], payload_hash=req["payload_hash"])
        return self._public(req)

    def status(self, rid: str) -> dict:
        return self._public(self._expire_if_due(rid))

    @staticmethod
    def _public(req: dict) -> dict:
        return {k: req[k] for k in ("request_id", "action", "tier", "category", "known", "status",
                                    "approvals_required", "approvals", "payload_hash", "reasons", "expires_at")} | \
            {k: req.get(k) for k in ("destructive", "blast_radius", "advisory")}
