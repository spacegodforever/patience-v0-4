"""Versioned, strict, machine-readable view of one dev-gate request (`decision-v1`).

READ-ONLY and additive: building a DecisionRecord never writes to the store or the audit log, and
the existing `_public()` response shapes are unchanged. Raw payload values are never included
(only keys and the payload hash). Signed permit strings, claim tokens and grant ids are never
included. Anything the gate cannot establish is listed under `unknowns`, labelled "unknown", rather
than guessed. Confidence exists only where the gate has one (the rule-derived advisory level).
"""
from __future__ import annotations
import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "decision-v1"
STATES = ("allowed", "pending", "approved", "denied", "expired", "executing", "executed", "permit_issued",
          "needs_review")
_REFUSAL_EVENTS = {
    "dev.destructive.refused", "dev.propose.rejected", "dev.self_approval_rejected", "dev.self_resolution_rejected",
    "dev.execute.forbidden", "dev.permit.forbidden", "dev.authority.refused", "dev.permit.refused",
    "dev.payload_mismatch", "dev.kill_switch.blocked", "dev.breaker.held", "dev.denied",
    "dev.execute.denied_attempt", "dev.execute.unapproved_attempt", "dev.expiry.tampered", "dev.expired"}
_SAFE_REASON = re.compile(r"^[A-Za-z0-9_.:\- ]{1,120}$")


class _S(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Unknown(_S):
    item: str
    label: Literal["unknown"] = "unknown"
    source: Literal["advisory", "system"]


class BasisItem(_S):
    kind: Literal["policy_rule", "tier_floor", "destructive_guard", "advisory"]
    detail: str


class PolicyResult(_S):
    tier: str
    category: Optional[str]
    known_action: bool
    approvals_required: int
    destructive: bool
    basis: list[BasisItem]


class ApprovalState(_S):
    required: int
    granted_by: list[str]
    satisfied: bool


class Refusal(_S):
    seq: int
    ts: str
    event: str
    actor: Optional[str]
    reason: Optional[str]


class Execution(_S):
    status: Literal["not_executed", "in_progress", "executed", "failed", "needs_review"]
    simulated: Optional[bool]
    dry_run: Optional[bool]
    error: Optional[str]


class GatewayEvent(_S):
    seq: int
    event: str
    reason_code: Optional[str]


class PermitState(_S):
    issued: bool
    permit_id: Optional[str]
    key_id: Optional[str]
    issued_at: Optional[float]
    expires_at: Optional[float]
    gateway_events: list[GatewayEvent]   # accepted / rejected / executed as recorded by the gateway


class Confidence(_S):
    level: Literal["high", "medium", "low", "not_applicable"]
    source: Literal["rule_derived_advisory", "none"]
    note: str


class TimelineEvent(_S):
    seq: int
    ts: str
    event: str
    actor: Optional[str]
    hash: str


class DecisionRecord(_S):
    schema_version: Literal["decision-v1"]
    request_id: str
    action: str
    proposer: str
    owners: list[str]
    state: Literal["allowed", "pending", "approved", "denied", "expired", "executing", "executed", "permit_issued",
                   "needs_review", "unknown"]
    payload_hash: str
    payload_keys: list[str]
    payload_values: Literal["withheld"]
    policy: PolicyResult
    approvals: ApprovalState
    refusals: list[Refusal]
    execution: Execution
    permit: PermitState
    confidence: Confidence
    what_could_go_wrong: list[str]
    unknowns: list[Unknown]
    created_at: float
    expires_at: float
    timeline: list[TimelineEvent]


def _basis(reasons: list, advisory: Optional[dict]) -> list:
    out = []
    for r in reasons or []:
        r = str(r)
        kind = ("destructive_guard" if r.startswith("destructive") else
                "tier_floor" if ("floor" in r or "raised" in r) else "policy_rule")
        out.append(BasisItem(kind=kind, detail=r[:300]))
    for b in (advisory or {}).get("basis", []) or []:
        out.append(BasisItem(kind="advisory", detail=str(b)[:300]))
    return out


def _data(rec: dict) -> dict:
    d = rec.get("data")
    return d if isinstance(d, dict) else {}


def build_decision(req: dict, audit_records: Optional[list] = None) -> DecisionRecord:
    """`req` is a stored gate request; `audit_records` is the (already loaded) audit log. Pure function."""
    rid = req["request_id"]
    recs = [r for r in (audit_records or []) if isinstance(r, dict) and _data(r).get("request_id") == rid
            and isinstance(r.get("seq"), int) and isinstance(r.get("hash"), str)]
    recs.sort(key=lambda r: r["seq"])
    adv = req.get("advisory") if isinstance(req.get("advisory"), dict) else None
    status = req.get("status")
    unknowns = []
    if adv is None:
        unknowns.append(Unknown(item="advisory report not generated for this request (low tier, no language warning)",
                                source="system"))
    else:
        unknowns += [Unknown(item=str(u)[:300], source="advisory") for u in adv.get("unknowns", [])]
    if status not in STATES:
        unknowns.append(Unknown(item=f"state {str(status)[:40]!r} is not in the known state list", source="system"))
    if audit_records is None:
        unknowns.append(Unknown(item="audit log not consulted: refusals, permit use and timeline are not shown",
                                source="system"))
    refusals = [Refusal(seq=r["seq"], ts=str(r.get("ts")), event=str(r.get("event")), actor=r.get("actor"),
                        reason=(lambda v: v if isinstance(v, str) and _SAFE_REASON.match(v) else None)(_data(r).get("reason")))
                for r in recs if r.get("event") in _REFUSAL_EVENTS]
    issued = [r for r in recs if r.get("event") == "dev.permit.issued"]
    p = _data(issued[-1]) if issued else {}
    permit_info = req.get("permit") if isinstance(req.get("permit"), dict) else {}
    permit = PermitState(
        issued=bool(issued or permit_info or status == "permit_issued"),
        permit_id=p.get("permit_id") or permit_info.get("jti"), key_id=p.get("key_id") or permit_info.get("kid"),
        issued_at=p.get("issued_at") or permit_info.get("iat"), expires_at=p.get("expires_at") or permit_info.get("exp"),
        gateway_events=[GatewayEvent(seq=r["seq"], event=str(r["event"]),
                                     reason_code=(lambda v: v if isinstance(v, str) and _SAFE_REASON.match(v) else None)(_data(r).get("reason_code")))
                        for r in recs if str(r.get("event", "")).startswith("gateway.")])
    last_exec = [r for r in recs if r.get("event") in ("dev.executed", "dev.execute.failed")]
    ed = _data(last_exec[-1]) if last_exec else {}
    err = req.get("error") if isinstance(req.get("error"), str) else None
    if status == "executing":
        exe = "in_progress"
    elif status == "needs_review":
        exe = "needs_review"
    elif status == "executed" and err is None:
        exe = "executed"
    elif err is not None:
        exe = "failed"
    else:
        exe = "not_executed"
    if exe in ("executed", "failed") and not last_exec:
        unknowns.append(Unknown(item="no execute event found in the audit log for this request", source="system"))
    execution = Execution(status=exe, simulated=ed.get("simulated") if isinstance(ed.get("simulated"), bool) else None,
                          dry_run=ed.get("dry_run") if isinstance(ed.get("dry_run"), bool) else None,
                          error=(err[:200] if err else None))
    lvl = adv.get("confidence") if adv else None
    conf = (Confidence(level=lvl, source="rule_derived_advisory",
                       note="derived from the number of unknowns in the advisory; not a probability")
            if lvl in ("high", "medium", "low") else
            Confidence(level="not_applicable", source="none", note="the gate has no confidence value for this request"))
    approvals = list(req.get("approvals") or [])
    need = int(req.get("approvals_required") or 0)
    return DecisionRecord(
        schema_version=SCHEMA_VERSION, request_id=rid, action=str(req["action"]), proposer=str(req["proposer"]),
        owners=[str(o) for o in (req.get("owners") or [])], state=status if status in STATES else "unknown",
        payload_hash=str(req["payload_hash"]), payload_keys=sorted(str(k) for k in (req.get("payload") or {})),
        payload_values="withheld",
        policy=PolicyResult(tier=str(req["tier"]), category=req.get("category"), known_action=bool(req.get("known")),
                            approvals_required=need, destructive=bool(req.get("destructive")),
                            basis=_basis(req.get("reasons"), adv)),
        approvals=ApprovalState(required=need, granted_by=[str(a) for a in approvals],
                                satisfied=len(set(approvals)) >= need),
        refusals=refusals, execution=execution, permit=permit, confidence=conf,
        what_could_go_wrong=[str(x)[:300] for x in (adv or {}).get("what_could_go_wrong", [])],
        unknowns=unknowns, created_at=float(req["created_at"]), expires_at=float(req["expires_at"]),
        timeline=[TimelineEvent(seq=r["seq"], ts=str(r.get("ts")), event=str(r.get("event")), actor=r.get("actor"),
                                hash=r["hash"]) for r in recs])


def export_decision(gate, rid: str, include_audit: bool = True) -> dict:
    """Read-only JSON export for one request. Applies the gate's expiry check like `status()` does
    (same behaviour as GET /requests/{rid}); writes nothing else."""
    import audit
    req = gate._expire_if_due(rid)
    recs = audit.read() if include_audit else None
    return build_decision(req, recs).model_dump(mode="json")


def json_schema() -> dict:
    return DecisionRecord.model_json_schema()
