"""The one integration point: a validated recommendation becomes an ordinary gate PROPOSAL.

`propose_recommendation` calls `DevGate.propose` and nothing else on the gate: never approve, deny,
execute, issue a permit, or use a capability grant. The payload is supplied by the caller (the Oracle
does not invent payloads in step 1), and the proposal is subject to the same policy, ambiguity,
destructive guard, approval and payload-hash binding as any other proposal. The capped, raise-only
risk hint is passed as the gate's existing `floor` argument (policy.assess applies raise_only).
"""
from __future__ import annotations
from typing import Optional

import audit
from .schema import NON_ACTIONS
from .service import AdviceResult, ORACLE_EXCLUDED_ACTIONS


class RoutingRefused(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def propose_recommendation(gate, result: AdviceResult, payload: dict, proposer: str,
                           owners: Optional[list] = None, require_owners: bool = False,
                           text: Optional[str] = None) -> dict:
    """Route `result` to gate.propose(). Raises RoutingRefused (and audits) if there is nothing valid to
    route; GateError from the gate propagates unchanged (the gate's refusal is final)."""
    def refuse(reason: str):
        audit.append("oracle.recommendation.route_refused", proposer or None, rec_id=getattr(result, "rec_id", None),
                     reason=reason)
        raise RoutingRefused(reason)

    if not isinstance(result, AdviceResult) or not result.ok or result.recommendation is None:
        refuse("no_valid_recommendation")
    rec = result.recommendation
    if rec.action in NON_ACTIONS:
        refuse("non_action")
    if rec.action in ORACLE_EXCLUDED_ACTIONS:
        refuse("action_excluded")
    if not proposer or not isinstance(proposer, str):
        refuse("proposer_required")
    if not isinstance(payload, dict):
        refuse("payload_required")
    out = gate.propose(rec.action, payload, proposer, floor=result.risk_floor_applied, owners=owners,
                       require_owners=require_owners, text=text)
    audit.append("oracle.recommendation.routed", proposer, rec_id=result.rec_id, request_id=out.get("request_id"),
                 action=rec.action, payload_hash=out.get("payload_hash"), tier=out.get("tier"),
                 status=out.get("status"), risk_floor_applied=result.risk_floor_applied)
    return out
