"""FastAPI router for the dev gate, mounted by api.py at /v1/dev.

Identity comes ONLY from injected dependencies (api.require_caller / api.require_approver).
There is no identity header: the old X-Patience-User test header was removed.
"""
from __future__ import annotations
from typing import Any, Callable, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from .gate import DevGate, GateError


class ProposeIn(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)
    payload: Dict[str, Any] = Field(default_factory=dict)
    text: Optional[str] = Field(None, max_length=4000)
    authority_grant: Optional[str] = Field(None, max_length=100)


class DecideIn(BaseModel):
    reason: str = Field("", max_length=1000)


class ResolveIn(BaseModel):
    outcome: str = Field(..., pattern="^(executed|failed)$")
    note: str = Field(..., min_length=1, max_length=1000)


class ReconcileIn(BaseModel):
    min_age_seconds: float = Field(300, ge=0, le=86400 * 30)


def _run(fn):
    try:
        return fn()
    except GateError as e:
        raise HTTPException(e.status, e.message)


def owners_of(caller: dict) -> list:
    """Human approvers responsible for a caller (RT-03).

    agent mode: agents.yaml entry `owners: [..]` or `owner: name`.
    token mode: PATIENCE_API_TOKEN_OWNERS (comma-separated) - a shared token is attributable only
    to whoever holds it. The caller id itself is always included (same-string self-approval).
    """
    import os
    raw = caller.get("owners") or caller.get("owner") or []
    if isinstance(raw, str):
        raw = [raw]
    out = [str(x) for x in raw]
    if caller.get("mode") == "token":
        out += [x for x in os.environ.get("PATIENCE_API_TOKEN_OWNERS", "").split(",")]
    return [x.strip() for x in out if x and x.strip()]


def make_router(gate_factory: Callable[[], DevGate], caller_dep: Callable, approver_dep: Callable) -> APIRouter:
    r = APIRouter(prefix="/v1/dev")
    base_approver = approver_dep

    def approver_dep(who: dict = Depends(base_approver)) -> dict:  # noqa: F811
        """RT-13: the deprecated shared legacy token is never accepted on dev-governance routes
        (approve/deny/breaker reset); a named per-user approver account is required."""
        if who.get("legacy"):
            import audit
            audit.append("auth.legacy_token_refused", who.get("user"), channel="api", scope="dev")
            raise HTTPException(403, "The legacy shared approver token is not accepted for dev actions; "
                                     "use a named approvers.yaml account.")
        return who

    @r.post("/check")
    def check(body: ProposeIn, caller: dict = Depends(caller_dep)):
        from .threat import assess as _threat  # RT-11: server-side floor; never client-supplied
        t = _threat(body.action, body.text, body.payload)
        return _run(lambda: gate_factory().propose(body.action, body.payload, caller["id"],
                                                   floor=t["floor"],
                                                   owners=owners_of(caller),
                                                   require_owners=caller.get("mode") != "dev",
                                                   text=body.text, authority_grant=body.authority_grant))

    @r.get("/requests/{rid}")
    def status(rid: str, caller: dict = Depends(caller_dep)):
        return _run(lambda: gate_factory().status(rid))

    @r.post("/requests/{rid}/approve")
    def approve(rid: str, body: DecideIn = DecideIn(), who: dict = Depends(approver_dep)):
        return _run(lambda: gate_factory().approve(rid, who["user"], body.reason))

    @r.post("/requests/{rid}/deny")
    def deny(rid: str, body: DecideIn = DecideIn(), who: dict = Depends(approver_dep)):
        return _run(lambda: gate_factory().deny(rid, who["user"], body.reason))

    @r.post("/requests/{rid}/execute")
    def execute(rid: str, body: ProposeIn, caller: dict = Depends(caller_dep)):
        code, out = _run(lambda: gate_factory().execute(rid, body.action, body.payload, caller["id"]))
        return JSONResponse(status_code=code, content=out)

    @r.post("/admin/reconcile")
    def reconcile(body: ReconcileIn = ReconcileIn(), who: dict = Depends(approver_dep)):
        """Flag requests stuck in 'executing' as 'needs_review'. Never retries anything."""
        flagged = _run(lambda: gate_factory().flag_stuck_executions(who["user"], body.min_age_seconds))
        return {"flagged": flagged}

    @r.post("/requests/{rid}/resolve")
    def resolve(rid: str, body: ResolveIn, who: dict = Depends(approver_dep)):
        return _run(lambda: gate_factory().resolve_review(rid, who["user"], body.outcome, body.note))

    @r.get("/breaker/{agent}")
    def breaker_status(agent: str, caller: dict = Depends(caller_dep)):
        return _run(lambda: gate_factory().breaker_status(agent))

    @r.post("/breaker/{agent}/reset")
    def breaker_reset(agent: str, body: DecideIn = DecideIn(), who: dict = Depends(approver_dep)):
        return _run(lambda: gate_factory().reset_breaker(agent, who["user"], body.reason))

    return r
