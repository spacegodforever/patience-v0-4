"""FastAPI router for the dev gate, mounted by api.py at /v1/dev.

Identity comes ONLY from injected dependencies (api.require_caller / api.require_approver).
There is no identity header: the old X-Patience-User test header was removed.
"""
from __future__ import annotations
from typing import Any, Callable, Dict
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from .gate import DevGate, GateError


class ProposeIn(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)
    payload: Dict[str, Any] = Field(default_factory=dict)


class DecideIn(BaseModel):
    reason: str = Field("", max_length=1000)


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

    @r.post("/check")
    def check(body: ProposeIn, caller: dict = Depends(caller_dep)):
        return _run(lambda: gate_factory().propose(body.action, body.payload, caller["id"],
                                                   owners=owners_of(caller),
                                                   require_owners=caller.get("mode") != "dev"))

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

    @r.get("/breaker/{agent}")
    def breaker_status(agent: str, caller: dict = Depends(caller_dep)):
        return _run(lambda: gate_factory().breaker_status(agent))

    @r.post("/breaker/{agent}/reset")
    def breaker_reset(agent: str, body: DecideIn = DecideIn(), who: dict = Depends(approver_dep)):
        return _run(lambda: gate_factory().reset_breaker(agent, who["user"], body.reason))

    return r
