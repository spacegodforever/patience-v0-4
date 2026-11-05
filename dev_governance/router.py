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


def make_router(gate_factory: Callable[[], DevGate], caller_dep: Callable, approver_dep: Callable) -> APIRouter:
    r = APIRouter(prefix="/v1/dev")

    @r.post("/check")
    def check(body: ProposeIn, caller: dict = Depends(caller_dep)):
        return _run(lambda: gate_factory().propose(body.action, body.payload, caller["id"]))

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

    return r
