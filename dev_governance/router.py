"""Optional FastAPI router exposing the dev gate (not mounted into api.py on this branch).

Identity here is taken from headers for simulation/testing only; real use must reuse
api.require_caller / api.require_approver.
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from .gate import DevGate, GateError


class ProposeIn(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)
    payload: Dict[str, Any] = Field(default_factory=dict)


class ExecIn(ProposeIn):
    pass


def make_router(gate: Optional[DevGate] = None) -> APIRouter:
    g = gate or DevGate()
    r = APIRouter(prefix="/v1/dev")

    def wrap(fn):
        try:
            return fn()
        except GateError as e:
            raise HTTPException(e.status, e.message)

    @r.post("/check")
    def check(body: ProposeIn, x_patience_user: str = Header(...)):
        return wrap(lambda: g.propose(body.action, body.payload, x_patience_user))

    @r.post("/requests/{rid}/approve")
    def approve(rid: str, x_patience_user: str = Header(...)):
        return wrap(lambda: g.approve(rid, x_patience_user))

    @r.post("/requests/{rid}/execute")
    def execute(rid: str, body: ExecIn, x_patience_user: str = Header(...)):
        code, out = wrap(lambda: g.execute(rid, body.action, body.payload, x_patience_user))
        return JSONResponse(status_code=code, content=out)

    return r
