"""HTTP surface for the memory foundation. Mounted by api.py."""
from __future__ import annotations
import json
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import store
from .contract import MemoryRecordIn
from .db import connect


class DeviceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: str = Field(min_length=1, max_length=200)
    label: Optional[str] = Field(None, max_length=200)



class GrantIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    subject: str = Field(min_length=1, max_length=200)
    level: int
    reason: str = Field("", max_length=1000)



class RevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=200)
    reason: str = Field("", max_length=1000)



class InvokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    args: Dict[str, Any] = {}
    context: Optional[str] = Field(None, max_length=8000)


def build_router(require_caller, require_approver, check_impl, CheckIn) -> APIRouter:
    r = APIRouter(prefix="/v1")

    def _device(con, did, key, caller):
        if did is None and key is None:
            return None
        d = store.resolve_device(con, did, key)
        if not d:
            raise HTTPException(403, "Unknown or revoked device.")
        if d["owner"] != caller["id"]:
            raise HTTPException(403, "Device belongs to another identity.")
        return d

    @r.post("/memory/records")
    def write(body: Dict[str, Any], caller: dict = Depends(require_caller),
              x_device_id: Optional[str] = Header(None), x_device_key: Optional[str] = Header(None)):
        try:
            rec = MemoryRecordIn.model_validate_json(json.dumps(body))
        except ValidationError as e:  # fail closed on unknown class/scope/fields
            raise HTTPException(422, [err["msg"] for err in e.errors()])
        con = connect()
        try:
            d = _device(con, x_device_id, x_device_key, caller)
            return store.write_record(con, rec, caller["id"], d["device_id"] if d else None)
        finally:
            con.close()

    @r.get("/memory/records")
    def list_(caller: dict = Depends(require_caller)):
        con = connect()
        try:
            return {"records": store.list_records(con, caller["id"])}
        finally:
            con.close()

    @r.post("/devices")
    def register(body: DeviceIn, who: dict = Depends(require_approver)):
        con = connect()
        try:
            did, key = store.register_device(con, body.owner, body.label, who["user"])
            return {"device_id": did, "device_key": key, "note": "key shown once"}
        finally:
            con.close()

    @r.post("/devices/{did}/revoke")
    def revoke_dev(did: str, who: dict = Depends(require_approver)):
        con = connect()
        try:
            if not store.revoke_device(con, did, who["user"]):
                raise HTTPException(404, "No active device with that id.")
            return {"device_id": did, "revoked": True}
        finally:
            con.close()

    @r.post("/capabilities/{cap}/grant")
    def grant(cap: str, body: GrantIn, who: dict = Depends(require_approver)):
        con = connect()
        try:
            return store.grant(con, cap, body.subject, body.level, who, body.reason)
        except store.PermissionError_ as e:
            raise HTTPException(403, str(e))
        finally:
            con.close()

    @r.post("/capabilities/{cap}/revoke")
    def revoke_cap(cap: str, body: RevokeIn, who: dict = Depends(require_approver)):
        con = connect()
        try:
            return store.revoke(con, cap, body.subject, who["user"], body.reason)
        finally:
            con.close()

    @r.post("/capabilities/{cap}/self-revoke")
    def self_revoke(cap: str, caller: dict = Depends(require_caller)):
        """An agent may always lower its own autonomy; it can never raise it (no grant route for callers)."""
        con = connect()
        try:
            return store.revoke(con, cap, caller["id"], caller["id"], "self-revoke")
        finally:
            con.close()

    @r.get("/capabilities/{cap}/level")
    def level(cap: str, caller: dict = Depends(require_caller)):
        con = connect()
        try:
            return store.effective(con, cap, caller["id"])
        finally:
            con.close()

    @r.post("/capabilities/{cap}/request")
    def request(cap: str, body: InvokeIn, caller: dict = Depends(require_caller)):
        """Ask to use a capability. Autonomy level never bypasses the gate: every level,
        including 4, is routed through /v1/check; nothing executes here."""
        con = connect()
        try:
            eff = store.effective(con, cap, caller["id"])
        finally:
            con.close()
        if eff["level"] < 1:
            raise HTTPException(403, f"No autonomy granted for '{cap}' ({eff['state']}).")
        res = check_impl(CheckIn(tool=cap, args=body.args, context=body.context), caller)
        return {"autonomy": eff, "gate": res}

    return r
