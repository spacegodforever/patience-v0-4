"""Memory records, devices and the capability permission registry."""
from __future__ import annotations
import hashlib
import hmac
import json
import secrets
import uuid
from typing import Optional

import audit
from models import now_iso
from .contract import MemoryRecordIn, RECORD_FIELDS
from .db import tx

MAX_LEVEL = 4
LEVELS = {0: "suggest only", 1: "draft for review", 2: "act on approval", 3: "act within policy limits",
          4: "act with post-hoc review"}


class PermissionError_(Exception):
    pass


def _row(r) -> dict:
    d = {k: r[k] for k in RECORD_FIELDS}
    d["review_required"] = bool(d["review_required"])
    d["provenance"] = json.loads(r["provenance"])
    d["sharing_scope"] = r["sharing_scope"]
    return d


# ---------------- memory records ----------------
def write_record(con, rec: MemoryRecordIn, owner: str, device_id: Optional[str]) -> dict:
    now = now_iso()
    mid = "mem_" + uuid.uuid4().hex
    prov = {"actor": owner, "device_id": device_id, "source": rec.source, "at": now}
    with tx(con):
        con.execute("INSERT INTO memory_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (mid, rec.record_type.value, rec.content, rec.source, rec.confidence,
                     rec.classification.value, rec.sharing_scope.value, rec.project_id, now, now, 1,
                     int(rec.review_required), rec.expires_at, json.dumps(prov), owner))
        audit.append("memory.written", owner, memory_id=mid, record_type=rec.record_type.value,
                     sharing_scope=rec.sharing_scope.value, device_id=device_id,
                     content_sha256=hashlib.sha256(rec.content.encode()).hexdigest())
    return get_record(con, mid)


def get_record(con, mid: str) -> Optional[dict]:
    r = con.execute("SELECT * FROM memory_records WHERE memory_id=?", (mid,)).fetchone()
    return _row(r) if r else None


def list_records(con, owner: str) -> list:
    return [_row(r) for r in con.execute(
        "SELECT * FROM memory_records WHERE owner=? ORDER BY created_at", (owner,))]


# ---------------- devices ----------------
def _h(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()


def register_device(con, owner: str, label: Optional[str], approver: str) -> tuple[str, str]:
    did = "dev_" + uuid.uuid4().hex[:16]
    key = "pdk_" + secrets.token_urlsafe(32)  # returned once, stored hashed
    with tx(con):
        con.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,NULL,NULL)",
                    (did, owner, label, _h(key), approver, now_iso()))
        audit.append("device.registered", approver, device_id=did, owner=owner, label=label)
    return did, key


def revoke_device(con, did: str, approver: str) -> bool:
    with tx(con):
        n = con.execute("UPDATE devices SET revoked_at=?, revoked_by=? WHERE device_id=? AND revoked_at IS NULL",
                        (now_iso(), approver, did)).rowcount
        if n:
            audit.append("device.revoked", approver, device_id=did)
    return bool(n)


def resolve_device(con, did: Optional[str], key: Optional[str]) -> Optional[dict]:
    """Registered, non-revoked device whose key matches; else None (fail closed)."""
    if not did or not key:
        return None
    r = con.execute("SELECT * FROM devices WHERE device_id=?", (did,)).fetchone()
    if not r or r["revoked_at"] or not hmac.compare_digest(r["key_sha256"], _h(key)):
        return None
    return dict(r)


# ---------------- permission registry ----------------
def grant(con, capability: str, subject: str, level: int, approver: dict, reason: str = "") -> dict:
    """Grant an autonomy level. Only a human approver may grant; never to themselves."""
    who = approver.get("user")
    if approver.get("role") not in ("approver", "admin") or not who:
        raise PermissionError_("only an approver may grant autonomy")
    if subject in (who, f"user:{who}"):
        audit.append("capability.grant_refused", who, capability=capability, subject=subject,
                     level=level, why="self-grant")
        raise PermissionError_("self-grant is not allowed")
    if not isinstance(level, int) or isinstance(level, bool) or not 0 <= level <= MAX_LEVEL:
        raise PermissionError_("level must be an integer 0-4")
    with tx(con):
        con.execute("INSERT INTO capability_events (capability,subject,kind,level,actor,at,reason) "
                    "VALUES (?,?,?,?,?,?,?)", (capability, subject, "grant", level, who, now_iso(), reason))
        audit.append("capability.granted", who, capability=capability, subject=subject, level=level, reason=reason)
    return effective(con, capability, subject)


def revoke(con, capability: str, subject: str, actor: str, reason: str = "") -> dict:
    """Anyone authenticated as an approver, or the subject itself, may revoke (lowering is always safe)."""
    with tx(con):
        con.execute("INSERT INTO capability_events (capability,subject,kind,level,actor,at,reason) "
                    "VALUES (?,?,?,NULL,?,?,?)", (capability, subject, "revoke", actor, now_iso(), reason))
        audit.append("capability.revoked", actor, capability=capability, subject=subject, reason=reason)
    return effective(con, capability, subject)


def effective(con, capability: str, subject: str) -> dict:
    """Latest event decides; a revoke at the same timestamp as a grant wins; no grant = level 0."""
    rows = con.execute("SELECT * FROM capability_events WHERE capability=? AND subject=? ORDER BY id",
                       (capability, subject)).fetchall()
    if not rows:
        return {"capability": capability, "subject": subject, "level": 0, "state": "none"}
    last = rows[-1]
    same_tick_revoke = any(r["kind"] == "revoke" and r["at"] == last["at"] for r in rows)
    if last["kind"] == "revoke" or same_tick_revoke:
        return {"capability": capability, "subject": subject, "level": 0, "state": "revoked"}
    return {"capability": capability, "subject": subject, "level": last["level"], "state": "granted",
            "granted_by": last["actor"]}
