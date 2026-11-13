"""Source registry (allowlist). A source must be registered by a named approver before anything can be
ingested from it; each source lists who may ingest into and read from it."""
from __future__ import annotations
import json
import os
import re
from typing import Optional
from urllib.parse import urlsplit

from .common import IntelError, audit_required, sha, utc_iso, Clock
from .store import Store

CATEGORIES = ("public_market", "public_filings", "internal_docs")
KINDS = ("file_upload", "manual", "public_api")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.()\-]{2,79}$")


def api_hosts() -> frozenset:
    return frozenset(h.strip().lower() for h in os.environ.get("PATIENCE_INTEL_API_HOSTS", "").split(",") if h.strip())


def _refuse(actor, code: str, msg: str, status: int = 422):
    try:
        audit_required("intel.source.refused", actor, reason=code)
    finally:
        raise IntelError(status, msg, code)


def register_source(store: Store, *, actor: str, name: str, category: str, kind: str, description: str,
                    license_note: str, allowed_callers: list, uri: Optional[str] = None, clock: Clock) -> dict:
    """`actor` is the authenticated named approver (taken from auth, never from the request body)."""
    if not actor:
        raise IntelError(403, "a named approver is required to register a source", "approver_required")
    if not isinstance(name, str) or not NAME_RE.match(name):
        _refuse(actor, "bad_name", "name must be 3-80 chars: letters, digits, space, _ . ( ) -")
    if category not in CATEGORIES:
        _refuse(actor, "bad_category", f"category must be one of {', '.join(CATEGORIES)}")
    if kind not in KINDS:
        _refuse(actor, "bad_kind", f"kind must be one of {', '.join(KINDS)}")
    if not isinstance(description, str) or not (1 <= len(description.strip()) <= 500):
        _refuse(actor, "bad_description", "description must be 1-500 chars")
    if not isinstance(license_note, str) or not (3 <= len(license_note.strip()) <= 500):
        _refuse(actor, "license_required",
                "a license/authorization note (3-500 chars) is required: state why this source may be used")
    if not isinstance(allowed_callers, list) or not (1 <= len(allowed_callers) <= 20) or \
            any(not isinstance(c, str) or not (1 <= len(c.strip()) <= 100) for c in allowed_callers):
        _refuse(actor, "bad_allowed_callers", "allowed_callers must be 1-20 caller ids (or ['*'] explicitly)")
    callers = sorted({c.strip() for c in allowed_callers})
    if kind == "public_api":
        u = urlsplit(uri or "")
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.hostname.lower() not in api_hosts():
            _refuse(actor, "api_host_not_allowlisted",
                    "public_api sources must be https and the host must be in PATIENCE_INTEL_API_HOSTS (empty by default)")
        uri = f"https://{u.hostname.lower()}{u.path}"[:300]
    elif uri:
        _refuse(actor, "uri_not_allowed", "uri is only accepted for public_api sources")
    sid = "src_" + sha(name.strip().lower())[:12]
    with store.transaction() as c:
        if c.execute("SELECT 1 FROM intelligence_sources WHERE source_id=? OR name=?", (sid, name.strip())).fetchone():
            raise IntelError(409, "a source with this name already exists", "duplicate_source")
        c.execute("INSERT INTO intelligence_sources (source_id, name, category, kind, uri, description, license_note, "
                  "authorized_by, allowed_callers, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,?,1,?)",
                  (sid, name.strip(), category, kind, uri, description.strip(), license_note.strip(), actor,
                   json.dumps(callers), utc_iso(clock())))
        audit_required("intel.source.registered", actor, source_id=sid, category=category, kind=kind,
                       allowed_callers=callers, uri_host=(urlsplit(uri).hostname if uri else None))
    return get_source(store, sid)


def _row(r) -> dict:
    return {"source_id": r[0], "name": r[1], "category": r[2], "kind": r[3], "uri": r[4], "description": r[5],
            "license_note": r[6], "authorized_by": r[7], "allowed_callers": json.loads(r[8]), "enabled": bool(r[9]),
            "created_at": r[10]}


_COLS = ("source_id, name, category, kind, uri, description, license_note, authorized_by, allowed_callers, "
         "enabled, created_at")


def get_source(store: Store, source_id: str) -> dict:
    rows = store.query(f"SELECT {_COLS} FROM intelligence_sources WHERE source_id=?", (source_id,))
    if not rows:
        raise IntelError(404, "unknown source", "unknown_source")
    return _row(rows[0])


def list_sources(store: Store, caller: Optional[str] = None) -> list:
    out = [_row(r) for r in store.query(f"SELECT {_COLS} FROM intelligence_sources ORDER BY source_id")]
    return [s for s in out if caller is None or can_access(s, caller)]


def can_access(source: dict, caller: str) -> bool:
    return bool(source["enabled"]) and ("*" in source["allowed_callers"] or caller in source["allowed_callers"])
