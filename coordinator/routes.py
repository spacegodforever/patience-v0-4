"""/v1/coordinator/* routes, mounted on api.app.

Auth: either the normal API caller (api.require_caller: agent key / API token / dev-open), or a
local browser session created from an approvers.yaml account. Sessions use an HttpOnly,
SameSite=Strict cookie; every mutating request on a session must carry X-CSRF-Token.
Identity and `source` are always derived server-side from the authenticated caller.
"""
from __future__ import annotations
import hmac
import os
import secrets
import time
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field
from . import llm, policy, store

router = APIRouter(prefix="/v1/coordinator", tags=["coordinator"])
COOKIE = "patience_coord_session"
SESSION_TTL = int(os.environ.get("PATIENCE_COORD_SESSION_TTL", "28800"))
_SESSIONS: Dict[str, dict] = {}
MUTATING = {"POST", "PATCH", "PUT", "DELETE"}


def _api():
    import api  # lazy: api imports this module at the end of its own import
    return api


def _session(request: Request) -> Optional[dict]:
    tok = request.cookies.get(COOKIE)
    s = _SESSIONS.get(tok or "")
    if s and s["exp"] < time.time():
        _SESSIONS.pop(tok, None)
        return None
    return s


def coord_caller(request: Request, authorization: Optional[str] = Header(None),
                 x_csrf_token: Optional[str] = Header(None)) -> dict:
    s = _session(request)
    if s:
        if request.method in MUTATING and not (x_csrf_token and hmac.compare_digest(x_csrf_token, s["csrf"])):
            raise HTTPException(403, "CSRF token missing or invalid.")
        return {"id": f"user:{s['user']}", "mode": "session", "user": s["user"]}
    if request.cookies.get(COOKIE) and not authorization:
        raise HTTPException(401, "Session expired or unknown; log in again.")
    caller = _api().require_caller(authorization)  # fail closed when no auth is configured
    if (caller["mode"] == "dev" and request.method in MUTATING
            and not (request.headers.get("content-type") or "").startswith("application/json")):
        raise HTTPException(415, "JSON body required.")
    return caller


def source_of(caller: dict) -> str:
    return f"{caller['mode']}:{caller['id']}"


def _write(fn, *a):
    try:
        return fn(*a)
    except store.AuditUnavailable as e:
        raise HTTPException(503, f"Write refused: {e}")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except LookupError as e:
        raise HTTPException(404, str(e))


# ---------- session ----------
class LoginIn(BaseModel):
    user: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=500)


@router.post("/session")
def login(body: LoginIn, request: Request, response: Response):
    a = _api()
    import approvers, audit
    ip = a._client_ip(request)
    if a._auth_locked(ip, body.user):
        raise HTTPException(429, "Too many failed attempts; try again later.")
    who = approvers.verify_password(body.user, body.password)
    if not who:
        a._ip_fail(ip)
        audit.append("auth.failed", body.user[:100], channel="coordinator")
        raise HTTPException(403, "Invalid credentials.")
    tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    audit.append("coord.session.create", who["user"], channel="coordinator")
    _SESSIONS[tok] = {"user": who["user"], "role": who.get("role"), "csrf": csrf, "exp": time.time() + SESSION_TTL}
    response.set_cookie(COOKIE, tok, httponly=True, samesite="strict", max_age=SESSION_TTL, path="/v1/coordinator",
                        secure=os.environ.get("PATIENCE_COORD_SECURE_COOKIE") == "1")
    return {"user": who["user"], "csrf_token": csrf}


@router.delete("/session")
def logout(request: Request, response: Response, caller: dict = Depends(coord_caller)):
    tok = request.cookies.get(COOKIE)
    if tok:
        _SESSIONS.pop(tok, None)
    response.delete_cookie(COOKIE, path="/v1/coordinator")
    return {"ok": True}


# ---------- read ----------
@router.get("/health")
def health(caller: dict = Depends(coord_caller)):
    return {"status": "online", "mode": "local-first", "ollama_available": llm.available() if llm.model() else False,
            "ollama_model": llm.model() or None, "caller": source_of(caller)}


@router.get("/projects")
def projects(caller: dict = Depends(coord_caller)):
    return store.list_projects()


@router.get("/events")
def events(caller: dict = Depends(coord_caller)):
    return store.list_events()


@router.get("/previews")
def previews(caller: dict = Depends(coord_caller)):
    return store.list_previews()


# ---------- write ----------
class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    priority: str = "medium"
    next_step: str = Field("", max_length=1000)


class StatusIn(BaseModel):
    status: str


class EventIn(BaseModel):  # no `source` field: it is derived from the caller
    kind: str = "note"
    title: str = Field(min_length=1, max_length=180)
    detail: str = Field("", max_length=4000)

    model_config = {"extra": "ignore"}


@router.post("/projects")
def add_project(item: ProjectIn, caller: dict = Depends(coord_caller)):
    return _write(store.add_project, item.name, item.priority, item.next_step, source_of(caller), caller["id"])


@router.patch("/projects/{pid}")
def update_project(pid: int, body: StatusIn, caller: dict = Depends(coord_caller)):
    return _write(store.set_status, pid, body.status, source_of(caller), caller["id"])


@router.post("/events")
def add_event(item: EventIn, caller: dict = Depends(coord_caller)):
    return _write(store.add_event, item.kind, item.title, item.detail, source_of(caller), caller["id"])


@router.get("/recommendation")
def recommendation(caller: dict = Depends(coord_caller)):
    import audit
    ps, es = store.list_projects(), store.list_events(12)
    det = policy.recommend(ps)
    sug = llm.suggest(policy.rank(ps), es)
    try:
        audit.append("coord.recommend", caller["id"], mode="ollama-local" if sug["used"] else "deterministic-local",
                     model=sug["model"], llm_error=sug["llm_error"], observed_projects=det["observed_projects"])
    except Exception as e:  # noqa: BLE001
        raise HTTPException(503, f"Refused: audit log unavailable ({type(e).__name__})")
    return {**det, "mode": "ollama-local" if sug["used"] else "deterministic-local",
            "llm_suggestion": {"text": sug["text"], "model": sug["model"], "unverified": True,
                               "note": "Model output; not verified and not covered by basis/confidence."}
            if sug["used"] else None,
            "llm_error": sug["llm_error"],
            "proposed_action": {"type": "human_review", "status": "preview_only",
                                "description": "Review this recommendation; no action has been taken."}}


class PreviewIn(BaseModel):
    tool: str = Field(min_length=1, max_length=100)
    args: Dict[str, Any] = Field(default_factory=dict)
    context: Optional[str] = Field(None, max_length=4000)
    project_id: Optional[int] = None


def _known_tool(tool: str) -> bool:
    import risk_policy
    p = risk_policy.get_policy()
    t = tool.strip().lower()
    return t in p.tools or any(t.startswith(x) for x in p.raw.get("read_only_tool_prefixes", []))


@router.post("/previews")
def submit_preview(body: PreviewIn, caller: dict = Depends(coord_caller)):
    """Submit a proposed action to the approval gate. Never executes it."""
    a = _api()
    try:
        known = _known_tool(body.tool)
    except Exception as e:  # noqa: BLE001 - unreadable policy: fail closed
        raise HTTPException(503, f"Refused: risk policy unavailable ({type(e).__name__})")
    req = a._check_impl(a.CheckIn(tool=body.tool, args=body.args, context=body.context,
                                  metadata={"via": "coordinator"}), caller)
    decision = req["decision"]
    if not known and decision == "allow":  # belt and braces: the gate should already require approval
        decision = "needs_approval"
    rec = {**req, "decision": decision}
    row = _write(store.add_preview, body.project_id, rec, source_of(caller), caller["id"])
    return {"preview_id": row["id"], "request_id": req["request_id"], "decision": decision,
            "known_tool": known, "preview": req["preview"], "executed": False,
            "next": "Approve via /v1/requests/{id}/approve, then the agent calls /v1/execute."}
