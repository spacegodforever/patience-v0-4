"""PATIENCE integration for the Command Board: auth, CSRF, server-set source, transactional
audit of every write, seed gating, and the advisory label on every response."""
from __future__ import annotations
import contextvars
import hashlib
import json
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.responses import Response

from . import uow

ADVISORY_NOTE = ("Advisory only: Command Board scores, lanes and its 'patience' assessment are "
                 "recommendations. They never replace the PATIENCE policy gate (/v1/check) or a human approval.")
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
_CALLER: contextvars.ContextVar = contextvars.ContextVar("board_caller", default=None)


async def board_caller(request: Request, authorization: Optional[str] = Header(None),
                       x_csrf_token: Optional[str] = Header(None)) -> dict:
    """Same rules as the coordinator: agent key / API token / dev-open via api.require_caller
    (401 when no auth is configured), or an approver session cookie with X-CSRF-Token on writes."""
    from coordinator.routes import coord_caller
    caller = coord_caller(request, authorization, x_csrf_token)
    request.state.board_caller = caller
    _CALLER.set(caller)
    return caller


def caller() -> dict:
    c = _CALLER.get()
    if not c:  # never reachable through the router; fail closed if it is
        raise HTTPException(401, "No authenticated caller.")
    return c


def server_source() -> str:
    c = caller()
    return f"{c['mode']}:{c['id']}"


def require_seed_permission(request: Request, who: dict = Depends(board_caller)) -> dict:
    import api, audit
    if api.dev_open() or who.get("mode") == "session":  # sessions exist only for approvers.yaml accounts
        return who
    audit.append("board.seed_refused", who.get("id"), source=f"{who['mode']}:{who['id']}")
    raise HTTPException(403, "Seeding demo data requires PATIENCE_DEV_OPEN=1 or an approver session.")


class _Lazy:
    """Resolve PATIENCE_BOARD_DB at call time; build each DB (schema init) outside any unit of work."""
    def __init__(self, cls):
        self._cls, self._cache = cls, {}

    def path(self):
        return uow.db_path()

    def _get(self):
        p = uow.db_path()
        key = str(p.resolve()) if p.parent.exists() else str(p)
        if key not in self._cache:
            p.parent.mkdir(parents=True, exist_ok=True)
            with uow.suspended():
                self._cache[key] = self._cls(p)
        return self._cache[key]

    def __getattr__(self, name):
        return getattr(self._get(), name)


_REGISTRY: list = []


def lazy_db(cls):
    lz = _Lazy(cls)
    _REGISTRY.append(lz)
    return lz


def warm_all() -> None:
    """Run every board DB's schema init (own connection, own commit) before a unit of work
    opens, so init never contends with the request's deferred write transaction."""
    for lz in _REGISTRY:
        lz._get()


def _label(resp: Response) -> Response:
    resp.headers["X-Patience-Advisory"] = "true"
    if resp.media_type != "application/json" and not (resp.headers.get("content-type") or "").startswith("application/json"):
        return resp
    try:
        data = json.loads(resp.body)
    except Exception:  # noqa: BLE001
        return resp
    if isinstance(data, dict):
        data["patience_advisory"] = ADVISORY_NOTE
        headers = {k: v for k, v in resp.headers.items() if k.lower() not in ("content-length", "content-type")}
        return JSONResponse(data, status_code=resp.status_code, headers=headers)
    return resp


class AdvisoryRoute(APIRoute):
    def get_route_handler(self):
        orig = super().get_route_handler()

        async def handler(request: Request) -> Response:
            if request.method not in MUTATING:
                return _label(await orig(request))
            import audit
            warm_all()
            work, tok = uow.begin()
            try:
                try:
                    resp = await orig(request)
                except Exception:
                    work.rollback()
                    raise
                if resp.status_code >= 400:
                    work.rollback()
                    return _label(resp)
                who = getattr(request.state, "board_caller", None) or {}
                body = await request.body()
                path = request.url.path
                try:
                    audit.append("board.seed" if path.endswith("/seed") else "board.write", who.get("id"),
                                 method=request.method, path=path, status=resp.status_code,
                                 source=f"{who.get('mode')}:{who.get('id')}",
                                 body_sha256=hashlib.sha256(body).hexdigest())
                except Exception as e:  # noqa: BLE001 - any audit failure refuses the write
                    work.rollback()
                    return JSONResponse({"detail": f"Write refused: audit log unavailable ({type(e).__name__})"},
                                        status_code=503)
                work.commit()
                return _label(resp)
            finally:
                work.close()
                uow.end(tok)

        return handler
