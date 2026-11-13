"""FastAPI router for Oracle Intelligence, mounted by api.py at /v1/intel.

Identity comes only from the injected dependencies (api.require_caller / api.require_approver); there is
no identity header or body field. Reads and ingestion need an authenticated caller who is on the
source's allowed_callers list; registering a source needs a named approver account. Nothing here can
approve, execute or change policy.
"""
from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from . import connectors, ingest as _ingest, inquiry as _inquiry, sec_edgar as _edgar, sources as _sources
from .common import IntelError
from .report import to_markdown
from .store import Store


class SourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., max_length=80)
    category: str = Field(..., max_length=30)
    kind: str = Field(..., max_length=20)
    description: str = Field(..., max_length=500)
    license_note: str = Field(..., max_length=500)
    allowed_callers: List[str] = Field(..., max_length=20)
    uri: Optional[str] = Field(None, max_length=300)


class IngestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: str = Field(..., max_length=10)
    content: str = Field(..., max_length=2_100_000)
    title: Optional[str] = Field(None, max_length=200)
    published_at: Optional[str] = Field(None, max_length=40)
    doc_type: Optional[str] = Field(None, max_length=30)


class EdgarSourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., max_length=80)
    allowed_callers: List[str] = Field(..., max_length=20)


class EdgarLiveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class EdgarFetchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cik: str = Field(..., max_length=10)
    dataset: str = Field(..., max_length=20)


class InquiryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(..., max_length=1000)
    source_ids: Optional[List[str]] = Field(None, max_length=50)
    since: Optional[str] = Field(None, max_length=40)
    until: Optional[str] = Field(None, max_length=40)


def _run(fn):
    try:
        return fn()
    except IntelError as e:
        raise HTTPException(e.status, e.message)


def make_router(store_factory: Callable[[], Store], caller_dep: Callable, approver_dep: Callable,
                clock: Optional[Callable[[], float]] = None, model_factory: Optional[Callable[[], Any]] = None,
                connector_factory: Optional[Callable[[], Any]] = None,
                edgar_connector_factory: Optional[Callable[[], Any]] = None) -> APIRouter:
    import time
    clk = clock or time.time
    r = APIRouter(prefix="/v1/intel")
    base_approver = approver_dep

    def approver_dep(who: dict = Depends(base_approver)) -> dict:  # noqa: F811
        if who.get("legacy"):
            raise HTTPException(403, "The legacy shared approver token is not accepted; use a named approvers.yaml account.")
        return who

    @r.post("/sources")
    def register(body: SourceIn, who: dict = Depends(approver_dep)):
        return _run(lambda: _sources.register_source(store_factory(), actor=who["user"], clock=clk, **body.model_dump()))

    @r.get("/sources")
    def list_sources(caller: dict = Depends(caller_dep)):
        return {"sources": _sources.list_sources(store_factory(), caller["id"]), "connectors_live": connectors.live_enabled()}

    @r.post("/sources/{source_id}/ingest")
    def ingest(source_id: str, body: IngestIn, caller: dict = Depends(caller_dep)):
        return _run(lambda: _ingest.ingest(store_factory(), caller=caller["id"], source_id=source_id, fmt=body.format,
                                           content=body.content, title=body.title, published_at=body.published_at,
                                           doc_type=body.doc_type, clock=clk))

    @r.post("/sources/{source_id}/fetch")
    def fetch(source_id: str, caller: dict = Depends(caller_dep)):
        """Documented-public-API connector. OFF by default: returns 409 unless explicitly enabled AND a transport exists."""
        def go():
            st = store_factory()
            src = _sources.get_source(st, source_id)
            if not _sources.can_access(src, caller["id"]):
                raise IntelError(403, "this caller may not ingest into that source", "access_denied")
            conn = connector_factory() if connector_factory else connectors.PublicApiConnector()
            try:
                fmt, text = conn.fetch(src)
            except connectors.ConnectorDisabled as e:
                raise IntelError(409, f"connector disabled: {e}", "connector_disabled")
            return _ingest.ingest(st, caller=caller["id"], source_id=source_id, fmt=fmt, content=text, clock=clk,
                                  via_connector=True)
        return _run(go)

    # --- SEC EDGAR connector (OFF by default; see docs/ORACLE_INTEL_SEC_EDGAR_CONNECTOR.md)
    @r.post("/connectors/sec-edgar/sources")
    def edgar_register(body: EdgarSourceIn, who: dict = Depends(approver_dep)):
        return _run(lambda: _edgar.register_edgar_source(store_factory(), actor=who["user"], clock=clk, **body.model_dump()))

    @r.post("/connectors/sec-edgar/sources/{source_id}/live")
    def edgar_live(source_id: str, body: EdgarLiveIn, who: dict = Depends(approver_dep)):
        return _run(lambda: _edgar.set_live(store_factory(), actor=who["user"], source_id=source_id, enabled=body.enabled, clock=clk))

    @r.get("/connectors/sec-edgar/policy")
    def edgar_policy(caller: dict = Depends(caller_dep)):
        return {"policy": _edgar.POLICY, "policy_hash": _edgar.POLICY_HASH, "live_flags": {
            "PATIENCE_INTEL_CONNECTORS_LIVE": connectors.live_enabled(), "PATIENCE_INTEL_SEC_EDGAR_LIVE": _edgar.edgar_flag()}}

    @r.post("/connectors/sec-edgar/sources/{source_id}/fetch")
    def edgar_fetch(source_id: str, body: EdgarFetchIn, caller: dict = Depends(caller_dep)):
        conn = edgar_connector_factory() if edgar_connector_factory else _edgar.SecEdgarConnector()
        return _run(lambda: _edgar.fetch_and_ingest(store_factory(), caller=caller["id"], source_id=source_id, cik=body.cik,
                                                    dataset=body.dataset, clock=clk, connector=conn))

    @r.get("/records")
    def records(q: str, source_id: Optional[str] = None, limit: int = 10, caller: dict = Depends(caller_dep)):
        return {"results": _run(lambda: _inquiry.search_records(store_factory(), caller["id"], q,
                                                                 [source_id] if source_id else None, limit))}

    @r.post("/inquiries")
    def inquire(body: InquiryIn, caller: dict = Depends(caller_dep)):
        model = model_factory() if model_factory else None
        return _run(lambda: _inquiry.run_inquiry(store_factory(), caller=caller["id"], question=body.question, clock=clk,
                                                 source_ids=body.source_ids, since=body.since, until=body.until, model=model))

    @r.get("/reports/{report_id}")
    def report(report_id: str, format: str = "json", caller: dict = Depends(caller_dep)):
        if format not in ("json", "md"):
            raise HTTPException(422, "format must be json or md")
        rep = _run(lambda: _inquiry.get_report(store_factory(), caller["id"], report_id))
        return PlainTextResponse(to_markdown(rep), media_type="text/markdown") if format == "md" else rep

    @r.get("/stats")
    def counters(caller: dict = Depends(caller_dep)):
        st = store_factory()
        c = st.counts([x["source_id"] for x in _sources.list_sources(st, caller["id"])])
        mine = st.query("SELECT COUNT(*) FROM analytical_queries WHERE asked_by=?", (caller["id"],))[0][0]
        rep = st.query("SELECT COUNT(*) FROM intelligence_reports WHERE created_by=?", (caller["id"],))[0][0]
        return {**c, "queries": mine, "reports": rep, "scope": "sources this caller can access; own queries and reports"}

    return r
