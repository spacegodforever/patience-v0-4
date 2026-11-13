"""SEC EDGAR XBRL connector (data.sec.gov): company facts and filing submissions.

READ-ONLY, fetch-only, OFF by default. Live fetching needs ALL of: PATIENCE_INTEL_CONNECTORS_LIVE=1,
PATIENCE_INTEL_SEC_EDGAR_LIVE=1, a source registered by a named approver (with the policy record below stored
alongside it), that approver switching the source live, and a configured declared User-Agent
(PATIENCE_INTEL_SEC_USER_AGENT, no default). The caller supplies only a CIK and a dataset name; the URL is built
here from two fixed templates, so callers cannot point the connector anywhere else.

Fetched content is untrusted data. It is parsed strictly, schema-validated, mapped to a small fixed set of
observations (and filing-index documents), screened by the same quarantine path as every other ingest, and
stored write-once with a content hash. Nothing here approves, executes or changes policy.
See docs/ORACLE_INTEL_SEC_EDGAR_CONNECTOR.md.
"""
from __future__ import annotations
import json
import math
import os
import re
import time
import zlib
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Optional

from . import connectors as C
from . import ingest as _ing
from .common import IntelError, audit_required, canon, sha, utc_iso, Clock
from .sources import can_access, get_source, register_source
from .store import Store

CONNECTOR = "sec_edgar"
MAPPER_VERSION = "sec-edgar-map-v1"
HOSTS = frozenset({"data.sec.gov", "www.sec.gov"})        # hard-coded; the env host list can never widen it
DATASETS = {"companyfacts": ("https://data.sec.gov/api/xbrl/companyfacts/CIK{cik}.json", "/api/xbrl/companyfacts/"),
            "submissions": ("https://data.sec.gov/submissions/CIK{cik}.json", "/submissions/")}
PATH_PREFIXES = tuple(v[1] for v in DATASETS.values())
DEFAULT_RATE = 2.0
DEFAULT_MAX_BYTES = 16_000_000
HARD_MAX_BYTES = 32_000_000
DEFAULT_TIMEOUT = 20.0
HARD_MAX_TIMEOUT = 60.0

POLICY = {
    "policy_version": "sec-edgar-policy-v1",
    "source_name": "SEC EDGAR XBRL data APIs (data.sec.gov)",
    "publisher": "U.S. Securities and Exchange Commission",
    "source_urls": ["https://data.sec.gov/api/xbrl/companyfacts/CIK##########.json",
                    "https://data.sec.gov/submissions/CIK##########.json"],
    "terms_urls": ["https://www.sec.gov/os/accessing-edgar-data",
                   "https://www.sec.gov/about/privacy-information#website-dissemination"],
    "terms_checked": {"date": "2026-11-13", "method": "page text read by the engineering agent via a web fetch tool",
                      "accessing_edgar_data_page_last_reviewed": "2024-06-26",
                      "privacy_page_last_reviewed": "2023-11-29"},
    "license": ("U.S. government public data. SEC states that information presented on sec.gov is public information "
                "and may be copied or further distributed without the SEC's permission, and asks for appropriate "
                "citation to the SEC as the source. SEC/EDGAR names and logos are trademarks and are not used here "
                "to imply affiliation or endorsement. This is a summary, not legal advice."),
    "attribution": "Source: U.S. Securities and Exchange Commission, EDGAR XBRL APIs (data.sec.gov).",
    "fair_access": {"sec_max_requests_per_second": 10, "this_connector_hard_ceiling_per_second": C.MAX_RATE_PER_S,
                    "this_connector_default_per_second": DEFAULT_RATE,
                    "declared_user_agent_with_contact_required": True,
                    "user_agent_configured_via": "PATIENCE_INTEL_SEC_USER_AGENT (no default, fail closed)",
                    "automated_bulk_crawling": "not performed: one request per explicit API call, two fixed endpoints",
                    "accept_encoding": "identity (compressed responses are refused)"},
    "robots": {"www.sec.gov/robots.txt": "checked 2026-11-13; does not disallow /Archives/edgar/data; the two API "
                                          "paths used are on data.sec.gov",
               "data.sec.gov/robots.txt": "returned 404 on 2026-11-13 (none published)",
               "note": "robots.txt is not re-checked at runtime; the SEC fair-access policy above is the governing rule"},
    "data_notes": ["values are as reported by filers in XBRL and are not audited or verified here",
                   "restated values may differ between fetches; conflicting values for one period are excluded "
                   "from statistics, not silently resolved"],
}
POLICY_JSON = canon(POLICY)
POLICY_HASH = sha(POLICY_JSON)

# concept -> (metric base, priority: lower wins when several concepts report the same period)
CONCEPTS = {"RevenueFromContractWithCustomerExcludingAssessedTax": ("revenue", 0), "Revenues": ("revenue", 1),
            "SalesRevenueNet": ("revenue", 2), "NetIncomeLoss": ("net_income", 0)}
FORMS_FACTS = ("10-K", "10-Q", "10-K/A", "10-Q/A")
FORMS_FILINGS = ("10-K", "10-Q", "8-K")
KEEP = {"quarterly": 40, "annual": 12}
MAX_FACTS_SCANNED = 40_000
MAX_FILINGS_SCANNED = 20_000
KEEP_FILINGS = 40
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ACCN_RE = re.compile(r"^\d{10}-\d{2}-\d{6}$")
FP_OK = ("FY", "Q1", "Q2", "Q3", "Q4")
FORM_RE = re.compile(r"^[0-9A-Za-z\-/]{1,12}$")


# ---------------------------------------------------------------------------- config (env, read at call time)
def edgar_flag() -> bool:
    return os.environ.get("PATIENCE_INTEL_SEC_EDGAR_LIVE", "") == "1"


def _f(name: str, default: float, hard_max: float) -> float:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        v = float(raw)
    except ValueError:
        raise C.FetchRefused("bad_config", f"{name} is not a number")
    if not (0 < v <= hard_max) or math.isnan(v):
        raise C.FetchRefused("bad_config", f"{name} must be > 0 and <= {hard_max}")
    return v


_LIMITER: dict = {}


def shared_limiter() -> C.RateLimiter:
    """One process-wide limiter per configured rate (so separate connector instances cannot multiply the rate)."""
    rate = _f("PATIENCE_INTEL_SEC_RATE", DEFAULT_RATE, C.MAX_RATE_PER_S)
    if rate not in _LIMITER:
        _LIMITER.clear()
        _LIMITER[rate] = C.RateLimiter(rate)
    return _LIMITER[rate]


class SecEdgarConnector:
    """Holds only the injected transport and limiter; all policy lives in fetch_and_ingest / guarded_get."""
    def __init__(self, transport: Optional[Callable] = None, limiter: Optional[C.RateLimiter] = None):
        self._transport, self._limiter = transport, limiter

    def transport(self) -> Callable:
        if self._transport is not None:
            return self._transport
        from .https_transport import https_transport      # the single network-touching module
        return https_transport

    def limiter(self) -> C.RateLimiter:
        return self._limiter or shared_limiter()


# ---------------------------------------------------------------------------- registration / policy / live switch
def register_edgar_source(store: Store, *, actor: str, name: str, allowed_callers: list, clock: Clock) -> dict:
    """Approver-only. Needs data.sec.gov in PATIENCE_INTEL_API_HOSTS (existing public_api registration rule).
    The source starts with live fetching DISABLED."""
    src = register_source(store, actor=actor, name=name, category="public_filings", kind="public_api",
                          description="SEC EDGAR XBRL APIs: company facts (fixed concept subset) and filing submissions index",
                          license_note="U.S. government public data (SEC); see stored source policy sec-edgar-policy-v1",
                          allowed_callers=allowed_callers, uri="https://data.sec.gov/", clock=clock)
    with store.transaction() as c:
        c.execute("INSERT INTO intelligence_source_policies (source_id, connector, policy_json, policy_hash, recorded_by, "
                  "recorded_at, live_enabled) VALUES (?,?,?,?,?,?,0)",
                  (src["source_id"], CONNECTOR, POLICY_JSON, POLICY_HASH, actor, utc_iso(clock())))
        audit_required("intel.source.policy_recorded", actor, source_id=src["source_id"], connector=CONNECTOR,
                       policy_hash=POLICY_HASH, live_enabled=False)
    return {**src, "policy": get_policy(store, src["source_id"])}


def get_policy(store: Store, source_id: str) -> Optional[dict]:
    rows = store.query("SELECT connector, policy_json, policy_hash, recorded_by, recorded_at, live_enabled, live_changed_by, "
                       "live_changed_at FROM intelligence_source_policies WHERE source_id=?", (source_id,))
    if not rows:
        return None
    r = rows[0]
    return {"connector": r[0], "policy": json.loads(r[1]), "policy_hash": r[2], "recorded_by": r[3], "recorded_at": r[4],
            "live_enabled": bool(r[5]), "live_changed_by": r[6], "live_changed_at": r[7]}


def set_live(store: Store, *, actor: str, source_id: str, enabled: bool, clock: Clock) -> dict:
    """Approver-only per-source switch. Still inert unless the two env flags and a User-Agent are also set."""
    if not actor:
        raise IntelError(403, "a named approver is required to change live fetching", "approver_required")
    if not isinstance(enabled, bool):
        raise IntelError(422, "enabled must be true or false", "bad_request")
    get_source(store, source_id)
    if get_policy(store, source_id) is None:
        raise IntelError(404, "source has no connector policy", "no_policy")
    with store.transaction() as c:
        c.execute("UPDATE intelligence_source_policies SET live_enabled=?, live_changed_by=?, live_changed_at=? WHERE source_id=?",
                  (1 if enabled else 0, actor, utc_iso(clock()), source_id))
        audit_required("intel.fetch.live_changed", actor, source_id=source_id, connector=CONNECTOR, live_enabled=enabled)
    return get_policy(store, source_id)


# ---------------------------------------------------------------------------- validation + mapping (pure functions)
class SchemaError(Exception):
    pass


def norm_cik(cik: Any) -> str:
    if isinstance(cik, bool) or not (isinstance(cik, int) or (isinstance(cik, str) and cik.strip().isascii() and cik.strip().isdigit())):
        raise IntelError(422, "cik must be 1-10 digits", "bad_cik")
    n = int(cik) if isinstance(cik, int) else int(cik.strip())
    if not (0 < n < 10 ** 10) or len(str(cik).strip()) > 10:
        raise IntelError(422, "cik must be 1-10 digits", "bad_cik")
    return f"{n:010d}"


def _d(v: Any, what: str) -> date:
    if not isinstance(v, str) or not DATE_RE.match(v):
        raise SchemaError(f"bad {what}")
    try:
        return date.fromisoformat(v)
    except ValueError:
        raise SchemaError(f"bad {what}")


def _name(v: Any) -> str:
    if not isinstance(v, str) or not (1 <= len(v.strip()) <= 150) or any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
        raise SchemaError("bad entity name")
    return v.strip()


def safe_entity(name: str, cik10: str) -> str:
    s = re.sub(r"[^A-Za-z0-9 _.&()\-/]", " ", name)
    s = re.sub(r"\s+", " ", s).strip()[:100].strip()
    return s if _ing.ENTITY_RE.match(s) else f"CIK{cik10}"


def _cik_matches(v: Any, cik10: str) -> bool:
    try:
        return not isinstance(v, bool) and isinstance(v, (int, str)) and f"{int(v):010d}" == cik10
    except ValueError:
        return False


def validate_and_map_companyfacts(doc: Any, cik10: str, today: date) -> dict:
    """Strict schema checks on the structure (SchemaError = whole payload refused); per-fact problems are skipped
    and counted. Returns {entity, name, records, prov, skipped}."""
    if not isinstance(doc, dict) or not _cik_matches(doc.get("cik"), cik10):
        raise SchemaError("cik missing or does not match the request")
    name = _name(doc.get("entityName"))
    facts = doc.get("facts")
    if not isinstance(facts, dict):
        raise SchemaError("facts must be an object")
    gaap = facts.get("us-gaap", {})
    if not isinstance(gaap, dict):
        raise SchemaError("facts.us-gaap must be an object")
    ent = safe_entity(name, cik10)
    skipped = {"invalid_fact": 0, "other_duration": 0, "no_period_start": 0, "other_form": 0, "non_usd_unit": 0,
               "future_date": 0, "scanned": 0}
    best: dict = {}   # (base, kind, start, end) -> candidate
    for concept, (base, prio) in CONCEPTS.items():
        node = gaap.get(concept)
        if node is None:
            continue
        if not isinstance(node, dict) or not isinstance(node.get("units"), dict):
            raise SchemaError(f"{concept}: units must be an object")
        for unit, arr in node["units"].items():
            if not isinstance(arr, list):
                raise SchemaError(f"{concept}: unit list must be an array")
            if unit != "USD":
                skipped["non_usd_unit"] += len(arr)
                continue
            for f in arr:
                skipped["scanned"] += 1
                if skipped["scanned"] > MAX_FACTS_SCANNED:
                    raise SchemaError("too many facts")
                try:
                    if not isinstance(f, dict):
                        raise SchemaError("fact")
                    end = _d(f.get("end"), "end")
                    filed = _d(f.get("filed"), "filed")
                    val = f.get("val")
                    if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val) or abs(val) >= 1e15:
                        raise SchemaError("val")
                    accn = f.get("accn")
                    if not isinstance(accn, str) or not ACCN_RE.match(accn):
                        raise SchemaError("accn")
                    form = f.get("form")
                    if not isinstance(form, str) or not FORM_RE.match(form):
                        raise SchemaError("form")
                    fy = f.get("fy")
                    if fy is not None and (isinstance(fy, bool) or not isinstance(fy, int) or not (1990 <= fy <= 2100)):
                        raise SchemaError("fy")
                    fp = f.get("fp")
                    if fp is not None and (not isinstance(fp, str) or len(fp) > 4):
                        raise SchemaError("fp")
                    frame = f.get("frame")
                    if frame is not None and (not isinstance(frame, str) or not re.match(r"^CY\d{4}(Q[1-4])?I?$", frame)):
                        raise SchemaError("frame")
                    start = _d(f["start"], "start") if f.get("start") is not None else None
                except (SchemaError, KeyError):
                    skipped["invalid_fact"] += 1
                    continue
                if end > today + timedelta(days=1) or filed > today + timedelta(days=1):
                    skipped["future_date"] += 1
                    continue
                if form not in FORMS_FACTS:
                    skipped["other_form"] += 1
                    continue
                if start is None:
                    skipped["no_period_start"] += 1
                    continue
                days = (end - start).days
                kind = "quarterly" if 80 <= days <= 100 else "annual" if 350 <= days <= 380 else None
                if kind is None:
                    skipped["other_duration"] += 1       # e.g. 6- and 9-month year-to-date values: not mapped
                    continue
                cand = {"concept": concept, "prio": prio, "val": float(val), "end": end, "start": start, "filed": filed,
                        "accn": accn, "form": form, "fy": fy, "fp": fp if fp in FP_OK else None, "frame": frame}
                k = (base, kind, start, end)
                cur = best.get(k)
                if cur is None or (cand["prio"], -cand["filed"].toordinal(), cand["accn"]) < (cur["prio"], -cur["filed"].toordinal(), cur["accn"]):
                    best[k] = cand
    records, prov = [], []
    for base in ("revenue", "net_income"):
        for kind in ("quarterly", "annual"):
            picks = sorted((k for k in best if k[0] == base and k[1] == kind), key=lambda k: k[3])[-KEEP[kind]:]
            for k in picks:
                b = best[k]
                note = (f"entityName={name}; CIK{cik10}; SEC XBRL us-gaap:{b['concept']}; period {b['start']}..{b['end']} ({kind}); "
                        f"fy={b['fy'] if b['fy'] is not None else 'unknown'} fp={b['fp'] or 'unknown'}; form={b['form']}; "
                        f"accn={b['accn']}; filed={b['filed']}; frame={b['frame'] or 'none'}; as reported, unverified")
                records.append({"entity": ent, "metric": f"{base}_{kind}", "date": b["end"].isoformat(), "value": b["val"],
                                "unit": "USD", "note": note[:500], "published_at": b["filed"].isoformat()})
                prov.append({"kind": "fact", "match": ("observation", ent, f"{base}_{kind}", b["end"].isoformat(), b["val"]),
                             "concept": f"us-gaap:{b['concept']}", "accession": b["accn"], "form": b["form"],
                             "fiscal_year": b["fy"], "fiscal_period": b["fp"], "period_start": b["start"].isoformat(),
                             "period_end": b["end"].isoformat(), "filed": b["filed"].isoformat(), "frame": b["frame"]})
    return {"entity": ent, "name": name, "records": records, "prov": prov, "skipped": skipped}


def validate_and_map_submissions(doc: Any, cik10: str, today: date) -> dict:
    if not isinstance(doc, dict) or not _cik_matches(doc.get("cik"), cik10):
        raise SchemaError("cik missing or does not match the request")
    name = _name(doc.get("name"))
    filings = doc.get("filings")
    recent = filings.get("recent") if isinstance(filings, dict) else None
    if not isinstance(recent, dict):
        raise SchemaError("filings.recent must be an object")
    need = ("accessionNumber", "filingDate", "form")
    cols = {k: recent.get(k) for k in need + ("reportDate", "items", "primaryDocDescription")}
    if any(not isinstance(cols[k], list) for k in need):
        raise SchemaError("filings.recent arrays missing")
    n = len(cols["accessionNumber"])
    if n > MAX_FILINGS_SCANNED or any(len(cols[k]) != n for k in need) or \
            any(cols[k] is not None and (not isinstance(cols[k], list) or len(cols[k]) != n)
                for k in ("reportDate", "items", "primaryDocDescription")):
        raise SchemaError("filings.recent arrays have inconsistent lengths")
    sic_desc = doc.get("sicDescription")
    if sic_desc is not None and (not isinstance(sic_desc, str) or len(sic_desc) > 100):
        raise SchemaError("bad sicDescription")
    ent = safe_entity(name, cik10)
    rows, skipped = [], {"invalid_filing": 0, "other_form": 0, "future_date": 0}
    for i in range(n):
        try:
            accn, form = cols["accessionNumber"][i], cols["form"][i]
            if not isinstance(accn, str) or not ACCN_RE.match(accn) or not isinstance(form, str) or not FORM_RE.match(form):
                raise SchemaError("row")
            filed = _d(cols["filingDate"][i], "filingDate")
            rep = cols["reportDate"][i] if cols["reportDate"] else ""
            rep_d = _d(rep, "reportDate") if rep not in ("", None) else None
            items = cols["items"][i] if cols["items"] else ""
            desc = cols["primaryDocDescription"][i] if cols["primaryDocDescription"] else ""
            if not isinstance(items or "", str) or len(items or "") > 100 or not isinstance(desc or "", str) or len(desc or "") > 150:
                raise SchemaError("row")
        except SchemaError:
            skipped["invalid_filing"] += 1
            continue
        if form not in FORMS_FILINGS:
            skipped["other_form"] += 1
            continue
        if filed > today + timedelta(days=1):
            skipped["future_date"] += 1
            continue
        rows.append((filed, accn, form, rep_d, items or "", desc or ""))
    rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
    records, prov = [], []
    for filed, accn, form, rep_d, items, desc in rows[:KEEP_FILINGS]:
        title = f"{ent} {form} filed {filed.isoformat()} ({accn})"
        text = (f"{name} (CIK {cik10}) filed Form {form} on {filed.isoformat()}; report period "
                f"{rep_d.isoformat() if rep_d else 'unknown'}; accession {accn}; 8-K items: {items or 'none listed'}; "
                f"filer description: {desc or 'none'}."
                + (f" EDGAR industry classification: {sic_desc}." if sic_desc else "")
                + " Source: SEC EDGAR submissions index; metadata only, filing text not retrieved.")
        records.append({"title": title, "text": text, "doc_type": form, "entities": [ent], "published_at": filed.isoformat()})
        prov.append({"kind": "filing", "match": ("document", title, _ing._clean_text(text)), "concept": None, "accession": accn,
                     "form": form, "fiscal_year": None, "fiscal_period": None, "period_start": None,
                     "period_end": rep_d.isoformat() if rep_d else None, "filed": filed.isoformat(), "frame": None})
    return {"entity": ent, "name": name, "records": records, "prov": prov, "skipped": skipped}


# ---------------------------------------------------------------------------- orchestration
def _refuse(caller: str, source_id: str, code: str, msg: str, status: int, **extra) -> None:
    audit_required("intel.fetch.refused", caller, source_id=source_id, connector=CONNECTOR, reason=code, **extra)
    raise IntelError(status, msg, code)


def read_raw(store: Store, fetch_id: str) -> Optional[str]:
    rows = store.query("SELECT raw_z, content_hash FROM intelligence_raw_fetches WHERE fetch_id=?", (fetch_id,))
    if not rows:
        return None
    text = zlib.decompress(rows[0][0]).decode("utf-8")
    return text if sha(text) == rows[0][1] else None   # None = stored bytes no longer match their hash


def fetch_and_ingest(store: Store, *, caller: str, source_id: str, cik: Any, dataset: str, clock: Clock,
                     connector: Optional[SecEdgarConnector] = None) -> dict:
    src = get_source(store, source_id)
    pol = get_policy(store, source_id)
    if pol is None or pol["connector"] != CONNECTOR or src["kind"] != "public_api":
        audit_required("intel.fetch.refused", caller, source_id=source_id, connector=CONNECTOR, reason="not_an_edgar_source")
        raise IntelError(409, "this source is not a registered SEC EDGAR source", "not_an_edgar_source")
    if not can_access(src, caller):
        audit_required("intel.access.denied", caller, source_id=source_id, op="fetch")
        raise IntelError(403, "this caller may not fetch into that source", "access_denied")
    if dataset not in DATASETS:
        _refuse(caller, source_id, "bad_dataset", f"dataset must be one of {', '.join(DATASETS)}", 422)
    try:
        cik10 = norm_cik(cik)
    except IntelError as e:
        _refuse(caller, source_id, e.code, e.message, e.status, dataset=dataset)
    ctx = {"dataset": dataset, "cik": cik10}
    # --- gates, each refusal audited
    if not C.live_enabled():
        _refuse(caller, source_id, "live_off", "live connectors are off (PATIENCE_INTEL_CONNECTORS_LIVE is not 1)", 409, **ctx)
    if not edgar_flag():
        _refuse(caller, source_id, "edgar_flag_off", "SEC EDGAR fetching is off (PATIENCE_INTEL_SEC_EDGAR_LIVE is not 1)", 409, **ctx)
    if not pol["live_enabled"]:
        _refuse(caller, source_id, "source_not_live", "an approver has not enabled live fetching for this source", 409, **ctx)
    try:
        ua = C.validate_user_agent(os.environ.get("PATIENCE_INTEL_SEC_USER_AGENT"))
        _f("PATIENCE_INTEL_SEC_RATE", DEFAULT_RATE, C.MAX_RATE_PER_S)     # validates config (fail closed)
        max_bytes = int(_f("PATIENCE_INTEL_SEC_MAX_BYTES", DEFAULT_MAX_BYTES, HARD_MAX_BYTES))
        timeout = _f("PATIENCE_INTEL_SEC_TIMEOUT", DEFAULT_TIMEOUT, HARD_MAX_TIMEOUT)
        conn = connector or SecEdgarConnector()
        limiter = conn.limiter()
    except C.FetchRefused as e:
        _refuse(caller, source_id, e.code, e.message, 409, **ctx)
    url_t = DATASETS[dataset][0]
    url = url_t.format(cik=cik10)
    ts = clock()
    fetched_at = utc_iso(ts)
    audit_required("intel.fetch.attempt", caller, source_id=source_id, connector=CONNECTOR, url=url, **ctx)   # before any I/O
    try:
        final_url, resp = C.guarded_get(conn.transport(), url, hosts=HOSTS, path_prefixes=PATH_PREFIXES, user_agent=ua,
                                        limiter=limiter, timeout_s=timeout, max_bytes=max_bytes)
    except C.FetchRefused as e:
        audit_required("intel.fetch.blocked", caller, source_id=source_id, connector=CONNECTOR, url=url, reason=e.code, **ctx)
        raise IntelError(429 if e.code == "rate_limited" else 502, f"fetch refused: {e.code}", e.code)
    except Exception as e:  # noqa: BLE001  (network errors, timeouts, TLS failures)
        audit_required("intel.fetch.failed", caller, source_id=source_id, connector=CONNECTOR, url=url,
                       error_class=type(e).__name__, **ctx)
        raise IntelError(502, "upstream fetch failed", "upstream_error")
    body = bytes(resp.body)
    try:
        text = body.decode("utf-8")
        if "\x00" in text:
            raise ValueError("NUL")
    except (UnicodeDecodeError, ValueError):
        audit_required("intel.fetch.rejected", caller, source_id=source_id, connector=CONNECTOR, url=url, reason="bad_encoding",
                       size_bytes=len(body), **ctx)
        raise IntelError(422, "response is not valid UTF-8 text", "bad_encoding")
    chash = sha(text)
    audit_required("intel.fetch.completed", caller, source_id=source_id, connector=CONNECTOR, url=final_url,
                   http_status=resp.status, size_bytes=len(body), content_hash=chash, **ctx)
    today = parse_today(ts)
    try:
        doc = _ing._strict_json(text)
        mapped = (validate_and_map_companyfacts if dataset == "companyfacts" else validate_and_map_submissions)(doc, cik10, today)
    except (ValueError, RecursionError, SchemaError) as e:
        reason = "malformed_json" if isinstance(e, (ValueError, RecursionError)) and not isinstance(e, SchemaError) else "schema_invalid"
        audit_required("intel.fetch.rejected", caller, source_id=source_id, connector=CONNECTOR, url=final_url, reason=reason,
                       detail=str(e)[:100], content_hash=chash, size_bytes=len(body), **ctx)
        raise IntelError(422, f"response rejected: {reason}", reason)
    # --- write-once raw storage + dedupe at response level
    existing = store.query("SELECT fetch_id FROM intelligence_raw_fetches WHERE source_id=? AND content_hash=?", (source_id, chash))
    if existing:
        fetch_id = existing[0][0]
        if store.query("SELECT 1 FROM intelligence_fetch_links WHERE fetch_id=?", (fetch_id,)):
            audit_required("intel.fetch.duplicate", caller, source_id=source_id, connector=CONNECTOR, fetch_id=fetch_id,
                           content_hash=chash, **ctx)
            return {"fetch_id": fetch_id, "source_id": source_id, "dataset": dataset, "cik": cik10, "duplicate": True,
                    "content_hash": chash, "fetched_at": fetched_at, "skipped": mapped["skipped"], "ingest": None}
        # raw stored earlier but never ingested (e.g. earlier crash): reuse it, ingest now
    else:
        fetch_id = "fch_" + sha(source_id + ":" + chash)[:16]
        with store.transaction() as c:
            c.execute("INSERT INTO intelligence_raw_fetches (fetch_id, source_id, dataset, cik, url, fetched_at, http_status, "
                      "content_type, size_bytes, content_hash, raw_z, fetched_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (fetch_id, source_id, dataset, cik10, final_url, fetched_at, resp.status,
                       (resp.headers or {}).get("content-type", "")[:100], len(body), chash, zlib.compress(body, 6), caller))
            audit_required("intel.fetch.stored", caller, source_id=source_id, connector=CONNECTOR, fetch_id=fetch_id,
                           content_hash=chash, size_bytes=len(body), **ctx)
    # --- ingest through the normal pipeline (validation, quarantine, dedupe, index, audit)
    result = None
    if mapped["records"]:
        result = _ing.ingest(store, caller=caller, source_id=source_id, fmt="json", clock=clock, via_connector=True,
                             content=json.dumps({"records": mapped["records"]}, ensure_ascii=False, allow_nan=False))
    _link(store, caller=caller, source_id=source_id, fetch_id=fetch_id, cik10=cik10, mapped=mapped, result=result,
          fetched_at=fetched_at)
    return {"fetch_id": fetch_id, "source_id": source_id, "dataset": dataset, "cik": cik10, "duplicate": False,
            "content_hash": chash, "fetched_at": fetched_at, "entity": mapped["entity"], "mapped": len(mapped["records"]),
            "skipped": mapped["skipped"], "ingest": result}


def parse_today(ts: float) -> date:
    return datetime.fromtimestamp(ts, tz=timezone.utc).date()


def _link(store: Store, *, caller, source_id, fetch_id, cik10, mapped, result, fetched_at) -> None:
    counts = {"records": len(mapped["records"]), "skipped": mapped["skipped"], "mapper_version": MAPPER_VERSION}
    with store.transaction() as c:
        n = 0
        c.execute("INSERT INTO intelligence_fetch_links (fetch_id, batch_id, mapped_json, created_at) VALUES (?,?,?,?)",
                  (fetch_id, result["batch_id"] if result else None, canon(counts), fetched_at))
        for p in mapped["prov"]:
            rid = _lookup(c, source_id, p["match"])
            if rid is None:
                continue
            c.execute("INSERT OR IGNORE INTO intelligence_edgar_provenance (record_id, fetch_id, kind, cik, concept, accession, form, "
                      "fiscal_year, fiscal_period, period_start, period_end, filed, frame) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (rid, fetch_id, p["kind"], cik10, p["concept"], p["accession"], p["form"], p["fiscal_year"],
                       p["fiscal_period"], p["period_start"], p["period_end"], p["filed"], p["frame"]))
            n += 1
        audit_required("intel.fetch.ingested", caller, source_id=source_id, connector=CONNECTOR, fetch_id=fetch_id,
                       batch_id=(result or {}).get("batch_id"), mapped=len(mapped["records"]), provenance_rows=n,
                       stored=(result or {}).get("stored", 0), duplicates=(result or {}).get("duplicates", 0),
                       quarantined=(result or {}).get("quarantined", 0), mapper_version=MAPPER_VERSION)


def _lookup(c, source_id: str, match: tuple) -> Optional[str]:
    if match[0] == "observation":
        row = c.execute("SELECT r.record_id FROM intelligence_records r JOIN intelligence_processed p ON p.record_id=r.record_id "
                        "WHERE r.source_id=? AND p.kind='observation' AND p.entity=? AND p.metric=? AND p.obs_date=? AND p.value=?",
                        (source_id, *match[1:])).fetchone()
    else:
        row = c.execute("SELECT r.record_id FROM intelligence_records r JOIN intelligence_processed p ON p.record_id=r.record_id "
                        "WHERE r.source_id=? AND p.kind='document' AND p.title=? AND p.text=?", (source_id, *match[1:])).fetchone()
    return row[0] if row else None
