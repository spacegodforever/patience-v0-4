"""Ingestion pipeline: INGEST -> NORMALIZE -> VALIDATE -> DEDUPLICATE -> CLASSIFY -> STORE -> INDEX.

Raw records are stored exactly as received. Publication time is taken from the data or left NULL
("unknown"); it is never invented. Retrieval time is the server clock. Text that looks like an
instruction aimed at an AI/gate is quarantined: stored (provenance) but never indexed or retrieved.
"""
from __future__ import annotations
import csv
import io
import json
import math
import re
import secrets
import unicodedata
from datetime import timedelta
from typing import Optional

import risk_policy

from . import search as _search
from .common import IntelError, audit_required, canon, parse_time, sha, utc_iso, Clock
from .sources import can_access, get_source
from .store import Store

PARSER_VERSION = "ingest-v1"
MAX_BYTES = 2_000_000
MAX_ROWS = 5000
FORMATS = ("csv", "json", "text")
DOC_TYPES = ("10-K", "10-Q", "8-K", "annual_report", "filing", "announcement", "research_note", "internal_memo",
             "logistics_report", "other")
ENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.&()\-/]{0,99}$")
METRIC_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,60}$")
REL_RE = re.compile(r"^[a-z_]{2,40}$")
# instruction-like phrases aimed at an AI or the gate (documented; best effort, can be evaded / false-positive)
INSTRUCTION_RES = [re.compile(p, re.I) for p in (
    r"\bignore (all |any |the )?(previous|prior|above|earlier) (instructions|rules|messages)",
    r"\bdisregard (all |any |the )?(previous|prior|above|earlier|your) (instructions|rules|policy|policies)",
    r"\b(you are|act as|pretend to be) (now )?(an? )?(ai|assistant|admin|administrator|system|developer)",
    r"\b(system prompt|developer message)\b",
    r"\b(approve|grant|allow|authorize|whitelist)\b.{0,40}\b(all|every|any)\b.{0,30}\b(request|action|payment|transfer|permission|access)",
    r"\b(set|change|lower|downgrade)\b.{0,30}\b(risk|tier|policy|permission)s?\b",
    r"\b(execute|run|send|transfer|wire|delete|drop)\b.{0,30}\b(immediately|now|without (approval|review|asking))",
    r"\bdo not (tell|inform|notify|ask) (the )?(user|human|operator|approver)",
    r"\bnew instructions?\s*:",
)]


def _clean_text(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if ch in "\n\t" or unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp"))
    return re.sub(r"[ \t]+", " ", re.sub(r"\n{3,}", "\n\n", s)).strip()


def injection_reason(*texts: str) -> Optional[str]:
    blob = "\n".join(t for t in texts if t)
    if not blob:
        return None
    if "injection" in (risk_policy.classify(blob[:20000]).get("flags") or []):
        return "injection_classifier"
    if any(rx.search(blob) for rx in INSTRUCTION_RES):
        return "instruction_like_text"
    return None


class _Bad(Exception):
    pass


def _finite(v) -> float:
    if isinstance(v, bool) or v is None:
        raise _Bad("bad_value")
    try:
        f = float(v) if not isinstance(v, str) else float(v.strip())
    except (TypeError, ValueError):
        raise _Bad("bad_value")
    if not math.isfinite(f):
        raise _Bad("bad_value")
    return f


def _pub(v, now) -> Optional[str]:
    if v in (None, ""):
        return None
    d = parse_time(v if isinstance(v, str) else "")
    if d is None:
        raise _Bad("bad_published_at")
    if d > now + timedelta(days=1):
        raise _Bad("future_published_at")
    return d.isoformat(timespec="seconds")


def _obs(row: dict, now) -> dict:
    ent = row.get("entity")
    met = row.get("metric")
    if not isinstance(ent, str) or not ENTITY_RE.match(ent.strip()):
        raise _Bad("bad_entity")
    if not isinstance(met, str) or not METRIC_RE.match(met.strip()):
        raise _Bad("bad_metric")
    d = parse_time(row.get("date") if isinstance(row.get("date"), str) else "")
    if d is None:
        raise _Bad("bad_date")
    if d > now + timedelta(days=1):
        raise _Bad("future_date")
    unit = row.get("unit")
    if unit not in (None, "") and (not isinstance(unit, str) or len(unit.strip()) > 20):
        raise _Bad("bad_unit")
    note = row.get("note")
    if note not in (None, "") and (not isinstance(note, str) or len(note) > 500):
        raise _Bad("bad_note")
    return {"kind": "observation", "entity": ent.strip(), "metric": met.strip().lower(), "obs_date": d.date().isoformat(),
            "value": _finite(row.get("value")), "unit": (unit or "").strip() or None, "note": (note or "").strip(),
            "published_at": _pub(row.get("published_at"), now)}


def _doc(o: dict, now, title_default=None, published_default=None, doc_type_default=None) -> dict:
    text = o.get("text")
    if not isinstance(text, str) or not (1 <= len(text.strip()) <= 200_000):
        raise _Bad("bad_text")
    title = o.get("title", title_default)
    if title in (None, ""):
        title = text.strip().splitlines()[0][:120]
    if not isinstance(title, str) or len(title) > 200:
        raise _Bad("bad_title")
    dt = o.get("doc_type", doc_type_default)
    if dt not in (None, "") and dt not in DOC_TYPES:
        raise _Bad("bad_doc_type")
    ents = o.get("entities") or []
    if not isinstance(ents, list) or len(ents) > 50 or any(not isinstance(e, str) or not ENTITY_RE.match(e.strip()) for e in ents):
        raise _Bad("bad_entities")
    rels = o.get("relationships") or []
    if not isinstance(rels, list) or len(rels) > 50:
        raise _Bad("bad_relationships")
    for r in rels:
        if not (isinstance(r, dict) and isinstance(r.get("from"), str) and isinstance(r.get("to"), str)
                and ENTITY_RE.match(r["from"].strip()) and ENTITY_RE.match(r["to"].strip())
                and isinstance(r.get("type"), str) and REL_RE.match(r["type"])):
            raise _Bad("bad_relationships")
    return {"kind": "document", "title": _clean_text(title), "text": _clean_text(text), "doc_type": dt or None,
            "entities": sorted({e.strip() for e in ents}),
            "relationships": [{"from": r["from"].strip(), "to": r["to"].strip(), "type": r["type"]} for r in rels],
            "published_at": _pub(o.get("published_at", published_default), now)}


def _strict_json(content: str):
    def no_const(n):
        raise ValueError(n)

    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate key")
            d[k] = v
        return d
    return json.loads(content, parse_constant=no_const, object_pairs_hook=no_dupes)


def _items(fmt: str, content: str, now, title, published_at, doc_type):
    """Yield (raw_text, parsed-or-_Bad-reason). Raw text is the original row/object/document."""
    if fmt == "csv":
        rd = csv.reader(io.StringIO(content))
        try:
            head = next(rd)
        except StopIteration:
            raise IntelError(422, "empty CSV", "empty")
        head = [h.strip().lower() for h in head]
        if len(set(head)) != len(head) or not {"date", "entity", "metric", "value"} <= set(head):
            raise IntelError(422, "CSV needs unique headers including date, entity, metric, value", "bad_headers")
        for i, row in enumerate(rd, 1):
            if i > MAX_ROWS:
                raise IntelError(422, f"more than {MAX_ROWS} rows", "too_many_rows")
            if not row or all(not c.strip() for c in row):
                continue
            raw = canon(dict(zip(head, row)))
            if len(row) != len(head):
                yield raw, "bad_row_width"
                continue
            try:
                yield raw, _obs(dict(zip(head, row)), now)
            except _Bad as e:
                yield raw, str(e)
    elif fmt == "json":
        try:
            data = _strict_json(content)
        except (ValueError, RecursionError):
            raise IntelError(422, "invalid JSON (duplicate keys and NaN/Infinity are rejected)", "bad_json")
        if isinstance(data, dict) and isinstance(data.get("records"), list):
            data = data["records"]
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list) or not data:
            raise IntelError(422, "JSON must be an object, a list of objects, or {\"records\": [...]}", "bad_json")
        if len(data) > MAX_ROWS:
            raise IntelError(422, f"more than {MAX_ROWS} records", "too_many_rows")
        for o in data:
            try:
                raw = canon(o)
            except (TypeError, ValueError):
                yield repr(o)[:200], "bad_record"
                continue
            if not isinstance(o, dict):
                yield raw, "bad_record"
                continue
            try:
                yield raw, (_doc(o, now) if "text" in o else _obs(o, now))
            except _Bad as e:
                yield raw, str(e)
    else:
        try:
            yield content, _doc({"text": content, "title": title, "published_at": published_at, "doc_type": doc_type}, now)
        except _Bad as e:
            yield content, str(e)


def _classify(category: str, p: dict, tags: list) -> str:
    if p["kind"] == "observation":
        if category == "public_market":
            return "market_data"
        if category == "internal_docs":
            return "internal_logistics" if ("supply_chain" in tags or "logistics" in p["metric"]) else "internal_metric"
        return "observation"
    dt = p.get("doc_type")
    if category == "public_filings":
        return "announcement" if dt == "announcement" else "filing"
    if category == "internal_docs":
        return "internal_logistics" if ("supply_chain" in tags or dt == "logistics_report") else "internal_business"
    return "research_note" if dt == "research_note" else "market_commentary"


def ingest(store: Store, *, caller: str, source_id: str, fmt: str, content, clock: Clock, title: Optional[str] = None,
           published_at: Optional[str] = None, doc_type: Optional[str] = None, via_connector: bool = False) -> dict:
    src = get_source(store, source_id)
    if not can_access(src, caller):
        audit_required("intel.access.denied", caller, source_id=source_id, op="ingest")
        raise IntelError(403, "this caller may not ingest into that source", "access_denied")
    if src["kind"] == "public_api" and not via_connector:
        audit_required("intel.ingest.refused", caller, source_id=source_id, reason="public_api_requires_connector")
        raise IntelError(409, "public_api sources can only be ingested through their connector (off by default)",
                         "connector_required")
    if fmt not in FORMATS:
        raise IntelError(422, f"format must be one of {', '.join(FORMATS)}", "bad_format")
    if not isinstance(content, str) or not content.strip():
        raise IntelError(422, "content is required", "empty")
    if "\x00" in content:
        raise IntelError(422, "content contains NUL", "bad_encoding")
    if len(content.encode("utf-8", "replace")) > MAX_BYTES:
        raise IntelError(413, f"content larger than {MAX_BYTES} bytes", "too_large")
    ts = clock()
    now = parse_time(utc_iso(ts))
    retrieved_at = utc_iso(ts)
    batch_id = "bat_" + secrets.token_hex(6)
    stats = {"received": 0, "stored": 0, "duplicates": 0, "invalid": 0, "quarantined": 0}
    rejections, stored_ids = [], []
    with store.transaction() as c:
        for idx, (raw, parsed) in enumerate(_items(fmt, content, now, title, published_at, doc_type), 1):
            stats["received"] += 1
            if isinstance(parsed, str):
                stats["invalid"] += 1
                if len(rejections) < 50:
                    rejections.append({"item": idx, "reason": parsed})
                continue
            p = parsed
            core = ({k: p[k] for k in ("entity", "metric", "obs_date", "value", "unit")} if p["kind"] == "observation"
                    else {"title": p["title"], "text": " ".join(p["text"].split())})
            content_hash = sha(canon({"k": p["kind"], "core": core}))
            rid = "rec_" + sha(source_id + ":" + content_hash)[:16]
            if c.execute("SELECT 1 FROM intelligence_records WHERE source_id=? AND content_hash=?",
                         (source_id, content_hash)).fetchone():
                stats["duplicates"] += 1
                continue
            text = p["text"] if p["kind"] == "document" else \
                f"{p['entity']} {p['metric']} {p['obs_date']} {p['value']} {p['unit'] or ''} {p['note']}".strip()
            tags = _search.tags_for(text, [p.get("metric", ""), p.get("title", ""), src["name"], src["description"]])  # source text is approver-entered
            quarantine = injection_reason(text, p.get("title", ""), p.get("entity", ""), p.get("note", ""))
            klass = _classify(src["category"], p, tags)
            prov = sha(canon([source_id, content_hash, batch_id, retrieved_at, p["published_at"] or "unknown", PARSER_VERSION]))
            c.execute("INSERT INTO intelligence_records (record_id, source_id, batch_id, raw_text, raw_format, content_hash, "
                      "provenance_hash, retrieved_at, published_at, ingested_by, quarantined, quarantine_reason) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (rid, source_id, batch_id, raw, fmt, content_hash, prov, retrieved_at, p["published_at"], caller,
                       1 if quarantine else 0, quarantine))
            c.execute("INSERT INTO intelligence_processed (record_id, kind, entity, metric, obs_date, value, unit, title, text, "
                      "classification, tags, processor_version, processed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (rid, p["kind"], p.get("entity"), p.get("metric"), p.get("obs_date"), p.get("value"), p.get("unit"),
                       p.get("title"), text[:20000], klass, json.dumps(tags), PARSER_VERSION, retrieved_at))
            stats["stored"] += 1
            stored_ids.append(rid)
            if quarantine:
                stats["quarantined"] += 1
                continue  # stored for provenance; not indexed, no entities, never retrieved
            for t in _search.index_terms(text, p.get("entity") or "", p.get("metric") or "", p.get("title") or "", " ".join(tags)):
                c.execute("INSERT OR IGNORE INTO intelligence_terms (term, record_id) VALUES (?,?)", (t, rid))
            names = ([p["entity"]] if p["kind"] == "observation" else p["entities"])
            for n in names:
                c.execute("INSERT OR IGNORE INTO intelligence_entities (entity_id, name, entity_type, first_seen_record, created_at) "
                          "VALUES (?,?,?,?,?)", ("ent_" + sha(n.lower())[:12], n, "unspecified", rid, retrieved_at))
            for r in (p.get("relationships") or []):
                for n in (r["from"], r["to"]):
                    c.execute("INSERT OR IGNORE INTO intelligence_entities (entity_id, name, entity_type, first_seen_record, "
                              "created_at) VALUES (?,?,?,?,?)", ("ent_" + sha(n.lower())[:12], n, "unspecified", rid, retrieved_at))
                c.execute("INSERT OR IGNORE INTO entity_relationships (from_entity, to_entity, rel_type, record_id) VALUES (?,?,?,?)",
                          (r["from"], r["to"], r["type"], rid))
        batch_hash = sha(canon(sorted(stored_ids)))
        audit_required("intel.ingest.batch", caller, source_id=source_id, batch_id=batch_id, format=fmt, batch_hash=batch_hash,
                       via_connector=via_connector, parser_version=PARSER_VERSION, **stats)
    return {"batch_id": batch_id, "source_id": source_id, "retrieved_at": retrieved_at, "batch_hash": batch_hash,
            "rejections": rejections, **stats}


def verify_provenance(store: Store, record_id: str) -> dict:
    """Recompute the provenance hash (and, for observations, the content hash) from stored columns."""
    rows = store.query("SELECT r.source_id, r.batch_id, r.content_hash, r.provenance_hash, r.retrieved_at, r.published_at, "
                       "p.kind, p.entity, p.metric, p.obs_date, p.value, p.unit FROM intelligence_records r "
                       "JOIN intelligence_processed p ON p.record_id=r.record_id WHERE r.record_id=?", (record_id,))
    if not rows:
        return {"ok": False, "record_id": record_id, "reason": "unknown record"}
    sid, bid, ch, ph, ret, pub, kind, ent, met, od, val, unit = rows[0]
    prov_ok = sha(canon([sid, ch, bid, ret, pub or "unknown", PARSER_VERSION])) == ph
    content_ok = None
    if kind == "observation":
        content_ok = sha(canon({"k": "observation", "core": {"entity": ent, "metric": met, "obs_date": od, "value": val,
                                                           "unit": unit}})) == ch
    return {"ok": prov_ok and content_ok is not False, "record_id": record_id, "provenance_ok": prov_ok,
            "content_ok": content_ok}
