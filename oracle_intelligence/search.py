"""Tokenizer, classification vocabulary and the simple term index / search (no model, no embeddings)."""
from __future__ import annotations
import re
from typing import Iterable, Optional

STOP = frozenset("a an and are as at be by for from has have how in is it its of on or that the their these this to "
                 "was were what which who with across between over under into about identify emerging show me "
                 "give list find tell please trend trends analysis analyse analyze".split())
# documented vocabulary: tag -> words/phrases (matched on lowercase normalized text)
VOCAB = {
    "semiconductor": ("semiconductor", "chip", "wafer", "foundry", "fab", "lithography", "dram", "nand", "memory",
                      "equipment"),
    "supply_chain": ("supply chain", "supplier", "shortage", "lead time", "inventory", "shipment", "logistics",
                     "freight", "backlog", "transit"),
    "capacity": ("capacity", "utilization", "capex", "expansion"),
    "earnings": ("revenue", "earnings", "margin", "guidance", "quarter"),
    "demand": ("demand", "orders", "bookings"),
    "pricing": ("price", "close", "pricing"),
    "policy": ("tariff", "subsidy", "regulation", "policy"),
}
_TOK = re.compile(r"[a-z0-9]+")


def stem(t: str) -> str:
    return t[:-1] if len(t) > 3 and t.endswith("s") and not t.endswith("ss") else t


def tokenize(text: str) -> list:
    return [stem(t) for t in _TOK.findall((text or "").lower()) if len(t) >= 2 and t not in STOP]


def tags_for(text: str, extra: Iterable[str] = ()) -> list:
    low = " ".join(_TOK.findall((text + " " + " ".join(extra)).lower()))
    out = []
    for tag, words in VOCAB.items():
        if any((" " + w + " ") in (" " + low + " ") or (" " + w + "s ") in (" " + low + " ") for w in words):
            out.append(tag)
    return sorted(out)


def index_terms(*parts: str, cap: int = 400) -> list:
    seen = []
    for p in parts:
        for t in tokenize(p or ""):
            if t not in seen:
                seen.append(t)
    return seen[:cap]


def search(store, question_terms: list, source_ids: list, limit: int = 10, since: Optional[str] = None,
           until: Optional[str] = None) -> list:
    """Return [(record_id, score)] for NON-quarantined records in the given sources, best first.
    Score = number of distinct matched terms; ties break on record_id (deterministic)."""
    if not question_terms or not source_ids:
        return []
    ph_t = ",".join("?" * len(question_terms))
    ph_s = ",".join("?" * len(source_ids))
    args = list(question_terms) + list(source_ids)
    sql = (f"SELECT t.record_id, COUNT(DISTINCT t.term) AS sc FROM intelligence_terms t "
           f"JOIN intelligence_records r ON r.record_id=t.record_id "
           f"JOIN intelligence_processed p ON p.record_id=t.record_id "
           f"WHERE t.term IN ({ph_t}) AND r.source_id IN ({ph_s}) AND r.quarantined=0 ")
    if since:
        sql += "AND (p.obs_date IS NULL OR p.obs_date >= ?) "
        args.append(since[:10])
    if until:
        sql += "AND (p.obs_date IS NULL OR p.obs_date <= ?) "
        args.append(until[:10])
    sql += "GROUP BY t.record_id ORDER BY sc DESC, t.record_id ASC LIMIT ?"
    args.append(int(limit))
    return [(r[0], r[1]) for r in store.query(sql, tuple(args))]
