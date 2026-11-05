"""Deterministic language ambiguity analyzer for dev requests.

Compares a request's natural-language text with its payload using YAML rules
(policies/dev/ambiguity.yaml). Output feeds the advisory report. It can only raise the
tier floor or add warnings - never lower a tier or remove a requirement.
"""
from __future__ import annotations
import os
import re
from functools import lru_cache
from typing import Optional

import yaml

import tiers as _tiers
from .destructive import classify as _classify

_DEFAULT = os.path.join(os.path.dirname(__file__), "..", "policies", "dev", "ambiguity.yaml")


@lru_cache(maxsize=8)
def load_rules(path: Optional[str] = None) -> dict:
    with open(path or os.environ.get("PATIENCE_AMBIGUITY_RULES") or _DEFAULT) as f:
        return yaml.safe_load(f) or {}


def _has(text: str, phrase: str) -> bool:
    if not phrase.strip("*"):
        return phrase in text
    return re.search(r"(?<![\w-])" + re.escape(phrase.lower()) + r"(?![\w-])", text) is not None


def _rank_of(action: str, interps: list) -> Optional[int]:
    for i, it in enumerate(interps):
        if action in (it.get("actions") or []):
            return i
    return None


def analyze(text: Optional[str], action: str, payload: dict, rules: Optional[dict] = None) -> dict:
    r = rules if rules is not None else load_rules()
    t = (text or "").lower()
    tiermap = r.get("tiers") or {}
    floor, warnings, unknowns, basis, verbs = "low", [], [], [], []
    if not t.strip():
        unknowns.append("intent: no natural-language text supplied; cannot check text vs payload")
        return {"version": r.get("version"), "tier_floor": floor, "warnings": warnings,
                "unknowns": unknowns, "interpretations": [], "basis": ["no text"], "confidence": "low"}

    destructive = bool(_classify(action, payload or {}))
    for verb, interps in (r.get("ambiguous_verbs") or {}).items():
        if not _has(t, verb):
            continue
        rank = _rank_of(action, interps)
        ranked = [{"rank": i, "meaning": it["meaning"], "matches_payload": i == rank}
                  for i, it in enumerate(interps)]
        verbs.append({"verb": verb, "interpretations": ranked, "payload_rank": rank})
        warnings.append(f"ambiguous verb '{verb}': {len(interps)} readings")
        basis.append(f"verb rule '{verb}'")
        floor = _tiers.max_tier(floor, tiermap.get("ambiguous_verb", "medium"))
        if rank is None:
            unknowns.append(f"payload action {action!r} matches no listed reading of '{verb}'")
        elif rank == len(interps) - 1 and len(interps) > 1:
            warnings.append(f"mismatch: payload takes the MOST destructive reading of '{verb}'")
            floor = _tiers.max_tier(floor, tiermap.get("mismatch", "critical"))

    scope_hits = [w for w in (r.get("unbounded_scope") or []) if _has(t, w)]
    limits = [w for w in (r.get("scope_limits") or []) if _has(t, w)]
    if scope_hits:
        warnings.append(f"unbounded scope wording: {', '.join(scope_hits)}")
        floor = _tiers.max_tier(floor, tiermap.get("unbounded_scope", "high"))
        basis.append("scope rule")
    if (scope_hits or destructive) and not limits:
        unknowns.append("scope limit: text names no table/repo/date/id bound")

    pressure = [w for w in (r.get("pressure") or []) if _has(t, w)]
    if pressure:
        warnings.append(f"pressure/coercion wording: {', '.join(pressure)} (does not shorten review)")
        floor = _tiers.max_tier(floor, tiermap.get("pressure", "high"))
        basis.append("pressure rule")

    # payload broader/more destructive than words
    if destructive and not any(v["payload_rank"] is not None for v in verbs) and not scope_hits:
        destructive_words = ("drop", "delete", "truncate", "wipe", "destroy", "erase", "force")
        if not any(_has(t, w) for w in destructive_words):
            warnings.append("mismatch: payload is destructive but the text does not say so")
            floor = _tiers.max_tier(floor, tiermap.get("mismatch", "critical"))
            basis.append("text-vs-payload rule")
    br = (payload or {}).get("blast_radius") or {}
    if isinstance(br, dict) and (br.get("rows", 0) or 0) > 0 and re.search(r"\b(a few|one|single|some)\b", t):
        if (br.get("rows") or 0) > 100:
            warnings.append(f"mismatch: text implies small scope but payload declares {br['rows']} rows")
            floor = _tiers.max_tier(floor, tiermap.get("mismatch", "critical"))

    confidence = "high" if not unknowns and not verbs else ("medium" if len(unknowns) <= 1 else "low")
    return {"version": r.get("version"), "tier_floor": floor, "warnings": warnings,
            "unknowns": unknowns, "interpretations": verbs, "basis": basis or ["no rule matched"],
            "confidence": confidence}
