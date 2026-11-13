"""Strict structured recommendation (schema `oracle-rec-v1`, review mode only) and its validator.

The recommendation is DATA. No field approves, executes, or lowers anything: unknown fields (for
example `approved`, `tier`, `execute`, `plan_steps`) make the whole output invalid. Pipeline, first
failure wins: size -> encoding -> strict JSON parse -> pydantic schema -> action catalog ->
basis refs -> output injection scan -> risk-hint cap. Every failure maps to a RejectCode and the
caller falls back to "no recommendation".
"""
from __future__ import annotations
import json
import re
import unicodedata
from typing import Any, Iterable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

import tiers as _tiers

SCHEMA_VERSION = "oracle-rec-v1"
NON_ACTIONS = ("none", "ask_human")          # "text only" answers; never routed to the gate
RISK_HINT_CAP = "high"                        # the model alone can never push a request to critical
SOURCE_KINDS = ("request_payload", "request_text", "policy", "advisory", "audit_entry", "attached_doc", "human_note")
REF_RE = re.compile(r"^ctx:[A-Za-z0-9_.\-]{1,64}$")
ACTION_RE = re.compile(r"^([a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+|none|ask_human)$")

RejectCode = Literal[
    "oversize_response", "bad_encoding", "schema_invalid", "action_not_in_catalog", "basis_ref_unknown",
    "output_injection_flag",
    # service-level codes (same enum so audit/result handling is uniform)
    "disabled", "unreachable", "timeout", "http_error", "model_mismatch", "truncated_prompt", "busy",
    "bad_response", "context_too_large", "bad_request", "kill_switch", "audit_failed", "internal_error"]


class SchemaRejection(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, str(detail)[:200]


def _clean_text(v: str) -> str:
    """Reject control chars (except \\n and \\t), bidi overrides and zero-width characters."""
    for ch in v:
        cat = unicodedata.category(ch)
        if (cat in ("Cc", "Cf", "Cs", "Co") and ch not in "\n\t") or cat in ("Zl", "Zp"):
            raise ValueError("control or invisible character in text")
    return v


_Text = lambda mx, mn=1: Field(min_length=mn, max_length=mx)  # noqa: E731


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Source(_Strict):
    kind: Literal["request_payload", "request_text", "policy", "advisory", "audit_entry", "attached_doc", "human_note"]
    ref: str = Field(pattern=REF_RE.pattern)
    quote: Optional[str] = Field(default=None, min_length=1, max_length=200)

    @field_validator("quote")
    @classmethod
    def _q(cls, v):
        return v if v is None else _clean_text(v)


class Basis(_Strict):
    fact: str = _Text(300)
    source: Source

    @field_validator("fact")
    @classmethod
    def _f(cls, v):
        return _clean_text(v)


class Confidence(_Strict):
    """MODEL-REPORTED, not calibrated. Bounded to three labelled levels."""
    level: Literal["low", "medium", "high"]
    reason: str = _Text(400)

    @field_validator("reason")
    @classmethod
    def _r(cls, v):
        return _clean_text(v)


class RiskHint(_Strict):
    """A suggested MINIMUM tier. It can only raise (see cap_floor / effective_tier); 'low' is a no-op."""
    floor: Literal["low", "medium", "high", "critical"]
    reason: str = Field(max_length=300)

    @field_validator("reason")
    @classmethod
    def _r(cls, v):
        return _clean_text(v)


class Recommendation(_Strict):
    schema_version: Literal["oracle-rec-v1"]
    action: str = Field(max_length=100, pattern=ACTION_RE.pattern)
    rationale: str = _Text(1200)
    basis: list[Basis] = Field(min_length=1, max_length=12)
    confidence: Confidence
    unknowns: list[str] = Field(max_length=10)
    risk_hint: RiskHint
    assumptions: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("rationale")
    @classmethod
    def _ra(cls, v):
        return _clean_text(v)

    @field_validator("unknowns", "assumptions")
    @classmethod
    def _lst(cls, v):
        for s in v:
            if not (1 <= len(s) <= 200):
                raise ValueError("list entries must be 1-200 chars")
            _clean_text(s)
        return v


# ------------------------------------------------------------------ strict JSON parsing
def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _no_const(name):
    raise ValueError(f"non-finite number {name}")


def parse_strict(raw: str) -> dict:
    """The entire text must be exactly one JSON object: no prose before/after, no markdown fences,
    no duplicate keys, no NaN/Infinity. (Deliberately NOT the lenient first-{-to-last-} parser.)"""
    try:
        obj = json.loads(raw, object_pairs_hook=_no_dupes, parse_constant=_no_const)
    except (ValueError, RecursionError) as e:
        raise SchemaRejection("schema_invalid", f"json: {type(e).__name__}")
    if not isinstance(obj, dict):
        raise SchemaRejection("schema_invalid", "top level must be an object")
    return obj


# ------------------------------------------------------------------ risk hint: raise-only, capped
def cap_floor(floor: Optional[str]) -> Optional[str]:
    """Cap a model-suggested floor at RISK_HINT_CAP; 'low'/None means no hint. Unknown values count as
    the fail-safe tier (never lower), then are capped."""
    if floor is None or floor == "low":
        return None
    f = _tiers.normalize(floor)
    return RISK_HINT_CAP if _tiers.rank(f) > _tiers.rank(RISK_HINT_CAP) else f


def effective_tier(deterministic_tier: str, hint_floor: Optional[str]) -> str:
    """Tier after applying a model hint: max(deterministic, capped hint). Cannot lower; cannot exceed
    max(deterministic, 'high') (so a model never produces 'critical' alone)."""
    return _tiers.raise_only(deterministic_tier, cap_floor(hint_floor))


# ------------------------------------------------------------------ validation pipeline


def _output_strings(rec: Recommendation) -> Iterable[str]:
    yield rec.rationale
    yield rec.confidence.reason
    yield rec.risk_hint.reason
    for b in rec.basis:
        yield b.fact
        if b.source.quote:
            yield b.source.quote
    yield from rec.unknowns
    yield from rec.assumptions


def _injection_flagged(texts: Iterable[str]) -> bool:
    import risk_policy
    blob = ". ".join(texts)
    return "injection" in (risk_policy.classify(blob).get("flags") or [])


def validate_output(raw: Any, catalog: Iterable[str], manifest: dict, max_bytes: int):
    """Validate raw model text. `manifest` maps allowed ref ids ('ctx:...') to item text.
    Returns (Recommendation, info) where info = {"quote_unverified": n}. Raises SchemaRejection."""
    if not isinstance(raw, str):
        raise SchemaRejection("bad_encoding", "output is not text")
    try:
        data = raw.encode("utf-8")
    except UnicodeEncodeError:
        raise SchemaRejection("bad_encoding", "not utf-8")
    if len(data) > max_bytes:
        raise SchemaRejection("oversize_response")
    if "\x00" in raw:
        raise SchemaRejection("bad_encoding", "NUL")
    obj = parse_strict(raw)
    try:
        rec = Recommendation.model_validate(obj)
    except ValidationError as e:
        raise SchemaRejection("schema_invalid", f"{e.error_count()} errors")
    cat = set(catalog) | set(NON_ACTIONS)
    if rec.action not in cat:
        raise SchemaRejection("action_not_in_catalog", rec.action[:60])
    unverified = 0
    for b in rec.basis:
        item = manifest.get(b.source.ref)
        if item is None:
            raise SchemaRejection("basis_ref_unknown", b.source.ref)
        if b.source.quote and " ".join(b.source.quote.split()) not in " ".join(str(item).split()):
            unverified += 1  # kept, but counted and labelled (not a rejection)
    if _injection_flagged(_output_strings(rec)):
        raise SchemaRejection("output_injection_flag")
    return rec, {"quote_unverified": unverified}
