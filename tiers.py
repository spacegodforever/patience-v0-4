"""Shared risk-tier primitives (one engine for /v1/check and dev governance).

Compatible with feat/risk-tiers (PR #10): same TIERS tuple and same fail-safe (unknown -> high).
After #10 merges, risk_policy.TIERS should be `from tiers import TIERS` and risk_tier() should
use rank()/max_tier() from here; see docs/dev-governance-gaps.md.
"""
from __future__ import annotations
from typing import Iterable, Optional

TIERS = ("low", "medium", "high", "critical")
FAIL_SAFE = "high"
DEFAULT_APPROVALS = {"low": 0, "medium": 1, "high": 1, "critical": 2}


def normalize(tier: Optional[str], unknown: str = FAIL_SAFE) -> str:
    t = (tier or "").strip().lower()
    return t if t in TIERS else unknown


def rank(tier: Optional[str]) -> int:
    return TIERS.index(normalize(tier))


def max_tier(*tiers: Optional[str]) -> str:
    """Highest of the given tiers; unknown values count as FAIL_SAFE. No tiers -> low."""
    ts = [t for t in tiers if t is not None]
    return TIERS[max((rank(t) for t in ts), default=0)]


def raise_only(base: str, floor: Optional[str]) -> str:
    """Apply an external signal (e.g. threat assessment): may raise, never lower."""
    return base if floor is None else max_tier(base, floor)


def approvals_required(tier: str, overrides: Optional[dict] = None) -> int:
    m = {**DEFAULT_APPROVALS, **(overrides or {})}
    return int(m.get(normalize(tier), 2))


def highest(tiers: Iterable[str]) -> str:
    return max_tier(*list(tiers))
