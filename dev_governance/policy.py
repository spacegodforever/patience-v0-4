"""Load the dev policy pack and assign a risk tier to a proposed action.

Tiers come from set rules in YAML, not a statistical model. Unknown actions fail closed.
Overlap note: feat/risk-tiers (PR #10) adds tiers to the main /v1/check path; this module is
built on the shared tiers.py module so both paths use one engine after #10 merges.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
import yaml
import tiers as _tiers

TIERS = list(_tiers.TIERS)
DEFAULT_PATH = Path(__file__).resolve().parent.parent / "policies" / "dev" / "default.yaml"


def _max(a: str, b: str) -> str:
    return _tiers.max_tier(a, b)


@dataclass
class Assessment:
    action: str
    tier: str
    category: Optional[str]
    known: bool
    approvals_required: int
    reasons: list


class DevPolicy:
    def __init__(self, data: dict):
        self.data = data or {}
        self.actions = self.data.get("actions") or {}
        self.ttl = int(self.data.get("approval_ttl_seconds", 3600))
        self.unknown_tier = self.data.get("unknown_action_tier", "high")
        if self.unknown_tier not in TIERS or TIERS.index(self.unknown_tier) < 1:
            self.unknown_tier = "high"  # fail closed: unknown can never be auto-allowed
        self.required_overrides = dict(self.data.get("approvers_required") or {})
        for t, floor_n in (("medium", 1), ("high", 1), ("critical", 2)):  # policy may not weaken these
            if int(self.required_overrides.get(t, floor_n)) < floor_n:
                self.required_overrides[t] = floor_n
        for t, rule in self.actions.items():
            if (rule or {}).get("tier") not in TIERS:
                raise ValueError(f"policy: action {t!r} has invalid tier")

    def assess(self, action: str, payload: dict[str, Any], floor: Optional[str] = None) -> Assessment:
        action = (action or "").strip().lower()
        rule = self.actions.get(action)
        if rule is None:
            tier, reasons, cat = self.unknown_tier, [f"unknown action {action!r}: fail closed"], None
        else:
            tier, reasons, cat = rule["tier"], [f"base tier {rule['tier']}"], rule.get("category")
            for field, mapping in (rule.get("by_arg") or {}).items():
                val = str(payload.get(field, "")).strip().lower()
                if val in mapping:
                    tier = _max(tier, mapping[val])
                    reasons.append(f"{field}={val} -> {mapping[val]}")
            oa = rule.get("over_amount")
            if oa:
                try:
                    amt = float(payload.get(oa["field"], 0))
                except (TypeError, ValueError):
                    amt = float("inf")  # unparseable amount: treat as over threshold
                if amt > float(oa["threshold"]):
                    tier = _max(tier, oa["tier"])
                    reasons.append(f"{oa['field']} over {oa['threshold']} -> {oa['tier']}")
        if floor is not None:  # e.g. a threat-assessment result: can only raise, never lower
            new = _tiers.raise_only(tier, floor)
            if new != tier:
                reasons.append(f"raised to {new} by external floor")
            tier = new
        return Assessment(action, tier, cat, rule is not None, _tiers.approvals_required(tier, self.required_overrides), reasons)


def load_policy(path: Optional[str | Path] = None) -> DevPolicy:
    p = Path(path) if path else DEFAULT_PATH
    return DevPolicy(yaml.safe_load(p.read_text(encoding="utf-8")))
