"""Load the dev policy pack and assign a risk tier to a proposed action.

Tiers come from set rules in YAML, not a statistical model. Unknown actions fail closed.
Overlap note: feat/risk-tiers (PR #10) adds tiers to the main /v1/check path; this module is
built on the shared tiers.py module so both paths use one engine after #10 merges.
"""
from __future__ import annotations
import re
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


# RT-14: code-level floors. Policy YAML may raise these, never lower them (or drop the action).
ACTION_FLOORS = {
    **{a: "critical" for a in ("db.drop", "db.truncate", "db.delete_rows", "repo.delete", "code.force_push",
                               "data.wipe", "infra.destroy", "secrets.rotate")},
    **{a: "high" for a in ("code.merge_pr", "deploy.rollback", "db.migrate", "infra.apply", "secrets.read",
                           "spend.charge", "payments.pay_invoice")},
    "deploy.release": "medium",
}
# catastrophe limits: (key, bound, "max" = YAML may not exceed / "min" = YAML may not go below)
CATASTROPHE_BOUNDS = (("max_rows", 10000, "max"), ("max_resources", 10, "max"), ("hard_factor", 10, "max"),
                      ("min_rollback_chars", 20, "min"))
BREAKER_BOUNDS = (("window_seconds", 60, "min"), ("max_high_proposals", 50, "max"), ("max_anomalies", 20, "max"))
EXECUTE_BY = ("proposer", "proposer_or_owner")


def _clamp(section: dict, bounds, where: str, notes: list) -> dict:
    out = dict(section or {})
    for k, bound, kind in bounds:
        if k not in out:
            continue
        try:
            v = float(out[k])
        except (TypeError, ValueError):
            v = float("inf") if kind == "max" else float("-inf")
        if (kind == "max" and v > bound) or (kind == "min" and v < bound) or v != v:
            notes.append(f"{where}.{k}={out[k]!r} is looser than the floor; clamped to {bound}")
            out[k] = bound
    return out


class DevPolicy:
    def __init__(self, data: dict):
        self.data = dict(data or {})
        self.floor_violations: list = []
        acts = {k: dict(v or {}) for k, v in (self.data.get("actions") or {}).items()}
        for act, floor in ACTION_FLOORS.items():
            rule = acts.get(act)
            if rule is None:
                continue  # missing -> assess() still applies the floor
            if rule.get("tier") in TIERS and TIERS.index(rule["tier"]) < TIERS.index(floor):
                self.floor_violations.append(f"actions.{act}.tier={rule['tier']} below floor {floor}; raised")
                rule["tier"] = floor
        self.data["actions"] = acts
        self.data["catastrophe"] = _clamp(self.data.get("catastrophe"), CATASTROPHE_BOUNDS, "catastrophe",
                                          self.floor_violations)
        self.data["breaker"] = _clamp(self.data.get("breaker"), BREAKER_BOUNDS, "breaker", self.floor_violations)
        if self.data.get("execute_by", "proposer_or_owner") not in EXECUTE_BY:
            self.floor_violations.append(f"execute_by={self.data.get('execute_by')!r} invalid; using proposer")
            self.data["execute_by"] = "proposer"
        if self.floor_violations:
            import audit
            audit.append("dev.policy.floor_enforced", None, violations=self.floor_violations)
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
                if field == "environment":  # RT-04: normalize; unknown fails closed
                    env = normalize_environment(payload.get(field))
                    if env is None:
                        tier = _max(tier, "critical")
                        reasons.append(f"environment={val!r} unrecognized -> critical (fail closed)")
                        continue
                    if env == "production":
                        tier = _max(tier, "critical")
                        reasons.append(f"environment={val} is production -> critical")
                        continue
                    val = env
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
        hard = ACTION_FLOORS.get(action)
        if hard and _tiers.rank(tier) < _tiers.rank(hard):  # RT-14 (also if the YAML omits the action)
            reasons.append(f"code floor for {action}: {hard}")
            tier = hard
        if floor is not None:  # e.g. a threat-assessment result: can only raise, never lower
            new = _tiers.raise_only(tier, floor)
            if new != tier:
                reasons.append(f"raised to {new} by external floor")
            tier = new
        return Assessment(action, tier, cat, rule is not None, _tiers.approvals_required(tier, self.required_overrides), reasons)


_NONPROD = {
    "dev": "dev", "development": "dev", "local": "dev", "sandbox": "dev",
    "test": "test", "testing": "test", "qa": "test", "ci": "test",
    "staging": "staging", "stage": "staging", "stg": "staging", "preview": "staging",
}
_PROD_EXACT = {"prod", "prd", "production", "live", "main", "release", "master"}


def normalize_environment(value: Any) -> Optional[str]:
    """Map an environment name to dev|test|staging|production, or None if unrecognized.

    Anything that looks like production (prod*, prd*, *-prod, live*, production1, prod-us ...) is
    production. Only an explicit allowlist counts as non-production; everything else is unknown.
    """
    if value is None:
        return None
    v = str(value).strip().lower()
    if not v:
        return None
    toks = [t for t in re.split(r"[^a-z0-9]+", v) if t]
    if v in _PROD_EXACT or any(t.startswith(("prod", "prd", "live")) or t in _PROD_EXACT for t in toks) \
            or "prod" in v:
        return "production"
    return _NONPROD.get(v)


def load_policy(path: Optional[str | Path] = None) -> DevPolicy:
    p = Path(path) if path else DEFAULT_PATH
    return DevPolicy(yaml.safe_load(p.read_text(encoding="utf-8")))
