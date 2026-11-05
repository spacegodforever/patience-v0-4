"""Deterministic advisory report attached to every dev request that needs approval.

Pure function of (action, payload, policy assessment, destructive guard, optional ambiguity
findings). No model calls, no clock, no randomness: same input -> same report. The report may
RAISE the tier (via `threat_floor`) but can never lower it.
"""
from __future__ import annotations
from typing import Any, Optional

import tiers as _tiers

VERSION = "advisory-v1"

# action prefix -> (what could go wrong, reversibility)
_RISKS = {
    "db.drop": (["table and its data permanently removed", "dependent services break"], "irreversible without backup"),
    "db.truncate": (["all rows removed"], "irreversible without backup"),
    "db.delete_rows": (["rows removed; an over-broad filter removes far more than intended"], "irreversible without backup"),
    "db.migrate": (["schema change locks or corrupts tables", "app/schema version skew"], "reversible only with a tested down-migration"),
    "repo.delete": (["repository, history, issues and PRs lost"], "irreversible after provider grace period"),
    "code.force_push": (["remote history overwritten; others' commits lost"], "partially reversible via reflog/mirrors"),
    "data.wipe": (["dataset destroyed"], "irreversible without backup"),
    "infra.destroy": (["resources and attached storage deleted", "outage"], "irreversible for stateful resources"),
    "infra.apply": (["unintended resource replacement or deletion", "outage"], "partially reversible"),
    "secrets.rotate": (["dependent services lose access", "lockout"], "reversible if old secret retained"),
    "deploy.release": (["regression or outage in target environment"], "reversible via rollback"),
    "deploy.rollback": (["reintroduces previously fixed defects"], "reversible via re-release"),
    "code.merge_pr": (["unreviewed or broken code lands on target branch"], "reversible via revert"),
}
_FLOOR = {"irreversible": "critical", "partially": "high"}


def _reversibility_floor(rev: str) -> str:
    for k, t in _FLOOR.items():
        if rev.startswith(k):
            return t
    return "low"


def build(action: str, payload: dict, tier: str, known: bool, guard: Any,
          ambiguity: Optional[dict] = None) -> dict:
    payload = payload or {}
    risks, rev = _RISKS.get(action, (["unrecognized action: effects unknown"], "unknown"))
    risks = list(risks)
    unknowns, basis = [], [f"action rule: {action if action in _RISKS else 'none (unknown action)'}"]
    floor = _reversibility_floor(rev)
    if rev == "unknown":
        unknowns.append("reversibility: no rule for this action (policy tier stands)")
    if not known:
        unknowns.append("action not in policy; tier is fail-safe")
    blast = getattr(guard, "blast", None) or payload.get("blast_radius")
    if getattr(guard, "destructive", False):
        floor = "critical"
        basis.append("destructive guard: " + "; ".join(guard.why))
    if not blast:
        unknowns.append("blast radius: not declared")
    rollback = payload.get("rollback_plan") or None
    if not rollback:
        unknowns.append("rollback plan: not provided")
    backup = payload.get("backup") or None
    if getattr(guard, "destructive", False) and not backup:
        unknowns.append("backup evidence: not provided")
    if payload.get("environment") is None and action.startswith(("deploy.", "infra.", "db.")):
        unknowns.append("environment: not stated")
    warnings: list = []
    if ambiguity:
        basis.append(f"language analysis ({ambiguity.get('version')})")
        floor = _tiers.max_tier(floor, ambiguity.get("tier_floor") or "low")
        warnings += ambiguity.get("warnings", [])
        unknowns += ambiguity.get("unknowns", [])
        risks += [f"text/payload: {w}" for w in ambiguity.get("warnings", []) if "mismatch" in w]
    floor = _tiers.max_tier(floor, tier)  # never below the policy tier
    confidence = "high" if not unknowns else ("medium" if len(unknowns) <= 2 else "low")
    return {"version": VERSION, "what_could_go_wrong": risks, "blast_radius": blast or "unknown",
            "reversibility": rev, "rollback": rollback or "unknown", "backup": backup or "unknown",
            "threat_floor": floor, "warnings": warnings, "unknowns": unknowns,
            "basis": basis, "confidence": confidence}
