"""Deterministic project ranking. Basis and confidence here describe ONLY this ranking."""
from __future__ import annotations

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def rank(projects):
    open_ = [p for p in projects if p["status"] != "complete"]
    return sorted(open_, key=lambda p: (RANK.get(p["priority"], 9), p["id"]))


def recommend(projects) -> dict:
    ps = rank(projects)
    if not ps:
        return {"recommendation": "Create a project and define its next verifiable step.",
                "basis": "No active or planned projects are recorded.", "confidence": 1.0, "observed_projects": 0}
    p = ps[0]
    return {"recommendation": f"Prioritize {p['name']}: {p['next_step'] or 'define one measurable next step'}.",
            "basis": f"Deterministic ranking of {len(ps)} unfinished project(s) by stored priority, then age.",
            "confidence": 0.82, "observed_projects": len(ps), "top_project_id": p["id"]}
