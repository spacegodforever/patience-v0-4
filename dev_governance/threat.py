"""Server-side threat floor for /v1/dev/check (RT-11).

The floor is computed on the server from the request text and payload using the same
deterministic risk classifier as /v1/check (risk_policy.classify). Clients cannot supply or
lower it; it can only raise the policy tier.
"""
from __future__ import annotations
from typing import Any, Optional

import risk_policy


def _strings(obj: Any, out: list, depth: int = 0) -> None:
    if depth > 6 or len(out) > 200:
        return
    if isinstance(obj, str):
        out.append(obj[:2000])
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k)); _strings(v, out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _strings(v, out, depth + 1)


def assess(action: str, text: Optional[str], payload: dict) -> dict:
    parts: list = []
    _strings(payload or {}, parts)
    blob = ". ".join([text or ""] + parts)
    c = risk_policy.classify(blob)
    cons = float(c.get("consequence") or 0)
    if "injection" in (c.get("flags") or []):
        floor = "critical"
    elif c.get("irreversible") and cons >= 0.85:
        floor = "high"
    elif cons >= 0.6 and not c.get("read_only") and set(c.get("categories") or []) - {"unknown_side_effect"}:
        floor = "medium"
    else:
        floor = "low"
    return {"floor": floor, "categories": c.get("categories", []), "consequence": cons,
            "irreversible": bool(c.get("irreversible")), "flags": c.get("flags", [])}
