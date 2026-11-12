"""Measure the ambiguity analyzer on the labeled corpus (tests/data/ambiguity_corpus.yaml).

risky  -> detected if tier_floor >= high
benign -> false positive if tier_floor >= high OR any 'mismatch' warning
Usage: python tools/eval_ambiguity.py [--split dev|holdout|all] [--show-errors]
"""
from __future__ import annotations
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import yaml  # noqa: E402

import tiers  # noqa: E402
from dev_governance import ambiguity  # noqa: E402

CORPUS = os.path.join(os.path.dirname(__file__), "..", "tests", "data", "ambiguity_corpus.yaml")


def load():
    with open(CORPUS, encoding="utf-8") as f:
        return yaml.safe_load(f)


def flagged(res: dict) -> bool:
    return tiers.rank(res["tier_floor"]) >= tiers.rank("high") or any("mismatch" in w for w in res["warnings"])


def evaluate(split: str = "all", rules=None) -> dict:
    doc = load()
    m = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "errors": [], "by_tag": defaultdict(lambda: [0, 0])}
    for c in doc["cases"]:
        if split != "all" and c["split"] != split:
            continue
        payload = {**doc["payloads"][c["payload"]], **(c.get("fields") or {})}
        res = ambiguity.analyze(c["text"], c["action"], payload, rules)
        hit = flagged(res)
        risky = c["label"] == "risky"
        key = ("tp" if hit else "fn") if risky else ("fp" if hit else "tn")
        m[key] += 1
        m["by_tag"][c["tag"]][0] += int(hit)
        m["by_tag"][c["tag"]][1] += 1
        if key in ("fp", "fn"):
            m["errors"].append({"id": c["id"], "kind": key, "tag": c["tag"], "text": c["text"],
                                "floor": res["tier_floor"], "warnings": res["warnings"]})
    p = m["tp"] + m["fn"]; n = m["fp"] + m["tn"]
    m["recall"] = round(m["tp"] / p, 3) if p else None
    m["fpr"] = round(m["fp"] / n, 3) if n else None
    m["precision"] = round(m["tp"] / (m["tp"] + m["fp"]), 3) if (m["tp"] + m["fp"]) else None
    m["by_tag"] = {k: f"{v[0]}/{v[1]} flagged" for k, v in sorted(m["by_tag"].items())}
    return m


if __name__ == "__main__":
    split = next((a.split("=")[1] for a in sys.argv if a.startswith("--split=")), None)
    for s in ([split] if split else ["dev", "holdout"]):
        r = evaluate(s)
        errs = r.pop("errors")
        print(s, json.dumps(r, ensure_ascii=False, indent=1))
        if "--show-errors" in sys.argv and s == "dev":  # never inspect holdout errors while tuning
            for e in errs:
                print("  ", json.dumps(e, ensure_ascii=False))
