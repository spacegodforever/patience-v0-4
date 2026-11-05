"""Simulated workloads for tuning the circuit breaker and blast-radius defaults.

Deterministic (seeded). Benign and runaway agent sessions are replayed against the real
dev_governance.breaker.Breaker with a fake clock. Tuning uses seeds [0, N); the reported numbers
use separate held-out seeds [10_000, 10_000 + N) so the chosen config isn't graded on its own
training data. These are SIMULATED workloads with assumed shapes; real traffic may differ.

Usage: python tools/sim_breaker.py [--grid] [--n=200]
"""
from __future__ import annotations
import itertools
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from dev_governance.breaker import Breaker  # noqa: E402

HOUR = 3600.0


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


# ---- workloads: list of (t_seconds, kind) with kind in {"high","anomaly"} ---------------------
def benign_release_train(r):   # merges a stack of PRs, a few times per 8h day, human-paced
    ev, t = [], 0.0
    while t < 8 * HOUR:
        t += r.uniform(0.5, 2.5) * HOUR
        for _ in range(r.randint(2, 6)):
            t += r.uniform(20, 90)
            ev.append((t, "high"))
    return ev


def benign_steady(r):          # one high-tier action every 2-6 minutes all day
    ev, t = [], 0.0
    while t < 8 * HOUR:
        t += r.uniform(120, 360); ev.append((t, "high"))
    return ev


def benign_batch_migrations(r):  # staging migrations applied in a burst of up to 7 within ~5 min
    ev, t = [], 0.0
    for _ in range(r.randint(1, 3)):
        t += r.uniform(1, 3) * HOUR
        for _ in range(r.randint(3, 7)):
            t += r.uniform(30, 60); ev.append((t, "high"))
    return ev


def benign_sloppy(r):          # forgets rollback_plan once or twice, fixes it, retries
    ev, t = [], 0.0
    for _ in range(r.randint(1, 3)):
        t += r.uniform(0.3, 2) * HOUR
        for _ in range(r.randint(1, 2)):
            t += r.uniform(30, 180); ev.append((t, "anomaly"))
        t += r.uniform(60, 300); ev.append((t, "high"))
    return ev


def runaway_tight_loop(r):     # loop proposing high actions every 1-5 s
    t, ev = r.uniform(0, HOUR), []
    for _ in range(500):
        t += r.uniform(1, 5); ev.append((t, "high"))
    return ev


def runaway_slow_drip(r):      # retry loop every 20-60 s, indefinitely
    t, ev = r.uniform(0, HOUR), []
    for _ in range(300):
        t += r.uniform(20, 60); ev.append((t, "high"))
    return ev


def runaway_refusal_loop(r):   # keeps re-submitting refused destructive requests
    t, ev = r.uniform(0, HOUR), []
    for _ in range(200):
        t += r.uniform(5, 40); ev.append((t, "anomaly"))
    return ev


def runaway_mixed(r):          # destructive spray: high proposals interleaved with refusals
    t, ev = r.uniform(0, HOUR), []
    for _ in range(300):
        t += r.uniform(5, 30); ev.append((t, "anomaly" if r.random() < 0.3 else "high"))
    return ev


BENIGN = {"release_train": benign_release_train, "steady": benign_steady,
          "batch_migrations": benign_batch_migrations, "sloppy_retries": benign_sloppy}
RUNAWAY = {"tight_loop": runaway_tight_loop, "slow_drip": runaway_slow_drip,
           "refusal_loop": runaway_refusal_loop, "mixed_spray": runaway_mixed}
CATCH_BUDGET = 20  # a runaway counts as caught only if tripped within its first 20 events


def replay(events, cfg):
    clk = Clock(); b = Breaker(None, cfg, clk)
    for i, (t, kind) in enumerate(sorted(events)):
        clk.t = t
        if b.record("a", kind):
            return i + 1, t - events[0][0]
    return None, None


def measure(cfg, seeds):
    out = {"benign": {}, "runaway": {}}
    for name, gen in BENIGN.items():
        trips = sum(1 for s in seeds if replay(gen(random.Random(s * 7 + 1)), cfg)[0] is not None)
        out["benign"][name] = trips / len(seeds)
    for name, gen in RUNAWAY.items():
        caught, evs, secs = 0, [], []
        for s in seeds:
            n, dt = replay(gen(random.Random(s * 13 + 5)), cfg)
            if n is not None and n <= CATCH_BUDGET:
                caught += 1; evs.append(n); secs.append(dt)
        out["runaway"][name] = {"catch": caught / len(seeds),
                                "median_events_to_trip": sorted(evs)[len(evs) // 2] if evs else None,
                                "median_seconds_to_trip": round(sorted(secs)[len(secs) // 2]) if secs else None}
    out["false_trip_rate"] = round(sum(out["benign"].values()) / len(BENIGN), 4)
    out["catch_rate"] = round(sum(v["catch"] for v in out["runaway"].values()) / len(RUNAWAY), 4)
    return out


def grid(seeds, max_false=0.01):
    best = None
    for w, mh, ma in itertools.product((120, 300, 600, 900), (3, 5, 8, 10, 12, 15), (2, 3, 4, 5)):
        cfg = {"window_seconds": w, "max_high_proposals": mh, "max_anomalies": ma}
        m = measure(cfg, seeds)
        key = (m["false_trip_rate"] <= max_false, m["catch_rate"], -m["false_trip_rate"],
               -sum((v["median_events_to_trip"] or 99) for v in m["runaway"].values()))
        if best is None or key > best[0]:
            best = (key, cfg, m)
    return best[1], best[2]


# ---- blast radius ---------------------------------------------------------------------------
def blast_measure(max_rows, hard_factor, n=2000, seed0=0):
    r = random.Random(seed0)
    benign = [int(math.exp(r.gauss(math.log(800), 1.3))) for _ in range(n)]   # targeted cleanups
    runaway = [int(math.exp(r.gauss(math.log(2_000_000), 1.0))) for _ in range(n)]  # whole-table
    def bucket(rows):
        return "refused" if rows > max_rows * hard_factor else ("3_approvers" if rows > max_rows else "2_approvers")
    res = {}
    for name, xs in (("benign", benign), ("runaway", runaway)):
        c = {"2_approvers": 0, "3_approvers": 0, "refused": 0}
        for x in xs:
            c[bucket(x)] += 1
        res[name] = {k: round(v / n, 4) for k, v in c.items()}
    return res


if __name__ == "__main__":
    n = int(next((a.split("=")[1] for a in sys.argv if a.startswith("--n=")), 200))
    tune, held = list(range(n)), list(range(10_000, 10_000 + n))
    old = {"window_seconds": 300, "max_high_proposals": 5, "max_anomalies": 3}
    report = {"old_defaults": old, "old_on_heldout": measure(old, held)}
    if "--grid" in sys.argv:
        cfg, m_tune = grid(tune)
        report.update(chosen=cfg, chosen_on_tune=m_tune, chosen_on_heldout=measure(cfg, held))
    report["blast_radius"] = {f"max_rows={mr},hard_factor={hf}": blast_measure(mr, hf)
                              for mr, hf in ((10000, 10), (5000, 10), (5000, 20), (2000, 10))}
    print(json.dumps(report, indent=1))
