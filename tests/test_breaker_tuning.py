"""Simulation-backed defaults for the circuit breaker and blast radius (tools/sim_breaker.py)."""
import os
import sys

from dev_governance.breaker import DEFAULTS
from dev_governance.policy import load_policy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import sim_breaker as sim  # noqa: E402

HELD = list(range(10_000, 10_060))


def test_defaults_match_policy_and_tuned_values():
    assert DEFAULTS == {"window_seconds": 600, "max_high_proposals": 8, "max_anomalies": 3}
    assert load_policy().data["breaker"] == DEFAULTS


def test_tuned_defaults_no_false_trips_and_catch_all_runaways_on_heldout_seeds():
    m = sim.measure(DEFAULTS, HELD)
    assert m["false_trip_rate"] == 0.0
    assert m["catch_rate"] == 1.0
    assert all(v["median_events_to_trip"] <= 9 for v in m["runaway"].values())


def test_old_defaults_false_tripped_benign_bursts():
    m = sim.measure({"window_seconds": 300, "max_high_proposals": 5, "max_anomalies": 3}, HELD)
    assert m["false_trip_rate"] > 0.1   # why the defaults changed


def test_simulation_is_deterministic():
    assert sim.measure(DEFAULTS, HELD[:10]) == sim.measure(DEFAULTS, HELD[:10])


def test_blast_radius_defaults_keep_runaways_refused():
    r = sim.blast_measure(10000, 10)
    assert r["runaway"]["refused"] >= 0.99 and r["benign"]["refused"] == 0.0
