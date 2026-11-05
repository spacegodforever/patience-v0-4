"""Catastrophe guard: RT-07 executor binding, RT-10 claim tokens, destructive-action guard,
circuit breaker, advisory report. Simulation only; network blocked."""
import socket
import pytest

import audit
from dev_governance import DevGate, GateError, load_policy, DevPolicy
from dev_governance.store import MemoryStore


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k): raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


PR = {"repo": "spacegodforever/patience-v0-4", "head": "feat/x", "base": "v0.6-security-fixes"}


def events():
    return [str(e) for e in audit.read()]


# ---- 1. RT-07: execute bound to proposer ------------------------------------------
def test_rt07_other_agent_cannot_execute():
    g = DevGate(clock=Clock())
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    with pytest.raises(GateError) as e:
        g.execute(rid, "code.open_pr", PR, "agent-2")
    assert e.value.status == 403
    assert any("dev.execute.forbidden" in ev for ev in events())
    assert g.execute(rid, "code.open_pr", PR, "agent-1")[0] == 200


def test_rt07_owner_may_execute_per_policy():
    g = DevGate(clock=Clock())
    rid = g.propose("code.open_pr", PR, "bot", owners=["ops"])["request_id"]
    g.approve(rid, "matthew")
    assert g.execute(rid, "code.open_pr", PR, "ops")[0] == 200


def test_rt07_proposer_only_policy_blocks_owner():
    pol = load_policy(); pol.data["execute_by"] = "proposer"
    g = DevGate(policy=pol, clock=Clock())
    rid = g.propose("code.open_pr", PR, "bot", owners=["ops"])["request_id"]
    g.approve(rid, "matthew")
    with pytest.raises(GateError) as e:
        g.execute(rid, "code.open_pr", PR, "ops")
    assert e.value.status == 403


def test_rt07_forbidden_does_not_consume_approval():
    g = DevGate(clock=Clock())
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    with pytest.raises(GateError):
        g.execute(rid, "code.open_pr", PR, "intruder")
    assert g.status(rid)["status"] == "approved"
