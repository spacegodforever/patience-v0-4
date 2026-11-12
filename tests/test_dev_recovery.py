"""Crash recovery for the dev gate: stuck 'executing' -> 'needs_review' -> human resolution.
Never retried automatically; every step is in the append-only, tamper-evident audit log."""
import base64
import socket
import pytest
from fastapi.testclient import TestClient

import audit
from dev_governance import DevGate, GateError
from dev_governance.store import SqliteStore


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


class Counting:
    actions = ("ci.run",)
    simulated = True

    def __init__(self, crash=False):
        self.calls, self.crash = 0, crash

    def execute(self, action, payload, ctx):
        self.calls += 1
        if self.crash:
            raise SystemExit("process died")  # BaseException: the gate's except Exception does not catch it
        return {"simulated": True}


def stuck(gate, ad):
    r = gate.propose("ci.run", {}, "agent-1", owners=["matthew"])
    with pytest.raises(SystemExit):
        gate.execute(r["request_id"], "ci.run", {}, "agent-1")
    assert gate.status(r["request_id"])["status"] == "executing"
    return r["request_id"]


def events(): return [r["event"] for r in audit.read()]


@pytest.fixture(params=["memory", "sqlite"])
def gate_ad(request, tmp_path):
    clock, ad = Clock(), Counting(crash=True)
    store = SqliteStore(str(tmp_path / "gate.db")) if request.param == "sqlite" else None
    return DevGate(clock=clock, adapters=[ad], store=store), ad, clock


def test_stuck_request_is_never_reexecuted_and_stays_blocked(gate_ad):
    gate, ad, clock = gate_ad
    rid = stuck(gate, ad)
    with pytest.raises(GateError) as e:
        gate.execute(rid, "ci.run", {}, "agent-1")
    assert e.value.status == 409 and ad.calls == 1


def test_flagging_respects_min_age_and_audits(gate_ad):
    gate, ad, clock = gate_ad
    rid = stuck(gate, ad)
    assert gate.flag_stuck_executions("alice", 300) == []  # too fresh: could still be running
    clock.t += 301
    assert gate.flag_stuck_executions("alice", 300) == [rid]
    assert gate.status(rid)["status"] == "needs_review"
    assert gate.flag_stuck_executions("alice", 300) == []  # idempotent
    assert "dev.execute.needs_review" in events() and audit.verify()["ok"]
    with pytest.raises(GateError) as e:  # needs_review is not executable and not a retry path
        gate.execute(rid, "ci.run", {}, "agent-1")
    assert e.value.status == 409 and ad.calls == 1


def test_flagging_requires_named_actor_and_valid_age(gate_ad):
    gate, ad, clock = gate_ad
    with pytest.raises(GateError) as e:
        gate.flag_stuck_executions("", 0)
    assert e.value.status == 403
    for bad in (-1, "x", float("nan")):
        with pytest.raises(GateError) as e:
            gate.flag_stuck_executions("alice", bad)
        assert e.value.status == 422


def test_resolve_requires_human_other_than_proposer_or_owner(gate_ad):
    gate, ad, clock = gate_ad
    rid = stuck(gate, ad)
    clock.t += 400
    gate.flag_stuck_executions("alice", 300)
    for who in ("agent-1", "matthew", ""):
        with pytest.raises(GateError) as e:
            gate.resolve_review(rid, who, "failed", "checked target")
        assert e.value.status == 403
    with pytest.raises(GateError) as e:
        gate.resolve_review(rid, "alice", "failed", "  ")
    assert e.value.status == 422
    with pytest.raises(GateError) as e:
        gate.resolve_review(rid, "alice", "maybe", "checked")
    assert e.value.status == 422
    out = gate.resolve_review(rid, "alice", "failed", "target shows no change")
    assert out["status"] == "executed"
    assert "dev.execute.resolved" in events() and audit.verify()["ok"]
    with pytest.raises(GateError) as e:  # terminal: cannot resolve twice or run again
        gate.resolve_review(rid, "alice", "executed", "again")
    assert e.value.status == 409
    with pytest.raises(GateError):
        gate.execute(rid, "ci.run", {}, "agent-1")
    assert ad.calls == 1


def test_resolve_refuses_requests_that_are_not_in_review(gate_ad):
    gate, ad, clock = gate_ad
    rid = stuck(gate, ad)  # still 'executing', not flagged
    with pytest.raises(GateError) as e:
        gate.resolve_review(rid, "alice", "executed", "checked")
    assert e.value.status == 409


def test_normal_execution_is_unchanged_and_never_flagged(clock=None):
    clock, ad = Clock(), Counting()
    gate = DevGate(clock=clock, adapters=[ad])
    r = gate.propose("ci.run", {}, "agent-1", owners=["matthew"])
    assert gate.execute(r["request_id"], "ci.run", {}, "agent-1")[0] == 200
    clock.t += 10_000
    assert gate.flag_stuck_executions("alice", 0) == []
    assert gate.status(r["request_id"])["status"] == "executed"


def test_legacy_executing_row_without_claimed_at_is_flagged():
    clock, ad = Clock(), Counting(crash=True)
    gate = DevGate(clock=clock, adapters=[ad])
    rid = stuck(gate, ad)
    req = gate.store.get(rid); req.pop("claimed_at"); assert gate.store.cas(req)
    assert gate.flag_stuck_executions("alice", 300) == [rid]


def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


def test_api_reconcile_and_resolve_need_named_approver(monkeypatch):
    import approvers, api
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    monkeypatch.delenv("PATIENCE_LEGACY_APPROVER_TOKEN", raising=False)
    monkeypatch.setenv("PATIENCE_API_TOKEN", "agent-token-0123456789")
    approvers.add("alice", "alice-password-12", "approver")
    c = TestClient(api.app)
    assert c.post("/v1/dev/admin/reconcile").status_code == 403
    assert c.post("/v1/dev/admin/reconcile", headers={"Authorization": "Bearer agent-token-0123456789"}).status_code == 403
    r = c.post("/v1/dev/admin/reconcile", json={"min_age_seconds": 0}, headers=_basic("alice", "alice-password-12"))
    assert r.status_code == 200 and r.json() == {"flagged": []}
    assert c.post("/v1/dev/requests/dev_x/resolve", json={"outcome": "executed", "note": "n"}).status_code == 403
    r = c.post("/v1/dev/requests/dev_unknown/resolve", json={"outcome": "executed", "note": "n"},
               headers=_basic("alice", "alice-password-12"))
    assert r.status_code == 404
    r = c.post("/v1/dev/requests/dev_unknown/resolve", json={"outcome": "bogus", "note": "n"},
               headers=_basic("alice", "alice-password-12"))
    assert r.status_code == 422
