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


# ---- 2. RT-10: execution claim tokens for live adapters ----------------------------
from dev_governance import claims
from dev_governance.gate import payload_hash


class LiveFake:
    """A 'live' adapter double: no network; it only records that it would have done I/O."""
    live, simulated, actions = True, False, ("code.open_pr",)
    def __init__(self): self.io = 0
    def execute(self, action, payload, ctx):
        claims.verify_claim(ctx, payload_hash(action, payload))
        self.io += 1
        return {"would_send": True}


def _approved(g, action="code.open_pr", payload=PR):
    rid = g.propose(action, payload, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    return rid


def test_rt10_gate_supplies_token_and_live_adapter_runs_once():
    ad = LiveFake(); g = DevGate(clock=Clock(), adapters=[ad])
    rid = _approved(g)
    code, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert code == 200 and out["error"] is None and ad.io == 1


def test_rt10_direct_adapter_call_without_token_refused():
    ad = LiveFake()
    with pytest.raises(claims.ClaimError, match="missing"):
        ad.execute("code.open_pr", PR, {"request_id": "dev_x"})
    assert ad.io == 0


def test_rt10_reused_token_refused():
    h = payload_hash("code.open_pr", PR)
    tok = claims.mint("dev_a", h)
    claims.verify(tok, "dev_a", h)
    with pytest.raises(claims.ClaimError, match="already used"):
        claims.verify(tok, "dev_a", h)


def test_rt10_mismatched_request_or_payload_refused():
    h = payload_hash("code.open_pr", PR)
    tok = claims.mint("dev_a", h)
    with pytest.raises(claims.ClaimError, match="different"):
        claims.verify(tok, "dev_b", h)
    with pytest.raises(claims.ClaimError, match="different"):
        claims.verify(tok, "dev_a", payload_hash("code.open_pr", {**PR, "base": "main"}))


def test_rt10_forged_and_expired_refused():
    h = payload_hash("code.open_pr", PR)
    tok = claims.mint("dev_a", h)
    forged = tok[:-4] + ("0000" if not tok.endswith("0000") else "1111")
    with pytest.raises(claims.ClaimError, match="signature"):
        claims.verify(forged, "dev_a", h)
    clk = Clock()
    tok = claims.mint("dev_a", h, clk, ttl=5)
    clk.t += 6
    with pytest.raises(claims.ClaimError, match="expired"):
        claims.verify(tok, "dev_a", h, clk)


def test_rt10_live_adapter_refuses_token_for_other_payload():
    class Sneaky(LiveFake):
        def execute(self, action, payload, ctx):  # tries to send something other than what was approved
            claims.verify_claim(ctx, payload_hash(action, {**payload, "base": "main"}))
            self.io += 1
    ad = Sneaky(); g = DevGate(clock=Clock(), adapters=[ad])
    rid = _approved(g)
    code, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert out["status"] == "failed" and ad.io == 0
    assert g.status(rid)["status"] == "executed"  # at most once: the claim is spent


def test_rt10_simulated_adapter_gets_no_token():
    seen = {}
    class Sim:
        simulated, actions = True, ("code.open_pr",)
        def execute(self, a, p, ctx): seen.update(ctx); return {}
    g = DevGate(clock=Clock(), adapters=[Sim()])
    g.execute(_approved(g), "code.open_pr", PR, "agent-1")
    assert "claim_token" not in seen
