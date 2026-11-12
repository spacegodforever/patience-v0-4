import socket
import pytest

import audit
from dev_governance import CapabilityAuthority, DevGate, GateError
from dev_governance.authority import AuthorityError


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("network blocked")))
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("network blocked")))


PAYLOAD = {"command": "pytest -q", "workspace": "/workspace/patience", "environment": "test",
           "adapter": "isolated-test", "resource": "local-checkout"}


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


@pytest.fixture
def clock(): return Clock()


@pytest.fixture
def authority(clock): return CapabilityAuthority(clock=clock)


def grant(authority, clock, **overrides):
    values = {"grant_id": "grant-test", "actor": "agent-1", "action": "test.run_isolated",
              "resource": "local-checkout", "scope": {k: PAYLOAD[k] for k in
              ("command", "workspace", "environment", "adapter")}, "granted_by": "reviewer",
              "human_owner": "matthew", "owners": ["matthew"], "max_level": 2,
              "expires_at": clock() + 7200, "max_action_ttl_seconds": 3600,
              "isolation": {"network_allowed": False, "secrets_allowed": False, "production_allowed": False},
              "evidence": {"basis": "human_decision", "reference": "local test scope",
                           "confidence": "high", "reason": "directly granted for this isolated action"}}
    values.update(overrides)
    if "attestation" not in values:
        values["attestation"] = authority.attest(values["granted_by"], "grant", values["grant_id"])
    return authority.grant(**values)


def revoke(authority, grant_id, by, reason):
    return authority.revoke(grant_id, by, reason, attestation=authority.attest(by, "revoke", grant_id))


def adapter():
    return type("IsolatedTestStub", (), {"actions": ("test.run_isolated",), "simulated": True,
                "execute": lambda self, a, p, c: {"simulated": True, "no_external_effects": True}})()


def test_missing_grant_blocks_low_tier_ci_even_with_adapter(clock):
    gate = DevGate(clock=clock, adapters=[adapter()])
    with pytest.raises(GateError) as e:
        gate.propose("test.run_isolated", PAYLOAD, "agent-1")
    assert e.value.status == 403
    assert gate.adapters["test.run_isolated"] is not None


def test_human_grant_covers_exact_action_and_executes(clock, authority):
    grant(authority, clock)
    gate = DevGate(clock=clock, authority=authority, adapters=[adapter()])
    r = gate.propose("test.run_isolated", PAYLOAD, "agent-1", owners=["matthew"], authority_grant="grant-test")
    assert r["tier"] == "low" and r["approvals_required"] == 0
    code, out = gate.execute(r["request_id"], "test.run_isolated", {**PAYLOAD, "authority_grant": "grant-test"}, "agent-1")
    assert code == 200 and out["result"]["simulated"] is True
    assert audit.verify()["ok"]


@pytest.mark.parametrize("field,value", [("command", "pytest -q; deploy"), ("workspace", "/other"),
                                         ("environment", "prod"), ("adapter", "unrestricted")])
def test_scope_mismatch_fails_closed(clock, authority, field, value):
    grant(authority, clock)
    gate = DevGate(clock=clock, authority=authority, adapters=[adapter()])
    with pytest.raises(GateError) as e:
        gate.propose("test.run_isolated", {**PAYLOAD, field: value}, "agent-1", owners=["matthew"], authority_grant="grant-test")
    assert e.value.status == 403


def test_revocation_after_proposal_blocks_execution(clock, authority):
    grant(authority, clock)
    gate = DevGate(clock=clock, authority=authority, adapters=[adapter()])
    r = gate.propose("test.run_isolated", PAYLOAD, "agent-1", owners=["matthew"], authority_grant="grant-test")
    revoke(authority, "grant-test", "reviewer", "scope retired")
    with pytest.raises(GateError) as e:
        gate.execute(r["request_id"], "test.run_isolated", {**PAYLOAD, "authority_grant": "grant-test"}, "agent-1")
    assert e.value.status == 403 and "revoked" in e.value.message


def test_expiry_after_proposal_blocks_execution(clock, authority):
    grant(authority, clock, expires_at=clock() + 3700)
    gate = DevGate(clock=clock, authority=authority, adapters=[adapter()])
    r = gate.propose("test.run_isolated", PAYLOAD, "agent-1", owners=["matthew"], authority_grant="grant-test")
    clock.t += 3701
    with pytest.raises(GateError) as e:
        gate.execute(r["request_id"], "test.run_isolated", {**PAYLOAD, "authority_grant": "grant-test"}, "agent-1")
    assert e.value.status == 403


def test_owner_cannot_grant_agent_and_grant_ids_are_not_reusable(clock, authority):
    with pytest.raises(AuthorityError) as e:
        grant(authority, clock, granted_by="matthew")
    assert e.value.status == 403
    grant(authority, clock)
    with pytest.raises(AuthorityError) as e:
        grant(authority, clock)
    assert e.value.status == 409


def test_missing_or_ambiguous_isolation_is_not_a_grant(clock, authority):
    with pytest.raises(AuthorityError):
        grant(authority, clock, isolation={"network_allowed": False})
    with pytest.raises(AuthorityError):
        grant(authority, clock, isolation={"network_allowed": False, "secrets_allowed": False,
                                           "production_allowed": True})


def test_owners_are_hash_bound_and_must_match_grant(clock, authority):
    grant(authority, clock)
    gate = DevGate(clock=clock, authority=authority, adapters=[adapter()])
    with pytest.raises(GateError) as e:
        gate.propose("test.run_isolated", PAYLOAD, "agent-1", owners=["other"], authority_grant="grant-test")
    assert e.value.status == 403


def test_level_metadata_never_reduces_approvals(clock, authority):
    grant(authority, clock, max_level=4)
    gate = DevGate(clock=clock, authority=authority)
    r = gate.propose("code.open_pr", {"repo": "r", "head": "h", "base": "b"}, "agent-1",
                     owners=["matthew"])
    assert r["approvals_required"] == 1 and r["status"] == "pending"
    with pytest.raises(GateError):
        gate.propose("code.open_pr", {"repo": "r", "head": "h", "base": "b"}, "agent-1",
                     owners=["matthew"], authority_grant="grant-test")


def test_suggest_only_grant_cannot_execute(clock, authority):
    with pytest.raises(AuthorityError):
        grant(authority, clock, max_level=1)


def test_grant_cannot_authorize_unsupported_action(clock, authority):
    with pytest.raises(AuthorityError):
        grant(authority, clock, action="code.open_pr")


def test_grant_survives_store_reopen_and_revocation_is_immutable(clock, tmp_path):
    path = str(tmp_path / "authority.db")
    authority = CapabilityAuthority(path=path, clock=clock)
    grant(authority, clock)
    reopened = CapabilityAuthority(path=path, clock=clock)
    assert reopened.require(grant_id="grant-test", actor="agent-1", action="test.run_isolated",
                            payload=PAYLOAD, owners=["matthew"], request_expires_at=clock() + 100)
    revoke(reopened, "grant-test", "reviewer", "retired")
    with pytest.raises(AuthorityError):
        reopened.require(grant_id="grant-test", actor="agent-1", action="test.run_isolated",
                         payload=PAYLOAD, owners=["matthew"], request_expires_at=clock() + 100)
    with pytest.raises(AuthorityError):
        grant(reopened, clock)
