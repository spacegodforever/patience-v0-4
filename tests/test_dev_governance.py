import socket
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import audit
from dev_governance import DevGate, GateError, load_policy, DevPolicy
from dev_governance.router import make_router


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


@pytest.fixture
def clock(): return Clock()


@pytest.fixture
def gate(clock): return DevGate(clock=clock)


PR = {"repo": "spacegodforever/patience-v0-4", "head": "feat/x", "base": "v0.6-security-fixes", "title": "t"}
DEPLOY_PROD = {"service": "api", "environment": "prod", "version": "1.2.3",
    # destructive-action guard (feat/catastrophe-guard) requires these for prod changes
    "rollback_plan": "redeploy previous version 1.2.2 via deploy.rollback", "backup": {"snapshot_id": "snap-1"},
    "blast_radius": {"rows": 0, "resources": 1}}
DEPLOY_STG = {"service": "api", "environment": "staging", "version": "1.2.3"}


def events(): return [r["event"] for r in audit.read()]


# --- policy pack -------------------------------------------------------------
def test_policy_pack_loads_and_covers_all_categories():
    p = load_policy()
    cats = {r.get("category") for r in p.actions.values()}
    assert {"code_change", "ci", "deploy", "db_migration", "infra", "secrets", "spend"} <= cats


@pytest.mark.parametrize("action,payload,tier", [
    ("ci.run", {}, "low"),
    ("code.open_pr", PR, "medium"),
    ("code.merge_pr", {"repo": "r", "pr_number": 1}, "high"),
    ("code.force_push", {"repo": "r"}, "critical"),
    ("deploy.release", DEPLOY_STG, "medium"),
    ("deploy.release", DEPLOY_PROD, "critical"),
    ("deploy.release", {**DEPLOY_PROD, "environment": "Production"}, "critical"),
    ("db.migrate", {"environment": "staging"}, "high"),
    ("db.migrate", {"environment": "prod"}, "critical"),
    ("infra.apply", {"environment": "prod"}, "critical"),
    ("secrets.read", {"name": "x"}, "high"),
    ("secrets.rotate", {"name": "x"}, "critical"),
    ("spend.charge", {"amount_usd": 50}, "high"),
    ("spend.charge", {"amount_usd": 5000}, "critical"),
    ("spend.charge", {"amount_usd": "lots"}, "critical"),
])
def test_tiers(action, payload, tier):
    assert load_policy().assess(action, payload).tier == tier


def test_prod_deploy_tiered_higher_than_staging():
    p = load_policy()
    assert p.assess("deploy.release", DEPLOY_PROD).approvals_required > p.assess("deploy.release", DEPLOY_STG).approvals_required


def test_floor_only_raises_never_lowers():
    p = load_policy()
    assert p.assess("ci.run", {}, floor="high").tier == "high"
    assert p.assess("secrets.rotate", {}, floor="low").tier == "critical"


def test_unknown_tier_in_policy_cannot_be_low():
    p = DevPolicy({"unknown_action_tier": "low", "actions": {}})
    assert p.assess("anything", {}).tier == "high"


def test_invalid_tier_rejected():
    with pytest.raises(ValueError):
        DevPolicy({"actions": {"x": {"tier": "trivial"}}})


# --- fail closed ---------------------------------------------------------------
def test_unknown_action_fails_closed(gate):
    r = gate.propose("db.drop_everything", {}, "agent-1")
    assert r["known"] is False and r["status"] == "pending" and r["tier"] == "high"
    code, out = gate.execute(r["request_id"], "db.drop_everything", {}, "agent-1")
    assert code == 202


def test_unknown_action_without_adapter_still_cannot_run_after_approval(gate):
    r = gate.propose("db.drop_everything", {}, "agent-1")
    gate.approve(r["request_id"], "matthew")
    with pytest.raises(GateError) as e:
        gate.execute(r["request_id"], "db.drop_everything", {}, "agent-1")
    assert e.value.status == 501


def test_low_tier_auto_allowed_but_audited(gate):
    gate.adapters["ci.run"] = type("A", (), {"simulated": True, "execute": lambda s, a, p, c: {"simulated": True}})()
    r = gate.propose("ci.run", {}, "agent-1")
    assert r["status"] == "allowed"
    code, out = gate.execute(r["request_id"], "ci.run", {}, "agent-1")
    assert code == 200 and out["status"] == "executed"
    assert "dev.executed" in events()


def test_adapter_validation_rejects_bad_payload(gate):
    with pytest.raises(GateError) as e:
        gate.propose("code.open_pr", {"repo": "r"}, "agent-1")
    assert e.value.status == 422


# --- approval flow ----------------------------------------------------------------
def test_execute_before_approval_returns_202(gate):
    r = gate.propose("code.open_pr", PR, "agent-1")
    code, out = gate.execute(r["request_id"], "code.open_pr", PR, "agent-1")
    assert code == 202 and out["status"] == "pending_approval"


def test_full_pr_flow_simulated(gate):
    r = gate.propose("code.open_pr", PR, "agent-1")
    gate.approve(r["request_id"], "matthew")
    code, out = gate.execute(r["request_id"], "code.open_pr", PR, "agent-1")
    assert code == 200 and out["result"]["simulated"] is True and out["result"]["adapter"] == "github_pr"


def test_payload_change_rejected_409(gate):
    r = gate.propose("code.open_pr", PR, "agent-1")
    gate.approve(r["request_id"], "matthew")
    with pytest.raises(GateError) as e:
        gate.execute(r["request_id"], "code.open_pr", {**PR, "base": "main"}, "agent-1")
    assert e.value.status == 409
    assert "dev.payload_mismatch" in events()


def test_action_change_rejected_409(gate):
    r = gate.propose("deploy.release", DEPLOY_STG, "agent-1")
    gate.approve(r["request_id"], "matthew")
    with pytest.raises(GateError) as e:
        gate.execute(r["request_id"], "deploy.rollback", DEPLOY_STG, "agent-1")
    assert e.value.status == 409


def test_payload_mutation_after_propose_does_not_change_approved_payload(gate):
    p = dict(PR)
    r = gate.propose("code.open_pr", p, "agent-1")
    p["base"] = "main"
    gate.approve(r["request_id"], "matthew")
    code, out = gate.execute(r["request_id"], "code.open_pr", PR, "agent-1")
    assert code == 200


def test_approval_expiry(gate, clock):
    r = gate.propose("code.open_pr", PR, "agent-1")
    clock.t += gate.policy.ttl + 1
    with pytest.raises(GateError) as e:
        gate.approve(r["request_id"], "matthew")
    assert e.value.status == 409
    assert gate.status(r["request_id"])["status"] == "expired"
    assert "dev.expired" in events()


def test_approved_but_expired_before_execute(gate, clock):
    r = gate.propose("code.open_pr", PR, "agent-1")
    gate.approve(r["request_id"], "matthew")
    clock.t += gate.policy.ttl + 1
    with pytest.raises(GateError) as e:
        gate.execute(r["request_id"], "code.open_pr", PR, "agent-1")
    assert e.value.status == 409


def test_no_self_approval(gate):
    r = gate.propose("code.open_pr", PR, "agent-1")
    with pytest.raises(GateError) as e:
        gate.approve(r["request_id"], "agent-1")
    assert e.value.status == 403
    assert gate.status(r["request_id"])["status"] == "pending"
    assert "dev.self_approval_rejected" in events()


def test_critical_needs_two_distinct_approvers(gate):
    r = gate.propose("deploy.release", DEPLOY_PROD, "agent-1")
    assert r["tier"] == "critical" and r["approvals_required"] == 2
    gate.approve(r["request_id"], "matthew")
    code, _ = gate.execute(r["request_id"], "deploy.release", DEPLOY_PROD, "agent-1")
    assert code == 202
    with pytest.raises(GateError) as e:
        gate.approve(r["request_id"], "matthew")
    assert e.value.status == 409
    gate.approve(r["request_id"], "helm-reviewer")
    code, out = gate.execute(r["request_id"], "deploy.release", DEPLOY_PROD, "agent-1")
    assert code == 200 and out["result"]["adapter"] == "deploy" and out["result"]["simulated"]


def test_execute_at_most_once(gate):
    r = gate.propose("code.open_pr", PR, "agent-1")
    gate.approve(r["request_id"], "matthew")
    gate.execute(r["request_id"], "code.open_pr", PR, "agent-1")
    with pytest.raises(GateError) as e:
        gate.execute(r["request_id"], "code.open_pr", PR, "agent-1")
    assert e.value.status == 409


def test_denied_cannot_execute(gate):
    r = gate.propose("code.open_pr", PR, "agent-1")
    gate.deny(r["request_id"], "matthew", "no")
    with pytest.raises(GateError) as e:
        gate.execute(r["request_id"], "code.open_pr", PR, "agent-1")
    assert e.value.status == 403


# --- audit -----------------------------------------------------------------------
def test_audit_entries_recorded_and_chain_verifies(gate):
    r = gate.propose("code.open_pr", PR, "agent-1")
    gate.approve(r["request_id"], "matthew")
    gate.execute(r["request_id"], "code.open_pr", PR, "agent-1")
    ev = events()
    for e in ("dev.proposed", "dev.approved", "dev.execute.claimed", "dev.executed"):
        assert e in ev
    recs = [x for x in audit.read() if x["data"].get("request_id") == r["request_id"]]
    assert all(x["data"].get("payload_hash", r["payload_hash"]) == r["payload_hash"] for x in recs)
    assert audit.verify()["ok"]


def test_audit_tamper_detected(gate):
    gate.propose("code.open_pr", PR, "agent-1")
    p = audit.path()
    p.write_text(p.read_text().replace("agent-1", "agent-2"))
    assert not audit.verify()["ok"]


def test_adapter_failure_is_audited(gate):
    class Bad:
        simulated = True
        def execute(self, *a): raise RuntimeError("secret-ish text")
    gate.adapters["code.open_pr"] = Bad()
    r = gate.propose("code.open_pr", PR, "agent-1")
    gate.approve(r["request_id"], "matthew")
    code, out = gate.execute(r["request_id"], "code.open_pr", PR, "agent-1")
    assert out["status"] == "failed" and "secret-ish" not in out["error"]
    assert "dev.execute.failed" in events()


# --- HTTP router (injected identity; production wiring is tested in test_dev_governance_gaps.py)
def test_router_end_to_end_status_codes(clock):
    from fastapi import Header
    def ident(x_test_user: str = Header(...)):
        return {"id": x_test_user, "user": x_test_user, "owners": ["owner-of-" + x_test_user]}
    g = DevGate(clock=clock)
    app = FastAPI(); app.include_router(make_router(lambda: g, ident, ident))
    c = TestClient(app)
    A = {"X-Test-User": "agent-1"}; M = {"X-Test-User": "matthew"}
    rid = c.post("/v1/dev/check", json={"action": "code.open_pr", "payload": PR}, headers=A).json()["request_id"]
    assert c.post(f"/v1/dev/requests/{rid}/execute", json={"action": "code.open_pr", "payload": PR}, headers=A).status_code == 202
    assert c.post(f"/v1/dev/requests/{rid}/approve", headers=A).status_code == 403
    assert c.post(f"/v1/dev/requests/{rid}/approve", headers=M).status_code == 200
    assert c.post(f"/v1/dev/requests/{rid}/execute", json={"action": "code.open_pr", "payload": {**PR, "base": "main"}}, headers=A).status_code == 409
    assert c.post(f"/v1/dev/requests/{rid}/execute", json={"action": "code.open_pr", "payload": PR}, headers=A).status_code == 200
