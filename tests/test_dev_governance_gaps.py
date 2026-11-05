import base64
import socket
import sqlite3
import pytest
from fastapi.testclient import TestClient

import audit
import tiers
from dev_governance import DevGate, GateError, DevPolicy, load_policy
from dev_governance.store import MemoryStore, SqliteStore, SCHEMA_VERSION, default_store


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k): raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


PR = {"repo": "spacegodforever/patience-v0-4", "head": "feat/x", "base": "v0.6-security-fixes"}
PROD = {"service": "api", "environment": "prod", "version": "1.2.3"}


# ---- gap 1: durable state ---------------------------------------------------------
def test_sqlite_state_survives_restart(tmp_path):
    db, clk = str(tmp_path / "g.db"), Clock()
    rid = DevGate(store=SqliteStore(db), clock=clk).propose("code.open_pr", PR, "agent-1")["request_id"]
    DevGate(store=SqliteStore(db), clock=clk).approve(rid, "matthew")
    code, out = DevGate(store=SqliteStore(db), clock=clk).execute(rid, "code.open_pr", PR, "agent-1")
    assert code == 200 and out["result"]["simulated"]
    assert DevGate(store=SqliteStore(db), clock=clk).status(rid)["status"] == "executed"


def test_payload_hash_enforced_after_reload(tmp_path):
    db, clk = str(tmp_path / "g.db"), Clock()
    rid = DevGate(store=SqliteStore(db), clock=clk).propose("code.open_pr", PR, "agent-1")["request_id"]
    DevGate(store=SqliteStore(db), clock=clk).approve(rid, "matthew")
    with pytest.raises(GateError) as e:
        DevGate(store=SqliteStore(db), clock=clk).execute(rid, "code.open_pr", {**PR, "base": "main"}, "agent-1")
    assert e.value.status == 409


def test_expiry_enforced_after_reload(tmp_path):
    db, clk = str(tmp_path / "g.db"), Clock()
    g = DevGate(store=SqliteStore(db), clock=clk)
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    clk.t += g.policy.ttl + 1
    with pytest.raises(GateError) as e:
        DevGate(store=SqliteStore(db), clock=clk).execute(rid, "code.open_pr", PR, "agent-1")
    assert e.value.status == 409
    assert DevGate(store=SqliteStore(db), clock=clk).status(rid)["status"] == "expired"


def test_two_approvals_accumulate_across_restarts(tmp_path):
    db, clk = str(tmp_path / "g.db"), Clock()
    rid = DevGate(store=SqliteStore(db), clock=clk).propose("deploy.release", PROD, "agent-1")["request_id"]
    DevGate(store=SqliteStore(db), clock=clk).approve(rid, "matthew")
    with pytest.raises(GateError):
        DevGate(store=SqliteStore(db), clock=clk).approve(rid, "matthew")
    assert DevGate(store=SqliteStore(db), clock=clk).approve(rid, "reviewer2")["status"] == "approved"


def test_executed_once_across_restart(tmp_path):
    db, clk = str(tmp_path / "g.db"), Clock()
    rid = DevGate(store=SqliteStore(db), clock=clk).propose("code.open_pr", PR, "agent-1")["request_id"]
    DevGate(store=SqliteStore(db), clock=clk).approve(rid, "matthew")
    DevGate(store=SqliteStore(db), clock=clk).execute(rid, "code.open_pr", PR, "agent-1")
    with pytest.raises(GateError) as e:
        DevGate(store=SqliteStore(db), clock=clk).execute(rid, "code.open_pr", PR, "agent-1")
    assert e.value.status == 409


def test_claim_is_compare_and_set(tmp_path):
    s = SqliteStore(str(tmp_path / "g.db"))
    g = DevGate(store=s, clock=Clock())
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    req = s.get(rid); stale = dict(req); req["status"] = "executing"
    assert s.cas(req) is True
    stale["status"] = "denied"
    assert s.cas(stale) is False  # stale version cannot overwrite the claim


def test_schema_version_and_migration_from_v0(tmp_path):
    db = str(tmp_path / "old.db")
    sqlite3.connect(db).close()  # empty pre-versioned file
    s = SqliteStore(db)
    assert s.schema_version() == SCHEMA_VERSION
    SqliteStore(db)  # re-open is idempotent
    assert s.schema_version() == SCHEMA_VERSION


def test_newer_schema_refused(tmp_path):
    db = str(tmp_path / "new.db")
    SqliteStore(db)
    with sqlite3.connect(db) as c:
        c.execute("UPDATE meta SET v='999' WHERE k='schema_version'")
    with pytest.raises(RuntimeError):
        SqliteStore(db)


def test_tampered_row_refused(tmp_path):
    db = str(tmp_path / "g.db")
    g = DevGate(store=SqliteStore(db), clock=Clock())
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    with sqlite3.connect(db) as c:
        c.execute("UPDATE dev_requests SET payload_hash='x' WHERE request_id=?", (rid,))
    with pytest.raises(RuntimeError):
        DevGate(store=SqliteStore(db)).status(rid)


def test_memory_fallback(monkeypatch):
    monkeypatch.setenv("PATIENCE_DEV_GATE_DB", ":memory:")
    assert isinstance(default_store(), MemoryStore)


def test_default_store_is_sqlite(monkeypatch, tmp_path):
    monkeypatch.setenv("PATIENCE_DEV_GATE_DB", str(tmp_path / "d.db"))
    assert isinstance(default_store(), SqliteStore)


# ---- gap 2: API wiring with real auth ----------------------------------------------
def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


@pytest.fixture
def secured(monkeypatch):
    import approvers, api
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    monkeypatch.delenv("PATIENCE_LEGACY_APPROVER_TOKEN", raising=False)
    monkeypatch.setenv("PATIENCE_API_TOKEN", "agent-token-0123456789")
    monkeypatch.setenv("PATIENCE_API_TOKEN_OWNERS", "token-owner")
    approvers.add("matthew", "matthew-password-1", "approver")
    approvers.add("default", "default-password-1", "approver")  # same name as the token caller id
    return TestClient(api.app)


BEARER = {"Authorization": "Bearer agent-token-0123456789"}


def _propose(c):
    r = c.post("/v1/dev/check", json={"action": "code.open_pr", "payload": PR}, headers=BEARER)
    assert r.status_code == 200, r.text
    return r.json()["request_id"]


def test_unauthenticated_requests_rejected(secured):
    c = secured
    assert c.post("/v1/dev/check", json={"action": "code.open_pr", "payload": PR}).status_code == 401
    rid = _propose(c)
    assert c.get(f"/v1/dev/requests/{rid}").status_code == 401
    assert c.post(f"/v1/dev/requests/{rid}/execute", json={"action": "code.open_pr", "payload": PR}).status_code == 401
    assert c.post(f"/v1/dev/requests/{rid}/approve").status_code == 403


def test_identity_header_ignored(secured):
    c = secured
    r = c.post("/v1/dev/check", json={"action": "code.open_pr", "payload": PR},
               headers={"X-Patience-User": "matthew"})
    assert r.status_code == 401
    rid = _propose(c)
    assert c.post(f"/v1/dev/requests/{rid}/approve", headers={"X-Patience-User": "matthew"}).status_code == 403


def test_agent_key_cannot_approve(secured):
    rid = _propose(secured)
    assert secured.post(f"/v1/dev/requests/{rid}/approve", headers=BEARER).status_code == 403


def test_wrong_password_cannot_approve(secured):
    rid = _propose(secured)
    assert secured.post(f"/v1/dev/requests/{rid}/approve", headers=_basic("matthew", "nope")).status_code == 403


def test_self_approval_blocked_via_api(secured):
    rid = _propose(secured)  # proposer id is "default" (token caller)
    r = secured.post(f"/v1/dev/requests/{rid}/approve", headers=_basic("default", "default-password-1"))
    assert r.status_code == 403
    assert "dev.self_approval_rejected" in [x["event"] for x in audit.read()]


def test_full_flow_via_api(secured):
    c = secured
    rid = _propose(c)
    ex = lambda p: c.post(f"/v1/dev/requests/{rid}/execute", json={"action": "code.open_pr", "payload": p}, headers=BEARER)
    assert ex(PR).status_code == 202
    assert c.post(f"/v1/dev/requests/{rid}/approve", headers=_basic("matthew", "matthew-password-1")).status_code == 200
    assert ex({**PR, "base": "main"}).status_code == 409
    r = ex(PR)
    assert r.status_code == 200 and r.json()["result"]["simulated"] is True
    assert ex(PR).status_code == 409
    assert audit.verify()["ok"]


# ---- gap 4: shared tier engine ---------------------------------------------------
def test_shared_tiers_match_pr10_tuple():
    assert tiers.TIERS == ("low", "medium", "high", "critical")


def test_tier_helpers_fail_safe():
    assert tiers.normalize("bogus") == "high"
    assert tiers.max_tier() == "low"
    assert tiers.max_tier("low", "bogus") == "high"
    assert tiers.raise_only("critical", "low") == "critical"
    assert tiers.raise_only("low", "medium") == "medium"


def test_dev_policy_uses_shared_engine():
    import dev_governance.policy as dp
    assert tuple(dp.TIERS) == tiers.TIERS


def test_policy_cannot_weaken_critical_approvals():
    p = DevPolicy({"approvers_required": {"critical": 1, "high": 0}, "actions": {"x": {"tier": "critical"}, "y": {"tier": "high"}}})
    assert p.assess("x", {}).approvals_required == 2
    assert p.assess("y", {}).approvals_required == 1


def test_bogus_floor_raises_to_fail_safe():
    assert load_policy().assess("ci.run", {}, floor="weird").tier == "high"
