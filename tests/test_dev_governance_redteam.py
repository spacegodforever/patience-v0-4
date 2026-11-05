"""Regression tests for Hacksaw's red-team of feat/dev-governance @ b97aab9 (critical + high)."""
import base64
import socket
import threading
import pytest
from fastapi.testclient import TestClient

import audit
from dev_governance import DevGate, GateError, load_policy
from dev_governance.policy import normalize_environment
from dev_governance.store import MemoryStore, SqliteStore


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k): raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


PR = {"repo": "spacegodforever/patience-v0-4", "head": "feat/x", "base": "v0.6-security-fixes"}
MERGE = {**PR, "pr_number": 7}
PROD = {"service": "api", "environment": "prod", "version": "1.2.3"}


class SlowAdapter:
    simulated = True
    def __init__(self, actions):
        self.actions, self.calls = actions, 0
        self.started, self.release = threading.Event(), threading.Event()
    def execute(self, action, payload, ctx):
        self.calls += 1
        self.started.set()
        assert self.release.wait(5)
        return {"ok": True}


def _stores(tmp_path):
    return [MemoryStore(), SqliteStore(str(tmp_path / "g.db"))]


# ---- RT-01 (critical): stale writes cannot clobber an execute claim ------------------
@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_rt01_stale_expire_or_deny_cannot_overwrite_executing(tmp_path, kind):
    store = MemoryStore() if kind == "memory" else SqliteStore(str(tmp_path / "g.db"))
    clk = Clock(); ad = SlowAdapter(["code.open_pr"])
    g = DevGate(store=store, clock=clk, adapters=[ad])
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    stale = store.get(rid)  # read before the claim
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("a", g.execute(rid, "code.open_pr", PR, "agent-1")))
    t.start(); assert ad.started.wait(5)
    clk.t += 10 * 3600  # past TTL while the adapter runs
    assert g.status(rid)["status"] == "executing"
    with pytest.raises(GateError) as e:
        g.deny(rid, "alice")
    assert e.value.status == 409
    stale["status"] = "expired"
    assert store.cas(stale) is False  # the old blind REPLACE would have won here
    ad.release.set(); t.join(5)
    assert out["a"][0] == 200 and ad.calls == 1
    assert g.status(rid)["status"] == "executed"
    with pytest.raises(GateError) as e:
        g.execute(rid, "code.open_pr", PR, "agent-1")
    assert e.value.status == 409 and ad.calls == 1


def test_rt01_terminal_rows_are_immutable(tmp_path):
    for store in _stores(tmp_path):
        g = DevGate(store=store, clock=Clock())
        rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
        g.deny(rid, "matthew")
        req = store.get(rid); req["status"] = "approved"
        assert store.cas(req) is False
        assert store.get(rid)["status"] == "denied"


def test_rt01_insert_never_replaces(tmp_path):
    from dev_governance.store import StoreConflict
    for store in _stores(tmp_path):
        g = DevGate(store=store, clock=Clock())
        rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
        req = store.get(rid); req.pop("_v"); req["status"] = "approved"
        with pytest.raises(StoreConflict):
            store.insert(req)


def test_rt01_api_shares_one_store_per_process(monkeypatch, tmp_path):
    import api
    monkeypatch.setenv("PATIENCE_DEV_GATE_DB", str(tmp_path / "shared.db"))
    assert api.dev_gate().store is api.dev_gate().store


def test_rt01_migrates_v1_db(tmp_path):
    import sqlite3
    from dev_governance.store import MIGRATIONS, SCHEMA_VERSION
    db = str(tmp_path / "v1.db")
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        c.execute(MIGRATIONS[0]); c.execute("INSERT INTO meta VALUES ('schema_version','1')")
    s = SqliteStore(db)
    assert s.schema_version() == SCHEMA_VERSION == 2
    g = DevGate(store=s, clock=Clock())
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    assert g.execute(rid, "code.open_pr", PR, "agent-1")[0] == 200


# ---- RT-02 (high): concurrent dual approvals both land ------------------------------
@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_rt02_parallel_approvals_not_lost(tmp_path, kind):
    for i in range(10):
        store = MemoryStore() if kind == "memory" else SqliteStore(str(tmp_path / f"g{i}.db"))
        g = DevGate(store=store, clock=Clock())
        rid = g.propose("deploy.release", PROD, "agent-1")["request_id"]
        bar = threading.Barrier(3); res = {}
        def go(who):
            bar.wait()
            try:
                g.approve(rid, who); res[who] = 200
            except GateError as e:
                res[who] = e.status
        ts = [threading.Thread(target=go, args=(w,)) for w in ("alice", "bob", "carol")]
        [t.start() for t in ts]; [t.join(10) for t in ts]
        st = g.status(rid)
        assert st["status"] == "approved"
        assert len(st["approvals"]) == 2 and len(set(st["approvals"])) == 2
        assert sorted(res.values()) == [200, 200, 409]
        assert set(st["approvals"]) == {w for w, c in res.items() if c == 200}


# ---- RT-03 (high): owner cannot approve their own agent -----------------------------
def test_rt03_owner_blocked_in_gate():
    g = DevGate(clock=Clock())
    rid = g.propose("code.merge_pr", MERGE, "billing-bot", owners=["matthew"])["request_id"]
    with pytest.raises(GateError) as e:
        g.approve(rid, "matthew")
    assert e.value.status == 403
    assert any("dev.self_approval_rejected" in str(ev) and "owner_of_proposer" in str(ev)
               for ev in audit.read())
    assert g.approve(rid, "alice")["status"] == "approved"


def test_rt03_same_string_still_blocked():
    g = DevGate(clock=Clock())
    rid = g.propose("code.merge_pr", MERGE, "matthew", owners=["someone"])["request_id"]
    with pytest.raises(GateError) as e:
        g.approve(rid, "matthew")
    assert e.value.status == 403


def test_rt03_missing_owner_fails_closed_for_non_low():
    g = DevGate(clock=Clock())
    with pytest.raises(GateError) as e:
        g.propose("code.merge_pr", MERGE, "billing-bot", require_owners=True)
    assert e.value.status == 403
    assert g.propose("ci.run", {}, "billing-bot", require_owners=True)["status"] == "allowed"


def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


def test_rt03_owner_blocked_via_api(monkeypatch, tmp_path):
    import approvers, api, identity
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    monkeypatch.delenv("PATIENCE_LEGACY_APPROVER_TOKEN", raising=False)
    key = identity.add_agent("billing-bot")
    agents = identity.load_agents(); agents["billing-bot"]["owners"] = ["matthew"]
    key2 = identity.add_agent("orphan-bot")
    identity._write({**identity.load_agents(), "billing-bot": agents["billing-bot"]})
    approvers.add("matthew", "matthew-password-1", "approver")
    approvers.add("alice", "alice-password-12", "approver")
    c = TestClient(api.app)
    B = {"Authorization": f"Bearer {key}"}
    r = c.post("/v1/dev/check", json={"action": "code.merge_pr", "payload": MERGE}, headers=B)
    assert r.status_code == 200, r.text
    rid = r.json()["request_id"]
    assert c.post(f"/v1/dev/requests/{rid}/approve", headers=_basic("matthew", "matthew-password-1")).status_code == 403
    assert c.post(f"/v1/dev/requests/{rid}/approve", headers=_basic("alice", "alice-password-12")).status_code == 200
    # agent without owner mapping cannot propose a non-low action
    r = c.post("/v1/dev/check", json={"action": "code.merge_pr", "payload": MERGE},
               headers={"Authorization": f"Bearer {key2}"})
    assert r.status_code == 403


# ---- RT-04 (high): environment aliases cannot downgrade prod -------------------------
@pytest.mark.parametrize("env", ["prd", "live", "prod-us", "PROD", "production1", " Production ", "us-prod",
                                 "prod_eu", "LIVE-2", None, "", "mars", "uat2"])
def test_rt04_prod_aliases_and_unknown_are_critical(env):
    p = load_policy()
    payload = {"service": "api", "version": "1"}
    if env is not None:
        payload["environment"] = env
    for action in ("deploy.release", "deploy.rollback", "db.migrate", "infra.apply"):
        a = p.assess(action, payload)
        assert a.tier == "critical" and a.approvals_required == 2, (action, env)


@pytest.mark.parametrize("env,tier", [("staging", "medium"), ("Stage", "medium"), ("dev", "medium"),
                                      ("qa", "medium")])
def test_rt04_known_nonprod_unchanged(env, tier):
    assert load_policy().assess("deploy.release", {"environment": env}).tier == tier


def test_rt04_normalizer():
    assert normalize_environment("prd") == "production"
    assert normalize_environment("staging") == "staging"
    assert normalize_environment("unknown-env") is None


# ---- RT-05 (high): MemoryStore claim is atomic ---------------------------------------
@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_rt05_concurrent_execute_runs_once(tmp_path, kind):
    for i in range(10):
        store = MemoryStore() if kind == "memory" else SqliteStore(str(tmp_path / f"e{i}.db"))
        class Count:
            simulated = True; actions = ["code.open_pr"]; calls = 0
            def execute(self, *a):
                Count.calls += 1; return {"ok": True}
        g = DevGate(store=store, clock=Clock(), adapters=[Count()])
        rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
        g.approve(rid, "matthew")
        bar = threading.Barrier(2); codes = []
        def go():
            bar.wait()
            try:
                codes.append(g.execute(rid, "code.open_pr", PR, "agent-1")[0])
            except GateError as e:
                codes.append(e.status)
        ts = [threading.Thread(target=go) for _ in range(2)]
        [t.start() for t in ts]; [t.join(10) for t in ts]
        assert sorted(codes) == [200, 409] and Count.calls == 1


# ---- RT-06 (high): strict canonical payloads ----------------------------------------
@pytest.mark.parametrize("bad", [{"x": {1, 2}}, {"x": b"raw"}, {"x": float("nan")}, {1: "int key"},
                                 {"x": object()}])
def test_rt06_non_json_payload_rejected(bad):
    with pytest.raises(GateError) as e:
        DevGate(clock=Clock()).propose("ci.run", bad, "agent-1")
    assert e.value.status == 422


def test_rt06_json_identical_ok_type_change_409():
    g = DevGate(clock=Clock())
    p = {**PR, "n": 1}
    rid = g.propose("code.open_pr", p, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    with pytest.raises(GateError) as e:
        g.execute(rid, "code.open_pr", {**PR, "n": "1"}, "agent-1")
    assert e.value.status == 409
    with pytest.raises(GateError) as e:
        g.execute(rid, "code.open_pr", {**PR, "n": {1, 2}}, "agent-1")
    assert e.value.status == 409
    assert g.execute(rid, "code.open_pr", dict(reversed(list(p.items()))), "agent-1")[0] == 200


def test_rt06_hash_matches_stored_body():
    from dev_governance.gate import payload_hash
    store = MemoryStore()
    g = DevGate(store=store, clock=Clock())
    rid = g.propose("code.open_pr", {**PR, "labels": ("a", "b")}, "agent-1")["request_id"]
    req = store.get(rid)
    assert req["payload_hash"] == payload_hash(req["action"], req["payload"])


# ---- RT-12 (medium, fixed alongside RT-01): execute is an allowlist ------------------
def test_rt12_bogus_status_not_executed():
    store = MemoryStore()
    g = DevGate(store=store, clock=Clock())
    rid = g.propose("deploy.release", PROD, "agent-1")["request_id"]
    req = store.get(rid); req["status"] = "approving"; assert store.cas(req)
    with pytest.raises(GateError) as e:
        g.execute(rid, "deploy.release", PROD, "agent-1")
    assert e.value.status == 409
    req = store.get(rid); req["status"] = "approved"; req["approvals"] = ["alice"]; assert store.cas(req)
    with pytest.raises(GateError) as e:  # 1 of 2
        g.execute(rid, "deploy.release", PROD, "agent-1")
    assert e.value.status == 409
