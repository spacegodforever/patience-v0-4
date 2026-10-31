"""Memory foundation (ADR 0011): schema/migrations, record contract, devices, permission registry."""
import base64
import json
import sqlite3
import pytest
from fastapi.testclient import TestClient


def B(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))
    monkeypatch.setenv("PATIENCE_EXECUTOR_MOCK", "1")
    for v in ("PATIENCE_API_TOKEN", "PATIENCE_LLM_API_KEY", "PATIENCE_APPROVER_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    import identity, approvers, api
    keys = {n: identity.add_agent(n) for n in ("alice", "bob")}
    approvers.add("matt", "matt-password-1", "approver")
    approvers.add("alice", "alice-password-1", "approver")  # same name as an agent
    return TestClient(api.app), keys


def A(k):
    return {"Authorization": f"Bearer {k}"}


MATT = B("matt", "matt-password-1")
REC = {"record_type": "project", "content": "Prefers weekly summaries", "source": "user-entered",
       "confidence": 0.8, "classification": "internal", "sharing_scope": "project", "project_id": "p1"}


def events():
    import audit
    return [r["event"] for r in audit.read()]


# ---------------- schema / migrations ----------------
def test_migrations_idempotent_and_versioned(tmp_path):
    from memory_foundation import db
    p = tmp_path / "m.db"
    c = db.connect(p); assert db.schema_version(c) == 1; c.close()
    c = db.connect(p); assert db.schema_version(c) == 1
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"memory_records", "devices", "capability_events", "schema_migrations"} <= tables


def test_newer_schema_fails_closed(tmp_path):
    from memory_foundation import db
    p = tmp_path / "m.db"
    db.connect(p).execute("INSERT INTO schema_migrations VALUES (99,'future',datetime('now'))")
    with pytest.raises(RuntimeError):
        db.connect(p)


def test_db_check_constraints_reject_unknown_class(tmp_path):
    from memory_foundation import db
    c = db.connect(tmp_path / "m.db")
    with pytest.raises(sqlite3.IntegrityError):
        c.execute("INSERT INTO memory_records VALUES ('m','dream','x','s',0.5,'internal','user',NULL,"
                  "'t','t',1,0,NULL,'{}','o')")


# ---------------- record contract ----------------
def test_record_contract_fields_and_provenance(env):
    c, k = env
    r = c.post("/v1/memory/records", headers=A(k["alice"]), json=REC)
    assert r.status_code == 200, r.text
    d = r.json()
    for f in ("memory_id", "record_type", "content", "source", "confidence", "classification", "sharing_scope",
              "project_id", "created_at", "updated_at", "version", "review_required", "expires_at"):
        assert f in d
    assert d["version"] == 1 and d["provenance"]["actor"] == "alice"
    assert "memory.written" in events()


@pytest.mark.parametrize("bad", [
    {"record_type": "dream"}, {"sharing_scope": "public_internet"}, {"classification": "secret"},
    {"confidence": 1.5}, {"extra_field": 1}, {"memory_id": "forged"}, {"version": 7},
    {"sharing_scope": "project", "project_id": None}, {"confidence": "0.5"},
])
def test_record_contract_fails_closed(env, bad):
    c, k = env
    r = c.post("/v1/memory/records", headers=A(k["alice"]), json={**REC, **bad})
    assert r.status_code == 422


def test_governance_memory_always_review_required(env):
    c, k = env
    d = c.post("/v1/memory/records", headers=A(k["alice"]),
               json={**REC, "record_type": "governance", "review_required": False}).json()
    assert d["review_required"] is True


def test_records_scoped_to_caller(env):
    c, k = env
    c.post("/v1/memory/records", headers=A(k["alice"]), json=REC)
    assert c.get("/v1/memory/records", headers=A(k["bob"])).json()["records"] == []
    assert c.post("/v1/memory/records", json=REC).status_code == 401


# ---------------- devices ----------------
def test_device_register_and_revoke(env):
    c, k = env
    assert c.post("/v1/devices", headers=A(k["alice"]), json={"owner": "alice"}).status_code == 403  # agents can't
    d = c.post("/v1/devices", headers=MATT, json={"owner": "alice", "label": "laptop"}).json()
    hdr = {**A(k["alice"]), "X-Device-Id": d["device_id"], "X-Device-Key": d["device_key"]}
    r = c.post("/v1/memory/records", headers=hdr, json=REC)
    assert r.status_code == 200 and r.json()["provenance"]["device_id"] == d["device_id"]
    assert c.post(f"/v1/devices/{d['device_id']}/revoke", headers=MATT).status_code == 200
    assert c.post("/v1/memory/records", headers=hdr, json=REC).status_code == 403
    assert {"device.registered", "device.revoked"} <= set(events())


def test_device_wrong_key_or_other_owner_refused(env, tmp_path):
    c, k = env
    d = c.post("/v1/devices", headers=MATT, json={"owner": "alice"}).json()
    bad = {**A(k["alice"]), "X-Device-Id": d["device_id"], "X-Device-Key": "pdk_wrong"}
    assert c.post("/v1/memory/records", headers=bad, json=REC).status_code == 403
    other = {**A(k["bob"]), "X-Device-Id": d["device_id"], "X-Device-Key": d["device_key"]}
    assert c.post("/v1/memory/records", headers=other, json=REC).status_code == 403
    import os
    raw = open(os.environ["PATIENCE_MEMORY_DB"], "rb").read()
    assert d["device_key"].encode() not in raw  # stored hashed only


# ---------------- permission registry ----------------
def test_default_level_zero_and_request_refused(env):
    c, k = env
    assert c.get("/v1/capabilities/refund/level", headers=A(k["alice"])).json()["level"] == 0
    assert c.post("/v1/capabilities/refund/request", headers=A(k["alice"]), json={"args": {}}).status_code == 403


def test_only_approver_can_grant_no_self_promotion(env):
    c, k = env
    # agent key cannot reach grant at all
    assert c.post("/v1/capabilities/refund/grant", headers=A(k["alice"]),
                  json={"subject": "alice", "level": 4}).status_code == 403
    # approver whose username equals the subject cannot self-grant
    r = c.post("/v1/capabilities/refund/grant", headers=B("alice", "alice-password-1"),
               json={"subject": "alice", "level": 4})
    assert r.status_code == 403
    assert "capability.grant_refused" in events()
    assert c.get("/v1/capabilities/refund/level", headers=A(k["alice"])).json()["level"] == 0


@pytest.mark.parametrize("lvl", [-1, 5, True, "4"])
def test_grant_level_validated(env, lvl):
    c, _ = env
    assert c.post("/v1/capabilities/refund/grant", headers=MATT,
                  json={"subject": "alice", "level": lvl}).status_code in (403, 422)


def test_revocation_wins(env):
    c, k = env
    c.post("/v1/capabilities/refund/grant", headers=MATT, json={"subject": "alice", "level": 3})
    assert c.get("/v1/capabilities/refund/level", headers=A(k["alice"])).json()["level"] == 3
    c.post("/v1/capabilities/refund/revoke", headers=MATT, json={"subject": "alice"})
    assert c.get("/v1/capabilities/refund/level", headers=A(k["alice"])).json()["state"] == "revoked"
    assert c.post("/v1/capabilities/refund/request", headers=A(k["alice"]), json={"args": {}}).status_code == 403
    assert {"capability.granted", "capability.revoked"} <= set(events())


def test_revoke_same_tick_as_grant_wins(tmp_path):
    from memory_foundation import db, store
    con = db.connect(tmp_path / "m.db")
    for kind, lvl in (("revoke", None), ("grant", 4)):  # grant recorded last, same timestamp
        con.execute("INSERT INTO capability_events (capability,subject,kind,level,actor,at) VALUES "
                    "('refund','alice',?,?,'matt','2026-10-31T00:00:00Z')", (kind, lvl))
    assert store.effective(con, "refund", "alice")["level"] == 0


def test_agent_can_self_revoke_but_not_self_raise(env):
    c, k = env
    c.post("/v1/capabilities/refund/grant", headers=MATT, json={"subject": "alice", "level": 2})
    assert c.post("/v1/capabilities/refund/self-revoke", headers=A(k["alice"])).json()["level"] == 0


def test_level4_still_routes_through_gate(env):
    c, k = env
    c.post("/v1/capabilities/refund/grant", headers=MATT, json={"subject": "alice", "level": 4})
    r = c.post("/v1/capabilities/refund/request", headers=A(k["alice"]),
               json={"args": {"amount": 5000, "order": "A-1", "reason": "x"}})
    assert r.status_code == 200
    body = r.json()
    assert body["autonomy"]["level"] == 4
    assert body["gate"]["decision"] == "needs_approval"  # autonomy never bypasses human approval
    assert body["gate"]["request_id"]  # pending a human decision; nothing executed here


def test_audit_failure_rolls_back_grant(env, monkeypatch):
    c, k = env
    import audit
    def boom(*a, **kw): raise OSError("disk full")
    real = audit.append
    audit.append = boom
    try:
        with pytest.raises(OSError):
            c.post("/v1/capabilities/refund/grant", headers=MATT, json={"subject": "alice", "level": 2})
    finally:
        audit.append = real
    assert c.get("/v1/capabilities/refund/level", headers=A(k["alice"])).json()["level"] == 0
