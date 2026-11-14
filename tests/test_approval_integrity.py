"""fix/approval-integrity: one approval runs once, no self-approval, approvals expire, atomic audit head."""
import base64
import pytest
from test_gateway import env, H, ex  # noqa: F401

APPR = {"X-Approver-Token": "appr"}
BODY = {"tool": "refund", "args": {"amount": 5000, "order": "A-1"}}


def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


def test_deferred_duplicate_cannot_reuse_approval(env):
    c, keys, mock, _ = env
    k = keys["alice"]
    r1 = c.post("/v1/check", headers=H(k), json=BODY).json()
    r2 = c.post("/v1/check", headers=H(k), json=BODY).json()
    assert (r1["decision"], r2["decision"]) == ("needs_approval", "defer")
    assert c.post(f"/v1/requests/{r1['request_id']}/approve", headers=APPR).status_code == 200
    assert ex(c, k, "idem-dup-001", BODY, request_id=r1["request_id"]).status_code == 200
    assert ex(c, k, "idem-dup-002", BODY, request_id=r2["request_id"]).status_code == 409
    assert len(mock.calls) == 1


def test_deferred_duplicate_first_still_only_once(env):
    c, keys, mock, _ = env
    k = keys["alice"]
    r1 = c.post("/v1/check", headers=H(k), json=BODY).json()
    r2 = c.post("/v1/check", headers=H(k), json=BODY).json()
    c.post(f"/v1/requests/{r1['request_id']}/approve", headers=APPR)
    ex(c, k, "idem-dup-003", BODY, request_id=r2["request_id"])  # deferred copy: refused or consumes it
    ex(c, k, "idem-dup-004", BODY, request_id=r1["request_id"])
    assert len(mock.calls) == 1


def test_self_approval_rejected_and_audited(env):
    c, keys, _, _ = env
    import approvers, audit
    approvers.add("alice", "correct horse battery")
    approvers.add("carol", "correct horse battery")
    r = c.post("/v1/check", headers=H(keys["alice"]), json=BODY).json()
    assert c.post(f"/v1/requests/{r['request_id']}/approve",
                  headers=_basic("alice", "correct horse battery")).status_code == 403
    assert any(e["event"] == "approval.self_rejected" for e in audit.read())
    assert c.post(f"/v1/requests/{r['request_id']}/approve",
                  headers=_basic("carol", "correct horse battery")).status_code == 200


def test_self_deny_still_allowed(env):
    c, keys, _, _ = env
    import approvers
    approvers.add("alice", "correct horse battery")
    r = c.post("/v1/check", headers=H(keys["alice"]), json=BODY).json()
    assert c.post(f"/v1/requests/{r['request_id']}/deny",
                  headers=_basic("alice", "correct horse battery"), json={"reason": "no"}).status_code == 200


def test_approval_expires(env, monkeypatch):
    c, keys, mock, _ = env
    k = keys["alice"]
    r = c.post("/v1/check", headers=H(k), json=BODY).json()
    c.post(f"/v1/requests/{r['request_id']}/approve", headers=APPR)
    import api
    real = api._approval_expired
    monkeypatch.setattr(api, "_approval_expired", lambda req: True)
    assert ex(c, k, "idem-exp-001", BODY, request_id=r["request_id"]).status_code == 409
    monkeypatch.setattr(api, "_approval_expired", real)
    assert ex(c, k, "idem-exp-002", BODY, request_id=r["request_id"]).status_code == 200
    assert len(mock.calls) == 1


def test_approval_expired_logic(monkeypatch):
    import api
    monkeypatch.setenv("PATIENCE_APPROVAL_TTL_SECONDS", "60")
    assert api._approval_expired({"decided": {"at": "2020-01-01T00:00:00+00:00"}})
    from models import now_iso
    assert not api._approval_expired({"decided": {"at": now_iso()}})
    assert api._approval_expired({})  # no decision time: fail closed


def test_audit_head_written_atomically(tmp_path):
    import audit
    for i in range(3):
        audit.append("x", None, i=i)
    assert audit.verify()["ok"]
    assert not list(tmp_path.glob("*.tmp"))
