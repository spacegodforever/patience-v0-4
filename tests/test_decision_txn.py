"""F3: status check + decide under one lock; audit is part of the commit (rolled back on failure)."""
import base64
import threading
import pytest
from fastapi import HTTPException
from test_gateway import env, H  # noqa: F401


def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


def _risky(c, key):
    r = c.post("/v1/check", headers=H(key), json={"tool": "refund", "args": {"amount": 500}})
    assert r.json()["decision"] == "needs_approval"
    return r.json()["request_id"]


def _break_audit(monkeypatch):
    import audit
    monkeypatch.setattr(audit, "append", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))


def test_concurrent_approve_deny_exactly_one_decision(env):
    c, keys, _, _ = env
    import api, approvers, audit
    approvers.add("ann", "ann-password-12")
    approvers.add("ben", "ben-password-12")
    rid = _risky(c, keys["alice"])
    results, barrier = [], threading.Barrier(2)

    def go(approve, user):
        barrier.wait()
        try:
            results.append(("ok", api.decide_request(rid, approve, {"user": user, "role": "approver"})["status"]))
        except HTTPException as e:
            results.append(("err", e.status_code))

    ts = [threading.Thread(target=go, args=(True, "ann")), threading.Thread(target=go, args=(False, "ben"))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(r[0] for r in results) == ["err", "ok"]
    assert [r[1] for r in results if r[0] == "err"] == [409]
    p = api._engine()
    p.refresh()
    assert len([x for x in p.state.approval_log if x["request_id"] == rid]) == 1
    assert len([r for r in audit.read() if r["event"].startswith("approval.")]) == 1


def test_audit_failure_on_check_leaves_no_pending_request(env, monkeypatch):
    c, keys, _, _ = env
    import api
    before = set(api._engine().state.requests)
    _break_audit(monkeypatch)
    r = c.post("/v1/check", headers=H(keys["alice"]), json={"tool": "refund", "args": {"amount": 5000}})
    assert r.status_code == 503
    monkeypatch.undo()
    p = api._engine()
    p.refresh()
    assert set(p.state.requests) == before


def test_audit_failure_on_approve_leaves_request_pending(env, monkeypatch):
    c, keys, _, _ = env
    import api, approvers
    approvers.add("ann", "ann-password-12")
    rid = _risky(c, keys["alice"])
    import audit
    orig = audit.append

    def selective(event, *a, **k):
        if event.startswith("approval."):
            raise OSError("disk full")
        return orig(event, *a, **k)
    monkeypatch.setattr(audit, "append", selective)
    r = c.post(f"/v1/requests/{rid}/approve", headers=_basic("ann", "ann-password-12"))
    assert r.status_code == 503
    monkeypatch.setattr(audit, "append", orig)
    st = c.get(f"/v1/requests/{rid}", headers=H(keys["alice"])).json()
    assert st["status"] == "pending" and st["decided"] is None
    p = api._engine()
    p.refresh()
    assert p.state.approval_log == []
    # and it can still be decided normally afterwards
    assert c.post(f"/v1/requests/{rid}/approve", headers=_basic("ann", "ann-password-12")).json()["status"] == "approved"


def test_every_committed_decision_has_an_audit_record(env):
    c, keys, _, _ = env
    import api, approvers, audit
    approvers.add("ann", "ann-password-12")
    rids = [_risky(c, keys["alice"]) for _ in range(1)]
    for rid in rids:
        c.post(f"/v1/requests/{rid}/deny", headers=_basic("ann", "ann-password-12"), json={"reason": "no"})
    p = api._engine()
    p.refresh()
    logged = {r["data"]["request_id"] for r in audit.read() if r["event"].startswith("approval.")}
    assert {x["request_id"] for x in p.state.approval_log} <= logged
    checks = {r["data"]["request_id"] for r in audit.read() if r["event"] == "check"}
    assert set(p.state.requests) <= checks
    assert audit.verify()["ok"]
