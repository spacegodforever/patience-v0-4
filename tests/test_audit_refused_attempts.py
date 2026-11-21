"""Refused execute and approve attempts are audited (fail closed).

Closes gap 5 in docs/SENTINEL_FORGE_HASHING_AND_KEYS.md: the 409/501 execute refusals (already used,
not executable, permit-only, no adapter, CAS contention, expired / already expired) and the approve-path
409s (expired, not pending, duplicate approver, contention) now write `dev.execute.refused` /
`dev.approve.refused` with a short reason code. If that audit write fails, the caller gets 503 instead
(fail closed) and the request state is unchanged. Status codes and messages of the refusals themselves
are unchanged. Offline; sockets blocked."""
import importlib.util
import socket
from pathlib import Path

import pytest

import audit
from dev_governance import DevGate, GateError
from dev_governance import decision_schema as ds
from dev_governance.gate import ContentionError
from dev_governance.store import SqliteStore

ROOT = Path(__file__).resolve().parent.parent
STG = {"service": "api", "environment": "staging", "version": "1.2.3"}
INV = {"invoice_id": "INV-1001", "payee": "Acme Supplies (SIMULATED)", "amount_usd": 250.0}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.delenv("PATIENCE_DEV_KILL", raising=False)


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


class Crashing:
    actions = ("ci.run",)
    simulated = True

    def execute(self, action, payload, ctx):
        raise SystemExit("process died")  # leaves the request in 'executing'


@pytest.fixture(params=["memory", "sqlite"])
def store_kind(request):
    return request.param


@pytest.fixture
def mk(store_kind, tmp_path):
    def make(**kw):
        kw.setdefault("clock", Clock())
        if store_kind == "sqlite":
            kw.setdefault("store", SqliteStore(str(tmp_path / "gate.db")))
        return DevGate(**kw)
    return make


def refused(event):
    return [e for e in audit.read() if e["event"] == event]


def only_refusal(event, reason):
    ev = refused(event)
    assert len(ev) == 1, ev
    assert ev[0]["data"]["reason"] == reason
    return ev[0]


def approved_staging(g):
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    g.approve(r["request_id"], "bob")
    return r


# =============================================================== execute path
def test_already_used_is_audited(mk):
    g = mk()
    r = approved_staging(g)
    assert g.execute(r["request_id"], "deploy.release", STG, "agent-1")[0] == 200
    with pytest.raises(GateError) as e:
        g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    assert (e.value.status, e.value.message) == (409, "this approval was already used")
    ev = only_refusal("dev.execute.refused", "already_used")
    assert ev["actor"] == "agent-1"
    assert ev["data"] == {"reason": "already_used", "http_status": 409, "request_id": r["request_id"],
                          "payload_hash": r["payload_hash"], "request_status": "executed"}
    assert audit.verify()["ok"] is True


def test_not_executable_needs_review_is_audited(mk):
    clock = Clock()
    g = mk(clock=clock, adapters=[Crashing()])
    r = g.propose("ci.run", {}, "agent-1", owners=["matthew"])
    with pytest.raises(SystemExit):
        g.execute(r["request_id"], "ci.run", {}, "agent-1")
    clock.t += 301
    assert g.flag_stuck_executions("alice", 300) == [r["request_id"]]
    with pytest.raises(GateError) as e:
        g.execute(r["request_id"], "ci.run", {}, "agent-1")
    assert e.value.status == 409 and e.value.message == "request is not executable (status 'needs_review')"
    ev = only_refusal("dev.execute.refused", "not_executable")
    assert ev["data"]["request_status"] == "needs_review" and ev["data"]["http_status"] == 409
    assert g.status(r["request_id"])["status"] == "needs_review"


def test_permit_only_action_is_audited(mk):
    g = mk()
    r = g.propose("payments.pay_invoice", dict(INV), "agent-a", owners=["alice"])
    g.approve(r["request_id"], "bob")
    with pytest.raises(GateError) as e:
        g.execute(r["request_id"], "payments.pay_invoice", dict(INV), "agent-a")
    assert e.value.status == 409 and "executed only by the execution gateway" in e.value.message
    ev = only_refusal("dev.execute.refused", "permit_only")
    assert ev["data"]["request_id"] == r["request_id"] and ev["data"]["payload_hash"] == r["payload_hash"]
    assert g.status(r["request_id"])["status"] == "approved"   # approval left unused


def test_no_adapter_is_audited(mk):
    g = mk(adapters=[])
    r = approved_staging(g)
    with pytest.raises(GateError) as e:
        g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    assert (e.value.status, e.value.message) == (501, "no adapter configured for 'deploy.release'")
    ev = only_refusal("dev.execute.refused", "no_adapter")
    assert ev["data"]["http_status"] == 501 and ev["data"]["action"] == "deploy.release"
    assert g.status(r["request_id"])["status"] == "approved"


def test_contention_is_audited(mk, monkeypatch):
    g = mk()
    r = approved_staging(g)
    monkeypatch.setattr(g.store, "cas", lambda req: False)
    with pytest.raises(GateError) as e:
        g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    assert isinstance(e.value, GateError) and not isinstance(e.value, ContentionError)
    assert (e.value.status, e.value.message) == (409, "request is under heavy contention; retry")
    only_refusal("dev.execute.refused", "contention")
    assert g.status(r["request_id"])["status"] == "approved"


def test_expired_then_already_expired_are_both_audited(mk):
    clock = Clock()
    g = mk(clock=clock)
    r = approved_staging(g)
    clock.t += g.policy.ttl + 1
    for _ in range(2):
        with pytest.raises(GateError) as e:
            g.execute(r["request_id"], "deploy.release", STG, "agent-1")
        assert (e.value.status, e.value.message) == (409, "approval window expired; submit a new proposal")
    reasons = [x["data"]["reason"] for x in refused("dev.execute.refused")]
    assert reasons == ["expired", "already_expired"]
    assert [x["event"] for x in audit.read()].count("dev.expired") == 1   # the transition itself, once
    assert audit.verify()["ok"] is True


def test_approved_path_writes_no_refusal(mk):
    g = mk()
    r = approved_staging(g)
    assert g.execute(r["request_id"], "deploy.release", STG, "agent-1")[0] == 200
    assert not refused("dev.execute.refused") and not refused("dev.approve.refused")


def test_existing_refusal_events_unchanged(mk):
    g = mk()
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    assert g.execute(r["request_id"], "deploy.release", STG, "agent-1")[0] == 202
    g.deny(r["request_id"], "bob", "no")
    with pytest.raises(GateError):
        g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    evs = [x["event"] for x in audit.read()]
    assert "dev.execute.unapproved_attempt" in evs and "dev.execute.denied_attempt" in evs
    assert "dev.execute.refused" not in evs


# =============================================================== approve path
def test_approve_not_pending_is_audited(mk):
    g = mk()
    r = approved_staging(g)
    with pytest.raises(GateError) as e:
        g.approve(r["request_id"], "carol")
    assert (e.value.status, e.value.message) == (409, "request is approved, not pending")
    ev = only_refusal("dev.approve.refused", "not_pending")
    assert ev["actor"] == "carol" and ev["data"]["request_status"] == "approved"


def test_approve_duplicate_approver_is_audited(mk):
    g = mk()
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    rid = r["request_id"]
    # force a two-approver request so a repeat by the same approver hits the duplicate check
    req = g.store.get(rid)
    req["approvals_required"] = 2
    assert g.store.cas(req)
    g.approve(rid, "bob")
    with pytest.raises(GateError) as e:
        g.approve(rid, "bob")
    assert (e.value.status, e.value.message) == (409, "this approver already approved; a different approver is required")
    ev = only_refusal("dev.approve.refused", "duplicate_approver")
    assert ev["actor"] == "bob" and ev["data"]["request_id"] == rid
    assert g.store.get(rid)["approvals"] == ["bob"] and g.store.get(rid)["status"] == "pending"


def test_approve_expired_and_already_expired_are_audited(mk):
    clock = Clock()
    g = mk(clock=clock)
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    clock.t += g.policy.ttl + 1
    for _ in range(2):
        with pytest.raises(GateError) as e:
            g.approve(r["request_id"], "bob")
        assert (e.value.status, e.value.message) == (409, "approval window expired; submit a new proposal")
    assert [x["data"]["reason"] for x in refused("dev.approve.refused")] == ["expired", "already_expired"]


def test_approve_contention_is_audited(mk, monkeypatch):
    g = mk()
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    monkeypatch.setattr(g.store, "cas", lambda req: False)
    with pytest.raises(GateError) as e:
        g.approve(r["request_id"], "bob")
    assert (e.value.status, e.value.message) == (409, "request is under heavy contention; retry")
    only_refusal("dev.approve.refused", "contention")
    assert "dev.approved" not in [x["event"] for x in audit.read()]


# =============================================================== fail closed
def _break(monkeypatch, event):
    real = audit.append

    def flaky(name, actor=None, **data):
        if name == event:
            raise OSError("disk full")
        return real(name, actor, **data)
    monkeypatch.setattr(audit, "append", flaky)


def _scenario(name, mk, monkeypatch):
    """Return (gate, request_id, thunk, expected_state) for one refusal, set up before the audit breaks."""
    clock = Clock()
    if name == "already_used":
        g = mk(clock=clock); r = approved_staging(g)
        g.execute(r["request_id"], "deploy.release", STG, "agent-1")
        return g, r["request_id"], lambda: g.execute(r["request_id"], "deploy.release", STG, "agent-1"), "executed"
    if name == "no_adapter":
        g = mk(clock=clock, adapters=[]); r = approved_staging(g)
        return g, r["request_id"], lambda: g.execute(r["request_id"], "deploy.release", STG, "agent-1"), "approved"
    if name == "permit_only":
        g = mk(clock=clock); r = g.propose("payments.pay_invoice", dict(INV), "agent-a", owners=["alice"])
        g.approve(r["request_id"], "bob")
        return g, r["request_id"], lambda: g.execute(r["request_id"], "payments.pay_invoice", dict(INV), "agent-a"), "approved"
    if name == "already_expired":
        g = mk(clock=clock); r = approved_staging(g)
        clock.t += g.policy.ttl + 1
        with pytest.raises(GateError):
            g.execute(r["request_id"], "deploy.release", STG, "agent-1")
        return g, r["request_id"], lambda: g.execute(r["request_id"], "deploy.release", STG, "agent-1"), "expired"
    if name == "contention":
        g = mk(clock=clock); r = approved_staging(g)
        monkeypatch.setattr(g.store, "cas", lambda req: False)
        return g, r["request_id"], lambda: g.execute(r["request_id"], "deploy.release", STG, "agent-1"), "approved"
    if name == "approve_not_pending":
        g = mk(clock=clock); r = approved_staging(g)
        return g, r["request_id"], lambda: g.approve(r["request_id"], "carol"), "approved"
    raise AssertionError(name)


@pytest.mark.parametrize("name,event", [
    ("already_used", "dev.execute.refused"), ("no_adapter", "dev.execute.refused"),
    ("permit_only", "dev.execute.refused"), ("already_expired", "dev.execute.refused"),
    ("contention", "dev.execute.refused"), ("approve_not_pending", "dev.approve.refused")])
def test_refusal_audit_failure_fails_closed(mk, monkeypatch, name, event):
    g, rid, thunk, state = _scenario(name, mk, monkeypatch)
    before = audit.read()
    _break(monkeypatch, event)
    with pytest.raises(GateError) as e:
        thunk()
    assert e.value.status == 503 and "fail closed" in e.value.message
    assert g.store.get(rid)["status"] == state   # request state unchanged
    assert audit.read() == before   # nothing written for the refused attempt
    assert audit.verify()["ok"] is True


# =============================================================== reporting
def _load_report_tool():
    spec = importlib.util.spec_from_file_location("audit_report_refusals", ROOT / "tools" / "audit_report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_new_events_are_refusals_in_reports_and_decisions(mk):
    AR = _load_report_tool()
    assert AR.category("dev.execute.refused") == "refused" and AR.category("dev.approve.refused") == "refused"
    assert {"http_status", "request_status"} <= AR.ALLOW_KEYS
    g = mk()
    r = approved_staging(g)
    g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    with pytest.raises(GateError):
        g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    with pytest.raises(GateError):
        g.approve(r["request_id"], "carol")
    d = ds.export_decision(g, r["request_id"])
    got = [(x["event"], x["reason"]) for x in d["refusals"]]
    assert got == [("dev.execute.refused", "already_used"), ("dev.approve.refused", "not_pending")]
