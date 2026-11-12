"""Execution Gateway v0: adversarial and control tests. Everything is simulated; sockets are blocked."""
import ast
import json
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import audit
from dev_governance import DevGate, GateError
from dev_governance import breaker as dev_breaker
from dev_governance.gate import payload_hash as gate_payload_hash
from dev_governance.router import make_router
from execution_gateway import (ExecutionGateway, MockPaymentsService, NonceStore, PermitIssuer, PermitVerifier,
                               create_gateway_app, create_payments_app, payload_hash)
from execution_gateway.issuer import PermitError
from execution_gateway.nonces import NonceStoreError
from execution_gateway.permit import b64e, signing_input

ROOT = Path(__file__).resolve().parent.parent
ACTION = "payments.pay_invoice"
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


class Stack:
    """PATIENCE gate + separate gateway + mock payments service, wired like the docs describe."""
    def __init__(self, tmp_path, max_ttl=900, supported=(ACTION,)):
        self.clock = Clock()
        self.issuer = PermitIssuer(clock=self.clock)
        self.gate = DevGate(clock=self.clock, permit_issuer=self.issuer)
        self.service = MockPaymentsService()
        self.nonces = NonceStore(str(tmp_path / "gateway_nonces.db"))
        self.verifier = PermitVerifier(self.issuer.public_keys(), max_ttl_seconds=max_ttl, clock=self.clock)
        self.gw = ExecutionGateway(self.verifier, self.nonces, self.service.issue_client(), clock=self.clock,
                                   supported_actions=supported)
        self.http = TestClient(create_gateway_app(self.gw))

    def permit(self, agent="agent-a", payload=None, owners=("alice",), approver="bob", approvals=None):
        payload = dict(INV if payload is None else payload)
        r = self.gate.propose(ACTION, payload, agent, owners=list(owners))
        rid = r["request_id"]
        for who in (approvals or [approver]):
            self.gate.approve(rid, who)
        return rid, self.gate.issue_permit(rid, ACTION, payload, agent)

    def pay(self, token, agent="agent-a", payload=None, action=ACTION, headers=None):
        h = {"X-Agent-Id": agent} if agent is not None else {}
        if token is not None:
            h["X-Patience-Permit"] = token if token.isascii() else token.encode("latin-1")
        h.update(headers or {})
        return self.http.post("/v1/payments/pay", json={"action": action, "payload": dict(INV if payload is None else payload)},
                              headers=h)


@pytest.fixture
def s(tmp_path): return Stack(tmp_path)


def events(prefix=""): return [r for r in audit.read() if r["event"].startswith(prefix)]
def reasons(): return [r["data"].get("reason_code") for r in events("gateway.rejected")]


def verify_cli(log, *extra, cwd=None):
    """Run the standalone verifier in isolated mode (no repo on sys.path)."""
    p = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "verify_audit.py"), str(log), *extra],
                       capture_output=True, text=True, cwd=cwd or str(ROOT.parent))
    return p.returncode, p.stdout + p.stderr


# ----------------------------------------------------------------------------------------------
# happy path
# ----------------------------------------------------------------------------------------------
def test_happy_path_approved_permit_one_payment_audit_verifies(s):
    rid, p = s.permit()
    assert p["expires_at"] - p["issued_at"] == 300  # default 5 minutes
    r = s.pay(p["permit"])
    assert r.status_code == 200 and r.json()["decision"] == "accept", r.text
    receipt = r.json()["receipt"]
    assert receipt["simulated"] is True and receipt["amount_usd"] == 250.0
    assert len(s.service.ledger) == 1
    ev = [e["event"] for e in audit.read()]
    for needed in ("dev.proposed", "dev.approved", "dev.permit.issued", "gateway.accepted", "gateway.payment_executed"):
        assert needed in ev
    assert audit.verify()["ok"]
    code, out = verify_cli(audit.path())
    assert code == 0 and out.startswith("OK"), out


def test_happy_path_over_the_http_router(tmp_path):
    clock = Clock()
    issuer = PermitIssuer(clock=clock)
    gate = DevGate(clock=clock, permit_issuer=issuer)
    app = FastAPI()
    app.include_router(make_router(lambda: gate, lambda: {"id": "agent-a", "mode": "dev"},
                                   lambda: {"user": "bob", "legacy": False}))
    c = TestClient(app)
    r = c.post("/v1/dev/check", json={"action": ACTION, "payload": INV})
    assert r.status_code == 200, r.text
    rid = r.json()["request_id"]
    assert r.json()["tier"] == "high" and r.json()["status"] == "pending"
    assert c.post(f"/v1/dev/requests/{rid}/approve", json={}).status_code == 200
    # the legacy execute route refuses permit-gated actions: only the gateway executes them
    assert c.post(f"/v1/dev/requests/{rid}/execute", json={"action": ACTION, "payload": INV}).status_code == 409
    pr = c.post(f"/v1/dev/requests/{rid}/permit", json={"action": ACTION, "payload": INV})
    assert pr.status_code == 200, pr.text
    service = MockPaymentsService()
    gw = ExecutionGateway(PermitVerifier(issuer.public_keys(), clock=clock), NonceStore(str(tmp_path / "n.db")),
                          service.issue_client(), clock=clock)
    g = TestClient(create_gateway_app(gw))
    res = g.post("/v1/payments/pay", json={"action": ACTION, "payload": INV},
                 headers={"X-Agent-Id": "agent-a", "X-Patience-Permit": pr.json()["permit"]})
    assert res.status_code == 200 and len(service.ledger) == 1


# ----------------------------------------------------------------------------------------------
# agent has no path around the gateway
# ----------------------------------------------------------------------------------------------
def test_direct_call_without_permit_is_refused(s):
    r = s.pay(None)
    assert r.status_code == 401 and r.json() == {"decision": "reject", "reason_code": "missing_permit"}
    assert s.service.ledger == [] and reasons() == ["missing_permit"]
    r = s.http.post("/v1/payments/pay", content=b"", headers={"X-Agent-Id": "agent-a"})
    assert r.status_code == 401 and s.service.ledger == []


def test_direct_call_to_payments_service_needs_the_credential(s):
    pay_app = TestClient(create_payments_app(s.service))
    body = {"payload": INV, "reference": "x"}
    assert pay_app.post("/charge", json=body).status_code == 401
    assert pay_app.post("/charge", json=body, headers={"X-Service-Credential": "mock_sk_guess"}).status_code == 401
    assert s.service.ledger == []
    with pytest.raises(Exception):
        s.service.issue_client()  # the credential cannot be handed out a second time
    assert not hasattr(s.issuer, "_credential")


def test_agent_side_objects_hold_no_credential(s):
    """The permit, the verifier and the gate carry no payments credential."""
    rid, p = s.permit()
    cred = s.service._credential
    assert cred not in json.dumps(p)
    assert cred not in repr(vars(s.verifier)) and cred not in repr(vars(s.gate))


# ----------------------------------------------------------------------------------------------
# permit forgery / signature / key id
# ----------------------------------------------------------------------------------------------
def _forge(kid, signer, claims):
    c = b64e(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    return f"pp1.{kid}.{c}.{b64e(signer.sign(signing_input(kid, c)))}"


def _claims(s, **over):
    c = {"v": 1, "sub": "agent-a", "act": ACTION, "ph": payload_hash(ACTION, INV), "rid": "dev_x",
         "jti": "f" * 32, "iat": int(s.clock()), "nbf": int(s.clock()), "exp": int(s.clock()) + 300}
    c.update(over)
    return c


def test_forged_permit_signed_by_attacker_key_unknown_kid(s):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    evil = PermitIssuer(Ed25519PrivateKey.generate(), clock=s.clock)
    r = s.pay(_forge(evil.kid, evil._sk, _claims(s)))
    assert r.status_code == 401 and r.json()["reason_code"] == "unknown_key_id"
    assert s.service.ledger == []


def test_signature_with_wrong_key_under_real_kid(s):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    evil = Ed25519PrivateKey.generate()
    r = s.pay(_forge(s.issuer.kid, evil, _claims(s)))
    assert r.status_code == 401 and r.json()["reason_code"] == "bad_signature"
    assert s.service.ledger == []


def test_claims_edited_after_signing_are_rejected(s):
    _, p = s.permit()
    kid, c, sig = p["permit"].split(".")[1:]
    import base64
    claims = json.loads(base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)))
    claims["exp"] += 100000  # try to extend lifetime
    forged = f"pp1.{kid}.{b64e(json.dumps(claims, sort_keys=True, separators=(',', ':')).encode())}.{sig}"
    r = s.pay(forged)
    assert r.json()["reason_code"] == "bad_signature" and s.service.ledger == []


@pytest.mark.parametrize("token", [
    "x", "pp1", "pp1.a.b.c", "pp1." + "0" * 16 + ".!!!.???", "pp2." + "0" * 16 + ".YQ.YQ",
    "pp1." + "0" * 16 + ".YQ.YQ.extra", "é" * 20, "A" * 5000, "   ", "pp1..."])
def test_malformed_permits_are_rejected(s, token):
    r = s.pay(token)
    assert r.status_code in (401, 400) and r.json()["decision"] == "reject"
    assert r.json()["reason_code"] in ("malformed_permit", "missing_permit", "unknown_key_id")
    assert s.service.ledger == []


def test_unknown_key_after_rotation_or_empty_keyring(s, tmp_path):
    _, p = s.permit()
    gw = ExecutionGateway(PermitVerifier({}, clock=s.clock), NonceStore(str(tmp_path / "n2.db")),
                          MockPaymentsService().issue_client(), clock=s.clock)
    res = gw.handle(p["permit"], "agent-a", ACTION, INV)
    assert res.status == 401 and res.body["reason_code"] == "unknown_key_id"


def test_keyring_entry_with_wrong_kid_is_a_config_error(s):
    with pytest.raises(ValueError):
        PermitVerifier({"0" * 16: s.issuer.public_hex})


# ----------------------------------------------------------------------------------------------
# replay, expiry, window, ttl
# ----------------------------------------------------------------------------------------------
def test_replay_is_rejected_and_pays_once(s):
    _, p = s.permit()
    assert s.pay(p["permit"]).status_code == 200
    r = s.pay(p["permit"])
    assert r.status_code == 409 and r.json()["reason_code"] == "replayed"
    assert len(s.service.ledger) == 1


def test_concurrent_replay_exactly_one_payment(s):
    _, p = s.permit()
    out = []
    def go(): out.append(s.gw.handle(p["permit"], "agent-a", ACTION, INV).status)
    ts = [threading.Thread(target=go) for _ in range(10)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert sorted(out).count(200) == 1 and len(s.service.ledger) == 1


def test_replay_survives_gateway_restart(s, tmp_path):
    _, p = s.permit()
    assert s.pay(p["permit"]).status_code == 200
    gw2 = ExecutionGateway(s.verifier, NonceStore(s.nonces.path), MockPaymentsService().issue_client(),
                           clock=s.clock)  # a fresh gateway process over the same nonce file
    assert gw2.handle(p["permit"], "agent-a", ACTION, INV).body["reason_code"] == "replayed"


def test_expired_permit_is_rejected(s):
    _, p = s.permit()
    s.clock.t += 300 + 5  # exactly at exp + skew: still inside the tolerated skew
    assert s.gw.handle(p["permit"], "agent-a", ACTION, INV).status == 200
    _, p2 = s.permit(payload={**INV, "invoice_id": "INV-2"})
    s.clock.t += 300 + 6
    r = s.pay(p2["permit"], payload={**INV, "invoice_id": "INV-2"})
    assert r.status_code == 403 and r.json()["reason_code"] == "expired"
    assert len(s.service.ledger) == 1


def test_not_yet_valid_permit_is_rejected(s):
    future = PermitIssuer(s.issuer._sk, clock=lambda: s.clock() + 1000)
    tok = future.issue(agent="agent-a", action=ACTION, payload_hash=payload_hash(ACTION, INV), request_id="dev_x")
    r = s.pay(tok["permit"])
    assert r.status_code == 403 and r.json()["reason_code"] == "not_yet_valid" and s.service.ledger == []


def test_permit_lifetime_longer_than_gateway_max_is_rejected(tmp_path):
    st = Stack(tmp_path, max_ttl=300)
    tok = st.issuer.issue(agent="agent-a", action=ACTION, payload_hash=payload_hash(ACTION, INV),
                          request_id="dev_x", ttl_seconds=900)
    r = st.pay(tok["permit"])
    assert r.json()["reason_code"] == "ttl_exceeds_max" and st.service.ledger == []


def test_issuer_clamps_ttl_and_never_outlives_the_approval(s):
    t = s.issuer.issue(agent="a", action=ACTION, payload_hash="h", request_id="r", ttl_seconds=10 ** 6)
    assert t["exp"] - t["iat"] == 900
    t = s.issuer.issue(agent="a", action=ACTION, payload_hash="h", request_id="r", not_after=s.clock() + 20)
    assert t["exp"] - t["iat"] == 20
    for bad in (0, -5, "x"):
        with pytest.raises(PermitError):
            s.issuer.issue(agent="a", action=ACTION, payload_hash="h", request_id="r", ttl_seconds=bad)
    with pytest.raises(PermitError):
        s.issuer.issue(agent="a", action=ACTION, payload_hash="h", request_id="r", not_after=s.clock() - 1)


# ----------------------------------------------------------------------------------------------
# binding: payload, agent, action
# ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize("change", [{"amount_usd": 9999.0}, {"payee": "Mallory"}, {"invoice_id": "INV-9"},
                                    {"amount_usd": 250.01}])
def test_altered_payload_is_rejected(s, change):
    _, p = s.permit()
    r = s.pay(p["permit"], payload={**INV, **change})
    assert r.status_code == 403 and r.json()["reason_code"] == "payload_mismatch"
    assert s.service.ledger == []
    assert s.pay(p["permit"]).status_code == 200  # the rejected probe did not burn the permit


def test_wrong_agent_is_rejected(s):
    _, p = s.permit(agent="agent-a")
    r = s.pay(p["permit"], agent="agent-b")
    assert r.status_code == 403 and r.json()["reason_code"] == "wrong_agent"
    r = s.http.post("/v1/payments/pay", json={"action": ACTION, "payload": INV},
                    headers={"X-Patience-Permit": p["permit"]})  # no agent id at all
    assert r.json()["reason_code"] == "malformed_input"  # an absent agent id is refused outright
    assert s.service.ledger == []


def test_wrong_action_is_rejected(tmp_path):
    st = Stack(tmp_path, supported=(ACTION, "payments.other"))
    _, p = st.permit()
    r = st.pay(p["permit"], action="payments.other")
    assert r.status_code == 403 and r.json()["reason_code"] == "wrong_action"
    assert st.service.ledger == []


def test_unsupported_action_is_rejected(s):
    _, p = s.permit()
    r = s.pay(p["permit"], action="payments.wire_transfer")
    assert r.json()["reason_code"] == "unsupported_action" and s.service.ledger == []


def test_validly_signed_permit_for_an_invalid_payload_is_still_refused(s):
    bad = {**INV, "amount_usd": -5}
    tok = s.issuer.issue(agent="agent-a", action=ACTION, payload_hash=payload_hash(ACTION, bad), request_id="r")
    r = s.pay(tok["permit"], payload=bad)
    assert r.status_code == 422 and r.json()["reason_code"] == "invalid_payload" and s.service.ledger == []


# ----------------------------------------------------------------------------------------------
# kill switch, malformed input, verifier errors (all fail closed)
# ----------------------------------------------------------------------------------------------
def test_kill_switch_blocks_gateway_and_issuance_and_is_not_sticky(s, monkeypatch):
    rid, p = s.permit()
    rid2 = s.gate.propose(ACTION, {**INV, "invoice_id": "INV-2"}, "agent-a", owners=["alice"])["request_id"]
    monkeypatch.setenv("PATIENCE_DEV_KILL", "1")
    r = s.pay(p["permit"])
    assert r.status_code == 503 and r.json()["reason_code"] == "kill_switch" and s.service.ledger == []
    with pytest.raises(GateError) as e:
        s.gate.approve(rid2, "bob")
    assert e.value.status == 503
    monkeypatch.delenv("PATIENCE_DEV_KILL")
    s.gate.approve(rid2, "bob")
    monkeypatch.setenv("PATIENCE_DEV_KILL", "true")
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid2, ACTION, {**INV, "invoice_id": "INV-2"}, "agent-a")
    assert e.value.status == 503
    monkeypatch.delenv("PATIENCE_DEV_KILL")
    assert s.pay(p["permit"]).status_code == 200  # kill switch rejects without burning the permit


@pytest.mark.parametrize("val", ["1", "true", "YES", "on", " On ", "", "0", "false", "no", "off", "2"])
def test_gateway_kill_switch_reads_same_values_as_patience(val, monkeypatch):
    from execution_gateway.gateway import kill_switch_on
    monkeypatch.setenv("PATIENCE_DEV_KILL", val)
    assert kill_switch_on() == dev_breaker.kill_switch_on()


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"null", b'"str"', b'{"action": 5, "payload": {}}',
                                 b'{"action": "payments.pay_invoice", "payload": []}',
                                 b'{"action": "payments.pay_invoice", "payload": {"amount_usd": NaN}}',
                                 b'{"action": "payments.pay_invoice", "payload": {"amount_usd": Infinity}}',
                                 b"\xff\xfe", b"{" * 10])
def test_malformed_requests_are_rejected_not_crashed(s, raw):
    _, p = s.permit()
    r = s.http.post("/v1/payments/pay", content=raw,
                    headers={"X-Agent-Id": "agent-a", "X-Patience-Permit": p["permit"]})
    assert r.status_code in (400, 401, 422) and r.json()["decision"] == "reject"
    assert s.service.ledger == []


def test_oversized_body_is_rejected(s):
    r = s.http.post("/v1/payments/pay", content=b"{" + b" " * 40000 + b"}", headers={"X-Agent-Id": "a", "X-Patience-Permit": "x"})
    assert r.status_code == 400 and r.json()["reason_code"] == "malformed_input"


def test_verifier_exception_fails_closed(s, monkeypatch):
    _, p = s.permit()
    def boom(*a, **k): raise RuntimeError("verifier bug")
    monkeypatch.setattr(s.verifier, "verify", boom)
    r = s.pay(p["permit"])
    assert r.status_code == 503 and r.json()["reason_code"] == "verifier_error" and s.service.ledger == []
    assert "verifier_error" in reasons()


def test_nonce_store_failure_fails_closed(s, monkeypatch):
    _, p = s.permit()
    def boom(*a, **k): raise NonceStoreError("disk")
    monkeypatch.setattr(s.nonces, "burn", boom)
    r = s.pay(p["permit"])
    assert r.json()["reason_code"] == "verifier_error" and s.service.ledger == []


def test_unwritable_nonce_db_fails_closed(s, tmp_path):
    _, p = s.permit()
    s.nonces.path = str(tmp_path / "no_such_dir" / "n.db")  # simulate the store vanishing
    r = s.pay(p["permit"])
    assert r.json()["reason_code"] == "verifier_error" and s.service.ledger == []


def test_audit_failure_on_accept_means_no_payment(tmp_path):
    st = Stack(tmp_path)
    def broken(*a, **k): raise OSError("disk full")
    st.gw._audit = broken
    _, p = st.permit()
    r = st.pay(p["permit"])
    assert r.status_code == 503 and r.json()["reason_code"] == "audit_unavailable"
    assert st.service.ledger == []
    assert st.pay(None).status_code == 401  # rejects still reject when the audit log is down


def test_payment_backend_failure_is_reported_and_not_retried(s, monkeypatch):
    _, p = s.permit()
    monkeypatch.setattr(s.gw.payments, "pay_invoice", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    r = s.pay(p["permit"])
    assert r.status_code == 502 and r.json()["reason_code"] == "payment_failed"
    assert s.pay(p["permit"]).json()["reason_code"] == "replayed"  # permit is spent; needs a new approval
    assert "gateway.payment_failed" in [e["event"] for e in audit.read()]


# ----------------------------------------------------------------------------------------------
# audit: every decision recorded with a reason code; token never logged; tamper detected
# ----------------------------------------------------------------------------------------------
def test_every_decision_is_audited_with_reason_code_and_no_token(s):
    _, p = s.permit()
    s.pay(None)
    s.pay(p["permit"], agent="agent-b")
    s.pay(p["permit"], payload={**INV, "amount_usd": 1.0})
    assert s.pay(p["permit"]).status_code == 200
    s.pay(p["permit"])
    assert reasons() == ["missing_permit", "wrong_agent", "payload_mismatch", "replayed"]
    acc = events("gateway.accepted")[0]
    assert acc["data"]["reason_code"] == "ok" and acc["data"]["payload_hash"] == payload_hash(ACTION, INV)
    assert p["permit"] not in Path(audit.path()).read_text()
    assert verify_cli(audit.path())[0] == 0


def test_tampered_gateway_audit_is_detected_by_the_standalone_verifier(s):
    _, p = s.permit()
    s.pay(p["permit"]); s.pay(p["permit"])
    log = Path(audit.path())
    assert verify_cli(log)[0] == 0
    lines = log.read_text().splitlines()
    i = next(n for n, l in enumerate(lines) if '"reason_code":"replayed"' in l)
    lines[i] = lines[i].replace('"replayed"', '"ok"')  # an attacker hides the replay attempt
    log.write_text("\n".join(lines) + "\n")
    code, out = verify_cli(log)
    assert code == 1 and f"line {i + 1}" in out and "modified" in out


# ----------------------------------------------------------------------------------------------
# PATIENCE gate side: permits only after approval, once, to the right caller
# ----------------------------------------------------------------------------------------------
def test_no_permit_before_approval_or_after_denial(s):
    rid = s.gate.propose(ACTION, INV, "agent-a", owners=["alice"])["request_id"]
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid, ACTION, INV, "agent-a")
    assert e.value.status == 409
    s.gate.deny(rid, "bob")
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid, ACTION, INV, "agent-a")
    assert e.value.status == 403
    assert not events("dev.permit.issued")


def test_proposer_and_owner_cannot_approve_so_no_self_issued_permit(s):
    rid = s.gate.propose(ACTION, INV, "agent-a", owners=["alice"])["request_id"]
    for who in ("agent-a", "alice"):
        with pytest.raises(GateError) as e:
            s.gate.approve(rid, who)
        assert e.value.status == 403
    with pytest.raises(GateError):
        s.gate.issue_permit(rid, ACTION, INV, "agent-a")


def test_one_approval_yields_exactly_one_permit(s):
    rid, p = s.permit()
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid, ACTION, INV, "agent-a")
    assert e.value.status == 409
    assert len(events("dev.permit.issued")) == 1
    assert s.gate.status(rid)["status"] == "permit_issued"
    with pytest.raises(GateError):
        s.gate.execute(rid, ACTION, INV, "agent-a")


def test_permit_requires_matching_payload_and_proposer(s):
    rid = s.gate.propose(ACTION, INV, "agent-a", owners=["alice"])["request_id"]
    s.gate.approve(rid, "bob")
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid, ACTION, {**INV, "amount_usd": 499.0}, "agent-a")
    assert e.value.status == 409
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid, ACTION, INV, "agent-evil")
    assert e.value.status == 403
    assert s.gate.status(rid)["status"] == "approved"  # failed attempts did not consume the approval
    assert s.gate.issue_permit(rid, ACTION, INV, "agent-a")["agent"] == "agent-a"


def test_permit_is_bound_to_proposer_even_if_owner_requests_it(s):
    rid = s.gate.propose(ACTION, INV, "agent-a", owners=["alice"])["request_id"]
    s.gate.approve(rid, "bob")
    tok = s.gate.issue_permit(rid, ACTION, INV, "alice")  # execute_by=proposer_or_owner
    assert s.pay(tok["permit"], agent="alice").json()["reason_code"] == "wrong_agent"
    assert s.pay(tok["permit"], agent="agent-a").status_code == 200


def test_expired_approval_gives_no_permit(s):
    rid = s.gate.propose(ACTION, INV, "agent-a", owners=["alice"])["request_id"]
    s.gate.approve(rid, "bob")
    s.clock.t += s.gate.policy.ttl + 1
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid, ACTION, INV, "agent-a")
    assert e.value.status == 409


def test_permit_never_outlives_the_approval_window(s):
    rid = s.gate.propose(ACTION, INV, "agent-a", owners=["alice"])["request_id"]
    s.gate.approve(rid, "bob")
    s.clock.t += s.gate.policy.ttl - 30
    tok = s.gate.issue_permit(rid, ACTION, INV, "agent-a")
    assert tok["expires_at"] - tok["issued_at"] == 30


def test_large_payment_needs_two_approvers_before_a_permit(s):
    big = {**INV, "amount_usd": 5000.0}
    rid = s.gate.propose(ACTION, big, "agent-a", owners=["alice"])["request_id"]
    s.gate.approve(rid, "bob")
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid, ACTION, big, "agent-a")
    assert e.value.status == 409
    s.gate.approve(rid, "carol")
    assert s.pay(s.gate.issue_permit(rid, ACTION, big, "agent-a")["permit"], payload=big).status_code == 200


def test_propose_rejects_malformed_invoice_payloads(s):
    for bad in ({}, {**INV, "amount_usd": 0}, {**INV, "amount_usd": -1}, {**INV, "amount_usd": True},
                {**INV, "amount_usd": float("inf")}, {**INV, "amount_usd": "250"}, {**INV, "currency": "EUR"},
                {**INV, "extra": 1}, {**INV, "invoice_id": "../etc"}, {**INV, "payee": ""},
                {**INV, "amount_usd": 10 ** 9}):
        with pytest.raises(GateError) as e:
            s.gate.propose(ACTION, bad, "agent-a", owners=["alice"])
        assert e.value.status == 422, bad


def test_permit_issuance_is_audited_without_the_token(s):
    rid, p = s.permit()
    ev = events("dev.permit.issued")[0]
    assert ev["data"]["permit_id"] and ev["data"]["payload_hash"] == gate_payload_hash(ACTION, INV)
    assert p["permit"] not in json.dumps(audit.read())


def test_permit_action_is_never_executed_by_the_gate_even_with_an_adapter_free_path(s):
    rid = s.gate.propose(ACTION, INV, "agent-a", owners=["alice"])["request_id"]
    s.gate.approve(rid, "bob")
    with pytest.raises(GateError) as e:
        s.gate.execute(rid, ACTION, INV, "agent-a")
    assert e.value.status == 409 and "gateway" in e.value.message
    assert s.service.ledger == []


def test_non_permit_actions_cannot_get_permits(s):
    rid = s.gate.propose("ci.run", {"job": "x"}, "agent-a")["request_id"]
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid, "ci.run", {"job": "x"}, "agent-a")
    assert e.value.status == 422


def test_breaker_frozen_agent_gets_no_permit(s):
    rid = s.gate.propose(ACTION, INV, "agent-a", owners=["alice"])["request_id"]
    s.gate.approve(rid, "bob")
    for _ in range(3):
        s.gate.breaker.record("agent-a", "anomaly")
    assert s.gate.breaker.frozen("agent-a")
    with pytest.raises(GateError) as e:
        s.gate.issue_permit(rid, ACTION, INV, "agent-a")
    assert e.value.status == 423


def test_payload_hash_matches_the_gate_for_all_shapes():
    for pl in (INV, {"b": 1, "a": [1, 2, {"z": None}]}, {"é": "ü"}, {"x": 1.5}, {}):
        for act in (ACTION, "  Payments.Pay_Invoice "):
            assert payload_hash(act, pl) == gate_payload_hash(act, pl)


# ----------------------------------------------------------------------------------------------
# key and nonce-store hygiene
# ----------------------------------------------------------------------------------------------
def test_nonce_store_is_private_durable_and_append_only(tmp_path):
    n = NonceStore(str(tmp_path / "n.db"))
    assert n.burn("j1", 5, 1.0, "a", "r") is True and n.burn("j1", 5, 2.0, "a", "r") is False
    assert stat.S_IMODE(os.stat(n.path).st_mode) == 0o600
    assert NonceStore(n.path).burn("j1", 5, 3.0, "a", "r") is False  # durable across instances
    c = sqlite3.connect(n.path)
    for sql in ("DELETE FROM used_permits", "UPDATE used_permits SET jti='x'"):
        with pytest.raises(sqlite3.DatabaseError):
            c.execute(sql)
    c.close()
    with pytest.raises(NonceStoreError):
        NonceStore(":memory:")


def test_signing_key_file_is_0600_stable_and_fails_closed_when_malformed(tmp_path):
    path = str(tmp_path / "k.key")
    a = PermitIssuer.from_file(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert PermitIssuer.from_file(path).kid == a.kid
    os.chmod(path, 0o644)
    PermitIssuer.from_file(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600  # loose perms are tightened
    seed = Path(path).read_text().strip()
    assert seed not in json.dumps(a.public_keys())
    Path(path).write_text("not-hex")
    with pytest.raises(PermitError):
        PermitIssuer.from_file(path)


def test_gate_with_durable_store_keeps_one_signing_key(tmp_path, monkeypatch):
    from dev_governance.store import SqliteStore
    from execution_gateway import issuer as issuer_mod
    issuer_mod._CACHE.clear()
    store = SqliteStore(str(tmp_path / "gate.db"))
    g1 = DevGate(store=store)
    g2 = DevGate(store=store)
    assert g1.permit_issuer().kid == g2.permit_issuer().kid
    assert stat.S_IMODE(os.stat(str(tmp_path / "gate.db.permit_key")).st_mode) == 0o600
    issuer_mod._CACHE.clear()


def test_keyring_from_env_takes_public_keys_only(s, monkeypatch):
    from execution_gateway import keyring_from_env
    monkeypatch.setenv("PATIENCE_GATEWAY_PUBKEYS", f"{s.issuer.kid}={s.issuer.public_hex}")
    ring = keyring_from_env()
    v = PermitVerifier(ring, clock=s.clock)
    _, p = s.permit()
    assert v.verify(p["permit"], agent="agent-a", action=ACTION, expected_hash=payload_hash(ACTION, INV)).sub == "agent-a"


def test_gateway_package_does_not_import_the_patience_gate():
    """The gateway verifies with public keys and its own code; it must not depend on gate internals."""
    for f in (ROOT / "execution_gateway").glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            for n in names:
                assert not n.startswith("dev_governance"), (f.name, n)


def test_keyring_with_two_keys_accepts_either_and_old_key_can_be_dropped(s, tmp_path):
    new = PermitIssuer(clock=s.clock)
    ring = {**s.issuer.public_keys(), **new.public_keys()}
    v = PermitVerifier(ring, clock=s.clock)
    h = payload_hash(ACTION, INV)
    for iss in (s.issuer, new):
        tok = iss.issue(agent="agent-a", action=ACTION, payload_hash=h, request_id="r")["permit"]
        assert v.verify(tok, agent="agent-a", action=ACTION, expected_hash=h).kid == iss.kid
    from execution_gateway import PermitRejected
    only_new = PermitVerifier(new.public_keys(), clock=s.clock)
    old = s.issuer.issue(agent="agent-a", action=ACTION, payload_hash=h, request_id="r")["permit"]
    with pytest.raises(PermitRejected) as e:
        only_new.verify(old, agent="agent-a", action=ACTION, expected_hash=h)
    assert e.value.code == "unknown_key_id"
