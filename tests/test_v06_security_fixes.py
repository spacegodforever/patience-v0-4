"""Regression tests for the v0.6 security review fixes."""
import base64
import pytest
from fastapi.testclient import TestClient
from test_gateway import env, H, ex  # noqa: F401  (fixture reuse)

APPR = {"X-Approver-Token": "appr"}


def _long_args(tail):
    # identical first 400+ chars of the JSON label, different payload afterwards
    return {"amount": 500, "a_note": "x" * 450, "zz_destination": tail}


# ---- fix 1: duplicates compared by full args hash; approval bound per request ----
def test_truncated_label_collision_does_not_share_approval(env):
    c, keys, mock, _ = env
    k = keys["alice"]
    r1 = c.post("/v1/check", headers=H(k), json={"tool": "refund", "args": _long_args("acct-GOOD")}).json()
    r2 = c.post("/v1/check", headers=H(k), json={"tool": "refund", "args": _long_args("acct-EVIL")}).json()
    assert r1["decision"] == "needs_approval"
    assert r2["decision"] != "defer", "different payload must not be folded into the first request"
    assert c.post(f"/v1/requests/{r1['request_id']}/approve", headers=APPR).status_code == 200
    # the second (unapproved) payload must not execute
    r = c.post("/v1/execute", headers=H(k), json={"tool": "refund", "args": _long_args("acct-EVIL"),
                                                  "idempotency_key": "idem-evil-1", "request_id": r2["request_id"]})
    assert r.status_code in (202, 409), r.text
    assert mock.calls == []
    # the approved payload still runs exactly once
    r = c.post("/v1/execute", headers=H(k), json={"tool": "refund", "args": _long_args("acct-GOOD"),
                                                  "idempotency_key": "idem-good-1", "request_id": r1["request_id"]})
    assert r.status_code == 200 and len(mock.calls) == 1
    assert mock.calls[0]["args"]["zz_destination"] == "acct-GOOD"


def test_identical_payload_still_deduplicated(env):
    c, keys, _, _ = env
    k = keys["alice"]
    body = {"tool": "refund", "args": {"amount": 500, "order": "A-9"}}
    assert c.post("/v1/check", headers=H(k), json=body).json()["decision"] == "needs_approval"
    assert c.post("/v1/check", headers=H(k), json=body).json()["decision"] == "defer"


# ---- fix 2: fail closed when no API auth is configured ----
def test_fail_closed_without_auth_config(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "s.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "none.yaml"))
    monkeypatch.delenv("PATIENCE_API_TOKEN", raising=False)
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    import api
    c = TestClient(api.app)
    r = c.post("/v1/check", json={"action": "read the docs"})
    assert r.status_code == 401
    assert c.get("/health").json()["auth"] == "not_configured_fail_closed"
    monkeypatch.setenv("PATIENCE_DEV_OPEN", "1")
    assert c.post("/v1/check", json={"action": "read the docs"}).status_code == 200
    assert c.get("/health").json()["auth"] == "dev_open"


# ---- fix 4: per-user lockout and per-IP rate limit (Basic auth and link PIN) ----
def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


def test_basic_auth_locks_out_user_with_429(env):
    c, keys, _, _ = env
    import approvers
    approvers.add("carol", "carol-password-12", pin="123456")
    rid = c.post("/v1/check", headers=H(keys["alice"]), json={"tool": "refund", "args": {"amount": 500}}).json()["request_id"]
    for _ in range(approvers.MAX_FAILS):
        assert c.post(f"/v1/requests/{rid}/approve", headers=_basic("carol", "wrong")).status_code == 403
    # correct password is now refused while locked
    assert c.post(f"/v1/requests/{rid}/approve", headers=_basic("carol", "carol-password-12")).status_code == 429


def test_per_ip_limit_across_usernames(env):
    c, keys, _, _ = env
    import api
    rid = c.post("/v1/check", headers=H(keys["alice"]), json={"tool": "refund", "args": {"amount": 500}}).json()["request_id"]
    for i in range(api.IP_MAX_FAILS):
        c.post(f"/v1/requests/{rid}/approve", headers=_basic(f"user{i}", "wrong"))
    assert c.post(f"/v1/requests/{rid}/approve", headers=_basic("someone-new", "x")).status_code == 429


def test_link_pin_lockout(env):
    c, keys, _, _ = env
    import approvers, links, api
    approvers.add("dave", "dave-password-12", pin="654321")
    rid = c.post("/v1/check", headers=H(keys["alice"]), json={"tool": "refund", "args": {"amount": 500}}).json()["request_id"]
    p = api._engine()
    req = p.state.requests[rid]
    tok = links.make(req["request_id"], "approve", api.request_hash(req))
    for _ in range(approvers.MAX_FAILS):
        assert c.post(f"/l/{tok}", data={"user": "dave", "pin": "000000"}).status_code == 403
    assert c.post(f"/l/{tok}", data={"user": "dave", "pin": "654321"}).status_code == 429
