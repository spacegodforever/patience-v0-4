"""C2 risk tiers / batch approval / two-person rule, and C3 executed-only budgets."""
import os
import tempfile

import pytest
import yaml

import risk_policy
from test_gateway import env, H, APPR, ex  # noqa: F401  (fixture re-use)
from twoperson import basic, ensure_accounts

CASES = os.path.join(os.path.dirname(__file__), "cases", "governance_cases.yaml")


def _llm_disagree(monkeypatch):
    import api
    monkeypatch.setattr(api, "second_opinion_risk", lambda text, tags, cats: {
        "categories": ["llm_disagreement"], "consequence": .5, "irreversible": False, "reasons": ["llm: unsure"]})


# ---------------- tiers ----------------
def test_tier_mapping_and_escalation():
    t = risk_policy.risk_tier
    assert t([]) == "low" and t(["llm_disagreement"]) == "low"
    assert t(["communication"]) == "medium" and t(["public_publishing"]) == "medium"
    assert t(["money"], {"amount_total": 999}) == "high"
    assert t(["money"], {"amount_total": 1000}) == "critical"
    assert t(["mass_communication"], {"recipients": 400}) == "high"
    assert t(["mass_communication"], {"recipients": 500}) == "critical"
    for c in ("deletion", "account_permissions", "security", "injection"):
        assert t([c]) == "critical"
    assert t(["communication", "deploy"]) == "high"           # max wins
    assert t(["some_new_category"]) == "high"                 # unknown fails safe
    assert t([], {"amount_total": 10 ** 6}) == "low"          # escalation needs a side-effect category


def test_labeled_cases_tiers_never_relax_decisions():
    """Tiers choose the approval workflow only: needs_approval count is unchanged and no
    high/critical case is allowed."""
    from engine import Patience
    cases = yaml.safe_load(open(CASES))["cases"]
    na, by = 0, {}
    for c in cases:
        with tempfile.TemporaryDirectory() as d:
            out = Patience(os.path.join(d, "s.json")).cycle(c["action"])
        allowed = out["verification"]["verified"]
        cats = out["assessment"]["risk_categories"]
        tier = risk_policy.risk_tier(cats, risk_policy.text_usage(c["action"], cats))
        assert ("allow" if allowed else "needs_approval") == c["expected"], c["action"]
        assert not (allowed and tier in ("high", "critical")), c["action"]
        na += not allowed
        by[tier] = by.get(tier, 0) + 1
    assert len(cases) == 187 and na == 133
    assert by["critical"] > 0 and by["high"] > 0


def test_check_returns_tier(env):
    c, keys, _, _ = env
    a = H(keys["alice"])
    assert c.post("/v1/check", headers=a, json={"action": "read the docs"}).json()["risk_tier"] == "low"
    r = c.post("/v1/check", headers=a, json={"tool": "refund", "args": {"amount": 500}}).json()
    assert r["decision"] == "needs_approval" and r["risk_tier"] == "high"
    r = c.post("/v1/check", headers=a, json={"tool": "refund", "args": {"amount": 5000}}).json()
    assert r["risk_tier"] == "critical"
    assert c.get(f"/v1/requests/{r['request_id']}", headers=a).json()["risk_tier"] == "critical"


# ---------------- two-person rule ----------------
def _critical(c, key, amount=5000):
    r = c.post("/v1/check", headers=H(key), json={"tool": "refund", "args": {"amount": amount, "order": "Z"}}).json()
    assert r["risk_tier"] == "critical"
    return r["request_id"]


def test_two_distinct_approvers_required(env):
    c, keys, mock, _ = env
    ensure_accounts()
    rid = _critical(c, keys["alice"])
    r1 = c.post(f"/v1/requests/{rid}/approve", headers=basic("tp-first"))
    assert r1.status_code == 200 and r1.json()["decision"] == "pending_second_approval"
    assert r1.json()["status"] == "pending" and r1.json()["approvals"] == ["tp-first"]
    # the agent still cannot execute after one approval
    body = {"tool": "refund", "args": {"amount": 5000, "order": "Z"}, "idempotency_key": "tp-key-1", "request_id": rid}
    assert c.post("/v1/execute", headers=H(keys["alice"]), json=body).status_code == 202
    # same approver twice: refused
    assert c.post(f"/v1/requests/{rid}/approve", headers=basic("tp-first")).status_code == 409
    # shared legacy token never counts for critical items
    assert c.post(f"/v1/requests/{rid}/approve", headers=APPR).status_code == 409
    r2 = c.post(f"/v1/requests/{rid}/approve", headers=basic("tp-second"))
    assert r2.status_code == 200 and r2.json()["status"] == "approved"
    st = c.get(f"/v1/requests/{rid}", headers=H(keys["alice"])).json()
    assert st["approvals"] == ["tp-first", "tp-second"]
    r = c.post("/v1/execute", headers=H(keys["alice"]), json={**body, "idempotency_key": "tp-key-2"})
    assert r.status_code == 200 and r.json()["status"] == "executed" and len(mock.calls) == 1
    import audit
    ev = [x["event"] for x in audit.read()]
    assert "approval.first" in ev and "approval.approved" in ev


def test_requesting_agent_can_never_approve(env):
    c, keys, _, _ = env
    import approvers
    approvers.add("alice", "alice-password-12")  # a human account sharing the agent's name
    ensure_accounts()
    import base64
    hdr = {"Authorization": "Basic " + base64.b64encode(b"alice:alice-password-12").decode()}
    rid = _critical(c, keys["alice"])
    assert c.post(f"/v1/requests/{rid}/approve", headers=hdr).status_code == 409
    c.post(f"/v1/requests/{rid}/approve", headers=basic("tp-first"))
    assert c.post(f"/v1/requests/{rid}/approve", headers=hdr).status_code == 409
    rid2 = c.post("/v1/check", headers=H(keys["alice"]), json={"tool": "refund", "args": {"amount": 500}}).json()["request_id"]
    assert c.post(f"/v1/requests/{rid2}/approve", headers=hdr).status_code == 409  # any tier
    # agent bearer keys are never approvers
    assert c.post(f"/v1/requests/{rid}/approve", headers=H(keys["alice"])).status_code == 403


def test_single_deny_is_final_for_critical(env):
    c, keys, _, _ = env
    ensure_accounts()
    rid = _critical(c, keys["alice"])
    c.post(f"/v1/requests/{rid}/approve", headers=basic("tp-first"))
    d = c.post(f"/v1/requests/{rid}/deny", headers=basic("tp-second"), json={"reason": "no"})
    assert d.status_code == 200 and d.json()["status"] == "denied"


def test_high_tier_needs_only_one_approver(env):
    c, keys, _, _ = env
    rid = c.post("/v1/check", headers=H(keys["alice"]), json={"tool": "refund", "args": {"amount": 500}}).json()["request_id"]
    assert c.post(f"/v1/requests/{rid}/approve", headers=APPR).json()["status"] == "approved"


# ---------------- batch ----------------
def test_batch_approves_low_tier_only_all_or_nothing(env, monkeypatch):
    c, keys, _, _ = env
    _llm_disagree(monkeypatch)
    a = H(keys["alice"])
    lows = []
    for i in range(3):
        r = c.post("/v1/check", headers=a, json={"action": f"summarize sign-ups for week {i}"}).json()
        assert r["decision"] == "needs_approval" and r["risk_tier"] == "low", r
        lows.append(r["request_id"])
    high = c.post("/v1/check", headers=a, json={"tool": "refund", "args": {"amount": 500}}).json()["request_id"]
    r = c.post("/v1/requests/batch/approve", headers=APPR, json={"request_ids": lows + [high]})
    assert r.status_code == 409 and "tier high" in str(r.json())
    for rid in lows:  # nothing approved
        assert c.get(f"/v1/requests/{rid}", headers=a).json()["status"] == "pending"
    assert c.post("/v1/requests/batch/approve", headers=a, json={"request_ids": lows}).status_code == 403
    r = c.post("/v1/requests/batch/approve", headers=APPR, json={"request_ids": lows, "reason": "routine"})
    assert r.status_code == 200 and r.json()["approved"] == lows
    for rid in lows:
        st = c.get(f"/v1/requests/{rid}", headers=a).json()
        assert st["status"] == "approved" and st["decided"]["via"] == "batch"
    # already decided -> refused
    assert c.post("/v1/requests/batch/approve", headers=APPR, json={"request_ids": lows[:1]}).status_code == 409
    import audit
    assert [x for x in audit.read() if x["event"] == "approval.batch"][0]["data"]["count"] == 3


def test_batch_rejects_unknown_and_critical(env):
    c, keys, _, _ = env
    rid = _critical(c, keys["alice"])
    assert c.post("/v1/requests/batch/approve", headers=APPR, json={"request_ids": ["nope"]}).status_code == 409
    assert c.post("/v1/requests/batch/approve", headers=APPR, json={"request_ids": [rid]}).status_code == 409
    assert c.post("/v1/requests/batch/approve", headers=APPR, json={"request_ids": []}).status_code == 422


# ---------------- C3: only executed actions count ----------------
def _ledger():
    import api
    p = api._engine()
    p.refresh()
    return p.state.usage_log


def test_gateway_counts_only_successful_execution(env, monkeypatch):
    c, keys, mock, _ = env
    small = {"tool": "refund", "args": {"amount": 150, "order": "S"}}
    # dry run (no executor configured) does not count
    monkeypatch.delenv("PATIENCE_EXECUTOR_MOCK")
    monkeypatch.setenv("PATIENCE_WEBHOOK_URL", "https://hooks.example.com/abc")
    assert ex(c, keys["alice"], "c3-key-dry", small).json()["status"] == "dry_run"
    assert _ledger() == []
    monkeypatch.setenv("PATIENCE_EXECUTOR_MOCK", "1")
    r = ex(c, keys["alice"], "c3-key-live", small)
    assert r.json()["status"] == "executed"
    assert [e["usage"]["amount_total"] for e in _ledger()] == [150]
    # a pending (not executed) gateway call does not count
    assert ex(c, keys["alice"], "c3-key-big", {"tool": "refund", "args": {"amount": 900, "order": "B"}}).status_code == 202
    assert len(_ledger()) == 1


def test_approved_but_unexecuted_does_not_count_and_outcome_rules(env):
    c, keys, _, _ = env
    a, b = H(keys["alice"]), H(keys["bob"])
    rid = c.post("/v1/check", headers=a, json={"tool": "refund", "args": {"amount": 900}}).json()["request_id"]
    assert c.post(f"/v1/requests/{rid}/approve", headers=APPR).status_code == 200
    assert _ledger() == []                                     # approval alone: no budget used
    assert c.post(f"/v1/requests/{rid}/outcome", headers=b, json={"outcome": "executed"}).status_code == 404
    r = c.post(f"/v1/requests/{rid}/outcome", headers=a, json={"outcome": "executed"})
    assert r.status_code == 200 and r.json()["usage_counted"] is True
    c.post(f"/v1/requests/{rid}/outcome", headers=a, json={"outcome": "executed"})  # idempotent
    assert [e["request_id"] for e in _ledger()] == [rid]
    assert c.post(f"/v1/requests/{rid}/outcome", headers=a, json={"outcome": "not_executed"}).status_code == 409
    # pending / denied requests cannot be reported
    pend = c.post("/v1/check", headers=a, json={"tool": "refund", "args": {"amount": 800}}).json()["request_id"]
    assert c.post(f"/v1/requests/{pend}/outcome", headers=a, json={"outcome": "executed"}).status_code == 409
    assert c.post(f"/v1/requests/{pend}/outcome", headers=a, json={"outcome": "maybe"}).status_code == 422


def test_allowed_check_refunded_when_not_executed(env):
    c, keys, _, _ = env
    a = H(keys["alice"])
    rid = c.post("/v1/check", headers=a, json={"tool": "refund", "args": {"amount": 150}}).json()
    assert rid["decision"] == "allow"
    assert len(_ledger()) == 1 and _ledger()[0]["request_id"] == rid["request_id"]
    r = c.post(f"/v1/requests/{rid['request_id']}/outcome", headers=a, json={"outcome": "not_executed"})
    assert r.status_code == 200 and r.json()["usage_counted"] is False
    assert _ledger() == []
