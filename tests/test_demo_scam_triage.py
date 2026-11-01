"""Scam-triage demo: fixed snapshot -> rule-based assess -> needs_approval -> approve -> simulated send -> audit."""
import json, os, socket, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demos import scam_triage as st


@pytest.fixture
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)


def _clear(monkeypatch):
    for k in list(os.environ):
        if k.startswith("PATIENCE_"):
            monkeypatch.delenv(k)


def _cleanup():
    for k in list(os.environ):
        if k.startswith("PATIENCE_"):
            os.environ.pop(k, None)


@pytest.fixture
def result(tmp_path, monkeypatch, no_network):
    _clear(monkeypatch)
    out = []
    r = st.run(tmp_path, say=out.append)
    yield r, out
    _cleanup()


def test_fixture_rdap_and_controls_are_synthetic_example_domains():
    s = st.load_fixture()
    t = s["cases"][0]
    assert t["domain"] == "new2026.pro" and t["rdap"]["registrar"] == "Dynadot Inc"
    assert t["rdap"]["abuse_email"] == "abuse@dynadot.com" and t["rdap"]["abuse_phone"] == "+1.6502620100"
    assert t["rdap"]["registered"] == "2026-10-27T14:15:19Z"
    assert t["content"]["source"] == "user_report" and t["content"]["page_capture"] is False
    controls = [c for c in s["cases"] if c["synthetic"]]
    assert 1 <= len(controls) <= 2
    for c in controls:
        assert "SYNTHETIC" in c["label"] and ".example" in c["domain"]


def test_target_signals_basis_confidence_and_high_risk():
    s = st.load_fixture()
    a = st.assess(s["cases"][0], s["as_of"])
    assert all(a["signals"][k]["hit"] for k in st.WEIGHTS)
    for sig in a["signals"].values():
        assert sig["basis"] and sig["confidence"]
    assert "user report" in a["signals"]["deposit_to_withdraw"]["basis"]
    assert a["risk"]["level"] == "high"
    assert set(a["unknown"]) == set(st.UNKNOWN_FIELDS)
    assert all(v.startswith("UNKNOWN") for v in a["unknown"].values())


def test_controls_not_flagged_high():
    s = st.load_fixture()
    for c in s["cases"]:
        if c["synthetic"]:
            a = st.assess(c, s["as_of"])
            assert a["risk"]["level"] != "high" and not a["signals"]["young_domain"]["hit"]


def test_young_domain_threshold():
    s = st.load_fixture()
    c = json.loads(json.dumps(s["cases"][0]))
    c["rdap"]["registered"] = "2026-09-01T00:00:00Z"
    assert not st.assess(c, s["as_of"])["signals"]["young_domain"]["hit"]


def test_all_three_reports_need_approval_and_fail_closed(result):
    r, _ = result
    assert [p["args"]["channel"] for p in r["previews"]] == [
        "registrar_abuse_email", "cloudflare_abuse", "google_safe_browsing"]
    assert [d["decision"] for d in r["checks"]] == ["needs_approval"] * 3
    assert r["unknown_variant"] != "allow"


def test_send_refused_before_approval_and_with_changed_payload(result):
    r, _ = result
    assert r["execute_before_approval"] == 202
    assert r["approve"] == [200, 200, 200]
    assert r["execute_changed"] == 409


def test_simulated_send_mock_only_no_network(result):
    r, _ = result  # no_network fixture would raise on any socket use
    assert r["execute"] == [200, 200, 200]
    assert len(r["mock_calls"]) == 3
    assert all(c["args"]["simulated"] is True for c in r["mock_calls"])
    assert r["mock_calls"][0]["args"]["to"] == "abuse@dynadot.com"


def test_audit_verifies_then_detects_tamper(result):
    r, out = result
    assert r["verify"]["ok"] and r["verify"]["records"] >= 8
    assert not r["tampered"]["ok"] and "hash mismatch" in r["tampered"]["error"]
    assert not any("immutable" in line.lower() for line in out)


def test_approve_requires_approver_login(tmp_path, monkeypatch, no_network):
    _clear(monkeypatch)
    st.setup_env(tmp_path)
    from fastapi.testclient import TestClient
    import api, identity
    key = identity.add_agent("triage-agent")
    c = TestClient(api.app)
    A = {"Authorization": f"Bearer {key}"}
    s = st.load_fixture()
    p = st.report_previews(s["cases"][0], st.assess(s["cases"][0], s["as_of"]))[1]
    rid = c.post("/v1/check", headers=A, json=p).json()["request_id"]
    assert c.post(f"/v1/requests/{rid}/approve", headers=A).status_code in (401, 403)
    assert c.post(f"/v1/requests/{rid}/approve").status_code in (401, 403)
    _cleanup()


def test_policy_gap_stock_send_email_single_recipient_is_auto_allowed(tmp_path, monkeypatch, no_network):
    """Documents a real gap: the default policy auto-allows a 1-recipient send_email.
    The demo therefore uses a dedicated tool name that fails closed. If policy changes, update this test."""
    _clear(monkeypatch)
    st.setup_env(tmp_path)
    from fastapi.testclient import TestClient
    import api, identity
    key = identity.add_agent("triage-agent")
    d = TestClient(api.app).post("/v1/check", headers={"Authorization": f"Bearer {key}"},
                                 json={"tool": "send_email", "args": {"to": "abuse@dynadot.com", "subject": "x"}}).json()
    assert d["decision"] == "allow"
    _cleanup()
