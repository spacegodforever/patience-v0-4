"""Travel-booking demo: fixed snapshot -> compare -> needs_approval -> approve -> simulated execute -> audit."""
import json, os, socket, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demos import travel_booking as tb


@pytest.fixture
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)


@pytest.fixture
def result(tmp_path, monkeypatch, no_network):
    for k in list(os.environ):
        if k.startswith("PATIENCE_"):
            monkeypatch.delenv(k)
    out = []
    r = tb.run(tmp_path, say=out.append)
    yield r, out
    for k in list(os.environ):
        if k.startswith("PATIENCE_"):
            os.environ.pop(k, None)


def test_fixture_snapshot_provenance_and_data():
    s = tb.load_fixture()
    assert s["fetched_at"] == "2026-11-01" and "Helm" in s["supplied_by"]
    assert [(t["days"], t["price_from"]) for t in s["trips"]] == [(8, 1169), (5, 715), (1, 99)]


def test_compare_basis_confidence_and_unknowns():
    cmp = tb.compare(tb.load_fixture())
    assert [r["id"] for r in cmp] == ["heinzhof", "kaernten", "abano"]
    assert cmp[2]["price_per_day_eur"]["value"] == 146.12
    for r in cmp:
        for f in ("price_from_eur", "price_per_day_eur", "dates", "duration_days"):
            assert r[f]["basis"] and r[f]["confidence"]
        assert set(r["unknown"]) == set(tb.UNKNOWN_FIELDS)
        assert all(v.startswith("UNKNOWN") for v in r["unknown"].values())


def test_date_span_matches_days():
    for r in tb.compare(tb.load_fixture()):
        assert r["duration_days"]["confidence"] == "high"


def test_book_trip_needs_approval_and_fail_closed(result):
    r, _ = result
    assert r["check"]["decision"] == "needs_approval"
    assert r["unknown_variant"] != "allow"


def test_execute_refused_before_approval_and_with_changed_payload(result):
    r, _ = result
    assert r["execute_before_approval"] == 202
    assert r["approve"] == 200
    assert r["execute_changed"] == 409


def test_simulated_execute_runs_once_with_approved_payload(result):
    r, _ = result
    assert r["execute"] == 200
    assert len(r["mock_calls"]) == 1
    assert r["mock_calls"][0]["args"]["simulated"] is True and r["mock_calls"][0]["args"]["amount"] == 198


def test_audit_verifies_then_detects_tamper(result):
    r, out = result
    assert r["verify"]["ok"] and r["verify"]["records"] >= 5
    assert not r["tampered"]["ok"] and "hash mismatch" in r["tampered"]["error"]
    assert not any("immutable" in line.lower() for line in out)


def test_audit_records_observe_and_execute(tmp_path, monkeypatch, no_network):
    for k in list(os.environ):
        if k.startswith("PATIENCE_"):
            monkeypatch.delenv(k)
    tb.run(tmp_path, say=lambda *_: None)
    events = [json.loads(l)["event"] for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert events[0] == "observe" and "oracle.compare" in events and "execute.executed" in events
    for k in list(os.environ):
        if k.startswith("PATIENCE_"):
            os.environ.pop(k, None)


def test_approve_requires_approver_login(tmp_path, monkeypatch, no_network):
    for k in list(os.environ):
        if k.startswith("PATIENCE_"):
            monkeypatch.delenv(k)
    tb.setup_env(tmp_path)
    from fastapi.testclient import TestClient
    import api, identity
    key = identity.add_agent("travel-agent")
    c = TestClient(api.app)
    A = {"Authorization": f"Bearer {key}"}
    rid = c.post("/v1/check", headers=A, json={"tool": "book_trip",
                 "args": tb.booking_args(tb.load_fixture()["trips"][0])}).json()["request_id"]
    assert c.post(f"/v1/requests/{rid}/approve", headers=A).status_code in (401, 403)
    assert c.post(f"/v1/requests/{rid}/approve").status_code in (401, 403)
    for k in list(os.environ):
        if k.startswith("PATIENCE_"):
            os.environ.pop(k, None)
