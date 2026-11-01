"""Coordinator (merged from PATIENCE Experimental): auth, audit, gate routing, LLM fallback."""
import subprocess
import pytest
import httpx
from fastapi.testclient import TestClient
from test_gateway import env, H  # noqa: F401  (fixture reuse)

P = "/v1/coordinator"


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_COORD_DB", str(tmp_path / "coord.db"))
    monkeypatch.delenv("PATIENCE_OLLAMA_MODEL", raising=False)
    from coordinator import routes
    routes._SESSIONS.clear()


@pytest.fixture
def dev(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "none.yaml"))
    monkeypatch.setenv("PATIENCE_APPROVER_TOKEN", "appr")
    monkeypatch.setenv("PATIENCE_EXECUTOR_MOCK", "1")
    monkeypatch.delenv("PATIENCE_API_TOKEN", raising=False)
    import api
    from executors.mock import MockExecutor
    return TestClient(api.app), MockExecutor.reset()


# ---- store ----
def test_store_schema_and_whitelists():
    from coordinator import store
    r = store.add_project("Core", "high", "ship", "dev:x", "x")
    assert r["created_by"] == "dev:x"
    with pytest.raises(ValueError):
        store.set_status(r["id"], "bogus", "dev:x", "x")
    with pytest.raises(ValueError):
        store.add_project("A", "urgent!!", "", "dev:x", "x")
    with pytest.raises(LookupError):
        store.set_status(999, "paused", "dev:x", "x")
    assert {"projects", "events", "previews"} <= {
        x[0] for x in store.connect().execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_db_is_per_test(tmp_path):
    from coordinator import store
    assert store.db_path().parent == tmp_path and store.list_projects() == []


# ---- auth ----
@pytest.mark.parametrize("method,path", [("get", "/projects"), ("get", "/events"), ("get", "/recommendation"),
                                         ("get", "/previews"), ("post", "/projects"), ("post", "/events"),
                                         ("post", "/previews"), ("patch", "/projects/1")])
def test_every_endpoint_401_without_auth_config(dev, monkeypatch, method, path):
    c, _ = dev
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    r = getattr(c, method)(P + path, **({"json": {}} if method != "get" else {}))
    assert r.status_code == 401


def test_agent_key_required_and_source_server_side(env):
    c, keys, _, _ = env
    assert c.get(P + "/projects", headers=H("nope")).status_code == 401
    r = c.post(P + "/events", headers=H(keys["alice"]),
               json={"title": "hi", "kind": "note", "source": "user-input"})
    assert r.status_code == 200 and r.json()["source"] == "agent:alice"


def _login(c):
    import approvers
    approvers.add("matt", "correct horse battery", role="approver")
    r = c.post(P + "/session", json={"user": "matt", "password": "correct horse battery"})
    assert r.status_code == 200
    return r


def test_session_cookie_flags_and_csrf(dev, monkeypatch):
    c, _ = dev
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    r = _login(c)
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc
    csrf = r.json()["csrf_token"]
    assert c.get(P + "/projects").status_code == 200
    assert c.post(P + "/projects", json={"name": "X"}).status_code == 403
    assert c.post(P + "/projects", json={"name": "X"}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    r = c.post(P + "/projects", json={"name": "X"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and r.json()["created_by"] == "session:user:matt"


def test_bad_login_rejected_and_audited(dev):
    c, _ = dev
    import approvers, audit
    approvers.add("matt", "correct horse battery")
    assert c.post(P + "/session", json={"user": "matt", "password": "nope"}).status_code == 403
    assert any(e["event"] == "auth.failed" for e in audit.read())


# ---- policy ----
def test_ranking_deterministic():
    from coordinator import policy
    ps = [{"id": 1, "name": "a", "status": "active", "priority": "medium", "next_step": ""},
          {"id": 2, "name": "b", "status": "active", "priority": "critical", "next_step": "go"},
          {"id": 3, "name": "c", "status": "complete", "priority": "critical", "next_step": ""}]
    assert [p["id"] for p in policy.rank(ps)] == [2, 1]
    assert policy.recommend(ps) == policy.recommend(list(reversed(ps)))


# ---- llm ----
def test_ollama_failure_falls_back_marked_and_audited(dev, monkeypatch):
    c, _ = dev
    import audit
    from coordinator import llm
    monkeypatch.setenv("PATIENCE_OLLAMA_MODEL", "qwen2.5:3b")
    def boom(*a, **k):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(llm.httpx, "post", boom)
    c.post(P + "/projects", json={"name": "Core", "priority": "critical", "next_step": "test"})
    r = c.get(P + "/recommendation").json()
    assert r["mode"] == "deterministic-local" and "ConnectError" in r["llm_error"]
    assert r["llm_suggestion"] is None and r["basis"].startswith("Deterministic")
    rec = [e for e in audit.read() if e["event"] == "coord.recommend"][-1]
    assert rec["data"]["llm_error"]


def test_ollama_output_is_labelled_unverified_and_basis_unchanged(dev, monkeypatch):
    c, _ = dev
    from coordinator import llm
    monkeypatch.setenv("PATIENCE_OLLAMA_MODEL", "m")
    class R:
        def raise_for_status(self): pass
        def json(self): return {"message": {"content": "Do the thing, definitely 100% sure."}}
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **k: R())
    c.post(P + "/projects", json={"name": "Core", "priority": "high"})
    base = c.get(P + "/recommendation").json()
    assert base["llm_suggestion"]["unverified"] is True
    assert base["recommendation"].startswith("Prioritize Core") and base["confidence"] == 0.82
    assert "Deterministic" in base["basis"]


# ---- gate routing ----
def test_preview_goes_through_gate_and_never_executes(dev):
    c, mock = dev
    import audit
    r = c.post(P + "/previews", json={"tool": "refund", "args": {"amount": 5000, "order": "A-1"}})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["decision"] == "needs_approval" and j["executed"] is False and mock.calls == []
    evs = [e["event"] for e in audit.read()]
    assert "check" in evs and "coord.preview.submitted" in evs
    st = c.get(f"/v1/requests/{j['request_id']}")
    assert st.status_code == 200


def test_unknown_tool_needs_approval(dev):
    c, mock = dev
    j = c.post(P + "/previews", json={"tool": "launch_rockets", "args": {}}).json()
    assert j["decision"] == "needs_approval" and j["known_tool"] is False and mock.calls == []


def test_unreadable_policy_fails_closed(dev, monkeypatch):
    c, _ = dev
    import risk_policy
    monkeypatch.setattr(risk_policy, "get_policy", lambda: (_ for _ in ()).throw(OSError("gone")))
    assert c.post(P + "/previews", json={"tool": "refund", "args": {}}).status_code == 503


def test_approved_then_tampered_payload_not_executed(dev):
    c, mock = dev
    body = {"tool": "refund", "args": {"amount": 5000, "order": "A-1"}}
    j = c.post(P + "/previews", json=body).json()
    assert c.post(f"/v1/requests/{j['request_id']}/approve", headers={"X-Approver-Token": "appr"}).status_code == 200
    r = c.post("/v1/execute", json={"tool": "refund", "args": {"amount": 9000, "order": "A-1"},
                                    "idempotency_key": "coord-tamper-1", "request_id": j["request_id"]})
    assert r.status_code != 200 and mock.calls == []


# ---- audit ----
def test_audit_failure_refuses_write(dev, monkeypatch):
    c, _ = dev
    import audit
    from coordinator import store
    monkeypatch.setattr(audit, "append", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    r = c.post(P + "/projects", json={"name": "Nope"})
    assert r.status_code == 503
    monkeypatch.undo()
    assert store.list_projects() == []


def test_audit_chain_verifies_after_coordinator_use(dev):
    c, _ = dev
    import audit
    pid = c.post(P + "/projects", json={"name": "Core"}).json()["id"]
    c.patch(f"{P}/projects/{pid}", json={"status": "paused"})
    c.post(P + "/events", json={"title": "note"})
    c.get(P + "/recommendation")
    c.post(P + "/previews", json={"tool": "send_email", "args": {"recipients": ["a@b.c"]}})
    v = audit.verify()
    assert v["ok"] and v["records"] >= 5


def test_dev_mode_mutation_requires_json(dev):
    c, _ = dev
    assert c.post(P + "/events", content="title=x", headers={"content-type": "text/plain"}).status_code == 415


# ---- hygiene ----
def test_no_runtime_or_secret_files_tracked():
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
    bad = [f for f in files if f.endswith((".db", ".pyc")) or f.split("/")[-1] == ".env"
           or "node_modules/" in f or "__pycache__" in f or "/dist/" in f]
    assert bad == []
