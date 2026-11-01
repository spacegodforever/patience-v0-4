"""Command Board merged behind the PATIENCE gate: auth, CSRF, audited writes, seed gating,
server-set source, advisory label, hygiene."""
import pathlib
import re
import subprocess
import pytest
from fastapi.testclient import TestClient
from test_gateway import env, H  # noqa: F401

P = "/v1/board"
SIG = {"name": "rates", "value": "4.5%", "trend": "flat", "confidence": 0.6,
       "impact_area": "capital", "source": "spoofed-by-client"}


@pytest.fixture(autouse=True)
def _sessions():
    from coordinator import routes
    routes._SESSIONS.clear()


@pytest.fixture
def dev(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "none.yaml"))
    monkeypatch.setenv("PATIENCE_APPROVER_TOKEN", "appr")
    monkeypatch.delenv("PATIENCE_API_TOKEN", raising=False)
    import api
    return TestClient(api.app)


def _board_routes():
    import command_board.routes as r
    out = []
    for rt in r.router.routes:
        for m in sorted(rt.methods - {"HEAD", "OPTIONS"}):
            out.append((m, re.sub(r"\{[^}]+\}", "x", rt.path)))
    return out


def test_board_mounted_with_all_routes():
    rs = _board_routes()
    assert len(rs) >= 45 and all(p.startswith(P) for _, p in rs)
    assert ("POST", P + "/seed") in rs and ("GET", P + "/command/act-now") in rs


@pytest.mark.parametrize("method,path", _board_routes())
def test_every_board_route_401_without_auth_config(dev, monkeypatch, method, path):
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    r = dev.request(method, path, json={} if method != "GET" else None)
    assert r.status_code == 401


def _login(c):
    import approvers
    approvers.add("matt", "correct horse battery", role="approver")
    r = c.post("/v1/coordinator/session", json={"user": "matt", "password": "correct horse battery"})
    assert r.status_code == 200
    return r.json()["csrf_token"]


def test_session_csrf_required_on_writes(dev, monkeypatch):
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    csrf = _login(dev)
    assert dev.get(P + "/economic-signals").status_code == 200
    assert dev.post(P + "/economic-signals", json=SIG).status_code == 403
    assert dev.post(P + "/economic-signals", json=SIG, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert dev.get(P + "/economic-signals").json() == []
    r = dev.post(P + "/economic-signals", json=SIG, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201 and r.json()["source"] == "session:user:matt"


def test_source_is_server_set_for_agent(env):
    c, keys, _, _ = env
    assert c.get(P + "/economic-signals", headers=H("nope")).status_code == 401
    r = c.post(P + "/economic-signals", headers=H(keys["alice"]), json=SIG)
    assert r.status_code == 201 and r.json()["source"] == "agent:alice"
    got = c.get(P + "/economic-signals", headers=H(keys["alice"])).json()
    assert [s["source"] for s in got] == ["agent:alice"]


def test_write_audited_in_chain(dev):
    import audit
    assert dev.post(P + "/economic-signals", json=SIG).status_code == 201
    import os
    recs = [l for l in pathlib.Path(os.environ["PATIENCE_AUDIT_PATH"]).read_text().splitlines() if "board.write" in l]
    assert len(recs) == 1 and "/v1/board/economic-signals" in recs[0]
    assert audit.verify()["ok"]


def test_audit_failure_refuses_write(dev):
    import audit
    orig = audit.append
    audit.append = lambda *a, **k: (_ for _ in ()).throw(OSError("disk"))
    try:
        r = dev.post(P + "/economic-signals", json=SIG)
    finally:
        audit.append = orig
    assert r.status_code == 503
    assert dev.get(P + "/economic-signals").json() == []


def test_failed_handler_rolls_back(dev):
    bad = dict(SIG, name=" ")
    assert dev.post(P + "/economic-signals", json=bad).status_code in (422,)
    assert dev.get(P + "/economic-signals").json() == []


def test_seed_gating(env, monkeypatch):
    c, keys, _, _ = env
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    r = c.post(P + "/seed", headers=H(keys["alice"]), json={})
    assert r.status_code == 403
    assert c.get(P + "/projects", headers=H(keys["alice"])).json() == []
    import audit, os
    log = pathlib.Path(os.environ["PATIENCE_AUDIT_PATH"]).read_text()
    assert "board.seed_refused" in log


def test_seed_allowed_dev_open_and_audited(dev):
    import os
    r = dev.post(P + "/seed", json={})
    assert r.status_code == 200 and r.json()["seeded"] is True
    assert dev.get(P + "/projects").json() != []
    assert "board.seed" in pathlib.Path(os.environ["PATIENCE_AUDIT_PATH"]).read_text()


def test_seed_allowed_for_approver_session(dev, monkeypatch):
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    csrf = _login(dev)
    assert dev.post(P + "/seed", json={}, headers={"X-CSRF-Token": csrf}).status_code == 200


def test_advisory_label(dev):
    dev.post(P + "/seed", json={})
    for path in ("/command/act-now", "/command/evolution-readiness", "/", "/snapshot"):
        r = dev.get(P + path)
        assert r.status_code == 200 and r.headers["X-Patience-Advisory"] == "true"
        assert "never replace" in r.json()["patience_advisory"]
    r = dev.post(P + "/patience/evaluate", json={})
    assert r.headers.get("X-Patience-Advisory") == "true"
    assert dev.get(P + "/projects").headers["X-Patience-Advisory"] == "true"


def test_board_page_same_origin_paths(dev):
    r = dev.get("/board")
    assert r.status_code == 200 and "Command Board" in r.text
    assert "const API = '/v1/board'" in r.text and "Advisory only" in r.text
    assert "fetchJson('/command/" in r.text  # resolved against API prefix
    assert 'href="/command/' not in r.text and "http://" not in r.text and "https://" not in r.text


def test_board_db_path_from_env(dev, tmp_path):
    import os
    r = dev.get(P + "/health").json()
    assert r["database_path"] == os.environ["PATIENCE_BOARD_DB"]


# ---- hygiene ----
def test_repo_hygiene():
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
    assert [f for f in files if f.endswith((".db", ".db-wal", ".db-shm", ".sqlite"))] == []
    gi = pathlib.Path(".gitignore").read_text()
    assert "*.db" in gi and "*.db-wal" in gi
    root = pathlib.Path(__file__).resolve().parents[1] / "command_board"
    for f in root.rglob("*"):
        if f.suffix not in (".py", ".html"):
            continue
        t = f.read_text()
        assert "0.0.0.0" not in t and "uvicorn.run" not in t, f
        for mod in ("requests", "httpx", "urllib", "smtplib", "subprocess", "socket"):
            assert not re.search(rf"^\s*(import|from)\s+{mod}\b", t, re.M), (f, mod)
        assert not re.search(r"(sk_live|sk_test|AKIA)[0-9A-Za-z]{8,}", t), f
    api = (root.parent / "api.py").read_text()
    assert 'os.environ.get("PATIENCE_API_HOST", "127.0.0.1")' in api or "127.0.0.1" in api
