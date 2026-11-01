"""F6: coordinator sessions persisted hashed, rotated on login; CSRF required in dev mode."""
import sqlite3
import pytest
from fastapi.testclient import TestClient
from test_coordinator import P, _db, dev  # noqa: F401  (fixture reuse)


@pytest.fixture
def matt(tmp_path, monkeypatch):
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    import approvers
    approvers.add("matt", "correct horse battery")
    return approvers


def _login(c):
    r = c.post(P + "/session", json={"user": "matt", "password": "correct horse battery"})
    assert r.status_code == 200
    return r.cookies.get("patience_coord_session") or c.cookies.get("patience_coord_session"), r.json()["csrf_token"]


def test_session_survives_restart(dev, matt):
    c, _ = dev
    tok, csrf = _login(c)
    import api  # routes keep no in-memory session state; a fresh client with only the cookie = restart
    c2 = TestClient(api.app)
    c2.cookies.set("patience_coord_session", tok, path="/v1/coordinator")
    assert c2.get(P + "/projects").status_code == 200
    r = c2.post(P + "/projects", json={"name": "X"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and r.json()["created_by"] == "session:user:matt"


def test_tokens_stored_hashed_only(dev, matt, tmp_path):
    c, _ = dev
    tok, csrf = _login(c)
    db = sqlite3.connect(tmp_path / "coord.db")
    dump = "\n".join(db.iterdump())
    assert tok not in dump and csrf not in dump
    assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 1


def test_login_rotates_session(dev, matt):
    c, _ = dev
    old, _c = _login(c)
    new, _c2 = _login(c)
    assert old != new
    from coordinator import store
    assert store.session_get(old) is None and store.session_get(new)


def test_logout_deletes_persisted_session(dev, matt):
    c, _ = dev
    tok, csrf = _login(c)
    assert c.delete(P + "/session", headers={"X-CSRF-Token": csrf}).status_code == 200
    from coordinator import store
    assert store.session_get(tok) is None


def test_dev_mode_post_without_csrf_is_403(dev):
    c, _ = dev
    del c.headers["X-CSRF-Token"]
    assert c.post(P + "/events", json={"title": "x"}).status_code == 403
    c.headers["X-CSRF-Token"] = "forged"
    assert c.post(P + "/events", json={"title": "x"}).status_code == 403


def test_dev_mode_post_with_csrf_ok(dev):
    c, _ = dev
    assert c.post(P + "/events", json={"title": "x"}).status_code == 200


def test_expired_session_rejected(dev, matt, monkeypatch):
    c, _ = dev
    tok, _c = _login(c)
    from coordinator import store
    db = store.connect()
    db.execute("UPDATE sessions SET exp=0")
    db.commit()
    db.close()
    assert store.session_get(tok) is None
