"""C1: off-host replica + signed checkpoints detect a local rewrite."""
import base64
import json
import pytest
import audit
import audit_replica as ar

KEY = "hmac:" + "k" * 40


@pytest.fixture
def rep(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_AUDIT_REPLICA_DIR", str(tmp_path / "replica"))
    monkeypatch.setenv("PATIENCE_AUDIT_SIGNING_KEY", KEY)
    ar.set_sink(None)
    yield ar.sink()
    ar.set_sink(None)


def _log(n=3, ev="e"):
    for i in range(n):
        audit.append(ev, "t", i=i)


def _rewrite_local_with_valid_chain():
    """Attacker rewrites the whole local log, head and local checkpoint consistently."""
    p = audit.path()
    p.unlink()
    audit._head(p).unlink()
    audit.checkpoint_path().unlink()
    ar.set_sink(_NullSink())  # attacker's appends do not reach the replica
    _log(3, ev="forged")
    ar.set_sink(None)


class _NullSink:
    def append_lines(self, lines): pass
    def read_lines(self): return []
    def put_checkpoint(self, blob): pass
    def get_checkpoint(self): return None


def test_replica_mirrors_log_and_verifies(rep):
    _log()
    assert rep.read_lines() == audit.path().read_text().splitlines()
    cp = json.loads(rep.get_checkpoint())
    assert cp["seq"] == 3 and cp["alg"] == "hmac" and cp["sig"]
    r = ar.verify_replica()
    assert r["ok"] and r["lag"] == 0 and r["replica_records"] == 3


def test_local_rewrite_with_valid_chain_detected(rep):
    _log()
    _rewrite_local_with_valid_chain()
    assert audit.verify()["ok"]  # local-only checks are fooled...
    r = ar.verify_replica()
    assert not r["ok"] and "rewrite" in r["error"] and r["bad_seq"] == 1  # ...the replica is not


def test_local_truncation_detected(rep):
    _log()
    p = audit.path()
    p.write_text("\n".join(p.read_text().splitlines()[:1]) + "\n")
    r = ar.verify_replica()
    assert not r["ok"] and "missing" in r["error"]


def test_forged_replica_checkpoint_rejected(rep):
    _log()
    cp = json.loads(rep.get_checkpoint())
    cp["seq"] = 2
    rep.put_checkpoint(json.dumps(cp).encode())
    r = ar.verify_replica()
    assert not r["ok"] and "signature" in r["error"]


def test_wrong_key_rejected(rep, monkeypatch):
    _log()
    monkeypatch.setenv("PATIENCE_AUDIT_SIGNING_KEY", "hmac:" + "z" * 40)
    assert "signature" in ar.verify_replica()["error"]


def test_replica_edit_detected(rep):
    _log()
    lines = rep.read_lines()
    rec = json.loads(lines[1]); rec["actor"] = "mallory"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    rep.log.write_text("\n".join(lines) + "\n")
    assert not ar.verify_replica()["ok"]


def test_ed25519_with_public_verify_key(rep, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s
    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    pub = k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    monkeypatch.setenv("PATIENCE_AUDIT_SIGNING_KEY", "ed25519:" + base64.b64encode(seed).decode())
    _log()
    monkeypatch.setenv("PATIENCE_AUDIT_SIGNING_KEY", "")  # verifier holds only the public key
    monkeypatch.setenv("PATIENCE_AUDIT_VERIFY_KEY", "ed25519:" + base64.b64encode(pub).decode())
    assert ar.verify_replica()["ok"]


def test_best_effort_lag_then_sync(rep, monkeypatch):
    _log(1)
    class Down(_NullSink):
        def append_lines(self, lines): raise OSError("host down")
    ar.set_sink(Down())
    _log(2)  # best effort: append still succeeds locally
    ar.set_sink(None)
    r = ar.verify_replica()
    assert r["ok"] and r["lag"] == 2
    assert ar.sync() == 2 and ar.verify_replica()["lag"] == 0


def test_required_replication_fails_closed(rep, monkeypatch):
    monkeypatch.setenv("PATIENCE_AUDIT_REPLICA_REQUIRED", "1")
    class Down(_NullSink):
        def append_lines(self, lines): raise OSError("host down")
    ar.set_sink(Down())
    with pytest.raises(ar.ReplicationError):
        audit.append("e", "t")
    ar.set_sink(None)


def test_no_sink_is_noop_and_reported():
    _log(1)
    assert ar.verify_replica()["error"] == "no replica sink configured"


def test_sync_refuses_divergent_replica(rep):
    _log()
    _rewrite_local_with_valid_chain()
    with pytest.raises(ar.ReplicationError):
        ar.sync()
