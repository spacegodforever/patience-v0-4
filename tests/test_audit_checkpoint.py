"""F4: verify() fails when a previously seen head is missing; checkpoint kept in a second location."""
import json
import audit


def _log3():
    for i in range(3):
        audit.append("e", "t", i=i)


def test_checkpoint_written_outside_log_dir():
    _log3()
    cp = audit.checkpoint_path()
    assert cp.exists() and cp.parent != audit.path().parent
    assert json.loads(cp.read_text())["seq"] == 3
    assert audit.verify()["ok"]


def test_delete_log_and_head_detected():
    _log3()
    audit.path().unlink()
    audit._head(audit.path()).unlink()
    v = audit.verify()
    assert not v["ok"] and "checkpoint" in v["error"]


def test_truncate_and_rewrite_head_detected():
    _log3()
    p = audit.path()
    lines = p.read_text().splitlines()[:2]
    p.write_text("\n".join(lines) + "\n")
    audit._head(p).write_text(json.loads(lines[-1])["hash"])
    v = audit.verify()
    assert not v["ok"] and "shorter than checkpoint" in v["error"]


def test_head_deleted_detected():
    _log3()
    audit._head(audit.path()).unlink()
    assert not audit.verify()["ok"]


def test_rewritten_log_disagrees_with_checkpoint():
    _log3()
    p = audit.path()
    p.unlink()
    audit._head(p).unlink()
    cp = audit.checkpoint_path().read_text()
    for i in range(3):
        audit.append("forged", "x", i=i)
    audit.checkpoint_path().write_text(cp)  # attacker cannot reach the second location
    v = audit.verify()
    assert not v["ok"] and "disagrees" in v["error"]


def test_no_checkpoint_keeps_old_behaviour(monkeypatch, tmp_path):
    monkeypatch.setenv("PATIENCE_AUDIT_CHECKPOINT", str(tmp_path / "none" / "cp.json"))
    assert audit.verify()["ok"]
    _log3()
    assert audit.verify()["ok"]


def test_unreadable_checkpoint_fails():
    _log3()
    audit.checkpoint_path().write_text("garbage")
    assert not audit.verify()["ok"]
