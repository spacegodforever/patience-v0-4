"""F5: approvers.yaml / agents.yaml are written atomically with mode 0600 from creation."""
import os
import stat
import sys
import pytest
import approvers
import identity
import securefile

@pytest.fixture(autouse=True)
def _agents_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))


posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


@posix
def test_approvers_file_0600_immediately():
    os.umask(0o022)
    approvers._save({"alice": {"x": 1}})
    assert _mode(approvers.approvers_path()) == 0o600


@posix
def test_agents_file_0600_immediately():
    os.umask(0o022)
    identity.add_agent("bot1")
    assert _mode(identity.agents_path()) == 0o600


@posix
def test_temp_file_is_0600_before_any_bytes(monkeypatch, tmp_path):
    seen = []
    real = os.fdopen

    def spy(fd, *a, **k):
        seen.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return real(fd, *a, **k)
    monkeypatch.setattr(securefile.os, "fdopen", spy)
    securefile.write_secret(tmp_path / "s.yaml", "k: v\n")
    assert seen == [0o600]


def test_crash_mid_write_leaves_old_file(monkeypatch):
    approvers._save({"alice": {"v": 1}})
    p = approvers.approvers_path()
    before = p.read_bytes()

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(securefile.os, "replace", boom)
    with pytest.raises(OSError):
        approvers._save({"mallory": {"v": 2}})
    assert p.read_bytes() == before
    assert not [f for f in os.listdir(p.parent) if f.endswith(".tmp")]


def test_crash_mid_write_agents(monkeypatch):
    identity.add_agent("a1")
    p = identity.agents_path()
    before = p.read_bytes()
    monkeypatch.setattr(securefile.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("io")))
    with pytest.raises(OSError):
        identity.add_agent("a2")
    assert p.read_bytes() == before
