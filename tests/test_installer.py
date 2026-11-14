"""Tests for the local PATIENCE installer (tools/install.py).

All filesystem work is under tmp_path. These tests never write into the real
checkout and never print or assert live secret values in a way that requires
them to appear on stdout.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import install as inst  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_repo(tmp_path: Path, *, requires: str = ">=3.10", example: bool = True,
              requirements: str = "", name: str = "patience") -> Path:
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        textwrap.dedent(f"""\
            [project]
            name = "{name}"
            requires-python = "{requires}"
        """),
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text(requirements + "\n", encoding="utf-8")
    (root / "api.py").write_text("# stub api\n", encoding="utf-8")
    policies = root / "policies"
    policies.mkdir()
    (policies / "default.yaml").write_text("version: 1\nthresholds: {}\n", encoding="utf-8")
    if example:
        (root / ".env.example").write_text(inst.ENV_EXAMPLE_TEMPLATE, encoding="utf-8")
    return root


def captured_run(argv, *, stdin_fn=None):
    import io
    from contextlib import redirect_stderr, redirect_stdout

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = inst.run(argv, stdin_fn=stdin_fn)
    return code, out.getvalue(), err.getvalue()


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def read_secrets(env_path: Path, password_path: Path) -> list[str]:
    values = []
    assignments = inst.parse_dotenv_assignments(env_path.read_text(encoding="utf-8"))
    for key in inst.SECRET_KEYS:
        values.append(assignments[key])
    # Password file: last non-comment non-empty line.
    for line in password_path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if raw and not raw.startswith("#"):
            values.append(raw)
    return values


def assert_no_secrets_in_output(secrets: list[str], stdout: str, stderr: str) -> None:
    blob = stdout + stderr
    for secret in secrets:
        assert secret, "expected a generated secret"
        assert secret not in blob


def write_fake_python(path: Path, version: str) -> Path:
    path.write_text(
        textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import sys
            if sys.argv[1:2] == ["-c"]:
                print("{version}")
                sys.exit(0)
            sys.exit(1)
        """),
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def test_parse_requires_python_reads_pyproject_floor():
    major, minor = inst.parse_requires_python(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert (major, minor) == (3, 10)


def test_parse_requires_python_fails_closed_when_missing():
    with pytest.raises(inst.InstallError, match="Refusing to guess"):
        inst.parse_requires_python("[project]\nname = \"patience\"\n")


def test_parse_requires_python_fails_closed_on_unknown_constraint():
    with pytest.raises(inst.InstallError, match="Refusing to guess"):
        inst.parse_requires_python('requires-python = "~=3.10"\n')


def test_version_check_fails_closed_and_writes_nothing(tmp_path):
    root = make_repo(tmp_path, requires=">=99.0")
    fake = write_fake_python(tmp_path / "py99", "3.13")
    code, stdout, stderr = captured_run(
        ["--root", str(root), "--python", str(fake), "--no-deps"]
    )
    assert code != 0
    assert "Python 99.0 or newer" in stderr
    assert not (root / ".env").exists()
    assert not (root / ".venv").exists()
    assert not (root / ".patience_admin_password").exists()
    # The required version, not a generated secret, may appear in the error.
    assert "PATIENCE_CLAIM_SECRET=" not in stdout + stderr


def test_version_check_accepts_current_interpreter(tmp_path):
    root = make_repo(tmp_path, requires=">=3.10")
    exe, label, minimum = inst.find_python(root, sys.executable)
    assert exe == sys.executable
    assert minimum == (3, 10)
    major, minor, _ = inst.python_version_tuple(sys.executable)
    assert inst.version_meets((major, minor), minimum)


def test_rejects_non_patience_root(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "pyproject.toml").write_text(
        '[project]\nname = "something-else"\nrequires-python = ">=3.10"\n',
        encoding="utf-8",
    )
    (other / "requirements.txt").write_text("\n", encoding="utf-8")
    (other / "api.py").write_text("#\n", encoding="utf-8")
    with pytest.raises(inst.InstallError, match="not the PATIENCE project"):
        inst.assert_patience_root(other)


# ---------------------------------------------------------------------------
# Config writes, overwrite, backup, permissions
# ---------------------------------------------------------------------------

def test_write_config_creates_owner_only_random_secrets(tmp_path):
    root = make_repo(tmp_path)
    logs: list[str] = []
    meta = inst.write_local_config(
        root, dry_run=False, force=False, log=logs.append, warn=logs.append
    )
    env_path = Path(meta["env"])
    admin_path = Path(meta["admin_password_file"])
    approvers_path = Path(meta["approvers"])
    assert env_path.is_file()
    assert admin_path.is_file()
    assert approvers_path.is_file()
    assert (root / "policy.yaml").is_file()
    if os.name != "nt":
        assert mode_of(env_path) == 0o600
        assert mode_of(admin_path) == 0o600
        assert mode_of(approvers_path) == 0o600

    secrets = read_secrets(env_path, admin_path)
    assert len(set(secrets)) == len(secrets)
    for secret in secrets:
        assert len(secret) >= 10
    link = inst.parse_dotenv_assignments(env_path.read_text(encoding="utf-8"))
    assert len(link["PATIENCE_CLAIM_SECRET"]) >= 32
    assert len(link["PATIENCE_LINK_SECRET"]) >= 32
    assert len(link["PATIENCE_API_TOKEN"]) >= 32
    assert_no_secrets_in_output(secrets, "\n".join(logs), "")

    # Two independent installs must not share secrets.
    other = make_repo(tmp_path / "b")
    inst.write_local_config(other, dry_run=False, force=False, log=logs.append, warn=logs.append)
    other_secrets = read_secrets(other / ".env", other / ".patience_admin_password")
    assert set(secrets).isdisjoint(set(other_secrets))


def test_no_overwrite_without_force(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    original_env = (root / ".env").read_text(encoding="utf-8")
    original_pw = (root / ".patience_admin_password").read_text(encoding="utf-8")
    original_ap = (root / "approvers.yaml").read_text(encoding="utf-8")
    (root / ".env").write_text(original_env + "# marker-keep\n", encoding="utf-8")

    logs: list[str] = []
    inst.write_local_config(root, dry_run=False, force=False, log=logs.append, warn=logs.append)
    assert "Leave existing" in "\n".join(logs)
    assert "# marker-keep" in (root / ".env").read_text(encoding="utf-8")
    assert (root / ".patience_admin_password").read_text(encoding="utf-8") == original_pw
    assert (root / "approvers.yaml").read_text(encoding="utf-8") == original_ap
    assert not list(root.glob(".env.bak-*"))


def test_force_makes_backup_then_replaces(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    old_env = (root / ".env").read_text(encoding="utf-8")
    old_secrets = read_secrets(root / ".env", root / ".patience_admin_password")

    logs: list[str] = []
    inst.write_local_config(root, dry_run=False, force=True, log=logs.append, warn=logs.append)
    backups = list(root.glob(".env.bak-*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == old_env
    if os.name != "nt":
        assert mode_of(backups[0]) == 0o600
    new_env = (root / ".env").read_text(encoding="utf-8")
    assert new_env != old_env
    new_secrets = read_secrets(root / ".env", root / ".patience_admin_password")
    assert set(old_secrets).isdisjoint(set(new_secrets))
    joined = "\n".join(logs)
    assert_no_secrets_in_output(old_secrets + new_secrets, joined, "")
    assert "Backup" in joined


def test_live_flags_off_in_generated_env(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    assignments = inst.parse_dotenv_assignments((root / ".env").read_text(encoding="utf-8"))
    assert inst.live_flags_are_off(assignments) == []
    for key in inst.LIVE_FLAGS_OFF:
        assert assignments.get(key) == "0"
    assert assignments.get("PATIENCE_API_HOST") == "127.0.0.1"
    assert "PATIENCE_DEV_OPEN" not in assignments
    assert "PATIENCE_LEGACY_APPROVER_TOKEN" not in assignments
    assert "PATIENCE_APPROVER_TOKEN" not in assignments
    assert "PATIENCE_ORACLE" not in assignments
    assert "PATIENCE_DEV_KILL" not in assignments


def test_env_example_created_when_missing_has_no_real_secrets(tmp_path):
    root = make_repo(tmp_path, example=False)
    assert not (root / ".env.example").exists()
    logs: list[str] = []
    inst.write_local_config(root, dry_run=False, force=False, log=logs.append, warn=logs.append)
    example = (root / ".env.example").read_text(encoding="utf-8")
    secrets = read_secrets(root / ".env", root / ".patience_admin_password")
    assert inst.example_has_real_secrets(example, secrets) is False
    for secret in secrets:
        assert secret not in example
    # Placeholders only, no live keys, no sk_live material.
    assert "sk_live" not in example
    assert "PATIENCE_EXECUTE_LIVE=0" in example
    assert "change-me" in example  # placeholder, not a generated secret


def test_admin_password_hash_verifies_with_approvers_module(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    password = None
    for line in (root / ".patience_admin_password").read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if raw and not raw.startswith("#"):
            password = raw
    assert password
    import approvers
    import yaml

    # Load the YAML we wrote; do not use PATIENCE_APPROVERS from the suite fixture.
    data = yaml.safe_load((root / "approvers.yaml").read_text(encoding="utf-8"))
    hashed = data["approvers"]["admin"]["password"]
    assert password not in (root / "approvers.yaml").read_text(encoding="utf-8")
    assert approvers.check_secret(password, hashed)
    assert data["approvers"]["admin"]["role"] == "admin"


def test_dry_run_makes_no_changes(tmp_path):
    root = make_repo(tmp_path, example=False)
    before = {p.name for p in root.iterdir()}
    code, stdout, stderr = captured_run(
        ["--root", str(root), "--python", sys.executable, "--no-deps", "--dry-run"]
    )
    assert code == 0
    assert "Dry run" in stdout
    after = {p.name for p in root.iterdir()}
    assert after == before
    assert not (root / ".env").exists()
    assert not (root / ".venv").exists()
    assert not (root / ".patience_admin_password").exists()
    assert not (root / "policy.yaml").exists()
    assert not (root / ".env.example").exists()


def test_idempotent_second_run_keeps_secrets(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    first = (root / ".env").read_text(encoding="utf-8")
    first_pw = (root / ".patience_admin_password").read_text(encoding="utf-8")
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    assert (root / ".env").read_text(encoding="utf-8") == first
    assert (root / ".patience_admin_password").read_text(encoding="utf-8") == first_pw


# ---------------------------------------------------------------------------
# Uninstall / purge
# ---------------------------------------------------------------------------

def test_uninstall_removes_venv_only(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    venv = root / ".venv"
    venv.mkdir()
    # Fake a venv interpreter so the uninstaller recognises it.
    (venv / "bin").mkdir()
    (venv / "bin" / "python").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "patience_audit.jsonl").write_text('{"event":"test"}\n', encoding="utf-8")
    (root / "patience_audit.jsonl.head").write_text("abc\n", encoding="utf-8")
    (root / "dummy.permit_key").write_text("not-a-real-key\n", encoding="utf-8")
    (root / "dummy.key").write_text("not-a-real-key\n", encoding="utf-8")
    (root / "patience_state.json").write_text("{}\n", encoding="utf-8")

    code, stdout, stderr = captured_run(["--root", str(root), "--uninstall"])
    assert code == 0, stderr
    assert not venv.exists()
    assert (root / ".env").is_file()
    assert (root / ".patience_admin_password").is_file()
    assert (root / "approvers.yaml").is_file()
    assert (root / "patience_audit.jsonl").is_file()
    assert (root / "patience_audit.jsonl.head").is_file()
    assert (root / "dummy.permit_key").is_file()
    assert (root / "dummy.key").is_file()
    assert (root / "patience_state.json").is_file()
    assert "Left local config" in stdout


def test_purge_without_confirmation_keeps_files(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    (root / "patience_audit.jsonl").write_text("{}\n", encoding="utf-8")
    code, stdout, stderr = captured_run(
        ["--root", str(root), "--uninstall", "--purge"],
        stdin_fn=lambda _prompt: "nope",
    )
    assert code != 0
    assert "confirmation" in stderr.lower() or "DELETE LOCAL DATA" in stderr
    assert (root / ".env").is_file()
    assert (root / "patience_audit.jsonl").is_file()
    assert (root / ".patience_admin_password").is_file()


def test_purge_without_uninstall_is_refused(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    code, stdout, stderr = captured_run(
        ["--root", str(root), "--purge", "--confirm-purge"]
    )
    assert code != 0
    assert "--uninstall" in stderr
    assert (root / ".env").is_file()


def test_uninstall_purge_confirm_removes_runtime_files(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    (root / "patience_audit.jsonl").write_text("{}\n", encoding="utf-8")
    (root / "patience_audit.jsonl.head").write_text("h\n", encoding="utf-8")
    (root / "dummy.key").write_text("x\n", encoding="utf-8")
    (root / "api.py").write_text("# source must survive\n", encoding="utf-8")
    (root / ".env.example").write_text(inst.ENV_EXAMPLE_TEMPLATE, encoding="utf-8")

    code, stdout, stderr = captured_run(
        ["--root", str(root), "--uninstall", "--purge", "--confirm-purge"]
    )
    assert code == 0, stderr
    assert not (root / ".env").exists()
    assert not (root / ".patience_admin_password").exists()
    assert not (root / "approvers.yaml").exists()
    assert not (root / "policy.yaml").exists()
    assert not (root / "patience_audit.jsonl").exists()
    assert not (root / "patience_audit.jsonl.head").exists()
    assert not (root / "dummy.key").exists()
    # Source and the example template stay.
    assert (root / "api.py").is_file()
    assert (root / ".env.example").is_file()
    assert (root / "policies" / "default.yaml").is_file()
    assert (root / "pyproject.toml").is_file()


def test_dry_run_uninstall_purge_makes_no_changes(tmp_path):
    root = make_repo(tmp_path)
    inst.write_local_config(root, dry_run=False, force=False, log=lambda *_: None, warn=lambda *_: None)
    (root / ".venv" / "bin").mkdir(parents=True)
    (root / ".venv" / "bin" / "python").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "patience_audit.jsonl").write_text("{}\n", encoding="utf-8")
    code, stdout, stderr = captured_run(
        ["--root", str(root), "--uninstall", "--purge", "--confirm-purge", "--dry-run"]
    )
    assert code == 0, stderr
    assert (root / ".venv").is_dir()
    assert (root / ".env").is_file()
    assert (root / "patience_audit.jsonl").is_file()


# ---------------------------------------------------------------------------
# Start command, icacls, stdout secrecy via full run (no venv deps)
# ---------------------------------------------------------------------------

def test_api_start_command_is_loopback_only():
    venv = Path("/tmp/fake-venv")
    root = Path("/tmp/fake-root")
    env = inst.api_start_env()
    assert env["PATIENCE_API_HOST"] == "127.0.0.1"
    assert env["PATIENCE_API_PORT"] == "8765"
    cmd = inst.api_start_command(venv, root)
    assert cmd[-1].endswith("api.py")
    # The installer never passes --host 0.0.0.0.
    assert "0.0.0.0" not in " ".join(cmd)


def test_icacls_commands_restrict_to_named_user():
    cmds = inst.icacls_restrict_commands(r"C:\proj\.env", "matthew")
    assert cmds[0] == ["icacls", r"C:\proj\.env", "/inheritance:r"]
    assert cmds[1] == ["icacls", r"C:\proj\.env", "/grant:r", "matthew:(R,W)"]


def test_full_install_no_deps_hides_secrets_and_is_idempotent(tmp_path):
    root = make_repo(tmp_path)
    code, stdout, stderr = captured_run(
        ["--root", str(root), "--python", sys.executable, "--no-deps"]
    )
    assert code == 0, stderr
    assert (root / ".venv").is_dir()
    assert inst.venv_exists(root / ".venv")
    secrets = read_secrets(root / ".env", root / ".patience_admin_password")
    assert_no_secrets_in_output(secrets, stdout, stderr)
    assert str(root / ".env") in stdout
    assert str(root / ".patience_admin_password") in stdout
    assert "127.0.0.1" in stdout
    assignments = inst.parse_dotenv_assignments((root / ".env").read_text(encoding="utf-8"))
    assert inst.live_flags_are_off(assignments) == []

    env_before = (root / ".env").read_text(encoding="utf-8")
    code2, stdout2, stderr2 = captured_run(
        ["--root", str(root), "--python", sys.executable, "--no-deps"]
    )
    assert code2 == 0, stderr2
    assert (root / ".env").read_text(encoding="utf-8") == env_before
    assert_no_secrets_in_output(secrets, stdout2, stderr2)


def test_start_without_flag_does_not_launch(tmp_path, monkeypatch):
    root = make_repo(tmp_path)
    launched = []

    def fake_run(*_a, **_k):
        launched.append("ran")
        raise AssertionError("API must not be launched without --start")

    monkeypatch.setattr(inst.subprocess, "run", fake_run)
    # Bypass venv/pip by calling start_api directly after a dry config write.
    logs: list[str] = []
    inst.write_local_config(root, dry_run=False, force=False, log=lambda m: logs.append(m), warn=lambda m: logs.append(m))
    code = inst.start_api(root / ".venv", root, dry_run=False, log=logs.append, launch=False)
    assert code == 0
    assert launched == []
    assert any("127.0.0.1:8765" in m for m in logs)
    assert any("Not launching" in m for m in logs)


# ---------------------------------------------------------------------------
# Wrapper scripts
# ---------------------------------------------------------------------------

def test_install_sh_delegates_to_install_py_dry_run(tmp_path):
    script = ROOT / "install.sh"
    if not script.is_file():
        pytest.skip("install.sh missing")
    root = make_repo(tmp_path)
    result = subprocess.run(
        ["sh", str(script), "--root", str(root), "--python", sys.executable, "--no-deps", "--dry-run"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Dry run" in result.stdout
    assert not (root / ".env").exists()
    # Secrets cannot appear because none were generated to disk; still check change-me stayed off stdout as a value assignment.
    assert "PATIENCE_CLAIM_SECRET=" not in result.stdout


def test_install_ps1_exists_and_delegates_under_pwsh(tmp_path):
    script = ROOT / "install.ps1"
    assert script.is_file()
    pwsh = inst.shutil.which("pwsh")
    if not pwsh:
        pytest.skip("pwsh is not installed")
    root = make_repo(tmp_path)
    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(script), "--root", str(root),
         "--python", sys.executable, "--no-deps", "--dry-run"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "Dry run" in result.stdout
    assert not (root / ".env").exists()
