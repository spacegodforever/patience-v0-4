#!/usr/bin/env python3
"""PATIENCE local installer (stdlib only).

Creates a virtualenv, installs requirements, and writes a local development
config with freshly generated secrets. Live connectors stay off. This is not a
signed or packaged installer and is not a production deploy tool.

macOS/Linux:  ./install.sh
Windows:      .\\install.ps1
Both wrappers delegate here so the steps stay in one place.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults and names
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parent

VENV_DIRNAME = ".venv"
ENV_FILE = ".env"
ENV_EXAMPLE = ".env.example"
ADMIN_PASSWORD_FILE = ".patience_admin_password"
APPROVERS_FILE = "approvers.yaml"
POLICY_FILE = "policy.yaml"
DEFAULT_POLICY = Path("policies") / "default.yaml"
REQUIREMENTS_FILE = "requirements.txt"
PYPROJECT_FILE = "pyproject.toml"
API_MODULE = "api.py"

ADMIN_USER = "admin"
API_HOST = "127.0.0.1"
API_PORT = "8765"
PUBLIC_URL = f"http://{API_HOST}:{API_PORT}"

# Flags that must be off / unset in a local install. Assigned values are "0".
LIVE_FLAGS_OFF = (
    "PATIENCE_EXECUTE_LIVE",
    "PATIENCE_STRIPE_ALLOW_LIVE",
    "PATIENCE_INTEL_CONNECTORS_LIVE",
    "PATIENCE_INTEL_SEC_EDGAR_LIVE",
)

# These stay commented or absent (enabling them is a deliberate operator choice).
FLAGS_LEFT_UNSET = (
    "PATIENCE_DEV_OPEN",
    "PATIENCE_LEGACY_APPROVER_TOKEN",
    "PATIENCE_ORACLE",
    "PATIENCE_DEV_KILL",
)

SECRET_KEYS = (
    "PATIENCE_LINK_SECRET",
    "PATIENCE_CLAIM_SECRET",
    "PATIENCE_API_TOKEN",
)

# Files the uninstaller may remove with --purge (repo root only). Never source.
PURGE_NAMES = (
    ENV_FILE,
    ADMIN_PASSWORD_FILE,
    APPROVERS_FILE,
    "agents.yaml",
    POLICY_FILE,
    "patience_state.json",
    "patience_audit.jsonl",
    "patience_audit.jsonl.head",
    "patience_dev_gate.db",
    "patience_intelligence.db",
    "patience_coordinator.db",
    "trigger_queue.jsonl",
    "trigger_done.json",
    "latest_trigger_prompt.txt",
)
PURGE_SUFFIXES = (
    ".bak-",  # e.g. .env.bak-20261114T015000 (matched as start of suffix after name)
)
PURGE_ROOT_GLOBS = (
    ".env.bak-*",
    ".patience_admin_password.bak-*",
    "approvers.yaml.bak-*",
    "agents.yaml.bak-*",
    "policy.yaml.bak-*",
    "*.permit_key",
    "*.key",
    "*.db",
    "*.db-journal",
    "*.db-wal",
    "*.db-shm",
)

ENV_EXAMPLE_TEMPLATE = """\
# Copy to .env, or run ./install.sh / .\\install.ps1 / python tools/install.py
# (those write a local .env with freshly generated secrets and owner-only
# permissions). This example contains no real secrets.
# ---- core ----
PATIENCE_LINK_SECRET=change-me-to-48-random-characters-change-me-please
# PATIENCE_CLAIM_SECRET=
# PATIENCE_API_TOKEN=
PATIENCE_PUBLIC_URL=http://127.0.0.1:8765
# PATIENCE_API_HOST=127.0.0.1
# PATIENCE_API_PORT=8765
# PATIENCE_POLICY=policy.yaml
# PATIENCE_LINK_TTL_SECONDS=900
# Nothing real is sent/charged unless this is 1:
PATIENCE_EXECUTE_LIVE=0
PATIENCE_STRIPE_ALLOW_LIVE=0
PATIENCE_INTEL_CONNECTORS_LIVE=0
# PATIENCE_INTEL_SEC_EDGAR_LIVE=0

# ---- approval alerts (any subset) ----
# PATIENCE_NOTIFY_EMAIL_TO=you@example.com
# PATIENCE_SMTP_HOST=smtp.example.com
# PATIENCE_SMTP_PORT=587
# PATIENCE_SMTP_USER=
# PATIENCE_SMTP_PASSWORD=
# PATIENCE_SMTP_FROM=patience@example.com
# PATIENCE_NOTIFY_SLACK_WEBHOOK=https://hooks.slack.com/services/...
# PATIENCE_NOTIFY_WEBHOOK_URL=https://example.com/patience-hook
# PATIENCE_WEBHOOK_SECRET=

# ---- Stripe executor (test keys only unless allowed) ----
# PATIENCE_STRIPE_API_KEY=sk_test_...
# PATIENCE_STRIPE_ALLOW_LIVE=0

# ---- optional LLM second opinion ----
# PATIENCE_LLM_API_KEY=

# ---- legacy (DEPRECATED, will be removed; off by default) ----
# PATIENCE_LEGACY_APPROVER_TOKEN=1
# PATIENCE_APPROVER_TOKEN=
# PATIENCE_LEGACY_DASHBOARD_PASSWORD=1
# Local development ONLY: allow unauthenticated agent API calls when no keys/token are configured.
# PATIENCE_DEV_OPEN=1
"""


class InstallError(Exception):
    """Fatal installer error; message is safe to print (no secret values)."""

    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Repo / Python discovery
# ---------------------------------------------------------------------------

def parse_requires_python(text: str) -> tuple[int, int]:
    """Return the minimum (major, minor) from a pyproject ``requires-python`` field.

    Fail closed if the field is missing or not a ``>=X.Y`` constraint. The
    project's declared floor is the source of truth; this parser does not
    guess.
    """
    m = re.search(r"(?m)^\s*requires-python\s*=\s*['\"]\s*>=\s*(\d+)\.(\d+)", text)
    if not m:
        raise InstallError(
            "Could not read a 'requires-python = \">=X.Y\"' value from pyproject.toml. "
            "Refusing to guess the required Python version."
        )
    return int(m.group(1)), int(m.group(2))


def python_version_tuple(executable: str) -> tuple[int, int, str]:
    """Return (major, minor, printable) for an interpreter, or raise."""
    try:
        out = subprocess.run(
            [executable, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(f"Could not run {executable!r} to check its version: {exc}") from exc
    if out.returncode != 0:
        err = (out.stderr or out.stdout or "").strip().splitlines()
        detail = err[0] if err else f"exit {out.returncode}"
        raise InstallError(f"Could not read the Python version from {executable!r}: {detail}")
    text = (out.stdout or "").strip()
    m = re.fullmatch(r"(\d+)\.(\d+)", text)
    if not m:
        raise InstallError(f"Unexpected version output from {executable!r}.")
    return int(m.group(1)), int(m.group(2)), text


def version_meets(got: tuple[int, int], minimum: tuple[int, int]) -> bool:
    return got >= minimum


def iter_python_candidates(explicit: str | None = None) -> list[str]:
    names = []
    if explicit:
        names.append(explicit)
    else:
        # Prefer the interpreter running this script, then common names.
        names.append(sys.executable)
        for n in (
            "python3.13",
            "python3.12",
            "python3.11",
            "python3.10",
            "python3",
            "python",
        ):
            path = shutil.which(n)
            if path:
                names.append(path)
        if os.name == "nt":
            py = shutil.which("py")
            if py:
                names.append(py)
    # Deduplicate while preserving order.
    seen = set()
    out = []
    for n in names:
        key = os.path.normcase(os.path.abspath(n)) if os.path.sep in n or (os.path.altsep and os.path.altsep in n) else n
        if key not in seen:
            seen.add(key)
            out.append(n)
    return out


def find_python(root: Path, explicit: str | None = None) -> tuple[str, str, tuple[int, int]]:
    """Locate an interpreter that satisfies pyproject.toml. Fail closed if none."""
    pyproject = root / PYPROJECT_FILE
    if not pyproject.is_file():
        raise InstallError(f"No {PYPROJECT_FILE} in {root}. This does not look like a PATIENCE checkout.")
    minimum = parse_requires_python(pyproject.read_text(encoding="utf-8"))
    min_label = f"{minimum[0]}.{minimum[1]}"
    last_error = None
    tried = []
    for cand in iter_python_candidates(explicit):
        argv0 = cand
        # The Windows `py` launcher needs a version qualifier; try as-is first.
        try:
            major, minor, label = python_version_tuple(argv0)
        except InstallError as exc:
            last_error = exc
            tried.append(f"{argv0} (unreadable)")
            continue
        tried.append(f"{argv0} ({label})")
        if version_meets((major, minor), minimum):
            return argv0, label, minimum
    tried_txt = ", ".join(tried) if tried else "none found on PATH"
    extra = f" Last error: {last_error}" if last_error and not tried else ""
    raise InstallError(
        f"PATIENCE requires Python {min_label} or newer (from {PYPROJECT_FILE} requires-python). "
        f"No suitable interpreter was found. Tried: {tried_txt}.{extra} "
        f"Install Python {min_label}+ from https://www.python.org/downloads/ and re-run."
    )


def assert_patience_root(root: Path) -> None:
    missing = [name for name in (PYPROJECT_FILE, REQUIREMENTS_FILE, API_MODULE) if not (root / name).is_file()]
    if missing:
        raise InstallError(
            f"{root} does not look like a PATIENCE checkout (missing {', '.join(missing)})."
        )
    text = (root / PYPROJECT_FILE).read_text(encoding="utf-8")
    if re.search(r'(?m)^\s*name\s*=\s*["\']patience["\']', text) is None and "name = \"patience\"" not in text:
        # Soft check: some test fixtures include the name; require it.
        if "name" in text and "patience" not in text.lower():
            raise InstallError(f"{root / PYPROJECT_FILE} is not the PATIENCE project.")


# ---------------------------------------------------------------------------
# Secret generation and owner-only files
# ---------------------------------------------------------------------------

def generate_secret(nbytes: int = 36) -> str:
    """URL-safe secret from ``secrets.token_urlsafe`` (os.urandom underneath)."""
    import secrets

    value = secrets.token_urlsafe(nbytes)
    if len(value) < 32:
        raise InstallError("Internal error: generated a secret shorter than 32 characters.")
    return value


def generate_admin_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    groups = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
    return "-".join(groups)


def scrypt_hash(secret: str) -> str:
    """Match ``approvers.hash_secret`` (stdlib hashlib.scrypt) so the YAML we write is usable."""
    import base64
    import hashlib
    import secrets

    n, r, p = 2**14, 8, 1
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(secret.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return (
        f"scrypt${n}${r}${p}$"
        f"{base64.b64encode(salt).decode()}$"
        f"{base64.b64encode(digest).decode()}"
    )


def icacls_restrict_commands(path: str, username: str) -> list[list[str]]:
    """Windows ACL commands that leave the file readable/writable only by ``username``."""
    return [
        ["icacls", path, "/inheritance:r"],
        ["icacls", path, "/grant:r", f"{username}:(R,W)"],
    ]


def restrict_owner_only(path: Path, *, warn=None) -> None:
    """Make ``path`` owner-only. 0600 on POSIX; icacls on Windows. Re-raises on POSIX failure."""
    path = Path(path)
    if os.name == "nt":
        username = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        if not username:
            if warn:
                warn("Windows username is unset; could not restrict ACLs with icacls.")
            return
        for argv in icacls_restrict_commands(str(path), username):
            try:
                result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as exc:
                if warn:
                    warn(f"icacls failed on {path}: {exc}. File may not be owner-only on this Windows host.")
                return
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip().splitlines()
                if warn:
                    warn(
                        f"icacls returned {result.returncode} for {path}"
                        + (f": {detail[0]}" if detail else "")
                        + ". File may not be owner-only on this Windows host."
                    )
                return
        return
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        raise InstallError(f"Could not set owner-only permissions on {path}: {exc}") from exc
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise InstallError(f"{path} is not owner-only after chmod (mode {oct(mode)}).")


def write_secret_file(path: Path, content: str, *, warn=None) -> None:
    """Write ``content`` atomically, creating the file with mode 0600 when the OS allows it."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".patience_install_tmp")
    if tmp.exists():
        try:
            tmp.unlink()
        except OSError as exc:
            raise InstallError(f"Could not remove stale temp file {tmp}: {exc}") from exc
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(str(tmp), flags, 0o600)
    except OSError as exc:
        raise InstallError(f"Could not create {tmp}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise InstallError(f"Could not write {tmp}: {exc}") from exc
    try:
        os.replace(str(tmp), str(path))
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise InstallError(f"Could not replace {path}: {exc}") from exc
    restrict_owner_only(path, warn=warn)


def backup_path_for(path: Path, now: datetime | None = None) -> Path:
    stamp = (now or datetime.now(timezone.utc).astimezone()).strftime("%Y%m%dT%H%M%S")
    return path.with_name(path.name + ".bak-" + stamp)


def backup_if_exists(path: Path, *, dry_run: bool, log, warn=None) -> Path | None:
    path = Path(path)
    if not path.exists():
        return None
    dest = backup_path_for(path)
    # Avoid colliding if two backups land in the same second.
    n = 1
    while dest.exists():
        dest = path.with_name(f"{path.name}.bak-{dest.name.split('.bak-')[-1]}-{n}")
        n += 1
        if n > 20:
            raise InstallError(f"Could not find a free backup name for {path}.")
    log(f"Backup {path} -> {dest}")
    if not dry_run:
        shutil.copy2(path, dest)
        restrict_owner_only(dest, warn=warn)
    return dest


# ---------------------------------------------------------------------------
# .env example and generated config
# ---------------------------------------------------------------------------

_ASSIGN_RE = re.compile(r"^(?P<comment>#\s*)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<val>.*)$")


def upsert_env_line(text: str, key: str, value: str | None, *, comment: bool = False) -> str:
    """Set ``key=value`` in a dotenv body. ``comment=True`` writes a placeholder, never a secret."""
    lines = text.splitlines()
    if comment:
        rendered = f"# {key}=" if value is None else f"# {key}={value}"
    else:
        rendered = f"{key}=" if value is None else f"{key}={value}"
    found = False
    out = []
    for line in lines:
        m = _ASSIGN_RE.match(line.strip())
        if m and m.group("key") == key:
            if not found:
                out.append(rendered)
                found = True
            # Drop duplicate assignments of the same key.
        else:
            out.append(line)
    if not found:
        if out and out[-1].strip():
            out.append("")
        out.append(rendered)
    return "\n".join(out) + "\n"


def ensure_env_example(root: Path, *, dry_run: bool, log) -> Path:
    path = root / ENV_EXAMPLE
    if path.is_file():
        log(f"Using existing {path}")
        return path
    log(f"Write template {path} (no secrets)")
    if not dry_run:
        path.write_text(ENV_EXAMPLE_TEMPLATE, encoding="utf-8")
    return path


def example_has_real_secrets(text: str, generated: list[str]) -> bool:
    for secret in generated:
        if secret and secret in text:
            return True
    return False


def build_env_contents(example_text: str, secrets_map: dict[str, str]) -> str:
    text = example_text if example_text.endswith("\n") else example_text + "\n"
    # Start from the example, then overwrite managed keys. Never leave change-me placeholders.
    for key, value in secrets_map.items():
        text = upsert_env_line(text, key, value, comment=False)
    for key in LIVE_FLAGS_OFF:
        text = upsert_env_line(text, key, "0", comment=False)
    text = upsert_env_line(text, "PATIENCE_PUBLIC_URL", PUBLIC_URL, comment=False)
    text = upsert_env_line(text, "PATIENCE_API_HOST", API_HOST, comment=False)
    text = upsert_env_line(text, "PATIENCE_API_PORT", API_PORT, comment=False)
    # Keep dangerous flags commented and unvalued so a later edit is deliberate.
    for key in FLAGS_LEFT_UNSET:
        text = upsert_env_line(text, key, None, comment=True)
    # Do not enable the deprecated shared approver token, even if we generated nothing for it.
    text = upsert_env_line(text, "PATIENCE_APPROVER_TOKEN", None, comment=True)
    # Header if the example didn't already mention the installer.
    if not text.lstrip().startswith("#"):
        text = "# Generated by the PATIENCE local installer. Keep this file private.\n" + text
    return text


def parse_dotenv_assignments(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, _, val = raw.partition("=")
        values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def live_flags_are_off(assignments: dict[str, str]) -> list[str]:
    """Return a list of problems, empty if all live flags are off and open-dev is unset."""
    problems = []
    for key in LIVE_FLAGS_OFF:
        val = assignments.get(key, "0")
        if val == "1":
            problems.append(f"{key}={val}")
    for key in ("PATIENCE_DEV_OPEN", "PATIENCE_LEGACY_APPROVER_TOKEN", "PATIENCE_DEV_KILL"):
        if assignments.get(key) == "1":
            problems.append(f"{key} is enabled")
    if (assignments.get("PATIENCE_ORACLE") or "").strip().lower() == "ollama":
        problems.append("PATIENCE_ORACLE=ollama")
    if (assignments.get("PATIENCE_API_HOST") or API_HOST) not in ("127.0.0.1", "localhost", "::1"):
        problems.append(f"PATIENCE_API_HOST={assignments.get('PATIENCE_API_HOST')}")
    return problems


def approvers_yaml(user: str, password_hash: str) -> str:
    # Quote the hash: it contains '$' and base64 characters.
    escaped = password_hash.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "# Generated by the PATIENCE local installer. Passwords are stored as scrypt hashes only.\n"
        "approvers:\n"
        f"  {user}:\n"
        "    disabled: false\n"
        f'    password: "{escaped}"\n'
        "    role: admin\n"
    )


def format_admin_password_file(user: str, password: str) -> str:
    return (
        "# Local PATIENCE admin bootstrap password. Owner-only. Never commit this file.\n"
        f"# Sign in as: {user}\n"
        f"{password}\n"
    )


# ---------------------------------------------------------------------------
# venv, pip, tests, API start
# ---------------------------------------------------------------------------

def venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def venv_exists(venv: Path) -> bool:
    return venv_python(venv).is_file()


def create_venv(python: str, venv: Path, *, dry_run: bool, log) -> None:
    if venv_exists(venv):
        log(f"Virtualenv already exists at {venv}")
        return
    log(f"Create virtualenv {venv} with {python}")
    if dry_run:
        return
    result = subprocess.run([python, "-m", "venv", str(venv)], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise InstallError(
            f"Failed to create virtualenv at {venv} (exit {result.returncode})"
            + (f": {detail[-1]}" if detail else "")
        )


def install_requirements(venv: Path, root: Path, *, dry_run: bool, no_deps: bool, log) -> None:
    req = root / REQUIREMENTS_FILE
    if no_deps:
        log(f"Skip pip install ({REQUIREMENTS_FILE}) because --no-deps was set.")
        return
    py = venv_python(venv)
    log(f"Install dependencies from {req} into {venv} (this is the only network step).")
    if dry_run:
        return
    if not py.is_file():
        raise InstallError(f"Virtualenv Python is missing: {py}")
    cmd = [str(py), "-m", "pip", "install", "--upgrade", "pip"]
    # pip upgrade is helpful but not essential; do not fail the install if it errors
    # on a locked-down host. The requirements install below is required.
    subprocess.run(cmd, check=False, capture_output=True, text=True, cwd=str(root))
    result = subprocess.run(
        [str(py), "-m", "pip", "install", "-r", str(req)],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(root),
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        tail = "\n".join(detail[-8:]) if detail else ""
        raise InstallError(
            f"pip install -r {REQUIREMENTS_FILE} failed (exit {result.returncode}). "
            "No other network calls are made. Check your network and retry.\n" + tail
        )


def run_tests(venv: Path, root: Path, *, dry_run: bool, log) -> int:
    py = venv_python(venv)
    cmd = [str(py), "-m", "pytest", "-q", "tests"]
    log("Run tests: " + " ".join(cmd))
    if dry_run:
        return 0
    if not py.is_file():
        raise InstallError(f"Cannot run tests: virtualenv Python is missing ({py}).")
    result = subprocess.run(cmd, check=False, cwd=str(root))
    return result.returncode


def api_start_command(venv: Path, root: Path) -> list[str]:
    py = venv_python(venv)
    return [str(py), str(root / API_MODULE)]


def api_start_env() -> dict[str, str]:
    # Force loopback even if a leftover shell variable says otherwise.
    return {
        "PATIENCE_API_HOST": API_HOST,
        "PATIENCE_API_PORT": API_PORT,
    }


def start_api(venv: Path, root: Path, *, dry_run: bool, log, launch: bool) -> int:
    cmd = api_start_command(venv, root)
    log(
        f"Local API command (binds {API_HOST}:{API_PORT} only): " + " ".join(cmd)
    )
    log(f"Open {PUBLIC_URL} after it starts. This installer will not bind a non-loopback address.")
    if dry_run or not launch:
        if not launch:
            log("Not launching the API (pass --start to launch it).")
        return 0
    env = os.environ.copy()
    env.update(api_start_env())
    # Honour a local .env for tokens, but the host/port override above wins after envfile loads
    # unless we also pass them as the process environment *and* they are already set (envfile
    # uses setdefault). Set them before spawn so a leftover .env host cannot widen the bind:
    # api.py reads PATIENCE_API_HOST after envfile.setdefault, so a pre-set value wins.
    log(f"Launching {cmd[0]} (cwd={root}); host override {API_HOST}:{API_PORT}.")
    result = subprocess.run(cmd, check=False, cwd=str(root), env=env)
    return result.returncode


# ---------------------------------------------------------------------------
# Config write / idempotency
# ---------------------------------------------------------------------------

def write_local_config(
    root: Path,
    *,
    dry_run: bool,
    force: bool,
    log,
    warn,
    secret_factory=None,
    password_factory=None,
) -> dict[str, str]:
    """Create or leave alone the local config. Returns metadata (paths, actions); never secrets."""
    secret_factory = secret_factory or generate_secret
    password_factory = password_factory or generate_admin_password
    env_path = root / ENV_FILE
    admin_path = root / ADMIN_PASSWORD_FILE
    approvers_path = root / APPROVERS_FILE
    policy_path = root / POLICY_FILE
    meta = {
        "env": str(env_path),
        "admin_password_file": str(admin_path),
        "approvers": str(approvers_path),
        "policy": str(policy_path),
        "env_action": "skip",
        "admin_action": "skip",
        "approvers_action": "skip",
        "policy_action": "skip",
    }

    example_path = ensure_env_example(root, dry_run=dry_run, log=log)
    example_text = ENV_EXAMPLE_TEMPLATE
    if example_path.is_file():
        example_text = example_path.read_text(encoding="utf-8")
    elif dry_run:
        example_text = ENV_EXAMPLE_TEMPLATE

    def maybe_write_env() -> None:
        if env_path.exists() and not force:
            log(f"Leave existing {env_path} in place (pass --force to back it up and replace).")
            meta["env_action"] = "exists"
            return
        if env_path.exists() and force:
            backup_if_exists(env_path, dry_run=dry_run, log=log, warn=warn)
        link = secret_factory()
        claim = secret_factory()
        token = secret_factory()
        secrets_map = {
            "PATIENCE_LINK_SECRET": link,
            "PATIENCE_CLAIM_SECRET": claim,
            "PATIENCE_API_TOKEN": token,
        }
        body = build_env_contents(example_text, secrets_map)
        problems = live_flags_are_off(parse_dotenv_assignments(body))
        if problems:
            raise InstallError("Refusing to write a .env with live features enabled: " + ", ".join(problems))
        if example_has_real_secrets(example_text, [link, claim, token]):
            raise InstallError("Refusing to put generated secrets into .env.example.")
        log(f"Write local config {env_path} (secrets are not printed; owner-only permissions).")
        if not dry_run:
            write_secret_file(env_path, body, warn=warn)
        meta["env_action"] = "written"

    def maybe_write_admin() -> None:
        if (admin_path.exists() or approvers_path.exists()) and not force:
            if admin_path.exists():
                log(f"Leave existing {admin_path} in place (pass --force to back it up and replace).")
                meta["admin_action"] = "exists"
            if approvers_path.exists():
                log(f"Leave existing {approvers_path} in place (pass --force to back it up and replace).")
                meta["approvers_action"] = "exists"
            return
        if force:
            backup_if_exists(admin_path, dry_run=dry_run, log=log, warn=warn)
            backup_if_exists(approvers_path, dry_run=dry_run, log=log, warn=warn)
        password = password_factory()
        body = format_admin_password_file(ADMIN_USER, password)
        yaml_body = approvers_yaml(ADMIN_USER, scrypt_hash(password))
        log(f"Write admin bootstrap password to {admin_path} (value is not printed).")
        log(f"Write hashed admin account to {approvers_path} (owner-only).")
        if not dry_run:
            write_secret_file(admin_path, body, warn=warn)
            write_secret_file(approvers_path, yaml_body, warn=warn)
        meta["admin_action"] = "written"
        meta["approvers_action"] = "written"

    def maybe_write_policy() -> None:
        src = root / DEFAULT_POLICY
        if policy_path.exists() and not force:
            log(f"Leave existing {policy_path} in place (pass --force to back it up and replace).")
            meta["policy_action"] = "exists"
            return
        if not src.is_file():
            log(f"No {src}; skip {policy_path}.")
            meta["policy_action"] = "skipped-no-template"
            return
        if policy_path.exists() and force:
            backup_if_exists(policy_path, dry_run=dry_run, log=log, warn=warn)
        log(f"Copy {src} -> {policy_path}")
        if not dry_run:
            shutil.copyfile(src, policy_path)
        meta["policy_action"] = "written"

    maybe_write_env()
    maybe_write_admin()
    maybe_write_policy()
    return meta


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

def venv_dir(root: Path, name: str = VENV_DIRNAME) -> Path:
    return root / name


def remove_venv(venv: Path, *, dry_run: bool, log) -> None:
    if not venv.exists():
        log(f"No virtualenv at {venv} to remove.")
        return
    # Refuse to delete something that does not look like a venv.
    if venv.name != VENV_DIRNAME and not venv_exists(venv):
        raise InstallError(f"Refusing to delete {venv}: it does not look like a PATIENCE virtualenv.")
    if venv.exists() and not venv_exists(venv) and venv.is_dir():
        # An incomplete venv still named .venv is ok to remove; anything else is not.
        if venv.name != VENV_DIRNAME:
            raise InstallError(f"Refusing to delete {venv}: no virtualenv interpreter inside.")
    log(f"Remove virtualenv {venv}")
    if not dry_run:
        shutil.rmtree(venv)


def purge_candidates(root: Path) -> list[Path]:
    """Runtime config, keys, audit logs and state at the repo root only."""
    found: list[Path] = []
    seen = set()

    def add(p: Path) -> None:
        try:
            resolved = p.resolve()
        except OSError:
            resolved = p
        # Never follow a path outside the root (e.g. a symlink).
        try:
            resolved.relative_to(root.resolve())
        except (ValueError, OSError):
            return
        if resolved in seen or not p.exists():
            return
        seen.add(resolved)
        found.append(p)

    for name in PURGE_NAMES:
        add(root / name)
    for pattern in PURGE_ROOT_GLOBS:
        for p in root.glob(pattern):
            if p.is_file() or p.is_symlink():
                add(p)
    return found


def confirm_purge(confirm_flag: bool, *, stdin_fn=None) -> bool:
    if confirm_flag:
        return True
    fn = stdin_fn or input
    try:
        answer = fn("Type DELETE LOCAL DATA to permanently remove local config, keys, audit logs and state: ")
    except EOFError:
        return False
    return (answer or "").strip() == "DELETE LOCAL DATA"


def purge_runtime(root: Path, *, dry_run: bool, confirmed: bool, log) -> list[Path]:
    if not confirmed:
        raise InstallError(
            "Refusing to delete config, keys, audit logs or state without confirmation. "
            "Re-run with --uninstall --purge --confirm-purge, or confirm interactively."
        )
    targets = purge_candidates(root)
    if not targets:
        log("No local config, keys, audit logs or state found to purge.")
        return []
    for p in targets:
        log(f"Purge {p}")
        if not dry_run:
            try:
                p.unlink()
            except IsADirectoryError:
                raise InstallError(f"Refusing to recursively delete directory {p} during purge.") from None
            except OSError as exc:
                raise InstallError(f"Could not remove {p}: {exc}") from exc
    return targets


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="install.py",
        description="Local-development installer for PATIENCE (macOS, Linux, Windows).",
    )
    p.add_argument("--root", type=Path, default=None, help="PATIENCE checkout (default: parent of tools/).")
    p.add_argument("--python", default=None, help="Python interpreter to use for the virtualenv.")
    p.add_argument("--venv", default=VENV_DIRNAME, help="Virtualenv directory relative to --root (default: .venv).")
    p.add_argument("--force", action="store_true", help="Back up and replace existing local config and secrets.")
    p.add_argument("--dry-run", action="store_true", help="Print the steps without changing anything.")
    p.add_argument("--no-deps", action="store_true", help="Skip pip install (offline / test use).")
    p.add_argument("--run-tests", action="store_true", help="Run pytest from the virtualenv after install.")
    p.add_argument(
        "--start",
        action="store_true",
        help=f"Launch the local API on {API_HOST}:{API_PORT} only (after printing the command).",
    )
    p.add_argument("--uninstall", action="store_true", help="Remove the virtualenv only.")
    p.add_argument(
        "--purge",
        action="store_true",
        help="With --uninstall, also delete local config, keys, audit logs and state (needs confirmation).",
    )
    p.add_argument(
        "--confirm-purge",
        action="store_true",
        help="Required with --uninstall --purge unless you type DELETE LOCAL DATA interactively.",
    )
    return p


def _logger():
    def log(msg: str) -> None:
        print(msg, flush=True)

    def warn(msg: str) -> None:
        print("warning: " + msg, file=sys.stderr, flush=True)

    return log, warn


def run(argv: list[str] | None = None, *, stdin_fn=None) -> int:
    args = build_parser().parse_args(argv)
    log, warn = _logger()
    root = (args.root or DEFAULT_ROOT).resolve()
    venv = (root / args.venv).resolve() if not Path(args.venv).is_absolute() else Path(args.venv).resolve()

    try:
        if args.purge and not args.uninstall:
            raise InstallError("--purge requires --uninstall. The uninstaller never deletes config without both.")
        if args.uninstall:
            # Uninstall does not require a full repo check beyond staying inside root.
            if not root.is_dir():
                raise InstallError(f"No such directory: {root}")
            try:
                venv.relative_to(root)
            except ValueError:
                raise InstallError(f"Refusing to delete a virtualenv outside {root}: {venv}") from None
            if args.dry_run:
                log("Dry run: no files will be removed.")
            remove_venv(venv, dry_run=args.dry_run, log=log)
            if args.purge:
                confirmed = confirm_purge(args.confirm_purge, stdin_fn=stdin_fn)
                purge_runtime(root, dry_run=args.dry_run, confirmed=confirmed, log=log)
            else:
                log(
                    "Left local config, keys, audit logs and state in place. "
                    "To delete those as well, re-run with --uninstall --purge (confirmation required)."
                )
            log("Uninstall finished." if not args.dry_run else "Dry run finished.")
            return 0

        assert_patience_root(root)
        if venv != root and root not in venv.parents:
            # venv must live under the checkout so uninstall cannot escape.
            try:
                venv.relative_to(root)
            except ValueError:
                raise InstallError(f"The virtualenv path must be inside {root}.") from None

        if args.dry_run:
            log("Dry run: no files will be created or changed.")

        python, label, minimum = find_python(root, args.python)
        log(f"Using Python {label} at {python} (requires >={minimum[0]}.{minimum[1]}).")

        create_venv(python, venv, dry_run=args.dry_run, log=log)
        install_requirements(venv, root, dry_run=args.dry_run, no_deps=args.no_deps, log=log)
        meta = write_local_config(root, dry_run=args.dry_run, force=args.force, log=log, warn=warn)
        log(f"Local config path: {meta['env']}")
        log(f"Admin bootstrap password path: {meta['admin_password_file']}")
        log("Secret values are not printed.")

        code = 0
        if args.run_tests:
            code = run_tests(venv, root, dry_run=args.dry_run, log=log)
            if code != 0:
                return code
        # Always print the start command so a user can launch later.
        start_code = start_api(venv, root, dry_run=args.dry_run, log=log, launch=bool(args.start))
        if start_code != 0:
            return start_code
        log("Install finished." if not args.dry_run else "Dry run finished.")
        return code
    except InstallError as exc:
        print(str(exc), file=sys.stderr, flush=True)
        return exc.code


def main(argv: list[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    sys.exit(main())
