# Installing PATIENCE locally

This is a **local development install**. It is not a signed or notarized package, not a `.pkg` / `.msi` / `.exe`, and not a production deploy. The installer generates fresh secrets on your machine, keeps live connectors off, and binds the API to loopback when you start it.

The steps live in `tools/install.py` (Python standard library only). The shell wrappers only find a Python interpreter and delegate to that script, so macOS, Linux and Windows follow the same path.

## Prerequisites

- A checkout of this repository
- Python **3.10 or newer**. The installer reads the floor from `requires-python` in `pyproject.toml` and refuses to guess. If no suitable interpreter is on `PATH`, it exits with a clear error.
- Network access only if you want dependencies installed (that is the only network call; it is `pip install -r requirements.txt`). Use `--no-deps` to skip pip.

## macOS and Linux

From the checkout:

```sh
./install.sh
```

Optional flags (passed through to `tools/install.py`):

```sh
./install.sh --dry-run          # print the steps; change nothing
./install.sh --no-deps          # skip pip (offline / already installed)
./install.sh --run-tests        # run pytest from the new virtualenv
./install.sh --start            # launch the API on 127.0.0.1:8765 after install
./install.sh --force            # back up existing config, then replace it
```

You can also run `python3 tools/install.py` with the same flags. `PYTHON` selects the interpreter used to start the script (it still has to satisfy `requires-python`).

## Windows

In PowerShell, from the checkout:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

The same flags work: `-dry-run` is not a PowerShell switch here; pass them as they are defined by the Python script:

```powershell
.\install.ps1 --dry-run
.\install.ps1 --no-deps
.\install.ps1 --run-tests
.\install.ps1 --start
.\install.ps1 --force
```

If `python` / `python3` is not on `PATH`, the official installer from [python.org](https://www.python.org/downloads/) and the `py` launcher are both accepted. This script was syntax-checked and exercised under PowerShell 7; Windows ACL restriction (`icacls`) is implemented and unit-tested, but was not executed on a Windows host in the environment that added this installer.

## What gets created

| Path | Role |
|---|---|
| `.venv/` | Virtualenv, using a Python that meets `requires-python` |
| `.env` | Local config, generated from `.env.example`, with fresh secrets and live flags off (mode `0600` on POSIX) |
| `.patience_admin_password` | Bootstrap password for the `admin` approver. **The installer never prints the value**; it prints this path only. |
| `approvers.yaml` | scrypt hash of that password (no plaintext), role `admin` |
| `policy.yaml` | Copy of `policies/default.yaml` if you did not already have one |
| `.env.example` | Template with **no real secrets**. Created only if it is missing. |

Re-running the installer is idempotent: an existing `.venv` is reused, and existing `.env`, `.patience_admin_password`, `approvers.yaml` and `policy.yaml` are left alone unless you pass `--force`. `--force` writes a timestamped `*.bak-...` copy of each file it replaces before writing the new one.

## Secrets and permissions

The installer generates, with `secrets.token_urlsafe` / `secrets.choice` (both backed by `os.urandom`):

- `PATIENCE_LINK_SECRET` — HMAC secret for one-tap approval links
- `PATIENCE_CLAIM_SECRET` — HMAC secret for execution-claim tokens (32+ characters)
- `PATIENCE_API_TOKEN` — shared agent token used when `agents.yaml` is absent
- the `admin` bootstrap password (file above; the hash goes in `approvers.yaml`)

It never prints those values, including on `--dry-run`. It prints only the paths.

On POSIX it writes secret files with mode `0600` from creation and fails if the result is still group- or world-readable. On Windows it runs `icacls /inheritance:r` and grants `(R,W)` to the current user only. If `icacls` is missing or fails, it warns and does not claim the file is owner-only. This is a best-effort local-dev restriction, not a security boundary against someone who already has administrator or disk access.

The deprecated shared approver token (`PATIENCE_LEGACY_APPROVER_TOKEN` / `PATIENCE_APPROVER_TOKEN`) is **not** enabled. `PATIENCE_DEV_OPEN` is left unset, so the API stays fail-closed and authenticates with `PATIENCE_API_TOKEN` (or later with agent keys).

After install you can create additional approvers or agent keys with `patience init` / `patience add-approver` / `patience add-agent`. Those commands may print a secret **once**; that is separate from this installer.

## Live features stay off

The generated `.env` sets all of the following to `0` and does not turn on a local model adapter:

- `PATIENCE_EXECUTE_LIVE=0` — nothing real is sent, refunded or charged
- `PATIENCE_STRIPE_ALLOW_LIVE=0`
- `PATIENCE_INTEL_CONNECTORS_LIVE=0`
- `PATIENCE_INTEL_SEC_EDGAR_LIVE=0`

`PATIENCE_ORACLE` and `PATIENCE_DEV_KILL` are left unset. The installer itself makes no network calls except `pip`.

## Starting the API

`./install.sh --start` (or `.\install.ps1 --start`) launches `api.py` from the virtualenv with `PATIENCE_API_HOST=127.0.0.1` and `PATIENCE_API_PORT=8765`. Without `--start`, the installer prints that command and does not launch anything. It will not bind `0.0.0.0` or another non-loopback address.

Without `--start`:

```sh
# macOS / Linux
.venv/bin/python api.py

# Windows
.venv\Scripts\python.exe api.py
```

The process listens on `http://127.0.0.1:8765`. The dashboard, if you want it, is still `python -m streamlit run dashboard.py` (see the README). Run a single API process.

## Uninstall

```sh
./install.sh --uninstall
```

This removes `.venv` only. Local config, bootstrap secrets, keys (`*.key`, `*.permit_key`), audit logs and state files are left in place.

To delete those as well:

```sh
./install.sh --uninstall --purge --confirm-purge
```

`--purge` is refused unless it is paired with `--uninstall` and confirmed, either by `--confirm-purge` or by typing `DELETE LOCAL DATA` at the prompt. Purge only looks at known runtime files in the checkout root. It does not delete source, `.env.example`, `policies/default.yaml`, or files outside the checkout.

`--dry-run` works with uninstall and purge: it lists the targets and changes nothing.

## Honest limits

- Local development only. Do not treat this as a hardened, production-ready, signed, or notarized install.
- No Apple notarization, no Authenticode signature, no OS package (`.pkg`, `.msi`, `.deb`, `.exe`).
- Secrets are generated locally and stored in gitignored files; anyone who can read those files can use them. Protect the checkout directory.
- There is no key rotation, revocation, or secret escrow in the installer. Rotate by regenerating with `--force` (after a backup) or by editing the files yourself.
- Windows owner-only ACLs depend on `icacls` and were unit-tested, not proven on a real Windows machine in the environment that added this installer. POSIX `0600` is checked after `chmod`.
- `shellcheck` may or may not be available where you run; `install.sh` is POSIX `sh` and is meant to pass it.
- Pip may fail on an offline or filtered network; use `--no-deps` and install requirements yourself.
- This installer does not deploy to a server, open a firewall, or register a service.

For the broader security model (auth, audit chain, claims, permits), see `docs/SECURITY.md` and `docs/SENTINEL_FORGE_HASHING_AND_KEYS.md`.
