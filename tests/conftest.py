import os
# Disable .env loading before any test module can import api/dashboard/worker
# (those call envfile.load() at import time).
os.environ["PATIENCE_NO_DOTENV"] = "1"
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Live-side effects that must never be inherited from a developer shell, even
# if they are not prefixed with PATIENCE_.
_STRIP_ALWAYS = (
    "STRIPE_API_KEY",
    "STRIPE_SECRET_KEY",
    "STRIPE_LIVE_SECRET",
)


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Each test runs with isolated state, audit, policy, and identity paths.

    Repo-root (or cwd) leftovers such as .env, agents.yaml, approvers.yaml,
    policy.yaml, and patience_state.json must not affect results. Inherited
    PATIENCE_* environment variables are stripped, then test defaults are
    re-applied. Production loaders are unchanged; they already honor these
    environment overrides.
    """
    for key in list(os.environ):
        if key.startswith("PATIENCE_") or key in _STRIP_ALWAYS:
            monkeypatch.delenv(key, raising=False)

    isolated = tmp_path / "_isolated"
    isolated.mkdir()
    monkeypatch.setenv("PATIENCE_NO_DOTENV", "1")
    monkeypatch.setenv("PATIENCE_DOTENV", str(isolated / "no-such.env"))
    monkeypatch.setenv("PATIENCE_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(isolated / "patience_state.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(isolated / "agents.yaml"))
    monkeypatch.setenv("PATIENCE_APPROVERS", str(tmp_path / "approvers.yaml"))
    monkeypatch.setenv("PATIENCE_DEV_GATE_DB", str(tmp_path / "dev_gate.db"))
    monkeypatch.setenv("PATIENCE_DEV_AUTHORITY_DB", str(tmp_path / "dev_authority.db"))
    monkeypatch.setenv("PATIENCE_INTEL_DB", str(tmp_path / "patience_intelligence.db"))
    monkeypatch.setenv("PATIENCE_CLAIM_NONCE_DB", str(isolated / "claim_nonces.db"))
    monkeypatch.setenv("PATIENCE_LEGACY_APPROVER_TOKEN", "1")
    monkeypatch.setenv("PATIENCE_LINK_SECRET", "test-link-secret-0123456789abcdef")
    # Fail-closed tests unset this explicitly.
    monkeypatch.setenv("PATIENCE_DEV_OPEN", "1")
    # PATIENCE_POLICY is intentionally left unset so Policy uses the
    # packaged policies/default.yaml, not a leftover repo-root policy.yaml.

    # Cwd-relative defaults (Patience("patience_state.json"), audit fallback,
    # trigger_worker) must not see files in the repo root or other files
    # tests write directly under tmp_path.
    monkeypatch.chdir(isolated)

    import risk_policy
    risk_policy.reload_policy()
    import approvers
    approvers._FAILS.clear()
    import api as _api
    getattr(_api, "_IP_FAILS", {}).clear()
    yield
