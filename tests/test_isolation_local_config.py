"""Regression: local repo-root config and state must not leak into tests.

Synthetic decoys only. Files are written under tmp_path (a repo-root equivalent)
and cleaned up by pytest. This module never writes into the real repo root.
"""
from __future__ import annotations
import os
from pathlib import Path

import api
import approvers
import audit
import envfile
import identity
import risk_policy
from engine import Patience


HOSTILE_ENV = """\
# synthetic decoy — not real credentials
PATIENCE_EXECUTE_LIVE=1
PATIENCE_DEV_OPEN=0
PATIENCE_DEV_KILL=1
PATIENCE_API_TOKEN=hostile-synthetic-token-from-dotenv
PATIENCE_POLICY=policy.yaml
PATIENCE_AGENTS=agents.yaml
PATIENCE_APPROVERS=approvers.yaml
PATIENCE_STATE_PATH=patience_state.json
PATIENCE_AUDIT_PATH=patience_audit.jsonl
PATIENCE_CLAIM_SECRET=hostile-synthetic-claim-secret-xxxx
"""

HOSTILE_AGENTS = """\
agents:
  hostile-bot:
    key_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    industry: retail
"""

HOSTILE_APPROVERS = """\
approvers:
  hostile-admin:
    password: "scrypt$16384$8$1$AAAA$BBBB"
    role: admin
    disabled: false
"""

# Minimal policy that would change scoring if it were loaded.
HOSTILE_POLICY = """\
version: 1
thresholds:
  mass_recipients: 1
  default_consequence: 0
  unknown_side_effect: 0
categories: {}
"""

HOSTILE_STATE = """\
{
  "version": "0.3",
  "mission": "HOSTILE_SYNTHETIC_STATE",
  "end_state": "should-not-be-loaded",
  "current_objective": "leak-into-tests",
  "priority": "hostile",
  "observations": [{"content": "synthetic-decoy"}],
  "assessments": [],
  "model_votes": [],
  "decisions": [],
  "tasks": [],
  "risks": [],
  "assumptions": [],
  "unknowns": [],
  "authorized_actions": ["send_invoice"],
  "blocked_actions": [],
  "memory": [],
  "next_checkpoint": "",
  "last_updated": ""
}
"""


def write_hostile_decoys(root: Path) -> None:
    (root / ".env").write_text(HOSTILE_ENV, encoding="utf-8")
    (root / "agents.yaml").write_text(HOSTILE_AGENTS, encoding="utf-8")
    (root / "approvers.yaml").write_text(HOSTILE_APPROVERS, encoding="utf-8")
    (root / "policy.yaml").write_text(HOSTILE_POLICY, encoding="utf-8")
    (root / "patience_state.json").write_text(HOSTILE_STATE, encoding="utf-8")
    (root / "patience_audit.jsonl").write_text("{}\n", encoding="utf-8")


def test_suite_ignores_hostile_local_config_in_repo_root_equivalent(tmp_path, monkeypatch):
    """Drop synthetic leftovers into a repo-root equivalent and prove the
    autouse isolation fixture still holds the suite's assumptions.

    Decoys go in a sibling of the isolated cwd, matching how a developer
    leftover sits in the checkout while tests run with a tmp cwd. A hostile
    .env is also placed in the isolated cwd to prove envfile.load is disabled.
    """
    decoy = tmp_path / "hostile-root"
    decoy.mkdir()
    write_hostile_decoys(decoy)
    # envfile.load() defaults to ./.env; the fixture already set PATIENCE_NO_DOTENV.
    (Path.cwd() / ".env").write_text(HOSTILE_ENV, encoding="utf-8")

    envfile.load()
    assert os.environ.get("PATIENCE_NO_DOTENV") == "1"
    assert os.environ.get("PATIENCE_EXECUTE_LIVE") is None
    assert os.environ.get("PATIENCE_DEV_KILL") is None
    assert os.environ.get("PATIENCE_API_TOKEN") is None
    assert os.environ.get("PATIENCE_CLAIM_SECRET") is None
    assert os.environ.get("PATIENCE_POLICY") is None
    # Test default, not the hostile PATIENCE_DEV_OPEN=0 from the decoy .env.
    assert os.environ.get("PATIENCE_DEV_OPEN") == "1"

    # identity.agents_path() otherwise defaults to <repo>/agents.yaml (next to
    # identity.py), which is how a leftover repo-root agents.yaml leaked in.
    assert identity.load_agents() == {}
    assert identity.agent_mode() is False
    assert identity.agents_path().resolve() != (decoy / "agents.yaml").resolve()
    assert not identity.agents_path().exists()

    # Isolated approvers file is empty; the decoy account is not loaded.
    assert approvers.load() == {}
    assert approvers.approvers_path().resolve() != (decoy / "approvers.yaml").resolve()

    # Unset PATIENCE_POLICY must keep the packaged default, not a leftover policy.yaml.
    policy = risk_policy.Policy()
    assert policy.path.resolve() == risk_policy.DEFAULT_POLICY.resolve()
    assert policy.path.resolve() != (decoy / "policy.yaml").resolve()
    assert policy.raw.get("thresholds", {}).get("mass_recipients") != 1

    # Engine / API state is isolated; leftover patience_state.json is not loaded.
    state_path = Path(api._state_path()).resolve()
    assert state_path != (decoy / "patience_state.json").resolve()
    engine = Patience(api._state_path())
    assert engine.state.mission != "HOSTILE_SYNTHETIC_STATE"
    assert engine.state.authorized_actions == []

    # Cwd-relative default used by trigger_worker / Patience() also misses the
    # repo-root equivalent because the fixture chdirs into an empty isolated dir.
    cwd_default = Patience("patience_state.json")
    assert cwd_default.state.mission != "HOSTILE_SYNTHETIC_STATE"
    assert cwd_default.memory_store.path.resolve() != (decoy / "patience_state.json").resolve()

    assert audit.path().resolve() != (decoy / "patience_audit.jsonl").resolve()

    assert (decoy / ".env").is_file()
    assert (decoy / "agents.yaml").is_file()
    assert (decoy / "approvers.yaml").is_file()
    assert (decoy / "policy.yaml").is_file()
    assert (decoy / "patience_state.json").is_file()
    assert monkeypatch is not None


def test_inherited_patience_env_is_stripped():
    """Leftover policy/agents/state pointers and kill/live flags are absent
    unless a test sets them. The autouse fixture strips inherited PATIENCE_*."""
    assert os.environ.get("PATIENCE_POLICY") is None
    assert os.environ.get("PATIENCE_EXECUTE_LIVE") is None
    assert os.environ.get("PATIENCE_DEV_KILL") is None
    assert os.environ.get("PATIENCE_AGENTS", "").endswith(os.path.join("_isolated", "agents.yaml"))
    assert os.environ.get("PATIENCE_STATE_PATH", "").endswith(os.path.join("_isolated", "patience_state.json"))
    assert os.environ.get("PATIENCE_NO_DOTENV") == "1"
    assert os.environ.get("PATIENCE_DEV_OPEN") == "1"
