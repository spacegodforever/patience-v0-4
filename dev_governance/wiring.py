"""Default adapter wiring for the API's dev gate (see docs/github-dryrun-wiring.md).

GitHub actions (code.get_repo / code.list_prs / code.get_pr_diff / code.open_pr) are handled by
`GitHubAdapter`, which is DRY-RUN unless every live prerequisite holds. This module decides only
whether the adapter is given a network transport at all:

- PATIENCE_GITHUB_LIVE not set  -> no transport object is created; nothing can be sent.
- PATIENCE_GITHUB_LIVE=1        -> `UrllibTransport` (api.github.com over https only). It is
  read-only (GET) unless `code.open_pr` AND at least one repo are allowlisted.
  The adapter and the gate still enforce the remaining write prerequisites (approved payload
  hash, kill switch off, single-use claim token, token present) on every send.

Transport and adapters are resolved on every call so environment changes take effect without a
restart. `transport_factory` is a module-level hook so tests can inject a fake and never touch the
network.
"""
from __future__ import annotations
import os
from typing import Callable, Optional

from .adapters import Adapter, default_adapters
from .github_adapter import GitHubAdapter, _csv, _flag, WRITE_ACTIONS
from .github_transport import UrllibTransport


def github_transport_from_env() -> Optional[Callable[[dict], dict]]:
    if not _flag("PATIENCE_GITHUB_LIVE"):
        return None
    can_write = bool(set(WRITE_ACTIONS) & _csv("PATIENCE_GITHUB_ACTION_ALLOWLIST")) \
        and bool(_csv("PATIENCE_GITHUB_REPO_ALLOWLIST"))
    return UrllibTransport(read_only=not can_write)


transport_factory: Callable[[], Optional[Callable[[dict], dict]]] = github_transport_from_env


def api_adapters() -> list[Adapter]:
    """Simulated adapters for everything except GitHub reads and `code.open_pr`, which use the
    real adapter in dry-run-by-default mode. merge/push/force-push stay simulated (never real)."""
    return [*default_adapters(), GitHubAdapter(transport=transport_factory())]
