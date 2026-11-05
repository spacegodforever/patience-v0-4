"""Adapters execute an approved action. Everything here is SIMULATED: no network, no credentials."""
from __future__ import annotations
import hashlib
from typing import Any


class Adapter:
    actions: tuple = ()
    simulated = True

    def validate(self, action: str, payload: dict) -> None:
        """Raise ValueError if the payload is malformed (checked at propose time)."""

    def execute(self, action: str, payload: dict, ctx: dict) -> dict[str, Any]:
        raise NotImplementedError


def _fake_id(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:12]


class SimulatedGitHubPRAdapter(Adapter):
    actions = ("code.open_pr", "code.merge_pr", "code.push_branch", "code.force_push")

    def validate(self, action, payload):
        if not payload.get("repo"):
            raise ValueError("repo is required")
        if action in ("code.open_pr",) and not (payload.get("head") and payload.get("base")):
            raise ValueError("head and base are required")
        if action == "code.merge_pr" and not payload.get("pr_number"):
            raise ValueError("pr_number is required")

    def execute(self, action, payload, ctx):
        return {"simulated": True, "adapter": "github_pr", "action": action, "repo": payload["repo"],
                "would_do": f"{action} on {payload['repo']}",
                "fake_ref": _fake_id(action, payload.get("repo"), ctx["request_id"])}


class SimulatedDeployAdapter(Adapter):
    actions = ("deploy.release", "deploy.rollback")

    def validate(self, action, payload):
        for f in ("service", "environment", "version"):
            if not payload.get(f):
                raise ValueError(f"{f} is required")

    def execute(self, action, payload, ctx):
        return {"simulated": True, "adapter": "deploy", "action": action, "service": payload["service"],
                "environment": payload["environment"], "version": payload["version"],
                "deployment_id": _fake_id(payload["service"], payload["version"], ctx["request_id"])}


class SimulatedDestructiveAdapter(Adapter):
    """Simulates irreversible operations. Never touches anything; reports what it would do."""
    actions = ("db.drop", "db.truncate", "db.delete_rows", "db.migrate", "repo.delete", "data.wipe",
               "infra.destroy", "infra.apply", "secrets.rotate")

    def execute(self, action, payload, ctx):
        return {"simulated": True, "adapter": "destructive_sim", "action": action,
                "would_do": f"{action} (blast radius {payload.get('blast_radius')})",
                "rollback_plan_recorded": bool(payload.get("rollback_plan")),
                "fake_ref": _fake_id(action, ctx["request_id"])}


def default_adapters() -> list[Adapter]:
    return [SimulatedGitHubPRAdapter(), SimulatedDeployAdapter(), SimulatedDestructiveAdapter()]
