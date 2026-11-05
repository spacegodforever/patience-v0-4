"""GitHub adapter, built in three phases (see docs/github-adapter.md).

Phase 1  read-only: code.get_repo, code.list_prs, code.get_pr_diff
Phase 2  dry-run (DEFAULT): build the exact HTTP request and return it without sending
Phase 3  gated write: code.open_pr only, sent only when ALL hold:
           PATIENCE_GITHUB_LIVE=1, action allowlisted, repo allowlisted,
           request approved with matching payload hash, PATIENCE_DEV_KILL not set.

Network goes ONLY through an injected `transport(request) -> response`. No transport is
configured by default, so nothing is ever sent unless a caller explicitly supplies one.
The token is read from PATIENCE_GITHUB_TOKEN at execution time, used only in the header handed
to the transport, and never returned, logged, audited, or included in error text.
"""
from __future__ import annotations
import json
import os
import re
from typing import Any, Callable, Optional

from .adapters import Adapter

API = "https://api.github.com"
READ_ACTIONS = ("code.get_repo", "code.list_prs", "code.get_pr_diff")
WRITE_ACTIONS = ("code.open_pr",)
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")

Transport = Callable[[dict], dict]  # request {method,url,headers,body} -> {status, headers, body}


class GitHubAdapterError(Exception):
    """Safe-to-show error: messages never include the token."""


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _csv(name: str) -> set:
    return {x.strip().lower() for x in os.environ.get(name, "").split(",") if x.strip()}


class GitHubAdapter(Adapter):
    actions = READ_ACTIONS + WRITE_ACTIONS
    simulated = False

    def __init__(self, transport: Optional[Transport] = None, token_env: str = "PATIENCE_GITHUB_TOKEN"):
        self.transport = transport
        self.token_env = token_env

    # ---- validation (propose time) ------------------------------------------
    def validate(self, action: str, payload: dict) -> None:
        repo = str(payload.get("repo", ""))
        if not _REPO_RE.match(repo):
            raise ValueError("repo must be 'owner/name'")
        if action == "code.get_pr_diff":
            if not str(payload.get("pr_number", "")).isdigit():
                raise ValueError("pr_number must be a positive integer")
        if action == "code.list_prs" and payload.get("state", "open") not in ("open", "closed", "all"):
            raise ValueError("state must be open, closed or all")
        if action == "code.open_pr":
            for f in ("head", "base", "title"):
                if not payload.get(f):
                    raise ValueError(f"{f} is required")
            for f in ("head", "base"):
                if not _BRANCH_RE.match(str(payload[f])) or ".." in str(payload[f]):
                    raise ValueError(f"{f} is not a valid branch name")
            if len(str(payload["title"])) > 256 or len(str(payload.get("body", ""))) > 65536:
                raise ValueError("title or body too long")

    # ---- phase 2: build the exact request -------------------------------------
    def build_request(self, action: str, payload: dict) -> dict:
        repo = payload["repo"]
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
             "User-Agent": "patience-dev-governance"}
        if action == "code.get_repo":
            return {"method": "GET", "url": f"{API}/repos/{repo}", "headers": h, "body": None}
        if action == "code.list_prs":
            st = payload.get("state", "open")
            return {"method": "GET", "url": f"{API}/repos/{repo}/pulls?state={st}&per_page=30", "headers": h, "body": None}
        if action == "code.get_pr_diff":
            return {"method": "GET", "url": f"{API}/repos/{repo}/pulls/{int(payload['pr_number'])}",
                    "headers": {**h, "Accept": "application/vnd.github.diff"}, "body": None}
        if action == "code.open_pr":
            body = {"title": payload["title"], "head": payload["head"], "base": payload["base"],
                    "body": payload.get("body", ""), "draft": bool(payload.get("draft", True))}
            return {"method": "POST", "url": f"{API}/repos/{repo}/pulls", "headers": h,
                    "body": json.dumps(body, sort_keys=True)}
        raise GitHubAdapterError(f"unsupported action {action!r}")

    # ---- phase 3 gates ---------------------------------------------------------
    def write_blockers(self, action: str, payload: dict, ctx: dict) -> list:
        b = []
        if not _flag("PATIENCE_GITHUB_LIVE"):
            b.append("PATIENCE_GITHUB_LIVE is off")
        if action not in WRITE_ACTIONS or action not in _csv("PATIENCE_GITHUB_ACTION_ALLOWLIST"):
            b.append("action not allowlisted")
        if str(payload.get("repo", "")).lower() not in _csv("PATIENCE_GITHUB_REPO_ALLOWLIST"):
            b.append("repo not allowlisted")
        if not ctx.get("approved") or ctx.get("tier") == "low":
            b.append("request not approved by a human")
        from .gate import payload_hash  # local import avoids a cycle
        if not ctx.get("payload_hash") or ctx["payload_hash"] != payload_hash(action, payload):
            b.append("payload hash does not match the approval")
        if _flag("PATIENCE_DEV_KILL"):
            b.append("kill switch PATIENCE_DEV_KILL is on")
        if self.transport is None:
            b.append("no transport configured")
        return b

    # ---- execute ------------------------------------------------------------
    def execute(self, action: str, payload: dict, ctx: dict) -> dict[str, Any]:
        req = self.build_request(action, payload)
        preview = {k: req[k] for k in ("method", "url", "headers", "body")}  # no token in here
        if action in WRITE_ACTIONS:
            blockers = self.write_blockers(action, payload, ctx)
            if blockers:
                return {"dry_run": True, "adapter": "github", "action": action, "request": preview,
                        "not_sent_because": blockers}
        else:
            if _flag("PATIENCE_DEV_KILL") or self.transport is None:
                return {"dry_run": True, "adapter": "github", "action": action, "request": preview,
                        "not_sent_because": ["kill switch PATIENCE_DEV_KILL is on"] if _flag("PATIENCE_DEV_KILL")
                        else ["no transport configured"]}
        if _flag("PATIENCE_DEV_KILL"):  # re-check immediately before sending
            raise GitHubAdapterError("kill switch on")
        token = os.environ.get(self.token_env, "")
        if not token:
            raise GitHubAdapterError(f"{self.token_env} is not set")
        wire = {**req, "headers": {**req["headers"], "Authorization": f"Bearer {token}"}}
        try:
            resp = self.transport(wire)
        except Exception as e:
            raise GitHubAdapterError(f"transport error ({type(e).__name__})") from None
        finally:
            wire = None; token = None  # noqa: F841 - drop references
        status = int(resp.get("status", 0))
        if status >= 400:
            raise GitHubAdapterError(f"GitHub returned HTTP {status}")
        return {"dry_run": False, "adapter": "github", "action": action, "status": status,
                "data": _summarize(action, resp.get("body"))}


def _summarize(action: str, body: Any) -> Any:
    """Return only the fields we need, never the raw response (which could echo headers)."""
    if action == "code.get_pr_diff":
        text = body if isinstance(body, str) else ""
        return {"diff": text[:200_000], "truncated": len(text) > 200_000}
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return {}
    if action == "code.get_repo" and isinstance(body, dict):
        return {k: body.get(k) for k in ("full_name", "private", "default_branch", "visibility")}
    if action == "code.list_prs" and isinstance(body, list):
        return [{k: p.get(k) for k in ("number", "title", "state", "draft")} |
                {"head": (p.get("head") or {}).get("ref"), "base": (p.get("base") or {}).get("ref")}
                for p in body if isinstance(p, dict)]
    if action == "code.open_pr" and isinstance(body, dict):
        return {k: body.get(k) for k in ("number", "html_url", "state", "draft")}
    return {}
