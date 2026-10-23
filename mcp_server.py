"""Minimal PATIENCE MCP server (stdio). Requires `pip install mcp` (tested with mcp 2.3.0).

Run: python mcp_server.py   (env PATIENCE_STATE overrides the state file path)
NOTE: `approver` is asserted by the MCP client; there is no authentication of
who the approver is. Only expose this server to a client you control.
"""
from __future__ import annotations
import os
from pathlib import Path
from mcp.server.mcpserver import MCPServer
from engine import Patience
from executor import ExecutionRefused

STATE = os.environ.get("PATIENCE_STATE") or str(Path(__file__).resolve().parent / "patience_state.json")
server = MCPServer("patience", instructions="PATIENCE governed decision gate (v0.5 local prototype).")


def _p():
    return Patience(STATE)  # reload each call so CLI/dashboard writes are seen


@server.tool()
def propose_action(content: str, executor: str = "", params: dict | None = None) -> dict:
    """Route an observation (and optional allowlisted action) through the PATIENCE gate."""
    r = _p().cycle(content, source="mcp", proposed={"executor": executor, "params": params or {}} if executor else None)
    return {"decision_id": r["decision_id"], "decision": r["decision"], "oracle_path": r["oracle_path"]}


@server.tool()
def list_pending() -> list[dict]:
    """List decisions awaiting per-decision human authorization."""
    return _p().pending()


@server.tool()
def authorize(decision_id: str, approver: str, execute: bool = True) -> dict:
    """Authorize ONE decision by id and (by default) execute its allowlisted action."""
    p = _p()
    p.authorize_decision(decision_id, approver)
    if not execute:
        return {"authorized": decision_id}
    try:
        return {"authorized": decision_id, "receipt": p.execute(decision_id)}
    except ExecutionRefused as e:
        return {"authorized": decision_id, "refused": str(e)}


@server.tool()
def deny(decision_id: str, approver: str, reason: str = "") -> dict:
    """Deny one decision by id."""
    return _p().deny_decision(decision_id, approver, reason)


@server.tool()
def verify_audit() -> dict:
    """Verify the hash-chained audit log."""
    return _p().verify_audit()


if __name__ == "__main__":
    server.run()  # stdio transport by default
