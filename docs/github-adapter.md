# GitHub adapter (dev governance)

Status: experimental. Off by default. Not production-ready. Every call still goes through the dev
gate, whose audit log is append-only and tamper-evident (hash chain), not immutable.
`dev_governance/github_adapter.py`; opt-in: `DevGate(adapters=[GitHubAdapter(transport=...)])`.
It is **not** in `default_adapters()`, and **no network transport ships**: the caller must inject one.

## Phases

| Phase | Actions | Tier | What happens |
|---|---|---|---|
| 1 read-only | `code.get_repo`, `code.list_prs`, `code.get_pr_diff` | low | GET only; responses reduced to a few fields (no raw body) |
| 2 dry-run (default) | all | – | builds the exact method/URL/headers/body and returns it with `not_sent_because`; does not use up the approval |
| 3 gated write | `code.open_pr` only (as draft by default) | medium | sent only if **all** hold, else falls back to dry-run |

Phase 3 conditions, all checked by the adapter itself (in addition to the gate):
`PATIENCE_GITHUB_LIVE=1`; `code.open_pr` in `PATIENCE_GITHUB_ACTION_ALLOWLIST`; the repo in
`PATIENCE_GITHUB_REPO_ALLOWLIST`; the request was approved by a human and its payload hash matches;
`PATIENCE_DEV_KILL` is not set (checked again immediately before sending); a transport is injected.
Merge, push and force-push are not supported by this adapter.

## Token
`PATIENCE_GITHUB_TOKEN`, read from the environment only at execution time and put only on the
request given to the transport. It is never returned, stored in gate state, written to the audit
log, or included in error text (errors are reduced to type or HTTP status). Recommended: a
fine-grained token limited to one repo with `Pull requests: read/write` and `Contents: read`.

## Transport
`transport(request: dict) -> {"status": int, "body": ...}`. Tests use a mock and block sockets.

## Not done yet
- No real HTTP transport is included; adding one (e.g. httpx with timeouts) is the next step and
  needs Matthew's yes and a real fine-grained token to try against a test repo.
- No pagination for `list_prs`; no idempotency marker to prevent a duplicate PR on retry.
- Kill switch is env-only (no admin endpoint / DB flag yet). Allowlists are env-only.
