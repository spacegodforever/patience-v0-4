# Architecture overview

```
agent --(Bearer agent key)--> api.py /v1/check   -> risk_policy (policies/default.yaml)
                                                 -> engine.Patience (oracle.Oracle assess, governance.GovernanceGate)
                                                 -> optional LLM second opinion (can only add approval)
                                                 -> state (patience_state.json, filelock) + audit.jsonl
human approver --(Basic / signed link / dashboard)--> decisions.decide -> state + audit
agent --> /v1/execute (agent-key mode only) -> executors/* (dry-run unless PATIENCE_EXECUTE_LIVE=1)
coordinator UI/session --> /v1/coordinator/* [branch] -> coordinator/store (SQLite) ; previews -> _check_impl
```

## Components [exists]
- `api.py`: FastAPI app. Auth (`require_caller`, `require_approver`, `require_admin`), `/v1/check`, approve/deny, `/v1/execute`, admin reconcile, signed-link pages.
- `risk_policy.py` + `policies/default.yaml`: deterministic text and tool classification, auto-allow limits, rolling budgets.
- `engine.py`, `oracle.py`, `governance.py`: observe/assess/decide cycle; `GovernanceGate` decides whether authorization is needed.
- `decisions.py`: the single approve/deny path for API, dashboard and links.
- `approvers.py`: scrypt-hashed approver accounts, PINs, in-process throttle.
- `identity.py`: per-agent hashed API keys (`agents.yaml`).
- `audit.py`: append-only JSONL with SHA-256 hash chain plus `.head` file. Tamper-evident on one host only.
- `executors/`: mock, SMTP, webhook, Stripe. Disabled until configured; dry-run by default.
- `links.py`, `notify.py`: HMAC-signed single-use approve/deny links; Slack/webhook/email alerts.
- `dashboard*.py`: Streamlit dashboard. `patience_mcp.py`: MCP stdio wrapper over the HTTP API.
- `reconcile.py`: crash recovery for executions stuck in `executing`.

## Coordinator [branch: feat/coordinator]
`coordinator/` (store, policy, llm, routes) under `/v1/coordinator`; UI in `ui/coordinator/`. It ranks
projects, optionally asks local Ollama for an unverified suggestion, and submits action previews to
`_check_impl`. It never executes.

## Trust boundaries
1. Agent to API: agent key; identity is never taken from the body.
2. Human to API: approver accounts; agent keys never approve.
3. API to tool providers: credentials live only in the PATIENCE process env (gateway mode). Enforcement
   depends on agents not holding those credentials and on egress controls (README, "Gateway mode").
4. Host: state, approvers, agents and audit files are on the same disk as the API. A local user with write
   access to that disk is **outside** the protection model today (see audit finding A3).

## Deployment assumptions [exists]
Single API process owns the state file; loopback bind (127.0.0.1); Docker binds loopback.
