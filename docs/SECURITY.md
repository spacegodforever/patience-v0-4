# PATIENCE v0.6 — security notes

## API authentication (fail closed)
`/v1/*` requires per-agent API keys (`agents.yaml`) or a shared `PATIENCE_API_TOKEN`.
If neither is configured the API returns **401** for every agent call and `/health` reports
`auth: not_configured_fail_closed`. Open local-dev mode exists only when `PATIENCE_DEV_OPEN=1`
is set deliberately; never set it on a reachable host.

## Approvals are bound to the exact payload
* Duplicate pending requests are merged only when the **full** SHA-256 hash of tool + args matches.
* When a human approves, the approved args hash is stored on that request (`approved_args_hash`).
  `/v1/execute` refuses (409) if the args being executed differ from the approved hash.
* Each approval executes at most once (idempotency keys).

## Login throttling
* Per user: 5 failed password/PIN attempts lock the account for 5 minutes (HTTP 429 while locked).
* Per client IP: 20 failures in 10 minutes lock that IP for 15 minutes (HTTP 429).
* Applies to API HTTP Basic auth and signed-link password/PIN forms. Counters are in-process
  (single API process; they reset on restart). Behind a proxy all clients share the proxy IP
  unless the server is run with trusted forwarded headers (`uvicorn --proxy-headers --forwarded-allow-ips`).

## Network binding
* `python api.py` and the Docker image bind to **127.0.0.1** by default (`PATIENCE_API_HOST` / `PATIENCE_BIND`).
* `docker compose` widens the bind to the container's private network only (Docker publishing cannot
  reach a container-loopback process) and publishes host ports on `127.0.0.1` only.
* To expose remotely, keep these loopback bindings and put a TLS reverse proxy in front, e.g. Caddy:

      patience.example.com {
          reverse_proxy 127.0.0.1:8765
      }

  Add proxy-level rate limiting and, ideally, SSO or mTLS in front of the dashboard (8501).

## Actions that run without human approval
The governance gate (`governance.py`, `GovernanceGate.AUTONOMOUS`) lets these engine actions proceed
without approval, and only when the assessment found **no** side-effect risk categories and
consequence < 0.7:

`respond`, `research`, `summarize`, `log`, `wait`, `remind`, `inspect_state`

Anything with a side-effect category (payments, communication, deletion, unknown side effect, etc.),
any unknown tool, and any high-consequence action requires a human approver. There is no
"autonomous mode" switch and no API to change this list.

## Deprecated: legacy shared approver token
`PATIENCE_LEGACY_APPROVER_TOKEN=1` + `PATIENCE_APPROVER_TOKEN` (header `X-Approver-Token`) is
**deprecated** and will be removed. Decisions made with it are recorded as approver `legacy-token`
(no individual identity), and each use writes an `auth.legacy_token_used` audit event.
Use per-approver accounts in `approvers.yaml`.

## Known limits
* Approver identity is a local username/password/PIN; it is not yet independently verified (no SSO/IdP).
* Single API process: state, locks and throttles are per process; do not scale the api service.
