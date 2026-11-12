# Completeness pass (local branch `feat/completeness-pass`)

Review of `feat/catastrophe-guard`, `feat/github-adapter` and `feat/org-authority-gate` against the
gate flow (propose -> policy -> approval -> execute bound to the payload hash -> audit). The audit
log is append-only and tamper-evident (hash-chained); it is not immutable. Nothing here is
production-ready or a compliance claim.

## 1. Recovery for requests stuck at `executing`

Before: a process crash after the execute claim left a request at `executing` forever. It was safely
unrunnable (409 "already used") but invisible and unresolvable.

Now (`DevGate.flag_stuck_executions`, `DevGate.resolve_review`, routes `POST /v1/dev/admin/reconcile`
and `POST /v1/dev/requests/{id}/resolve`):

- The execute claim records `claimed_at`.
- A named human approver (per-user account; the legacy shared token is refused) can sweep requests
  that have been `executing` longer than a minimum age (default 300 s; set it above the slowest
  adapter timeout). They move to `needs_review`. Requests with no `claimed_at` (older rows) are
  treated as old enough.
- `needs_review` is never retried and is not executable. A named human other than the proposer or
  its owners records `executed` or `failed` plus a required note after checking the target system.
  The request then ends in terminal `executed` status with a `resolution` record.
- Each step is written to the audit log (`dev.execute.needs_review`, `dev.execute.resolved`,
  `dev.self_resolution_rejected`).

Limits: the sweep is human-triggered, not scheduled. The age threshold is a heuristic: flagging a
request whose adapter is still running would not stop that adapter. Resolution outcome is the
human's statement, not verified by the gate.

## 2. Authenticated grant/revoke callers (fail closed)

Before: `CapabilityAuthority.grant/revoke` took `granted_by` / `revoked_by` as plain strings, there
were no grant routes, grants were not in the audit log, and the API built `DevGate` with no
authority store, so `test.run_isolated` could never be granted over the API.

Now:

- `grant()` and `revoke()` require an `attestation`: a 60-second, HMAC-signed assertion bound to the
  signer, the purpose (grant or revoke) and the grant id. Missing, forged, expired, or mismatched
  attestations are refused with 401 and nothing is stored.
- New routes `POST /v1/dev/authority/grants` and `POST /v1/dev/authority/grants/{id}/revoke` accept
  only a named per-user account with the `admin` role (the legacy shared token and agent keys are
  refused). The signer is always the authenticated user; a `granted_by` in the request body is
  ignored. An admin who owns the agent still cannot grant its capability.
- Grants and revocations are written to the audit log (`dev.authority.granted`,
  `dev.authority.revoked`).
- The API now wires a durable grant store (`PATIENCE_DEV_AUTHORITY_DB`, default
  `patience_dev_authority.db`, git-ignored via `*.db`, mode 0600).

Limits: the attestation proves the authenticating route vouched for the signer; any code running in
the same process with the claim secret can still mint one, so this is a trust-boundary check, not a
second factor. Who may hold the `admin` role is a deployment decision. Isolation flags remain
declared evidence, not enforced.
