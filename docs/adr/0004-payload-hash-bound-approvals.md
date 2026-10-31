# ADR 0004: Approvals bound to payload hash, executed at most once

Status: Accepted (v0.6 security fixes)

## Context
Truncated labels let a different payload share an approval.

## Decision
Approval records `approved_args_hash`; execute requires a matching hash and claims under the state lock; idempotency keys never re-run.

## Consequences
Strong per-request binding. Gap found 2026-10-31: deferred duplicates share the key (fixed on local branch `fix/approval-integrity`).
