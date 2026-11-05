# Organizational authority: local increment

## Assessment (observed on `feat/github-adapter` at `7d47295`)

- The kit is explicitly a **proposed operating model**, not adopted policy or an execution grant.
  Its mandatory Matthew approval for every build/policy change is left for a human policy decision;
  this increment does not silently add it.
- Existing `ci.run` and `ci.rerun_failed` are low tier (zero per-action approvals), but there is no
  default CI adapter. Low risk does not establish authority. Rather than silently making every CI
  action require a new grant, this increment adds only `test.run_isolated` with explicit authority;
  legacy CI behavior and the stricter build-bearing CI policy remain an explicit human decision.
- Proposed ADR 0011 (read from `feat/memory-foundation`) requires human-granted per-capability
  autonomy, no self-grant, revocation precedence, and unchanged gate outcomes at every level. Its
  milestone does not enforce grant expiry or decide what levels may relax. This increment preserves
  that boundary: level metadata is recorded, never used to reduce a tier or approval count.
- Lead charters, domain ownership, evidence ranking, learning handoffs, sandbox execution, and
  build/push executors remain organizational or future implementation decisions. No broad agency
  layer or second approval gate was added.

## Implemented

`dev_governance/authority.py` stores human grant/revoke events and binds an explicit grant id to
actor, action, resource, exact command/workspace/environment/adapter scope, authenticated owners,
expiry, maximum request TTL, evidence basis/confidence, and explicit no-network/no-secrets/
no-production declarations. Missing, unknown, expired, revoked, mismatched, or malformed grants
fail closed. A human owner, proposer, or mapped owner cannot grant that proposer's capability.

`DevGate` accepts an injected `CapabilityAuthority` and an optional `authority_grant` id at propose.
The new `test.run_isolated` action requires that grant at both proposal and execution, so later
revocation or expiry blocks execution. The grant id is included in the existing hash-bound payload. All existing
payload binding, proposer/owner execution checks, multi-approver floors, signed claims, breaker,
kill switch, and append-only tamper-evident audit behavior remain in place.

## Limits and unresolved human decisions

This is an authority check, **not a sandbox or test runner**. Exact string scope does not prove a
command is safe; adapter/plugin/subprocess isolation is unverified. The declared isolation flags are
evidence requirements, not technical enforcement. Applications must inject a durable SQLite path;
the default is in-memory. Grant administration routes, authenticated grant/revoke signers (currently ordinary method
arguments, not verified identities), deployment wiring, charter records, OS/container isolation, command/resource limits, and recovery from `executing` remain open.
Matthew must still decide whether builds/policy changes need his additional approval and who may
grant/revoke each capability. No external write, push, or deployment is enabled.
