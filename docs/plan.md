# Prioritized engineering plan

Sizes: S <= 1 day, M 2-4 days, L 1-2 weeks. Fixes first, then capabilities.

## Fixes
| P | Item | Size | Proving tests |
|---|---|---|---|
| F1 | Merge `fix/approval-integrity`: one approval, one execution across deferred duplicates (D1); block self-approval (A2a); approval TTL (A2d); atomic `.head` (A3b) | S (done locally) | `tests/test_approval_integrity.py` (7 tests) |
| F2 | Lockout without DoS: throttle per (user, IP) with global backoff, cap `_FAILS` size, persist counters in state; optionally TOTP for approvers | M | N bad attempts from IP X do not lock the user from IP Y; dict size bounded; counters survive restart |
| F3 | Transactional decisions: status check + decide under one lock; audit-before-commit pattern in `_check_impl` and coordinator store (A3c, O2, O3) | M | concurrent approve/deny yields exactly one decision; audit failure leaves no pending request; no audit entry without a committed write |
| F4 | `verify()` fails when a previously seen head is missing (A3); store expected head in a second location | S | delete log + head, verify not ok if checkpoint exists |
| F5 | Atomic, 0600-from-creation writes for `approvers.yaml`/`agents.yaml` (O1) | S | file mode 0600 immediately; crash mid-write leaves old file |
| F6 | Coordinator: persist sessions (hashed), rotate on login, CSRF also in dev mode (A2e) | S | session survives restart; dev-mode POST without CSRF is 403 |

## Capabilities
| P | Item | Size | Proving tests |
|---|---|---|---|
| C1 | Off-host audit replication + signed checkpoints + `audit verify --remote` (ADR 0010) | L | replica matches local; local rewrite detected against replica; replication lag beyond threshold blocks approve/execute |
| C2 | Risk tiers + batching to reduce approval fatigue: tier low/medium/high in policy; batch approve of identical low-tier items with per-item hashes; two-person rule for high tier; approval-load metrics | L | batch approves only listed hashes; high tier needs two distinct approvers; metrics endpoint counts needs_approval/day |
| C3 | Budget accounting counts executed usage only (approved-unexecuted released on TTL) | S | approved-but-expired refund no longer consumes budget |
| C4 | Hardened ingestion: source registry + versioned schemas, SQLite-WAL inbox with idempotency keys, leased workers with backoff and dead-letter, all items through the policy core, fail closed (design/ingestion.md) | L | unknown source/schema = 422 + audit; duplicate idem key same hash returns same id, different hash 409; crash mid-processing reclaimed after lease; N failures go to dead_letter; policy/audit unavailable = 503 |
| C5 | Move JSON state into the same DB; enable multiple API replicas (prerequisite for HA) | L | concurrent processes never double-execute (multi-process test) |
| C6 | Gateway enforcement aids: startup check warning if tool credentials are visible to agent configs; documented egress templates (A1) | M | check flags a test env with SMTP creds in agent env |
| C7 | Coordinator UI: preview submission form, approval status view; frontend tests | M | Vitest/Playwright: preview shows `needs_approval`, never "executed" |

## Memory foundation (ADR 0011), after F1-F6
See `design/memory-foundation.md` for M1-M7. M1 (schema + migrations, record contract, device identity, permission registry with audited grants and revokes) is implemented on local branch `feat/memory-foundation`, size M, proven by `tests/test_memory_foundation.py` (28 tests).
