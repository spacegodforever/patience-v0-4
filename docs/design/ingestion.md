# Design: hardened, highly available ingestion [proposed]

## What exists today
- Intake is synchronous HTTP: `/v1/check`, `/v1/execute`, coordinator endpoints [branch]. Pydantic models validate shape and size (e.g. `CheckIn`, args <= 8000 bytes).
- Every `/v1/check` passes the policy gate; unknown tools fail safe to approval.
- State is one JSON file under a file lock, one process; no queue, no retries (a failed execution is never retried by design), no replication.
- Idempotency exists for `/v1/execute` only (`idempotency_key`).
- Audit log is local JSONL + `.head` on the same host.

## Goals
1. Schema-validated intake for every source, versioned.
2. Every item passes the policy gate before anything consequential; unknown source, schema, tool or policy = reject or hold, never allow.
3. Durable queue: accepted items survive process crash; retries with backoff and a dead-letter state; idempotency keys at intake.
4. Audit replication off-host so a local attacker cannot silently rewrite history.
5. Availability: the intake keeps accepting (or cleanly refusing) while workers or replicas are down.

Non-goals: multi-region consensus; autonomous execution without approval.

## Proposed design
**Edge validation.** `ingest/schemas/<source>/<version>.json` (JSON Schema) or Pydantic models with `extra="forbid"`. Envelope: `{source, schema_version, idempotency_key, occurred_at, payload}`. Source must be registered in a per-source permission registry (`ingest/sources.yaml`: allowed schemas, max rate, owner). Unregistered source or unknown version = 422 + audit `ingest.rejected`.

**Durable queue (transactional outbox).** SQLite in WAL mode, table `inbox(id, source, idem_key UNIQUE(source, idem_key), payload_hash, state, attempts, next_attempt_at, last_error, created_at)`. Insert and the audit `ingest.accepted` record are written in one transaction (audit-first outbox row, see replication). Duplicate `(source, idem_key)` with the same hash returns the original id; with a different hash it returns 409.

**Workers.** Claim with `UPDATE ... SET state='processing', lease_until=? WHERE state='queued' AND next_attempt_at<=now`. Each item goes through `_check_impl` (or the policy core extracted from it). Outcomes: `allowed`, `needs_approval` (waits for a human), `rejected`. Transient errors retry with exponential backoff and jitter up to N attempts, then `dead_letter` + alert. Expired leases are reclaimed (at-least-once processing; idempotent handlers). Consequential execution still goes only through `/v1/execute` at most once.

**Fail closed.** Policy load failure, audit write failure, schema registry missing, or queue disk full: intake returns 503 and accepts nothing.

**Off-host audit replication.** A replicator tails the local chain and ships records in order to a separate host or write-once object storage (for example an object-lock bucket). Every K records or T seconds it publishes a signed checkpoint `{seq, hash, ts}` (Ed25519 key not stored with the API). `audit verify --remote` compares the local chain with the replica and the latest checkpoint. Replication lag is monitored; if lag exceeds a threshold, consequential operations (approve/execute) stop (configurable fail-closed).

**HA.** Stateless API replicas in front of one queue database is the first step; true multi-writer HA needs a server database (e.g. Postgres with `SELECT ... FOR UPDATE SKIP LOCKED`). The JSON state file (ADR 0008) must move into the same database first.

## Threats addressed / not addressed
- Addressed: replayed intake (idempotency), malformed payloads (schema), unknown sources (registry), crash loss (WAL), silent local log rewrite (remote checkpoints).
- Not addressed: compromise of the replica host and the signing key together; a malicious approver; agents holding direct tool credentials.

## Rollout
1. Extract policy core from `_check_impl`. 2. Source registry + schemas. 3. SQLite inbox + worker. 4. Replicator + checkpoints + `verify --remote`. 5. Move state into DB; optional Postgres.
