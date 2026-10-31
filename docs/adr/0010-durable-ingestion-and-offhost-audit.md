# ADR 0010: Durable, schema-validated ingestion and off-host audit replication

Status: Proposed

## Context
Ingestion today is synchronous HTTP into a JSON state file; audit lives on the protected host.

## Decision
Adopt the design in `docs/design/ingestion.md`: versioned schemas at the edge, an SQLite-WAL outbox/queue with idempotency keys and bounded retries, every item through the policy gate, and an append-only replicator shipping audit records and signed checkpoints to a separate host or write-once store.

## Consequences
More moving parts; needs ops runbooks. Until built, none of these properties should be claimed.
