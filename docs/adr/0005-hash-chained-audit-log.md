# ADR 0005: Hash-chained JSONL audit log with .head

Status: Accepted (v0.6)

## Context
Need tamper evidence without external infrastructure.

## Decision
SHA-256 chain per record, newest hash in `.head`, `audit.py verify`.

## Consequences
Detects edits/reorders/truncation by someone who does not also rewrite `.head`. Not tamper-proof on the same host; off-host replication proposed (ADR 0010).
