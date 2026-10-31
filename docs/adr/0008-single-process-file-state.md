# ADR 0008: Single-process JSON state with file lock

Status: Accepted (v0.5)

## Context
Local-first, minimal dependencies.

## Decision
`memory_store` JSON file + `filelock`; one API process owns it; `reconcile.py` handles crashes.

## Consequences
Simple; no HA, no multi-writer scale. Revisit with ingestion design.
