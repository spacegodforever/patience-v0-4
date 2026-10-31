# ADR 0007: Fail-closed API auth

Status: Accepted (v0.6 security fixes)

## Context
Open-by-default APIs get deployed open.

## Decision
No agents file and no token = 401 unless `PATIENCE_DEV_OPEN=1`.

## Consequences
Dev mode must never be set in shared environments.
