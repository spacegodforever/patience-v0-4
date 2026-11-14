# ADR 0006: Per-approver scrypt accounts; shared token deprecated

Status: Accepted (v0.6)

## Context
A shared approver token cannot attribute decisions.

## Decision
`approvers.yaml` with scrypt password/PIN hashes and roles; legacy token only with explicit flag.

## Consequences
Attribution per person; throttling is in-process and per username (see audit A2).
