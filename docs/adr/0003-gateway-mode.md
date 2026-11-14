# ADR 0003: Gateway mode: PATIENCE holds tool credentials

Status: Accepted (v0.6)

## Context
`/v1/check` alone is advisory; an agent holding credentials can skip it.

## Decision
`/v1/execute` (agent-key mode only) runs executors with credentials held only by PATIENCE.

## Consequences
Real enforcement additionally needs agents stripped of credentials and egress blocked to tool hosts; that is a deployment duty, not code.
