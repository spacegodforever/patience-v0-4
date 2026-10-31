# ADR 0001: Deterministic YAML policy gate

Status: Accepted (v0.5)

## Context
Agents can phrase risky actions many ways; a model alone is not a reliable gate.

## Decision
Risk is classified by `risk_policy.py` from `policies/default.yaml` (verbs, categories, stemming, typo fixing, tool specs). Decisions are reproducible and testable (`tests/cases/governance_cases.yaml`, 188 labelled cases).

## Consequences
Predictable and auditable; misses novel phrasings, so unknown side-effect verbs and unknown tools fail safe to approval.
