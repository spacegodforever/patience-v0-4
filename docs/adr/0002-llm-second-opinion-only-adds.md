# ADR 0002: LLM second opinion can only add approval

Status: Accepted (v0.5)

## Context
An LLM may catch risk the rules miss, but may also be wrong or prompt-injected.

## Decision
`second_opinion.py` runs when a key is configured; its output can add `llm_disagreement` and force approval, never downgrade.

## Consequences
Model failure cannot loosen the gate; it can add approval load.
