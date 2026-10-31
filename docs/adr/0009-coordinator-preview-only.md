# ADR 0009: Coordinator is preview-only and routes through the gate

Status: Accepted on branch feat/coordinator

## Context
Experimental coordinator had no auth and an unchecked `preview_only` label.

## Decision
Coordinator mounted under `/v1/coordinator` behind `require_caller`/session+CSRF; previews go through `_check_impl`; writes fail if audit fails; LLM text unverified.

## Consequences
Keeps one enforcement path. Sessions are in-memory.
