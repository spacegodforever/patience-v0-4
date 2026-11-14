# ADRs

Format: Nygard-style (Context, Decision, Consequences). 0001-0009 are backfilled from code and commit history.

- [0001 Deterministic YAML policy gate](0001-deterministic-policy-gate.md) (Accepted (v0.5))
- [0002 LLM second opinion can only add approval](0002-llm-second-opinion-only-adds.md) (Accepted (v0.5))
- [0003 Gateway mode: PATIENCE holds tool credentials](0003-gateway-mode.md) (Accepted (v0.6))
- [0004 Approvals bound to payload hash, executed at most once](0004-payload-hash-bound-approvals.md) (Accepted (v0.6 security fixes))
- [0005 Hash-chained JSONL audit log with .head](0005-hash-chained-audit-log.md) (Accepted (v0.6))
- [0006 Per-approver scrypt accounts; shared token deprecated](0006-per-approver-accounts.md) (Accepted (v0.6))
- [0007 Fail-closed API auth](0007-fail-closed-api-auth.md) (Accepted (v0.6 security fixes))
- [0008 Single-process JSON state with file lock](0008-single-process-file-state.md) (Accepted (v0.5))
- [0009 Coordinator is preview-only and routes through the gate](0009-coordinator-preview-only.md) (Accepted on branch feat/coordinator)
- [0010 Durable, schema-validated ingestion and off-host audit replication](0010-durable-ingestion-and-offhost-audit.md) (Proposed)
