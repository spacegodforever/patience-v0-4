# Test map

Baseline on `v0.6-security-fixes`: 276 passed. `feat/coordinator`: 300. `fix/approval-integrity`: 283.

| Guarantee | Tests |
|---|---|
| Fail-closed API auth | `test_v06_security_fixes.py`, `test_gateway.py` (401 for unknown/missing key) |
| Identity from key, not body | `test_gateway.py` identity tests |
| Payload-hash-bound approvals, no label collision | `test_v06_security_fixes.py::test_truncated_label_collision_does_not_share_approval` |
| Execute at most once, idempotency | `test_gateway.py`, `test_v06_recovery.py` |
| One approval across deferred duplicates [fix branch] | `test_approval_integrity.py::test_deferred_duplicate_*` |
| No self-approval; approval TTL [fix branch] | `test_approval_integrity.py` |
| Policy classification (188 labelled cases) | `test_governance_cases.py`, `test_governance_scoring.py`, `eval_governance.py` |
| Approver accounts, audit chain | `test_v06_accounts_audit.py` |
| Signed links single-use, hash-bound | `test_v06_links_notify.py` |
| Dashboard auth | `test_v06_dashboard.py` |
| MCP wrapper | `test_v06_mcp.py` |
| Stripe executor | `test_v06_stripe.py` |
| Packaging/Docker | `test_v06_packaging.py` |
| Coordinator auth, CSRF, audit fail-closed, gate routing, LLM labelling [branch] | `test_coordinator.py` |

Gaps (no test today): concurrent approve/deny, audit replication, lockout-DoS behaviour, approval-load metrics, ingestion (not built).
