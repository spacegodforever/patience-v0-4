# Suspected tamper
1. Stop the API (no new approvals or executions).
2. Copy `patience_audit.jsonl*`, `patience_state.json`, `approvers.yaml`, `agents.yaml` off the host read-only.
3. Run `audit.py verify` on the copy; compare with any off-box `.head` copies.
4. Rotate agent keys (`identity.py`), approver passwords/PINs, `PATIENCE_LINK_SECRET`, and tool credentials.
5. Review executions since the last known-good head against provider records.
Limitation: an attacker who rewrote both log and `.head` is only detectable against an off-host copy.
