# PATIENCE v0.5 changelog (Oct 23, 2026, local prototype)

Code: `/workspace/patience/src` (v0.4 snapshot: `/workspace/patience/src_v0.4_backup`). src is not a git repo, so no commit or branch was made. Nothing was pushed.

## Shipped
1. **Pluggable LLM Oracle** (`llm_oracle.py`). Calls an OpenAI-compatible `/chat/completions` endpoint set through env vars. Model JSON is parsed and validated into `Assessment` (scores must be in [0,1], lists must be strings). If no key is set, or on HTTP, parse, or validation errors, it falls back to the heuristic. `oracle_path` is recorded per assessment and in the audit log. A rule-based consequence floor means the model can't de-escalate risk.
2. **Approvals that execute** (`executor.py`, `engine.py`, `governance.py`). Authorization is per decision id (`authorize_decision`, `deny_decision`). An executor allowlist covers `write_note` (sandbox dir, path-escape refused), `append_memory`, and `schedule_reminder`. Each run produces an `ExecutionReceipt` (id, decision_id, approver, timestamp, executor, result, result_hash = SHA-256). Unauthorized, denied, and non-allowlisted actions are refused and logged. Execution is idempotent.
3. **Tamper-evident audit log** (`audit_log.py`). Append-only JSONL with seq, prev_hash, and a SHA-256 hash per entry, plus a head anchor file. It logs mission changes, decisions (with assessment), council votes, authorizations, denials, executions, refusals, and trigger routing. `verify()` and the CLI detect edits, middle deletions or reordering, and tail truncation.
4. **Trigger worker** (`trigger_worker.py`). Consumes `trigger_queue.jsonl`, sends each event through the gate, auto-executes autonomous-allowed actions, and holds the rest for approval. A persisted cursor and in-flight decision map mean a restart, or a crash mid-event, never duplicates decisions or executions. It refuses to run if the queue was rewritten behind the cursor.
5. **MCP server** (`mcp_server.py`, official `mcp` SDK 2.3.0, stdio). Tools: propose_action, list_pending, authorize, deny, verify_audit. LangGraph/CrewAI integration is **not** built. See the design note `INTEGRATIONS_design_note_v0.5.md`.
6. **Dashboard crash fix.** `set_mission` validates its inputs and coerces a numeric priority to text, and the dashboard escapes `str(priority)`.
7. **Base44 instruction** at `BASE44_builder_instruction_v0.5.md` (needs the Builder plan or higher). No Base44 changes were made.

## Tested
- 34 tests pass: the 11 original v0.4 tests plus 23 new ones (6 Oracle with a mocked HTTP LLM server, 7 execution/approval, 4 audit tamper, 4 worker including restart and crash-resume, 1 mission coercion, 1 MCP stdio start + list_tools + call).
- Without the `mcp` package installed, 33 pass and the MCP test is skipped.

## Not verified
- **Live LLM use is untested.** No API key was available, and only a local mock server was used. Real-model JSON compliance, latency, and cost are unknown.
- The dashboard UI was not updated to show pending decisions or receipts (the engine API and MCP have them). There was no visual QA of the dashboard after the fix. The fix is covered by a unit test only.
- MCP was tested with the Python SDK client only, not Claude Desktop or Cursor. Approver identity over MCP is not authenticated.
- Audit anchoring is local. Someone with file access who rewrites both the log and the anchor is not detected.
- Windows `.ps1` launchers do not start the worker or MCP server yet.

## Homepage-safe wording
> PATIENCE (local prototype) routes every proposed AI action through a policy gate. Low-risk actions run automatically from a small allowlist. Risky ones wait for a person to approve that specific decision. Every decision, vote, approval, denial, and execution is written to a hash-chained, tamper-evident audit log with execution receipts. Scheduled triggers are processed by a worker that resumes after a restart. An optional LLM can power the assessment, with a rule-based fallback. It exposes an MCP server so MCP-capable clients can propose actions and request approvals.

Can say: "tamper-evident audit log (hash-chained)", "per-decision human approval", "approved actions execute from an allowlist with receipts", "MCP server (prototype)", "pluggable LLM assessment with rule-based fallback".
Avoid: "integrates with LangGraph/CrewAI", "AI council of models", "production-ready", "verified with GPT/Claude", "server-enforced in the web app" (Base44 isn't changed yet), "immutable audit trail".
