# Design note: LangGraph and CrewAI adapters (not built in v0.5)

Both adapters stay thin. PATIENCE remains the policy point, and the framework only *proposes* actions. The public surface they wrap is already in `engine.Patience`: `propose(content, executor, params)` → `decision_id`; `pending()`; `authorize_decision(id, approver)`; `execute(id)` → ExecutionReceipt or `ExecutionRefused`; `verify_audit()`. Any MCP-capable client can use the same surface today via `mcp_server.py`.

## LangGraph (`patience_langgraph.py`, ~80 lines)
- Add a `patience_gate` node before every tool-executing node. It calls `propose()` with the planned tool call mapped to an allowlisted executor, then routes:
  - executed/autonomous → continue to the next node with the receipt in state.
  - pending → call `langgraph.types.interrupt({"decision_id": ...})`. The graph checkpointer persists the thread. On resume, `Command(resume={"approver": ...})` → `authorize_decision` + `execute`.
- Tools stay unbound from the LLM's direct execution: the tool node only runs `Patience.execute`.
- Risk: LangGraph API churn (interrupt/Command). Pin the version and test with an in-memory checkpointer.

## CrewAI (`patience_crewai.py`, ~60 lines)
- Wrap each allowed tool as a `BaseTool` subclass whose `_run` calls `propose()` and then `execute()`. If the action is held, it returns "PENDING_APPROVAL <decision_id>" instead of acting, so the agent cannot bypass the gate by re-asking.
- Use CrewAI's `human_input`/task callback, or a separate approval CLI, to call `authorize_decision`. The crew is re-kicked off with the decision id.
- Register no non-PATIENCE tools on agents that can act externally.

## Common
- Map framework tool names → PATIENCE executors in one table. Unknown tools are refused (already enforced by `ExecutorRegistry`).
- Approver identity must come from the host app's auth, not from model output.
