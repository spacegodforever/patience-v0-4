# PATIENCE v0.5 — local command dashboard, governed executor, trigger worker, MCP server

Python 3.11+ on Windows. This project is separate from the React PATIENCE Core app.

## Setup and launch

```powershell
Set-Location "C:\Users\matth\Documents\patience_v0_4"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup_patience.ps1
.\run_patience.ps1
```

Open http://127.0.0.1:8504. Run `stop_patience.ps1` to stop the recorded
processes. Background helpers are hidden; output and errors live in `runtime/`.
The launcher checks dashboard health and preserves unrelated listeners.
After setup the launcher does not install dependencies or change system policy.
For another machine, extract the project and change the folder path above.

## Use

Inject an observation to inspect local assessments, dissent, recommendations,
and authorization requirements. Add a task with a timezone-aware ISO timestamp.
The agent checks state every 30 seconds and queues due-task, blocked-action,
high-uncertainty, due-checkpoint, and 30-minute idle reassessment prompts.

```powershell
.\.venv\Scripts\python.exe .\trigger_bridge.py
```

This exports the latest queued prompt to `latest_trigger_prompt.txt` without
acknowledging it or sending it anywhere. Queue records survive agent restarts.
Plain-language checkpoints are not interpreted as scheduled deadlines.

## Boundaries

No external model, Calendar, Gmail, or action tool is connected. The council is
three local deterministic rule adapters, and scores are heuristics rather than
calibrated probabilities. Authorization does not execute or verify an action.
ChatGPT cannot be awakened by this local queue. See AGENT_LOOP.md for limitations.

Use one dashboard browser session and one agent. State saves are atomic, but
concurrent dashboard writers are not supported. Queue records include observation
text; inspect them before sharing. Streamlit usage statistics are disabled and
the dashboard listens on loopback only.

Streamlit is the supplied UI dependency (Apache-2.0); it has a substantial
transitive dependency set. requirements-lock.txt records the tested environment.
It can be removed by replacing dashboard.py; the core and trigger tests use only
the Python standard library. Recreate the environment to update dependencies,
then rerun the checks rather than silently updating during launch.

## Checks

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip check
```

The source ZIP excludes the environment, live state, queue, prompt exports, and
runtime logs. It includes source, tests, launch/stop scripts, configuration, and
the dependency lock. Browser rendering and interaction need separate visual QA.

## v0.5 additions (see ../PATIENCE_v0.5_changelog.md)

Commands below are for Linux/macOS; on Windows use `.\.venv\Scripts\python.exe`.

**LLM Oracle (optional).** Set `PATIENCE_LLM_BASE_URL` (e.g. `https://api.openai.com/v1`),
`PATIENCE_LLM_API_KEY`, `PATIENCE_LLM_MODEL`, and optionally `PATIENCE_LLM_TIMEOUT`. Any
OpenAI-compatible `/chat/completions` endpoint works. If they are unset, or the call or
validation fails, the heuristic Oracle runs. Each assessment and audit entry records
`oracle_path` (`llm` or `heuristic`). The model can never lower consequence below the rule score.

**Per-decision approvals and execution.**
```python
from engine import Patience
p = Patience("patience_state.json")
d = p.propose("publish irreversible summary", "write_note", {"filename": "summary.md", "text": "..."})["decision_id"]
p.pending(); p.authorize_decision(d, "matthew"); p.execute(d)   # -> ExecutionReceipt
```
Allowlisted executors: `write_note` (only into `./sandbox/`), `append_memory`, `schedule_reminder`.
Anything else is refused. Running `execute` again for the same decision returns the same receipt and does nothing new.
The dashboard's old "authorize action type" button still only records an authorization. It does not execute.

**Audit log.** `audit_log.jsonl` is append-only and hash-chained, with the head anchor in `audit_log.jsonl.head.json`.
Verify with `python audit_log.py [path]` (exit code 1 if it was tampered with).

**Trigger worker.** `python agent_daemon.py` writes triggers. `python trigger_worker.py --once` (or no flag to loop)
runs each trigger through the gate, auto-executes autonomous actions, and holds the rest in `p.pending()`.
It resumes from `trigger_worker_checkpoint.json` and does not redo work.

**MCP server (stdio).** `pip install -r requirements-mcp.txt` (needs Python 3.10+), then `python mcp_server.py`.
Tools: `propose_action`, `list_pending`, `authorize`, `deny`, `verify_audit`. Example client config:
`{"command": "python", "args": ["<path>/mcp_server.py"], "env": {"PATIENCE_STATE": "<path>/patience_state.json"}}`.
Approver names sent over MCP are not authenticated. Only connect clients you control.

**Tests.** `python -m unittest discover -s tests -v` runs 34 tests. The MCP test is skipped if `mcp` is not installed.
