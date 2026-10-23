# PATIENCE v0.4 local trigger loop

State → trigger agent → local JSONL queue → manual prompt export.

The agent watches due tasks, blocked actions, high uncertainty, due timestamp
checkpoints, and idle intervals. It requests attention only. It never calls a
model, authorizes an action, or executes a tool. Local council members are
deterministic rules rather than independent LLMs. Confidence is a heuristic.

Authorization is distinct from execution and verification. This version has
no executor and cannot verify external results or wake a ChatGPT conversation.

Exactly one dashboard writer and one agent are supported. State writes are
atomic, but concurrent dashboard sessions can overwrite each other's updates.
Queue deduplication covers identical payloads across restarts while the queue
is retained. Resolved and then recurring identical conditions need an explicit
incident identity before event-driven consumers are added. The bridge exports
the latest prompt without acknowledging or consuming it. Queue/state/prompt
files may contain your observations; keep them local and inspect before sharing.
