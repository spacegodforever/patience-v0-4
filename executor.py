"""Allowlisted executors. Only these actions can ever run; anything else is refused."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict
from models import Task, now_iso
from scheduler import parse_due


class ExecutionRefused(Exception):
    pass


def result_hash(result: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest()


class ExecutorRegistry:
    def __init__(self, sandbox_dir):
        self.sandbox = Path(sandbox_dir).resolve()
        self._fns: Dict[str, Callable] = {
            "write_note": self.write_note,
            "append_memory": self.append_memory,
            "schedule_reminder": self.schedule_reminder,
        }

    @property
    def allowlist(self):
        return sorted(self._fns)

    def run(self, name: str, params: Dict[str, Any], patience) -> Dict[str, Any]:
        if name not in self._fns:
            raise ExecutionRefused(f"executor '{name}' is not allowlisted")
        if not isinstance(params, dict):
            raise ExecutionRefused("params must be an object")
        return self._fns[name](params, patience)

    def write_note(self, params, patience):
        name = str(params.get("filename", "note.md"))
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", name) or name.startswith("."):
            raise ExecutionRefused("filename must be a plain name (letters, digits, . _ -)")
        text = str(params.get("text", ""))
        if len(text) > 100_000:
            raise ExecutionRefused("note too large")
        target = (self.sandbox / name).resolve()
        if target.parent != self.sandbox:
            raise ExecutionRefused("path escapes sandbox")
        self.sandbox.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return {"path": str(target), "bytes": len(text.encode("utf-8")),
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}

    def append_memory(self, params, patience):
        content = str(params.get("content", "")).strip()
        if not content:
            raise ExecutionRefused("memory content required")
        entry = {"kind": str(params.get("kind", "note")), "content": content[:2000],
                 "confidence": 1.0, "timestamp": now_iso()}
        patience.state.memory.append(entry)
        return {"memory_index": len(patience.state.memory) - 1, "entry": entry}

    def schedule_reminder(self, params, patience):
        title = str(params.get("title", "")).strip()
        due = params.get("due_at")
        if not title or not due:
            raise ExecutionRefused("title and due_at required")
        try:
            parse_due(due)
        except ValueError as e:
            raise ExecutionRefused(str(e)) from e
        task = Task(title=title, due_at=due, trigger="reminder")
        patience.time.add_task(patience.state, task)
        patience.state.next_checkpoint = patience.time.next_checkpoint(patience.state)
        return {"task_id": task.id, "title": title, "due_at": due}
