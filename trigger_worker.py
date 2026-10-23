"""Trigger worker (v0.5): consumes trigger_queue.jsonl, routes each event through
the PATIENCE gate, auto-executes autonomous-allowed actions, holds the rest for
per-decision approval, and resumes from a persisted cursor after restart.

Exactly-once per queue line: the cursor (line count + hash of the last consumed
line) is saved after each event, and each event's decision id is recorded in the
checkpoint *before* execution, so a crash mid-event re-uses the same decision
(execution itself is idempotent per decision id).
"""
from __future__ import annotations
import hashlib
import json
import os
import time
from pathlib import Path
from engine import Patience
from executor import ExecutionRefused


def default_plan(event):
    """Map a trigger to (observation text, proposed allowlisted action)."""
    t, p = event.get("trigger_type"), event.get("payload") or {}
    if event.get("proposed"):
        return f"Trigger {t}: {json.dumps(p, sort_keys=True)}", event["proposed"]
    if t == "task_due":
        title = p.get("title", "task")
        return (f"Summarize reminder: task '{title}' is due",
                {"executor": "write_note", "params": {"filename": f"reminder-{str(p.get('id','x'))[:8]}.md",
                                                     "text": f"# Due: {title}\nDue at: {p.get('due_at')}\n"}})
    if t == "blocked_action":
        return (f"Log that action {p.get('action')} is waiting for human authorization",
                {"executor": "append_memory", "params": {"kind": "trigger", "content": f"Blocked: {p.get('action')}"}})
    if t == "checkpoint":
        return ("Summarize checkpoint reached",
                {"executor": "append_memory", "params": {"kind": "checkpoint", "content": f"Checkpoint {p.get('checkpoint')}"}})
    return (f"Summarize trigger {t}",
            {"executor": "append_memory", "params": {"kind": "trigger", "content": f"{t}: {json.dumps(p, sort_keys=True)[:500]}"}})


class TriggerWorker:
    def __init__(self, state_path="patience_state.json", queue_path="trigger_queue.jsonl",
                 checkpoint_path=None, patience=None):
        self.queue_path = Path(queue_path)
        self.checkpoint_path = Path(checkpoint_path or self.queue_path.with_name("trigger_worker_checkpoint.json"))
        self.p = patience or Patience(state_path)
        self.ckpt = self._load()

    def _load(self):
        if self.checkpoint_path.exists():
            return json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        return {"cursor": 0, "last_line_sha": None, "in_flight": {}}

    def _save(self):
        tmp = self.checkpoint_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.ckpt, indent=2), encoding="utf-8")
        os.replace(tmp, self.checkpoint_path)

    def _lines(self):
        if not self.queue_path.exists():
            return []
        return [l for l in self.queue_path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def process_once(self, crash_after_decision=False):
        lines = self._lines()
        cur = self.ckpt["cursor"]
        if cur and (cur > len(lines) or hashlib.sha256(lines[cur - 1].encode()).hexdigest() != self.ckpt["last_line_sha"]):
            raise RuntimeError("trigger queue was rewritten/truncated behind the worker cursor; refusing to guess")
        results = []
        for idx in range(cur, len(lines)):
            line = lines[idx]
            sha = hashlib.sha256(line.encode()).hexdigest()
            event = json.loads(line)
            key = f"{idx}:{sha}"
            did = self.ckpt["in_flight"].get(key)
            if did is None:
                text, proposed = default_plan(event)
                r = self.p.cycle(text, source=f"trigger:{event.get('trigger_type')}", reliability=.9, proposed=proposed)
                did = r["decision_id"]
                self.ckpt["in_flight"][key] = did
                self._save()
                self.p.audit.append("trigger_routed", {"queue_line": idx + 1, "trigger_type": event.get("trigger_type"),
                                                       "decision_id": did})
                if crash_after_decision:
                    raise SystemExit("simulated crash")
            d = self.p.get_decision(did)
            outcome = "held_for_approval"
            if d.get("status") != "pending_authorization":
                try:
                    receipt = self.p.execute(did, approver="policy:autonomous")
                    outcome = "already_executed" if receipt.get("already_executed") else "executed"
                except ExecutionRefused as e:
                    outcome = f"refused: {e}"
            results.append({"line": idx + 1, "trigger_type": event.get("trigger_type"),
                            "decision_id": did, "outcome": outcome})
            self.ckpt.update(cursor=idx + 1, last_line_sha=sha)
            self.ckpt["in_flight"].pop(key, None)
            self._save()
        return results

    def run_forever(self, poll_seconds=15):
        while True:
            for r in self.process_once():
                print("WORKER:", r)
            time.sleep(max(2, poll_seconds))


if __name__ == "__main__":
    import argparse
    base = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    w = TriggerWorker(base / "patience_state.json", base / "trigger_queue.jsonl")
    print(json.dumps(w.process_once(), indent=2)) if a.once else w.run_forever()
