"""Append-only, hash-chained JSONL audit log (PATIENCE v0.5).

Each line: {"seq", "timestamp", "event", "data", "prev_hash", "hash"} where
hash = SHA-256 of the canonical JSON of every other field. Editing any entry,
deleting or reordering a middle entry breaks the chain. Truncating the tail is
detected by comparing against the head anchor file (<log>.head.json), which is
rewritten after every append. An attacker who rewrites both the log and the
anchor consistently is NOT detected; ship the head hash off-box for that.
"""
from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def entry_hash(entry: Dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.head_path = self.path.with_name(self.path.name + ".head.json")

    def _last(self) -> Tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS
        e = json.loads(last)
        return int(e["seq"]), e["hash"]

    def append(self, event: str, data: Dict[str, Any]) -> Dict[str, Any]:
        seq, prev = self._last()
        entry = {
            "seq": seq + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": data,
            "prev_hash": prev,
        }
        entry["hash"] = entry_hash(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(_canonical(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        tmp = self.head_path.with_suffix(".tmp")
        tmp.write_text(_canonical({"seq": entry["seq"], "hash": entry["hash"]}), encoding="utf-8")
        os.replace(tmp, self.head_path)
        return entry

    def entries(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def verify(self) -> Dict[str, Any]:
        return verify(self.path)


def verify(path) -> Dict[str, Any]:
    """Return {"ok": bool, "entries": n, "errors": [...]}."""
    path = Path(path)
    head_path = path.with_name(path.name + ".head.json")
    errors: List[str] = []
    prev, expected_seq, n = GENESIS, 1, 0
    if path.exists():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            n += 1
            try:
                e = json.loads(line)
            except ValueError:
                errors.append(f"line {lineno}: not valid JSON")
                prev = None
                continue
            if e.get("seq") != expected_seq:
                errors.append(f"line {lineno}: seq {e.get('seq')} != expected {expected_seq} (deleted/reordered entry)")
            if prev is not None and e.get("prev_hash") != prev:
                errors.append(f"line {lineno}: prev_hash mismatch (chain broken)")
            if entry_hash(e) != e.get("hash"):
                errors.append(f"line {lineno}: hash mismatch (entry edited)")
            prev = e.get("hash")
            expected_seq = (e.get("seq") or expected_seq) + 1
    if head_path.exists():
        head = json.loads(head_path.read_text(encoding="utf-8"))
        if head.get("hash") != (prev if n else None) or head.get("seq") != expected_seq - 1:
            errors.append(f"head anchor mismatch: anchor seq {head.get('seq')} vs log seq {expected_seq - 1} (tail truncated or rewritten)")
    elif n:
        errors.append("head anchor file missing")
    return {"ok": not errors, "entries": n, "errors": errors}


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent / "audit_log.jsonl")
    result = verify(target)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["ok"] else 1)
