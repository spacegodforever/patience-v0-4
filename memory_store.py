import json
from pathlib import Path
from dataclasses import asdict
from models import PatienceState, now_iso

class MemoryStore:
    def __init__(self, path="patience_state.json"):
        self.path = Path(path)

    def save(self, state: PatienceState) -> None:
        state.last_updated = now_iso()
        self.path.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")

    def load(self) -> PatienceState:
        if not self.path.exists():
            return PatienceState()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        allowed = PatienceState.__dataclass_fields__.keys()
        return PatienceState(**{k:v for k,v in data.items() if k in allowed})

    def record_memory(self, state, kind, content, confidence):
        state.memory.append({
            "kind": kind,
            "content": content,
            "confidence": confidence,
            "timestamp": now_iso()
        })
