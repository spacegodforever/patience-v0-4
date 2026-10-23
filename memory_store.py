import json
import os
import tempfile
from pathlib import Path
from dataclasses import asdict
from models import PatienceState, now_iso

class MemoryStore:
    def __init__(self, path="patience_state.json"):
        self.path = Path(path)

    def save(self, state: PatienceState) -> None:
        state.last_updated = now_iso()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=self.path.parent, suffix='.tmp')
        try:
            with os.fdopen(handle, 'w', encoding='utf-8') as stream:
                json.dump(asdict(state), stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            Path(temporary).unlink(missing_ok=True)

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
