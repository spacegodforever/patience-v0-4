"""Small shared helpers: errors, hashing, time, audit."""
from __future__ import annotations
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import audit as _audit


class IntelError(Exception):
    def __init__(self, status: int, message: str, code: str = "error"):
        super().__init__(message)
        self.status, self.message, self.code = status, message, code


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def canon(o: Any) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def parse_time(s: Any) -> Optional[datetime]:
    """ISO-8601 date or datetime -> aware UTC datetime. Naive values are taken as UTC. None on failure."""
    if not isinstance(s, str) or not (4 <= len(s.strip()) <= 40):
        return None
    t = s.strip().replace("Z", "+00:00").replace("z", "+00:00")
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        return None
    return d.astimezone(timezone.utc) if d.tzinfo else d.replace(tzinfo=timezone.utc)


def audit_required(event: str, actor: Optional[str], **data) -> None:
    """Audit write that must succeed: failure raises 503 so the surrounding transaction rolls back."""
    try:
        _audit.append(event, actor, **data)
    except Exception:
        raise IntelError(503, "audit log unavailable; refused (fail closed)", "audit_unavailable")


Clock = Callable[[], float]
