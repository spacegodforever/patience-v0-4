"""Audit-and-commit for PATIENCE state (F3).

    with state_txn(p):            # holds the state lock for the whole check-and-decide
        ...mutate p.state...; p.memory_store.save(p.state)
        audited("event", actor, **data)   # last step; on failure the prior state file is restored

The audit append is the final step inside the lock. If it fails, the state file is put back
exactly as it was before the transaction, so a failed audit leaves no committed write. A crash
between the save and the append can still leave a write without its audit record; `reconcile`
remains the tool for that case. The audit log is tamper-evident, not immutable.
"""
from __future__ import annotations
import os
import tempfile
from contextlib import contextmanager

import audit


class AuditFailed(Exception):
    """The audit log could not be written; the surrounding state change was rolled back."""


def _restore(path, before):
    if before is None:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        return
    fd, tmp = tempfile.mkstemp(dir=str(path.parent) or ".", prefix=".patience_restore_", suffix=".tmp")
    with os.fdopen(fd, "wb") as f:
        f.write(before)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


@contextmanager
def state_txn(p):
    store = p.memory_store
    with store.locked():
        before = store.path.read_bytes() if store.path.exists() else None
        try:
            yield
        except BaseException:
            _restore(store.path, before)
            p.refresh()
            raise


def audited(event, actor=None, **data):
    try:
        return audit.append(event, actor, **data)
    except Exception as e:  # noqa: BLE001 - any failure to record refuses the change
        raise AuditFailed(f"audit log unavailable ({type(e).__name__})") from e
