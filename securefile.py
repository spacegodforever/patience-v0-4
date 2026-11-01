"""Atomic, owner-only writes for secret-bearing files (approvers.yaml, agents.yaml).

The temp file is created by mkstemp (mode 0600 from creation on POSIX), written, fsynced,
then os.replace()d over the target, so a crash mid-write leaves the old file intact.
On Windows the POSIX mode bits are not enforced; NTFS ACLs apply instead.
"""
from __future__ import annotations
import os
import tempfile
from pathlib import Path


def write_secret(target, text: str) -> None:
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + target.name + ".", suffix=".tmp", dir=str(target.parent))
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
