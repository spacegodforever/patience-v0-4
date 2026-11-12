"""File-permission hardening for local state files (RT-09)."""
from __future__ import annotations
import os
import stat

SUFFIXES = ("", "-wal", "-shm", "-journal")


def secure_file(path: str) -> list:
    """chmod 0600 the file and its sqlite sidecars if they exist (new AND pre-existing files).
    Returns the paths whose mode was tightened. Best-effort on filesystems without POSIX modes."""
    fixed = []
    if not path or path == ":memory:":
        return fixed
    for s in SUFFIXES:
        p = path + s
        try:
            mode = stat.S_IMODE(os.stat(p).st_mode)
        except OSError:
            continue
        if mode & 0o077:
            try:
                os.chmod(p, 0o600)
                fixed.append(p)
            except OSError:
                pass
    return fixed
