"""Off-host replication of the append-only, tamper-evident audit log (plan item C1).

Every audit.append() also ships the record line plus a *signed checkpoint* {seq, hash, ts}
to a replica sink. verify_replica() then compares the local log against the replica and
checks the checkpoint signature, so rewriting the local log (even with a recomputed hash
chain, .head and local checkpoint) is detected as long as the attacker cannot also write
the replica and does not hold the signing key. This raises the bar; it does not make the
log immutable.

Signing key (env only, never committed):
    PATIENCE_AUDIT_SIGNING_KEY = "hmac:<secret, >= 32 chars>"
                               | "ed25519:<base64 32-byte private seed>"   (needs `cryptography`)
    PATIENCE_AUDIT_VERIFY_KEY  = "ed25519:<base64 32-byte public key>"     (optional; lets a
                                 verifier check Ed25519 checkpoints without the private key)
Sink:
    PATIENCE_AUDIT_REPLICA_DIR      directory on another disk / host mount (NFS, SMB, sshfs)
    PATIENCE_AUDIT_REPLICA_REQUIRED "1" = audit.append raises if replication fails (fail closed);
                                    default: best effort, lag shows up in verify_replica()

Sink interface (implement for S3, a remote append API, etc.; see docs/audit-replication.md):
    class ReplicaSink(Protocol):
        def append_lines(self, lines: list[str]) -> None    # append-only; must never overwrite
        def read_lines(self) -> list[str]
        def put_checkpoint(self, blob: bytes) -> None       # latest signed checkpoint
        def get_checkpoint(self) -> Optional[bytes]

    python audit_replica.py verify     exit 0 if local log matches replica and signature
    python audit_replica.py sync       copy any records the replica is missing (backfill)
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Protocol

from filelock import FileLock


class ReplicationError(RuntimeError):
    pass


class ReplicaSink(Protocol):
    def append_lines(self, lines: List[str]) -> None: ...
    def read_lines(self) -> List[str]: ...
    def put_checkpoint(self, blob: bytes) -> None: ...
    def get_checkpoint(self) -> Optional[bytes]: ...


class DirectorySink:
    """Replica in a directory: audit.replica.jsonl (append-only) + checkpoint.json (atomic)."""

    def __init__(self, root):
        self.root = Path(root)
        self.log = self.root / "audit.replica.jsonl"
        self.cp = self.root / "checkpoint.json"

    def _lock(self):
        self.root.mkdir(parents=True, exist_ok=True)
        return FileLock(str(self.root / ".replica.lock"), timeout=30)

    def append_lines(self, lines):
        with self._lock():
            with open(self.log, "a", encoding="utf-8") as f:
                for ln in lines:
                    f.write(ln.rstrip("\n") + "\n")
                f.flush()
                os.fsync(f.fileno())

    def read_lines(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def put_checkpoint(self, blob):
        with self._lock():
            tmp = self.cp.with_name(self.cp.name + ".tmp")
            with open(tmp, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.cp)

    def get_checkpoint(self):
        return self.cp.read_bytes() if self.cp.exists() else None


_SINK_OVERRIDE: Optional[ReplicaSink] = None


def set_sink(sink: Optional[ReplicaSink]) -> None:
    """Install a custom sink (S3, remote API...). None = fall back to env configuration."""
    global _SINK_OVERRIDE
    _SINK_OVERRIDE = sink


def sink() -> Optional[ReplicaSink]:
    if _SINK_OVERRIDE is not None:
        return _SINK_OVERRIDE
    d = os.environ.get("PATIENCE_AUDIT_REPLICA_DIR")
    return DirectorySink(d) if d else None


# ---------- signing ----------
def _canon(cp: dict) -> bytes:
    return json.dumps({k: cp[k] for k in ("seq", "hash", "ts")}, sort_keys=True, separators=(",", ":")).encode()


def _key():
    raw = os.environ.get("PATIENCE_AUDIT_SIGNING_KEY", "")
    if not raw:
        return None
    alg, _, val = raw.partition(":")
    if alg == "hmac" and len(val) >= 32:
        return ("hmac", val.encode())
    if alg == "ed25519":
        return ("ed25519", base64.b64decode(val))
    raise ReplicationError("PATIENCE_AUDIT_SIGNING_KEY must be 'hmac:<>=32 chars>' or 'ed25519:<base64 seed>'")


def sign(cp: dict) -> dict:
    k = _key()
    if k is None:
        raise ReplicationError("no signing key configured (PATIENCE_AUDIT_SIGNING_KEY)")
    alg, secret = k
    if alg == "hmac":
        sig = hmac.new(secret, _canon(cp), hashlib.sha256).hexdigest()
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sig = base64.b64encode(Ed25519PrivateKey.from_private_bytes(secret).sign(_canon(cp))).decode()
    return {**cp, "alg": alg, "sig": sig}


def check_signature(cp: dict) -> bool:
    alg = cp.get("alg")
    try:
        if alg == "hmac":
            k = _key()
            if not k or k[0] != "hmac":
                return False
            want = hmac.new(k[1], _canon(cp), hashlib.sha256).hexdigest()
            return hmac.compare_digest(want, str(cp.get("sig", "")))
        if alg == "ed25519":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
            vk = os.environ.get("PATIENCE_AUDIT_VERIFY_KEY", "")
            if vk.startswith("ed25519:"):
                pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(vk.split(":", 1)[1]))
            else:
                k = _key()
                if not k or k[0] != "ed25519":
                    return False
                pub = Ed25519PrivateKey.from_private_bytes(k[1]).public_key()
            pub.verify(base64.b64decode(cp["sig"]), _canon(cp))
            return True
    except Exception:  # noqa: BLE001 - any parse/verify failure = bad signature
        return False
    return False


# ---------- replication ----------
def replicate(rec: dict, line: str) -> None:
    """Called by audit.append (under the log lock) after the local write. No-op if no sink."""
    s = sink()
    if s is None:
        return
    try:
        s.append_lines([line])
        s.put_checkpoint(json.dumps(sign({"seq": rec["seq"], "hash": rec["hash"], "ts": rec["ts"]})).encode())
    except Exception as e:  # noqa: BLE001
        if os.environ.get("PATIENCE_AUDIT_REPLICA_REQUIRED") == "1":
            raise ReplicationError(f"audit replication failed: {type(e).__name__}") from e


def sync() -> int:
    """Backfill records the replica is missing; returns how many lines were shipped."""
    import audit
    s = sink()
    if s is None:
        raise ReplicationError("no replica sink configured")
    local = audit.path().read_text(encoding="utf-8").splitlines() if audit.path().exists() else []
    remote = s.read_lines()
    if local[:len(remote)] != remote:
        raise ReplicationError("replica and local log diverge; refusing to sync (run verify)")
    missing = local[len(remote):]
    if missing:
        s.append_lines(missing)
        last = json.loads(missing[-1])
        s.put_checkpoint(json.dumps(sign({"seq": last["seq"], "hash": last["hash"], "ts": last["ts"]})).encode())
    return len(missing)


def verify_replica() -> dict:
    """{"ok", "local_records", "replica_records", "lag", "error", "bad_seq"}"""
    import audit
    out = {"ok": False, "local_records": 0, "replica_records": 0, "lag": 0, "error": None, "bad_seq": None}
    s = sink()
    if s is None:
        out["error"] = "no replica sink configured"
        return out
    v = audit.verify()
    out["local_records"] = v["records"]
    local = audit.path().read_text(encoding="utf-8").splitlines() if audit.path().exists() else []
    remote = s.read_lines()
    out["replica_records"] = len(remote)
    blob = s.get_checkpoint()
    if remote and blob is None:
        out["error"] = "replica has records but no signed checkpoint"
        return out
    if blob is not None:
        try:
            cp = json.loads(blob)
        except ValueError:
            out["error"] = "replica checkpoint unreadable"
            return out
        if not check_signature(cp):
            out["error"] = "replica checkpoint signature invalid"
            return out
        if cp["seq"] > len(remote):
            out["error"] = "replica log shorter than its signed checkpoint"
            return out
        if cp["seq"] and json.loads(remote[cp["seq"] - 1]).get("hash") != cp["hash"]:
            out["error"] = "replica log disagrees with its signed checkpoint"
            out["bad_seq"] = cp["seq"]
            return out
    for i, (a, b) in enumerate(zip(local, remote), 1):
        if a != b:
            out["error"] = f"local log differs from replica at seq {i} (rewrite)"
            out["bad_seq"] = i
            return out
    if len(local) < len(remote):
        out["error"] = f"local log is missing {len(remote) - len(local)} record(s) present in the replica"
        out["bad_seq"] = len(local) + 1
        return out
    if not v["ok"]:
        out["error"] = f"local chain: {v['error']}"
        out["bad_seq"] = v.get("bad_seq")
        return out
    out["lag"] = len(local) - len(remote)
    out["ok"] = True
    return out


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "verify"
    if cmd == "sync":
        print(f"shipped {sync()} record(s)")
        return 0
    r = verify_replica()
    print(json.dumps(r, indent=2))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
