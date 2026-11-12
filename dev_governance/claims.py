"""Single-use, request-bound execution claim tokens (RT-10).

The gate mints a token only after it has atomically claimed an approved request. A token is an
HMAC-SHA256 over (request_id, payload_hash, expiry, nonce) with a short TTL. Any adapter marked
`live = True` must call `verify_claim(ctx, action_payload_hash)` immediately before I/O; a missing,
expired, reused, forged, or mismatched token is refused. This makes the gate the choke point:
constructing a live adapter and calling execute() directly does nothing without a fresh claim.

Secret: PATIENCE_CLAIM_SECRET (>= 32 chars) or a random per-process secret (tokens then do not
survive a restart, which is fine - they live seconds). Used nonces are kept in-process AND, when the
gate uses a SQLite store, in its shared `dev_claim_nonces` table so other workers cannot reuse them.
"""
from __future__ import annotations
import hashlib
import hmac
import os
import secrets
import threading
import time
from typing import Callable

CLAIM_TTL_SECONDS = 60
MAX_SKEW_SECONDS = 30
_PROCESS_SECRET = secrets.token_bytes(32)
_FILE_SECRET: bytes | None = None


def skew_seconds() -> int:
    """RT-08: tolerated clock skew between workers (PATIENCE_CLAIM_SKEW, default 5, clamped 0..30)."""
    try:
        v = int(os.environ.get("PATIENCE_CLAIM_SKEW", "5"))
    except ValueError:
        v = 5
    return max(0, min(MAX_SKEW_SECONDS, v))


def use_secret_file(path: str) -> None:
    """Shared-secret fallback for multi-worker deployments without PATIENCE_CLAIM_SECRET:
    a 0600 key file next to the shared DB (created once, atomically)."""
    global _FILE_SECRET
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    from .fsperm import secure_file
    secure_file(path)
    with open(path) as f:
        key = f.read().strip()
    if len(key) >= 32:
        _FILE_SECRET = key.encode()
_used: dict[str, float] = {}
_lock = threading.Lock()


class ClaimError(Exception):
    pass


def _secret() -> bytes:
    s = os.environ.get("PATIENCE_CLAIM_SECRET", "")
    if len(s) >= 32:
        return s.encode()
    return _FILE_SECRET or _PROCESS_SECRET


def sign_fields(kind: str, *fields) -> str:
    """HMAC over arbitrary fields, e.g. a request's expiry (RT-08)."""
    msg = "|".join([kind] + [repr(f) for f in fields]).encode()
    return hmac.new(_secret(), msg, hashlib.sha256).hexdigest()


def check_fields(sig: str, kind: str, *fields) -> bool:
    return isinstance(sig, str) and hmac.compare_digest(sig, sign_fields(kind, *fields))


def _sig(rid: str, h: str, exp: int, nonce: str) -> str:
    return hmac.new(_secret(), f"v1|{rid}|{h}|{exp}|{nonce}".encode(), hashlib.sha256).hexdigest()


def mint(rid: str, payload_hash: str, clock: Callable[[], float] = time.time,
         ttl: int = CLAIM_TTL_SECONDS) -> str:
    exp, nonce = int(clock()) + int(ttl), secrets.token_hex(12)
    return f"v1.{rid}.{payload_hash}.{exp}.{nonce}.{_sig(rid, payload_hash, exp, nonce)}"


def verify(token: str, rid: str, payload_hash: str, clock: Callable[[], float] = time.time,
           nonce_db: str | None = None) -> None:
    """Raise ClaimError unless token is valid for exactly this request + payload; consumes it."""
    if not token or not isinstance(token, str):
        raise ClaimError("missing execution claim token")
    parts = token.split(".")
    if len(parts) != 6 or parts[0] != "v1":
        raise ClaimError("malformed execution claim token")
    _, t_rid, t_h, t_exp, nonce, sig = parts
    try:
        exp = int(t_exp)
    except ValueError:
        raise ClaimError("malformed execution claim token")
    if not hmac.compare_digest(sig, _sig(t_rid, t_h, exp, nonce)):
        raise ClaimError("execution claim token signature invalid")
    if not (hmac.compare_digest(t_rid, rid) and hmac.compare_digest(t_h, payload_hash)):
        raise ClaimError("execution claim token is for a different request or payload")
    now, skew = clock(), skew_seconds()
    if now > exp + skew:  # RT-08: tolerate small clock skew between workers
        raise ClaimError("execution claim token expired")
    if exp > now + CLAIM_TTL_SECONDS + skew:
        raise ClaimError("execution claim token expiry is too far in the future")
    with _lock:
        for n, e in list(_used.items()):
            if e < now - 3600:
                del _used[n]
        if nonce in _used:
            raise ClaimError("execution claim token already used")
        if nonce_db:
            _burn_shared(nonce_db, nonce, exp, now)  # raises if another worker already used it
        _used[nonce] = exp


def _burn_shared(path: str, nonce: str, exp: int, now: float) -> None:
    """Record a used nonce in the shared SQLite DB so no other worker/process can reuse it.
    INSERT on a PRIMARY KEY is atomic across processes; a DB error fails closed."""
    import sqlite3
    try:
        c = sqlite3.connect(path, timeout=30, isolation_level=None)
        try:
            c.execute("CREATE TABLE IF NOT EXISTS dev_claim_nonces (nonce TEXT PRIMARY KEY, exp REAL NOT NULL)")
            c.execute("BEGIN IMMEDIATE")
            c.execute("DELETE FROM dev_claim_nonces WHERE exp < ?", (now - 3600,))
            c.execute("INSERT INTO dev_claim_nonces (nonce, exp) VALUES (?, ?)", (nonce, exp))
            c.execute("COMMIT")
        finally:
            c.close()
    except sqlite3.IntegrityError:
        raise ClaimError("execution claim token already used")
    except sqlite3.Error as e:
        raise ClaimError(f"claim nonce store unavailable ({type(e).__name__}); refusing") from None


def verify_claim(ctx: dict, payload_hash: str, clock: Callable[[], float] = time.time) -> None:
    """For live adapters: check ctx['claim_token'] against ctx['request_id'] and the payload hash
    the adapter computes itself from what it is about to send."""
    verify((ctx or {}).get("claim_token"), (ctx or {}).get("request_id", ""), payload_hash, clock,
           nonce_db=(ctx or {}).get("claim_nonce_db") or os.environ.get("PATIENCE_CLAIM_NONCE_DB"))
