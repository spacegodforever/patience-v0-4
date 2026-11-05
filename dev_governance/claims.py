"""Single-use, request-bound execution claim tokens (RT-10).

The gate mints a token only after it has atomically claimed an approved request. A token is an
HMAC-SHA256 over (request_id, payload_hash, expiry, nonce) with a short TTL. Any adapter marked
`live = True` must call `verify_claim(ctx, action_payload_hash)` immediately before I/O; a missing,
expired, reused, forged, or mismatched token is refused. This makes the gate the choke point:
constructing a live adapter and calling execute() directly does nothing without a fresh claim.

Secret: PATIENCE_CLAIM_SECRET (>= 32 chars) or a random per-process secret (tokens then do not
survive a restart, which is fine - they live seconds). Used nonces are kept in-process.
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
_PROCESS_SECRET = secrets.token_bytes(32)
_used: dict[str, float] = {}
_lock = threading.Lock()


class ClaimError(Exception):
    pass


def _secret() -> bytes:
    s = os.environ.get("PATIENCE_CLAIM_SECRET", "")
    return s.encode() if len(s) >= 32 else _PROCESS_SECRET


def _sig(rid: str, h: str, exp: int, nonce: str) -> str:
    return hmac.new(_secret(), f"v1|{rid}|{h}|{exp}|{nonce}".encode(), hashlib.sha256).hexdigest()


def mint(rid: str, payload_hash: str, clock: Callable[[], float] = time.time,
         ttl: int = CLAIM_TTL_SECONDS) -> str:
    exp, nonce = int(clock()) + int(ttl), secrets.token_hex(12)
    return f"v1.{rid}.{payload_hash}.{exp}.{nonce}.{_sig(rid, payload_hash, exp, nonce)}"


def verify(token: str, rid: str, payload_hash: str, clock: Callable[[], float] = time.time) -> None:
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
    now = clock()
    if now > exp:
        raise ClaimError("execution claim token expired")
    with _lock:
        for n, e in list(_used.items()):
            if e < now - 3600:
                del _used[n]
        if nonce in _used:
            raise ClaimError("execution claim token already used")
        _used[nonce] = exp


def verify_claim(ctx: dict, payload_hash: str, clock: Callable[[], float] = time.time) -> None:
    """For live adapters: check ctx['claim_token'] against ctx['request_id'] and the payload hash
    the adapter computes itself from what it is about to send."""
    verify((ctx or {}).get("claim_token"), (ctx or {}).get("request_id", ""), payload_hash, clock)
