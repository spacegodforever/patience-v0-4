"""Permit format and verification (Ed25519). Pure: depends only on the stdlib and `cryptography`.

Wire format:  pp1.<kid>.<claims_b64url>.<signature_b64url>
  kid         first 16 hex chars of sha256(raw public key); selects the verification key
  claims      canonical JSON object (see Permit)
  signature   Ed25519 over the ASCII bytes  "pp1." + kid + "." + claims_b64url
              (the version tag and kid are inside the signed bytes)

The verifier holds PUBLIC keys only. It cannot mint permits. Every failure raises PermitRejected with
a stable reason code; there is no "soft" outcome.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

VERSION_TAG = "pp1"
DEFAULT_TTL_SECONDS = 300      # 5 minutes
MAX_TTL_SECONDS = 900          # issuer clamp; a gateway may enforce less
DEFAULT_SKEW_SECONDS = 5
MAX_TOKEN_CHARS = 4096

REASONS = (
    "missing_permit", "malformed_permit", "malformed_input", "unknown_key_id", "bad_signature",
    "expired", "not_yet_valid", "ttl_exceeds_max", "payload_mismatch", "wrong_agent", "wrong_action",
    "unsupported_action", "invalid_payload", "replayed", "kill_switch", "verifier_error",
    "audit_unavailable", "payment_failed",
)

_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
_KID = re.compile(r"^[0-9a-f]{16}$")


class PermitRejected(Exception):
    def __init__(self, code: str, detail: str = ""):
        assert code in REASONS, code
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code, self.detail = code, detail


def canonical_json(obj: Any) -> str:
    """Same canonical form as dev_governance.gate.canonical_json (a test pins the equivalence)."""
    def check(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if not isinstance(k, str):
                    raise PermitRejected("malformed_input", "payload keys must be strings")
                check(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                check(v)
        elif o is None or isinstance(o, (str, bool, int, float)):
            pass
        else:
            raise PermitRejected("malformed_input", "payload contains a non-JSON value")
    check(obj)
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        raise PermitRejected("malformed_input", "payload is not canonical JSON")


def payload_hash(action: str, payload: dict) -> str:
    canon = canonical_json({"action": (action or "").strip().lower(), "payload": payload or {}})
    return hashlib.sha256(canon.encode()).hexdigest()


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64d(s: str) -> bytes:
    if not isinstance(s, str) or not s or not _B64.match(s):
        raise ValueError("bad base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("bad base64url")


def key_id(raw_public: bytes) -> str:
    return hashlib.sha256(raw_public).hexdigest()[:16]


def signing_input(kid: str, claims_b64: str) -> bytes:
    return f"{VERSION_TAG}.{kid}.{claims_b64}".encode("ascii")


@dataclass(frozen=True)
class Permit:
    """Signed claims. `sub` is the agent (the proposer) that must present the permit."""
    kid: str
    sub: str       # agent / proposer id
    act: str       # action name
    ph: str        # approved payload hash: sha256(canonical {"action","payload"})
    rid: str       # PATIENCE request id (for audit correlation)
    jti: str       # single-use nonce
    iat: int       # issued at (epoch seconds)
    nbf: int       # not valid before
    exp: int       # expiry


_CLAIM_TYPES = {"sub": str, "act": str, "ph": str, "rid": str, "jti": str, "iat": int, "nbf": int, "exp": int}


def _load_pubkey(v):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if isinstance(v, Ed25519PublicKey):
        return v
    if isinstance(v, str):
        v = bytes.fromhex(v)
    return Ed25519PublicKey.from_public_bytes(bytes(v))


class PermitVerifier:
    """Stateless checks. Replay (single use) is enforced by the gateway's durable NonceStore."""

    def __init__(self, keyring: Mapping[str, Any], max_ttl_seconds: int = MAX_TTL_SECONDS,
                 skew_seconds: int = DEFAULT_SKEW_SECONDS, clock: Callable[[], float] = time.time):
        self._keys = {}
        for kid, k in (keyring or {}).items():
            pk = _load_pubkey(k)
            from cryptography.hazmat.primitives import serialization
            raw = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if kid != key_id(raw):  # a keyring entry whose id does not match its key is a config error
                raise ValueError(f"key id {kid!r} does not match its public key")
            self._keys[kid] = pk
        self.max_ttl = int(max_ttl_seconds)
        self.skew = max(0, int(skew_seconds))
        self.clock = clock

    def verify(self, token: Any, *, agent: Any, action: Any, expected_hash: str) -> Permit:
        """Raise PermitRejected unless `token` is a valid permit for exactly this agent, action and
        payload hash at this moment. Does NOT consume the permit."""
        if token is None or (isinstance(token, str) and not token.strip()):
            raise PermitRejected("missing_permit")
        if not isinstance(token, str) or len(token) > MAX_TOKEN_CHARS or not token.isascii():
            raise PermitRejected("malformed_permit")
        parts = token.strip().split(".")
        if len(parts) != 4 or parts[0] != VERSION_TAG or not _KID.match(parts[1]):
            raise PermitRejected("malformed_permit")
        _, kid, claims_b64, sig_b64 = parts
        try:
            sig = b64d(sig_b64)
            claims_raw = b64d(claims_b64)
        except ValueError:
            raise PermitRejected("malformed_permit")
        pk = self._keys.get(kid)
        if pk is None:
            raise PermitRejected("unknown_key_id")
        from cryptography.exceptions import InvalidSignature
        try:
            pk.verify(sig, signing_input(kid, claims_b64))
        except InvalidSignature:
            raise PermitRejected("bad_signature")
        claims = self._parse_claims(claims_raw)
        permit = Permit(kid=kid, **{k: claims[k] for k in _CLAIM_TYPES})
        if not isinstance(agent, str) or not agent or permit.sub != agent:
            raise PermitRejected("wrong_agent")
        if not isinstance(action, str) or permit.act != action.strip().lower():
            raise PermitRejected("wrong_action")
        now = self.clock()
        if permit.nbf > permit.iat or permit.exp <= permit.iat:
            raise PermitRejected("malformed_permit", "inconsistent times")
        if permit.exp - permit.iat > self.max_ttl:
            raise PermitRejected("ttl_exceeds_max")
        if permit.nbf > now + self.skew or permit.iat > now + self.skew:
            raise PermitRejected("not_yet_valid")
        if now > permit.exp + self.skew:
            raise PermitRejected("expired")
        if not isinstance(expected_hash, str) or permit.ph != expected_hash:
            raise PermitRejected("payload_mismatch")
        return permit

    @staticmethod
    def _parse_claims(raw: bytes) -> dict:
        try:
            c = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise PermitRejected("malformed_permit")
        if not isinstance(c, dict) or set(c) != set(_CLAIM_TYPES) | {"v"} or c.get("v") != 1:
            raise PermitRejected("malformed_permit")
        for k, t in _CLAIM_TYPES.items():
            v = c[k]
            if isinstance(v, bool) or not isinstance(v, t):
                raise PermitRejected("malformed_permit")
            if t is str and (not v or len(v) > 256):
                raise PermitRejected("malformed_permit")
            if t is int and not (0 <= v < 4_102_444_800):
                raise PermitRejected("malformed_permit")
        return c
