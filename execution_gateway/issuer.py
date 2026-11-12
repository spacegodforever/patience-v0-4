"""PATIENCE-side permit signing. The private key lives only here (a 0600 file or the process);
the gateway is given public keys only.

Key location: PATIENCE_PERMIT_SIGNING_KEY_FILE, else <gate store db>.permit_key (see DevGate), else an
ephemeral in-process key. The file holds a 32-byte Ed25519 seed as 64 hex chars. A malformed or
unreadable key file raises PermitError (fail closed: no permits are issued).
"""
from __future__ import annotations
import json
import os
import secrets
import time
from typing import Callable, Optional

from .permit import (DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS, VERSION_TAG, b64e, key_id, signing_input)


class PermitError(Exception):
    pass


def _secure(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class PermitIssuer:
    def __init__(self, private_key=None, clock: Callable[[], float] = time.time):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:  # no HMAC fallback in v0: refuse rather than weaken
            raise PermitError("the 'cryptography' package is required to issue permits (Ed25519)") from None
        self._sk = private_key if private_key is not None else Ed25519PrivateKey.generate()
        self._raw_pub = self._sk.public_key().public_bytes(serialization.Encoding.Raw,
                                                           serialization.PublicFormat.Raw)
        self.kid = key_id(self._raw_pub)
        self.clock = clock

    @property
    def public_hex(self) -> str:
        return self._raw_pub.hex()

    def public_keys(self) -> dict:
        """Verification material for a gateway keyring: {kid: public key hex}. Never the private key."""
        return {self.kid: self.public_hex}

    @classmethod
    def from_file(cls, path: str, clock: Callable[[], float] = time.time) -> "PermitIssuer":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        except OSError as e:
            raise PermitError(f"cannot create permit signing key ({type(e).__name__})") from None
        _secure(path)
        try:
            with open(path) as f:
                seed = bytes.fromhex(f.read().strip())
            if len(seed) != 32:
                raise ValueError("wrong length")
            return cls(Ed25519PrivateKey.from_private_bytes(seed), clock)
        except (OSError, ValueError):
            raise PermitError("permit signing key file is unreadable or malformed; refusing to issue") from None

    def issue(self, *, agent: str, action: str, payload_hash: str, request_id: str,
              ttl_seconds: Optional[int] = None, not_after: Optional[float] = None) -> dict:
        """Sign a single-action permit. ttl defaults to 5 minutes and is clamped to MAX_TTL_SECONDS;
        `not_after` (e.g. the approval's own expiry) can only shorten it."""
        if not agent or not action or not payload_hash or not request_id:
            raise PermitError("agent, action, payload_hash and request_id are required")
        try:
            ttl = int(DEFAULT_TTL_SECONDS if ttl_seconds is None else ttl_seconds)
        except (TypeError, ValueError):
            raise PermitError("ttl must be an integer") from None
        if ttl <= 0:
            raise PermitError("ttl must be positive")
        ttl = min(ttl, MAX_TTL_SECONDS)
        iat = int(self.clock())
        exp = iat + ttl
        if not_after is not None:
            exp = min(exp, int(not_after))
        if exp <= iat:
            raise PermitError("the approval has no validity left")
        claims = {"v": 1, "sub": agent, "act": action.strip().lower(), "ph": payload_hash, "rid": request_id,
                  "jti": secrets.token_hex(16), "iat": iat, "nbf": iat, "exp": exp}
        claims_b64 = b64e(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        sig = self._sk.sign(signing_input(self.kid, claims_b64))
        return {"permit": f"{VERSION_TAG}.{self.kid}.{claims_b64}.{b64e(sig)}", "jti": claims["jti"],
                "kid": self.kid, "iat": iat, "exp": exp}


_CACHE: dict = {}


def issuer_for_store(store_path: Optional[str], clock: Callable[[], float] = time.time) -> PermitIssuer:
    """Stable issuer across DevGate instances (the API builds a gate per request)."""
    explicit = os.environ.get("PATIENCE_PERMIT_SIGNING_KEY_FILE", "").strip()
    path = explicit or (store_path + ".permit_key" if store_path and store_path != ":memory:" else "")
    if not path:
        key = ("ephemeral",)
        if key not in _CACHE:
            _CACHE[key] = PermitIssuer(clock=clock)
        iss = _CACHE[key]
    else:
        iss = _CACHE.get(path)
        if iss is None or not os.path.exists(path):
            iss = _CACHE[path] = PermitIssuer.from_file(path, clock)
    iss.clock = clock
    return iss
