"""Per-approver accounts (approvers.yaml, path in PATIENCE_APPROVERS).

    approvers:
      alice: {password: "scrypt$16384$8$1$<salt>$<hash>", role: admin, pin: "scrypt$...", disabled: false}

Roles: approver (approve/deny), admin (also edit policy, reconcile, manage accounts).
Passwords and PINs are stored only as scrypt hashes (stdlib hashlib.scrypt, random salt).

    python approvers.py add <user> [--role approver|admin]   (prompts for password, optional PIN)
    python approvers.py set-pin <user>
    python approvers.py disable <user>
    python approvers.py list
"""
from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import hmac
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional
import yaml
from securefile import write_secret

ROLES = ("approver", "admin")
_N, _R, _P = 2 ** 14, 8, 1
# Brute-force throttle (F2). Keyed by (user, client) so bad attempts from one IP do not lock the
# user out from another; a much higher per-user global threshold adds exponential backoff across
# all clients. Bounded in size and persisted to a JSON file so counters survive a restart.
_FAILS: dict = {}  # key "user|client" or "user|*global*" -> [count, locked_until, last_ts, strikes]
MAX_FAILS, LOCK_S = 5, 300
GLOBAL_MAX_FAILS, GLOBAL_BASE_S, GLOBAL_CAP_S = 25, 60, 900
MAX_ENTRIES = 5000
_LOADED = {"path": None}


def approvers_path() -> Path:
    return Path(os.environ.get("PATIENCE_APPROVERS", Path(__file__).with_name("approvers.yaml")))


def hash_secret(secret: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(secret.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"


def check_secret(secret: str, stored: Optional[str]) -> bool:
    try:
        _, n, r, p, salt, h = (stored or "").split("$")
        got = hashlib.scrypt((secret or "").encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(base64.b64decode(h)))
        return hmac.compare_digest(got, base64.b64decode(h))
    except Exception:
        return False


_DUMMY = None


def load() -> dict:
    p = approvers_path()
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return dict(data.get("approvers") or {})


def configured() -> bool:
    return bool(load())


def _save(accts: dict):
    p = approvers_path()
    write_secret(p, yaml.safe_dump({"approvers": accts}, sort_keys=True))


def throttle_path() -> Path:
    return Path(os.environ.get("PATIENCE_THROTTLE_PATH") or str(approvers_path()) + ".throttle.json")


def _ensure_loaded():
    p = str(throttle_path())
    if _LOADED["path"] == p:
        return
    _LOADED["path"] = p
    _FAILS.clear()
    try:
        import json
        data = json.loads(Path(p).read_text(encoding="utf-8"))
        now = time.time()
        for k, v in (data or {}).items():
            if isinstance(v, list) and len(v) == 4 and (v[1] > now or now - v[2] < GLOBAL_CAP_S * 4):
                _FAILS[str(k)[:300]] = [int(v[0]), float(v[1]), float(v[2]), int(v[3])]
    except Exception:  # missing or unreadable: start empty
        pass
    _trim()


def _persist():
    import json
    import tempfile
    p = throttle_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".throttle.")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(_FAILS, f)
        os.replace(tmp, p)
    except OSError:
        pass  # persistence is best effort; the in-memory throttle still applies


def _trim():
    if len(_FAILS) <= MAX_ENTRIES:
        return
    now = time.time()
    # drop unlocked entries first, oldest activity first; then oldest overall
    order = sorted(_FAILS.items(), key=lambda kv: (kv[1][1] > now, kv[1][2]))
    for k, _ in order[: len(_FAILS) - MAX_ENTRIES]:
        _FAILS.pop(k, None)


def _key(user: str, client: Optional[str]) -> str:
    return f"{user[:100]}|{(client or '*')[:100]}"


def _gkey(user: str) -> str:
    return f"{user[:100]}|*global*"


def _throttled(user: str, client: Optional[str] = None) -> bool:
    _ensure_loaded()
    now = time.time()
    for k in (_key(user, client), _gkey(user)):
        c = _FAILS.get(k)
        if c and c[1] > now:
            return True
    return False


def _fail(user: str, client: Optional[str] = None):
    _ensure_loaded()
    now = time.time()
    c = _FAILS.setdefault(_key(user, client), [0, 0.0, now, 0])
    c[0] += 1
    c[2] = now
    if c[0] >= MAX_FAILS:
        c[0], c[1] = 0, now + LOCK_S
    g = _FAILS.setdefault(_gkey(user), [0, 0.0, now, 0])
    g[0] += 1
    g[2] = now
    if g[0] >= GLOBAL_MAX_FAILS:
        g[3] += 1
        g[0], g[1] = 0, now + min(GLOBAL_CAP_S, GLOBAL_BASE_S * 2 ** (g[3] - 1))
    _trim()
    _persist()


def _succeed(user: str, client: Optional[str] = None):
    _ensure_loaded()
    if _FAILS.pop(_key(user, client), None) is not None:
        _persist()


def _verify(user: str, secret: str, field: str, client: Optional[str] = None) -> Optional[dict]:
    global _DUMMY
    user = (user or "").strip()
    if not user or _throttled(user, client):
        return None
    cfg = load().get(user)
    if not cfg or cfg.get("disabled") or not cfg.get(field):
        _DUMMY = _DUMMY or hash_secret("x")
        check_secret(secret, _DUMMY)  # equalise timing for unknown users
        _fail(user, client)
        return None
    if not check_secret(secret, cfg[field]):
        _fail(user, client)
        return None
    _succeed(user, client)
    role = cfg.get("role", "approver")
    return {"user": user, "role": role if role in ROLES else "approver"}


def verify_password(user: str, password: str, client: Optional[str] = None) -> Optional[dict]:
    return _verify(user, password, "password", client)


def verify_pin(user: str, pin: str, client: Optional[str] = None) -> Optional[dict]:
    return _verify(user, pin, "pin", client)


def add(user: str, password: str, role: str = "approver", pin: Optional[str] = None) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if len(password or "") < 10:
        raise ValueError("password must be at least 10 characters")
    if pin is not None and (not pin.isdigit() or len(pin) < 6):
        raise ValueError("PIN must be at least 6 digits")
    accts = load()
    accts[user] = {"password": hash_secret(password), "role": role}
    if pin:
        accts[user]["pin"] = hash_secret(pin)
    _save(accts)


def set_pin(user: str, pin: str):
    if not pin.isdigit() or len(pin) < 6:
        raise ValueError("PIN must be at least 6 digits")
    accts = load()
    accts[user]["pin"] = hash_secret(pin)
    _save(accts)


def disable(user: str) -> bool:
    accts = load()
    if user not in accts:
        return False
    accts[user]["disabled"] = True
    _save(accts)
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(prog="approvers.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add"); a.add_argument("user"); a.add_argument("--role", default="approver", choices=ROLES)
    s = sub.add_parser("set-pin"); s.add_argument("user")
    d = sub.add_parser("disable"); d.add_argument("user")
    sub.add_parser("list")
    ns = ap.parse_args(argv)
    if ns.cmd == "add":
        pw = getpass.getpass("Password (10+ chars): ")
        pin = getpass.getpass("Approval PIN for one-tap links (6+ digits, blank to skip): ") or None
        add(ns.user, pw, ns.role, pin)
        print(f"Added {ns.user} ({ns.role}).")
    elif ns.cmd == "set-pin":
        set_pin(ns.user, getpass.getpass("New PIN: "))
        print("PIN set.")
    elif ns.cmd == "disable":
        print("Disabled." if disable(ns.user) else "No such user.")
    else:
        for u, c in sorted(load().items()):
            print(f"{u:20} {c.get('role','approver'):9} {'disabled' if c.get('disabled') else 'active'}"
                  f"{'  pin' if c.get('pin') else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
