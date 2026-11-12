"""Human-granted, per-action capability evidence for the development gate.

This module checks human decision records. It does not authenticate signers, execute commands,
or establish a sandbox. A grant is deliberately not derived from a risk tier, role, strategy document, or
agent request. SQLite events are append-only; the latest event wins and revocation wins ties.

The default store is in-memory. Applications must inject a durable store path to retain grants.
"""
from __future__ import annotations

import math
import sqlite3
import time
from typing import Callable, Optional

import audit
from . import claims as _claims

LEVELS = range(5)
BASES = ("human_decision", "observed_test", "local_documentation", "primary_public_source", "hypothesis")
CONFIDENCE = ("high", "medium", "low")
SCOPE_FIELDS = ("command", "workspace", "environment", "adapter")


class AuthorityError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


ATTEST_TTL_SECONDS = 60


class CapabilityAuthority:
    """Evaluate exact human grants for one actor, owner set, action and resource scope.

    Scope values are exact matches, not filesystem or command safety verification. Callers must
    still use an adapter with real isolation. Grants never supply an adapter or reduce approvals.
    """

    def __init__(self, path: str = ":memory:", clock: Callable[[], float] = time.time):
        self.path, self.clock = path, clock
        # Grants must be explicit about the intended test action and actual execution authority.
        self._grant_actions = {"test.run_isolated"}
        # SQLite :memory: is connection-local; retain one connection for that explicit test mode.
        self._memory = sqlite3.connect(":memory:", check_same_thread=False) if path == ":memory:" else None
        with self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS capability_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    grant_id TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK(event_type IN ('grant', 'revoke')),
                    body TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS capability_events_grant
                    ON capability_events(grant_id, seq);
                CREATE TRIGGER IF NOT EXISTS capability_events_no_update
                    BEFORE UPDATE ON capability_events
                    BEGIN SELECT RAISE(ABORT, 'capability_events is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS capability_events_no_delete
                    BEFORE DELETE ON capability_events
                    BEGIN SELECT RAISE(ABORT, 'capability_events is append-only'); END;
            """)

        if path != ":memory:":
            from .fsperm import secure_file
            self.permissions_fixed = secure_file(path)  # grants are sensitive: 0600 like the gate DB

    def _conn(self):
        return self._memory if self._memory is not None else sqlite3.connect(self.path, timeout=30)

    def attest(self, user: str, purpose: str, subject: str, ttl: int = ATTEST_TTL_SECONDS) -> str:
        """Mint a short-lived assertion that `user` was authenticated as a human admin for ONE
        grant or revoke of `subject` (the grant id). Only the API layer should call this, after
        its own authentication dependency has verified the person. It is HMAC-signed with the
        gate's claim secret, so a caller cannot make one up, but any code running in this process
        with the secret can: it moves the trust boundary to the authenticating route, it is not
        a second authentication factor."""
        exp = int(self.clock()) + max(1, min(int(ttl), ATTEST_TTL_SECONDS))
        return f"{exp}.{_claims.sign_fields('authority-attest-v1', purpose, user, subject, exp)}"

    def _verify_attestation(self, attestation, purpose: str, user: str, subject: str) -> None:
        """Fail closed (401) unless the attestation is current, unforged and bound to this user,
        purpose and grant id."""
        try:
            exp_s, _, sig = str(attestation).partition(".")
            exp = int(exp_s)
        except (TypeError, ValueError):
            raise AuthorityError(401, "an authenticated human attestation is required")
        if self.clock() >= exp or exp > self.clock() + ATTEST_TTL_SECONDS + 5 \
                or not _claims.check_fields(sig, "authority-attest-v1", purpose, user, subject, exp):
            raise AuthorityError(401, "an authenticated human attestation is required")

    @staticmethod
    def _text(value, field: str, limit: int = 200) -> str:
        if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
            raise AuthorityError(422, f"{field} must be a non-empty string of at most {limit} characters")
        return value.strip()

    def grant(self, *, grant_id: str, actor: str, action: str, resource: str, scope: dict,
              granted_by: str, human_owner: str, owners: list[str], max_level: int,
              expires_at: float, max_action_ttl_seconds: int, isolation: dict,
              evidence: dict, attestation: Optional[str] = None) -> dict:
        """Record a named human's grant; the human owner cannot grant their own agent.

        `attestation` (see attest()) proves the API layer authenticated `granted_by`; without a
        valid one the grant is refused (401) and nothing is stored."""
        now = self.clock()
        grant_id = self._text(grant_id, "grant_id", 100)
        self._verify_attestation(attestation, "grant", self._text(granted_by, "granted_by", 100), grant_id)
        actor = self._text(actor, "actor", 100)
        action = self._text(action, "action", 100)
        if action not in self._grant_actions:
            raise AuthorityError(422, "capability grants are currently supported only for test.run_isolated")
        resource = self._text(resource, "resource", 500)
        granted_by = self._text(granted_by, "granted_by", 100)
        human_owner = self._text(human_owner, "human_owner", 100)
        owners = sorted({self._text(o, "owner", 100) for o in owners})
        if granted_by == actor or granted_by in owners or granted_by == human_owner:
            raise AuthorityError(403, "an actor or its human owner cannot grant its capability")
        if not isinstance(max_level, int) or isinstance(max_level, bool) or max_level not in LEVELS:
            raise AuthorityError(422, "max_level must be an integer from 0 through 4")
        if max_level < 2:
            raise AuthorityError(422, "isolated test execution requires at least level 2 (act on approval)")
        try:
            expires_at = float(expires_at)
            ttl = int(max_action_ttl_seconds)
        except (TypeError, ValueError, OverflowError):
            raise AuthorityError(422, "grant expiry and action TTL must be numeric")
        if ttl != max_action_ttl_seconds:
            raise AuthorityError(422, "max_action_ttl_seconds must be an integer")
        if not math.isfinite(expires_at):
            raise AuthorityError(422, "grant expiry must be finite")
        if expires_at <= now:
            raise AuthorityError(422, "grant must expire in the future")
        if ttl <= 0 or ttl > 86400:
            raise AuthorityError(422, "max_action_ttl_seconds must be between 1 and 86400")
        if not isinstance(scope, dict) or set(scope) - set(SCOPE_FIELDS):
            raise AuthorityError(422, f"scope may contain only {', '.join(SCOPE_FIELDS)}")
        scope = {k: self._text(v, f"scope.{k}", 500) for k, v in scope.items()}
        if set(scope) != set(SCOPE_FIELDS):
            raise AuthorityError(422, "command, workspace, environment and adapter scope are all required")
        if not isinstance(isolation, dict) or any(isolation.get(k) is not False for k in
                ("network_allowed", "secrets_allowed", "production_allowed")):
            raise AuthorityError(422, "network, secrets and production access must each be explicitly false")
        if set(isolation) != {"network_allowed", "secrets_allowed", "production_allowed"}:
            raise AuthorityError(422, "isolation must contain exactly the three explicit access declarations")
        if not isinstance(evidence, dict) or set(evidence) != {"basis", "reference", "confidence", "reason"}:
            raise AuthorityError(422, "evidence requires basis, reference, confidence and reason")
        evidence = dict(evidence)
        if evidence["basis"] not in BASES or evidence["confidence"] not in CONFIDENCE:
            raise AuthorityError(422, "evidence basis or confidence is not recognized")
        for field in ("reference", "reason"):
            evidence[field] = self._text(evidence[field], f"evidence.{field}", 1000)
        body = {"actor": actor, "action": action, "resource": resource, "scope": scope,
                "granted_by": granted_by, "human_owner": human_owner, "owners": owners,
                "max_level": max_level, "expires_at": expires_at, "max_action_ttl_seconds": ttl,
                "isolation": isolation, "evidence": evidence}
        with self._conn() as c:
            if c.execute("SELECT 1 FROM capability_events WHERE grant_id=?", (grant_id,)).fetchone():
                raise AuthorityError(409, "grant_id already has an event; choose a new id")
            c.execute("INSERT INTO capability_events(grant_id,event_type,body,created_at) VALUES(?,?,?,?)",
                      (grant_id, "grant", self._encode(body), now))
        audit.append("dev.authority.granted", granted_by, grant_id=grant_id, agent=actor, action=action,
                     resource=resource, scope=scope, owners=owners, max_level=max_level,
                     expires_at=expires_at, max_action_ttl_seconds=ttl, isolation=isolation,
                     evidence=evidence)
        return {"grant_id": grant_id, **body}

    @staticmethod
    def _encode(body: dict) -> str:
        import json
        return json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)

    def revoke(self, grant_id: str, revoked_by: str, reason: str, attestation: Optional[str] = None) -> dict:
        grant_id = self._text(grant_id, "grant_id", 100)
        revoked_by = self._text(revoked_by, "revoked_by", 100)
        reason = self._text(reason, "reason", 1000)
        self._verify_attestation(attestation, "revoke", revoked_by, grant_id)
        with self._conn() as c:
            if not c.execute("SELECT 1 FROM capability_events WHERE grant_id=?", (grant_id,)).fetchone():
                raise AuthorityError(404, "unknown grant")
            c.execute("INSERT INTO capability_events(grant_id,event_type,body,created_at) VALUES(?,?,?,?)",
                      (grant_id, "revoke", self._encode({"revoked_by": revoked_by, "reason": reason}), self.clock()))
        audit.append("dev.authority.revoked", revoked_by, grant_id=grant_id, reason=reason)
        return {"grant_id": grant_id, "revoked": True}

    def _current(self, grant_id: str) -> Optional[tuple[str, dict]]:
        with self._conn() as c:
            row = c.execute("SELECT event_type,body FROM capability_events WHERE grant_id=? "
                            "ORDER BY seq DESC LIMIT 1", (grant_id,)).fetchone()
        if not row:
            return None
        import json
        return row[0], json.loads(row[1])

    def require(self, *, grant_id: Optional[str], actor: str, action: str, payload: dict,
                owners: list[str], request_expires_at: float) -> dict:
        """Fail closed unless the current grant covers this exact request and remains isolated."""
        kind, grant = self._current(grant_id or "") or (None, None)
        if kind != "grant":
            message = "capability grant was revoked" if kind == "revoke" else "a current human capability grant is required"
            raise AuthorityError(403, message)
        now = self.clock()
        if now >= grant["expires_at"]:
            raise AuthorityError(403, "capability grant has expired")
        expected = {"command": payload.get("command"), "workspace": payload.get("workspace"),
                    "environment": payload.get("environment"), "adapter": payload.get("adapter")}
        mismatches = [k for k, v in expected.items() if grant["scope"][k] != v]
        if (grant["actor"], grant["action"]) != (actor, action) or grant["resource"] != payload.get("resource"):
            mismatches.append("actor/action/resource")
        if set(owners or []) != set(grant["owners"]):
            mismatches.append("owners")
        if mismatches:
            raise AuthorityError(403, "request is outside the human-granted capability scope")
        try:
            request_expires_at = float(request_expires_at)
        except (TypeError, ValueError):
            raise AuthorityError(403, "request expiry is invalid")
        if not math.isfinite(request_expires_at) or request_expires_at <= now:
            raise AuthorityError(403, "request expiry is invalid")
        if request_expires_at > min(grant["expires_at"], now + grant["max_action_ttl_seconds"]):
            raise AuthorityError(403, "request approval window exceeds the capability grant")
        return {"grant_id": grant_id, "granted_by": grant["granted_by"],
                "human_owner": grant["human_owner"], "max_level": grant["max_level"],
                "evidence": grant["evidence"], "isolation": grant["isolation"]}


_SHARED: dict = {}


def default_authority() -> CapabilityAuthority:
    """One durable grant store per path per process. PATIENCE_DEV_AUTHORITY_DB defaults to
    patience_dev_authority.db (git-ignored); ':memory:' is allowed for tests only."""
    import os
    path = os.environ.get("PATIENCE_DEV_AUTHORITY_DB", "patience_dev_authority.db")
    if path == ":memory:":
        return CapabilityAuthority()
    a = _SHARED.get(path)
    if a is None or not os.path.exists(path):
        a = _SHARED[path] = CapabilityAuthority(path=path)
    return a
