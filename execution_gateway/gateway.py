"""Execution gateway: the only path to the mock payments credential. Fails closed.

Decision order (first failure rejects; every accept AND reject is written to the audit log with a
reason code; the raw permit is never logged):
  kill switch -> permit present -> permit well-formed -> known key id -> signature -> agent -> action
  -> validity window / max lifetime -> payload hash -> payload shape -> single-use nonce burn
  -> audit "accepted" -> simulated payment -> audit "executed".
A permit is consumed only when every earlier check passed, so a rejected probe does not burn it.
Any unexpected exception becomes `verifier_error` (reject). If the audit log cannot be written for an
accept, the request is rejected (`audit_unavailable`) and no payment is made.

The gateway reads the same kill switch variable as PATIENCE (PATIENCE_DEV_KILL) but does not import
the PATIENCE gate.
"""
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .nonces import NonceStore, NonceStoreError
from .payments import PAY_INVOICE_ACTION, PaymentsClient, validate_invoice_payload
from .permit import PermitRejected, PermitVerifier, payload_hash

MAX_BODY_BYTES = 16 * 1024

_STATUS = {
    "missing_permit": 401, "malformed_permit": 401, "unknown_key_id": 401, "bad_signature": 401,
    "malformed_input": 400, "invalid_payload": 422, "unsupported_action": 422,
    "expired": 403, "not_yet_valid": 403, "ttl_exceeds_max": 403, "payload_mismatch": 403,
    "wrong_agent": 403, "wrong_action": 403, "replayed": 409,
    "kill_switch": 503, "verifier_error": 503, "audit_unavailable": 503, "payment_failed": 502,
}


def kill_switch_on() -> bool:
    return os.environ.get("PATIENCE_DEV_KILL", "").strip().lower() in ("1", "true", "yes", "on")


def _clip(v: Any, n: int = 128) -> str:
    s = v if isinstance(v, str) else repr(v)
    return "".join(ch if ch.isprintable() else "?" for ch in s[:n])


@dataclass
class GatewayResult:
    status: int
    body: dict = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.body.get("decision") == "accept"


class ExecutionGateway:
    def __init__(self, verifier: PermitVerifier, nonces: NonceStore, payments: PaymentsClient,
                 clock: Callable[[], float] = time.time, audit_fn: Optional[Callable] = None,
                 kill_switch: Callable[[], bool] = kill_switch_on,
                 supported_actions: tuple = (PAY_INVOICE_ACTION,)):
        if audit_fn is None:
            import audit as _audit
            audit_fn = _audit.append
        self.verifier, self.nonces, self.payments = verifier, nonces, payments
        self.clock, self._audit, self._kill = clock, audit_fn, kill_switch
        self.supported = tuple(supported_actions)

    # -- audit --------------------------------------------------------------------------------
    def _record(self, event: str, agent: Any, **data) -> bool:
        try:
            self._audit(event, _clip(agent) if agent is not None else None, **data)
            return True
        except Exception:
            return False

    def _reject(self, code: str, agent: Any, action: Any, ph: Optional[str], permit=None, detail: str = "") -> GatewayResult:
        self._record("gateway.rejected", agent, reason_code=code, action=_clip(action), payload_hash=ph,
                     request_id=_clip(permit.rid) if permit else None, permit_id=_clip(permit.jti) if permit else None,
                     key_id=_clip(permit.kid) if permit else None)
        return GatewayResult(_STATUS[code], {"decision": "reject", "reason_code": code})

    # -- the one entry point ------------------------------------------------------------------
    def handle(self, token: Any, agent: Any, action: Any, payload: Any) -> GatewayResult:
        ph: Optional[str] = None
        permit = None
        try:
            if self._kill():
                return self._reject("kill_switch", agent, action, None)
            if token is None or (isinstance(token, str) and not token.strip()):
                return self._reject("missing_permit", agent, action, None)
            if not isinstance(agent, str) or not agent.strip() or not isinstance(action, str) \
                    or not isinstance(payload, dict):
                return self._reject("malformed_input", agent, action, None)
            try:
                ph = payload_hash(action, payload)
            except PermitRejected as e:
                return self._reject(e.code, agent, action, None)
            if action.strip().lower() not in self.supported:
                return self._reject("unsupported_action", agent, action, ph)
            try:
                permit = self.verifier.verify(token, agent=agent, action=action, expected_hash=ph)
            except PermitRejected as e:
                return self._reject(e.code, agent, action, ph)
            try:
                clean = validate_invoice_payload(payload)
            except ValueError:
                return self._reject("invalid_payload", agent, action, ph, permit)
            try:
                first = self.nonces.burn(permit.jti, permit.exp, self.clock(), agent, permit.rid)
            except NonceStoreError:
                return self._reject("verifier_error", agent, action, ph, permit)
            if not first:
                return self._reject("replayed", agent, action, ph, permit)
            if not self._record("gateway.accepted", agent, reason_code="ok", action=_clip(action), payload_hash=ph,
                                request_id=_clip(permit.rid), permit_id=_clip(permit.jti), key_id=_clip(permit.kid)):
                # permit is already burned: fail closed, no payment
                return GatewayResult(_STATUS["audit_unavailable"], {"decision": "reject", "reason_code": "audit_unavailable"})
            try:
                receipt = self.payments.pay_invoice(clean, permit.jti)
            except Exception:
                self._record("gateway.payment_failed", agent, reason_code="payment_failed", payload_hash=ph,
                             request_id=_clip(permit.rid), permit_id=_clip(permit.jti))
                return GatewayResult(_STATUS["payment_failed"], {"decision": "reject", "reason_code": "payment_failed"})
            self._record("gateway.payment_executed", agent, payload_hash=ph, request_id=_clip(permit.rid),
                         permit_id=_clip(permit.jti), receipt_id=receipt["receipt_id"], simulated=True)
            return GatewayResult(200, {"decision": "accept", "reason_code": "ok", "receipt": receipt})
        except Exception:  # verifier bug / unexpected state: never fail open
            try:
                return self._reject("verifier_error", agent, action, ph, permit)
            except Exception:
                return GatewayResult(503, {"decision": "reject", "reason_code": "verifier_error"})


def keyring_from_env() -> dict:
    """PATIENCE_GATEWAY_PUBKEYS = "kid=hexpub,kid2=hexpub2" or PATIENCE_GATEWAY_PUBKEYS_FILE (one
    kid=hexpub per line). Public keys only. An empty keyring rejects everything (unknown_key_id)."""
    raw = os.environ.get("PATIENCE_GATEWAY_PUBKEYS", "")
    f = os.environ.get("PATIENCE_GATEWAY_PUBKEYS_FILE", "").strip()
    if f:
        with open(f) as fh:
            raw += "," + ",".join(fh.read().split())
    out = {}
    for item in raw.split(","):
        item = item.strip()
        if item:
            kid, _, hx = item.partition("=")
            out[kid.strip()] = hx.strip()
    return out


def create_gateway_app(gateway: ExecutionGateway,
                       agent_id_fn: Optional[Callable[[Any], Optional[str]]] = None):
    """POST /v1/payments/pay  headers: X-Patience-Permit, X-Agent-Id  body: {"action":..., "payload":{...}}

    v0 limitation: the agent id is ASSERTED by the caller (X-Agent-Id); pass `agent_id_fn` to plug in a
    real authenticator. A permit stolen together with its agent id would be accepted until it expires
    or is used."""
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    app = FastAPI(title="patience-execution-gateway (SIMULATED payments)")

    @app.post("/v1/payments/pay")
    async def pay(request: Request):
        agent = (agent_id_fn(request) if agent_id_fn else request.headers.get("x-agent-id"))
        token = request.headers.get("x-patience-permit")
        raw = await request.body()
        action = payload = None
        if len(raw) > MAX_BODY_BYTES:
            res = gateway._reject("malformed_input", agent, None, None)
        else:
            try:
                body = json.loads(raw.decode("utf-8")) if raw else None
                action, payload = body.get("action"), body.get("payload")
            except Exception:
                body = None
            if body is None or not isinstance(body, dict):
                res = gateway.handle(token, agent, None, None)  # records a missing/malformed rejection
            else:
                res = gateway.handle(token, agent, action, payload)
        return JSONResponse(status_code=res.status, content=res.body)
    return app
