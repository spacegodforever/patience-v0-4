"""Mock protected payments service. SIMULATED: no network, no real money, no real credential.

`MockPaymentsService` holds the only (fake) credential. It will execute a simulated invoice payment
only for a caller that presents that credential. The credential is handed once, to the gateway, as a
`PaymentsClient`; agents are never given it. `create_payments_app` exposes the service over HTTP so a
test can show that a direct call without the credential is refused.

Honest limit: in this process-local mock the "credential" is a Python attribute. It models the rule
"only the gateway holds it"; it does not enforce isolation against code running in the same process.
"""
from __future__ import annotations
import hashlib
import hmac
import math
import re
import secrets
import threading
from typing import Any

PAY_INVOICE_ACTION = "payments.pay_invoice"
MAX_AMOUNT_USD = 1_000_000
_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_FIELDS = {"invoice_id", "payee", "amount_usd", "currency"}


def validate_invoice_payload(payload: Any) -> dict:
    """Strict shape check; raises ValueError. Returns a normalised copy (currency defaults to USD)."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    extra = set(payload) - _FIELDS
    if extra:
        raise ValueError(f"unexpected fields: {sorted(extra)}")
    inv, payee, amt = payload.get("invoice_id"), payload.get("payee"), payload.get("amount_usd")
    cur = payload.get("currency", "USD")
    if not isinstance(inv, str) or not _ID.match(inv):
        raise ValueError("invoice_id must be 1-64 chars of [A-Za-z0-9_.-]")
    if not isinstance(payee, str) or not payee.strip() or len(payee) > 100:
        raise ValueError("payee is required (max 100 chars)")
    if isinstance(amt, bool) or not isinstance(amt, (int, float)) or not math.isfinite(amt) \
            or not (0 < amt <= MAX_AMOUNT_USD):
        raise ValueError(f"amount_usd must be a number > 0 and <= {MAX_AMOUNT_USD}")
    if cur != "USD":
        raise ValueError("only USD is supported")
    return {"invoice_id": inv, "payee": payee, "amount_usd": amt, "currency": "USD"}


class CredentialError(Exception):
    pass


class DuplicateCharge(Exception):
    pass


class MockPaymentsService:
    def __init__(self):
        self._credential = "mock_sk_" + secrets.token_hex(16)  # FAKE; never a real secret
        self._lock = threading.Lock()
        self._client_issued = False
        self.ledger: list[dict] = []          # simulated ledger, inspectable by tests
        self._seen_refs: set = set()

    def issue_client(self) -> "PaymentsClient":
        """One-time hand-over of the credential to the gateway."""
        with self._lock:
            if self._client_issued:
                raise CredentialError("the credential was already handed to the gateway")
            self._client_issued = True
        return PaymentsClient(self, self._credential)

    def charge(self, credential: Any, payload: dict, reference: str) -> dict:
        if not isinstance(credential, str) or not hmac.compare_digest(credential, self._credential):
            raise CredentialError("invalid service credential")
        clean = validate_invoice_payload(payload)
        with self._lock:
            if reference in self._seen_refs:  # defence in depth: one permit reference, one payment
                raise DuplicateCharge("this permit reference was already charged")
            self._seen_refs.add(reference)
            receipt = {"simulated": True, "receipt_id": "mockpay_" + hashlib.sha256(
                f"{reference}|{clean['invoice_id']}".encode()).hexdigest()[:16],
                "invoice_id": clean["invoice_id"], "payee": clean["payee"],
                "amount_usd": clean["amount_usd"], "currency": "USD", "reference": reference}
            self.ledger.append(receipt)
        return dict(receipt)


class PaymentsClient:
    """Holds the credential on the gateway's behalf. Not given to agents."""
    def __init__(self, service: MockPaymentsService, credential: str):
        self._service, self._credential = service, credential

    def pay_invoice(self, payload: dict, reference: str) -> dict:
        return self._service.charge(self._credential, payload, reference)


def create_payments_app(service: MockPaymentsService):
    """The protected service over HTTP. Requires the service credential; agents do not have it."""
    from fastapi import FastAPI, Header, HTTPException
    app = FastAPI(title="mock-payments (SIMULATED)")

    @app.post("/charge")
    def charge(body: dict, x_service_credential: str = Header(default="")):
        try:
            return service.charge(x_service_credential, body.get("payload"), str(body.get("reference", "")))
        except CredentialError:
            raise HTTPException(401, "credential required")
        except (ValueError, DuplicateCharge) as e:
            raise HTTPException(422, str(e))
    return app
