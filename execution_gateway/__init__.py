"""Execution Gateway v0: a simulated, permit-gated payments service (no real money, no network).

PATIENCE issues short-lived, single-use, Ed25519-signed permits after a human approval. The gateway
verifies a permit (fail closed) before a mock payments service, which alone holds a fake credential,
will execute a simulated invoice payment. See docs/execution-gateway-v0.md.
"""
from .permit import (PermitRejected, PermitVerifier, Permit, REASONS, canonical_json, payload_hash,
                     DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS)
from .issuer import PermitIssuer, PermitError
from .nonces import NonceStore, NonceStoreError
from .payments import (MockPaymentsService, PaymentsClient, create_payments_app, validate_invoice_payload,
                       PAY_INVOICE_ACTION)
from .gateway import ExecutionGateway, GatewayResult, create_gateway_app, keyring_from_env

PERMIT_ACTIONS = (PAY_INVOICE_ACTION,)

__all__ = ["PermitRejected", "PermitVerifier", "Permit", "REASONS", "canonical_json", "payload_hash",
           "DEFAULT_TTL_SECONDS", "MAX_TTL_SECONDS", "PermitIssuer", "PermitError", "NonceStore",
           "NonceStoreError", "MockPaymentsService", "PaymentsClient", "create_payments_app",
           "validate_invoice_payload", "PAY_INVOICE_ACTION", "ExecutionGateway", "GatewayResult",
           "create_gateway_app", "keyring_from_env", "PERMIT_ACTIONS"]
