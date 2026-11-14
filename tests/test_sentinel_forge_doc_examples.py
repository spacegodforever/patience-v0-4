"""Worked examples for docs/SENTINEL_FORGE_HASHING_AND_KEYS.md.

Freshly generated test keys and synthetic data only. These tests reuse existing APIs and do not
touch production key files, env secrets, or store/db files in the repo. The autouse isolation
fixture in conftest.py points the audit log at a temp path.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

import audit
from dev_governance import claims
from dev_governance.gate import payload_hash as gate_payload_hash
from execution_gateway.issuer import PermitIssuer
from execution_gateway.permit import (
    PermitRejected,
    PermitVerifier,
    payload_hash as permit_payload_hash,
)


ACTION = "docs.sentinel_forge.example"
PAYLOAD = {"amount": "1.00", "currency": "USD", "vendor": "example-only"}
# Synthetic HMAC material for this module only; never a live secret.
_CLAIM_SECRET = "sentinel-forge-doc-example-claim-secret-not-used-elsewhere"


@pytest.fixture
def claim_secret(monkeypatch):
    monkeypatch.setenv("PATIENCE_CLAIM_SECRET", _CLAIM_SECRET)
    return _CLAIM_SECRET


def test_payload_hash_change_is_detected():
    h1 = gate_payload_hash(ACTION, PAYLOAD)
    h2 = gate_payload_hash(ACTION, {**PAYLOAD, "vendor": "other"})
    assert h1 != h2
    assert len(h1) == 64 and h1 != "0" * 64
    # The gateway's copy must stay equivalent to the gate's (content binding is shared).
    assert h1 == permit_payload_hash(ACTION, PAYLOAD)
    # Canonicalization is strict: key order must not change the hash.
    assert gate_payload_hash(ACTION, {"b": 1, "a": 2}) == gate_payload_hash(ACTION, {"a": 2, "b": 1})


def test_audit_chain_break_is_detected():
    first = audit.append("docs.sentinel.one", "example-actor", n=1)
    second = audit.append("docs.sentinel.two", "example-actor", n=2)
    assert audit.verify()["ok"] is True
    assert first["hash"] == second["prev"]
    assert Path(str(audit.path()) + ".head").read_text(encoding="utf-8").strip() == second["hash"]

    lines = Path(audit.path()).read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["data"]["n"] = 999
    lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    Path(audit.path()).write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = audit.verify()
    assert result["ok"] is False
    assert result["bad_seq"] == 1
    assert "modified" in (result["error"] or "")


def test_audit_chain_prev_mismatch_is_detected():
    audit.append("docs.sentinel.a", "example-actor")
    audit.append("docs.sentinel.b", "example-actor")
    lines = Path(audit.path()).read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["prev"] = "a" * 64
    rec["hash"] = audit._digest(rec)  # re-hash so only the chain link is wrong
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    Path(audit.path()).write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = audit.verify()
    assert result["ok"] is False
    assert "chain broken" in (result["error"] or "")


def test_claim_token_tamper_is_detected(claim_secret):
    h = gate_payload_hash(ACTION, PAYLOAD)
    token = claims.mint("dev_example", h)
    claims.verify(token, "dev_example", h)  # intact token works once

    token2 = claims.mint("dev_example", h)
    # Flip bits in the HMAC so the token stays well-formed but the signature does not verify.
    parts = token2.split(".")
    assert len(parts) == 6
    sig = parts[-1]
    flipped = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    tampered = ".".join(parts[:-1] + [flipped])
    # The flipped digest must not accidentally equal a recompute under the test secret.
    expected = hmac.new(
        claim_secret.encode(),
        f"v1|dev_example|{h}|{int(parts[3])}|{parts[4]}".encode(),
        hashlib.sha256,
    ).hexdigest()
    assert flipped != expected
    with pytest.raises(claims.ClaimError, match="signature"):
        claims.verify(tampered, "dev_example", h)


def test_permit_signature_tamper_is_detected():
    # Ephemeral in-process key; never written to a .permit_key file.
    issuer = PermitIssuer()
    ph = permit_payload_hash(ACTION, PAYLOAD)
    issued = issuer.issue(agent="agent-example", action=ACTION, payload_hash=ph, request_id="dev_example")
    verifier = PermitVerifier(issuer.public_keys())
    verifier.verify(issued["permit"], agent="agent-example", action=ACTION, expected_hash=ph)

    tag, kid, claims_b64, sig_b64 = issued["permit"].split(".")
    # Flip an early base64url character. The last character often only carries
    # padding bits (Ed25519 signatures are 64 bytes), so changing it can leave
    # the decoded signature unchanged and the test would flake.
    first = sig_b64[0]
    flipped_first = "A" if first != "A" else "B"
    tampered = f"{tag}.{kid}.{claims_b64}.{flipped_first}{sig_b64[1:]}"
    with pytest.raises(PermitRejected) as err:
        verifier.verify(tampered, agent="agent-example", action=ACTION, expected_hash=ph)
    assert err.value.code == "bad_signature"
