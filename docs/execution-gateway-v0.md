# Execution Gateway v0 (local branch `feat/execution-gateway-v0`)

Status: **experimental, simulated only.** No real money moves, nothing touches a network, and no
real credential exists anywhere in this code. The audit log is append-only and tamper-evident (hash
chain); edits are detectable, not impossible. Nothing here is a readiness, certification or
compliance claim. Everything below marked *tested* has an automated test in
`tests/test_execution_gateway.py` or `tests/test_verify_audit.py`.

## What it proves (and what it does not)

Claim being tested: **an agent that holds no credential can cause a (simulated) invoice payment only
by presenting a valid, unexpired, single-use permit that PATIENCE issued after a human approved that
exact payload.** The gate controls the *decision*; the gateway controls the *execution*. This closes
the gap named in the PATIENCE GOV notes ("no execution gateway that prevents agents from bypassing
PATIENCE") **for this one simulated action only**. It is not a deployed, network-isolated system.

## Architecture

```mermaid
flowchart LR
    A[Agent<br/>no credentials] -->|1 propose payments.pay_invoice| G
    subgraph PATIENCE [PATIENCE dev gate - existing modules extended]
      G[DevGate.propose<br/>policy tier high / critical over 500 USD] --> H[Human approvers<br/>proposer and owner cannot approve]
      H -->|2 approved| I[DevGate.issue_permit<br/>hash match + proposer + kill switch + breaker + expiry<br/>status -> permit_issued terminal]
      K[(Ed25519 private key<br/>0600 file)] --> I
    end
    I -->|3 signed single-action permit, 5 min| A
    A -->|4 permit + agent id + action + payload| GW
    subgraph GATEWAY [Execution gateway - verifies with PUBLIC key only]
      GW[ExecutionGateway.handle<br/>kill switch, format, kid, signature, agent, action,<br/>window, payload hash, shape] --> N[(NonceStore<br/>SQLite 0600, append-only trigger)]
      N -->|5 first use| P[PaymentsClient<br/>holds the only fake credential]
    end
    P --> M[MockPaymentsService<br/>simulated ledger]
    G -. dev.proposed / dev.approved .-> L[(Hash-chained audit log)]
    I -. dev.permit.issued .-> L
    GW -. gateway.accepted / rejected + reason code .-> L
    L --> V[tools/verify_audit.py<br/>stdlib only, no PATIENCE imports]
```

New code:

| Path | Role |
|---|---|
| `execution_gateway/permit.py` | permit wire format, canonical payload hash, `PermitVerifier` (public keys only) |
| `execution_gateway/issuer.py` | `PermitIssuer` (Ed25519 signing, 0600 key file), `issuer_for_store` |
| `execution_gateway/nonces.py` | durable single-use nonce store |
| `execution_gateway/payments.py` | `MockPaymentsService` (the only fake credential), payload validation, optional HTTP app |
| `execution_gateway/gateway.py` | `ExecutionGateway` decision logic + FastAPI app `POST /v1/payments/pay` |
| `tools/verify_audit.py` | independent audit-chain verifier (stdlib only) |

Extended (not rewritten): `dev_governance/gate.py` (`issue_permit`, propose-time validation,
`execute` refuses permit-gated actions), `dev_governance/router.py` (`POST /v1/dev/requests/{id}/permit`),
`dev_governance/store.py` (`permit_issued` is a terminal status), `dev_governance/policy.py` and
`policies/dev/default.yaml` (`payments.pay_invoice`: floor `high`, `critical` over 500 USD),
`requirements.txt` (`cryptography>=41`, already installed here as 43.0.0; no HMAC fallback, see below).
`audit.py`, `claims.py`, `breaker.py` and `authority.py` are unchanged. `audit.append` is reused as the
decision log; the `claims.py` patterns (single-use nonce in SQLite, 0600 key file created with
`O_EXCL`) and the `PATIENCE_DEV_KILL` semantics are followed in new code rather than imported.

### Permit

`pp1.<kid>.<claims>.<signature>` (base64url). Claims, all signed: `sub` (agent = the proposer id),
`act` (action), `ph` (approved payload hash, the same `sha256` over canonical `{"action","payload"}`
the gate already binds execution to), `rid` (request id), `jti` (128-bit single-use nonce), `iat`,
`nbf`, `exp`. Default lifetime 300 s, issuer clamp 900 s, never longer than the approval's own expiry.
Signature: Ed25519 over `pp1.<kid>.<claims>` (version and key id are inside the signed bytes).

### Gateway decision order (all rejections fail closed, each audited with a reason code)

`kill_switch` (503) -> `missing_permit` (401) -> `malformed_input`/`malformed_permit` (400/401) ->
`unsupported_action` -> `unknown_key_id` (401) -> `bad_signature` (401) -> `wrong_agent` ->
`wrong_action` -> `ttl_exceeds_max` / `not_yet_valid` / `expired` (403) -> `payload_mismatch` (403) ->
`invalid_payload` (422) -> `replayed` (409, atomic INSERT on the nonce) -> audit `gateway.accepted`
(if the log cannot be written: `audit_unavailable`, no payment) -> simulated payment ->
`gateway.payment_executed`. Any unexpected exception -> `verifier_error` (503). The permit is burned
only after every earlier check passed, so a probe with a wrong agent or altered payload does not spend
a legitimate permit. A payment failure after the burn is **not** retried; a new approval is needed.

## Decisions

1. **Ed25519, not HMAC.** `cryptography` was already installed, so the gateway can hold only a
   *public* key and cannot mint permits. If `cryptography` is missing, permit issuance and the
   verifier fail closed with a clear error. There is deliberately **no HMAC fallback** in v0: it
   would be untested code and would give the gateway the ability to forge. (`cryptography` was added
   to `requirements.txt`; it was not previously listed.)
2. **Issuing a permit consumes the approval.** Status becomes `permit_issued` (terminal), so one
   approval yields at most one permit and the old `execute` path can never also run it.
3. **PATIENCE never executes payments.** `DevGate.execute` returns 409 for `payments.pay_invoice`; no
   adapter exists. Only the gateway, holding the credential, can.
4. **Permit is bound to the proposer**, even if the proposer's owner requests it (`execute_by` policy).
5. **Separate gateway code.** `execution_gateway` does not import `dev_governance` (a test enforces
   this). It shares only the audit writer and the `PATIENCE_DEV_KILL` variable semantics (a test pins
   that both read the same values). The canonical payload hash is duplicated and a test pins equality
   with the gate's.
6. **Strict payload shape** (`invoice_id`, `payee`, `amount_usd` in (0, 1,000,000], USD, no extra
   fields) checked at propose time and again at the gateway.
7. **Verifier independence.** `tools/verify_audit.py` re-implements the documented record format
   with the standard library and is tested in `python3 -I` mode from outside the repo.

## Threat model

| Threat | Control | Tested |
|---|---|---|
| Agent calls payments directly | credential held only by the gateway's client; the HTTP payments app needs it | yes |
| Forged permit / wrong key / edited claims | Ed25519 signature, key-id keyring, signed claims | yes |
| Replay (also concurrent, also after restart) | atomic single-use nonce in durable SQLite | yes |
| Stolen permit used late | 5-minute expiry, `nbf`, max-lifetime check at the gateway | yes |
| Payload swapped after approval | payload hash bound in the permit and recomputed | yes |
| Another agent uses the permit | `sub` must equal the presenting agent id | yes (see limitation 3) |
| Permit used for another action | `act` binding + gateway action allowlist | yes |
| Runaway / emergency stop | `PATIENCE_DEV_KILL` blocks issuance and gateway execution | yes |
| Gateway bug, storage or audit outage | every error path rejects; accept requires a written audit record | yes |
| Audit tampering (edit, delete, insert, reorder, truncate) | hash chain + `.head`, independent verifier | yes |
| Self-approval / owner approval | existing gate rule; no permit without approval | yes |

## Known limitations (read these)

1. **Simulated only.** The "credential" is a random fake string; the ledger is an in-memory list. No
   real payment rail, no real credential, no network.
2. **Isolation is by convention in this mock.** The credential is a Python attribute in the same
   process. Code running in that process, or anyone who reads the machine's memory, can use it. A
   real deployment needs the gateway and the payments credential in a separate, network-isolated
   service with its own identity. This v0 is not that deployment.
3. **Agent identity at the gateway is asserted** (`X-Agent-Id`), not authenticated. A permit stolen
   together with its agent id works until it expires or is used. Plug a real authenticator into
   `create_gateway_app(agent_id_fn=...)`; mTLS or per-agent keys are not built.
4. **Key management is local files and environment.** The signing key is a 0600 file
   (`PATIENCE_PERMIT_SIGNING_KEY_FILE`, else `<gate db>.permit_key`); the gateway keyring comes from
   `PATIENCE_GATEWAY_PUBKEYS(_FILE)`. No HSM, no KMS, no rotation tooling (the gateway keyring accepts several key ids and a two-key test exists, but rotation is manual and not
   exercised end to end). Anyone who can read the
   signing key can mint permits.
5. **Agents could bypass everything if given the credential.** The control holds only because the
   gateway alone holds it.
6. **The audit log is tamper-evident, not tamper-proof.** Someone who can rewrite both the log and
   its `.head` file can forge a consistent chain; pin the head hash off-box and use
   `--expect-head` (tested, but no automatic off-box anchoring exists). The nonce store has
   append-only triggers, but its file owner can still edit it.
7. **A crash between burning the nonce and paying** loses that permit (fail closed); there is no
   automatic reconciliation for the payments service.
8. Single process tested; multi-worker behavior relies on SQLite atomicity and is only tested with
   threads in one process.
9. Clock skew tolerance is 5 s at the gateway; both sides must have sane clocks.
10. `pyproject.toml` `py-modules`/`packages` do not list `dev_governance` (pre-existing) nor
    `execution_gateway`; run from the repo checkout.

## Run it

```
python3 -m pytest -q tests/test_execution_gateway.py tests/test_verify_audit.py
python3 tools/verify_audit.py "$PATIENCE_AUDIT_PATH" [--expect-head <hash>] [--require-head]
```

Flow over HTTP (all simulated): `POST /v1/dev/check` -> a human approves -> `POST
/v1/dev/requests/{id}/permit` (same action and payload) -> `POST /v1/payments/pay` on the gateway app
with headers `X-Patience-Permit`, `X-Agent-Id` and body `{"action","payload"}`.
