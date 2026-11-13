# Smarter Oracle, step 1: model adapter + structured recommendation (local branch `feat/oracle-step1`)

Status: **experimental, advisory only, not wired into the gate.** Nothing here is a readiness,
certification or compliance claim. The audit log is append-only and tamper-evident (hash chain);
edits are detectable, not impossible. Everything marked *tested* has a test in
`tests/test_oracle_step1.py` (offline: sockets are blocked for every test in that file).

Code: `dev_governance/oracle_advisor/` (`model.py`, `schema.py`, `service.py`, `routing.py`).
Design source: `patience-oracle-reasoning-design.md` (§3 model layer, §4 schema, §8 audit), cut down to step 1.

## What it does

```
caller-entered items ──> OracleService.advise ──> OracleModel (stub | local Ollama, opt-in)
                              │  bounded prompt, hard deadline, no tools
                              ▼
                  strict validation (size, encoding, strict JSON, schema, action catalog,
                  basis refs, injection scan, hint cap)
                     │ ok                          │ any failure
                     ▼                             ▼
          AdviceResult(recommended)       AdviceResult(no_recommendation, label "unknown")
          audit oracle.recommendation.created      audit oracle.recommendation.rejected
                     │
   propose_recommendation(gate, result, payload, proposer)   (explicit, caller-driven)
                     ▼
        DevGate.propose  ->  policy -> approval -> execute (payload-hash bound) -> audit   (unchanged)
```

The Oracle recommends; PATIENCE enforces. A recommendation is data. It never approves, denies,
executes, issues a permit, uses a capability grant, or lowers a tier.

## Architecture decisions

1. **New package, no gate changes.** `gate.py`, `policy.py`, `router.py`, `wiring.py` are untouched
   (a test asserts they do not mention the Oracle). Backward compatible by construction: if nobody
   calls the Oracle, nothing changes. Wiring into `propose` (so a hint can raise a tier automatically)
   is step 2.
2. **Provider-agnostic `OracleModel` protocol** (`generate(ModelRequest) -> ModelResponse`, raises
   `OracleModelError` with an enum `code`). Two implementations: `StubModel` (deterministic, offline,
   used by tests) and `OllamaModel` (local, opt-in). No hosted/cloud provider exists in this step, and
   no API-key handling exists.
3. **Ollama is off unless explicitly configured**: `PATIENCE_ORACLE=ollama` **and**
   `PATIENCE_ORACLE_OLLAMA_MODEL=<tag>` must both be set; `PATIENCE_ORACLE_OLLAMA_URL` defaults to
   `http://127.0.0.1:11434`. Only plain http to a loopback host is accepted (checked again in the
   constructor). Generic `OLLAMA_URL`/`OLLAMA_MODEL` are deliberately ignored. The stub cannot be
   selected from the environment.
4. **Schema is pydantic v2, strict, `extra="forbid"`** (`oracle-rec-v1`, review mode only). Fields:
   `action`, `rationale`, `basis[] {fact, source{kind, ref, quote?}}`, `confidence {level, reason}`
   (low/medium/high, **model-reported, not calibrated**), `unknowns[]`, `risk_hint {floor, reason}`,
   `assumptions[]`, `schema_version`. There is no field for approving, executing, tier, payload or
   plan steps, so smuggling one makes the whole output invalid. `pydantic` was already installed
   transitively (via fastapi) but was not listed; **this branch adds `pydantic>=2` to
   `requirements.txt`** (no new package installed). The design's `jsonschema` was not adopted.
5. **Action catalog from the gate**: `action_catalog(gate)` = policy actions + registered adapters +
   code-level floors + permit actions, minus `test.run_isolated` (it needs a scoped human capability
   grant a recommendation cannot carry). `none` and `ask_human` are always allowed and are never routed.
   An action outside the catalog rejects the whole recommendation.
6. **Raise-only, capped risk hint.** `cap_floor` caps a suggested floor at `high` (`low` = no hint);
   `effective_tier` = `tiers.raise_only(base, capped)`. A model alone can never produce `critical`.
   On routing, the capped floor is passed as the gate's existing `floor` argument, which
   `policy.assess` applies with `raise_only`. The uncapped suggestion is kept in the result/audit.
7. **Fail closed, no re-roll.** Timeout (hard thread deadline), busy (max 2 concurrent calls, never
   queued), adapter error, any exception, oversize or malformed output, schema violation, unknown
   action/ref, injection flag, model-id mismatch, kill switch on (`PATIENCE_DEV_KILL`: model not called),
   audit write failure: all give `no_recommendation` with a code and the label
   "unknown: no recommendation (fell back to deterministic policy)". There is no retry, so the model
   cannot be re-asked until it answers conveniently.
8. **Strict parsing**: the entire output must be exactly one JSON object (no prose or markdown fence,
   no duplicate keys, no NaN/Infinity). Control, bidi and zero-width characters are rejected. The
   deterministic `risk_policy.classify` injection flag on any output text rejects the output.
9. **Prompt**: only caller-entered items, in delimited blocks marked `trust=agent|human|gate` and
   labelled as data. `<<<` inside an item is neutralized so it cannot forge a block. No payload or item
   is truncated: over budget means the Oracle is skipped.
10. **Single integration point** `propose_recommendation(gate, result, payload, proposer, ...)`: calls
    `DevGate.propose` and nothing else on the gate (AST-tested). Payload and proposer come from the
    caller; the Oracle never invents a payload. Refuses (and audits `route_refused`) if the result is
    not a valid recommendation, is `none`/`ask_human`, is excluded, or has no proposer/payload. A gate
    refusal propagates unchanged.
11. **Audit** (via `audit.append`, hash-chained): `oracle.recommendation.created` (rec id, backend, model
    id, prompt hash, output hash, action, confidence level, suggested/applied hint, counts, context
    source ids, latency, schema/oracle/limits versions, `advisory_only`), `oracle.recommendation.rejected`
    (code enum + hashes), `oracle.recommendation.routed` (request id, payload hash, tier, status),
    `oracle.recommendation.route_refused`. Model free text and prompts are **not** logged.

## Tests (all in `tests/test_oracle_step1.py`)

Schema rejection (unknown/nested fields, missing, bad values, type coercion, bad refs/kinds, unknown
action, strict-parse cases, duplicate keys, oversize, encoding, invisible chars, injection); risk-hint
property test over every `(tier, floor)` pair; fail-closed adapter (error, arbitrary exception,
timeout, busy then recover, malformed output, model mismatch, too large, bad request, kill switch, no
retry); audit (fields, no free text, rejected events, chain verifies, unaudited rec not released,
tamper detected); Ollama (off by default, both settings needed, loopback-only, request shape without
tools, 13 failure modes, no redirects/proxies, bounded read); routing (pending proposal, nothing
executed even for auto-allowed actions, hint only raises and is capped, destructive guard still
refuses, non-recommendations refused, excluded action, no gate state change from advise, AST no-execute).
Mutation checks: see the completion report (each control was disabled and a test failed).

## Known limitations (honest)

- **Not run against a live Ollama.** Field names follow Ollama's public API docs; correctness against
  a real server is unverified. No model quality, latency or hardware fit has been measured.
- Recommendation quality is unmeasured; confidence is model-reported, not calibrated. A small model can
  produce schema-valid nonsense. The evaluation set is later work.
- **Not wired into `propose`**: a hint raises a tier only if a caller routes through
  `propose_recommendation`. A caller can ignore the Oracle or route an action unrelated to a
  recommendation by calling the gate directly (that is the pre-existing behavior).
- Routing a recommendation for a low-tier action (e.g. `ci.run`) gives an `allowed` request, because
  that is the existing policy (0 approvals). Routing itself never executes it.
- The timeout uses a daemon thread; a hung backend call cannot be killed, only abandoned. It keeps its
  concurrency slot until it ends, which bounds thread build-up to the slot count.
- Injection scan is the existing keyword classifier; it can false-positive and can be evaded.
- Prompt/ output raw text is not stored (no `oracle_records`); only hashes. A hash cannot be matched
  to text after the fact. Planned for step 2.
- No secret redaction before the prompt (step 2). Only the loopback local backend exists, so prompts do
  not leave the machine, but callers must not enter secrets as items.
- No per-agent rate limit, no daily raise budget, no two-level step limit on hints.
- Quotes in `basis` are checked as substrings but an unverified quote is counted, not rejected.
- `dev_governance` is not listed in `pyproject.toml` packages (pre-existing), so this package is not in
  a built wheel either.

## Remaining work (not started)

Context builder, redaction, `oracle_records`, gate hook inside `propose` (step 2); evaluation set and
measured model run; plan mode and per-step gating; approval cards, rubber-stamp detection, outcome
verification (later steps); hosted backend (explicitly out of scope unless Matthew asks).
