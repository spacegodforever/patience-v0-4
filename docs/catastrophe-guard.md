# Catastrophe guard (dev governance)

Layers that make it hard for an agent to do something huge and irreversible, like wiping a
company's data, in a few seconds. Everything here is deterministic and simulated (no network).
The audit log is append-only and tamper-evident. This is a safety layer under active
development; it has not been audited.

Flow: `propose → policy tier → destructive guard → advisory (+ language analysis) → breaker →
approve (N distinct humans, not proposer/owner) → execute (proposer/owner only, claim token) → audit`.

## 1. Execute authorization (RT-07)
Only the proposer may execute. If `execute_by: proposer_or_owner` (the default) is set in
`policies/dev/default.yaml`, the proposer's owners may execute too. Anyone else gets
**403** and `dev.execute.forbidden` is audited.

## 2. Claim tokens (RT-10)
When the gate claims a request, it mints `v1.<rid>.<payload_hash>.<exp>.<nonce>.<hmac>` and
passes it to the adapter. The token:
- is single-use (nonce is burned when verified);
- is bound to that request ID and payload hash;
- lives 60 s;
- is signed with HMAC-SHA256 using `PATIENCE_CLAIM_SECRET` (≥32 chars, otherwise a random
  per-process key).

Live adapters (`live=True`) must call `claims.verify_claim(ctx, payload_hash)` themselves,
before any I/O, using a hash they recompute from what they are about to send. A missing,
reused, expired, or mismatched token raises `ClaimError`.

## 3. Destructive guard (`dev_governance/destructive.py`)
**What counts as destructive:**
- Always: `db.drop`, `db.truncate`, `db.delete_rows`, `repo.delete`, `code.force_push`,
  `data.wipe`, `infra.destroy`, `secrets.rotate`.
- When the environment is production or unrecognized: deploy, migrate, and `infra.apply`.
- When payload text matches DROP/TRUNCATE, DELETE without WHERE, `rm -rf`, force push, or
  `terraform destroy`.

**Required fields.** Each of these is fail-closed: if it is missing, the request gets **422**
and `dev.destructive.refused` is audited.
- `rollback_plan`: at least 20 characters.
- `backup.snapshot_id` or `backup.evidence`.
- `blast_radius {rows, resources}`.

**Tier and approvals.** A destructive request is forced to the critical tier, which needs
≥2 approvers.

**Blast-radius limits** (defaults 10 000 rows / 10 resources):
- Over the limit: needs 3 approvers.
- More than 10× the limit: refused, and the change must be split.

All of this is configured under `catastrophe:`.

## 4. Circuit breaker and kill switch (`dev_governance/breaker.py`)
The breaker works per agent, over a rolling window (default 300 s). It trips when the agent
goes past either limit:
- more than `max_high_proposals` (default 5) high or critical proposals;
- more than `max_anomalies` (default 3) refused or destructive-guard failures.

**When it trips:**
- `dev.breaker.tripped` is audited.
- The agent is frozen: its propose, approve, and execute calls return **423**.
- Its existing pending and approved requests are held, not consumed.

**Reset.** Only a human approver can reset the breaker, via
`POST /v1/dev/breaker/{agent}/reset`; agent bearer tokens are refused. The reset is audited as
`dev.breaker.reset`. `GET /v1/dev/breaker/{agent}` shows the agent's state.

**Persistence.** State persists in sqlite when the gate DB is configured.

**Global kill switch.** `PATIENCE_DEV_KILL=1` makes every propose, approve, and execute call
return **503**.

## 5. Advisory report (`dev_governance/advisory.py`)
A deterministic report is attached as `advisory` to every request that needs approval. It
contains these fields:
- `what_could_go_wrong`
- `blast_radius`
- `reversibility`
- `rollback`
- `backup`
- `threat_floor`
- `warnings`
- `unknowns` (labeled explicitly)
- `basis`
- `confidence`

`threat_floor` goes through `tiers.raise_only`. It can raise the tier, for example to critical
for irreversible actions or high for partially reversible ones. It can never lower the tier.

## 6. Language ambiguity analyzer (`dev_governance/ambiguity.py`, rules in `policies/dev/ambiguity.yaml`)
**Input.** The optional `text` on `POST /v1/dev/check` (or `propose(..., text=)`), plus the
payload.

**What it flags:**
- **Ambiguous verbs** (clean up, reset, remove, sync, fix). Each verb has interpretations
  ranked from least to most destructive, and the one the payload matches is marked.
- **Unbounded scope** (all, every, everything, prod…), or text with no table, repo, date, or
  id limit.
- **Pressure or coercion wording** (urgent, immediately, skip review, just do it…). This
  raises the tier and never shortens review.
- **Text vs. payload mismatch.** Any of:
  - the payload takes the most destructive reading;
  - the payload is destructive but the text never says so;
  - the text implies small scope but the payload declares a large blast radius.

**Output.** Warnings, labeled unknowns, basis, and confidence, all fed into the advisory.

**Limits.** It can only raise the tier or add warnings. Rules live in YAML; set
`PATIENCE_AMBIGUITY_RULES` to point at a different file.

## Known gaps
- Claim nonces are kept in memory, per process. Multiple workers need a shared nonce store.
- The analyzer matches keywords, not meaning. An adversary can word around it, which is why
  it can only add friction and never remove it.
- RT-08, RT-09 (partial), RT-11, RT-13, RT-14, RT-15 remain open.
