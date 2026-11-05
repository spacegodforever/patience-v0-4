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
- lives 60 s, with up to `PATIENCE_CLAIM_SKEW` seconds of clock skew tolerated (default 5,
  max 30). Expiries further in the future than TTL + skew are refused;
- is signed with HMAC-SHA256 using `PATIENCE_CLAIM_SECRET` (≥32 chars). Without it, the key is a
  shared 0600 file `<gate db>.key`, or a random per-process key for in-memory gates.

Used nonces are recorded in memory and in the shared SQLite table `dev_claim_nonces`, via an
atomic primary-key insert. A token used by one worker is therefore refused by every other
worker. If the nonce store errors, the token is refused (fail closed).

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
The breaker works per agent, over a rolling window (default 600 s). It trips when the agent
goes past either limit:
- more than `max_high_proposals` (default 8) high or critical proposals;
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

**Tuning (simulated, `tools/sim_breaker.py`).** Grid search picked the defaults on tuning seeds,
and they were then measured on separate held-out seeds (200 sessions per workload):

| Config | False trips on benign sessions | Runaways caught within 20 events | Median events to trip |
|---|---|---|---|
| old 300 s / 5 / 3 | 30% (release trains 58.5%, batch migrations 61.5%) | 100% | 3–7 |
| **new 600 s / 8 / 3** | **0%** | **100%** | 3–9 (slow drip: 9 events, ~5 min) |

The benign workloads are release trains, steady work, batches of up to 7 migrations, and sloppy
retries. The runaways are a tight loop, a slow drip, a refusal loop, and mixed spray. These
shapes are assumptions, and the clean separation partly reflects that. The margin is thin: at
8 high proposals, a benign burst of 9 or more within 10 minutes would trip it.

**Blast radius.** The defaults stay at 10 000 rows and hard factor 10. The policy floors (RT-14)
cap them there; they can only be tightened. In simulation (lognormal targeted cleanups vs.
whole-table runaways):
- 10 000/10: 3.2% of benign operations need 3 approvers, 0% are refused, and 99.9% of runaways
  are refused.
- 5 000/10: benign 3-approver rate rises to 8.5%, and 0.2% of benign operations are refused,
  with no runaway gain.

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

**v2 evasion hardening.** Text is normalized first:
- NFKC;
- zero-width and format characters stripped;
- case folded;
- Cyrillic and Greek homoglyphs and leetspeak folded;
- spaced or dotted letters re-joined.

Matching then works per token, with bounded typo tolerance: 1 edit for words of 5+ letters,
2 edits for 9+; shorter words are never fuzzed. On top of that:
- Synonyms map to the canonical verbs.
- Negated destructive wording ("don't delete anything") does not count as acknowledgement, and
  is a mismatch when the payload is destructive.
- Free-text payload fields (`note`, `description`…) are scanned with the text.
- An ambiguous verb is no longer treated as acknowledging a destructive payload.
- New mismatch checks: wrong table, and partial-scope wording against a whole-object action.

**Scoring.** Signals add YAML `weights`, and `thresholds` map the score to a tier. Any mismatch
is always critical.

**Measured on `tests/data/ambiguity_corpus.yaml`** (137 cases, fixed split by sha256(id) mod 3).
"Flagged" means floor ≥ high or a mismatch warning:

| Split | Risky caught (recall) | False positives on benign | Precision |
|---|---|---|---|
| v1 baseline, dev | 43/54 (0.796) | 0/35 | 1.0 |
| v1 baseline, holdout | 19/23 (0.826) | 1/25 | 0.95 |
| **v2, dev (tuned on)** | **53/54 (0.981)** | **0/35** | 1.0 |
| **v2, holdout (not tuned on)** | **21/23 (0.913)** | **0/25** | 1.0 |

The remaining misses are honest-sounding wording with a vague or different object: "shred the
archive", "nuke the staging data", and "D.R.O.P the table" against a different table.

Caveats:
- The corpus was written by the same author as the rules, so even the holdout is not
  independent.
- The baseline holdout errors were seen once before tuning began.
- Run `python tools/eval_ambiguity.py` to reproduce.
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
- The analyzer matches keywords, not meaning. Paraphrase, other languages, and splitting a word
  across fields can still get past it, which is why it can only add friction and never remove
  it. The corpus is small (137 cases) and was written in-house.
- Breaker and blast-radius tuning is based on simulated workloads only.
- Anyone who can read the key file can forge expiry signatures. Use `PATIENCE_CLAIM_SECRET`
  from a secret store.
- No Hacksaw findings are open on this branch.
