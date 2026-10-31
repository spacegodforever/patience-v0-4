# Design: memory foundation (ADR 0011)

Status: milestone M1 is implemented on local branch `feat/memory-foundation`. Everything else here is **proposed**.

## M1 scope (implemented)
- `memory_foundation/db.py`: SQLite (WAL) at `PATIENCE_MEMORY_DB`, with forward-only numbered migrations in `schema_migrations`. A DB whose schema is newer than the code refuses to open. CHECK constraints repeat the contract enums as a second line of defence.
- `memory_foundation/contract.py`: the `MemoryRecordIn` Pydantic model (strict, `extra="forbid"`).
  - Clients may not set `memory_id`, `version`, timestamps or provenance.
  - `project` scope or class requires `project_id`.
  - `governance` and `pattern` records are always `review_required`.
- `memory_foundation/store.py`: records, devices and the permission registry. Every write and its audit append share one SQLite transaction, so if the audit append fails the write rolls back.
- `memory_foundation/routes.py`, mounted in `api.py`:

| Route | Auth | Effect |
|---|---|---|
| `POST/GET /v1/memory/records` | agent (`require_caller`) + optional `X-Device-Id`/`X-Device-Key` | write/list own records; unknown/revoked/foreign device = 403 |
| `POST /v1/devices`, `POST /v1/devices/{id}/revoke` | approver | register (key shown once, stored sha256) / revoke |
| `POST /v1/capabilities/{cap}/grant` | approver | set level 0-4; self-grant refused + audited |
| `POST /v1/capabilities/{cap}/revoke` | approver | revoke |
| `POST /v1/capabilities/{cap}/self-revoke` | agent | lower own level to 0 (never raise) |
| `GET /v1/capabilities/{cap}/level` | agent | effective level |
| `POST /v1/capabilities/{cap}/request` | agent | level >= 1 required; **always** calls `_check_impl`; never executes |

- **Registry semantics:** grants and revokes are append-only events in `capability_events`.
  - The effective level comes from the latest event.
  - A revoke with the same timestamp as a grant wins.
  - With no events, the level is 0.
- **Audit events:** `memory.written` records only a hash of the content. The others are `device.registered`, `device.revoked`, `capability.granted`, `capability.revoked` and `capability.grant_refused`.

### Autonomy levels (labels; semantics beyond M1 are proposed)
0 suggest only, 1 draft for review, 2 act on approval, 3 act within policy limits, 4 act with post-hoc review. In M1, a level only decides whether `/request` may reach the gate. The gate's outcome is unchanged, and a $5,000 refund at level 4 still returns `needs_approval`.

### Known limits in M1
- Self-grant detection compares names only (approver `alice` vs. subject `alice` / `user:alice`). An agent-to-owner mapping is plan item C2.
- A crash between the audit append and COMMIT can leave an audit entry for a write that rolled back. That is the same class of issue as audit finding O3.
- Records are visible only to their owner. Project and team scopes are stored but not yet used to share anything.
- `expires_at` is stored but not enforced.
- `state.memory` from v0.6 has not been migrated.

## Later (not implemented)
- **Sync:**
  - encrypted, versioned event records (per-record version vector or Lamport clock), signed by the device key
  - transport through the durable outbox from `design/ingestion.md`
  - never copies of DB files
- **Conflict detection:** concurrent versions produce a `conflict` record with `review_required` set; no automatic merge for `governance` records.
- **Presence UI:** the six states, derived from audit and queue events; no synthetic states.
- **Key handling:** device keys become asymmetric (signing) keys; rotation; revocation propagates through sync.
- **Retention:** enforce `expires_at` and purge per classification.

## Implementation plan (sequenced after F1-F6)
| ID | Item | Size | Proving tests |
|---|---|---|---|
| M1 | Schema + migrations, contract, devices, permission registry, audit (done locally) | M | `tests/test_memory_foundation.py` (28) |
| M2 | Migrate `state.memory` into `memory_records` (one-shot, idempotent) | S | legacy entries imported once, classified `working`/`internal`, provenance `legacy` |
| M3 | Agent-to-owner mapping; self-grant covers owner too | S | owner of agent X cannot grant X |
| M4 | Expiry enforcement + review queue for `review_required` | M | expired records hidden; governance record needs approver review |
| M5 | Signed event log + sync over outbox; conflict records | L | two devices' concurrent edits produce a conflict; revoked device events rejected |
| M6 | Presence states from real events + UI | M | state changes only on audited backend events |
| M7 | ADR for level semantics (what a level may relax) | S | level-3 within-limit action remains gated by policy; approval never skipped |
