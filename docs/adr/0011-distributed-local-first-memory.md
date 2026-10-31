# ADR 0011: Distributed local-first memory, device identity and graduated autonomy

Status: Proposed (2026-10-31). Reconciled from Matthew McGuire's "ADR 003", written for PATIENCE Experimental v0.3.
**Numbering note:** that document's "ADR 003" clashes with this repo's ADR 0003 (gateway mode). In this repo it is ADR 0011; cite it as 0011.

## Context
v0.6 memory is a list of `{kind, content, confidence, timestamp}` dicts inside `patience_state.json` (`memory_store.MemoryStore.record_memory`). It has no class, scope, provenance or version, a single host, and no notion of devices. Autonomy is binary: the policy gate either allows an action or asks a human.

## Decision
1. **Six memory classes:** `working`, `project`, `episodic`, `long_term`, `pattern`, `governance`. Every record carries `sharing_scope`, `provenance` and `version`.
2. **Record contract:** `memory_id, record_type, content, source, confidence, classification, sharing_scope, project_id, created_at, updated_at, version, review_required, expires_at`, plus server-assigned `provenance`. Unknown class, scope, classification or field = reject (fail closed).
3. **Sync** (later) uses encrypted, versioned event records, never copies of database files.
4. **Device identity:** each device has a registered identity whose key is stored hashed. A revoked device is refused. Conflict detection (later) works on record versions.
5. **Presence states** (later): Observing, Analyzing, Coordinating, Waiting, Executing, Learning. They are driven only by real backend events, never simulated.
6. **Graduated autonomy, levels 0-4, per capability:**
   - Only a human approver grants a level, and never to themselves.
   - An agent can lower its own level but never raise it.
   - Revocation wins over any grant at the same or an earlier point.
   - Every level, including 4, still routes through `/v1/check`, so human approval can't be bypassed.

## Mapping onto v0.6
| ADR concept | v0.6 component |
|---|---|
| Memory store | new `memory_foundation/` SQLite DB; `memory_store.py` JSON state unchanged (migration of `state.memory` later) |
| Agent identity | `identity.py` agent keys; memory owner = `caller["id"]` |
| Device identity | new `devices` table, alongside agent keys (a device is bound to one owner identity) |
| Grant authority | `approvers.py` accounts via `require_approver` |
| Autonomy enforcement | `_check_impl` in `api.py` (the gate) |
| Accountability | `audit.py` chain (append-only and tamper-evident on one host; not immutable) |

## Consequences
- This adds a second store (SQLite) next to the JSON state. ADR 0008 and ADR 0010 should converge on one database.
- In this milestone, autonomy levels are recorded and checked but don't change gate outcomes. Deciding which policy outcomes a level may relax needs its own ADR, and approval stays mandatory.
