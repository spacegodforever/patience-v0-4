# Dev governance: development actions through the PATIENCE gate

Status: **experimental, simulation only.** Not production-ready and not a compliance control.
No adapter on this branch touches a real system or the network.

## Flow

```
propose -> policy tier (+ code floors, server threat floor, destructive guard, advisory,
ambiguity analysis, breaker) -> human approval -> execute (proposer/owner only, payload hash,
single-use claim token) -> audit
```

See `docs/catastrophe-guard.md` for the destructive guard, circuit breaker, advisory report and
language ambiguity analyzer.

1. **Propose** – an agent submits `action` + `payload` (`DevGate.propose`, or `POST /v1/dev/check`).
2. **Policy** – `policies/dev/default.yaml` assigns a tier: `low`, `medium`, `high`, `critical`.
   Tiers come from set rules, not a statistical model. On `POST /v1/dev/check` the server computes
   its own threat floor from the request text and payload (`dev_governance/threat.py`, same
   classifier as `/v1/check`; RT-11). Clients cannot supply or lower it. Code-level floors
   (`ACTION_FLOORS` in `policy.py`; RT-14) stop the YAML from lowering destructive or high-risk
   actions, even by leaving them out, and from loosening catastrophe or breaker limits.
3. **Approval** – `low` runs without a human; `medium`/`high` need one approver; `critical` needs
   two distinct approvers. Neither the proposer nor its owners can approve. Approvals expire
   after `approval_ttl_seconds` (default 3600). The expiry is HMAC-bound to the request (RT-08).
   An edited or missing signature, or a window longer than the TTL, expires the request (fail
   closed, `dev.expiry.tampered`).
4. **Execute** – the caller must resend the exact action and payload. The SHA-256 of the
   canonical action+payload must match what was approved, else **409**. Executing before enough
   approvals returns **202** (`pending_approval`). Each approval executes at most once.
5. **Audit** – every step (`dev.proposed`, `dev.approved`, `dev.self_approval_rejected`,
   `dev.payload_mismatch`, `dev.expired`, `dev.execute.claimed`, `dev.executed`,
   `dev.execute.failed`, `dev.denied`) is written to the existing `audit.py` log, which is
   **append-only and tamper-evident** (SHA-256 hash chain; `python audit.py verify`). It is not
   immutable: someone who can rewrite both the log and its head file can still alter it; ship
   it off-box to detect that.

## Policy pack (default tiers)

| Category | Action | Tier |
|---|---|---|
| CI | `ci.run`, `ci.rerun_failed` | low |
| Code / PRs | `code.open_pr`, `code.push_branch` | medium |
| | `code.merge_pr` | high |
| | `code.force_push` | critical |
| Deploys | `deploy.release` staging / prod | medium / **critical** |
| | `deploy.rollback` / prod | high / critical |
| DB migrations | `db.migrate` / prod | high / critical |
| Infra | `infra.apply` / prod | high / critical |
| Secrets | `secrets.read` / `secrets.rotate` | high / critical |
| Spend | `spend.charge` (>$500 or unparseable amount → critical) | high |
| Destructive | `db.drop/truncate/delete_rows`, `repo.delete`, `data.wipe`, `infra.destroy` | **critical** (+ destructive guard) |
| **Unknown** | anything not listed | **high, fail closed** (policy cannot set it to low) |

Unknown actions also have no adapter, so even after approval they return **501** and do nothing.

## Adapters (simulated)

`dev_governance/adapters.py` defines `Adapter.validate()` (checked at propose time) and
`Adapter.execute()`. Shipped:

- `SimulatedGitHubPRAdapter` – `code.open_pr / merge_pr / push_branch / force_push`; returns a
  description of what it *would* do and a fake reference. No GitHub API call.
- `SimulatedDeployAdapter` – `deploy.release / rollback`; returns a fake deployment id.

Adapter exceptions are audited as `dev.execute.failed` without echoing the exception text.

## Relation to other branches (overlap)

- **PR #10 `feat/risk-tiers`** adds tiers to the main `/v1/check` path. This branch carries its own
  tier logic in `dev_governance/policy.py`; once #10 merges, the two should share one tier engine.
- **PR #12 `fix/outbound-requires-approval`** adds outbound categories. Not needed here; dev
  actions have no auto-allow other than explicit `low` tiers.
- **`feat/threat-checker`** (local) produces a tier that can be passed as the `floor` argument.

## Known limits / what's left

- Gate state persists in SQLite (`PATIENCE_DEV_GATE_DB`). DB files, WAL/SHM sidecars and the
  key file are kept at 0600, including files that already existed (RT-09).
- `dev_governance/router.py` is mounted in `api.py` under `/v1/dev`, and uses
  `require_caller` / `require_approver`. The deprecated shared legacy approver token is never
  accepted there (RT-13).
- Live adapters: only `feat/github-adapter` (not on this branch). It is dry-run by default and
  needs a single-use claim token.
- Signing keys: `PATIENCE_CLAIM_SECRET` (≥32 chars) is recommended. Without it, a shared 0600
  key file `<gate db>.key` is used. Anyone who can read that file can sign expiries and claims.
- Tier cutoffs (e.g. $500) are judgment calls. Breaker defaults were tuned on simulated workloads
  only (`tools/sim_breaker.py`), not on real traffic.
