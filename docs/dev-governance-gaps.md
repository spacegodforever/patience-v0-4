# Dev governance: assessment of the four gaps

Branch `feat/dev-governance` (local). Status: experimental, simulation only. Not production-ready,
not a compliance control. The audit log is append-only and tamper-evident (hash chain), not immutable.

Order chosen: **1 → 2 → 4 → 3**. Durable state (1) must exist before the API (2) is meaningful,
because a per-process in-memory gate behind an HTTP server loses approvals between requests or workers.
Unifying tiers (4) is low effort and should land before #10 merges, to avoid two engines drifting.
Live adapters (3) come last and only behind everything above.

---

## Gap 1: gate state was in memory only — FIXED

- **Risk if left:** a restart lost every pending and approved request. Worse, with several workers,
  one process could hold an approval that another did not see, and there was no cross-process
  "execute once" guarantee.
- **Fix:** `dev_governance/store.py`.
  - `SqliteStore` (stdlib `sqlite3`) at `PATIENCE_DEV_GATE_DB` (default `patience_dev_gate.db`).
    The repo has no prior SQLite helper for gate state, so this is new; it follows the same
    "env var path, private local file, git-ignored" pattern as the JSON state and the audit log.
  - Schema versioned in a `meta` table; `MIGRATIONS[i]` upgrades version i → i+1. An empty or
    pre-versioned file is migrated; a DB with a *newer* schema is refused.
  - `MemoryStore` fallback with `PATIENCE_DEV_GATE_DB=":memory:"` (and the default for a bare
    `DevGate()` in unit tests).
  - Every state change is written immediately. Execution uses an atomic compare-and-set
    (`UPDATE … WHERE status=? AND payload_hash=?`), so only one process can claim a run.
  - The payload hash is stored as a column and inside the body; a mismatch makes the row unusable.
  - `.gitignore` now ignores `patience_dev_gate.db` and `*.db` (+ journal/WAL/SHM).
- **Effort:** small (~1 day). Done.
- **Tests** (`tests/test_dev_governance_gaps.py`): survives restart; payload hash enforced after
  reload (409); expiry enforced after reload; two approvals accumulate across restarts and the same
  approver can't count twice; execute-once across restart; compare-and-set claim; migration from an
  empty v0 file; newer schema refused; tampered row refused; memory fallback; default is SQLite.
- **Remaining:** approve is read-modify-write without a cross-process lock; two simultaneous
  approvals in different processes could lose one (fails safe: it needs re-approval, never runs early).
  No retention/cleanup of old rows yet.

## Gap 2: router not wired; identity came from a header — FIXED

- **Risk if left:** the `X-Patience-User` header let any caller claim to be any approver, which
  would make the gate decorative.
- **Fix:** `api.py` mounts `/v1/dev/*` with the existing `require_caller` (propose, status,
  execute) and `require_approver` (approve, deny). The router takes identity only from injected
  dependencies; the header was removed entirely (not just test-gated). The proposer id is the
  authenticated caller id; the approver is the approvers.yaml user. Self-approval is still blocked
  when they match.
- **Effort:** small. Done.
- **Tests:** unauthenticated propose/status/execute → 401 and approve → 403; `X-Patience-User` is
  ignored; an agent bearer key can't approve; wrong password can't approve; self-approval via the
  API → 403 and audited; full flow 202 → approve → 409 on changed payload → 200 → 409 on reuse,
  with the audit chain verifying.
- **Remaining:** agent ids and approver usernames are separate namespaces, so "self" means the
  same string. A mapping (agent X is operated by human Y) is needed to block a human approving their
  own agent's proposal. Dev requests aren't shown on the Command Board / dashboard yet, and no
  notification is sent for them.

## Gap 3: no live adapters — DESIGN ONLY (no live network code on this branch)

- **Risk if left:** the gate governs only simulations, so it can't yet stop a real action.
  Risk if done badly: a live adapter with broad credentials is a bigger hazard than none.
- **Design: first live GitHub PR adapter, in three stages, each a separate PR needing Matthew's yes.**
  1. **Read-only.** `GitHubReadAdapter` for `code.read_pr` / `code.list_prs` (low tier). Proves auth,
     transport and error handling with no writes. Token scope: fine-grained PAT or GitHub App
     installation token limited to the named repos, `Pull requests: read`, `Contents: read`.
  2. **Dry-run.** `code.open_pr` builds the exact HTTP request (method, URL, JSON body) and returns it
     plus a diff preview without sending it. Dry-run is the default; the result says
     `"dry_run": true`. The approver sees the exact request whose hash is approved.
  3. **Gated writes.** Live sending only when *all* hold: `PATIENCE_DEV_LIVE=1`; the action is listed in
     a per-adapter allowlist (start with `code.open_pr` only, never `merge`/`force_push`); the repo is
     on an allowlist; the request is approved and the payload hash matches; the kill switch is off.
     Merges stay simulated until a separate review.
- **Credentials:** read from env or a secret store at execute time only (`PATIENCE_GITHUB_TOKEN` or a
  secret-manager reference), never from the payload, never written to state, audit or logs. Error
  messages are summarised by type (as the current adapter-failure path already does). Least
  privilege: fine-grained token or GitHub App, single repo, write only `Pull requests`; short
  expiry; rotation documented. `secrets.read` itself remains a high-tier gated action.
- **Kill switch:** `PATIENCE_DEV_KILL=1` (and an admin endpoint that sets a flag in the gate DB)
  makes every live adapter refuse with 503 and audit `dev.killed`, checked immediately before the
  network call, not only at startup.
- **Tests (mocked transport only):** adapters take an injected transport (e.g. `httpx.MockTransport`);
  sockets stay blocked. Cover: read-only call shapes; dry-run never calls the transport; live
  refused without each of the flags; kill switch checked at send time; token never appears in the
  result, audit or exception text; repo/action allowlists; 4xx/5xx mapped to audited failures;
  idempotency (no duplicate PR on retry, using a client-side marker in the PR body).
- **Effort:** medium (~3–5 days across the three stages, plus review).

## Gap 4: two tier engines (this branch vs PR #10) — FIXED (shared module + merge plan)

- **Risk if left:** `/v1/check` and `/v1/dev` could disagree about what "critical" means, or one
  could get a fail-safe fix the other lacks.
- **Fix:** new top-level `tiers.py` with `TIERS = ("low", "medium", "high", "critical")` (identical
  to #10), `normalize` (unknown → high, the same fail-safe as #10's `risk_tier`), `rank`,
  `max_tier`, `raise_only` (threat floor can only raise) and `approvals_required`.
  `dev_governance/policy.py` now uses it. Policy files can't lower critical below 2 approvers or
  medium/high below 1. A bogus floor value now raises to high instead of being ignored.
- **Merge/rebase plan:** no other branch was modified. Checked in a throwaway worktree:
  merging `feat/risk-tiers` into this branch gives two trivial "keep both" conflicts
  (`.gitignore`, `tests/conftest.py`), and the merged tree passes **372** tests. Then the one-line shim
  in `risk_policy.py` — `from tiers import TIERS` instead of its own tuple — also passes 372.
  Plan: merge #10 first; then rebase this branch onto the result, resolve the two conflicts by
  keeping both lines, and add the shim in this branch's commit (so #10 itself is untouched).
  A follow-up can move `risk_tier`'s rank/max loop onto `tiers.max_tier`.
- **Effort:** small. Done (shim is planned, not committed, because #10 isn't on this base).
- **Tests:** shared tuple matches #10; fail-safe helpers; dev policy uses the shared module; policy
  can't weaken approval counts; bogus floor → high.

## Overlaps

- PR #10 (`feat/risk-tiers`): see gap 4.
- PR #12 (`fix/outbound-requires-approval`): not needed; no overlap in files.
- `feat/threat-checker` (local): its tier feeds `assess(..., floor=...)`.

## Red-team fixes (Hacksaw review of b97aab9, branch fix/dev-governance-redteam)

| Finding | Fix | Regression tests (tests/test_dev_governance_redteam.py) |
|---|---|---|
| RT-01 critical: blind INSERT OR REPLACE | Schema v2 adds `version`; all writes are CAS (`UPDATE ... WHERE version=? AND status NOT IN terminal`); inserts never replace; execute claims `executing`; one shared SqliteStore per process; new DB chmod 0600 | test_rt01_* |
| RT-02 high: approve RMW | approve/deny/expire run in a re-read/re-validate CAS retry loop; concurrent approvals all land | test_rt02_* |
| RT-03 high: owner self-approval | `owners` recorded at propose (agents.yaml `owners:`/`owner:`, token mode `PATIENCE_API_TOKEN_OWNERS`); owners get 403 (`owner_of_proposer`); non-low proposals without an owner mapping are refused (403) except in PATIENCE_DEV_OPEN dev mode | test_rt03_* |
| RT-04 high: environment aliases | `normalize_environment`: anything prod/prd/live-like -> production -> critical; only an allowlist (dev/test/qa/staging...) is non-prod; missing/unknown env -> critical | test_rt04_* |
| RT-05 high: MemoryStore TOCTOU | MemoryStore is lock-protected CAS | test_rt05_* |
| RT-06 high: hash canonicalization | strict canonical JSON (no default=str, no NaN, string keys); 422 on non-JSON; hash computed from the stored body | test_rt06_* |
| RT-12 medium (fixed in passing) | execute claims only from allowed(0 required)/approved(with enough distinct approvals) | test_rt12_* |

Follow-up on `feat/catastrophe-guard`:

| Finding | Fix | Tests |
|---|---|---|
| RT-07 | execute bound to proposer (or owner per `execute_by`); others 403 + `dev.execute.forbidden` | test_catastrophe_guard.py test_rt07_* |
| RT-08 | request expiry HMAC-bound (`expiry_sig`); tampered/missing/over-TTL → expired (`dev.expiry.tampered`); claim tokens tolerate ≤`PATIENCE_CLAIM_SKEW` (default 5 s, max 30 s) skew and refuse far-future expiries | test_redteam_followup.py test_rt08_* |
| RT-09 | DB, WAL/SHM, breaker DB and key file re-permissioned to 0600 on every open (existing files too) | test_rt09_* |
| RT-10 | single-use, request+payload-bound HMAC claim tokens; used nonces persisted in the shared SQLite DB | test_catastrophe_guard.py test_rt10_*, test_claim_* |
| RT-11 | server-side threat floor on `/v1/dev/check` (text + payload), raise-only, not client-settable | test_rt11_* |
| RT-13 | legacy shared approver token: explicit flag + ≥32 chars, never on `/v1/dev/*` | test_rt13_* |
| RT-14 | code-level action floors; catastrophe/breaker limits and `execute_by` clamped; clamps audited | test_rt14_* |
| RT-15 | docs refreshed (this file, dev-governance.md, SECURITY.md, catastrophe-guard.md) | — |

No Hacksaw findings are open on this branch. Remaining limits are listed in
`docs/catastrophe-guard.md`.
