# GitHub dry-run wiring (local branch `feat/completeness-pass`)

Status: experimental. Not a live GitHub integration. The audit log is append-only and
tamper-evident (hash chain); edits are detectable, not impossible. Nothing here is a readiness or
certification claim, and no live write to GitHub has been proven.

## What is wired

`api.dev_gate()` (the gate behind `/v1/dev/*`) now builds `DevGate` with
`dev_governance.wiring.api_adapters()`:

| Action | Adapter in the API | Behaviour by default |
|---|---|---|
| `code.get_repo`, `code.list_prs`, `code.get_pr_diff`, `code.open_pr` | `GitHubAdapter` | **dry run**: returns the exact request it would send plus `not_sent_because`; nothing is sent |
| `code.merge_pr`, `code.push_branch`, `code.force_push` | `SimulatedGitHubPRAdapter` | simulated only; there is no real merge or push path |
| deploy / destructive actions | existing simulated adapters | unchanged |

`DevGate()`'s own `default_adapters()` is unchanged (still simulated, no `GitHubAdapter`); only the
API wiring uses the real adapter. The API gate also uses the durable `CapabilityAuthority`
(`PATIENCE_DEV_AUTHORITY_DB`), as before.

Flow for every action: propose -> policy tier -> human approval -> execute bound to the approved
payload hash -> audit. Execute is limited to the proposer (or its owner); a proposer or its owner
cannot approve.

### When a network transport exists at all
`wiring.github_transport_from_env()` runs on every request:

- `PATIENCE_GITHUB_LIVE` not truthy: **no transport object is created.**
- `PATIENCE_GITHUB_LIVE=1`: a `UrllibTransport` (https://api.github.com only, no redirects, no env
  proxies, size cap). It is **GET-only** unless `code.open_pr` is in
  `PATIENCE_GITHUB_ACTION_ALLOWLIST` and `PATIENCE_GITHUB_REPO_ALLOWLIST` is non-empty.

### When `code.open_pr` is actually sent
Only if all of these hold (checked by the adapter, on top of the gate): `PATIENCE_GITHUB_LIVE=1`,
action allowlisted, repo allowlisted, request approved by a human, payload hash equals the approved
hash, `PATIENCE_DEV_KILL` off (re-checked right before sending), a transport, a fresh single-use
claim token minted by the gate for that request and payload, and `PATIENCE_GITHUB_TOKEN` present.
Otherwise the result is a dry run. A dry run does not consume the approval (it can be executed
again, still without sending); a real send does.

### Audit
`dev.proposed`, `dev.approved`, `dev.execute.claimed`, `dev.executed`. `dev.executed` now carries
`dry_run` (true when nothing was sent). Refusals audited: `dev.payload_mismatch`,
`dev.kill_switch.blocked`, `dev.authority.refused`, `dev.self_approval_rejected`, `dev.denied`.

## What is tested (`tests/test_github_dryrun_wiring.py`, all through `api.app`, sockets blocked, fake transport only)

1. Unapproved request: execute returns 202 pending, no claim, no transport call (also with every live
   prerequisite set). Denied request: 403, no transport call.
2. Altered payload/action after approval: 409, `dev.payload_mismatch` audited, approval left unused, no call.
3. Expired grant and 4. revoked grant (`test.run_isolated`, the only action that requires a grant):
   refused at propose and at execute, `dev.authority.refused` audited. A valid grant is the control.
5. `PATIENCE_DEV_KILL=1`: propose, approve and execute return 503, `dev.kill_switch.blocked`
   audited, no transport call, request left untouched.
6. Happy path: approved `code.open_pr` in default mode returns a dry run (no `Authorization` header in
   the preview, even with a token in the environment), no transport call, audit events in order,
   `audit.verify()` ok.
7. Without `PATIENCE_GITHUB_LIVE`: no transport is built or called for any of the four GitHub actions,
   even with allowlists and a token set; an adapter that is handed a transport still does not send a
   write. With all prerequisites a fake transport is called exactly once (positive control);
   removing the flag, either allowlist, or the token each stops the send.

## Limitations (honest)

- Not a live GitHub integration. No live write has been run or proven; tests use fakes and blocked
  sockets. The real transport exists but was not exercised against GitHub here.
- Dry run is the default and the only mode exercised. Live needs explicit environment settings.
- A GitHub action does not require a `CapabilityAuthority` grant: grants apply only to
  `test.run_isolated`. GitHub writes are gated by approval, allowlists and flags, not by a grant.
- Read actions only skip the network because the wiring creates no transport without
  `PATIENCE_GITHUB_LIVE`. `GitHubAdapter` given a transport directly (e.g. `tools/github_smoke.py`)
  sends reads without that flag by design; only writes need it at the adapter level.
- Through the API the server-side threat floor currently raises requests mentioning this repo name
  (and `/workspace/...` paths) to `high`, so even read actions need an approval. This is a
  classifier false positive that errs on the safe side; it was not changed here.
- Allowlists, the kill switch and the token are environment variables, not an admin-managed store.
- This is not an OS sandbox and does not stop an agent from bypassing PATIENCE and calling GitHub
  with its own credentials. Execution integrity is separate from audit integrity.
- Behaviour change: `code.open_pr` through the API used to be simulated (and single-use). It is now a
  dry run that needs `repo` as `owner/name` and a `title`; two existing API tests were updated for that.
