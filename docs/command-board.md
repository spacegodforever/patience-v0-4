# Command Board (merged into PATIENCE)

Ported from the Oracle + PATIENCE Operations Matrix app into `command_board/`.

- Routes: `/v1/board/*` (50 routes). Page: `GET /board` (static HTML, no data; same origin).
- Auth: same as the coordinator. Agent key / API token / `PATIENCE_DEV_OPEN=1` via `api.require_caller`,
  or an approver session from `POST /v1/coordinator/session` (cookie now scoped to `/v1`) with
  `X-CSRF-Token` on writes. No auth configured -> 401 (fail closed).
- Writes (POST/PUT/PATCH/DELETE): all DB work in a request shares one deferred-commit connection
  (`command_board/uow.py`); the commit happens only after `audit.append("board.write" | "board.seed")`.
  Audit failure -> rollback + 503. The audit log is append-only and tamper-evident (hash chain), not immutable.
- `source` on employment, economic signals and market exposures is set by the server to `<mode>:<id>`;
  client values are ignored. `evidence_source` (customer influences) is treated as evidence content, not identity.
- `/v1/board/seed`: only with `PATIENCE_DEV_OPEN=1` or an approver session; refusals are audited.
- Advisory: every response carries `X-Patience-Advisory: true` and JSON objects carry `patience_advisory`.
  Board scores, lanes and its own "patience" assessment never replace `/v1/check` or a human approval.
- No route performs a consequential or external action (no network, mail or process calls), so nothing
  is routed through `_check_impl`; any future action must be added as a `_check_impl` preview.
- DB path: `PATIENCE_BOARD_DB` (default `patience_board.db`, gitignored). Server binds 127.0.0.1 by default.
