# Oracle Intelligence v0.1: first working prototype (report)

Branch `feat/oracle-intelligence-v0.1`, local only (nothing pushed, no PR, no deploy). Companion plan:
`docs/ORACLE_INTELLIGENCE_IMPLEMENTATION_PLAN.md`. The audit log is append-only and tamper-evident. This
is a prototype for analysis on authorized data. It is not a forecasting product, and nothing here claims
readiness for production use or certification.

## What it does

A user can: register an authorized source (named approver), ingest a CSV, JSON or text document into it,
ask an analytical question, get traceable evidence, reproducible statistics and a strict structured report.

```
question -> collections (sources the caller may access) -> retrieve (series + keyword search)
   -> evidence list (ids, source, retrieved/published time, provenance digest)
   -> deterministic statistics -> competing hypotheses -> missing evidence -> intel-report-v1
```

The pipeline needs no model. An optional model summary exists (see Limitations) and is off by default.

## Features

- **Store**: own SQLite file (`PATIENCE_INTEL_DB`, default `patience_intelligence.db`, 0600), forward
  migrations v1 -> v2, refuses a newer DB. `patience_coordinator.db` is not touched.
- **Raw vs processed**: `intelligence_records` holds the raw item (write-once, UPDATE/DELETE blocked by
  triggers). Normalized observations/documents, the keyword index, entities and relationships are separate tables.
- **Sources**: categories `public_market`, `public_filings`, `internal_docs`; kinds `file_upload`, `manual`,
  `public_api`. Registration needs a named approver (legacy shared token refused), a license/authorization
  note and an explicit `allowed_callers` list. `public_api` needs an https host in `PATIENCE_INTEL_API_HOSTS` (empty by default).
- **Ingest**: validates every row (finite numbers, real dates, no future dates, size and row caps, duplicate
  JSON keys and NaN rejected), deduplicates by `(source, content hash)`, classifies, indexes. Invalid rows are
  rejected individually and reported. Duplicate ingestion is a no-op.
- **Provenance** on every record: source, retrieval time, publication time (NULL = unknown, never defaulted),
  content hash, provenance hash (recomputable with `verify_provenance`).
- **Prompt-injection handling**: all ingested text goes through `risk_policy.classify` plus an extra pattern list.
  Flagged records are stored but quarantined: not indexed, never retrieved, never in evidence or statistics;
  a count appears under missing evidence. Retrieved text is rendered as untrusted data only.
- **Statistics** (stdlib, deterministic, `stats-v1`): descriptive, percent change, moving average, linear
  trend (r2, direction), missing-period estimate, residual-based anomaly flag, Pearson correlation (levels and first differences).
- **Hypotheses**: templated from the statistics, each with supporting and contradicting evidence, variables,
  assumptions, validation criteria, review date (+30 days), `probability: null` with a reason. Trends and
  associations get a competing alternative. No causal wording (validator rejects it).
- **Report** `intel-report-v1` (strict pydantic, `extra=forbid`, JSON Schema in `schemas/`): every conclusion
  and hypothesis link must resolve to an evidence or statistic id, otherwise the report is not stored or returned.
  `data_snapshot_hash` and `reproducibility_hash` allow re-run comparison.
- **Governance**: endpoints use the existing `require_caller` / `require_approver`; the code never imports
  the gate (AST-tested). Registration, ingestion, search, query and report reads are audit events (ids,
  hashes and counts only, no question or document text).
- **UI**: `pages/1_Oracle_Intelligence.py` (Streamlit page, header ORACLE / INTELLIGENCE, counters, six-step
  pipeline, question, source and date selectors, evidence viewer, statistics, hypothesis board, missing evidence,
  Markdown download). Read-only when no approver accounts exist.

## Files

New: `oracle_intelligence/` (`__init__, common, store, sources, connectors, search, ingest, stats, report,
inquiry, router, ui`), `pages/1_Oracle_Intelligence.py`, `tools/intel_demo.py`, `examples/intelligence/*`
(SYNTHETIC data), `schemas/intel-report-v1.schema.json`, `tests/test_oracle_intelligence.py`, both docs.
Modified (additive): `api.py` (mounts the router at the end), `tools/export_schemas.py` (adds the schema),
`tests/conftest.py` (isolates `PATIENCE_INTEL_DB` per test). `dashboard.py` and the untracked `ui/` are untouched.

## Database changes

Nine tables as required: `intelligence_sources`, `intelligence_records`, `intelligence_entities`,
`entity_relationships`, `analytical_queries`, `hypotheses`, `forecasts`, `forecast_outcomes`,
`intelligence_reports`; plus `meta`, `intelligence_processed`, `intelligence_terms`. M1 creates the sources,
records, processed, index, entity tables; M2 adds queries, hypotheses, forecasts, outcomes, reports.
`forecasts` and `forecast_outcomes` exist but are empty in v0.1.

## Endpoints (`/v1/intel`)

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /sources` | named approver | register a source |
| `GET /sources` | caller | sources this caller may access |
| `POST /sources/{id}/ingest` | caller on the source's list | ingest csv/json/text |
| `POST /sources/{id}/fetch` | caller on the list | documented-API connector; 409 while it is off |
| `GET /records?q=` | caller | keyword search over accessible, non-quarantined records |
| `POST /inquiries` | caller | run the pipeline, return and store the report |
| `GET /reports/{id}?format=json|md` | caller | read a stored report |
| `GET /stats` | caller | counts for accessible sources and own queries/reports |

## Connectors

`PublicApiConnector` is an interface plus a stub: it needs `PATIENCE_INTEL_CONNECTORS_LIVE=1`, an injected
transport (none ships), an https allowlisted host, csv/json only and a size cap. Tests use local fixtures
only and block sockets. Before any real connector: documented public API terms, robots/rate-limit/User-Agent
policy, credential handling, per-source license record.

## Tests

New file `tests/test_oracle_intelligence.py`: 43 tests covering source validation, provenance, duplicate
ingestion, invalid data, timestamps, unauthorized access (library and HTTP), missing information, statistic
golden values and reproducibility (including two fresh processes with different hash seeds), evidence citation,
prompt injection (quarantine and query-time enforcement), audit records and fail-closed rollback, migration,
write-once triggers, connector off, optional model path, import boundary, demo run, UI smoke. Final full-suite
counts are in the hand-off report (baseline 938).

Mutation checks: 30 mutants of key controls were applied one at a time (access checks, quarantine in
ingest/search/series, dedupe, audit fail-closed, write-once triggers, causal regex, connector switch, future-date
and non-finite checks, published-time defaulting, probability rules, conflicting dates, legacy-token refusal,
report access check, model-output checks, provenance verify, size cap, public_api upload refusal, host
allowlist, link validators, reproducibility scope, query audit, stats scoping). All were killed. Four survived
the first pass and were closed: search and series quarantine (the index already excluded quarantined rows, so
tests now corrupt the index and check the query-time filters), the causal-regex mutant (my mutant was written
wrongly and did not disable the regex; rewritten, then killed) and the legacy-token check (the first test did
not prove the token was live; a positive control was added). The stats scoping check was added after review.

## Limitations (honest list)

- **Not done**: PDF ingestion (no PDF library in the repo; `pdftotext` is a box tool, not a dependency); a live
  connector (off, no transport); forecasts and forecast outcomes (tables only); entity types are all
  "unspecified"; entity and relationship extraction is limited to explicit fields; search is keyword-only, no embeddings.
- **No probabilities** anywhere: hypotheses carry `null` plus a reason. No significance tests. Trend and
  correlation are descriptive, never causal.
- **Question interpretation is rule-based** (entity names, vocabulary tags); a vague or unfamiliar question
  returns little or `insufficient_evidence`, stated in the report.
- **Optional model summary**: implemented through the existing `OracleModel` with strict schema, evidence-id,
  causal-wording and injection checks, labelled model-written and unverified, excluded from the
  reproducibility hash. It is off unless `PATIENCE_ORACLE` is configured, and it is only exercised in tests with `StubModel`.
- The injection classifier and extra patterns are best-effort; they can be evaded and can false-positive.
- The audit append happens inside the DB transaction but before COMMIT. A failed audit write rolls the data
  back; a commit failure after a successful append would leave an audit entry with no data row.
- A report's creator can always re-read it, even if their source access is later revoked.
- Access control is per source by caller id (`allowed_callers`); there are no roles or per-record ACLs.
- The default DB path is relative to the working directory (git-ignored via `*.db`); set `PATIENCE_INTEL_DB` for a fixed location.
- A `pages/` directory makes `dashboard.py` a Streamlit multipage app. That is additive and `dashboard.py` is unchanged.
- The UI test covers the read-only and locked states only; there is no signed-in run-inquiry test.
- The sample data is SYNTHETIC with fictional names. Nothing in the repo is real market data and no real source has been connected.
- `tools/audit_report.py` shows `intel.*` events under `other`; a dedicated category is later work.
- Version: the order says PATIENCE v0.8.0. The repository is 0.6.0 (`pyproject.toml`, `VERSION = "0.6"`), no tags,
  no 0.8.0 reference. No version was bumped. Matthew should confirm what v0.8.0 refers to.

## Demo

```
python3 tools/intel_demo.py          # temp DB and temp audit log; prints the Markdown report, then verifies the chain
python3 tools/intel_demo.py --keep /tmp/intel-demo
streamlit run dashboard.py           # then open "Oracle Intelligence" in the sidebar (sign in on the main page first)
python3 tools/export_schemas.py --check
```

API flow: `POST /v1/intel/sources` (approver) -> `POST /v1/intel/sources/{id}/ingest` -> `POST /v1/intel/inquiries`
`{"question": "..."}` -> `GET /v1/intel/reports/{id}?format=md`.

## Next milestone (proposal, not started)

1. A documented-public-API connector for one named source with a recorded license, robots/rate-limit policy and
   a real transport behind the allowlist. 2. A documented forecasting method (for example a naive or ETS baseline
   with backtest error) writing to `forecasts` and `forecast_outcomes`, with probabilities only from it.
3. PDF ingestion once a dependency is approved. 4. `intel.*` category in the audit report, and a signed-in UI test.
