# Oracle Intelligence: implementation plan (v0.1 prototype and phases A-J)

Status: plan plus the first working core (see `docs/ORACLE_INTELLIGENCE_V0_1_REPORT.md` for what was
built and tested). Branch `feat/oracle-intelligence-v0.1`, off `feat/structured-outputs-audit-reports`
(3c4a2d1). Local only: nothing pushed, no PR, no deploy. The audit log is append-only and
tamper-evident; nothing in this plan claims readiness, certification or compliance.

## 0. Version mismatch finding

Execution Order 05 says "inside the existing PATIENCE v0.8.0 architecture". The repository does not
contain that version: `pyproject.toml` says `0.6.0`; `api.py`, `patience_cli.py` and `patience_mcp.py`
say `VERSION = "0.6"`; `git tag` lists no tags; no file mentions 0.8.0; the base lineage is
`v0.6-security-fixes` plus feature branches (`feat/dev-governance`, `feat/execution-gateway-v0`,
`feat/oracle-step1`, ...). I treated "v0.8.0" as the order's name for the current architecture and did
**not** bump any version string. Matthew should confirm whether v0.8.0 is a planned label or refers to
code that is not in this repository.

## 1. Scope limits (from the order and Matthew's rules)

- Strategic research means high-level public policy, economics and industrial capacity only. No
  targeting, no operational military content.
- No trades, no financial transfers, no account changes. Analysis output is information for a human.
- Never bypass authentication, paywalls or robots.txt. Only documented public APIs, authorized feeds and
  user-provided documents. No scraping connector exists or is planned.
- Retrieved documents are untrusted data. They can never change policy, permissions, approvals or tiers.
- Forecast probabilities come only from a documented statistical method, never from an LLM. In v0.1 no
  method is implemented, so hypothesis and forecast probabilities are `null` with a stated reason.
- No invented data. The only bundled data is a clearly labelled SYNTHETIC example fixture.

## 2. Existing reusable components (inspected)

| Component | Where | How Oracle Intelligence reuses it |
|---|---|---|
| Auth for HTTP | `api.py` `require_caller` (agent key or token), `require_approver` (named account, legacy token refused on dev routes), `require_admin` | New `/v1/intel/*` routes take the same injected dependencies as `dev_governance/router.py`. |
| Dev gate | `dev_governance/gate.py` `DevGate` (propose, policy, approval, execute) | Not used for read/analysis. Any future *action* an analysis suggests goes through `oracle_advisor.propose_recommendation` and the gate. Intelligence code never imports the gate (AST-tested). |
| Audit chain | `audit.py` `append/verify`, standalone `tools/verify_audit.py`, `tools/audit_report.py` | All source registration, ingestion, search, query and report-read events are appended. Ingest writes its audit event inside the DB transaction and rolls back if the audit write fails. `audit_report.py` categorizes unknown events as `other`; an `intel.*` category is later work. |
| Oracle adapter + schema | `dev_governance/oracle_advisor/` (`OracleModel`, `StubModel`, `OllamaModel` opt-in, strict parsing, injection scan on model output) | Optional model summary uses the same `OracleModel` interface and `oracle_model_from_env()` (off unless explicitly configured), with its own tiny strict schema. The pipeline works fully without a model. |
| `decision-v1` / `oracle-rec-v1` | `dev_governance/decision_schema.py`, `schemas/` | Pattern reused: strict pydantic, published JSON Schema generated from the model, test that files match. The new `intel-report-v1` schema is added to `tools/export_schemas.py`. |
| Redaction | `tools/audit_report.py` deny/allow-list redactor | `intel.*` event fields are hashes, ids and counts only (no document text or questions). |
| Injection classifier | `risk_policy.classify` (`flags` contains `injection`), used by `threat.py`, `oracle_advisor.schema` | Run over every ingested text field; flagged records are stored but **quarantined** and never retrieved into evidence. A small extra pattern list covers instruction-like phrases. |
| Storage pattern | `dev_governance/store.py` (`meta` table, `MIGRATIONS[i]` forward migrations, 0600 via `fsperm.secure_file`, `*.db` git-ignored) | The intelligence store follows the same pattern in its own SQLite file. |
| UI | Tracked Streamlit `dashboard.py` + `dashboard_auth.py` (named approver login; read-only without accounts) | Streamlit `pages/` entry (additive; `dashboard.py` untouched). The untracked `ui/` folder is not touched. |

Not reusable as is: `llm_adapter.py` (lenient JSON parsing, redirects followed, no size cap) and the
root rule-based `oracle.py` (unrelated name).

## 3. Architecture

```
 caller (agent/token) ──► /v1/intel (existing auth) ───────────────┐
 approver (named acct) ──► POST /sources (allowlist, owner, license)│
                                                                    ▼
 SOURCE ─► CONNECT ─► INGEST ─► NORMALIZE ─► VALIDATE ─► DEDUPLICATE ─► CLASSIFY ─► STORE ─► INDEX
 (registry) (file/manual;   (csv|json|text)  (types, dates,  (source_id +    (kind, tags,    raw table  term
  access     public-API stub  size caps        finite nums,    content hash)   injection ->    +processed  index
  list)      OFF by default)                   ts rules)                       quarantine)     table
                                                                    │
 question ─► INTERPRET ─► SELECT collections ─► RETRIEVE ─► EVIDENCE (ids, citations) ─► STATS ─► HYPOTHESES ─► REPORT
 (rules,     (access-filtered  (index +        (record ids,   (stdlib, deterministic,   (templated, competing, (strict
  no LLM)     sources)          date range)     provenance)    hashed)                   probability=null)      pydantic)
                                                                         optional: model summary (off), strict schema, labelled unverified
```

- New package `oracle_intelligence/` (store, models, sources, ingest, search, stats, inquiry, report,
  connectors, router, ui). `dev_governance/` is not modified.
- **Raw vs processed**: `intelligence_records` holds the record exactly as received (raw text, hashes,
  retrieval/publication times) with UPDATE and DELETE blocked by triggers; `intelligence_processed`
  holds normalized observations/documents and `intelligence_terms` the search index. Processing can be
  re-run from raw.
- **Determinism**: record ids derive from `(source_id, content_hash)`; statistics use only the standard
  library with fixed rounding; each report carries `data_snapshot_hash` and `reproducibility_hash`.
  Re-running the same question on the same data yields the same hash.

## 4. Source connector strategy

Three categories (from the order): `public_market` (public financial and market information),
`public_filings` (company filings and announcements), `internal_docs` (approved internal business and
logistics documents). Source kinds: `file_upload` and `manual` (implemented), `public_api` (interface +
stub, OFF).

1. A source must be **registered by a named approver** with owner, a license/authorization note and an
   explicit `allowed_callers` list (`["*"]` only if stated). Registration is audited.
2. `public_api` sources must be `https`, host in `PATIENCE_INTEL_API_HOSTS` (empty by default, so none
   register), and are fetched only when `PATIENCE_INTEL_CONNECTORS_LIVE=1` **and** a transport is
   injected. v0.1 ships no real transport, so there is no network code path. Only documented JSON/CSV
   APIs; no HTML scraping, no login or paywall handling, no robots bypass.
3. Candidate documented sources for later phases (to be checked against current terms before use, none
   verified here): SEC EDGAR submissions/companyfacts APIs (public, requires a declared User-Agent and
   rate limiting), central-bank and statistics-agency open-data APIs, and licensed market-data feeds the
   user already has rights to. Terms, rate limits and licensing must be read at implementation time.

## 5. Database changes

New SQLite file (`PATIENCE_INTEL_DB`, default `patience_intelligence.db`, git-ignored via `*.db`,
0600). Own `meta.schema_version` and forward `MIGRATIONS` (same pattern as the dev gate store); a newer
on-disk version than the code refuses to open. Existing databases (`patience_dev_gate.db`, authority,
breaker, nonce stores) and the untracked `patience_coordinator.db` are not touched.

- M1: `intelligence_sources`, `intelligence_records` (+ no-update/no-delete triggers),
  `intelligence_processed`, `intelligence_terms`, `intelligence_entities`, `entity_relationships`.
- M2: `analytical_queries`, `hypotheses`, `forecasts`, `forecast_outcomes`, `intelligence_reports`.
- Migration test: a DB at M1 with rows is opened by the new code, upgraded to M2, rows preserved.
- `forecasts` and `forecast_outcomes` exist but stay empty in v0.1 (no documented method implemented).

## 6. Data contracts (provenance)

Every raw record: `record_id`, `source_id`, `batch_id`, `raw_text`, `raw_format`, `content_hash`
(sha256 of canonical raw text), `provenance_hash` = sha256 over `(source_id, content_hash, batch_id,
retrieved_at, published_at or "unknown", parser_version)`, `retrieved_at` (server clock, never client
supplied), `published_at` (from the data, or NULL = unknown; never invented), `ingested_by`,
`quarantined`. Observations carry `obs_date` (the date the value describes), which is not a publication
time. Report contract `intel-report-v1` (strict pydantic, published JSON Schema): question,
interpretation, collections, evidence (ids, source, times, hashes, excerpt labelled untrusted), statistics
(method, parameters, version, result, evidence ids), hypotheses (supporting and contradicting evidence,
variables, assumptions, validation criteria, review date, probability or null + reason), missing evidence,
conclusions (each with >= 1 existing evidence id and a claim type of `descriptive`,
`statistical_association` or `context`; causal wording rejected), limitations, snapshot and
reproducibility hashes, `llm_used`.

## 7. Security requirements

1. Read, ingest and analysis require existing authentication; registering a source requires a named
   approver. Per-source `allowed_callers` filters ingest, search and inquiry; denials are audited.
2. Intelligence code has no path to approve, execute, change a tier, or touch permissions or the gate
   store (AST test). Oracle output may retrieve, interpret and recommend only.
3. Retrieved text is data: injection classifier + extra patterns at ingest; quarantined records are not
   returned as evidence or sent to a model; instruction-like text never alters behaviour (test).
4. Audit: source registered/refused, ingest batch (counts + batch hash), search, query, report read,
   access denied. Fields are ids, hashes and counts only. Ingest fails closed if the audit write fails.
5. Limits: 2 MB per ingest, 5,000 rows, field length caps, finite numbers only, UTF-8 only, date rules
   (unparseable or future-dated publication times rejected).
6. Network: none by default and none in tests; the public API connector is off and transport-injected.
7. No secrets in the DB or reports; no API keys exist in v0.1.

## 8. Model-selection strategy

The pipeline is deterministic and needs no model. Where a model helps (summarizing the already-selected
evidence), use the existing local-first `OracleModel` (Ollama opt-in, loopback only) with a strict
output schema, output validation, injection scan, and a label "model-written, unverified". A model never
supplies statistics, probabilities, conclusions or evidence ids that are not in the retrieved set.
Selection rule (unchanged from the Oracle design): smallest model whose measured results on a labelled
evaluation set beat the deterministic baseline; no model is evaluated yet. No cloud provider.

## 9. Testing plan

Unit and integration tests, offline (sockets blocked): source validation and access, provenance
recompute, duplicate ingestion, invalid data, timestamp handling, unauthorized access, missing
information, statistical reproducibility (golden values + re-run hash), evidence citation (every id
resolves; provenance verifies), prompt injection in retrieved documents, audit records and chain
verification, migrations preserving data, raw-table trigger protection, report schema strictness,
causal-wording rejection, optional model path (stub only), UI smoke via Streamlit `AppTest`, and
mutation checks on the key controls. Later: a labelled evaluation set and forecast-accuracy tracking.

## 10. Phases and complexity (S = days, M = 1-2 weeks, L = 3+ weeks; estimates, not measured)

| Phase | Content | Size | In v0.1 |
|---|---|---|---|
| A | Store, forward migrations, source registry, access lists | S | Done |
| B | Ingestion: csv/json/text, normalize, validate, dedupe, classify, quarantine | M | Done (PDF not done) |
| C | Index and retrieval, question interpretation (rules) | S | Done (term index, no semantic search) |
| D | Statistics engine (descriptive, change, MA, correlation, trend, missing, anomaly) | M | Done |
| E | Hypotheses, missing evidence, strict report, markdown render | M | Done (templated) |
| F | API, audit, governance wiring | M | Done |
| G | Streamlit page | S | Done (minimal) |
| H | Live documented-API connectors, rate limits, license checks, scheduling | L | Interface + OFF stub only |
| I | Forecasting with documented baselines, outcome recording, accuracy metrics | L | Tables only |
| J | Model-assisted interpretation, evaluation set, PDF path, hardening, intel report category in `audit_report` | L | Optional model hook only |

## 11. Minimal first prototype (what v0.1 is)

Register a source (approver) -> ingest the bundled SYNTHETIC CSV and documents -> ask "Identify emerging
trends across semiconductor companies and supply chains" -> evidence list with citations -> reproducible
statistics -> competing hypotheses with probability null -> structured report (JSON + Markdown) -> all
steps in the hash-chained audit log. Demo: `python3 tools/intel_demo.py`.
