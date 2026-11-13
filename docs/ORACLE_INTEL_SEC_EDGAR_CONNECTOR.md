# Oracle Intelligence: SEC EDGAR connector (first real public data source)

Branch `feat/oracle-intel-sec-edgar` (off `7831a4c`, Oracle Intelligence v0.1). Local only; not pushed.
Read-only, fetch-only, **off by default**. Nothing here approves, executes, changes risk tiers or touches the dev gate.
This is a prototype connector. It is not production-ready, and nothing here is a compliance claim.

## What it does
Fetches two documented SEC endpoints on explicit request and feeds them through the existing Oracle Intelligence pipeline:

| dataset | URL template (built server-side; callers pass only a CIK) | becomes |
|---|---|---|
| `companyfacts` | `https://data.sec.gov/api/xbrl/companyfacts/CIK##########.json` | observations: `revenue_quarterly`, `revenue_annual`, `net_income_quarterly`, `net_income_annual` (unit USD) |
| `submissions` | `https://data.sec.gov/submissions/CIK##########.json` | filing-index documents for the 40 most recent 10-K / 10-Q / 8-K (metadata only: dates, accession, 8-K item codes, filer description; filing text is NOT retrieved) |

Then the normal `inquiry -> report` path works on it (`POST /v1/intel/inquiries`), citing these records as evidence.

## Source policy record (stored with the source, write-once, hash recorded)
Stored in `intelligence_source_policies` when an approver registers the source (`sec-edgar-policy-v1`, constant `sec_edgar.POLICY`):
- **Publisher / source:** U.S. SEC, EDGAR XBRL APIs on data.sec.gov (URLs above).
- **Terms read 2026-11-13** (page text via a web fetch tool): `https://www.sec.gov/os/accessing-edgar-data` (last reviewed by the SEC 2024-06-26): current max request rate 10 requests/second; use efficient scripting; "declare your user agent in request headers"; the SEC does not allow botnets or automated tools to crawl the site outside the acceptable policy.
- **License:** U.S. government public data. The SEC privacy page ("Website Dissemination", reviewed 2023-11-29) says information on sec.gov is public information and may be copied or further distributed without the SEC's permission; it asks for appropriate citation to the SEC. SEC/EDGAR names and logos are trademarks, not used to imply affiliation. This is a summary, not legal advice.
- **Robots:** `www.sec.gov/robots.txt` checked 2026-11-13 (does not disallow `/Archives/edgar/data`; the two API paths live on data.sec.gov). `data.sec.gov/robots.txt` returned 404 (none published). robots.txt is **not** re-checked at runtime; the SEC fair-access page is the governing rule.
- **Rate policy:** SEC ceiling 10/s. Connector: hard ceiling 10/s in code (a configured value above 10 is refused, not clamped), default **2/s**.
- Attribution string: "Source: U.S. Securities and Exchange Commission, EDGAR XBRL APIs (data.sec.gov)."

## Turning it on (all must be true; otherwise the attempt is refused and audited)
1. `PATIENCE_INTEL_CONNECTORS_LIVE=1` (existing global flag)
2. `PATIENCE_INTEL_SEC_EDGAR_LIVE=1`
3. `PATIENCE_INTEL_SEC_USER_AGENT` set to a declared agent with a contact (email or URL), 10-200 printable ASCII chars. **No default; unset or malformed fails closed.** Use an address Matthew has chosen for this purpose; none is in the repo.
4. `PATIENCE_INTEL_API_HOSTS` includes `data.sec.gov` (existing `public_api` registration rule)
5. A source registered by a **named approver** (`POST /v1/intel/connectors/sec-edgar/sources`; the legacy shared approver token is refused; agents cannot)
6. That approver switched the source live (`POST .../sources/{id}/live {"enabled": true}`); registration leaves it **off**, and the approver can turn it off again.
7. The caller must be on the source's `allowed_callers`.

Optional: `PATIENCE_INTEL_SEC_RATE` (default 2, max 10), `PATIENCE_INTEL_SEC_MAX_BYTES` (default 16,000,000, hard max 32,000,000), `PATIENCE_INTEL_SEC_TIMEOUT` (default 20 s, max 60). Invalid values refuse the fetch (`bad_config`).

## Architecture
- `connectors.py` (extended; the v0.1 `PublicApiConnector` stub is unchanged): `guarded_get` (https only, exact host allowlist, path allowlist, no userinfo/odd ports/fragments, every redirect hop re-validated, max 2 redirects, status 200 only, JSON content-type only, `Accept-Encoding: identity` and compressed responses refused, content-length and body size caps), `RateLimiter`, `validate_user_agent`. Performs no I/O itself.
- `https_transport.py` (new): the **only** module in the package that imports network modules (`http.client`, `ssl`). One request per call, TLS verification on, no redirects followed, no proxy env, bounded chunked read against a byte cap and wall-clock deadline. Imported lazily; tests replace it. A test pins its imports and that nothing else may import network modules.
- `sec_edgar.py` (new): policy record, registration, live switch, strict validation and mapping, orchestration.
- `store.py`: schema v3 (forward migration from v1/v2): `intelligence_source_policies`, `intelligence_raw_fetches` (zlib raw body, write-once triggers, `UNIQUE(source_id, content_hash)`), `intelligence_fetch_links`, `intelligence_edgar_provenance` (accession, form, fiscal year/period, period start/end, filed date, frame, concept per record; write-once).
- `router.py`: `POST /v1/intel/connectors/sec-edgar/sources` (approver), `.../sources/{id}/live` (approver), `GET .../policy`, `POST .../sources/{id}/fetch` (caller, body `{cik, dataset}` only).

Flow: gates (audited refusals) -> audit `intel.fetch.attempt` (before any I/O) -> guarded GET -> audit `intel.fetch.completed` (hash, size) -> strict parse + schema validation (malformed bodies are rejected and **not stored**) -> response-level dedupe -> write-once raw store (`intel.fetch.stored`) -> existing `ingest()` (per-record validation, injection quarantine, record-level dedupe, index, `intel.ingest.batch`) -> link + provenance rows (`intel.fetch.ingested`). Other events: `intel.fetch.refused`, `.blocked`, `.failed`, `.rejected`, `.duplicate`, `.live_changed`, `intel.source.policy_recorded`. Any failed audit write raises 503 and the surrounding transaction rolls back; a failed `attempt` write means no request is made.

## Fact mapping rules (documented, deliberately small)
- Concepts: `RevenueFromContractWithCustomerExcludingAssessedTax` (preferred), `Revenues`, `SalesRevenueNet` -> `revenue_*`; `NetIncomeLoss` -> `net_income_*`. USD unit only. Forms 10-K, 10-Q and their /A variants only.
- Duration classes: 80-100 days = quarterly, 350-380 days = annual. Year-to-date values (6 and 9 months) and anything else are **not mapped** (counted in `skipped.other_duration`). Q4 is not derived: a missing quarter stays a gap and the report says so.
- When the same period is reported in several filings or concepts: concept priority first, then the latest `filed`. Observation date = period end; `published_at` = filing date; the note carries concept, period, fiscal year/period (`unknown` if absent), form, accession, filed, frame.
- Newest 40 quarterly and 12 annual periods per metric.
- Entity = company name reduced to the pipeline's allowed characters (original kept in the screened note; falls back to `CIK##########`).

## Known limits and risks
- **Fixtures are hand-built, not recorded.** Real response shapes were checked via a web fetch tool, but it truncated bodies at ~100 KB, so no real numbers were available. The test company is fictitious (`EXAMPLE SEMI CORP`, CIK 0009990001) with synthetic values. No test ever touched the network; **the live path (real TLS, real SEC responses, SEC rate behaviour) has never been exercised end to end.**
- `https_transport.py` is tested only against a fake `http.client`; real-socket behaviour (DNS, certificate chain, partial reads, slow-loris pacing between chunks) is untested. DNS answers are not pinned or checked for private ranges; TLS hostname verification is the protection.
- The rate limiter is per process; multiple workers multiply the rate. It spaces requests but does not honour `Retry-After` or react to SEC 429/403 beyond refusing that fetch.
- Restated values: a later fetch with a changed value for the same period is stored beside the old one and the report marks that date as a conflict and excludes it, rather than choosing. Values are as reported, unaudited, not inflation-adjusted, and not reconciled across companies or taxonomies. Concept changes over time (e.g. `Revenues` -> ASC 606 concept) can create discontinuities within one metric.
- Injection screening is the existing best-effort heuristic (documented as evadable, with false positives); it screens the entity name, note, and filing text. Quarantined records are stored for provenance, never indexed or retrieved. The raw body is stored regardless (it is never read by the pipeline except by `read_raw`).
- Company names can collide after sanitization (series would merge); CIK is in the note and provenance table but is not the series key.
- Raw bodies up to 16 MB are compressed into SQLite; no retention or pruning policy exists. Write-once is enforced by triggers; a person with file access can still drop triggers. The audit log is append-only and hash-chained (tamper-evident), not immutable.
- No robots.txt re-check, no `If-Modified-Since`/ETag caching, no scheduled refresh (every fetch is an explicit call), no ticker-to-CIK lookup, no other forms or taxonomies, no filing text retrieval, no foreign-private-issuer (20-F/40-F) facts.
- User-Agent contact is a deployment choice that has not been made; the connector refuses to run without it.

## Tests
`tests/test_oracle_intel_sec_edgar.py` (offline: sockets blocked, injected fixture transport, fake clock, no sleeping). Also changed: `tests/test_oracle_intelligence.py` (schema version assertion 2 -> 3; the import-boundary test skips `https_transport.py`, whose imports are pinned by the new test file).
