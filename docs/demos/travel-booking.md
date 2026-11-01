# Demo: governed New Year's trip booking (simulated)

**Purpose.** Shows the PATIENCE gate end to end on a realistic "agent wants to pay for a trip" case,
with no real booking, no payment and no contact with the travel site.

**Source.** A fixed snapshot of http://www.federlreisen.de/reisen/reisetyp/silvester/ as of 2026-11-01,
supplied by Helm (Chief of Staff agent). Stored in `demos/fixtures/federlreisen_silvester_2026-11-01.json`.
The URL is provenance only; the demo never fetches it. Prices and dates may have changed since.

## Flow
1. **Observe**: load the fixture read-only; audit event `observe`.
2. **Compare**: price/day, dates, duration, each with a *basis* and *confidence*; audit event `oracle.compare` (`verified: false`).
   This is a deterministic comparison, not an LLM call.
3. **Check**: `book_trip` (external payment) goes through the real `POST /v1/check` -> `needs_approval`.
   An unknown/malformed variant (`book_trip_v2_unknown`, non-numeric amount) also does not come back `allow`.
   Executing before approval returns 202 `pending_approval`.
4. **Approve**: a human approver (HTTP Basic account in a temp `approvers.yaml`) via `/v1/requests/{rid}/approve`.
   Agent keys and anonymous calls are refused.
5. **Execute (simulated)**: `/v1/execute` with a changed payload -> 409; with the approved payload -> runs once on the
   **mock executor** (`PATIENCE_EXECUTOR_MOCK=1`). Tests block sockets to prove no network call happens.
6. **Audit**: `audit.verify()` passes (append-only, tamper-evident hash chain); editing one record is detected.

## Run
```
python3 -m demos.travel_booking          # temp state/audit dir, deleted afterwards
python3 -m pytest -q tests/test_demo_travel_booking.py
```

## Sample output
```
[1 observe] 3 trips from fixed snapshot (2026-11-01); no network
[2 compare] sorted by price/day (basis + confidence):
   - Jahreswechsel in der Waldschänke Heinzhof: 2026-12-31 to 2026-12-31, 1 days, from EUR 99, ~EUR 99.0/day [low (derived from a 'from' price)]
   - Jahreswechsel in Kärnten: 2026-12-29 to 2027-01-02, 5 days, from EUR 715, ~EUR 143.0/day [low (derived from a 'from' price)]
   - Silvester in Abano Terme: 2026-12-27 to 2027-01-03, 8 days, from EUR 1169, ~EUR 146.12/day [low (derived from a 'from' price)]
   UNKNOWN for every trip: inclusions, availability, cancellation_terms, departure_points, taxes_and_surcharges
[3 check] book_trip heinzhof EUR 198 -> needs_approval (request 10e0e618-eb3d-4bda-b350-c3a27e404106)
   fail-closed: unknown/malformed variant -> needs_approval
   execute before approval -> HTTP 202 (pending_approval); mock calls=0
[4 approve] approver 'matthew' -> HTTP 200
[5 execute] changed payload -> HTTP 409 (refused)
   approved payload -> HTTP 200 executed; SIMULATED by mock executor (1 call, no network, nothing booked)
[6 audit] verify -> ok=True records=7 (append-only, tamper-evident)
   after editing record 1 -> ok=False error='line 1: record modified (hash mismatch)'
```
(The request id changes on each run.)

## Labeled unknowns
Not in the snapshot and never invented: **inclusions, availability, cancellation terms, departure points,
taxes and surcharges**. Each comparison row reports them as `UNKNOWN (not in snapshot)`.

## Limits
- Simulated: nothing is booked or paid; the mock executor only records the call in memory.
- "From" prices are the lowest advertised; the per-day figure is low confidence. The booking amount assumes 2 travellers × from-price.
- The demo picks the cheapest per-day trip for illustration, not as a recommendation.
- Fail-closed for the unknown variant relies on the default policy (unrecognized tool -> needs_approval).
