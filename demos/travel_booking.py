"""PATIENCE demo: governed 'book a New Year's trip' on a FIXED snapshot (simulated, offline).

observe (read-only fixture) -> compare (basis + confidence, UNKNOWNs labeled) -> /v1/check
(needs_approval) -> human approves (approver login) -> SIMULATED execute (mock executor, no
network) -> audit log verify + tamper detection. Nothing is booked or paid.

Run:  python -m demos.travel_booking
"""
from __future__ import annotations
import base64, json, os, sys, tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURE = Path(__file__).parent / "fixtures" / "federlreisen_silvester_2026-11-01.json"
UNKNOWN_FIELDS = ("inclusions", "availability", "cancellation_terms", "departure_points",
                  "taxes_and_surcharges")


def load_fixture(path: Path = FIXTURE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))  # read-only; no network


def compare(snapshot: dict) -> list:
    out = []
    for t in snapshot["trips"]:
        start, end = date.fromisoformat(t["start"]), date.fromisoformat(t["end"])
        span = (end - start).days + 1
        out.append({
            "id": t["id"], "title": t["title"],
            "price_from_eur": {"value": t["price_from"], "basis": "snapshot 'ab' (from) price",
                               "confidence": "medium (lowest advertised price; real price may be higher)"},
            "price_per_day_eur": {"value": round(t["price_from"] / t["days"], 2),
                                  "basis": "price_from / advertised days",
                                  "confidence": "low (derived from a 'from' price)"},
            "dates": {"value": f"{t['start']} to {t['end']}", "basis": "snapshot dates",
                      "confidence": "high (as of fetched_at)"},
            "duration_days": {"value": t["days"], "basis": "snapshot day count",
                              "confidence": "high" if span == t["days"] else "medium (date span disagrees)"},
            "unknown": {f: "UNKNOWN (not in snapshot)" for f in UNKNOWN_FIELDS},
        })
    return sorted(out, key=lambda r: r["price_per_day_eur"]["value"])


def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


def setup_env(tmp: Path):
    os.environ.update({
        "PATIENCE_STATE_PATH": str(tmp / "state.json"), "PATIENCE_AGENTS": str(tmp / "agents.yaml"),
        "PATIENCE_AUDIT_PATH": str(tmp / "audit.jsonl"), "PATIENCE_APPROVERS": str(tmp / "approvers.yaml"),
        "PATIENCE_EXECUTOR_MOCK": "1"})
    for v in ("PATIENCE_API_TOKEN", "PATIENCE_DEV_OPEN", "PATIENCE_EXECUTE_LIVE", "PATIENCE_WEBHOOK_URL",
              "PATIENCE_LLM_API_KEY", "PATIENCE_LEGACY_APPROVER_TOKEN", "PATIENCE_APPROVER_TOKEN"):
        os.environ.pop(v, None)


def booking_args(trip: dict) -> dict:
    return {"vendor": "federlreisen.de (snapshot)", "trip_id": trip["id"], "trip": trip["title"],
            "travelers": 2, "amount": trip["price_from"] * 2, "currency": "EUR",
            "payment": "external card payment", "simulated": True}


def run(tmp: Path, say=print) -> dict:
    setup_env(tmp)
    from fastapi.testclient import TestClient
    import api, audit, identity, approvers
    from executors.mock import MockExecutor
    mock = MockExecutor.reset()
    key = identity.add_agent("travel-agent")
    approvers.add("matthew", "demo-approver-pass-1", pin="123456")
    c, A = TestClient(api.app), {"Authorization": f"Bearer {key}"}
    res = {}

    snap = load_fixture()
    audit.append("observe", "travel-agent", source=snap["source_url"], fetched_at=snap["fetched_at"],
                 trips=len(snap["trips"]), mode="fixture_read_only")
    say(f"[1 observe] {len(snap['trips'])} trips from fixed snapshot ({snap['fetched_at']}); no network")

    cmp = compare(snap)
    res["compare"] = cmp
    say("[2 compare] sorted by price/day (basis + confidence):")
    for r in cmp:
        say(f"   - {r['title']}: {r['dates']['value']}, {r['duration_days']['value']} days, "
            f"from EUR {r['price_from_eur']['value']}, ~EUR {r['price_per_day_eur']['value']}/day "
            f"[{r['price_per_day_eur']['confidence']}]")
    say("   UNKNOWN for every trip: " + ", ".join(UNKNOWN_FIELDS))
    audit.append("oracle.compare", "travel-agent", ranking=[r["id"] for r in cmp], unknowns=list(UNKNOWN_FIELDS),
                 verified=False)

    trip = next(t for t in snap["trips"] if t["id"] == cmp[0]["id"])
    args = booking_args(trip)
    d = c.post("/v1/check", headers=A, json={"tool": "book_trip", "args": args}).json()
    res["check"] = d
    say(f"[3 check] book_trip {trip['id']} EUR {args['amount']} -> {d['decision']} (request {d['request_id']})")
    bad = c.post("/v1/check", headers=A, json={"tool": "book_trip_v2_unknown", "args": {"amount": "??"}})
    res["unknown_variant"] = bad.json().get("decision") if bad.status_code == 200 else bad.status_code
    say(f"   fail-closed: unknown/malformed variant -> {res['unknown_variant']}")

    rid = d["request_id"]
    pre = c.post("/v1/execute", headers=A, json={"tool": "book_trip", "args": args,
                                                 "idempotency_key": "demo-exec-pre", "request_id": rid})
    res["execute_before_approval"] = pre.status_code
    say(f"   execute before approval -> HTTP {pre.status_code} ({pre.json().get('status')}); mock calls={len(mock.calls)}")

    ap = c.post(f"/v1/requests/{rid}/approve", headers=_basic("matthew", "demo-approver-pass-1"),
                json={"reason": "demo approval"})
    res["approve"] = ap.status_code
    say(f"[4 approve] approver 'matthew' -> HTTP {ap.status_code}")

    changed = {**args, "amount": 1}
    ch = c.post("/v1/execute", headers=A, json={"tool": "book_trip", "args": changed,
                                                "idempotency_key": "demo-exec-changed", "request_id": rid})
    res["execute_changed"] = ch.status_code
    say(f"[5 execute] changed payload -> HTTP {ch.status_code} (refused)")
    ok = c.post("/v1/execute", headers=A, json={"tool": "book_trip", "args": args,
                                                "idempotency_key": "demo-exec-ok", "request_id": rid})
    res["execute"] = ok.status_code
    res["mock_calls"] = list(mock.calls)
    say(f"   approved payload -> HTTP {ok.status_code} {ok.json().get('status')}; SIMULATED by mock executor "
        f"({len(mock.calls)} call, no network, nothing booked)")

    v = audit.verify()
    res["verify"] = v
    say(f"[6 audit] verify -> ok={v['ok']} records={v['records']} (append-only, tamper-evident)")
    p = audit.path()
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0]); rec["trips"] = 99; lines[0] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    t = audit.verify()
    res["tampered"] = t
    say(f"   after editing record 1 -> ok={t['ok']} error='{t['error']}'")
    return res


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        run(Path(d))
