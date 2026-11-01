"""PATIENCE demo: governed scam triage on a FIXED snapshot (rule-based, simulated, offline).

observe (read-only fixture) -> rule-based assessment (basis + confidence, UNKNOWNs labeled)
-> 3 report previews through /v1/check (needs_approval) -> human approves (approver login)
-> SIMULATED send (mock executor, no network) -> audit verify + tamper detection.
Nothing is sent. This is NOT ML training and NOT a production scam detector.

Run:  python -m demos.scam_triage
"""
from __future__ import annotations
import base64, json, os, sys, tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURE = Path(__file__).parent / "fixtures" / "scam_new2026_pro_2026-11-01.json"
UNKNOWN_FIELDS = ("operator_identity", "losses", "hosting_origin_behind_cloudflare", "license")
WEIGHTS = {"young_domain": 30, "deposit_to_withdraw": 45, "brand_impersonation": 25}
HIGH, MEDIUM = 60, 30


def load_fixture(path: Path = FIXTURE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))  # read-only; no network


def _dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def assess(case: dict, as_of: str) -> dict:
    rd, cl = case["rdap"], case["content"]["claims"]
    src = case["content"]["source"]
    age = (_dt(as_of) - _dt(rd["registered"])).days
    reported = "user report only, no page capture" if src == "user_report" else f"{src} fixture"
    sig = {
        "young_domain": {"hit": age < 30, "value": f"{age} days",
                         "basis": "RDAP registration date vs snapshot date (rule: < 30 days)",
                         "confidence": "high (registry data)"},
        "deposit_to_withdraw": {"hit": bool(cl["deposit_to_withdraw_demand"]),
                                "basis": f"deposit/fee required before withdrawal ({reported})",
                                "confidence": "medium (not independently verified)" if src == "user_report" else "n/a (synthetic)"},
        "brand_impersonation": {"hit": bool(cl["brands_shown"]) and cl["brands_authorized"] is False,
                                "value": cl["brands_shown"],
                                "basis": f"third-party logos shown without authorization ({reported})",
                                "confidence": "medium (not independently verified)" if src == "user_report" else "n/a (synthetic)"},
    }
    score = sum(WEIGHTS[k] for k, s in sig.items() if s["hit"])
    level = "high" if score >= HIGH else "medium" if score >= MEDIUM else "low"
    unknown = {"operator_identity": "UNKNOWN (RDAP registrant not shown)",
               "losses": "UNKNOWN (no loss reported in snapshot)",
               "hosting_origin_behind_cloudflare": "UNKNOWN (Cloudflare nameservers hide origin)"
               if any("cloudflare" in n for n in rd["nameservers"]) else "not behind Cloudflare per snapshot",
               "license": "UNKNOWN (none disclosed)" if not cl["license_disclosed"]
               else f"disclosed, not verified: {cl['license_disclosed']}"}
    return {"id": case["id"], "domain": case["domain"], "synthetic": case["synthetic"], "signals": sig,
            "risk": {"score": score, "level": level, "basis": f"sum of rule weights {WEIGHTS}",
                     "confidence": "rule-based heuristic, not a verdict"},
            "unknown": unknown}


def report_previews(case: dict, a: dict) -> list:
    d, rd = case["domain"], case["rdap"]
    facts = (f"{d} registered {rd['registered']} via {rd['registrar']}; nameservers "
             f"{', '.join(rd['nameservers'])}. User reports a fake casino demanding a deposit/fee before "
             f"withdrawal and unauthorized {' and '.join(case['content']['claims']['brands_shown'])} logos.")
    base = {"domain": d, "risk_score": a["risk"]["score"], "evidence": facts, "simulated": True,
            "reporter": "Matthew McGuire"}
    return [
        {"tool": "send_email", "args": {**base, "channel": "registrar_abuse_email", "to": rd["abuse_email"], "recipients": [rd["abuse_email"]],
                                        "subject": f"Abuse report: {d}, fraudulent casino / advance-fee scam"}},
        {"tool": "submit_web_form", "args": {**base, "channel": "cloudflare_abuse",
                                             "form": "Cloudflare abuse report (phishing & malware)"}},
        {"tool": "submit_web_form", "args": {**base, "channel": "google_safe_browsing",
                                             "form": "Google Safe Browsing: report phishing", "url": f"https://{d}"}},
    ]


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


def run(tmp: Path, say=print) -> dict:
    setup_env(tmp)
    from fastapi.testclient import TestClient
    import api, audit, identity, approvers
    from executors.mock import MockExecutor
    mock = MockExecutor.reset()
    key = identity.add_agent("triage-agent")
    approvers.add("matthew", "demo-approver-pass-1", pin="123456")
    c, A = TestClient(api.app), {"Authorization": f"Bearer {key}"}
    res = {}

    snap = load_fixture()
    audit.append("observe", "triage-agent", snapshot_date=snap["snapshot_date"],
                 cases=[x["id"] for x in snap["cases"]], mode="fixture_read_only")
    say(f"[1 observe] {len(snap['cases'])} cases from fixed snapshot ({snap['snapshot_date']}); "
        f"no network, site never visited")

    res["assess"] = {x["id"]: assess(x, snap["as_of"]) for x in snap["cases"]}
    say("[2 assess] rule-based (not ML):")
    for a in res["assess"].values():
        hits = [k for k, s in a["signals"].items() if s["hit"]]
        tag = " [SYNTHETIC control]" if a["synthetic"] else ""
        say(f"   - {a['domain']}{tag}: risk {a['risk']['score']} ({a['risk']['level']}); signals: "
            f"{', '.join(hits) or 'none'}")
    target = res["assess"]["new2026.pro"]
    for k, s in target["signals"].items():
        say(f"     {k}: {s.get('value', s['hit'])} | basis: {s['basis']} | confidence: {s['confidence']}")
    say("     UNKNOWN: " + ", ".join(UNKNOWN_FIELDS))
    audit.append("oracle.assess", "triage-agent",
                 scores={i: a["risk"]["score"] for i, a in res["assess"].items()},
                 unknowns=list(UNKNOWN_FIELDS), verified=False)

    case = next(x for x in snap["cases"] if x["id"] == "new2026.pro")
    previews = report_previews(case, target)
    res["previews"], res["checks"] = previews, []
    for p in previews:
        d = c.post("/v1/check", headers=A, json=p).json()
        res["checks"].append(d)
        say(f"[3 check] {p['args']['channel']} ({p['tool']}) -> {d['decision']} (request {d['request_id']})")
    bad = c.post("/v1/check", headers=A, json={"tool": "report_v2_unknown", "args": {"to": "??"}})
    res["unknown_variant"] = bad.json().get("decision") if bad.status_code == 200 else bad.status_code
    say(f"   fail-closed: unknown/malformed variant -> {res['unknown_variant']}")

    p0, rid0 = previews[0], res["checks"][0]["request_id"]
    pre = c.post("/v1/execute", headers=A, json={**p0, "idempotency_key": "demo-send-pre", "request_id": rid0})
    res["execute_before_approval"] = pre.status_code
    say(f"   send before approval -> HTTP {pre.status_code} ({pre.json().get('status')}); mock calls={len(mock.calls)}")

    res["approve"] = []
    for d in res["checks"]:
        ap = c.post(f"/v1/requests/{d['request_id']}/approve",
                    headers=_basic("matthew", "demo-approver-pass-1"), json={"reason": "demo approval"})
        res["approve"].append(ap.status_code)
    say(f"[4 approve] approver 'matthew' -> HTTP {res['approve']}")

    changed = {"tool": p0["tool"], "args": {**p0["args"], "to": "attacker@evil.example"}}
    ch = c.post("/v1/execute", headers=A, json={**changed, "idempotency_key": "demo-send-changed", "request_id": rid0})
    res["execute_changed"] = ch.status_code
    say(f"[5 send] changed payload (recipient swapped) -> HTTP {ch.status_code} (refused)")
    res["execute"] = []
    for i, (p, d) in enumerate(zip(previews, res["checks"])):
        ok = c.post("/v1/execute", headers=A, json={**p, "idempotency_key": f"demo-send-ok-{i}", "request_id": d["request_id"]})
        res["execute"].append(ok.status_code)
    res["mock_calls"] = list(mock.calls)
    say(f"   approved payloads -> HTTP {res['execute']}; SIMULATED by mock executor "
        f"({len(mock.calls)} calls, no network, nothing sent)")

    v = audit.verify()
    res["verify"] = v
    say(f"[6 audit] verify -> ok={v['ok']} records={v['records']} (append-only, tamper-evident)")
    pth = audit.path()
    lines = pth.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0]); rec["cases"] = ["edited"]; lines[0] = json.dumps(rec)
    pth.write_text("\n".join(lines) + "\n", encoding="utf-8")
    t = audit.verify()
    res["tampered"] = t
    say(f"   after editing record 1 -> ok={t['ok']} error='{t['error']}'")
    return res


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        run(Path(d))
