"""Structured decision outputs (decision-v1), published JSON Schemas, audited execute attempts, and
redacted, chain-bound audit reports (tools/audit_report.py). Offline; sockets blocked."""
import ast
import base64
import copy
import csv
import hashlib
import importlib.util
import io
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

import audit
from dev_governance import DevGate, GateError, load_policy
from dev_governance import decision_schema as ds
from dev_governance.router import make_router

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "audit_report.py"
VERIFY = ROOT / "tools" / "verify_audit.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("audit_report_under_test", TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AR = _load_tool()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.delenv("PATIENCE_DEV_KILL", raising=False)


STG = {"service": "api", "environment": "staging", "version": "1.2.3"}
PR = {"repo": "o/r", "head": "feat/x", "base": "main", "title": "t"}


def gate():
    return DevGate(load_policy())


def log_path():
    return str(audit.path())


def run_tool(*args, script=TOOL, isolated=True):
    p = subprocess.run([sys.executable, *(["-I"] if isolated else []), str(script), *map(str, args)], capture_output=True, text=True, cwd=str(ROOT.parent))
    return p.returncode, p.stdout + p.stderr


def events(name=None):
    return [e for e in audit.read() if name is None or e["event"] == name]


# =============================================================== 2. execute attempts are audited
def test_unapproved_execute_attempt_is_audited_and_response_unchanged():
    g = gate()
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    code, body = g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    assert code == 202 and body == {"status": "pending_approval", "request_id": r["request_id"], "approvals": 0, "required": 1}
    ev = events("dev.execute.unapproved_attempt")
    assert len(ev) == 1 and ev[0]["actor"] == "agent-1"
    assert ev[0]["data"]["request_id"] == r["request_id"] and ev[0]["data"]["approvals"] == 0 and ev[0]["data"]["required"] == 1
    assert ev[0]["data"]["payload_hash"] == r["payload_hash"]
    assert audit.verify()["ok"] is True
    assert g.status(r["request_id"])["status"] == "pending"   # state unchanged


def test_denied_execute_attempt_is_audited():
    g = gate()
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    g.deny(r["request_id"], "bob", "no")
    with pytest.raises(GateError) as e:
        g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    assert e.value.status == 403
    ev = events("dev.execute.denied_attempt")
    assert len(ev) == 1 and ev[0]["actor"] == "agent-1" and ev[0]["data"]["request_id"] == r["request_id"]
    assert g.status(r["request_id"])["status"] == "denied"
    assert audit.verify()["ok"] is True


@pytest.mark.parametrize("event", ["dev.execute.unapproved_attempt", "dev.execute.denied_attempt"])
def test_execute_attempt_audit_failure_fails_closed(monkeypatch, event):
    g = gate()
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    if event.endswith("denied_attempt"):
        g.deny(r["request_id"], "bob", "no")
    real = audit.append

    def flaky(name, actor=None, **data):
        if name == event:
            raise OSError("disk full")
        return real(name, actor, **data)
    monkeypatch.setattr(audit, "append", flaky)
    with pytest.raises(GateError) as e:
        g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    assert e.value.status == 503 and "fail closed" in e.value.message
    assert g.status(r["request_id"])["status"] in ("pending", "denied")   # nothing executed


def test_approved_execute_path_unchanged_and_not_flagged():
    g = gate()
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    g.approve(r["request_id"], "bob")
    assert g.execute(r["request_id"], "deploy.release", STG, "agent-1")[0] == 200
    assert not events("dev.execute.unapproved_attempt") and not events("dev.execute.denied_attempt")


# =============================================================== 1. decision-v1
def flow():
    g = gate()
    r = g.propose("deploy.release", {**STG, "token": "CANARY-PAYLOAD-VALUE"}, "agent-1", owners=["o"])
    rid = r["request_id"]
    g.execute(rid, "deploy.release", {**STG, "token": "CANARY-PAYLOAD-VALUE"}, "agent-1")        # 202 attempt
    with pytest.raises(GateError):
        g.approve(rid, "agent-1")                                                                 # self approval refused
    g.approve(rid, "bob")
    assert g.execute(rid, "deploy.release", {**STG, "token": "CANARY-PAYLOAD-VALUE"}, "agent-1")[0] == 200
    return g, rid


def test_decision_record_content_and_labels():
    g, rid = flow()
    d = ds.export_decision(g, rid)
    rec = ds.DecisionRecord.model_validate(d)          # round-trips through the strict model
    assert d["schema_version"] == "decision-v1" and d["state"] == "executed" and d["request_id"] == rid
    assert d["policy"]["tier"] == "medium" and d["policy"]["known_action"] is True
    assert {"policy_rule"} <= {b["kind"] for b in d["policy"]["basis"]} and any(b["kind"] == "advisory" for b in d["policy"]["basis"])
    assert d["approvals"] == {"required": 1, "granted_by": ["bob"], "satisfied": True}
    assert d["execution"]["status"] == "executed" and d["execution"]["simulated"] is True
    assert d["confidence"]["source"] == "rule_derived_advisory" and d["confidence"]["level"] in ("high", "medium", "low")
    assert "not a probability" in d["confidence"]["note"]
    assert d["unknowns"] and all(u["label"] == "unknown" and u["source"] in ("advisory", "system") for u in d["unknowns"])
    assert [r["event"] for r in d["refusals"]] == ["dev.execute.unapproved_attempt", "dev.self_approval_rejected"]
    seqs = [t["seq"] for t in d["timeline"]]
    assert seqs == sorted(seqs) and d["timeline"][0]["event"] == "dev.proposed" and d["timeline"][-1]["event"] == "dev.executed"
    assert rec.payload_values == "withheld" and d["payload_keys"] == ["environment", "service", "token", "version"]


def test_decision_never_contains_raw_payload_values_or_secrets():
    g, rid = flow()
    blob = json.dumps(ds.export_decision(g, rid))
    assert "CANARY-PAYLOAD-VALUE" not in blob and '"staging"' not in blob and "1.2.3" not in blob


def test_decision_schema_is_strict():
    g, rid = flow()
    d = ds.export_decision(g, rid)
    for mutate in (lambda x: x.update(extra=1), lambda x: x["policy"].update(approved=True), lambda x: x.update(schema_version="decision-v2"),
                   lambda x: x["execution"].update(status="done"), lambda x: x["unknowns"][0].update(label="known"),
                   lambda x: x.update(payload_values="included")):
        bad = copy.deepcopy(d)
        mutate(bad)
        with pytest.raises(Exception):
            ds.DecisionRecord.model_validate(bad)


def test_decision_labels_missing_information_as_unknown():
    g = gate()
    r = g.propose("ci.run", {}, "agent-1")                       # low tier: no advisory generated
    d = ds.export_decision(g, r["request_id"], include_audit=False)
    items = [u["item"] for u in d["unknowns"]]
    assert d["confidence"]["level"] == "not_applicable" and d["confidence"]["source"] == "none"
    assert any("advisory report not generated" in i for i in items) and any("audit log not consulted" in i for i in items)
    assert d["timeline"] == [] and d["state"] == "allowed"
    req = copy.deepcopy(g.store.get(r["request_id"]))
    req["status"] = "weird"
    d2 = ds.build_decision(req, []).model_dump(mode="json")
    assert d2["state"] == "unknown" and any("not in the known state list" in u["item"] for u in d2["unknowns"])


def test_denied_and_failed_states_are_reflected():
    g = gate()
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    g.deny(r["request_id"], "bob", "nope")
    with pytest.raises(GateError):
        g.execute(r["request_id"], "deploy.release", STG, "agent-1")
    d = ds.export_decision(g, r["request_id"])
    assert d["state"] == "denied" and d["execution"]["status"] == "not_executed"
    evs = [x["event"] for x in d["refusals"]]
    assert "dev.denied" in evs and "dev.execute.denied_attempt" in evs


def test_export_is_read_only():
    g, rid = flow()
    before_log = Path(log_path()).read_bytes()
    before_req = copy.deepcopy(g.store.get(rid))
    ds.export_decision(g, rid)
    assert Path(log_path()).read_bytes() == before_log and g.store.get(rid) == before_req


def test_public_response_shapes_unchanged():
    g = gate()
    r = g.propose("deploy.release", STG, "agent-1", owners=["o"])
    assert set(r) == {"request_id", "action", "tier", "category", "known", "status", "approvals_required", "approvals",
                      "payload_hash", "reasons", "expires_at", "destructive", "blast_radius", "advisory"}
    assert set(g.status(r["request_id"])) == set(r)


def test_permit_state_in_decision(tmp_path):
    from test_execution_gateway import Stack
    s = Stack(tmp_path)
    rid, tok = s.permit()
    s.pay(tok["permit"])                       # accepted + payment executed by the gateway
    s.pay(tok["permit"])                       # replay: rejected
    d = ds.export_decision(s.gate, rid)
    assert d["state"] == "permit_issued" and d["permit"]["issued"] is True
    assert d["permit"]["permit_id"] and d["permit"]["key_id"]
    evs = [g["event"] for g in d["permit"]["gateway_events"]]
    assert "gateway.accepted" in evs and "gateway.rejected" in evs
    assert any(g["reason_code"] for g in d["permit"]["gateway_events"] if g["event"] == "gateway.rejected")
    assert tok["permit"] not in json.dumps(d)  # the signed permit string is never exported


# ---- HTTP: read-only endpoint, same auth as status
def _client(g):
    def ident(x_test_user: str = Header(...)):
        return {"id": x_test_user, "user": x_test_user, "owners": ["o"]}
    app = FastAPI()
    app.include_router(make_router(lambda: g, ident, ident))
    return TestClient(app)


def test_decision_endpoint():
    g = gate()
    c = _client(g)
    A = {"X-Test-User": "agent-1"}
    rid = c.post("/v1/dev/check", json={"action": "deploy.release", "payload": STG}, headers=A).json()["request_id"]
    r = c.get(f"/v1/dev/requests/{rid}/decision", headers=A)
    assert r.status_code == 200
    ds.DecisionRecord.model_validate(r.json())
    assert c.get(f"/v1/dev/requests/{rid}/decision").status_code == 422           # no identity
    assert c.get("/v1/dev/requests/nope/decision", headers=A).status_code == 404
    assert c.get(f"/v1/dev/requests/{rid}", headers=A).json()["status"] == "pending"   # old route unchanged


def test_decision_endpoint_requires_auth_in_production_wiring(monkeypatch):
    import api
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    monkeypatch.delenv("PATIENCE_LEGACY_APPROVER_TOKEN", raising=False)
    monkeypatch.setenv("PATIENCE_API_TOKEN", "agent-token-0123456789")
    c = TestClient(api.app)
    assert c.get("/v1/dev/requests/x/decision").status_code == 401
    assert c.get("/v1/dev/requests/x/decision", headers={"Authorization": "Bearer wrong"}).status_code == 401


# =============================================================== published JSON Schemas
def test_published_schemas_match_models():
    sys.path.insert(0, str(ROOT / "tools"))
    import export_schemas as es
    for fname, obj in es.schemas().items():
        f = ROOT / "schemas" / fname
        assert f.exists(), fname
        assert f.read_text(encoding="utf-8") == es.render(obj), f"{fname} is stale: run python3 tools/export_schemas.py"
    assert run_tool("--check", script=ROOT / "tools" / "export_schemas.py", isolated=False)[0] == 0


def test_published_schemas_validate_real_instances():
    try:
        import jsonschema
    except ImportError:   # optional extra check only; the byte-equality test above is the guarantee
        return
    dec = json.loads((ROOT / "schemas" / "decision-v1.schema.json").read_text())
    rec = json.loads((ROOT / "schemas" / "oracle-rec-v1.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(dec)
    jsonschema.Draft202012Validator.check_schema(rec)
    g, rid = flow()
    jsonschema.validate(ds.export_decision(g, rid), dec)
    from test_oracle_step1 import valid
    jsonschema.validate(valid(), rec)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**valid(), "approved": True}, rec)
    with pytest.raises(jsonschema.ValidationError):
        bad = ds.export_decision(g, rid)
        bad["extra"] = 1
        jsonschema.validate(bad, dec)


def test_published_schemas_forbid_extra_fields_and_pin_version():
    dec = json.loads((ROOT / "schemas" / "decision-v1.schema.json").read_text())
    rec = json.loads((ROOT / "schemas" / "oracle-rec-v1.schema.json").read_text())
    assert dec["additionalProperties"] is False and rec["additionalProperties"] is False
    assert dec["properties"]["schema_version"]["const"] == "decision-v1"
    assert rec["properties"]["schema_version"]["const"] == "oracle-rec-v1"
    assert "plan_steps" not in rec["properties"] and "approved" not in rec["properties"]


# =============================================================== 3. audit reports
def two_agent_scenario():
    g = gate()
    a = g.propose("deploy.release", STG, "agent-a", owners=["o"])["request_id"]
    b = g.propose("deploy.release", {**STG, "service": "other"}, "agent-b", owners=["o"])["request_id"]
    g.execute(a, "deploy.release", STG, "agent-a")                       # unapproved attempt
    g.approve(a, "bob")
    g.execute(a, "deploy.release", STG, "agent-a")                       # executed
    g.deny(b, "carol", "no")
    with pytest.raises(GateError):
        g.execute(b, "deploy.release", {**STG, "service": "other"}, "agent-b")
    with pytest.raises(GateError):
        g.propose("db.drop", {"table": "t"}, "agent-b")                  # refused by destructive guard
    return a, b


def gen(**kw):
    return AR.finalize(AR.build_report(log_path(), **kw))


def test_report_summary_counts_and_categories():
    two_agent_scenario()
    r = gen()
    s = r["summary"]
    assert s["proposed"] == 2 and s["approved"] == 1 and s["denied"] == 1 and s["executed"] == 1
    assert s["refused"] == 1 and s["execute_attempt_unapproved"] == 1 and s["execute_attempt_denied"] == 1
    assert s["requests_seen"] == 2 and s["events_selected"] == r["chain"]["log_records"]
    assert r["schema_version"] == "audit-report-v1" and r["chain"]["verified_at_generation"] is True
    steps = {q["request_id"]: q["steps"] for q in r["requests"]}
    assert any(v[:2] == ["proposed", "execute_attempt_unapproved"] and "executed" in v for v in steps.values())


def test_report_agent_filter_includes_others_actions_on_agents_requests():
    a, b = two_agent_scenario()
    ra = gen(agent="agent-a")
    ev = {e["event"] for e in ra["events"]}
    assert "dev.approved" in ev and "dev.executed" in ev                      # bob's approval of a's request is included
    assert "dev.denied" not in ev                                              # carol's denial belongs to agent-b
    assert {q["request_id"] for q in ra["requests"]} == {a}
    rb = gen(agent="agent-b")
    assert "dev.denied" in {e["event"] for e in rb["events"]} and "dev.destructive.refused" in {e["event"] for e in rb["events"]}
    assert a not in {q["request_id"] for q in rb["requests"]}
    assert gen(agent="nobody")["events"] == [] and gen(agent="nobody")["chain"]["period_range"] is not None


def test_report_period_filter(monkeypatch):
    ts = iter(f"2026-11-0{d}T10:00:00+00:00" for d in range(1, 9))
    monkeypatch.setattr(audit, "now_iso", lambda: next(ts))
    for i in range(6):
        audit.append("dev.proposed", "agent-a", request_id=f"r{i}", action="ci.run", tier="low")
    r = gen(since="2026-11-02T00:00:00Z", until="2026-11-04T23:59:59Z")
    assert [e["seq"] for e in r["events"]] == [2, 3, 4]
    rng = r["chain"]["period_range"]
    recs = audit.read()
    assert (rng["first_seq"], rng["last_seq"]) == (2, 4)
    assert rng["first_hash"] == recs[1]["hash"] and rng["last_hash"] == recs[3]["hash"]
    assert r["chain"]["log_records"] == 6 and r["chain"]["head_hash"] == recs[5]["hash"]
    assert gen(since="2027-01-01T00:00:00Z")["events"] == []
    with pytest.raises(ValueError):
        AR.build_report(log_path(), since="not-a-date")


def test_report_chain_binding_matches_independent_verifier():
    two_agent_scenario()
    r = gen()
    code, out = run_tool(log_path(), "--json", script=VERIFY)
    v = json.loads(out)
    assert code == 0 and v["ok"] and v["head"] == r["chain"]["head_hash"] and v["records"] == r["chain"]["log_records"]
    recs = audit.read()
    assert r["chain"]["head_file_hash"] == Path(log_path() + ".head").read_text().strip() == recs[-1]["hash"]
    want = hashlib.sha256("\n".join(f"{x['seq']}:{x['hash']}" for x in recs).encode()).hexdigest()
    assert r["chain"]["selected_digest"] == want
    for e in r["events"]:
        assert recs[e["seq"] - 1]["hash"] == e["hash"] and recs[e["seq"] - 1]["event"] == e["event"]


def test_report_verifies_and_tolerates_log_growth():
    two_agent_scenario()
    r = gen()
    assert AR.verify_report(r, log_path()) == {"ok": True, "problems": []}
    audit.append("dev.proposed", "agent-z", request_id="later", action="ci.run", tier="low")   # log grew after the report
    assert AR.verify_report(r, log_path())["ok"] is True


def _lines():
    return Path(log_path()).read_text().splitlines()


def test_tampered_log_is_detected_by_report_verify():
    two_agent_scenario()
    r = gen()
    p = Path(log_path())
    orig = p.read_text()
    p.write_text(orig.replace("agent-a", "agent-x", 1))                    # edit a record
    res = AR.verify_report(r, str(p))
    assert not res["ok"] and any("chain does not verify" in x for x in res["problems"])
    ls = orig.splitlines()
    p.write_text("\n".join(ls[:2] + ls[3:]) + "\n")                         # delete a line
    assert not AR.verify_report(r, str(p))["ok"]
    p.write_text("\n".join(ls[:-2]) + "\n")                                 # truncate tail, head file now stale
    assert not AR.verify_report(r, str(p))["ok"]
    # attacker also rewrites the head file consistently: the report still notices the log is shorter
    Path(str(p) + ".head").write_text(json.loads(ls[-3])["hash"])
    res = AR.verify_report(r, str(p))
    assert not res["ok"] and any("truncated or replaced" in x for x in res["problems"])


def test_log_rewritten_consistently_is_detected_by_report_verify():
    """Rebuild a fully valid chain with a changed record: the report's head hash no longer matches."""
    two_agent_scenario()
    r = gen()
    recs = audit.read()
    recs[1]["data"]["tier"] = "low"
    prev = "0" * 64
    out = []
    for x in recs:
        x["prev"] = prev
        x["hash"] = audit._digest(x)
        prev = x["hash"]
        out.append(json.dumps(x, sort_keys=True, separators=(",", ":")))
    p = Path(log_path())
    p.write_text("\n".join(out) + "\n")
    Path(str(p) + ".head").write_text(prev)
    assert audit.verify()["ok"] is True                                    # chain itself is consistent...
    res = AR.verify_report(r, str(p))
    assert not res["ok"] and any("rewritten" in x for x in res["problems"])   # ...but not the report's pinned head


def mutated(report, fn):
    r = copy.deepcopy(report)
    fn(r)
    r["report_hash"] = AR._sha(AR._canon({k: v for k, v in r.items() if k not in ("report_hash", "generated_at")}))  # attacker fixes the hash
    return r


def test_tampered_report_is_detected_even_with_fixed_report_hash():
    two_agent_scenario()
    r = gen()
    cases = {
        "edit event data": lambda x: x["events"][0]["data"].update(tier="low"),
        "edit actor": lambda x: x["events"][1].update(actor="someone-else"),
        "drop event": lambda x: x["events"].pop(2),
        "reorder": lambda x: x["events"].reverse(),
        "add event": lambda x: x["events"].append(copy.deepcopy(x["events"][0])),
        "summary": lambda x: x["summary"].update(refused=0),
        "head file hash": lambda x: x["chain"].update(head_file_hash="c" * 64),
        "by_event": lambda x: x["by_event"].update({"dev.proposed": 99}),
        "head hash": lambda x: x["chain"].update(head_hash="a" * 64),
        "digest": lambda x: x["chain"].update(selected_digest="b" * 64),
        "filter widened": lambda x: x["filters"].update(agent="agent-a"),
        "request table": lambda x: x["requests"][0].update(action="db.drop"),
        "records count": lambda x: x["chain"].update(log_records=x["chain"]["log_records"] - 1),
    }
    for name, fn in cases.items():
        assert not AR.verify_report(mutated(r, fn), log_path())["ok"], name
    bad = copy.deepcopy(r)
    bad["events"][0]["data"]["tier"] = "low"
    res = AR.verify_report(bad, log_path())                                # hash NOT fixed
    assert not res["ok"] and any("report_hash" in x for x in res["problems"])
    assert not AR.verify_report({"schema_version": "x"}, log_path())["ok"]
    assert not AR.verify_report({"schema_version": "audit-report-v1"}, log_path())["ok"]


def test_cli_generate_and_verify_exit_codes(tmp_path):
    two_agent_scenario()
    out = tmp_path / "report.json"
    code, msg = run_tool("generate", log_path(), "--agent", "agent-a", "--out", out)
    assert code == 0 and out.exists()
    code, msg = run_tool("verify", out, log_path())
    assert code == 0 and msg.startswith("CONSISTENT")
    rep = json.loads(out.read_text())
    rep["summary"]["executed"] = 99
    out.write_text(json.dumps(rep))
    code, msg = run_tool("verify", out, log_path())
    assert code == 1 and "NOT CONSISTENT" in msg
    code, _ = run_tool("verify", tmp_path / "missing.json", log_path())
    assert code == 2
    for fmt in ("md", "csv", "json"):
        code, text = run_tool("generate", log_path(), "--format", fmt)
        assert code == 0 and len(text) > 100


def test_generate_refuses_broken_chain_and_writes_nothing(tmp_path):
    two_agent_scenario()
    p = Path(log_path())
    p.write_text(p.read_text().replace("agent-a", "agent-x", 1))
    out = tmp_path / "r.json"
    code, msg = run_tool("generate", p, "--out", out)
    assert code == 1 and "does not verify" in msg and not out.exists()


def test_reports_never_modify_the_log_and_refuse_to_overwrite_it():
    two_agent_scenario()
    p = Path(log_path())
    before = (p.read_bytes(), Path(str(p) + ".head").read_bytes())
    gen()
    AR.verify_report(gen(), str(p))
    for target in (p, Path(str(p) + ".head"), Path(str(p) + ".lock")):
        code, msg = run_tool("generate", p, "--out", target)
        assert code == 1 and "refusing to write" in msg
    assert (p.read_bytes(), Path(str(p) + ".head").read_bytes()) == before
    assert audit.verify()["ok"] is True


def test_report_tool_is_standalone_and_read_only_by_construction():
    src = TOOL.read_text()
    tree = ast.parse(src)
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module:
            mods.add(n.module.split(".")[0])
    assert mods <= set(sys.stdlib_module_names) | {"__future__"}, mods
    assert not any(isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "append" and getattr(getattr(n.func, "value", None), "id", "") == "audit"
                   for n in ast.walk(tree))
    opens = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "open"]
    modes = [n.args[1].value for n in opens if len(n.args) > 1 and isinstance(n.args[1], ast.Constant)]
    assert set(modes) <= {"rb", "w"}                                       # 'w' is only the --out file; no append/rw on the log


# ---- redaction
CANARIES = {
    "api_token": "TOKEN-CANARY-1111", "claim_token": "CLAIM-CANARY-2222", "permit": "pv1.CANARYPERMITSIGNATURE0000000000.CANARYPERMITSIGNATURE1111111111",
    "signature": "SIG-CANARY-3333", "private_key": "KEY-CANARY-4444", "password": "PW-CANARY-5555", "authorization": "Bearer BEARERCANARY66666666",
    "payload": {"amount": "PAYLOAD-CANARY-7777"}, "raw_value": "RAWVALUE-CANARY-8888", "nonce": "NONCE-CANARY-9999",
    "attestation": "ATTEST-CANARY-0000"}
TEXT_CANARIES = ["ghp_abcdefghijklmnopqrstuvwxyz0123", "sk-live-abcdefghijklmnop", "password=hunter2-CANARY", "AKIAABCDEFGHIJKLMNOP",
                 "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij", "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkq\n-----END PRIVATE KEY-----",
                 "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf"]


def canary_log():
    audit.append("dev.proposed", "agent-a", request_id="r1", action="deploy.release", tier="high", payload_hash="ab" * 32,
                 **CANARIES, permit_id="jti-123", key_id="kid-9", reasons=["base tier high"])
    for i, t in enumerate(TEXT_CANARIES):
        audit.append("dev.execute.failed", "agent-a", request_id=f"r{i + 2}", error=f"upstream said: {t} end", note=t, reason=t)


def all_canary_strings():
    out = []
    for v in CANARIES.values():
        out += list(v.values()) if isinstance(v, dict) else [v]
    out += ["CANARYPERMITSIGNATURE", "hunter2-CANARY", "BEARERCANARY", "MIIBVQIBADANBgkq", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
            "ghp_abcdefghijklmnop", "sk-live-abcdefgh", "AKIAABCDEFGHIJKLMNOP", "eyJhbGciOiJIUzI1NiJ9"]
    return out


@pytest.mark.parametrize("fmt", ["json", "md", "csv"])
def test_redaction_removes_all_canaries_in_every_format(fmt):
    canary_log()
    r = gen()
    text = {"json": lambda: json.dumps(r), "md": lambda: AR.to_markdown(r), "csv": lambda: AR.to_csv(r)}[fmt]()
    for c in all_canary_strings():
        assert c not in text, c
    assert r["redaction"]["raw_payload_values_included"] is False


def test_redaction_deny_allow_semantics():
    canary_log()
    d = gen()["events"][0]["data"]
    for k in ("api_token", "claim_token", "permit", "signature", "private_key", "password", "authorization", "nonce", "attestation"):
        assert d[k] == "[REDACTED]", k                                      # deny-list
    assert d["payload"] == "[withheld:dict]" and d["raw_value"] == "[withheld:str]"       # not allow-listed
    assert d["permit_id"] == "jti-123" and d["key_id"] == "kid-9" and d["payload_hash"] == "ab" * 32 and d["tier"] == "high"
    assert d["reasons"] == ["base tier high"] and d["action"] == "deploy.release"
    c = gen()["redaction"]["counts"]
    assert c["denied_key"] == 9 and c["withheld_key"] == 2 and c["scrubbed_value"] >= 6


def test_extra_allow_key_works_but_deny_list_always_wins():
    canary_log()
    r = AR.finalize(AR.build_report(log_path(), extra_allow=["raw_value", "api_token", "password"]))
    d = r["events"][0]["data"]
    assert d["raw_value"] == "RAWVALUE-CANARY-8888"                          # operator opted in
    assert d["api_token"] == "[REDACTED]" and d["password"] == "[REDACTED]"  # cannot be allow-listed
    assert AR.verify_report(r, log_path())["ok"] is True                     # allow-list is part of the verified filters
    r["redaction"]["extra_allowed_keys"] = []
    assert not AR.verify_report(r, log_path())["ok"]


def test_cli_allow_key(tmp_path):
    canary_log()
    code, out = run_tool("generate", log_path(), "--allow-key", "raw_value")
    assert code == 0 and "RAWVALUE-CANARY-8888" in out and "TOKEN-CANARY-1111" not in out


def test_csv_formula_injection_and_markdown_escaping():
    audit.append("dev.proposed", "=HYPERLINK(\"http://x\",\"y\")", request_id="+cmd|' /C calc", action="a|b")
    audit.append("dev.proposed", "@evil", request_id="r2", action="x")
    r = gen()
    rows = list(csv.reader(io.StringIO(AR.to_csv(r))))
    assert rows[1][4].startswith("'=") and rows[1][5].startswith("'+") and rows[2][4].startswith("'@")
    md = AR.to_markdown(r)
    assert "a\\|b" in md and "| a|b |" not in md


def test_empty_and_missing_log(tmp_path):
    r = AR.finalize(AR.build_report(str(tmp_path / "none.jsonl")))
    assert r["events"] == [] and r["chain"]["log_records"] == 0 and r["chain"]["period_range"] is None
    assert AR.verify_report(r, str(tmp_path / "none.jsonl"))["ok"] is True


# ---- read-only HTTP endpoint
def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


@pytest.fixture
def secured(monkeypatch):
    import approvers, api
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    monkeypatch.delenv("PATIENCE_LEGACY_APPROVER_TOKEN", raising=False)
    monkeypatch.setenv("PATIENCE_API_TOKEN", "agent-token-0123456789")
    approvers.add("matthew", "matthew-password-1", "approver")
    return TestClient(api.app)


def test_report_endpoint_auth_and_content(secured):
    c = secured
    two_agent_scenario()
    url = "/v1/dev/admin/audit-report"
    assert c.get(url).status_code in (401, 403)
    assert c.get(url, headers={"Authorization": "Bearer agent-token-0123456789"}).status_code in (401, 403)   # agents cannot read it
    before = Path(log_path()).read_bytes()
    r = c.get(url, params={"agent": "agent-a"}, headers=_basic("matthew", "matthew-password-1"))
    assert r.status_code == 200
    rep = r.json()
    assert rep["schema_version"] == "audit-report-v1" and rep["filters"]["agent"] == "agent-a"
    assert AR.verify_report(rep, log_path())["ok"] is True
    assert Path(log_path()).read_bytes() == before                           # read-only
    for fmt, ctype in (("md", "text/markdown"), ("csv", "text/csv")):
        rr = c.get(url, params={"format": fmt}, headers=_basic("matthew", "matthew-password-1"))
        assert rr.status_code == 200 and rr.headers["content-type"].startswith(ctype)
    H = _basic("matthew", "matthew-password-1")
    assert c.get(url, params={"format": "xml"}, headers=H).status_code == 422
    assert c.get(url, params={"since": "garbage"}, headers=H).status_code == 422


def test_report_endpoint_fails_closed_on_broken_chain(secured):
    two_agent_scenario()
    p = Path(log_path())
    p.write_text(p.read_text().replace("agent-a", "agent-x", 1))
    r = secured.get("/v1/dev/admin/audit-report", headers=_basic("matthew", "matthew-password-1"))
    assert r.status_code == 503 and "agent-x" not in r.text
