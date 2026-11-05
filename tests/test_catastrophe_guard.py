"""Catastrophe guard: RT-07 executor binding, RT-10 claim tokens, destructive-action guard,
circuit breaker, advisory report. Simulation only; network blocked."""
import socket
import pytest

import audit
from dev_governance import DevGate, GateError, load_policy, DevPolicy
from dev_governance.store import MemoryStore


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k): raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


PR = {"repo": "spacegodforever/patience-v0-4", "head": "feat/x", "base": "v0.6-security-fixes"}


def events():
    return [str(e) for e in audit.read()]


# ---- 1. RT-07: execute bound to proposer ------------------------------------------
def test_rt07_other_agent_cannot_execute():
    g = DevGate(clock=Clock())
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    with pytest.raises(GateError) as e:
        g.execute(rid, "code.open_pr", PR, "agent-2")
    assert e.value.status == 403
    assert any("dev.execute.forbidden" in ev for ev in events())
    assert g.execute(rid, "code.open_pr", PR, "agent-1")[0] == 200


def test_rt07_owner_may_execute_per_policy():
    g = DevGate(clock=Clock())
    rid = g.propose("code.open_pr", PR, "bot", owners=["ops"])["request_id"]
    g.approve(rid, "matthew")
    assert g.execute(rid, "code.open_pr", PR, "ops")[0] == 200


def test_rt07_proposer_only_policy_blocks_owner():
    pol = load_policy(); pol.data["execute_by"] = "proposer"
    g = DevGate(policy=pol, clock=Clock())
    rid = g.propose("code.open_pr", PR, "bot", owners=["ops"])["request_id"]
    g.approve(rid, "matthew")
    with pytest.raises(GateError) as e:
        g.execute(rid, "code.open_pr", PR, "ops")
    assert e.value.status == 403


def test_rt07_forbidden_does_not_consume_approval():
    g = DevGate(clock=Clock())
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    with pytest.raises(GateError):
        g.execute(rid, "code.open_pr", PR, "intruder")
    assert g.status(rid)["status"] == "approved"


# ---- 2. RT-10: execution claim tokens for live adapters ----------------------------
from dev_governance import claims
from dev_governance.gate import payload_hash


class LiveFake:
    """A 'live' adapter double: no network; it only records that it would have done I/O."""
    live, simulated, actions = True, False, ("code.open_pr",)
    def __init__(self): self.io = 0
    def execute(self, action, payload, ctx):
        claims.verify_claim(ctx, payload_hash(action, payload))
        self.io += 1
        return {"would_send": True}


def _approved(g, action="code.open_pr", payload=PR):
    rid = g.propose(action, payload, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    return rid


def test_rt10_gate_supplies_token_and_live_adapter_runs_once():
    ad = LiveFake(); g = DevGate(clock=Clock(), adapters=[ad])
    rid = _approved(g)
    code, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert code == 200 and out["error"] is None and ad.io == 1


def test_rt10_direct_adapter_call_without_token_refused():
    ad = LiveFake()
    with pytest.raises(claims.ClaimError, match="missing"):
        ad.execute("code.open_pr", PR, {"request_id": "dev_x"})
    assert ad.io == 0


def test_rt10_reused_token_refused():
    h = payload_hash("code.open_pr", PR)
    tok = claims.mint("dev_a", h)
    claims.verify(tok, "dev_a", h)
    with pytest.raises(claims.ClaimError, match="already used"):
        claims.verify(tok, "dev_a", h)


def test_rt10_mismatched_request_or_payload_refused():
    h = payload_hash("code.open_pr", PR)
    tok = claims.mint("dev_a", h)
    with pytest.raises(claims.ClaimError, match="different"):
        claims.verify(tok, "dev_b", h)
    with pytest.raises(claims.ClaimError, match="different"):
        claims.verify(tok, "dev_a", payload_hash("code.open_pr", {**PR, "base": "main"}))


def test_rt10_forged_and_expired_refused():
    h = payload_hash("code.open_pr", PR)
    tok = claims.mint("dev_a", h)
    forged = tok[:-4] + ("0000" if not tok.endswith("0000") else "1111")
    with pytest.raises(claims.ClaimError, match="signature"):
        claims.verify(forged, "dev_a", h)
    clk = Clock()
    tok = claims.mint("dev_a", h, clk, ttl=5)
    clk.t += 6 + claims.skew_seconds()  # past TTL plus tolerated skew (RT-08)
    with pytest.raises(claims.ClaimError, match="expired"):
        claims.verify(tok, "dev_a", h, clk)


def test_rt10_live_adapter_refuses_token_for_other_payload():
    class Sneaky(LiveFake):
        def execute(self, action, payload, ctx):  # tries to send something other than what was approved
            claims.verify_claim(ctx, payload_hash(action, {**payload, "base": "main"}))
            self.io += 1
    ad = Sneaky(); g = DevGate(clock=Clock(), adapters=[ad])
    rid = _approved(g)
    code, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert out["status"] == "failed" and ad.io == 0
    assert g.status(rid)["status"] == "executed"  # at most once: the claim is spent


def test_rt10_simulated_adapter_gets_no_token():
    seen = {}
    class Sim:
        simulated, actions = True, ("code.open_pr",)
        def execute(self, a, p, ctx): seen.update(ctx); return {}
    g = DevGate(clock=Clock(), adapters=[Sim()])
    g.execute(_approved(g), "code.open_pr", PR, "agent-1")
    assert "claim_token" not in seen


# ---- 3. destructive-action guard ---------------------------------------------------
from dev_governance import destructive

SAFE = {"rollback_plan": "restore snapshot snap-42 with pg_restore, then replay WAL",
        "backup": {"snapshot_id": "snap-42"}, "blast_radius": {"rows": 500, "resources": 1}}
DROP = {"database": "members", "table": "payments", **SAFE}


@pytest.mark.parametrize("action,payload", [
    ("db.drop", {"table": "x"}), ("db.truncate", {}), ("db.delete_rows", {}), ("repo.delete", {"repo": "a/b"}),
    ("code.force_push", {"repo": "a/b"}), ("data.wipe", {}), ("infra.destroy", {}), ("secrets.rotate", {}),
    ("deploy.release", {"service": "api", "environment": "prd", "version": "1"}),
    ("db.migrate", {"environment": "production"}), ("infra.apply", {"environment": "live"}),
    ("ci.run", {"script": "psql -c 'DROP TABLE members'"}), ("ci.run", {"cmd": "rm -rf /data"}),
    ("ci.run", {"sql": "DELETE FROM payments;"}), ("ci.run", {"cmd": "terraform destroy -auto-approve"}),
])
def test_destructive_without_plan_refused(action, payload):
    g = DevGate(clock=Clock())
    with pytest.raises(GateError) as e:
        g.propose(action, payload, "agent-1")
    assert e.value.status == 422 and "fail closed" in e.value.message
    assert any("dev.destructive.refused" in ev for ev in events())


@pytest.mark.parametrize("missing", ["rollback_plan", "backup", "blast_radius"])
def test_each_requirement_is_mandatory(missing):
    p = {k: v for k, v in DROP.items() if k != missing}
    with pytest.raises(GateError) as e:
        DevGate(clock=Clock()).propose("db.drop", p, "agent-1")
    assert e.value.status == 422


@pytest.mark.parametrize("bad", [{"rollback_plan": "undo"}, {"backup": {"snapshot_id": ""}},
                                 {"backup": "yes"}, {"blast_radius": {"rows": -1, "resources": 1}},
                                 {"blast_radius": {"rows": "many", "resources": 1}},
                                 {"blast_radius": {"rows": True, "resources": 1}}])
def test_weak_evidence_refused(bad):
    with pytest.raises(GateError):
        DevGate(clock=Clock()).propose("db.drop", {**DROP, **bad}, "agent-1")


def test_destructive_forced_critical_two_approvers():
    g = DevGate(clock=Clock())
    r = g.propose("ci.run", {"cmd": "psql -c 'TRUNCATE members'", **SAFE}, "agent-1")
    assert r["tier"] == "critical" and r["approvals_required"] == 2 and r["destructive"]  # was low
    p = {"table": "members", **SAFE}
    rid = g.propose("db.truncate", p, "agent-1")["request_id"]
    g.approve(rid, "alice")
    assert g.execute(rid, "db.truncate", p, "agent-1")[0] == 202
    g.approve(rid, "bob")
    code, out = g.execute(rid, "db.truncate", p, "agent-1")
    assert code == 200 and out["result"]["simulated"]


def test_blast_radius_over_limit_needs_split_approval():
    p = {**DROP, "blast_radius": {"rows": 50_000, "resources": 1}}
    g = DevGate(clock=Clock())
    r = g.propose("db.drop", p, "agent-1")
    assert r["approvals_required"] == 3
    for who in ("alice", "bob"):
        g.approve(r["request_id"], who)
    assert g.execute(r["request_id"], "db.drop", p, "agent-1")[0] == 202
    g.approve(r["request_id"], "carol")
    assert g.execute(r["request_id"], "db.drop", p, "agent-1")[0] == 200


@pytest.mark.parametrize("br", [{"rows": 100_001, "resources": 0}, {"rows": 0, "resources": 101}])
def test_blast_radius_over_hard_limit_refused(br):
    with pytest.raises(GateError) as e:
        DevGate(clock=Clock()).propose("db.drop", {**DROP, "blast_radius": br}, "agent-1")
    assert e.value.status == 422 and "split" in e.value.message


def test_non_destructive_untouched():
    g = DevGate(clock=Clock())
    assert g.propose("ci.run", {"cmd": "pytest -q"}, "agent-1")["status"] == "allowed"
    r = g.propose("deploy.release", {"service": "api", "environment": "staging", "version": "1"}, "agent-1")
    assert r["tier"] == "medium" and not r["destructive"]


def test_classify_is_deterministic():
    p = {"cmd": "rm -rf /srv && DROP TABLE x"}
    assert destructive.classify("ci.run", p) == destructive.classify("ci.run", dict(p))


# ---- 4. circuit breaker + kill switch -----------------------------------------------
from dev_governance.breaker import Breaker

MERGE = {**PR, "pr_number": 7}


def _gate(clk=None, path=None, **cfg):
    clk = clk or Clock()
    c = {"window_seconds": 300, "max_high_proposals": 3, "max_anomalies": 2, **cfg}
    return DevGate(clock=clk, breaker=Breaker(path, c, clk)), clk


def test_breaker_trips_on_burst_of_high_proposals_and_holds_pending():
    g, clk = _gate()
    rids = [g.propose("code.merge_pr", MERGE, "bot")["request_id"] for _ in range(3)]
    g.approve(rids[0], "matthew")
    with pytest.raises(GateError) as e:
        g.propose("code.merge_pr", MERGE, "bot")
    assert e.value.status == 423
    assert any("dev.breaker.tripped" in ev for ev in events())
    with pytest.raises(GateError) as e:  # approved request is held
        g.execute(rids[0], "code.merge_pr", MERGE, "bot")
    assert e.value.status == 423
    with pytest.raises(GateError) as e:  # pending request is held
        g.approve(rids[1], "matthew")
    assert e.value.status == 423
    assert g.status(rids[0])["status"] == "approved"  # held, not consumed


def test_breaker_window_rolls():
    g, clk = _gate()
    for _ in range(3):
        g.propose("code.merge_pr", MERGE, "bot")
    clk.t += 301
    for _ in range(3):
        g.propose("code.merge_pr", MERGE, "bot")


def test_low_tier_does_not_count_and_other_agents_unaffected():
    g, _ = _gate()
    for _ in range(20):
        g.propose("ci.run", {}, "bot")
    for _ in range(3):
        g.propose("code.merge_pr", MERGE, "bot")
    with pytest.raises(GateError):
        g.propose("code.merge_pr", MERGE, "bot")
    assert g.propose("code.merge_pr", MERGE, "other-bot")["status"] == "pending"


def test_breaker_trips_on_refused_destructive_anomalies():
    g, _ = _gate()
    for _ in range(2):
        with pytest.raises(GateError) as e:
            g.propose("db.drop", {"table": "x"}, "bot")
        assert e.value.status == 422
    with pytest.raises(GateError) as e:
        g.propose("ci.run", {}, "bot")
    assert e.value.status == 423


def test_only_human_reset_unfreezes_and_is_audited():
    g, _ = _gate()
    for _ in range(4):
        try:
            g.propose("code.merge_pr", MERGE, "bot")
        except GateError:
            pass
    with pytest.raises(GateError):
        g.reset_breaker("bot", "")
    assert g.breaker_status("bot")["frozen"]
    assert g.reset_breaker("bot", "matthew")["was_frozen"]
    assert any("dev.breaker.reset" in ev for ev in events())
    assert g.propose("code.merge_pr", MERGE, "bot")["status"] == "pending"


def test_breaker_state_survives_restart(tmp_path):
    db = str(tmp_path / "b.db")
    g, clk = _gate(path=db)
    for _ in range(4):
        try:
            g.propose("code.merge_pr", MERGE, "bot")
        except GateError:
            pass
    g2, _ = _gate(clk=clk, path=db)
    assert g2.breaker_status("bot")["frozen"]


def test_global_kill_switch(monkeypatch):
    g, _ = _gate()
    rid = g.propose("code.open_pr", PR, "bot")["request_id"]
    g.approve(rid, "matthew")
    monkeypatch.setenv("PATIENCE_DEV_KILL", "1")
    for fn in (lambda: g.propose("ci.run", {}, "bot"), lambda: g.approve(rid, "alice"),
               lambda: g.execute(rid, "code.open_pr", PR, "bot")):
        with pytest.raises(GateError) as e:
            fn()
        assert e.value.status == 503
    monkeypatch.delenv("PATIENCE_DEV_KILL")
    assert g.execute(rid, "code.open_pr", PR, "bot")[0] == 200


def test_breaker_reset_via_api_requires_approver(monkeypatch):
    import base64, approvers, api
    from fastapi.testclient import TestClient
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    monkeypatch.delenv("PATIENCE_LEGACY_APPROVER_TOKEN", raising=False)
    monkeypatch.setenv("PATIENCE_API_TOKEN", "agent-token-0123456789")
    approvers.add("matthew", "matthew-password-1", "approver")
    c = TestClient(api.app)
    B = {"Authorization": "Bearer agent-token-0123456789"}
    assert c.post("/v1/dev/breaker/bot/reset", headers=B).status_code in (401, 403)
    basic = {"Authorization": "Basic " + base64.b64encode(b"matthew:matthew-password-1").decode()}
    assert c.post("/v1/dev/breaker/bot/reset", headers=basic).status_code == 200
    assert c.get("/v1/dev/breaker/bot", headers=B).json()["frozen"] is False


# ---- 5. advisory report ---------------------------------------------------------------
from dev_governance import advisory
from types import SimpleNamespace

NOGUARD = SimpleNamespace(destructive=False, why=[], blast=None)
FIELDS = {"what_could_go_wrong", "blast_radius", "reversibility", "rollback", "threat_floor",
          "basis", "confidence", "unknowns"}


def test_advisory_attached_when_approval_needed_with_all_fields():
    g = DevGate(clock=Clock())
    r = g.propose("db.drop", DROP, "bot")
    adv = r["advisory"]
    assert FIELDS <= adv.keys()
    assert adv["threat_floor"] == "critical" and adv["reversibility"].startswith("irreversible")
    assert adv["rollback"] == SAFE["rollback_plan"]
    assert g.status(r["request_id"])["advisory"] == adv


def test_no_advisory_on_auto_allowed_low():
    assert DevGate(clock=Clock()).propose("ci.run", {}, "bot")["advisory"] is None


def test_advisory_is_deterministic():
    a = advisory.build("code.merge_pr", PR, "high", True, NOGUARD)
    b = advisory.build("code.merge_pr", dict(PR), "high", True, NOGUARD)
    assert a == b


def test_advisory_never_lowers_tier():
    adv = advisory.build("code.merge_pr", PR, "critical", True, NOGUARD)  # rule says revert-able
    assert adv["threat_floor"] == "critical"


def test_advisory_raises_tier_for_partially_reversible():
    adv = advisory.build("infra.apply", {"environment": "staging"}, "medium", True, NOGUARD)
    assert adv["threat_floor"] == "high"


def test_gate_applies_advisory_raise(monkeypatch):
    g = DevGate(clock=Clock())
    monkeypatch.setitem(advisory._RISKS, "code.open_pr", (["x"], "irreversible (test)"))
    r = g.propose("code.open_pr", PR, "bot")
    assert r["tier"] == "critical" and any("advisory raised" in x for x in r["reasons"])
    assert r["approvals_required"] >= 2


def test_advisory_labels_unknowns_and_confidence():
    adv = advisory.build("mystery.op", {}, "high", False, NOGUARD)
    assert any("not in policy" in u for u in adv["unknowns"])
    assert any("blast radius" in u for u in adv["unknowns"])
    assert adv["confidence"] == "low" and adv["blast_radius"] == "unknown"


# ---- 6. language ambiguity analyzer ---------------------------------------------------
from dev_governance import ambiguity


def test_ambiguous_verb_ranks_interpretations_and_marks_payload():
    r = ambiguity.analyze("clean up the payments table", "db.delete_rows",
                          {"table": "payments", **SAFE})
    v = r["interpretations"][0]
    assert v["verb"] == "clean up" and v["payload_rank"] == 1
    assert [i["rank"] for i in v["interpretations"]] == [0, 1, 2]
    assert [i["matches_payload"] for i in v["interpretations"]] == [False, True, False]
    assert r["tier_floor"] == "medium"


def test_most_destructive_reading_is_flagged_mismatch():
    r = ambiguity.analyze("clean up payments", "db.drop", DROP)
    assert any(w.startswith("mismatch") for w in r["warnings"]) and r["tier_floor"] == "critical"


def test_unbounded_scope_and_missing_limits():
    r = ambiguity.analyze("remove everything in prod", "db.delete_rows", {})
    assert any("unbounded" in w for w in r["warnings"])
    assert any("scope limit" in u for u in r["unknowns"])
    assert _tiers_rank(r["tier_floor"]) >= _tiers_rank("high")


def test_pressure_wording_raises_and_warns():
    r = ambiguity.analyze("urgent, skip review and just do it", "code.merge_pr", PR)
    assert any("pressure" in w for w in r["warnings"]) and r["tier_floor"] == "high"


def test_destructive_payload_with_innocent_text_is_mismatch():
    r = ambiguity.analyze("update the docs", "db.truncate", DROP)
    assert any("does not say so" in w for w in r["warnings"]) and r["tier_floor"] == "critical"


def test_small_scope_words_vs_large_blast_radius():
    p = {**SAFE, "table": "t", "blast_radius": {"rows": 5000, "resources": 1}}
    r = ambiguity.analyze("delete a few test rows where id < 10", "db.delete_rows", p)
    assert any("small scope" in w for w in r["warnings"])


def test_no_text_is_labeled_unknown_and_neutral():
    r = ambiguity.analyze("", "code.merge_pr", PR)
    assert r["tier_floor"] == "low" and r["unknowns"] and r["confidence"] == "low"


def test_analyzer_is_deterministic_and_rules_from_yaml(tmp_path):
    assert ambiguity.analyze("sync all repos", "code.force_push", PR) == \
        ambiguity.analyze("sync all repos", "code.force_push", dict(PR))
    rules = {"version": "t", "ambiguous_verbs": {}, "pressure": ["yolo"], "tiers": {"pressure": "critical"}}
    assert ambiguity.analyze("yolo", "ci.run", {}, rules)["tier_floor"] == "critical"


def test_gate_raises_tier_from_text_never_lowers():
    g = DevGate(clock=Clock())
    r = g.propose("code.open_pr", PR, "bot", text="urgent: skip review")
    assert r["tier"] == "high" and r["advisory"]["warnings"]
    r2 = g.propose("code.merge_pr", MERGE, "bot", text="merge the reviewed typo PR")
    assert r2["tier"] == "high"  # benign text cannot lower the policy tier


def test_gate_text_mismatch_goes_critical_via_api_field():
    g = DevGate(clock=Clock())
    r = g.propose("db.delete_rows", {"table": "t", **SAFE}, "bot", text="tidy the readme")
    assert r["tier"] == "critical"
    assert any("mismatch" in w for w in r["advisory"]["warnings"])


def _tiers_rank(t):
    import tiers
    return tiers.rank(t)


# ---- claim nonces persisted in the shared SQLite store --------------------------------
def test_claim_reuse_refused_across_workers(tmp_path, monkeypatch):
    db = str(tmp_path / "shared.db")
    h = payload_hash("code.open_pr", PR)
    tok = claims.mint("dev_w", h)
    claims.verify(tok, "dev_w", h, nonce_db=db)
    claims._used.clear()  # simulate a different worker process: empty in-memory set
    with pytest.raises(claims.ClaimError, match="already used"):
        claims.verify(tok, "dev_w", h, nonce_db=db)


def test_claim_nonce_store_concurrent_single_winner(tmp_path):
    import threading
    db = str(tmp_path / "shared.db")
    h = payload_hash("code.open_pr", PR)
    tok = claims.mint("dev_c", h)
    wins, errs = [], []

    def worker():
        try:
            claims._burn_shared(db, tok.split(".")[4], 2 ** 31, 0)
            wins.append(1)
        except claims.ClaimError:
            errs.append(1)
    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len(wins) == 1 and len(errs) == 7


def test_claim_nonce_store_unavailable_fails_closed(tmp_path):
    h = payload_hash("code.open_pr", PR)
    with pytest.raises(claims.ClaimError, match="unavailable"):
        claims.verify(claims.mint("r", h), "r", h, nonce_db=str(tmp_path / "no" / "such" / "dir.db"))


def test_gate_passes_shared_nonce_db_to_live_adapter(tmp_path):
    from dev_governance.store import SqliteStore
    seen = {}

    class Spy(LiveFake):
        def execute(self, action, payload, ctx):
            seen.update(ctx)
            return super().execute(action, payload, ctx)
    db = str(tmp_path / "g.db")
    g = DevGate(clock=Clock(), store=SqliteStore(db), adapters=[Spy()])
    rid = _approved(g)
    g.execute(rid, "code.open_pr", PR, "agent-1")
    assert seen["claim_nonce_db"] == db
    import sqlite3
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM dev_claim_nonces").fetchone()[0] == 1
