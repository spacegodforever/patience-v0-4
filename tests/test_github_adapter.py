import json
import socket
import pytest

import audit
from dev_governance import DevGate, GateError
from dev_governance.adapters import SimulatedDeployAdapter
from dev_governance.gate import payload_hash
from dev_governance import claims
from dev_governance.github_adapter import GitHubAdapter, GitHubAdapterError
from dev_governance.store import SqliteStore

FAKE = "ghp_FAKE_TEST_TOKEN_not_real_0123456789"
REPO = "spacegodforever/patience-v0-4"
PR = {"repo": REPO, "head": "feat/x", "base": "v0.6-security-fixes", "title": "t", "body": "b"}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    def boom(*a, **k): raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    for v in ("PATIENCE_GITHUB_LIVE", "PATIENCE_DEV_KILL", "PATIENCE_GITHUB_ACTION_ALLOWLIST",
              "PATIENCE_GITHUB_REPO_ALLOWLIST", "PATIENCE_GITHUB_TOKEN"):
        monkeypatch.delenv(v, raising=False)


class Mock:
    def __init__(self, status=200, body=None, exc=None):
        self.calls, self.status, self.body, self.exc = [], status, body, exc
    def __call__(self, req):
        self.calls.append(req)
        if self.exc: raise self.exc
        return {"status": self.status, "body": self.body}


def live_env(mp):
    mp.setenv("PATIENCE_GITHUB_LIVE", "1")
    mp.setenv("PATIENCE_GITHUB_ACTION_ALLOWLIST", "code.open_pr")
    mp.setenv("PATIENCE_GITHUB_REPO_ALLOWLIST", REPO)
    mp.setenv("PATIENCE_GITHUB_TOKEN", FAKE)


def gate_with(t, **kw):
    return DevGate(adapters=[GitHubAdapter(transport=t), SimulatedDeployAdapter()], **kw)


def approved(g, action="code.open_pr", payload=PR):
    rid = g.propose(action, payload, "agent-1")["request_id"]
    g.approve(rid, "matthew")
    return rid


def no_token_anywhere():
    p = audit.path()
    return not p.exists() or FAKE not in p.read_text()


# ---- phase 1: read-only ------------------------------------------------------------
def test_read_get_repo_via_mock(monkeypatch):
    monkeypatch.setenv("PATIENCE_GITHUB_TOKEN", FAKE)
    t = Mock(body=json.dumps({"full_name": REPO, "private": False, "default_branch": "main", "secret": "x"}))
    g = gate_with(t)
    rid = g.propose("code.get_repo", {"repo": REPO}, "agent-1")
    assert rid["tier"] == "low" and rid["status"] == "allowed"
    code, out = g.execute(rid["request_id"], "code.get_repo", {"repo": REPO}, "agent-1")
    assert out["result"]["data"] == {"full_name": REPO, "private": False, "default_branch": "main", "visibility": None}
    assert t.calls[0]["method"] == "GET" and t.calls[0]["url"].endswith(f"/repos/{REPO}")
    assert t.calls[0]["headers"]["Authorization"] == f"Bearer {FAKE}"
    assert FAKE not in json.dumps(out) and no_token_anywhere()


def test_read_list_prs_summarized(monkeypatch):
    monkeypatch.setenv("PATIENCE_GITHUB_TOKEN", FAKE)
    t = Mock(body=[{"number": 15, "title": "x", "state": "open", "draft": False,
                    "head": {"ref": "a"}, "base": {"ref": "b"}, "user": {"token": "leak?"}}])
    g = gate_with(t)
    r = g.propose("code.list_prs", {"repo": REPO}, "agent-1")
    _, out = g.execute(r["request_id"], "code.list_prs", {"repo": REPO}, "agent-1")
    assert out["result"]["data"] == [{"number": 15, "title": "x", "state": "open", "draft": False, "head": "a", "base": "b"}]
    assert "state=open" in t.calls[0]["url"]


def test_read_pr_diff(monkeypatch):
    monkeypatch.setenv("PATIENCE_GITHUB_TOKEN", FAKE)
    t = Mock(body="diff --git a/x b/x\n+hi\n")
    g = gate_with(t)
    p = {"repo": REPO, "pr_number": 15}
    r = g.propose("code.get_pr_diff", p, "agent-1")
    _, out = g.execute(r["request_id"], "code.get_pr_diff", p, "agent-1")
    assert out["result"]["data"]["diff"].startswith("diff --git")
    assert t.calls[0]["headers"]["Accept"] == "application/vnd.github.diff"
    assert t.calls[0]["url"].endswith("/pulls/15")


def test_reads_never_write():
    a = GitHubAdapter()
    for act, p in (("code.get_repo", {"repo": REPO}), ("code.list_prs", {"repo": REPO}),
                   ("code.get_pr_diff", {"repo": REPO, "pr_number": 1})):
        assert a.build_request(act, p)["method"] == "GET"


def test_read_without_transport_is_dry_run(monkeypatch):
    monkeypatch.setenv("PATIENCE_GITHUB_TOKEN", FAKE)
    g = DevGate(adapters=[GitHubAdapter()])
    r = g.propose("code.get_repo", {"repo": REPO}, "agent-1")
    _, out = g.execute(r["request_id"], "code.get_repo", {"repo": REPO}, "agent-1")
    assert out["result"]["dry_run"] is True and "no transport configured" in out["result"]["not_sent_because"]


@pytest.mark.parametrize("payload,action", [
    ({"repo": "not a repo"}, "code.get_repo"),
    ({"repo": "a/b; rm -rf"}, "code.list_prs"),
    ({"repo": REPO, "pr_number": "1/../../x"}, "code.get_pr_diff"),
    ({"repo": REPO, "state": "weird"}, "code.list_prs"),
    ({**PR, "head": "../etc"}, "code.open_pr"),
    ({**PR, "title": ""}, "code.open_pr"),
])
def test_validation_rejects_bad_input(payload, action):
    with pytest.raises(GateError) as e:
        gate_with(Mock()).propose(action, payload, "agent-1")
    assert e.value.status == 422


# ---- phase 2: dry-run default ---------------------------------------------------------
def test_open_pr_is_dry_run_by_default(monkeypatch):
    monkeypatch.setenv("PATIENCE_GITHUB_TOKEN", FAKE)
    t = Mock()
    g = gate_with(t)
    rid = approved(g)
    code, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    r = out["result"]
    assert r["dry_run"] is True and t.calls == []
    assert r["request"]["method"] == "POST" and r["request"]["url"].endswith(f"/repos/{REPO}/pulls")
    assert json.loads(r["request"]["body"]) == {"title": "t", "head": "feat/x", "base": "v0.6-security-fixes", "body": "b", "draft": True}
    assert "Authorization" not in r["request"]["headers"]
    assert "PATIENCE_GITHUB_LIVE is off" in r["not_sent_because"]
    assert FAKE not in json.dumps(out) and no_token_anywhere()


def test_dry_run_does_not_consume_approval(monkeypatch):
    t = Mock(status=201, body={"number": 99, "html_url": "u", "state": "open", "draft": True})
    g = gate_with(t)
    rid = approved(g)
    assert g.execute(rid, "code.open_pr", PR, "agent-1")[1]["result"]["dry_run"] is True
    assert g.status(rid)["status"] == "approved"
    live_env(monkeypatch)
    _, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert out["result"]["dry_run"] is False and len(t.calls) == 1
    with pytest.raises(GateError):
        g.execute(rid, "code.open_pr", PR, "agent-1")
    assert len(t.calls) == 1


def test_dry_run_request_matches_live_request(monkeypatch):
    t = Mock(status=201, body={})
    g = gate_with(t)
    rid = approved(g)
    preview = g.execute(rid, "code.open_pr", PR, "agent-1")[1]["result"]["request"]
    live_env(monkeypatch)
    g.execute(rid, "code.open_pr", PR, "agent-1")
    sent = dict(t.calls[0]); sent["headers"] = {k: v for k, v in sent["headers"].items() if k != "Authorization"}
    assert sent == preview


# ---- phase 3: gated write ---------------------------------------------------------
def test_live_open_pr_sends_when_all_gates_pass(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=201, body={"number": 16, "html_url": "https://github.com/x/pull/16", "state": "open", "draft": True})
    g = gate_with(t)
    rid = approved(g)
    _, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert out["result"] == {"dry_run": False, "adapter": "github", "action": "code.open_pr", "status": 201,
                             "data": {"number": 16, "html_url": "https://github.com/x/pull/16", "state": "open", "draft": True}}
    assert len(t.calls) == 1 and no_token_anywhere()


@pytest.mark.parametrize("breaker,reason", [
    (lambda mp: mp.delenv("PATIENCE_GITHUB_LIVE"), "PATIENCE_GITHUB_LIVE is off"),
    (lambda mp: mp.setenv("PATIENCE_GITHUB_LIVE", "0"), "PATIENCE_GITHUB_LIVE is off"),
    (lambda mp: mp.setenv("PATIENCE_GITHUB_ACTION_ALLOWLIST", "code.list_prs"), "action not allowlisted"),
    (lambda mp: mp.setenv("PATIENCE_GITHUB_REPO_ALLOWLIST", "someone/else"), "repo not allowlisted"),
])
def test_each_gate_blocks_the_send(monkeypatch, breaker, reason):
    live_env(monkeypatch)
    breaker(monkeypatch)
    t = Mock(status=201, body={})
    g = gate_with(t)
    rid = approved(g)
    _, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert out["result"]["dry_run"] is True and reason in out["result"]["not_sent_because"] and t.calls == []


def test_global_kill_switch_halts_before_adapter(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=201, body={})
    g = gate_with(t)
    rid = approved(g)
    monkeypatch.setenv("PATIENCE_DEV_KILL", "1")
    with pytest.raises(GateError) as e:
        g.execute(rid, "code.open_pr", PR, "agent-1")
    assert e.value.status == 503 and t.calls == []
    assert "kill switch PATIENCE_DEV_KILL is on" in GitHubAdapter(transport=t).write_blockers(
        "code.open_pr", PR, {"approved": True, "tier": "medium", "payload_hash": payload_hash("code.open_pr", PR)})


def test_unapproved_request_never_reaches_adapter(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=201, body={})
    g = gate_with(t)
    rid = g.propose("code.open_pr", PR, "agent-1")["request_id"]
    code, _ = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert code == 202 and t.calls == []


def test_adapter_rechecks_approval_and_hash_directly(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=201, body={})
    a = GitHubAdapter(transport=t)
    h = payload_hash("code.open_pr", PR)
    good = {"approved": True, "tier": "medium", "payload_hash": h, "request_id": "dev_x",
            "claim_token": claims.mint("dev_x", h)}
    assert a.execute("code.open_pr", PR, {**good, "approved": False})["dry_run"] is True
    assert a.execute("code.open_pr", PR, {**good, "payload_hash": "x"})["dry_run"] is True
    assert a.execute("code.open_pr", {**PR, "base": "main"}, good)["dry_run"] is True
    assert a.execute("code.open_pr", PR, {**good, "tier": "low"})["dry_run"] is True
    assert t.calls == []
    assert a.execute("code.open_pr", PR, good)["dry_run"] is False


def test_changed_payload_rejected_409(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=201, body={})
    g = gate_with(t)
    rid = approved(g)
    with pytest.raises(GateError) as e:
        g.execute(rid, "code.open_pr", {**PR, "base": "main"}, "agent-1")
    assert e.value.status == 409 and t.calls == []


def test_open_pr_is_only_write_action():
    assert GitHubAdapter.actions == ("code.get_repo", "code.list_prs", "code.get_pr_diff", "code.open_pr")
    assert "code.merge_pr" not in GitHubAdapter.actions and "code.force_push" not in GitHubAdapter.actions


def test_live_is_off_by_default():
    assert GitHubAdapter().write_blockers("code.open_pr", PR, {"approved": True, "tier": "medium",
        "payload_hash": payload_hash("code.open_pr", PR)})[0] == "PATIENCE_GITHUB_LIVE is off"


def test_github_adapter_not_in_default_adapters():
    from dev_governance.adapters import default_adapters
    assert not any(isinstance(a, GitHubAdapter) for a in default_adapters())


# ---- token handling ------------------------------------------------------------
def test_missing_token_fails_without_sending(monkeypatch):
    live_env(monkeypatch)
    monkeypatch.delenv("PATIENCE_GITHUB_TOKEN")
    t = Mock(status=201, body={})
    g = gate_with(t)
    rid = approved(g)
    _, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert out["status"] == "failed" and t.calls == []


def test_token_read_at_execution_time(monkeypatch):
    live_env(monkeypatch)
    monkeypatch.delenv("PATIENCE_GITHUB_TOKEN")
    t = Mock(status=201, body={})
    a = GitHubAdapter(transport=t)  # constructed with no token in env
    monkeypatch.setenv("PATIENCE_GITHUB_TOKEN", FAKE)
    h = payload_hash("code.open_pr", PR)
    a.execute("code.open_pr", PR, {"approved": True, "tier": "medium", "payload_hash": h,
                                   "request_id": "dev_t", "claim_token": claims.mint("dev_t", h)})
    assert t.calls[0]["headers"]["Authorization"] == f"Bearer {FAKE}"
    assert FAKE not in json.dumps(vars(a), default=str)


def test_transport_exception_text_not_echoed(monkeypatch):
    live_env(monkeypatch)
    t = Mock(exc=RuntimeError(f"boom with {FAKE}"))
    g = gate_with(t)
    rid = approved(g)
    _, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert out["status"] == "failed" and FAKE not in json.dumps(out) and no_token_anywhere()
    with pytest.raises(GitHubAdapterError) as e:
        GitHubAdapter(transport=t).execute("code.open_pr", PR, {"approved": True, "tier": "medium",
                                           "payload_hash": payload_hash("code.open_pr", PR)})
    assert FAKE not in str(e.value) and e.value.__cause__ is None


def test_http_error_mapped_and_audited(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=422, body={"message": f"bad {FAKE}"})
    g = gate_with(t)
    rid = approved(g)
    _, out = g.execute(rid, "code.open_pr", PR, "agent-1")
    assert out["status"] == "failed" and "dev.execute.failed" in [r["event"] for r in audit.read()]
    assert no_token_anywhere()


def test_token_not_in_persisted_state(monkeypatch, tmp_path):
    live_env(monkeypatch)
    db = tmp_path / "g.db"
    t = Mock(status=201, body={"number": 1})
    g = gate_with(t, store=SqliteStore(str(db)))
    rid = approved(g)
    g.execute(rid, "code.open_pr", PR, "agent-1")
    assert FAKE.encode() not in db.read_bytes()
    assert audit.verify()["ok"] and no_token_anywhere()


def test_kill_switch_checked_at_send_time(monkeypatch):
    live_env(monkeypatch)
    sent = []
    a = GitHubAdapter(transport=lambda r: sent.append(r) or {"status": 201, "body": {}})
    orig = a.write_blockers
    def flip(*args):  # kill switch flips on after the gate checks but before sending
        out = orig(*args); monkeypatch.setenv("PATIENCE_DEV_KILL", "1"); return out
    a.write_blockers = flip
    with pytest.raises(GitHubAdapterError):
        a.execute("code.open_pr", PR, {"approved": True, "tier": "medium", "payload_hash": payload_hash("code.open_pr", PR)})
    assert sent == []


# ---- RT-10: live path requires a single-use, request-bound claim token ---------------
def _ctx(rid="dev_c", payload=PR, token=True):
    h = payload_hash("code.open_pr", payload)
    c = {"approved": True, "tier": "medium", "payload_hash": h, "request_id": rid}
    if token:
        c["claim_token"] = claims.mint(rid, h)
    return c


def test_live_send_refused_without_claim_token(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=201, body={})
    with pytest.raises(GitHubAdapterError, match="claim token"):
        GitHubAdapter(transport=t).execute("code.open_pr", PR, _ctx(token=False))
    assert t.calls == []


def test_live_send_refuses_reused_claim_token(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=201, body={})
    a, c = GitHubAdapter(transport=t), _ctx()
    a.execute("code.open_pr", PR, c)
    with pytest.raises(GitHubAdapterError, match="claim token"):
        a.execute("code.open_pr", PR, c)
    assert len(t.calls) == 1


def test_live_send_refuses_token_for_other_request(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=201, body={})
    c = _ctx()
    c["claim_token"] = claims.mint("dev_other", c["payload_hash"])
    with pytest.raises(GitHubAdapterError, match="claim token"):
        GitHubAdapter(transport=t).execute("code.open_pr", PR, c)
    assert t.calls == []


def test_read_path_also_requires_claim_token(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=200, body={})
    p = {"repo": PR["repo"]}
    h = payload_hash("code.get_repo", p)
    with pytest.raises(GitHubAdapterError, match="claim token"):
        GitHubAdapter(transport=t).execute("code.get_repo", p, {"payload_hash": h, "request_id": "r"})
    assert t.calls == []


def test_gate_mints_token_for_github_adapter(monkeypatch):
    live_env(monkeypatch)
    t = Mock(status=201, body={"number": 1})
    g = gate_with(t)
    _, out = g.execute(approved(g), "code.open_pr", PR, "agent-1")
    assert out["result"]["dry_run"] is False and len(t.calls) == 1
