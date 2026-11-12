"""GitHub actions through the API's default wiring: dry-run by default, refusals, audit.

Everything goes through the real FastAPI app (api.app -> dev router -> DevGate built by
api.dev_gate() -> dev_governance.wiring.api_adapters()). The network is blocked at the socket
level and every transport is a recording fake, so a test that sends anything fails loudly.
"""
import base64
import json
import socket
import time

import pytest
from fastapi.testclient import TestClient

import audit
from dev_governance import wiring
from dev_governance.adapters import SimulatedGitHubPRAdapter, default_adapters
from dev_governance.authority import default_authority
from dev_governance.github_adapter import GitHubAdapter
from dev_governance.github_transport import UrllibTransport
from tests.test_org_authority import PAYLOAD as TEST_PAYLOAD

REPO = "spacegodforever/patience-v0-4"
PR = {"repo": REPO, "head": "feat/x", "base": "v0.6-security-fixes", "title": "t", "body": "b"}
FAKE = "ghp_FAKE_TEST_TOKEN_not_real_0123456789"
AGENT = {"Authorization": "Bearer agent-token-0123456789"}


def basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


BOB, ROOT = basic("bob", "bob-password-1234"), basic("root", "root-password-12")


class Spy:
    """Fake transport: records every request it is handed."""
    def __init__(self, status=201, body=None):
        self.calls, self.status, self.body = [], status, body if body is not None else {"number": 7, "html_url": "x"}

    def __call__(self, req):
        self.calls.append(req)
        return {"status": self.status, "body": self.body}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    for v in ("PATIENCE_GITHUB_LIVE", "PATIENCE_DEV_KILL", "PATIENCE_GITHUB_ACTION_ALLOWLIST",
              "PATIENCE_GITHUB_REPO_ALLOWLIST", "PATIENCE_GITHUB_TOKEN"):
        monkeypatch.delenv(v, raising=False)


@pytest.fixture
def spy(monkeypatch):
    """Hand a recording transport to the adapter even when the env would not create one, so a
    test can prove the adapter itself never calls it."""
    s = Spy()
    monkeypatch.setattr(wiring, "transport_factory", lambda: s)
    return s


@pytest.fixture
def c(monkeypatch):
    import approvers
    import api
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    monkeypatch.delenv("PATIENCE_LEGACY_APPROVER_TOKEN", raising=False)
    monkeypatch.setenv("PATIENCE_API_TOKEN", "agent-token-0123456789")
    monkeypatch.setenv("PATIENCE_API_TOKEN_OWNERS", "token-owner")
    approvers.add("root", "root-password-12", "admin")
    approvers.add("bob", "bob-password-1234", "approver")
    return TestClient(api.app)


def propose(c, action="code.open_pr", payload=PR, **extra):
    return c.post("/v1/dev/check", json={"action": action, "payload": payload, **extra}, headers=AGENT)


def approve(c, rid):
    return c.post(f"/v1/dev/requests/{rid}/approve", headers=BOB)


def execute(c, rid, action="code.open_pr", payload=PR):
    return c.post(f"/v1/dev/requests/{rid}/execute", json={"action": action, "payload": payload}, headers=AGENT)


def approved(c, action="code.open_pr", payload=PR):
    p = propose(c, action, payload)
    assert p.status_code == 200, p.text
    rid = p.json()["request_id"]
    assert approve(c, rid).status_code == 200
    return rid


def events():
    return [e["event"] for e in audit.read()]


def live_env(mp):
    mp.setenv("PATIENCE_GITHUB_LIVE", "1")
    mp.setenv("PATIENCE_GITHUB_ACTION_ALLOWLIST", "code.open_pr")
    mp.setenv("PATIENCE_GITHUB_REPO_ALLOWLIST", REPO)
    mp.setenv("PATIENCE_GITHUB_TOKEN", FAKE)


# ---- what the default wiring is -------------------------------------------------------
def test_api_gate_uses_github_adapter_for_open_pr_and_reads_but_not_merge_or_push():
    import api
    g = api.dev_gate()
    for a in ("code.open_pr", "code.get_repo", "code.list_prs", "code.get_pr_diff"):
        assert isinstance(g.adapters[a], GitHubAdapter)
    for a in ("code.merge_pr", "code.push_branch", "code.force_push"):  # never real
        assert isinstance(g.adapters[a], SimulatedGitHubPRAdapter)
    assert g.authority is default_authority()  # the durable CapabilityAuthority
    assert not any(isinstance(a, GitHubAdapter) for a in default_adapters())  # DevGate() default unchanged


def test_transport_exists_only_with_live_flag_and_is_read_only_unless_write_allowlisted(monkeypatch):
    assert wiring.github_transport_from_env() is None
    monkeypatch.setenv("PATIENCE_GITHUB_LIVE", "0")
    assert wiring.github_transport_from_env() is None
    monkeypatch.setenv("PATIENCE_GITHUB_LIVE", "1")
    t = wiring.github_transport_from_env()
    assert isinstance(t, UrllibTransport) and t.read_only is True
    monkeypatch.setenv("PATIENCE_GITHUB_ACTION_ALLOWLIST", "code.open_pr")
    assert wiring.github_transport_from_env().read_only is True  # no repo allowlisted yet
    monkeypatch.setenv("PATIENCE_GITHUB_REPO_ALLOWLIST", REPO)
    assert wiring.github_transport_from_env().read_only is False


def test_merge_stays_simulated_through_the_api(c, spy):
    p = {"repo": REPO, "pr_number": 3}
    rid = propose(c, "code.merge_pr", p).json()["request_id"]
    assert approve(c, rid).status_code == 200
    r = execute(c, rid, "code.merge_pr", p)
    assert r.status_code == 200 and r.json()["result"]["simulated"] is True and spy.calls == []


# ---- (6) happy path: default mode is a dry run ------------------------------------------
def test_approved_open_pr_in_default_mode_is_dry_run_with_audit_and_no_transport_call(c, spy, monkeypatch):
    monkeypatch.setenv("PATIENCE_GITHUB_TOKEN", FAKE)  # even with a token present, nothing is sent
    rid = approved(c)
    r = execute(c, rid)
    assert r.status_code == 200, r.text
    res = r.json()["result"]
    assert res["dry_run"] is True and res["adapter"] == "github"
    assert "PATIENCE_GITHUB_LIVE is off" in res["not_sent_because"]
    assert res["request"]["method"] == "POST" and res["request"]["url"] == f"https://api.github.com/repos/{REPO}/pulls"
    assert json.loads(res["request"]["body"])["draft"] is True
    assert "Authorization" not in res["request"]["headers"] and FAKE not in r.text
    assert spy.calls == []
    ev = events()
    assert [e for e in ev if e.startswith("dev.")] == ["dev.proposed", "dev.approved", "dev.execute.claimed", "dev.executed"]
    done = [e for e in audit.read() if e["event"] == "dev.executed"][0]["data"]
    assert done["dry_run"] is True and done["request_id"] == rid
    assert FAKE not in audit.path().read_text()
    assert audit.verify()["ok"]


def test_dry_run_does_not_consume_approval_and_still_never_sends(c, spy):
    rid = approved(c)
    assert execute(c, rid).json()["result"]["dry_run"] is True
    assert execute(c, rid).json()["result"]["dry_run"] is True  # nothing was sent, nothing was used up
    assert spy.calls == []


# ---- without PATIENCE_GITHUB_LIVE the transport is never used ---------------------------
def test_without_live_flag_no_transport_is_built_or_called_for_any_github_action(c, monkeypatch):
    built, called = [], []

    class Recording(UrllibTransport):
        def __init__(self, *a, **k):
            built.append(1)
            super().__init__(*a, **k)

        def __call__(self, req):
            called.append(req)
            raise AssertionError("transport must not be called without PATIENCE_GITHUB_LIVE")
    monkeypatch.setattr(wiring, "UrllibTransport", Recording)
    monkeypatch.setenv("PATIENCE_GITHUB_TOKEN", FAKE)
    monkeypatch.setenv("PATIENCE_GITHUB_ACTION_ALLOWLIST", "code.open_pr")  # allowlists alone do not enable it
    monkeypatch.setenv("PATIENCE_GITHUB_REPO_ALLOWLIST", REPO)
    for act, p in (("code.get_repo", {"repo": REPO}), ("code.list_prs", {"repo": REPO}),
                   ("code.get_pr_diff", {"repo": REPO, "pr_number": 15})):
        r = execute(c, approved(c, act, p), act, p)  # the server-side threat floor makes reads need approval too
        assert r.status_code == 200 and r.json()["result"]["dry_run"] is True
        assert r.json()["result"]["not_sent_because"] == ["no transport configured"]
    rid = approved(c)
    assert execute(c, rid).json()["result"]["dry_run"] is True
    assert built == [] and called == []


def test_adapter_given_a_transport_still_never_sends_a_write_without_live_flag(c, spy, monkeypatch):
    monkeypatch.setenv("PATIENCE_GITHUB_ACTION_ALLOWLIST", "code.open_pr")
    monkeypatch.setenv("PATIENCE_GITHUB_REPO_ALLOWLIST", REPO)
    monkeypatch.setenv("PATIENCE_GITHUB_TOKEN", FAKE)
    r = execute(c, approved(c))
    assert r.json()["result"]["dry_run"] is True and spy.calls == []


# ---- live stays impossible unless every prerequisite holds ----------------------------------
def test_live_send_through_api_requires_every_prerequisite(c, spy, monkeypatch):
    live_env(monkeypatch)
    for missing, reason in (("PATIENCE_GITHUB_LIVE", "PATIENCE_GITHUB_LIVE is off"),
                            ("PATIENCE_GITHUB_ACTION_ALLOWLIST", "action not allowlisted"),
                            ("PATIENCE_GITHUB_REPO_ALLOWLIST", "repo not allowlisted")):
        with monkeypatch.context() as m:
            m.delenv(missing)
            r = execute(c, approved(c, payload={**PR, "title": f"t-{missing}"}), payload={**PR, "title": f"t-{missing}"})
            assert r.json()["result"]["dry_run"] is True and reason in r.json()["result"]["not_sent_because"]
            assert spy.calls == []
    with monkeypatch.context() as m:  # no token -> refused, nothing sent
        m.delenv("PATIENCE_GITHUB_TOKEN")
        p = {**PR, "title": "no-token"}
        r = execute(c, approved(c, payload=p), payload=p)
        assert r.json()["status"] == "failed" and r.json()["error"].startswith("adapter error")
        assert spy.calls == []
    assert audit.verify()["ok"]


def test_live_positive_control_all_prerequisites_send_exactly_once_to_the_fake(c, spy, monkeypatch):
    live_env(monkeypatch)
    rid = approved(c)
    r = execute(c, rid)
    assert r.status_code == 200 and r.json()["result"]["dry_run"] is False
    assert len(spy.calls) == 1 and spy.calls[0]["method"] == "POST" and spy.calls[0]["url"].startswith("https://api.github.com/")
    assert execute(c, rid).status_code == 409  # a real send consumes the approval
    assert len(spy.calls) == 1
    assert FAKE not in audit.path().read_text() and FAKE not in r.text
    assert audit.verify()["ok"]


# ---- (1) unapproved --------------------------------------------------------------------------
def test_unapproved_request_is_not_executed_and_does_not_reach_transport(c, spy, monkeypatch):
    live_env(monkeypatch)  # even with every live prerequisite set
    rid = propose(c).json()["request_id"]
    r = execute(c, rid)
    assert r.status_code == 202 and r.json()["status"] == "pending_approval"
    assert spy.calls == []
    assert c.get(f"/v1/dev/requests/{rid}", headers=AGENT).json()["status"] == "pending"
    assert "dev.execute.claimed" not in events() and "dev.executed" not in events()


def test_denied_request_is_refused_and_does_not_reach_transport(c, spy, monkeypatch):
    live_env(monkeypatch)
    rid = propose(c).json()["request_id"]
    assert c.post(f"/v1/dev/requests/{rid}/deny", headers=BOB).status_code == 200
    r = execute(c, rid)
    assert r.status_code == 403 and "denied" in r.text and spy.calls == []
    assert "dev.denied" in events() and "dev.executed" not in events()


def test_owner_of_the_proposer_cannot_approve_its_github_request(c, spy, monkeypatch):
    import approvers
    live_env(monkeypatch)
    approvers.add("token-owner", "owner-password-12", "approver")  # the proposer's configured owner
    rid = propose(c).json()["request_id"]
    r = c.post(f"/v1/dev/requests/{rid}/approve", headers=basic("token-owner", "owner-password-12"))
    assert r.status_code == 403 and "dev.self_approval_rejected" in events()
    assert execute(c, rid).status_code == 202 and spy.calls == []


# ---- (2) altered payload after approval ----------------------------------------------------------
def test_altered_payload_after_approval_is_refused_and_audited(c, spy, monkeypatch):
    live_env(monkeypatch)
    rid = approved(c)
    for bad in ({**PR, "base": "main"}, {**PR, "head": "evil"}, {**PR, "repo": "other/repo"}, {**PR, "title": "t2"}):
        r = execute(c, rid, payload=bad)
        assert r.status_code == 409, r.text
    r = execute(c, rid, action="code.merge_pr")  # different action, same payload
    assert r.status_code == 409
    assert spy.calls == []
    assert events().count("dev.payload_mismatch") == 5
    mm = [e for e in audit.read() if e["event"] == "dev.payload_mismatch"][0]["data"]
    assert mm["request_id"] == rid and mm["expected"] != mm["got"]
    assert c.get(f"/v1/dev/requests/{rid}", headers=AGENT).json()["status"] == "approved"  # still unused
    assert audit.verify()["ok"]


# ---- (3)/(4) grants (only test.run_isolated requires one today) ----------------------------------
class Skew:
    """Authority clock that can be moved forward without touching the gate's request clock."""
    def __init__(self): self.offset = 0.0
    def __call__(self): return time.time() + self.offset


def grant_body(**o):
    v = {"grant_id": "gh-g1", "actor": "default", "action": "test.run_isolated", "resource": "local-checkout",
         "scope": {k: TEST_PAYLOAD[k] for k in ("command", "workspace", "environment", "adapter")},
         "human_owner": "token-owner", "owners": ["token-owner"], "max_level": 2,
         "expires_at": time.time() + 7200, "max_action_ttl_seconds": 3600,
         "isolation": {"network_allowed": False, "secrets_allowed": False, "production_allowed": False},
         "evidence": {"basis": "human_decision", "reference": "r", "confidence": "high", "reason": "why"}}
    v.update(o)
    return v


@pytest.fixture
def granted(c):
    clock = Skew()
    default_authority().clock = clock  # same durable instance the API uses
    assert c.post("/v1/dev/authority/grants", json=grant_body(), headers=ROOT).status_code == 200
    return clock


def gpayload():
    return {**TEST_PAYLOAD, "authority_grant": "gh-g1"}


def test_valid_grant_is_the_control_for_the_grant_refusals(c, granted):
    rid = propose(c, "test.run_isolated", TEST_PAYLOAD, authority_grant="gh-g1")
    assert rid.status_code == 200, rid.text
    assert approve(c, rid.json()["request_id"]).status_code == 200  # server-side floor raises it above 'low'
    r = execute(c, rid.json()["request_id"], "test.run_isolated", gpayload())
    assert r.status_code == 501  # grant accepted; the API wires no isolated-test adapter, so it stops there


def test_missing_grant_is_refused_and_audited(c, granted):
    r = propose(c, "test.run_isolated", TEST_PAYLOAD)
    assert r.status_code == 403 and "dev.authority.refused" in events()


def test_expired_grant_is_refused_at_propose_and_at_execute(c, granted):
    rid = propose(c, "test.run_isolated", TEST_PAYLOAD, authority_grant="gh-g1").json()["request_id"]
    granted.offset = 7300  # past the grant's expiry; the request's own approval window is unaffected
    r = execute(c, rid, "test.run_isolated", gpayload())
    assert r.status_code == 403 and "expired" in r.text
    r = propose(c, "test.run_isolated", TEST_PAYLOAD, authority_grant="gh-g1")
    assert r.status_code == 403 and "expired" in r.text
    refused = [e for e in audit.read() if e["event"] == "dev.authority.refused"]
    assert len(refused) == 2 and all("expired" in e["data"]["reason"] for e in refused)
    assert audit.verify()["ok"]


def test_revoked_grant_is_refused_at_propose_and_at_execute(c, granted):
    rid = propose(c, "test.run_isolated", TEST_PAYLOAD, authority_grant="gh-g1").json()["request_id"]
    assert c.post("/v1/dev/authority/grants/gh-g1/revoke", json={"reason": "retired"}, headers=ROOT).status_code == 200
    r = execute(c, rid, "test.run_isolated", gpayload())
    assert r.status_code == 403 and "revoked" in r.text
    r = propose(c, "test.run_isolated", TEST_PAYLOAD, authority_grant="gh-g1")
    assert r.status_code == 403 and "revoked" in r.text
    refused = [e for e in audit.read() if e["event"] == "dev.authority.refused"]
    assert len(refused) == 2 and all("revoked" in e["data"]["reason"] for e in refused)
    assert {"dev.authority.granted", "dev.authority.revoked"} <= set(events())
    assert audit.verify()["ok"]


def test_github_actions_do_not_require_a_grant_today(c, spy):
    """Documents a limit, not a feature: approval + payload hash + live flags gate GitHub actions,
    the CapabilityAuthority applies only to test.run_isolated."""
    assert execute(c, approved(c)).json()["result"]["dry_run"] is True


# ---- (5) kill switch ------------------------------------------------------------------------
def test_kill_switch_refuses_execution_before_any_adapter_work(c, spy, monkeypatch):
    live_env(monkeypatch)
    rid = approved(c)
    monkeypatch.setenv("PATIENCE_DEV_KILL", "1")
    r = execute(c, rid)
    assert r.status_code == 503 and "PATIENCE_DEV_KILL" in r.text
    assert propose(c, payload={**PR, "title": "later"}).status_code == 503
    assert approve(c, rid).status_code == 503
    assert spy.calls == []
    assert events().count("dev.kill_switch.blocked") >= 3
    assert "dev.executed" not in events() and "dev.execute.claimed" not in events()
    monkeypatch.delenv("PATIENCE_DEV_KILL")
    assert c.get(f"/v1/dev/requests/{rid}", headers=AGENT).json()["status"] == "approved"  # untouched
    assert audit.verify()["ok"]
