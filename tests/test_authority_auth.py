"""Grant/revoke callers must be authenticated (fail closed); grants/revocations are audited."""
import base64
import pytest
from fastapi.testclient import TestClient

import audit
from dev_governance import CapabilityAuthority
from dev_governance.authority import AuthorityError
from tests.test_org_authority import Clock, PAYLOAD


def base_args(clock, **o):
    v = {"grant_id": "g1", "actor": "agent-1", "action": "test.run_isolated", "resource": "local-checkout",
         "scope": {k: PAYLOAD[k] for k in ("command", "workspace", "environment", "adapter")},
         "granted_by": "reviewer", "human_owner": "matthew", "owners": ["matthew"], "max_level": 2,
         "expires_at": clock() + 7200, "max_action_ttl_seconds": 3600,
         "isolation": {"network_allowed": False, "secrets_allowed": False, "production_allowed": False},
         "evidence": {"basis": "human_decision", "reference": "r", "confidence": "high", "reason": "why"}}
    v.update(o)
    return v


@pytest.fixture
def clock(): return Clock()


@pytest.fixture
def authority(clock): return CapabilityAuthority(clock=clock)


@pytest.mark.parametrize("att", [None, "", "garbage", "1.2", "x.y", 12345])
def test_grant_without_valid_attestation_is_refused_and_not_stored(authority, clock, att):
    with pytest.raises(AuthorityError) as e:
        authority.grant(**base_args(clock), attestation=att)
    assert e.value.status == 401
    assert authority._current("g1") is None


def test_attestation_is_bound_to_user_purpose_and_grant_id(authority, clock):
    good = authority.attest("reviewer", "grant", "g1")
    for bad in (authority.attest("someone-else", "grant", "g1"),   # different signer
                authority.attest("reviewer", "revoke", "g1"),      # wrong purpose
                authority.attest("reviewer", "grant", "other")):   # different grant id
        with pytest.raises(AuthorityError) as e:
            authority.grant(**base_args(clock), attestation=bad)
        assert e.value.status == 401
    assert authority.grant(**base_args(clock), attestation=good)["grant_id"] == "g1"


def test_attestation_expires(authority, clock):
    att = authority.attest("reviewer", "grant", "g1")
    clock.t += 61
    with pytest.raises(AuthorityError) as e:
        authority.grant(**base_args(clock, expires_at=clock() + 7200), attestation=att)
    assert e.value.status == 401


def test_forged_signature_is_refused(authority, clock):
    exp = int(clock()) + 30
    with pytest.raises(AuthorityError) as e:
        authority.grant(**base_args(clock), attestation=f"{exp}.{'0' * 64}")
    assert e.value.status == 401


def test_revoke_requires_attestation_and_unattested_revoke_changes_nothing(authority, clock):
    authority.grant(**base_args(clock), attestation=authority.attest("reviewer", "grant", "g1"))
    with pytest.raises(AuthorityError) as e:
        authority.revoke("g1", "reviewer", "retire")
    assert e.value.status == 401
    assert authority._current("g1")[0] == "grant"
    authority.revoke("g1", "reviewer", "retire", attestation=authority.attest("reviewer", "revoke", "g1"))
    assert authority._current("g1")[0] == "revoke"


def test_grant_and_revoke_are_in_the_audit_chain(authority, clock):
    authority.grant(**base_args(clock), attestation=authority.attest("reviewer", "grant", "g1"))
    authority.revoke("g1", "reviewer", "retire", attestation=authority.attest("reviewer", "revoke", "g1"))
    evs = [(r["event"], r["actor"]) for r in audit.read()]
    assert ("dev.authority.granted", "reviewer") in evs and ("dev.authority.revoked", "reviewer") in evs
    assert audit.verify()["ok"]


def test_unauthenticated_failure_is_not_audited_as_a_grant(authority, clock):
    with pytest.raises(AuthorityError):
        authority.grant(**base_args(clock), attestation=None)
    assert "dev.authority.granted" not in [r["event"] for r in audit.read()]


# ---- API routes -------------------------------------------------------------------------------
def _basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


@pytest.fixture
def api_client(monkeypatch):
    import approvers, api
    monkeypatch.delenv("PATIENCE_DEV_OPEN", raising=False)
    monkeypatch.delenv("PATIENCE_LEGACY_APPROVER_TOKEN", raising=False)
    monkeypatch.setenv("PATIENCE_API_TOKEN", "agent-token-0123456789")
    monkeypatch.setenv("PATIENCE_API_TOKEN_OWNERS", "token-owner")
    approvers.add("root", "root-password-12", "admin")
    approvers.add("bob", "bob-password-1234", "approver")
    return TestClient(api.app)


def body(**o):
    v = {k: x for k, x in base_args(Clock()).items() if k not in ("granted_by",)}
    v.update(grant_id="api-g1", actor="default", owners=["token-owner"], human_owner="token-owner",
             expires_at=__import__("time").time() + 7200)
    v.update(o)
    return v


def test_api_grant_requires_named_admin(api_client):
    c = api_client
    assert c.post("/v1/dev/authority/grants", json=body()).status_code == 403
    assert c.post("/v1/dev/authority/grants", json=body(),
                  headers={"Authorization": "Bearer agent-token-0123456789"}).status_code == 403
    assert c.post("/v1/dev/authority/grants", json=body(), headers=_basic("bob", "bob-password-1234")).status_code == 403
    assert c.post("/v1/dev/authority/grants", json=body(), headers=_basic("root", "wrong")).status_code == 403


def test_api_signer_comes_from_login_not_body_and_grant_enables_propose(api_client):
    c = api_client
    r = c.post("/v1/dev/authority/grants", json={**body(), "granted_by": "forged"},
               headers=_basic("root", "root-password-12"))
    assert r.status_code == 200, r.text
    assert r.json()["granted_by"] == "root"
    h = {"Authorization": "Bearer agent-token-0123456789"}
    p = c.post("/v1/dev/check", json={"action": "test.run_isolated", "payload": PAYLOAD,
                                      "authority_grant": "api-g1"}, headers=h)
    assert p.status_code == 200, p.text
    # revoke needs admin, then the same proposal is refused
    assert c.post("/v1/dev/authority/grants/api-g1/revoke", json={"reason": "r"},
                  headers=_basic("bob", "bob-password-1234")).status_code == 403
    assert c.post("/v1/dev/authority/grants/api-g1/revoke", json={"reason": "retired"},
                  headers=_basic("root", "root-password-12")).status_code == 200
    p = c.post("/v1/dev/check", json={"action": "test.run_isolated", "payload": PAYLOAD,
                                      "authority_grant": "api-g1"}, headers=h)
    assert p.status_code == 403 and "revoked" in p.text
    assert audit.verify()["ok"]


def test_api_admin_who_owns_the_agent_cannot_grant_it(api_client):
    r = api_client.post("/v1/dev/authority/grants", json=body(owners=["root"], human_owner="root"),
                        headers=_basic("root", "root-password-12"))
    assert r.status_code == 403


def test_api_revoke_unknown_grant_is_404(api_client):
    assert api_client.post("/v1/dev/authority/grants/nope/revoke", json={"reason": "r"},
                           headers=_basic("root", "root-password-12")).status_code == 404
