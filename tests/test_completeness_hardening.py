"""Rough edges found in the completeness pass."""
import sqlite3
import pytest

from dev_governance import CapabilityAuthority, DevGate, GateError
from tests.test_org_authority import Clock, PAYLOAD


@pytest.mark.parametrize("bad", [[1], "text", 5, ["a", "b"], 1.5, True])
@pytest.mark.parametrize("action", ["ci.run", "code.open_pr", "test.run_isolated", "deploy.release", "unknown.thing"])
def test_non_object_payload_is_rejected_not_a_crash(bad, action):
    gate = DevGate(authority=CapabilityAuthority())
    with pytest.raises(GateError) as e:
        gate.propose(action, bad, "agent-1", owners=["matthew"])
    assert e.value.status == 422


def test_missing_payload_still_means_empty_object():
    gate = DevGate()
    assert gate.propose("ci.run", None, "agent-1")["status"] == "allowed"


def test_grant_events_cannot_be_updated_or_deleted_in_place(tmp_path):
    path = str(tmp_path / "authority.db")
    a = CapabilityAuthority(path=path, clock=Clock())
    c = sqlite3.connect(path)
    c.execute("INSERT INTO capability_events(grant_id,event_type,body,created_at) VALUES('x','grant','{}',1)")
    c.commit()
    with pytest.raises(sqlite3.DatabaseError):
        c.execute("UPDATE capability_events SET event_type='revoke'")
    with pytest.raises(sqlite3.DatabaseError):
        c.execute("DELETE FROM capability_events")
    c.close()
    CapabilityAuthority(path=path, clock=Clock())  # reopening an existing DB keeps the triggers


def test_authority_db_is_owner_only(tmp_path):
    import os, stat
    path = str(tmp_path / "authority.db")
    CapabilityAuthority(path=path)
    assert stat.S_IMODE(os.stat(path).st_mode) & 0o077 == 0
