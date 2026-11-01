"""Helpers for C2's two-person rule: critical requests need two distinct named approvers."""
import base64

import approvers

ACCOUNTS = {"tp-first": "tp-first-password-1", "tp-second": "tp-second-password-1"}


def basic(user):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{ACCOUNTS[user]}".encode()).decode()}


def ensure_accounts():
    for u, pw in ACCOUNTS.items():
        try:
            approvers.add(u, pw)
        except Exception:
            pass


def approve_critical(client, rid, reason="ok"):
    """Two distinct named approvals; returns the second response."""
    ensure_accounts()
    r1 = client.post(f"/v1/requests/{rid}/approve", headers=basic("tp-first"), json={"reason": reason})
    assert r1.status_code == 200 and r1.json().get("decision") == "pending_second_approval", r1.text
    return client.post(f"/v1/requests/{rid}/approve", headers=basic("tp-second"), json={"reason": reason})


def second_approval(client, rid, reason="ok"):
    """Add the second distinct approval after a test's own first approval."""
    ensure_accounts()
    return client.post(f"/v1/requests/{rid}/approve", headers=basic("tp-second"), json={"reason": reason})
