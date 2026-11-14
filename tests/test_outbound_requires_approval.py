"""Outbound communication on the user's behalf always needs approval (never auto-allows)."""
import pytest
import risk_policy
from tests.test_phase2 import client, chk  # noqa: F401  (reuse fixture + helper)

OUTBOUND = [
    ("send_email", {"recipients": ["a@x.com"], "subject": "hi"}),
    ("send_message", {"recipients": ["a@x.com"]}),
    ("send_sms", {"recipients": ["+15550100"]}),
    ("send_dm", {"recipients": ["@someone"]}),
    ("reply_email", {"recipients": ["a@x.com"]}),
    ("forward_email", {"recipients": ["a@x.com"]}),
    ("post_message", {"channel": "general", "text": "hi"}),
    ("slack_post_message", {"channel": "general", "text": "hi"}),
    ("post", {"channel": "blog"}),
    ("publish", {"channel": "twitter"}),
    ("submit_web_form", {"form": "contact"}),
    ("submit_abuse_report", {"domain": "bad.example"}),
    ("send_abuse_report_email", {"to": "abuse@registrar.example", "subject": "report"}),
]


def test_single_recipient_send_email_needs_approval(client):
    r = chk(client, tool="send_email", args={"recipients": ["a@x.com"], "subject": "hi", "body": "hello"})
    assert r["decision"] == "needs_approval"
    assert "communication" in r["risk_categories"]


@pytest.mark.parametrize("tool,args", OUTBOUND)
def test_each_outbound_tool_needs_approval(client, tool, args):
    assert chk(client, tool=tool, args=args)["decision"] == "needs_approval"


def test_auto_allow_ignored_for_outbound_category():
    p = risk_policy.get_policy()
    p.tools["custom_notify"] = {"category": "communication", "recipients_arg": "recipients",
                                "auto_allow": {"max_recipients": 99}}
    try:
        r = risk_policy.score_tool("custom_notify", {"recipients": ["a@x.com"]}, p)
        assert "communication" in r["categories"] and any("always needs approval" in x for x in r["reasons"])
    finally:
        p.tools.pop("custom_notify")


def test_policy_declares_outbound_categories():
    assert {"communication", "mass_communication", "public_publishing", "outbound_report"} <= risk_policy.get_policy().outbound


def test_non_outbound_low_risk_unchanged(client):
    assert chk(client, tool="list_orders", args={"limit": 5})["decision"] == "allow"
    assert chk(client, tool="refund", args={"amount": 40, "count": 2})["decision"] == "allow"
    assert chk(client, action="Summarize this week's sign-ups")["decision"] == "allow"
    assert chk(client, tool="frobnicate_ledger", args={})["decision"] == "needs_approval"
