# Policy note: outbound communication requires approval

**Rule:** anything PATIENCE would send, post, or submit to a third party on the user's behalf
needs a human approval. It never auto-allows, whatever the recipient count.

- **Mechanism:** `outbound_categories` in `policies/default.yaml`. `risk_policy.score_tool`
  ignores `auto_allow` for any tool whose category is listed and adds the reason
  "outbound communication (...): always needs approval".
- **Covered categories:** `communication`, `mass_communication`, `public_publishing`,
  `outbound_report` (new: third-party web forms and abuse reports).
- **Fail closed:** unlisted tools are `unknown_side_effect` → needs approval. If a custom policy
  omits the key, a built-in default still covers communication and publishing.
- **Unchanged:** read-only tools (`list_`, `get_`, …), small refunds within `max_total`, and
  read-only free text still allow.
- **Why:** the scam-triage demo showed a one-recipient `send_email` to an outside party
  auto-allowed. Matthew approved making outbound sends always gated.
- **Limit:** free-text `action` checks rely on the keyword classifier. Communication verbs
  there already map to the communication category, but a tool call that hides an outbound
  send under a non-outbound category (for example a mis-categorized custom tool) is not caught by
  this rule.
