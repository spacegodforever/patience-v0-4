# Principles

## Governance (v0.6) [exists]
1. **Fail closed.** No auth configured = 401. Unknown tool = `unknown_side_effect` = needs approval. Unreadable policy or audit = refuse.
2. **Approval is bound to the exact call** (sha256 of canonical tool+args) and runs at most once.
3. **Humans approve; agents never do.** Agent keys cannot reach approve/deny.
4. **Identity is derived from credentials**, never from request bodies.
5. **The LLM can only add caution**: the second opinion may add `needs_approval`, never remove it.
6. **Everything consequential is audited** in the hash-chained log.
7. **Dry-run by default**; live execution is an explicit opt-in.

## Coordinator principles (from PATIENCE Experimental)
1. **Oracle recommends.** Ranking and model output are advice only.
2. **PATIENCE enforces deterministically.** Allow/approve decisions come from policy code and YAML, not from a model.
3. **The human decides.** Every consequential action needs a human approval through the gate.
4. **Fail closed.** Unknown policy, missing permission, missing audit: refuse.
5. **Only deliberately entered data** is observed: no scraping, file harvesting or background collection.
6. **Basis and confidence** accompany every recommendation and describe only the method that produced it. Model text is labelled unverified.
7. **Previews are approved, not executed.** The coordinator submits previews to `/v1/check`; execution only via `/v1/execute` after approval.
8. **Unknowns are labelled**; the system must not fabricate observations.
9. **Coordinator means prioritization, not agency.** It prepares and ranks; it holds no tool credentials.

## Engineering
- Prefer small, test-backed changes; every guarantee in `test-map.md` must have a test.
- Be explicit about what exists vs. what is proposed. Do not describe PATIENCE as immutable, production-ready or compliant.
