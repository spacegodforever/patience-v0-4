# Demo: governed scam triage (new2026.pro)

**What this is:** a scripted, offline demo of PATIENCE governing a scam-reporting workflow.
**What this is not:** it is **rule-based, not ML training**, and it is **not a production scam detector**.
Three hand-written rules with fixed weights; no model is trained or called.

Run: `python -m demos.scam_triage` · Tests: `pytest tests/test_demo_scam_triage.py`

## Data (fixed snapshot, `demos/fixtures/scam_new2026_pro_2026-11-01.json`)
- `new2026.pro` RDAP fields as recorded 2026-11-01: Dynadot Inc, abuse@dynadot.com / +1.6502620100,
  registered 2026-10-27T14:15:19Z, last changed 2026-11-01, client transfer prohibited,
  nameservers riya/hayes.ns.cloudflare.com.
- Site content comes **only from the user's report** (fake casino, deposit/fee before withdrawal,
  unauthorized Crypto.com and Trust Wallet logos). There is no page capture.
- Two **SYNTHETIC** legitimate-operator controls on `.example` domains (old domains, disclosed fictional
  license, no withdraw fee). No real casinos are named.
- The demo never contacts the site, RDAP, or any reporting service.

## Flow
1. **Observe** the fixture read-only (audited).
2. **Assess** (deterministic): `young_domain` (<30 days, weight 30), `deposit_to_withdraw` (45),
   `brand_impersonation` (25); score ≥60 high, ≥30 medium. Each signal carries a basis and confidence;
   user-reported signals are medium confidence. UNKNOWN: operator identity, losses, hosting origin
   behind Cloudflare, license. Controls score low.
3. **Report previews** (registrar email, Cloudflare abuse, Google Safe Browsing) go through the real
   `/v1/check` → `needs_approval`. An unknown/malformed variant also does not get `allow`.
4. **Approve** via approver login (agent keys and anonymous calls are rejected).
5. **Simulated send** through the mock executor only. Sending before approval → 202 pending;
   a changed payload (swapped recipient) → 409. Tests block sockets to prove no network use.
6. **Audit** verifies (append-only, tamper-evident hash chain); editing a record is detected.

## Caveats
- **Policy gap found:** the default policy auto-allows a `send_email` with one recipient. The demo uses
  dedicated tool names (`send_abuse_report_email`, `submit_web_form`) which are unknown to the policy
  and therefore held by the fail-closed default — not by an explicit "external report" rule.
  A test pins the current `send_email` behavior so a policy fix will be noticed.
- Signals for content are the user's claims, unverified. Weights are arbitrary demo values.
- Nothing is actually reported by this demo; real reports were handled separately by a human.
