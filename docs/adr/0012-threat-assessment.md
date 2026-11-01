# ADR 0012: Threat assessment as a foundational ingestion layer

- **Status:** Proposed (2026-11-01)
- **Depends on:** ADR 0001–0011 and `docs/principles.md`, which live on the `docs/knowledge-base`
  branch (PR #4). This branch is based on `fix/outbound-requires-approval` (`dce58af`), which does not
  yet contain `docs/adr/`. Numbered 0012 to follow ADR 0011 (memory, devices, autonomy; PR #5).
  Rebase onto PR #4 after it merges.
- **Related:** `demos/scam_triage.py` (branch `demo/scam-triage`), `docs/policy/outbound-communication.md`.

## Context

On 2026-11-01 Matthew encountered **new2026.pro**, a fake crypto casino:

- **Domain age:** registered 2026-10-27T14:15:19Z through Dynadot Inc, so it was **4 days old**. It used
  Cloudflare nameservers (riya/hayes.ns.cloudflare.com), which hide the hosting origin.
- **Advance-fee pattern:** the user reported that it demanded a deposit or fee before any withdrawal.
- **Brand impersonation:** the user reported unauthorized Crypto.com and Trust Wallet logos.
- **Action taken:** a human-approved abuse report went to Dynadot (abuse@dynadot.com). Reports to
  Cloudflare and Google Safe Browsing were started through their web forms; at the time this ADR was
  written they had not been confirmed as submitted.

Building the scam-triage demo exposed a governance gap. The default policy **auto-allowed a
single-recipient `send_email`** (`max_recipients: 9`), so an agent could have emailed a third party in
the user's name without approval. Fix `dce58af` closed it: `outbound_categories` makes every outbound
communication need approval.

Two lessons:
1. **Hostile input reaches PATIENCE as ordinary data.** Without an explicit threat stage, a scam page,
   phishing email or manipulative prompt arrives at the Oracle with the same standing as a trusted
   instruction.
2. **Defaults decide outcomes.** The gap was a silent permissive default, not a bug in any one line.
   The order in which input is digested has to be explicit, and a test has to catch it if someone
   reorders it.

## Decision

Every input PATIENCE ingests, whether a user message, document, page snapshot, email, tool result or
agent proposal, goes through a fixed **precedence hierarchy**. Lower numbers come first, and a later
stage may never undo the safety output of an earlier one.

| # | Stage | Responsibility | Exists today? |
|---|-------|----------------|---------------|
| 0 | **Observe** | Accept only deliberately entered data, read-only. No scraping, crawling or background harvesting. Record where it came from (source, time, who supplied it). | Partly (coordinator principle 5; demo fixtures) |
| 1 | **Threat assessment** | Before any reasoning or action, run the signal catalog. Each signal has a `basis` and a `confidence`. Unknowns are labeled `UNKNOWN`, never guessed. Output: signals, threat level, unknowns. | Demo only (`demos/scam_triage.py`) |
| 2 | **Oracle recommendation** | Rank, compare and suggest using stage 1 output as an input it can't change. Recommendations are advisory and carry a basis and confidence. Model text is unverified. | Yes (`oracle.py`, coordinator) |
| 3 | **Deterministic policy and risk tier** | Policy YAML and code decide allow, needs_approval or deny and set the risk tier. **Threat risk can only raise a tier, never lower it.** | Policy yes; tiers on PR #10; threat input to tiers not yet |
| 4 | **Human approval gate** | A person approves the exact payload (hash-bound) through approver login. Agents never approve. | Yes (v0.6) |
| 5 | **Execute** | Only the approved payload runs, at most once. Dry-run or mock by default. | Yes (`/v1/execute`) |
| 6 | **Audit** | Every stage records to the append-only, tamper-evident hash chain. | Yes (`audit.py`) |

### Precedence invariants (each must have a test)

- **I1, no skipping:** an action can reach stage 5 only with recorded evidence of stages 0–4 for that
  request. The audit trail for an executed request shows observe → threat → oracle → check → approve →
  execute, in that order.
- **I2, the Oracle can't override threat output:** stage 1 output is immutable input to stage 2. If
  the Oracle's recommendation contradicts a threat signal (for example "safe to pay" on a high-threat
  case), the threat result stands and the contradiction is recorded and flagged.
- **I3, threat only raises:** `tier_final = max(tier_policy, tier_from_threat)`. No threat result can
  lower a tier or turn needs_approval into allow.
- **I4, unknown means fail closed:** an unknown signal, a missing stage 1 result, a threat-stage
  error, or an unparseable input is treated as at least *medium* threat and needs approval. It never
  auto-allows.
- **I5, outbound is always gated:** anything sent, posted or submitted to a third party on the user's
  behalf needs approval regardless of threat level (already enforced by `dce58af`).
- **I6, observe is read-only:** stages 0–1 have no tool credentials and make no network calls, so
  assessing a threat can't contact the threat.

## Components

### Signal catalog (deterministic rules, versioned in YAML)

| Signal | Basis | Default confidence |
|---|---|---|
| `young_domain` | RDAP registration date under 30 days before the observation | high (registry data) |
| `deposit_to_withdraw` | Payment demanded before funds are released (advance fee) | medium if user-reported; high if captured |
| `brand_impersonation` | Third-party marks shown without evidence of authorization | medium |
| `lookalike_domain` | Edit distance or homoglyph closeness to a known brand domain (supplied list) | medium |
| `urgency_pressure` | Deadline or countdown language ("act now", "account frozen") | low–medium |
| `unverifiable_license` | Gaming or financial license claimed but missing, or not verifiable from supplied data | medium; `UNKNOWN` if absent |
| `payment_method_red_flags` | Irreversible rails only: crypto, gift cards, wire to individuals | medium |

The weights and thresholds are explicit numbers in the policy, and changing them requires updating
the case library.

### Takedown-report previews
The registrar abuse email, the Cloudflare abuse form and the Google Safe Browsing report are produced
as **previews** built from the evidence and routed through `/v1/check`. They always need approval (I5)
and are executed only after approval.

### Labeled case library
Every real decision becomes a labeled, anonymized test case (fixture plus expected signals, threat
level and decision). The library must include **synthetic legitimate-operator controls**
(`.example` domains, never real operators) so false positives are visible. New rules may not ship if
any existing case regresses.

### Dashboard panel
A read-only panel showing, for each pending request, its threat signals with basis, confidence and
unknowns, next to the policy tier and approval controls, so the approver sees the threat stage before
deciding.

## Honest limits

- **Rule-based, not ML.** "Training" here means adding labeled cases and rules. No model is trained.
- **Not a production scam detector.** It's a governance layer for PATIENCE's own inputs and actions,
  with coverage limited to the signal catalog.
- **False positives are a real risk:** a new but legitimate site, or a legitimate partner's logo.
  Synthetic controls exist to catch this, but they are not proof that it won't happen.
- **User-reported content is unverified.** Without a capture, content signals stay at medium
  confidence.
- **The audit log is append-only and tamper-evident**, not immutable. Someone with host access can
  truncate it; verification detects edits, and off-host checkpoints (PR #9) help.
- The hierarchy is enforced by code and tests, not by any guarantee beyond them.

## Phased plan

| Phase | Scope | Acceptance criteria |
|---|---|---|
| **T1, threat module** | Move the demo rules into `threat.py` with a YAML signal catalog; pure, deterministic, no network. | The same input gives the same output (golden tests); every signal has basis and confidence; unknown fields are labeled; a socket-blocked test passes; the new2026.pro case is high and the synthetic controls are low. |
| **T2, pipeline wiring** | `/v1/check` runs stage 1 before policy, stores the result with the request, and audits a `threat.assess` record. | Tests prove I1 (audit order), I3 (threat raises a tier, never lowers it), I4 (missing or errored threat result means needs_approval). Existing suite stays green. |
| **T3, Oracle precedence** | Stage 1 output passed to the Oracle and coordinator as read-only; contradictions flagged. | A test proves I2: an Oracle "allow/safe" on a high-threat case still needs approval and records an `oracle.contradiction` audit event. |
| **T4, case library and remaining signals** | `tests/cases/threat/` with labeled real (anonymized) and synthetic cases; add lookalike, urgency, license and payment signals. | At least 20 cases including at least 5 synthetic controls; a precision/recall report printed by the test run (not claimed beyond the library); no control rated high. |
| **T5, report previews and dashboard** | Takedown previews as first-class tools (category `outbound_report`) and the dashboard threat panel. | Previews always need approval (I5 test); the panel shows signals, basis, confidence and unknowns before the approve button; panel tests pass; sends are mock-only in tests. |

## Proposed additions to `docs/principles.md`

`docs/principles.md` is on PR #4 and not on this base, so the text is proposed here. Add it as a
new top section, **"Order of operations (ADR 0012)"**:

> 1. **Observe, then assess threats, then reason.** Every input passes the threat stage before the
>    Oracle sees it or any action is proposed.
> 2. **The hierarchy is fixed:** observe → threat assessment → Oracle → deterministic policy/tier →
>    human approval → execute → audit. No stage is skipped.
> 3. **Threat results only add caution.** They can raise a risk tier, never lower one, and the Oracle
>    cannot override them.
> 4. **Unknown means fail closed.** A missing, unknown or failed threat assessment needs approval.
> 5. **Outbound is always gated.** Anything sent, posted or submitted on the user's behalf needs a
>    human approval.
> 6. **Assessing a threat never contacts it.** The observe and threat stages are read-only and offline.
> 7. **Every decision can become a case.** Real decisions feed the labeled case library, with
>    synthetic controls, so the rules are tested against what actually happened.
