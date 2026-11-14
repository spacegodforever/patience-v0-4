# PATIENCE Core Principle: Accurate Contact with Unmet Need

## Distinction

Standard regulation techniques (mindfulness, micro-patience, trigger identification, slowed movement, grounding sequences such as 5-4-3-2-1, physiological sighs) are valid first-line tools for buying seconds of choice when a nervous system is overloaded. They are not the core of PATIENCE.

The operational distinction:

- **Regulation** produces functional tolerance. It down-regulates the spike so the organism can continue without immediate explosion.
- **Accurate contact** keeps precise registration of what is missing (the unmet need, the real cost of waiting, the deficit) without collapsing into reactive demand or into premature peace / spiritualized indifference.

Urgency is frequently an accurate signal that something required is not present and that delay has a measurable cost. Treating every urgency as a pathology to be regulated away is a category error. Some signals are information that must remain visible.

## Mapping to PATIENCE Architecture

Existing invariants remain unchanged:

- Oracle recommends; PATIENCE enforces deterministically; authorized human decides consequential actions.
- Unknown policy or missing permission fails closed.
- Only deliberately entered data is observed.
- Recommendations carry basis and confidence; unknowns are labeled, never fabricated.
- External actions are previews a human approves.
- Coordinator mode = prioritization and preparation, not unrestricted agency.

Integration points for the refined principle:

1. **Representation of deficit / urgency**  
   Assessments already carry consequence, confidence, and evidence status. Extend the model (models.py / Assessment) so that an explicit `deficit_precision` or `unmet_need` field can record the specific missing element without auto-resolving it. High consequence or high uncertainty does not suppress the description of the gap; it routes to human_review.

2. **Gate behavior (governance.py)**  
   The GovernanceGate already forces human_review on elevated consequence. Preserve this. Do not add soft paths that convert an unmet need into an autonomous "wait" or "remind" solely to reduce surface urgency. A "carryable absence" is labeled as such and left visible in the pending queue and audit log; an "actionable deficit" remains a recommendation that still requires authorization when consequence is high.

3. **Audit and recommendations**  
   Every audit entry and recommendation must distinguish:  
   - actionable deficit (something that can be met by a permitted, authorized action)  
   - carryable absence (something that can only be held; no action is proposed or the proposal is explicitly "hold and surface").  
   Basis text must state the distinction. Confidence is never used to erase the description of what is missing.

4. **Coordinator / Oracle layer**  
   When the local coordinator (FastAPI + SQLite + optional Ollama) produces an action preview, the preview must include the precise statement of any unmet element. The approval gate and hash-chained audit log retain the original wording; no post-processing softens it into generic empathy language.

5. **Fail-closed alignment**  
   If the system cannot determine whether a need is actionable or only carryable, it labels the unknown and routes to human decision. It does not invent a resolution or a comforting frame.

## Non-goals

- This principle does not replace the existing consequence thresholds or per-decision authorization.  
- It does not authorize the system to "manage" the human by regulating their urgency away.  
- It does not claim the system is production-ready, compliant, or capable of true sentience.

## Implementation notes (non-binding)

Any concrete code changes (new fields, updated Decision/Assessment structures, gate comments, or UI surface of the distinction) must occur on a new branch, pass existing tests, and never weaken the human-in-loop or fail-closed rules. See current governance.py and models.py for the baseline.

---
*Integrated from direct discussion of the difference between regulation and remaining precise about what is missing. Date: 2026-11-14.*