from models import Assessment, Decision

class GovernanceGate:
    AUTONOMOUS = {"respond","research","summarize","log","wait","remind","inspect_state"}

    def decide(self, recommendation: str, a: Assessment, cheapest_test: str) -> Decision:
        if recommendation == "human_review" or a.consequence >= .7:
            return Decision(
                action="human_review",
                reason="Consequence threshold requires explicit authorization.",
                confidence=a.confidence,
                requires_authorization=True,
                checkpoint="After human authorization",
                reversible=False
            )
        if recommendation == "research":
            return Decision(
                action="research",
                reason=cheapest_test,
                confidence=a.confidence,
                requires_authorization=False,
                checkpoint="After evidence acquisition"
            )
        if recommendation == "prototype":
            return Decision(
                action="prototype",
                reason="Test the opportunity with a reversible prototype.",
                confidence=a.confidence,
                requires_authorization=True,
                checkpoint="After prototype verification"
            )
        return Decision(
            action="respond",
            reason="No elevated consequence or evidence deficit detected.",
            confidence=a.confidence,
            requires_authorization=False,
            checkpoint="After user response"
        )

    def may_execute(self, decision: Decision, authorized_actions: list[str]) -> bool:
        if not decision.requires_authorization and decision.action in self.AUTONOMOUS:
            return True
        return decision.action in authorized_actions

    # ---- v0.5: per-decision authorization ----
    def may_execute_decision(self, decision: dict, authorizations: dict, denials: dict | None = None) -> tuple[bool, str]:
        """Authorization is bound to one decision id, never to an action type."""
        did = decision.get("id")
        if denials and did in denials:
            return False, "decision was denied"
        if did in authorizations:
            return True, "authorized:" + str(authorizations[did].get("approver"))
        if not decision.get("requires_authorization") and decision.get("action") in self.AUTONOMOUS:
            return True, "autonomous_policy"
        return False, "requires per-decision authorization"
