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
        if decision.action in self.AUTONOMOUS:
            return True
        return decision.action in authorized_actions
