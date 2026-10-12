from dataclasses import asdict
from models import Observation, Task
from oracle import Oracle
from adapters import ModelCouncil
from governance import GovernanceGate
from scheduler import TemporalLayer
from memory_store import MemoryStore

class Patience:
    def __init__(self, state_path="patience_state.json"):
        self.memory_store = MemoryStore(state_path)
        self.state = self.memory_store.load()
        self.oracle = Oracle()
        self.council = ModelCouncil()
        self.governance = GovernanceGate()
        self.time = TemporalLayer()

    def set_mission(self, mission, end_state, objective, priority):
        self.state.mission = mission
        self.state.end_state = end_state
        self.state.current_objective = objective
        self.state.priority = priority
        self.memory_store.save(self.state)

    def authorize(self, action):
        if action not in self.state.authorized_actions:
            self.state.authorized_actions.append(action)
        self.state.blocked_actions = [x for x in self.state.blocked_actions if x != action]
        self.memory_store.save(self.state)

    def add_task(self, title, due_at=None, priority=3):
        self.time.add_task(self.state, Task(title=title, due_at=due_at, priority=priority))
        self.state.next_checkpoint = self.time.next_checkpoint(self.state)
        self.memory_store.save(self.state)

    def cycle(self, content, source="user", reliability=.9):
        obs = Observation(content=content, source=source, reliability=reliability)
        self.state.observations.append(asdict(obs))

        assessment = self.oracle.assess(obs, self.state)
        self.state.assessments.append(asdict(assessment))
        self.state.assumptions = assessment.assumptions
        self.state.unknowns = assessment.unknowns

        red = self.oracle.red_team(assessment)

        votes = self.council.deliberate(assessment)
        self.state.model_votes.extend(asdict(v) for v in votes)
        recommendation = self.council.consensus(votes)

        decision = self.governance.decide(recommendation, assessment, red["cheapest_test"])
        self.state.decisions.append(asdict(decision))
        self.state.next_checkpoint = decision.checkpoint

        allowed = self.governance.may_execute(decision, self.state.authorized_actions)
        if not allowed and decision.action not in self.state.blocked_actions:
            self.state.blocked_actions.append(decision.action)

        verification = {
            "verified": allowed,
            "status": "ready_or_executed" if allowed else "blocked_pending_authorization",
            "expected_outcome": decision.checkpoint
        }

        self.memory_store.record_memory(
            self.state,
            "decision",
            f"{decision.action}: {decision.reason}",
            decision.confidence
        )
        self.memory_store.save(self.state)

        return {
            "observation": asdict(obs),
            "assessment": asdict(assessment),
            "red_team": red,
            "model_votes": [asdict(v) for v in votes],
            "consensus": recommendation,
            "decision": asdict(decision),
            "verification": verification,
            "next_checkpoint": self.state.next_checkpoint
        }
