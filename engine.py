from dataclasses import asdict
from pathlib import Path
from models import Observation, Task, ExecutionReceipt, now_iso
from llm_oracle import LLMOracle
from audit_log import AuditLog
from executor import ExecutorRegistry, ExecutionRefused, result_hash
from adapters import ModelCouncil
from governance import GovernanceGate
from scheduler import TemporalLayer
from memory_store import MemoryStore

class Patience:
    def __init__(self, state_path="patience_state.json", audit_path=None, sandbox_dir=None, oracle=None):
        state_path = Path(state_path)
        self.memory_store = MemoryStore(state_path)
        self.state = self.memory_store.load()
        self.audit = AuditLog(audit_path or state_path.with_name("audit_log.jsonl"))
        self.executors = ExecutorRegistry(sandbox_dir or state_path.with_name("sandbox"))
        self.oracle = oracle or LLMOracle()
        self.council = ModelCouncil()
        self.governance = GovernanceGate()
        self.time = TemporalLayer()

    def set_mission(self, mission, end_state, objective, priority):
        def text(name, value):
            if value is None:
                return ""
            if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                raise ValueError(f"{name} must be text")
            return str(value).strip()
        self.state.mission = text("mission", mission)
        self.state.end_state = text("end_state", end_state)
        self.state.current_objective = text("objective", objective)
        self.state.priority = text("priority", priority)  # numeric priority coerced to str (v0.4 dashboard crash)
        self.memory_store.save(self.state)
        self.audit.append("mission_set", {"mission": self.state.mission, "priority": self.state.priority})

    def authorize(self, action):
        if action not in self.state.authorized_actions:
            self.state.authorized_actions.append(action)
        self.state.blocked_actions = [x for x in self.state.blocked_actions if x != action]
        self.memory_store.save(self.state)
        self.audit.append("legacy_action_type_authorization", {"action": action,
                          "note": "v0.4 record only; execution requires authorize_decision"})

    def add_task(self, title, due_at=None, priority=3):
        self.time.add_task(self.state, Task(title=title, due_at=due_at, priority=priority))
        self.state.next_checkpoint = self.time.next_checkpoint(self.state)
        self.memory_store.save(self.state)

    def cycle(self, content, source="user", reliability=.9, proposed=None):
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Observation must contain text.")
        if not isinstance(reliability, (int, float)) or not 0 <= reliability <= 1:
            raise ValueError("Reliability must be between zero and one.")
        obs = Observation(content=content, source=source, reliability=reliability)
        self.state.observations.append(asdict(obs))

        assessment = self.oracle.assess(obs, self.state)
        oracle_path = getattr(self.oracle, "last_path", "heuristic")
        oracle_error = getattr(self.oracle, "last_error", None)
        self.state.assessments.append({**asdict(assessment), "oracle_path": oracle_path})
        self.state.assumptions = assessment.assumptions
        self.state.unknowns = assessment.unknowns

        red = self.oracle.red_team(assessment)

        votes = self.council.deliberate(assessment)
        self.state.model_votes.extend(asdict(v) for v in votes)
        recommendation = self.council.consensus(votes)

        decision = self.governance.decide(recommendation, assessment, red["cheapest_test"])
        if proposed is not None:
            if not isinstance(proposed, dict) or "executor" not in proposed:
                raise ValueError("proposed must be {'executor': name, 'params': {...}}")
            decision.proposed = {"executor": str(proposed["executor"]), "params": proposed.get("params") or {}}
        auto_ok, _ = self.governance.may_execute_decision(asdict(decision), {}, {})
        decision.status = "proposed" if auto_ok else "pending_authorization"
        self.state.decisions.append(asdict(decision))
        self.state.next_checkpoint = self.time.next_checkpoint(self.state)

        allowed = self.governance.may_execute(decision, self.state.authorized_actions)
        if not allowed and decision.action not in self.state.blocked_actions:
            self.state.blocked_actions.append(decision.action)

        verification = {
            "verified": False,
            "authorized": allowed,
            "executed": False,
            "status": "authorized_not_executed" if allowed else "blocked_pending_authorization",
            "expected_outcome": decision.checkpoint
        }

        self.memory_store.record_memory(
            self.state,
            "decision",
            f"{decision.action}: {decision.reason}",
            decision.confidence
        )
        self.memory_store.save(self.state)
        self.audit.append("decision", {
            "decision_id": decision.id, "action": decision.action, "status": decision.status,
            "requires_authorization": decision.requires_authorization, "proposed": decision.proposed,
            "observation": obs.content, "oracle_path": oracle_path, "oracle_error": oracle_error,
            "assessment": asdict(assessment),
        })
        self.audit.append("votes", {"decision_id": decision.id, "consensus": recommendation,
                                    "votes": [asdict(v) for v in votes]})

        return {
            "decision_id": decision.id,
            "oracle_path": oracle_path,
            "observation": asdict(obs),
            "assessment": asdict(assessment),
            "red_team": red,
            "model_votes": [asdict(v) for v in votes],
            "consensus": recommendation,
            "decision": asdict(decision),
            "verification": verification,
            "next_checkpoint": self.state.next_checkpoint
        }

    # ---------------- v0.5: per-decision approvals + execution ----------------
    def get_decision(self, decision_id):
        for d in self.state.decisions:
            if d.get("id") == decision_id:
                return d
        raise KeyError(f"unknown decision {decision_id}")

    def propose(self, content, executor, params=None, source="user", reliability=.9):
        return self.cycle(content, source, reliability, proposed={"executor": executor, "params": params or {}})

    def pending(self):
        return [d for d in self.state.decisions if d.get("status") == "pending_authorization"]

    def authorize_decision(self, decision_id, approver):
        if not approver or not str(approver).strip():
            raise ValueError("approver required")
        d = self.get_decision(decision_id)
        if decision_id in self.state.denials:
            raise ValueError("decision already denied")
        if decision_id in self.state.receipts:
            return self.state.authorizations.get(decision_id)
        record = {"approver": str(approver), "timestamp": now_iso()}
        self.state.authorizations[decision_id] = record
        d["status"] = "authorized"
        self.memory_store.save(self.state)
        self.audit.append("authorization", {"decision_id": decision_id, **record})
        return record

    def deny_decision(self, decision_id, approver, reason=""):
        d = self.get_decision(decision_id)
        if decision_id in self.state.receipts:
            raise ValueError("decision already executed")
        record = {"approver": str(approver), "reason": str(reason), "timestamp": now_iso()}
        self.state.denials[decision_id] = record
        self.state.authorizations.pop(decision_id, None)
        d["status"] = "denied"
        self.memory_store.save(self.state)
        self.audit.append("denial", {"decision_id": decision_id, **record})
        return record

    def execute(self, decision_id, approver=None):
        """Run the decision's proposed allowlisted action once. Returns the receipt dict.
        Re-running an executed decision returns the existing receipt and does nothing."""
        if decision_id in self.state.receipts:
            return {**self.state.receipts[decision_id], "already_executed": True}
        d = self.get_decision(decision_id)
        ok, why = self.governance.may_execute_decision(d, self.state.authorizations, self.state.denials)
        proposed = d.get("proposed")
        if ok and not proposed:
            ok, why = False, "decision has no proposed executable action"
        if ok and proposed["executor"] not in self.executors.allowlist:
            ok, why = False, f"executor '{proposed['executor']}' is not allowlisted"
        if not ok:
            self.audit.append("execution_refused", {"decision_id": decision_id, "reason": why})
            raise ExecutionRefused(why)
        try:
            result = self.executors.run(proposed["executor"], proposed.get("params") or {}, self)
        except ExecutionRefused as e:
            self.audit.append("execution_refused", {"decision_id": decision_id, "reason": str(e)})
            raise
        who = self.state.authorizations.get(decision_id, {}).get("approver") or approver or "policy:autonomous"
        receipt = asdict(ExecutionReceipt(decision_id=decision_id, approver=who, executor=proposed["executor"],
                                          result=result, result_hash=result_hash(result)))
        self.state.receipts[decision_id] = receipt
        d["status"] = "executed"
        self.memory_store.save(self.state)
        self.audit.append("execution", {"decision_id": decision_id, "receipt_id": receipt["id"],
                                        "approver": who, "executor": receipt["executor"],
                                        "result_hash": receipt["result_hash"]})
        return receipt

    def verify_audit(self):
        return self.audit.verify()
