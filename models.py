from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import uuid

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass
class Observation:
    content: str
    source: str = "user"
    reliability: float = 0.5
    tags: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=now_iso)

@dataclass
class Assessment:
    relevance: float
    urgency: float
    uncertainty: float
    consequence: float
    opportunity: float
    confidence: float
    evidence: List[str]
    assumptions: List[str]
    unknowns: List[str]
    competing_explanations: List[str]

@dataclass
class ModelVote:
    model: str
    recommendation: str
    confidence: float
    reasoning_summary: str
    dissent: Optional[str] = None

@dataclass
class Decision:
    action: str
    reason: str
    confidence: float
    requires_authorization: bool
    checkpoint: str
    reversible: bool = True
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    proposed: Optional[Dict[str, Any]] = None   # {"executor": name, "params": {...}}
    status: str = "proposed"                    # proposed|pending_authorization|authorized|denied|executed|refused
    created_at: str = field(default_factory=now_iso)

@dataclass
class Task:
    title: str
    status: str = "active"
    priority: int = 3
    due_at: Optional[str] = None
    trigger: Optional[str] = None
    owner: str = "PATIENCE"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class PatienceState:
    version: str = "0.5"
    mission: str = ""
    end_state: str = ""
    current_objective: str = ""
    priority: str = ""
    observations: List[Dict[str, Any]] = field(default_factory=list)
    assessments: List[Dict[str, Any]] = field(default_factory=list)
    model_votes: List[Dict[str, Any]] = field(default_factory=list)
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    tasks: List[Dict[str, Any]] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    authorized_actions: List[str] = field(default_factory=list)
    blocked_actions: List[str] = field(default_factory=list)
    memory: List[Dict[str, Any]] = field(default_factory=list)
    authorizations: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # decision_id -> {approver, timestamp}
    denials: Dict[str, Dict[str, Any]] = field(default_factory=dict)         # decision_id -> {approver, reason, timestamp}
    receipts: Dict[str, Dict[str, Any]] = field(default_factory=dict)        # decision_id -> ExecutionReceipt
    next_checkpoint: str = ""
    last_updated: str = field(default_factory=now_iso)

@dataclass
class ExecutionReceipt:
    decision_id: str
    approver: str
    executor: str
    result: Dict[str, Any]
    result_hash: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=now_iso)
