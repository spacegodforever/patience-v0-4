from __future__ import annotations

from . import uow as _uow

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone, date
from enum import Enum
from pathlib import Path
from typing import List, Optional


class ExperienceSignalType(str, Enum):
    POSITIVE_FEEDBACK = "positive_feedback"
    PAIN_POINT_REMOVED = "pain_point_removed"
    ADOPTION = "adoption"
    RETENTION = "retention"
    SUPPORT_RESOLUTION = "support_resolution"
    REFERRAL = "referral"
    USABILITY_WIN = "usability_win"
    TRUST_SIGNAL = "trust_signal"


class ControlDomain(str, Enum):
    GOVERNANCE = "governance"
    FINANCIAL = "financial"
    OPERATIONAL = "operational"
    SECURITY = "security"
    CUSTOMER_EXPERIENCE = "customer_experience"
    COMPLIANCE = "compliance"
    PRODUCT = "product"
    PEOPLE = "people"


class ControlStatus(str, Enum):
    ACTIVE = "active"
    NEEDS_REVIEW = "needs_review"
    FAILED = "failed"
    RETIRED = "retired"


class InnovationRiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class RiskPosture(str, Enum):
    EXPLOIT = "exploit"      # upside outweighs risk and controls are in place
    ACCEPT = "accept"        # consciously accepted within guardrails
    MITIGATE = "mitigate"    # reduce risk before scale
    CONTAIN = "contain"      # stop expansion until control exists
    TRANSFER = "transfer"    # move risk through partner/legal/insurance/vendor path


class InnovationStatus(str, Enum):
    ACTIVE = "active"
    WATCH = "watch"
    CONTAINED = "contained"
    SCALING = "scaling"
    CLOSED = "closed"


@dataclass
class CustomerExperienceInfluence:
    segment: str
    touchpoint: str
    positive_outcome: str
    signal_type: ExperienceSignalType
    metric_name: str
    baseline_value: float
    current_value: float
    target_value: float
    evidence_source: str
    owner: str
    confidence: float
    customer_quotes: List[str] = field(default_factory=list)
    linked_project: str = ""
    follow_up_action: str = ""
    friction_removed: str = ""
    notes: str = ""
    observed_at: str = field(default_factory=lambda: utc_now())

    def improvement_ratio(self) -> float:
        if self.target_value == self.baseline_value:
            if self.target_value <= 0:
                return 0.0
            return clamp(self.current_value / self.target_value, 0.0, 1.0)
        return clamp((self.current_value - self.baseline_value) / (self.target_value - self.baseline_value), 0.0, 1.0)

    def influence_score(self) -> float:
        evidence_strength = 0.0
        if self.evidence_source.strip():
            evidence_strength += 0.45
        if self.customer_quotes:
            evidence_strength += 0.20
        if self.follow_up_action.strip():
            evidence_strength += 0.20
        if self.linked_project.strip():
            evidence_strength += 0.15
        score = (
            self.improvement_ratio() * 50
            + clamp(self.confidence, 0.0, 1.0) * 30
            + evidence_strength * 20
        )
        return round(clamp(score, 0.0, 100.0), 2)

    def recommended_next_step(self) -> str:
        if not self.follow_up_action.strip():
            return "Define the next customer follow-up action so the positive signal compounds instead of fading."
        if self.influence_score() >= 75:
            return f"Scale the winning touchpoint carefully: {self.follow_up_action}"
        if self.confidence < 0.55:
            return "Gather stronger evidence before treating this as a proven customer experience win."
        return self.follow_up_action


@dataclass
class EnterpriseControl:
    domain: ControlDomain
    control_name: str
    purpose: str
    owner: str
    status: ControlStatus
    risk_level: InnovationRiskLevel
    review_cadence_days: int = 30
    evidence_required: List[str] = field(default_factory=list)
    last_reviewed_at: str = ""
    next_review_due: str = ""
    linked_policy: str = ""
    notes: str = ""

    def is_overdue(self) -> bool:
        if not self.next_review_due.strip():
            return self.status in {ControlStatus.NEEDS_REVIEW, ControlStatus.FAILED}
        parsed = parse_date(self.next_review_due)
        if not parsed:
            return False
        return parsed < date.today()

    def control_score(self) -> float:
        base = {
            ControlStatus.ACTIVE: 88,
            ControlStatus.NEEDS_REVIEW: 55,
            ControlStatus.FAILED: 18,
            ControlStatus.RETIRED: 40,
        }[self.status]
        risk_penalty = {
            InnovationRiskLevel.LOW: 0,
            InnovationRiskLevel.MODERATE: 6,
            InnovationRiskLevel.HIGH: 14,
            InnovationRiskLevel.CRITICAL: 24,
        }[self.risk_level]
        evidence_bonus = min(len(self.evidence_required) * 2, 8)
        if self.last_reviewed_at.strip():
            evidence_bonus += 5
        overdue_penalty = 22 if self.is_overdue() else 0
        return round(clamp(base - risk_penalty + evidence_bonus - overdue_penalty, 0.0, 100.0), 2)

    def recommended_action(self) -> str:
        if self.status == ControlStatus.FAILED:
            return "Contain the related operation, assign remediation owner, and record proof before resuming expansion."
        if self.is_overdue():
            return "Review this control now; update evidence, next review date, and any changed risk assumptions."
        if self.control_score() < 65:
            return "Strengthen this control with clearer evidence, review cadence, and owner accountability."
        return "Maintain cadence and keep evidence current."


@dataclass
class InnovationRiskItem:
    name: str
    hypothesis: str
    opportunity: str
    risk: str
    owner: str
    risk_level: InnovationRiskLevel
    posture: RiskPosture
    upside_score: float
    evidence_quality: float
    control_link: str = ""
    next_experiment: str = ""
    kill_criteria: str = ""
    status: InnovationStatus = InnovationStatus.ACTIVE
    notes: str = ""

    def risk_adjusted_score(self) -> float:
        risk_penalty = {
            InnovationRiskLevel.LOW: 4,
            InnovationRiskLevel.MODERATE: 12,
            InnovationRiskLevel.HIGH: 24,
            InnovationRiskLevel.CRITICAL: 38,
        }[self.risk_level]
        posture_bonus = {
            RiskPosture.EXPLOIT: 14,
            RiskPosture.ACCEPT: 6,
            RiskPosture.MITIGATE: 0,
            RiskPosture.TRANSFER: -2,
            RiskPosture.CONTAIN: -18,
        }[self.posture]
        control_bonus = 12 if self.control_link.strip() else 0
        experiment_bonus = 8 if self.next_experiment.strip() else -8
        kill_bonus = 8 if self.kill_criteria.strip() else -8
        score = (
            clamp(self.upside_score, 0.0, 100.0) * 0.48
            + clamp(self.evidence_quality, 0.0, 1.0) * 100 * 0.30
            + 20
            + posture_bonus
            + control_bonus
            + experiment_bonus
            + kill_bonus
            - risk_penalty
        )
        if self.status == InnovationStatus.CONTAINED:
            score = min(score, 40)
        if self.status == InnovationStatus.CLOSED:
            score = min(score, 25)
        return round(clamp(score, 0.0, 100.0), 2)

    def command_lane(self) -> str:
        if self.posture == RiskPosture.CONTAIN or self.status == InnovationStatus.CONTAINED:
            return "contain"
        if self.risk_level in {InnovationRiskLevel.HIGH, InnovationRiskLevel.CRITICAL} and not self.control_link.strip():
            return "contain"
        if self.risk_adjusted_score() >= 72 and self.status in {InnovationStatus.ACTIVE, InnovationStatus.SCALING}:
            return "act_now"
        if self.risk_adjusted_score() >= 50:
            return "prepare"
        return "watch"

    def recommended_action(self) -> str:
        if self.command_lane() == "contain":
            return "Do not scale this innovation until the control link, evidence threshold, and kill criteria are explicit."
        if not self.next_experiment.strip():
            return "Define the next small experiment before investing more time, capital, or reputation."
        if not self.kill_criteria.strip():
            return "Add kill criteria so innovation stays disciplined and does not become uncontrolled risk."
        if self.command_lane() == "act_now":
            return f"Run the next controlled experiment: {self.next_experiment}"
        return "Prepare missing proof or control evidence before scaling."


class ExperienceControlDB:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        # PATIENCE: route through the unit of work so writes commit only after the audit append.
        return _uow.connect(self.db_path)

    def _init_db(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS customer_experience_influences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    segment TEXT NOT NULL,
                    touchpoint TEXT NOT NULL,
                    positive_outcome TEXT NOT NULL,
                    signal_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    baseline_value REAL NOT NULL,
                    current_value REAL NOT NULL,
                    target_value REAL NOT NULL,
                    evidence_source TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    customer_quotes_json TEXT NOT NULL,
                    linked_project TEXT,
                    follow_up_action TEXT,
                    friction_removed TEXT,
                    notes TEXT,
                    observed_at TEXT NOT NULL,
                    influence_score REAL NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enterprise_controls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    control_name TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    review_cadence_days INTEGER NOT NULL,
                    evidence_required_json TEXT NOT NULL,
                    last_reviewed_at TEXT,
                    next_review_due TEXT,
                    linked_policy TEXT,
                    notes TEXT,
                    control_score REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(domain, control_name)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS innovation_risks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    hypothesis TEXT NOT NULL,
                    opportunity TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    posture TEXT NOT NULL,
                    upside_score REAL NOT NULL,
                    evidence_quality REAL NOT NULL,
                    control_link TEXT,
                    next_experiment TEXT,
                    kill_criteria TEXT,
                    status TEXT NOT NULL,
                    notes TEXT,
                    risk_adjusted_score REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def add_customer_influence(self, item: CustomerExperienceInfluence) -> CustomerExperienceInfluence:
        self._validate_customer_influence(item)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO customer_experience_influences (
                    segment, touchpoint, positive_outcome, signal_type, metric_name,
                    baseline_value, current_value, target_value, evidence_source, owner,
                    confidence, customer_quotes_json, linked_project, follow_up_action,
                    friction_removed, notes, observed_at, influence_score, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    clean(item.segment), clean(item.touchpoint), item.positive_outcome.strip(), item.signal_type.value,
                    clean(item.metric_name), item.baseline_value, item.current_value, item.target_value,
                    item.evidence_source.strip(), item.owner.strip(), item.confidence,
                    json.dumps(item.customer_quotes), clean(item.linked_project), item.follow_up_action.strip(),
                    item.friction_removed.strip(), item.notes.strip(), item.observed_at.strip(), item.influence_score(), now,
                ),
            )
            conn.commit()
        return item

    def list_customer_influences(self, segment: str = "", touchpoint: str = "") -> List[CustomerExperienceInfluence]:
        query = "SELECT * FROM customer_experience_influences"
        clauses: list[str] = []
        params: list[str] = []
        if segment.strip():
            clauses.append("lower(segment)=lower(?)")
            params.append(clean(segment))
        if touchpoint.strip():
            clauses.append("lower(touchpoint)=lower(?)")
            params.append(clean(touchpoint))
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY influence_score DESC, observed_at DESC"
        with self.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [row_to_customer_influence(row) for row in rows]

    def upsert_enterprise_control(self, control: EnterpriseControl) -> EnterpriseControl:
        self._validate_control(control)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO enterprise_controls (
                    domain, control_name, purpose, owner, status, risk_level,
                    review_cadence_days, evidence_required_json, last_reviewed_at,
                    next_review_due, linked_policy, notes, control_score, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain, control_name) DO UPDATE SET
                    purpose=excluded.purpose,
                    owner=excluded.owner,
                    status=excluded.status,
                    risk_level=excluded.risk_level,
                    review_cadence_days=excluded.review_cadence_days,
                    evidence_required_json=excluded.evidence_required_json,
                    last_reviewed_at=excluded.last_reviewed_at,
                    next_review_due=excluded.next_review_due,
                    linked_policy=excluded.linked_policy,
                    notes=excluded.notes,
                    control_score=excluded.control_score,
                    updated_at=excluded.updated_at
                """,
                (
                    control.domain.value, clean(control.control_name), control.purpose.strip(), control.owner.strip(),
                    control.status.value, control.risk_level.value, control.review_cadence_days,
                    json.dumps(control.evidence_required), control.last_reviewed_at.strip(), control.next_review_due.strip(),
                    control.linked_policy.strip(), control.notes.strip(), control.control_score(), now, now,
                ),
            )
            conn.commit()
        return self.get_enterprise_control(control.domain.value, control.control_name)

    def get_enterprise_control(self, domain: str, control_name: str) -> EnterpriseControl:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM enterprise_controls WHERE lower(domain)=lower(?) AND lower(control_name)=lower(?)",
                (clean(domain), clean(control_name)),
            ).fetchone()
        if not row:
            raise KeyError(f"No enterprise control found for {domain} / {control_name}")
        return row_to_enterprise_control(row)

    def list_enterprise_controls(self, domain: str = "") -> List[EnterpriseControl]:
        query = "SELECT * FROM enterprise_controls"
        params: tuple = ()
        if domain.strip():
            query += " WHERE lower(domain)=lower(?)"
            params = (clean(domain),)
        query += " ORDER BY control_score ASC, domain ASC, control_name ASC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [row_to_enterprise_control(row) for row in rows]

    def upsert_innovation_risk(self, item: InnovationRiskItem) -> InnovationRiskItem:
        self._validate_innovation_risk(item)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO innovation_risks (
                    name, hypothesis, opportunity, risk, owner, risk_level, posture,
                    upside_score, evidence_quality, control_link, next_experiment,
                    kill_criteria, status, notes, risk_adjusted_score, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    hypothesis=excluded.hypothesis,
                    opportunity=excluded.opportunity,
                    risk=excluded.risk,
                    owner=excluded.owner,
                    risk_level=excluded.risk_level,
                    posture=excluded.posture,
                    upside_score=excluded.upside_score,
                    evidence_quality=excluded.evidence_quality,
                    control_link=excluded.control_link,
                    next_experiment=excluded.next_experiment,
                    kill_criteria=excluded.kill_criteria,
                    status=excluded.status,
                    notes=excluded.notes,
                    risk_adjusted_score=excluded.risk_adjusted_score,
                    updated_at=excluded.updated_at
                """,
                (
                    clean(item.name), item.hypothesis.strip(), item.opportunity.strip(), item.risk.strip(), item.owner.strip(),
                    item.risk_level.value, item.posture.value, item.upside_score, item.evidence_quality,
                    item.control_link.strip(), item.next_experiment.strip(), item.kill_criteria.strip(), item.status.value,
                    item.notes.strip(), item.risk_adjusted_score(), now, now,
                ),
            )
            conn.commit()
        return self.get_innovation_risk(item.name)

    def get_innovation_risk(self, name: str) -> InnovationRiskItem:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM innovation_risks WHERE lower(name)=lower(?)", (clean(name),)).fetchone()
        if not row:
            raise KeyError(f"No innovation risk found: {name}")
        return row_to_innovation_risk(row)

    def list_innovation_risks(self, active_only: bool = True) -> List[InnovationRiskItem]:
        query = "SELECT * FROM innovation_risks"
        params: tuple = ()
        if active_only:
            query += " WHERE status != ?"
            params = (InnovationStatus.CLOSED.value,)
        query += " ORDER BY risk_adjusted_score DESC, name ASC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [row_to_innovation_risk(row) for row in rows]

    def positive_customer_impact(self) -> dict:
        influences = self.list_customer_influences()
        by_touchpoint: dict[str, list[dict]] = {}
        top = []
        for item in influences:
            payload = customer_influence_to_dict(item)
            by_touchpoint.setdefault(item.touchpoint, []).append(payload)
            top.append(payload)
        scores = [item.influence_score() for item in influences]
        return {
            "generated_at": utc_now(),
            "influence_count": len(influences),
            "average_influence_score": avg(scores),
            "top_positive_influences": sorted(top, key=lambda row: row["influence_score"], reverse=True)[:10],
            "by_touchpoint": by_touchpoint,
            "interpretation": interpret_customer_impact(avg(scores), len(influences)),
        }

    def enterprise_control_status(self) -> dict:
        controls = self.list_enterprise_controls()
        failed = [c for c in controls if c.status == ControlStatus.FAILED]
        overdue = [c for c in controls if c.is_overdue()]
        critical = [c for c in controls if c.risk_level == InnovationRiskLevel.CRITICAL and c.status != ControlStatus.ACTIVE]
        scores = [c.control_score() for c in controls]
        return {
            "generated_at": utc_now(),
            "control_count": len(controls),
            "average_control_score": avg(scores),
            "failed_count": len(failed),
            "overdue_count": len(overdue),
            "critical_attention_count": len(critical),
            "failed_controls": [enterprise_control_to_dict(c) for c in failed],
            "overdue_controls": [enterprise_control_to_dict(c) for c in overdue],
            "critical_attention": [enterprise_control_to_dict(c) for c in critical],
            "all_controls": [enterprise_control_to_dict(c) for c in controls],
            "interpretation": interpret_control_status(avg(scores), failed, overdue, critical),
        }

    def innovation_risk_portfolio(self) -> dict:
        risks = self.list_innovation_risks(active_only=True)
        scores = [r.risk_adjusted_score() for r in risks]
        contained = [r for r in risks if r.command_lane() == "contain"]
        act_now = [r for r in risks if r.command_lane() == "act_now"]
        prepare = [r for r in risks if r.command_lane() == "prepare"]
        watch = [r for r in risks if r.command_lane() == "watch"]
        return {
            "generated_at": utc_now(),
            "risk_item_count": len(risks),
            "average_risk_adjusted_score": avg(scores),
            "lanes": {
                "contain": [innovation_risk_to_dict(r) for r in contained],
                "act_now": [innovation_risk_to_dict(r) for r in act_now],
                "prepare": [innovation_risk_to_dict(r) for r in prepare],
                "watch": [innovation_risk_to_dict(r) for r in watch],
            },
            "interpretation": interpret_innovation_portfolio(avg(scores), contained, act_now),
        }

    def customer_control_snapshot(self) -> dict:
        cx = self.positive_customer_impact()
        controls = self.enterprise_control_status()
        innovation = self.innovation_risk_portfolio()
        stability_score = avg([
            cx["average_influence_score"],
            controls["average_control_score"],
            innovation["average_risk_adjusted_score"],
        ])
        return {
            "generated_at": utc_now(),
            "operating_principle": "Customer experience gains are allowed to scale only when enterprise controls and risk guardrails stay visible.",
            "enterprise_modality_score": stability_score,
            "customer_experience": cx,
            "enterprise_controls": controls,
            "innovation_risk": innovation,
            "board_summary": summarize_customer_control(stability_score, cx, controls, innovation),
        }

    def seed_demo_data(self) -> None:
        # Keep seed idempotent for demos: controls and risks are upserts; influence
        # observations are append-only in normal use, so remove demo observations first.
        with self.connect() as conn:
            conn.execute(
                """
                DELETE FROM customer_experience_influences
                WHERE evidence_source IN (?, ?)
                   OR linked_project IN (?, ?)
                """,
                (
                    "manual demo notes",
                    "system-generated recovery report",
                    "PATIENCE Control Plane",
                    "Operations Matrix API",
                ),
            )
            conn.commit()

        self.add_customer_influence(CustomerExperienceInfluence(
            segment="early adopters",
            touchpoint="prototype demo",
            positive_outcome="Users understand the Oracle/PATIENCE command board faster when actions are separated into contain, act now, prepare, and watch.",
            signal_type=ExperienceSignalType.USABILITY_WIN,
            metric_name="demo_clarity_score",
            baseline_value=40,
            current_value=72,
            target_value=85,
            evidence_source="manual demo notes",
            owner="Matthew",
            confidence=0.68,
            customer_quotes=["The lanes make it easier to know what to do first."],
            linked_project="PATIENCE Control Plane",
            follow_up_action="Run three more demo reviews and record confusion points by touchpoint.",
            friction_removed="Reduced ambiguity between urgent action and governed preparation.",
            notes="Early signal that command language improves customer comprehension.",
        ))
        self.add_customer_influence(CustomerExperienceInfluence(
            segment="operator / founder",
            touchpoint="recovery actions",
            positive_outcome="The system translates weak cells into owner-based recovery steps instead of vague alerts.",
            signal_type=ExperienceSignalType.PAIN_POINT_REMOVED,
            metric_name="actionability_score",
            baseline_value=35,
            current_value=76,
            target_value=90,
            evidence_source="system-generated recovery report",
            owner="Operations Lead",
            confidence=0.72,
            linked_project="Operations Matrix API",
            follow_up_action="Add evidence-of-completion fields to each recovery action.",
            friction_removed="Reduced operational noise by making each weak area actionable.",
        ))
        self.upsert_enterprise_control(EnterpriseControl(
            domain=ControlDomain.CUSTOMER_EXPERIENCE,
            control_name="CX Evidence Trail",
            purpose="Every positive customer impact claim must link to metric, source, owner, and follow-up action.",
            owner="Matthew",
            status=ControlStatus.ACTIVE,
            risk_level=InnovationRiskLevel.HIGH,
            review_cadence_days=7,
            evidence_required=["metric", "evidence source", "owner", "follow-up action"],
            last_reviewed_at=str(date.today()),
            next_review_due="",
            linked_policy="Customer Experience Influence Tracking",
            notes="Prevents inflated claims and keeps customer value auditable.",
        ))
        self.upsert_enterprise_control(EnterpriseControl(
            domain=ControlDomain.FINANCIAL,
            control_name="Investor Readiness Gate",
            purpose="Capital outreach requires proof packet, risk note, and customer-impact evidence before scaling claims.",
            owner="Matthew",
            status=ControlStatus.NEEDS_REVIEW,
            risk_level=InnovationRiskLevel.CRITICAL,
            review_cadence_days=7,
            evidence_required=["proof packet", "risk note", "customer-impact evidence", "use of funds"],
            notes="Needs final review before new investor pool outreach.",
        ))
        self.upsert_enterprise_control(EnterpriseControl(
            domain=ControlDomain.SECURITY,
            control_name="Sensitive Data Handling",
            purpose="No customer, employment, investor, or partner data enters the system without permission and purpose fields.",
            owner="Matthew",
            status=ControlStatus.ACTIVE,
            risk_level=InnovationRiskLevel.CRITICAL,
            review_cadence_days=7,
            evidence_required=["source", "permission", "purpose", "retention note"],
            last_reviewed_at=str(date.today()),
            linked_policy="Data Governance",
            notes="Protects trust while expanding operations.",
        ))
        self.upsert_innovation_risk(InnovationRiskItem(
            name="Customer Impact Command Board",
            hypothesis="Tracking customer impact next to controls will make Oracle/PATIENCE easier to trust and easier to scale.",
            opportunity="Turn scattered customer signals into a defensible operating score for partners, employers, and investors.",
            risk="Overclaiming impact without enough evidence could weaken credibility.",
            owner="Matthew",
            risk_level=InnovationRiskLevel.HIGH,
            posture=RiskPosture.MITIGATE,
            upside_score=82,
            evidence_quality=0.62,
            control_link="CX Evidence Trail",
            next_experiment="Review five customer/operator interactions and log influence events with before/after metrics.",
            kill_criteria="Stop expanding claims if fewer than three evidence-backed customer impact records exist after two review cycles.",
            status=InnovationStatus.ACTIVE,
            notes="High upside when governed by evidence trail and clear review cadence.",
        ))
        self.upsert_innovation_risk(InnovationRiskItem(
            name="Investor Pool Expansion",
            hypothesis="New investor pools can accelerate growth if outreach is sequenced after proof and customer impact evidence.",
            opportunity="Qualify angels, workforce grants, and innovation funds around governed AI operations.",
            risk="Premature outreach could create reputational debt if governance and metrics are incomplete.",
            owner="Matthew",
            risk_level=InnovationRiskLevel.CRITICAL,
            posture=RiskPosture.CONTAIN,
            upside_score=88,
            evidence_quality=0.48,
            control_link="Investor Readiness Gate",
            next_experiment="Complete one proof packet and one customer-impact summary before contacting any new pool.",
            kill_criteria="No outreach if proof packet, risk note, or customer evidence is missing.",
            status=InnovationStatus.CONTAINED,
            notes="Contain does not mean abandon; it means protect the enterprise until evidence catches up.",
        ))

    def _validate_customer_influence(self, item: CustomerExperienceInfluence) -> None:
        required = [item.segment, item.touchpoint, item.positive_outcome, item.metric_name, item.evidence_source, item.owner]
        if any(not value.strip() for value in required):
            raise ValueError("Customer influence segment, touchpoint, outcome, metric, evidence source, and owner are required.")
        if not 0.0 <= item.confidence <= 1.0:
            raise ValueError("Customer influence confidence must be between 0.0 and 1.0.")

    def _validate_control(self, control: EnterpriseControl) -> None:
        if not control.control_name.strip() or not control.purpose.strip() or not control.owner.strip():
            raise ValueError("Enterprise control name, purpose, and owner are required.")
        if control.review_cadence_days <= 0:
            raise ValueError("Control review cadence must be positive.")

    def _validate_innovation_risk(self, item: InnovationRiskItem) -> None:
        required = [item.name, item.hypothesis, item.opportunity, item.risk, item.owner]
        if any(not value.strip() for value in required):
            raise ValueError("Innovation risk name, hypothesis, opportunity, risk, and owner are required.")
        if not 0.0 <= item.upside_score <= 100.0:
            raise ValueError("Innovation upside score must be between 0 and 100.")
        if not 0.0 <= item.evidence_quality <= 1.0:
            raise ValueError("Innovation evidence quality must be between 0.0 and 1.0.")


def row_to_customer_influence(row: sqlite3.Row) -> CustomerExperienceInfluence:
    return CustomerExperienceInfluence(
        segment=row["segment"],
        touchpoint=row["touchpoint"],
        positive_outcome=row["positive_outcome"],
        signal_type=ExperienceSignalType(row["signal_type"]),
        metric_name=row["metric_name"],
        baseline_value=float(row["baseline_value"]),
        current_value=float(row["current_value"]),
        target_value=float(row["target_value"]),
        evidence_source=row["evidence_source"],
        owner=row["owner"],
        confidence=float(row["confidence"]),
        customer_quotes=json.loads(row["customer_quotes_json"] or "[]"),
        linked_project=row["linked_project"] or "",
        follow_up_action=row["follow_up_action"] or "",
        friction_removed=row["friction_removed"] or "",
        notes=row["notes"] or "",
        observed_at=row["observed_at"],
    )


def row_to_enterprise_control(row: sqlite3.Row) -> EnterpriseControl:
    return EnterpriseControl(
        domain=ControlDomain(row["domain"]),
        control_name=row["control_name"],
        purpose=row["purpose"],
        owner=row["owner"],
        status=ControlStatus(row["status"]),
        risk_level=InnovationRiskLevel(row["risk_level"]),
        review_cadence_days=int(row["review_cadence_days"]),
        evidence_required=json.loads(row["evidence_required_json"] or "[]"),
        last_reviewed_at=row["last_reviewed_at"] or "",
        next_review_due=row["next_review_due"] or "",
        linked_policy=row["linked_policy"] or "",
        notes=row["notes"] or "",
    )


def row_to_innovation_risk(row: sqlite3.Row) -> InnovationRiskItem:
    return InnovationRiskItem(
        name=row["name"],
        hypothesis=row["hypothesis"],
        opportunity=row["opportunity"],
        risk=row["risk"],
        owner=row["owner"],
        risk_level=InnovationRiskLevel(row["risk_level"]),
        posture=RiskPosture(row["posture"]),
        upside_score=float(row["upside_score"]),
        evidence_quality=float(row["evidence_quality"]),
        control_link=row["control_link"] or "",
        next_experiment=row["next_experiment"] or "",
        kill_criteria=row["kill_criteria"] or "",
        status=InnovationStatus(row["status"]),
        notes=row["notes"] or "",
    )


def customer_influence_to_dict(item: CustomerExperienceInfluence) -> dict:
    return {
        "segment": item.segment,
        "touchpoint": item.touchpoint,
        "positive_outcome": item.positive_outcome,
        "signal_type": item.signal_type.value,
        "metric_name": item.metric_name,
        "baseline_value": item.baseline_value,
        "current_value": item.current_value,
        "target_value": item.target_value,
        "improvement_ratio": item.improvement_ratio(),
        "influence_score": item.influence_score(),
        "evidence_source": item.evidence_source,
        "owner": item.owner,
        "confidence": item.confidence,
        "customer_quotes": item.customer_quotes,
        "linked_project": item.linked_project,
        "follow_up_action": item.follow_up_action,
        "friction_removed": item.friction_removed,
        "recommended_next_step": item.recommended_next_step(),
        "notes": item.notes,
        "observed_at": item.observed_at,
    }


def enterprise_control_to_dict(control: EnterpriseControl) -> dict:
    return {
        "domain": control.domain.value,
        "control_name": control.control_name,
        "purpose": control.purpose,
        "owner": control.owner,
        "status": control.status.value,
        "risk_level": control.risk_level.value,
        "review_cadence_days": control.review_cadence_days,
        "evidence_required": control.evidence_required,
        "last_reviewed_at": control.last_reviewed_at,
        "next_review_due": control.next_review_due,
        "is_overdue": control.is_overdue(),
        "linked_policy": control.linked_policy,
        "control_score": control.control_score(),
        "recommended_action": control.recommended_action(),
        "notes": control.notes,
    }


def innovation_risk_to_dict(item: InnovationRiskItem) -> dict:
    return {
        "name": item.name,
        "hypothesis": item.hypothesis,
        "opportunity": item.opportunity,
        "risk": item.risk,
        "owner": item.owner,
        "risk_level": item.risk_level.value,
        "posture": item.posture.value,
        "upside_score": item.upside_score,
        "evidence_quality": item.evidence_quality,
        "control_link": item.control_link,
        "next_experiment": item.next_experiment,
        "kill_criteria": item.kill_criteria,
        "status": item.status.value,
        "risk_adjusted_score": item.risk_adjusted_score(),
        "command_lane": item.command_lane(),
        "recommended_action": item.recommended_action(),
        "notes": item.notes,
    }


def summarize_customer_control(stability_score: float, cx: dict, controls: dict, innovation: dict) -> str:
    if controls["failed_count"] or controls["critical_attention_count"]:
        return "Customer impact is being tracked, but enterprise control must tighten before aggressive scaling."
    if stability_score >= 75:
        return "The enterprise is in a strong innovation modality: customer impact, controls, and risk discipline are aligned."
    if cx["influence_count"] == 0:
        return "The system needs customer evidence. Add observed positive outcomes before claiming market traction."
    return "The enterprise is building evidence. Keep customer wins tied to controls, owners, and follow-up actions."


def interpret_customer_impact(score: float, count: int) -> str:
    if count == 0:
        return "No customer influence records yet. Start by logging one evidence-backed positive outcome."
    if score >= 75:
        return "Positive customer experience influence is strong enough to package as proof, while still requiring governance review."
    if score >= 55:
        return "Positive influence exists, but the system needs more evidence, clearer follow-up, or stronger metric movement."
    return "Customer experience claims are early-stage. Treat them as learning signals, not proof of traction."


def interpret_control_status(score: float, failed: list[EnterpriseControl], overdue: list[EnterpriseControl], critical: list[EnterpriseControl]) -> str:
    if failed or critical:
        return "Control posture requires containment on affected domains until evidence and owner review are current."
    if overdue:
        return "Control posture is usable but review debt is accumulating. Clear overdue controls before scale."
    if score >= 75:
        return "Control posture supports disciplined innovation and external positioning."
    return "Control posture is not yet strong enough for broad claims, broad hiring, or broad investor outreach."


def interpret_innovation_portfolio(score: float, contained: list[InnovationRiskItem], act_now: list[InnovationRiskItem]) -> str:
    if contained:
        return "Some innovation lanes are contained. This protects the enterprise while evidence, controls, or kill criteria are completed."
    if act_now and score >= 70:
        return "Innovation portfolio has controlled action opportunities. Move through small experiments with evidence capture."
    return "Innovation should remain in proof-building mode until risk-adjusted scores improve."


def parse_date(value: str) -> Optional[date]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None


def avg(values: list[float]) -> float:
    values = [float(v) for v in values if v is not None]
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)


def clean(value: str) -> str:
    return " ".join(value.strip().split())


def clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(float(value), upper))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
