from __future__ import annotations

from . import uow as _uow

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional


class IntegrationStage(str, Enum):
    CONCEPT = "concept"
    DESIGN = "design"
    PROTOTYPE = "prototype"
    VALIDATION = "validation"
    DEPLOYMENT = "deployment"
    SCALE = "scale"


class AlgorithmicConcernType(str, Enum):
    DATA_PROVENANCE = "data_provenance"
    MODEL_DRIFT = "model_drift"
    EVALUATION_GAP = "evaluation_gap"
    AUTOMATION_AUTHORITY = "automation_authority"
    EXPLAINABILITY = "explainability"
    PRIVACY_SECURITY = "privacy_security"
    CUSTOMER_HARM = "customer_harm"
    REGULATORY_COMPLIANCE = "regulatory_compliance"
    VENDOR_LOCK_IN = "vendor_lock_in"
    INTEGRATION_RELIABILITY = "integration_reliability"


class EvidenceStatus(str, Enum):
    MISSING = "missing"
    PARTIAL = "partial"
    REVIEWED = "reviewed"
    VERIFIED = "verified"


class DependencyType(str, Enum):
    TECHNICAL = "technical"
    MODEL_PROVIDER = "model_provider"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    DATA = "data"
    LEGAL_IP = "legal_ip"
    CAPITAL = "capital"
    TALENT = "talent"
    CUSTOMER = "customer"
    PARTNER = "partner"
    GOVERNANCE = "governance"


class DependencyStatus(str, Enum):
    UNKNOWN = "unknown"
    IDENTIFIED = "identified"
    OWNER_ASSIGNED = "owner_assigned"
    MITIGATION_IN_PROGRESS = "mitigation_in_progress"
    CONTROLLED = "controlled"
    BLOCKED = "blocked"


class ExposureType(str, Enum):
    DEMAND_EXPANSION = "demand_expansion"
    CAPITAL_CONSTRAINT = "capital_constraint"
    ENERGY_CONSTRAINT = "energy_constraint"
    REGULATORY_SHIFT = "regulatory_shift"
    COMPETITIVE_PRESSURE = "competitive_pressure"
    CUSTOMER_TRUST = "customer_trust"
    EMPLOYMENT_MARKET = "employment_market"
    INVESTOR_SENTIMENT = "investor_sentiment"
    INFRASTRUCTURE_DEPENDENCY = "infrastructure_dependency"


class RiskLane(str, Enum):
    CONTAIN = "contain"
    ACT_NOW = "act_now"
    PREPARE = "prepare"
    WATCH = "watch"


@dataclass
class AlgorithmicIntegrationConcern:
    system_component: str
    algorithm_or_model: str
    integration_stage: IntegrationStage
    concern_type: AlgorithmicConcernType
    severity: float
    likelihood: float
    detectability: float
    customer_impact: float
    control_owner: str
    evidence_status: EvidenceStatus
    dependency_links: List[str] = field(default_factory=list)
    mitigation_plan: str = ""
    fallback_mode: str = ""
    model_assumptions: List[str] = field(default_factory=list)
    data_sensitivity: str = "unspecified"
    notes: str = ""
    observed_at: str = field(default_factory=lambda: utc_now())

    def risk_score(self) -> float:
        severity = clamp(self.severity, 0, 1)
        likelihood = clamp(self.likelihood, 0, 1)
        detectability_gap = 1 - clamp(self.detectability, 0, 1)
        customer_impact = clamp(self.customer_impact, 0, 1)
        evidence_penalty = {
            EvidenceStatus.MISSING: 0.22,
            EvidenceStatus.PARTIAL: 0.12,
            EvidenceStatus.REVIEWED: 0.04,
            EvidenceStatus.VERIFIED: 0.0,
        }[self.evidence_status]
        score = ((severity * 0.35) + (likelihood * 0.25) + (detectability_gap * 0.20) + (customer_impact * 0.20) + evidence_penalty) * 100
        return round(clamp(score, 0, 100), 2)

    def lane(self) -> RiskLane:
        score = self.risk_score()
        if self.evidence_status == EvidenceStatus.MISSING and self.severity >= 0.75:
            return RiskLane.CONTAIN
        if self.concern_type in {AlgorithmicConcernType.PRIVACY_SECURITY, AlgorithmicConcernType.REGULATORY_COMPLIANCE, AlgorithmicConcernType.CUSTOMER_HARM} and score >= 65:
            return RiskLane.CONTAIN
        if score >= 72:
            return RiskLane.ACT_NOW
        if score >= 45:
            return RiskLane.PREPARE
        return RiskLane.WATCH

    def recommended_action(self) -> str:
        if self.lane() == RiskLane.CONTAIN:
            return "Pause expansion of this integration until evidence, owner approval, fallback behavior, and audit trail are documented."
        if self.concern_type == AlgorithmicConcernType.EVALUATION_GAP:
            return "Create an evaluation harness with golden cases, regression tests, human review, and acceptance thresholds before deployment."
        if self.concern_type == AlgorithmicConcernType.AUTOMATION_AUTHORITY:
            return "Define the action boundary: what the agent may observe, draft, recommend, and execute, with human approval for high-impact actions."
        if self.concern_type == AlgorithmicConcernType.DATA_PROVENANCE:
            return "Add source lineage, consent field, freshness timestamp, and retention policy before using this data for decisions."
        if self.concern_type == AlgorithmicConcernType.VENDOR_LOCK_IN:
            return "Add a portability plan: abstract the provider interface, document failover behavior, and define replacement criteria."
        return self.mitigation_plan or "Assign owner, evidence requirement, fallback mode, and review cadence before scale."


@dataclass
class DependencyRisk:
    dependency_name: str
    dependency_type: DependencyType
    owner: str
    status: DependencyStatus
    criticality: float
    confidence: float
    alternatives: List[str] = field(default_factory=list)
    failure_mode: str = ""
    mitigation_plan: str = ""
    due_date: str = ""
    linked_component: str = ""
    notes: str = ""
    observed_at: str = field(default_factory=lambda: utc_now())

    def risk_score(self) -> float:
        criticality = clamp(self.criticality, 0, 1)
        uncertainty = 1 - clamp(self.confidence, 0, 1)
        status_penalty = {
            DependencyStatus.UNKNOWN: 0.30,
            DependencyStatus.IDENTIFIED: 0.18,
            DependencyStatus.OWNER_ASSIGNED: 0.12,
            DependencyStatus.MITIGATION_IN_PROGRESS: 0.08,
            DependencyStatus.CONTROLLED: 0.0,
            DependencyStatus.BLOCKED: 0.38,
        }[self.status]
        alternative_credit = min(len(self.alternatives) * 0.05, 0.15)
        score = ((criticality * 0.45) + (uncertainty * 0.35) + status_penalty - alternative_credit) * 100
        return round(clamp(score, 0, 100), 2)

    def lane(self) -> RiskLane:
        score = self.risk_score()
        if self.status == DependencyStatus.BLOCKED or (self.status == DependencyStatus.UNKNOWN and self.criticality >= 0.75):
            return RiskLane.CONTAIN
        if score >= 70:
            return RiskLane.ACT_NOW
        if score >= 42:
            return RiskLane.PREPARE
        return RiskLane.WATCH

    def recommended_action(self) -> str:
        if self.status == DependencyStatus.UNKNOWN:
            return "Map the dependency contract: owner, SLA, failure mode, replacement path, and proof of availability."
        if self.status == DependencyStatus.BLOCKED:
            return "Escalate the blocking dependency and activate a fallback or scope reduction path immediately."
        if not self.alternatives:
            return "Create at least one viable alternative or fallback to reduce single-point-of-failure exposure."
        return self.mitigation_plan or "Keep mitigation active and review this dependency on the next governance cadence."


@dataclass
class MarketArchitectureExposure:
    operator_type: str
    market_vector: str
    exposure_type: ExposureType
    probability: float
    impact: float
    time_horizon_months: int
    current_position: str
    governance_control: str
    infrastructure_investment_signal: str
    strategic_response: str
    source: str = ""
    notes: str = ""
    observed_at: str = field(default_factory=lambda: utc_now())

    def exposure_score(self) -> float:
        time_multiplier = 1.15 if self.time_horizon_months <= 6 else (1.0 if self.time_horizon_months <= 18 else 0.85)
        score = clamp(self.probability, 0, 1) * clamp(self.impact, 0, 1) * 100 * time_multiplier
        return round(clamp(score, 0, 100), 2)

    def lane(self) -> RiskLane:
        score = self.exposure_score()
        if self.exposure_type in {ExposureType.REGULATORY_SHIFT, ExposureType.CUSTOMER_TRUST} and score >= 55:
            return RiskLane.PREPARE
        if score >= 75:
            return RiskLane.ACT_NOW
        if score >= 45:
            return RiskLane.PREPARE
        return RiskLane.WATCH

    def recommended_action(self) -> str:
        if self.exposure_type == ExposureType.CAPITAL_CONSTRAINT:
            return "Prioritize non-dilutive funding, proof packets, revenue validation, and controlled investor outreach."
        if self.exposure_type == ExposureType.ENERGY_CONSTRAINT:
            return "Avoid compute-heavy promises; optimize workloads and keep vendor/provider optionality."
        if self.exposure_type == ExposureType.REGULATORY_SHIFT:
            return "Keep governance evidence current: risk classification, audit trail, consent, and human oversight."
        return self.strategic_response or "Monitor exposure and define a trigger that moves it from watch to action."


@dataclass
class DevelopmentFailureScenario:
    phase: IntegrationStage
    failure_name: str
    trigger_condition: str
    consequence: str
    avoid_by: str
    owner: str
    probability: float
    impact: float
    detection_quality: float
    leading_indicators: List[str] = field(default_factory=list)
    linked_concerns: List[str] = field(default_factory=list)
    notes: str = ""
    observed_at: str = field(default_factory=lambda: utc_now())

    def failure_score(self) -> float:
        score = ((clamp(self.probability, 0, 1) * 0.35) + (clamp(self.impact, 0, 1) * 0.40) + ((1 - clamp(self.detection_quality, 0, 1)) * 0.25)) * 100
        return round(clamp(score, 0, 100), 2)

    def lane(self) -> RiskLane:
        score = self.failure_score()
        if score >= 75:
            return RiskLane.CONTAIN
        if score >= 60:
            return RiskLane.ACT_NOW
        if score >= 38:
            return RiskLane.PREPARE
        return RiskLane.WATCH

    def recommended_action(self) -> str:
        return self.avoid_by or "Define a specific prevention control, owner, trigger, and evidence requirement."


class RiskIntelligenceDB:
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
                CREATE TABLE IF NOT EXISTS algorithmic_integration_concerns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    system_component TEXT NOT NULL,
                    algorithm_or_model TEXT NOT NULL,
                    integration_stage TEXT NOT NULL,
                    concern_type TEXT NOT NULL,
                    severity REAL NOT NULL,
                    likelihood REAL NOT NULL,
                    detectability REAL NOT NULL,
                    customer_impact REAL NOT NULL,
                    control_owner TEXT NOT NULL,
                    evidence_status TEXT NOT NULL,
                    dependency_links_json TEXT NOT NULL,
                    mitigation_plan TEXT,
                    fallback_mode TEXT,
                    model_assumptions_json TEXT NOT NULL,
                    data_sensitivity TEXT,
                    notes TEXT,
                    risk_score REAL NOT NULL,
                    lane TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(system_component, algorithm_or_model, concern_type)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dependency_risks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dependency_name TEXT NOT NULL,
                    dependency_type TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    status TEXT NOT NULL,
                    criticality REAL NOT NULL,
                    confidence REAL NOT NULL,
                    alternatives_json TEXT NOT NULL,
                    failure_mode TEXT,
                    mitigation_plan TEXT,
                    due_date TEXT,
                    linked_component TEXT,
                    notes TEXT,
                    risk_score REAL NOT NULL,
                    lane TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(dependency_name, dependency_type, linked_component)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS market_architecture_exposures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operator_type TEXT NOT NULL,
                    market_vector TEXT NOT NULL,
                    exposure_type TEXT NOT NULL,
                    probability REAL NOT NULL,
                    impact REAL NOT NULL,
                    time_horizon_months INTEGER NOT NULL,
                    current_position TEXT NOT NULL,
                    governance_control TEXT NOT NULL,
                    infrastructure_investment_signal TEXT NOT NULL,
                    strategic_response TEXT NOT NULL,
                    source TEXT,
                    notes TEXT,
                    exposure_score REAL NOT NULL,
                    lane TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(operator_type, market_vector, exposure_type)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS development_failure_scenarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phase TEXT NOT NULL,
                    failure_name TEXT NOT NULL,
                    trigger_condition TEXT NOT NULL,
                    consequence TEXT NOT NULL,
                    avoid_by TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    probability REAL NOT NULL,
                    impact REAL NOT NULL,
                    detection_quality REAL NOT NULL,
                    leading_indicators_json TEXT NOT NULL,
                    linked_concerns_json TEXT NOT NULL,
                    notes TEXT,
                    failure_score REAL NOT NULL,
                    lane TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(phase, failure_name)
                )
                """
            )
            conn.commit()

    def upsert_algorithmic_concern(self, item: AlgorithmicIntegrationConcern) -> AlgorithmicIntegrationConcern:
        self._validate_common(item.control_owner)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO algorithmic_integration_concerns (
                    system_component, algorithm_or_model, integration_stage, concern_type, severity, likelihood,
                    detectability, customer_impact, control_owner, evidence_status, dependency_links_json,
                    mitigation_plan, fallback_mode, model_assumptions_json, data_sensitivity, notes,
                    risk_score, lane, observed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(system_component, algorithm_or_model, concern_type)
                DO UPDATE SET
                    integration_stage=excluded.integration_stage,
                    severity=excluded.severity,
                    likelihood=excluded.likelihood,
                    detectability=excluded.detectability,
                    customer_impact=excluded.customer_impact,
                    control_owner=excluded.control_owner,
                    evidence_status=excluded.evidence_status,
                    dependency_links_json=excluded.dependency_links_json,
                    mitigation_plan=excluded.mitigation_plan,
                    fallback_mode=excluded.fallback_mode,
                    model_assumptions_json=excluded.model_assumptions_json,
                    data_sensitivity=excluded.data_sensitivity,
                    notes=excluded.notes,
                    risk_score=excluded.risk_score,
                    lane=excluded.lane,
                    updated_at=excluded.updated_at
                """,
                (
                    clean(item.system_component), clean(item.algorithm_or_model), item.integration_stage.value,
                    item.concern_type.value, item.severity, item.likelihood, item.detectability, item.customer_impact,
                    item.control_owner.strip(), item.evidence_status.value, json.dumps(item.dependency_links),
                    item.mitigation_plan.strip(), item.fallback_mode.strip(), json.dumps(item.model_assumptions),
                    item.data_sensitivity.strip(), item.notes.strip(), item.risk_score(), item.lane().value,
                    item.observed_at, now,
                ),
            )
            conn.commit()
        return item

    def upsert_dependency_risk(self, item: DependencyRisk) -> DependencyRisk:
        self._validate_common(item.owner)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO dependency_risks (
                    dependency_name, dependency_type, owner, status, criticality, confidence, alternatives_json,
                    failure_mode, mitigation_plan, due_date, linked_component, notes, risk_score, lane, observed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dependency_name, dependency_type, linked_component)
                DO UPDATE SET
                    owner=excluded.owner,
                    status=excluded.status,
                    criticality=excluded.criticality,
                    confidence=excluded.confidence,
                    alternatives_json=excluded.alternatives_json,
                    failure_mode=excluded.failure_mode,
                    mitigation_plan=excluded.mitigation_plan,
                    due_date=excluded.due_date,
                    notes=excluded.notes,
                    risk_score=excluded.risk_score,
                    lane=excluded.lane,
                    updated_at=excluded.updated_at
                """,
                (
                    clean(item.dependency_name), item.dependency_type.value, item.owner.strip(), item.status.value,
                    item.criticality, item.confidence, json.dumps(item.alternatives), item.failure_mode.strip(),
                    item.mitigation_plan.strip(), item.due_date.strip(), item.linked_component.strip(), item.notes.strip(),
                    item.risk_score(), item.lane().value, item.observed_at, now,
                ),
            )
            conn.commit()
        return item

    def upsert_market_exposure(self, item: MarketArchitectureExposure) -> MarketArchitectureExposure:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO market_architecture_exposures (
                    operator_type, market_vector, exposure_type, probability, impact, time_horizon_months,
                    current_position, governance_control, infrastructure_investment_signal, strategic_response,
                    source, notes, exposure_score, lane, observed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(operator_type, market_vector, exposure_type)
                DO UPDATE SET
                    probability=excluded.probability,
                    impact=excluded.impact,
                    time_horizon_months=excluded.time_horizon_months,
                    current_position=excluded.current_position,
                    governance_control=excluded.governance_control,
                    infrastructure_investment_signal=excluded.infrastructure_investment_signal,
                    strategic_response=excluded.strategic_response,
                    source=excluded.source,
                    notes=excluded.notes,
                    exposure_score=excluded.exposure_score,
                    lane=excluded.lane,
                    updated_at=excluded.updated_at
                """,
                (
                    clean(item.operator_type), clean(item.market_vector), item.exposure_type.value,
                    item.probability, item.impact, int(item.time_horizon_months), item.current_position.strip(),
                    item.governance_control.strip(), item.infrastructure_investment_signal.strip(),
                    item.strategic_response.strip(), item.source.strip(), item.notes.strip(),
                    item.exposure_score(), item.lane().value, item.observed_at, now,
                ),
            )
            conn.commit()
        return item

    def upsert_failure_scenario(self, item: DevelopmentFailureScenario) -> DevelopmentFailureScenario:
        self._validate_common(item.owner)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO development_failure_scenarios (
                    phase, failure_name, trigger_condition, consequence, avoid_by, owner, probability, impact,
                    detection_quality, leading_indicators_json, linked_concerns_json, notes, failure_score, lane, observed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(phase, failure_name)
                DO UPDATE SET
                    trigger_condition=excluded.trigger_condition,
                    consequence=excluded.consequence,
                    avoid_by=excluded.avoid_by,
                    owner=excluded.owner,
                    probability=excluded.probability,
                    impact=excluded.impact,
                    detection_quality=excluded.detection_quality,
                    leading_indicators_json=excluded.leading_indicators_json,
                    linked_concerns_json=excluded.linked_concerns_json,
                    notes=excluded.notes,
                    failure_score=excluded.failure_score,
                    lane=excluded.lane,
                    updated_at=excluded.updated_at
                """,
                (
                    item.phase.value, clean(item.failure_name), item.trigger_condition.strip(), item.consequence.strip(),
                    item.avoid_by.strip(), item.owner.strip(), item.probability, item.impact, item.detection_quality,
                    json.dumps(item.leading_indicators), json.dumps(item.linked_concerns), item.notes.strip(),
                    item.failure_score(), item.lane().value, item.observed_at, now,
                ),
            )
            conn.commit()
        return item

    def list_algorithmic_concerns(self, lane: str = "") -> List[AlgorithmicIntegrationConcern]:
        rows = self._select("algorithmic_integration_concerns", lane)
        return [row_to_algorithmic_concern(row) for row in rows]

    def list_dependency_risks(self, lane: str = "") -> List[DependencyRisk]:
        rows = self._select("dependency_risks", lane)
        return [row_to_dependency_risk(row) for row in rows]

    def list_market_exposures(self, lane: str = "") -> List[MarketArchitectureExposure]:
        rows = self._select("market_architecture_exposures", lane, score_col="exposure_score")
        return [row_to_market_exposure(row) for row in rows]

    def list_failure_scenarios(self, lane: str = "") -> List[DevelopmentFailureScenario]:
        rows = self._select("development_failure_scenarios", lane, score_col="failure_score")
        return [row_to_failure_scenario(row) for row in rows]

    def _select(self, table: str, lane: str = "", score_col: str = "risk_score") -> List[sqlite3.Row]:
        query = f"SELECT * FROM {table}"
        params: list[str] = []
        if lane:
            query += " WHERE lane = ?"
            params.append(lane)
        query += f" ORDER BY {score_col} DESC, updated_at DESC"
        with self.connect() as conn:
            return conn.execute(query, params).fetchall()

    def risk_control_snapshot(self) -> dict:
        concerns = [algorithmic_concern_to_dict(item) for item in self.list_algorithmic_concerns()]
        dependencies = [dependency_risk_to_dict(item) for item in self.list_dependency_risks()]
        exposures = [market_exposure_to_dict(item) for item in self.list_market_exposures()]
        failures = [failure_scenario_to_dict(item) for item in self.list_failure_scenarios()]

        lanes = {"contain": [], "act_now": [], "prepare": [], "watch": []}
        for category, items in {
            "algorithmic_integration": concerns,
            "dependency_management": dependencies,
            "market_architecture": exposures,
            "failure_avoidance": failures,
        }.items():
            for item in items:
                item = dict(item)
                item["category"] = category
                lanes.setdefault(item["lane"], []).append(item)

        return {
            "generated_at": utc_now(),
            "doctrine": "Do not scale uncertain algorithms, unresolved dependencies, or market claims without evidence, fallback, owner, and governance control.",
            "top_problematic_concerns": (lanes["contain"] + lanes["act_now"])[:12],
            "algorithmic_integration": {
                "count": len(concerns),
                "average_risk_score": average([item["risk_score"] for item in concerns]),
                "items": concerns,
            },
            "dependency_management": {
                "count": len(dependencies),
                "average_risk_score": average([item["risk_score"] for item in dependencies]),
                "items": dependencies,
            },
            "market_architecture": {
                "count": len(exposures),
                "average_exposure_score": average([item["exposure_score"] for item in exposures]),
                "items": exposures,
            },
            "failure_avoidance": {
                "count": len(failures),
                "average_failure_score": average([item["failure_score"] for item in failures]),
                "items": failures,
            },
            "lanes": lanes,
            "counts": {lane: len(items) for lane, items in lanes.items()},
            "seventy_two_hour_ground_team": build_ground_team(lanes),
        }

    def seed_demo_data(self) -> None:
        self.upsert_algorithmic_concern(AlgorithmicIntegrationConcern(
            system_component="PATIENCE Command Layer",
            algorithm_or_model="Action-routing score",
            integration_stage=IntegrationStage.VALIDATION,
            concern_type=AlgorithmicConcernType.AUTOMATION_AUTHORITY,
            severity=0.86,
            likelihood=0.58,
            detectability=0.44,
            customer_impact=0.72,
            control_owner="Governance Lead",
            evidence_status=EvidenceStatus.PARTIAL,
            dependency_links=["decision log", "human approval boundary", "audit trail"],
            mitigation_plan="Define execute/recommend/observe boundaries and require human approval for investor, hiring, legal, or customer-impacting actions.",
            fallback_mode="recommendation_only",
            model_assumptions=["urgency score reflects real deadline", "governance status is current"],
            data_sensitivity="medium",
            notes="Highest concern: the system must not become an unsupervised operator before authority boundaries are explicit.",
        ))
        self.upsert_algorithmic_concern(AlgorithmicIntegrationConcern(
            system_component="Customer Experience Influence Tracker",
            algorithm_or_model="Influence scoring heuristic",
            integration_stage=IntegrationStage.PROTOTYPE,
            concern_type=AlgorithmicConcernType.EVALUATION_GAP,
            severity=0.69,
            likelihood=0.70,
            detectability=0.38,
            customer_impact=0.64,
            control_owner="CX Owner",
            evidence_status=EvidenceStatus.PARTIAL,
            dependency_links=["customer evidence", "metric definitions", "source trail"],
            mitigation_plan="Create baseline, target, confidence, evidence-source, and quote-validation rules before external traction claims.",
            fallback_mode="internal_only_claims",
            model_assumptions=["metric movement is attributable", "source evidence is reliable"],
            data_sensitivity="customer_feedback",
        ))
        self.upsert_algorithmic_concern(AlgorithmicIntegrationConcern(
            system_component="Investor Qualification Engine",
            algorithm_or_model="Capital readiness score",
            integration_stage=IntegrationStage.DESIGN,
            concern_type=AlgorithmicConcernType.DATA_PROVENANCE,
            severity=0.74,
            likelihood=0.62,
            detectability=0.45,
            customer_impact=0.35,
            control_owner="Capital Strategy Lead",
            evidence_status=EvidenceStatus.MISSING,
            dependency_links=["investor source list", "proof packet", "market evidence"],
            mitigation_plan="Require source-tagged investor thesis, warm intro path, check-size evidence, and legal review before outreach.",
            fallback_mode="research_only",
            model_assumptions=["investor thesis is current", "fit score maps to real interest"],
            data_sensitivity="relationship_data",
        ))
        self.upsert_algorithmic_concern(AlgorithmicIntegrationConcern(
            system_component="Operations Matrix API",
            algorithm_or_model="External model/provider calls",
            integration_stage=IntegrationStage.DESIGN,
            concern_type=AlgorithmicConcernType.VENDOR_LOCK_IN,
            severity=0.70,
            likelihood=0.66,
            detectability=0.55,
            customer_impact=0.48,
            control_owner="Technical Lead",
            evidence_status=EvidenceStatus.PARTIAL,
            dependency_links=["model provider", "cloud provider", "cost policy"],
            mitigation_plan="Abstract provider interface and maintain model/provider substitution path.",
            fallback_mode="local rules_engine",
            model_assumptions=["provider terms and pricing remain usable"],
            data_sensitivity="mixed",
        ))

        self.upsert_dependency_risk(DependencyRisk(
            dependency_name="Model provider and inference API",
            dependency_type=DependencyType.MODEL_PROVIDER,
            owner="Technical Lead",
            status=DependencyStatus.IDENTIFIED,
            criticality=0.86,
            confidence=0.48,
            alternatives=["rules-only fallback", "secondary model provider"],
            failure_mode="Provider outage, cost spike, quality regression, or terms change blocks command intelligence.",
            mitigation_plan="Use provider abstraction, request logging, budget ceilings, quality tests, and fallbacks.",
            linked_component="PATIENCE Command Layer",
        ))
        self.upsert_dependency_risk(DependencyRisk(
            dependency_name="Data governance / source trail",
            dependency_type=DependencyType.GOVERNANCE,
            owner="Governance Lead",
            status=DependencyStatus.MITIGATION_IN_PROGRESS,
            criticality=0.92,
            confidence=0.54,
            alternatives=[],
            failure_mode="Unverified claims create investor, customer, or compliance risk.",
            mitigation_plan="Require source, owner, freshness date, sensitivity tag, and decision log for all external claims.",
            linked_component="Enterprise Control Layer",
        ))
        self.upsert_dependency_risk(DependencyRisk(
            dependency_name="Legal/IP review capacity",
            dependency_type=DependencyType.LEGAL_IP,
            owner="Founder / Advisor",
            status=DependencyStatus.UNKNOWN,
            criticality=0.78,
            confidence=0.32,
            alternatives=["limited-scope startup counsel", "university clinic", "advisor review"],
            failure_mode="Ambiguous ownership, public disclosure, or partner terms weaken defensibility.",
            mitigation_plan="Secure at least lightweight IP/privacy review before investor documents or customer pilots.",
            linked_component="Investor + Research Packet",
        ))
        self.upsert_dependency_risk(DependencyRisk(
            dependency_name="Customer validation loop",
            dependency_type=DependencyType.CUSTOMER,
            owner="CX Owner",
            status=DependencyStatus.IDENTIFIED,
            criticality=0.80,
            confidence=0.42,
            alternatives=["advisor interviews", "operator interviews", "pilot cohort"],
            failure_mode="Product direction becomes internally convincing but externally unvalidated.",
            mitigation_plan="Run 5 structured operator interviews and store evidence in the CX influence tracker.",
            linked_component="Customer Experience Influence Tracker",
        ))

        self.upsert_market_exposure(MarketArchitectureExposure(
            operator_type="New AI operators",
            market_vector="AI infrastructure and data-center buildout",
            exposure_type=ExposureType.INFRASTRUCTURE_DEPENDENCY,
            probability=0.78,
            impact=0.76,
            time_horizon_months=12,
            current_position="High opportunity, but compute and energy availability can create cost and deployment pressure.",
            governance_control="Budget ceiling, provider optionality, workload efficiency checks, no compute-heavy promises without source of capacity.",
            infrastructure_investment_signal="Global data-center spending estimates have moved into multi-trillion-dollar territory by 2030.",
            strategic_response="Design lightweight, cloud-agnostic workflows and position Oracle/PATIENCE as governance intelligence, not raw compute infrastructure.",
            source="McKinsey / IEA market signals",
        ))
        self.upsert_market_exposure(MarketArchitectureExposure(
            operator_type="Established enterprises",
            market_vector="AI governance and compliance adoption",
            exposure_type=ExposureType.REGULATORY_SHIFT,
            probability=0.70,
            impact=0.68,
            time_horizon_months=18,
            current_position="Governance burden is increasing; trustworthy audit-ready systems become more valuable.",
            governance_control="AI risk classification, human oversight, source trails, and review cadence.",
            infrastructure_investment_signal="AI adoption is tied to risk controls and data governance, not only model quality.",
            strategic_response="Define the product as an auditable control layer for operators who need proof, not hype.",
            source="NIST AI RMF / EU AI Act timeline",
        ))
        self.upsert_market_exposure(MarketArchitectureExposure(
            operator_type="Investor pools",
            market_vector="Capital cost and proof discipline",
            exposure_type=ExposureType.CAPITAL_CONSTRAINT,
            probability=0.74,
            impact=0.72,
            time_horizon_months=6,
            current_position="Capital is available for AI, but investors are increasingly sensitive to ROI, governance, and infrastructure cost.",
            governance_control="Proof packet, use-of-funds discipline, pilot evidence, and risk note before outreach.",
            infrastructure_investment_signal="Large AI capex growth raises both opportunity and bubble-risk scrutiny.",
            strategic_response="Lead with controlled pilots, employment stability, non-dilutive funding, and investor qualification gates.",
            source="Fed / BEA / infrastructure market signals",
        ))

        self.upsert_failure_scenario(DevelopmentFailureScenario(
            phase=IntegrationStage.VALIDATION,
            failure_name="Algorithmic authority exceeds governance boundary",
            trigger_condition="The system recommends or executes high-impact actions without explicit approval mode.",
            consequence="Loss of trust, reputational exposure, compliance risk, or investor concern.",
            avoid_by="Lock high-impact domains into recommend-only mode until consent, audit, owner, and review policy exist.",
            owner="Governance Lead",
            probability=0.56,
            impact=0.88,
            detection_quality=0.46,
            leading_indicators=["no action taxonomy", "missing decision log", "unclear approval boundary"],
            linked_concerns=["PATIENCE Command Layer / Automation Authority"],
        ))
        self.upsert_failure_scenario(DevelopmentFailureScenario(
            phase=IntegrationStage.PROTOTYPE,
            failure_name="Inconclusive dependency management stalls deployment",
            trigger_condition="Critical dependencies have no owner, fallback, or alternative path.",
            consequence="Prototype remains impressive but cannot be safely deployed, funded, or sold.",
            avoid_by="For each critical dependency, assign owner, SLA/availability assumption, failure mode, fallback, and due date.",
            owner="Operations Lead",
            probability=0.64,
            impact=0.80,
            detection_quality=0.52,
            leading_indicators=["unknown status", "no alternatives", "blocked legal/IP review", "provider uncertainty"],
            linked_concerns=["Data governance / source trail", "Model provider and inference API"],
        ))
        self.upsert_failure_scenario(DevelopmentFailureScenario(
            phase=IntegrationStage.SCALE,
            failure_name="Market claim scales faster than customer proof",
            trigger_condition="Investor or public narrative cites positive impact without evidence-backed customer metrics.",
            consequence="Credibility loss and reduced investor/customer conversion.",
            avoid_by="Only use claims that have source, metric, baseline, owner, confidence, and follow-up action.",
            owner="CX Owner",
            probability=0.58,
            impact=0.76,
            detection_quality=0.55,
            leading_indicators=["anecdotal traction", "missing baseline", "no customer quote validation"],
            linked_concerns=["Customer Experience Influence Tracker / Evaluation Gap"],
        ))

    def _validate_common(self, owner: str) -> None:
        if not owner.strip():
            raise ValueError("Owner is required.")


def row_to_algorithmic_concern(row: sqlite3.Row) -> AlgorithmicIntegrationConcern:
    return AlgorithmicIntegrationConcern(
        system_component=row["system_component"],
        algorithm_or_model=row["algorithm_or_model"],
        integration_stage=IntegrationStage(row["integration_stage"]),
        concern_type=AlgorithmicConcernType(row["concern_type"]),
        severity=float(row["severity"]),
        likelihood=float(row["likelihood"]),
        detectability=float(row["detectability"]),
        customer_impact=float(row["customer_impact"]),
        control_owner=row["control_owner"],
        evidence_status=EvidenceStatus(row["evidence_status"]),
        dependency_links=json.loads(row["dependency_links_json"] or "[]"),
        mitigation_plan=row["mitigation_plan"] or "",
        fallback_mode=row["fallback_mode"] or "",
        model_assumptions=json.loads(row["model_assumptions_json"] or "[]"),
        data_sensitivity=row["data_sensitivity"] or "unspecified",
        notes=row["notes"] or "",
        observed_at=row["observed_at"],
    )


def row_to_dependency_risk(row: sqlite3.Row) -> DependencyRisk:
    return DependencyRisk(
        dependency_name=row["dependency_name"],
        dependency_type=DependencyType(row["dependency_type"]),
        owner=row["owner"],
        status=DependencyStatus(row["status"]),
        criticality=float(row["criticality"]),
        confidence=float(row["confidence"]),
        alternatives=json.loads(row["alternatives_json"] or "[]"),
        failure_mode=row["failure_mode"] or "",
        mitigation_plan=row["mitigation_plan"] or "",
        due_date=row["due_date"] or "",
        linked_component=row["linked_component"] or "",
        notes=row["notes"] or "",
        observed_at=row["observed_at"],
    )


def row_to_market_exposure(row: sqlite3.Row) -> MarketArchitectureExposure:
    return MarketArchitectureExposure(
        operator_type=row["operator_type"],
        market_vector=row["market_vector"],
        exposure_type=ExposureType(row["exposure_type"]),
        probability=float(row["probability"]),
        impact=float(row["impact"]),
        time_horizon_months=int(row["time_horizon_months"]),
        current_position=row["current_position"],
        governance_control=row["governance_control"],
        infrastructure_investment_signal=row["infrastructure_investment_signal"],
        strategic_response=row["strategic_response"],
        source=row["source"] or "",
        notes=row["notes"] or "",
        observed_at=row["observed_at"],
    )


def row_to_failure_scenario(row: sqlite3.Row) -> DevelopmentFailureScenario:
    return DevelopmentFailureScenario(
        phase=IntegrationStage(row["phase"]),
        failure_name=row["failure_name"],
        trigger_condition=row["trigger_condition"],
        consequence=row["consequence"],
        avoid_by=row["avoid_by"],
        owner=row["owner"],
        probability=float(row["probability"]),
        impact=float(row["impact"]),
        detection_quality=float(row["detection_quality"]),
        leading_indicators=json.loads(row["leading_indicators_json"] or "[]"),
        linked_concerns=json.loads(row["linked_concerns_json"] or "[]"),
        notes=row["notes"] or "",
        observed_at=row["observed_at"],
    )


def algorithmic_concern_to_dict(item: AlgorithmicIntegrationConcern) -> dict:
    return {
        "system_component": item.system_component,
        "algorithm_or_model": item.algorithm_or_model,
        "integration_stage": item.integration_stage.value,
        "concern_type": item.concern_type.value,
        "severity": item.severity,
        "likelihood": item.likelihood,
        "detectability": item.detectability,
        "customer_impact": item.customer_impact,
        "control_owner": item.control_owner,
        "evidence_status": item.evidence_status.value,
        "dependency_links": item.dependency_links,
        "mitigation_plan": item.mitigation_plan,
        "fallback_mode": item.fallback_mode,
        "model_assumptions": item.model_assumptions,
        "data_sensitivity": item.data_sensitivity,
        "notes": item.notes,
        "risk_score": item.risk_score(),
        "lane": item.lane().value,
        "recommended_action": item.recommended_action(),
        "observed_at": item.observed_at,
    }


def dependency_risk_to_dict(item: DependencyRisk) -> dict:
    return {
        "dependency_name": item.dependency_name,
        "dependency_type": item.dependency_type.value,
        "owner": item.owner,
        "status": item.status.value,
        "criticality": item.criticality,
        "confidence": item.confidence,
        "alternatives": item.alternatives,
        "failure_mode": item.failure_mode,
        "mitigation_plan": item.mitigation_plan,
        "due_date": item.due_date,
        "linked_component": item.linked_component,
        "notes": item.notes,
        "risk_score": item.risk_score(),
        "lane": item.lane().value,
        "recommended_action": item.recommended_action(),
        "observed_at": item.observed_at,
    }


def market_exposure_to_dict(item: MarketArchitectureExposure) -> dict:
    return {
        "operator_type": item.operator_type,
        "market_vector": item.market_vector,
        "exposure_type": item.exposure_type.value,
        "probability": item.probability,
        "impact": item.impact,
        "time_horizon_months": item.time_horizon_months,
        "current_position": item.current_position,
        "governance_control": item.governance_control,
        "infrastructure_investment_signal": item.infrastructure_investment_signal,
        "strategic_response": item.strategic_response,
        "source": item.source,
        "notes": item.notes,
        "exposure_score": item.exposure_score(),
        "lane": item.lane().value,
        "recommended_action": item.recommended_action(),
        "observed_at": item.observed_at,
    }


def failure_scenario_to_dict(item: DevelopmentFailureScenario) -> dict:
    return {
        "phase": item.phase.value,
        "failure_name": item.failure_name,
        "trigger_condition": item.trigger_condition,
        "consequence": item.consequence,
        "avoid_by": item.avoid_by,
        "owner": item.owner,
        "probability": item.probability,
        "impact": item.impact,
        "detection_quality": item.detection_quality,
        "leading_indicators": item.leading_indicators,
        "linked_concerns": item.linked_concerns,
        "notes": item.notes,
        "failure_score": item.failure_score(),
        "lane": item.lane().value,
        "recommended_action": item.recommended_action(),
        "observed_at": item.observed_at,
    }


def build_ground_team(lanes: dict) -> list[dict]:
    ground_team = []
    for item in lanes.get("contain", [])[:4] + lanes.get("act_now", [])[:4]:
        action = item.get("recommended_action") or item.get("avoid_by") or "Assign owner and control this risk."
        ground_team.append({
            "title": item.get("failure_name") or item.get("system_component") or item.get("dependency_name") or item.get("market_vector"),
            "category": item.get("category", "risk"),
            "lane": item.get("lane"),
            "owner": item.get("control_owner") or item.get("owner") or "Unassigned",
            "action": action,
            "evidence_required": infer_evidence_required(item),
            "deadline_days": 1 if item.get("lane") == "contain" else 3,
        })
    return ground_team[:7]


def infer_evidence_required(item: dict) -> list[str]:
    category = item.get("category")
    if category == "algorithmic_integration":
        return ["evaluation result", "fallback mode", "decision/audit log"]
    if category == "dependency_management":
        return ["owner", "fallback/alternative", "failure-mode note"]
    if category == "market_architecture":
        return ["source", "trigger threshold", "strategic response"]
    if category == "failure_avoidance":
        return ["leading indicator", "prevention control", "owner confirmation"]
    return ["owner", "evidence", "next action"]


def average(values: list[float]) -> float:
    return round(sum(values) / len(values), 2) if values else 0.0


def clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(float(value), max_value))


def clean(value: str) -> str:
    return " ".join(value.strip().split())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
