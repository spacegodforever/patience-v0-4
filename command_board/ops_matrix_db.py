from __future__ import annotations

from . import uow as _uow

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional


DEFAULT_DB_PATH = Path(os.getenv("PATIENCE_BOARD_DB", "patience_board.db"))  # PATIENCE: resolved per call in routes


class HealthStatus(str, Enum):
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"
    BLOCKED = "blocked"


class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PatienceMode(str, Enum):
    OBSERVE = "observe"          # monitor, gather signal, avoid premature action
    PREPARE = "prepare"          # build assets, remove friction, wait for trigger
    PROCEED = "proceed"          # act now with normal controls
    ESCALATE = "escalate"        # time-sensitive action; raise owner attention
    CONTAIN = "contain"          # governance, legal, safety, trust, or reputation risk


class ProjectStage(str, Enum):
    INTAKE = "intake"
    DISCOVERY = "discovery"
    BUILD = "build"
    VALIDATION = "validation"
    DEPLOYMENT = "deployment"
    SCALE = "scale"
    PAUSED = "paused"


class ProjectStatus(str, Enum):
    ACTIVE = "active"
    AT_RISK = "at_risk"
    BLOCKED = "blocked"
    WATCH = "watch"
    COMPLETE = "complete"


class EmploymentStatus(str, Enum):
    TARGET = "target"
    APPLIED = "applied"
    INTERVIEWING = "interviewing"
    OFFER = "offer"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class InvestorStatus(str, Enum):
    RESEARCH = "research"
    WARMING = "warming"
    READY_TO_CONTACT = "ready_to_contact"
    CONTACTED = "contacted"
    ACTIVE_DILIGENCE = "active_diligence"
    PASSED = "passed"
    COMMITTED = "committed"


class GovernanceSeverity(str, Enum):
    ADVISORY = "advisory"
    REQUIRED = "required"
    HARD_STOP = "hard_stop"


@dataclass
class KPI:
    name: str
    current_value: float
    target_value: float
    unit: str = ""

    def progress_ratio(self) -> float:
        if self.target_value <= 0:
            return 0.0
        return clamp(self.current_value / self.target_value, 0.0, 1.0)


@dataclass
class PatienceProfile:
    urgency: float = 0.5                 # 0 = no time pressure, 1 = immediate pressure
    reversibility: float = 0.5           # 0 = hard to reverse, 1 = easy to reverse
    volatility: float = 0.5              # 0 = stable context, 1 = unstable context
    runway_sensitivity: float = 0.5      # 0 = low cash/time pressure, 1 = high pressure
    opportunity_half_life_days: int = 30 # how quickly the window decays
    evidence_quality: float = 0.5        # 0 = assumption-heavy, 1 = strongly evidenced
    stakeholder_impact: float = 0.5      # 0 = low impact, 1 = high impact on people/team
    compliance_sensitivity: float = 0.5  # 0 = low governance sensitivity, 1 = high


@dataclass
class PatienceAssessment:
    patience_score: float
    mode: PatienceMode
    priority: Priority
    review_cadence_days: int
    escalation_deadline_days: int
    rationale: List[str]
    guardrails: List[str]
    next_actions: List[str]


@dataclass
class MatrixCell:
    workstream: str
    capability: str
    objective: str
    owner: str
    health: HealthStatus
    confidence: float
    kpi: Optional[KPI] = None
    blockers: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    notes: str = ""
    patience: PatienceProfile = field(default_factory=PatienceProfile)

    def score(self) -> float:
        base_scores = {
            HealthStatus.GREEN: 90,
            HealthStatus.YELLOW: 65,
            HealthStatus.RED: 35,
            HealthStatus.BLOCKED: 15,
        }
        score = base_scores[self.health]
        if self.kpi:
            score = (score * 0.65) + (self.kpi.progress_ratio() * 100 * 0.35)
        score *= clamp(self.confidence, 0.0, 1.0)
        score -= min(len(self.blockers) * 8, 30)
        score -= min(len(self.dependencies) * 4, 20)
        return round(clamp(score, 0.0, 100.0), 2)

    def patience_assessment(self) -> PatienceAssessment:
        return assess_patience(self.patience, operational_score=self.score(), context_label=f"{self.workstream} × {self.capability}")


@dataclass
class RecoveryAction:
    workstream: str
    capability: str
    owner: str
    priority: Priority
    score: float
    patience_mode: PatienceMode
    patience_score: float
    reason: str
    recommended_action: str
    review_cadence_days: int
    escalation_deadline_days: int


@dataclass
class Project:
    name: str
    category: str
    objective: str
    owner: str
    stage: ProjectStage
    status: ProjectStatus
    linked_workstream: str = ""
    linked_capability: str = ""
    north_star_metric: str = ""
    current_value: float = 0.0
    target_value: float = 1.0
    blockers: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    next_milestone: str = ""
    next_action: str = ""
    due_date: str = ""
    notes: str = ""
    patience: PatienceProfile = field(default_factory=PatienceProfile)

    def progress_ratio(self) -> float:
        if self.target_value <= 0:
            return 0.0
        return clamp(self.current_value / self.target_value, 0.0, 1.0)

    def follow_through_score(self) -> float:
        stage_bonus = {
            ProjectStage.INTAKE: 5,
            ProjectStage.DISCOVERY: 10,
            ProjectStage.BUILD: 18,
            ProjectStage.VALIDATION: 24,
            ProjectStage.DEPLOYMENT: 30,
            ProjectStage.SCALE: 35,
            ProjectStage.PAUSED: -10,
        }[self.stage]
        status_base = {
            ProjectStatus.ACTIVE: 60,
            ProjectStatus.WATCH: 50,
            ProjectStatus.AT_RISK: 35,
            ProjectStatus.BLOCKED: 20,
            ProjectStatus.COMPLETE: 95,
        }[self.status]
        score = status_base + stage_bonus + (self.progress_ratio() * 20)
        score -= min(len(self.blockers) * 8, 32)
        score -= min(len(self.dependencies) * 4, 20)
        if not self.next_action.strip():
            score -= 12
        if not self.owner.strip():
            score -= 15
        return round(clamp(score, 0.0, 100.0), 2)

    def patience_assessment(self) -> PatienceAssessment:
        return assess_patience(self.patience, operational_score=self.follow_through_score(), context_label=self.name)


@dataclass
class EmploymentOpportunity:
    title: str
    organization: str
    role_family: str
    source: str
    status: EmploymentStatus
    fit_score: float
    salary_min: Optional[float] = None
    salary_max: Optional[float] = None
    remote_type: str = "unspecified"
    location: str = ""
    requirements: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    next_action: str = ""
    due_date: str = ""
    notes: str = ""
    patience: PatienceProfile = field(default_factory=PatienceProfile)

    def readiness_score(self) -> float:
        score = clamp(self.fit_score, 0.0, 100.0)
        score -= min(len(self.gaps) * 7, 35)
        if not self.next_action.strip():
            score -= 10
        if self.status in {EmploymentStatus.INTERVIEWING, EmploymentStatus.OFFER}:
            score += 10
        if self.status in {EmploymentStatus.REJECTED, EmploymentStatus.ARCHIVED}:
            score = min(score, 25)
        return round(clamp(score, 0.0, 100.0), 2)

    def patience_assessment(self) -> PatienceAssessment:
        return assess_patience(self.patience, operational_score=self.readiness_score(), context_label=f"{self.title} at {self.organization}")


@dataclass
class InvestorPool:
    name: str
    investor_type: str
    thesis: str
    status: InvestorStatus
    strategic_fit: float
    capital_readiness_score: float
    stage_fit: str = ""
    check_size_min: Optional[float] = None
    check_size_max: Optional[float] = None
    geography: str = ""
    relationship_owner: str = ""
    warm_intro_path: str = ""
    evidence_required: List[str] = field(default_factory=list)
    next_action: str = ""
    notes: str = ""
    patience: PatienceProfile = field(default_factory=PatienceProfile)

    def qualification_score(self) -> float:
        score = (clamp(self.strategic_fit, 0.0, 100.0) * 0.55) + (clamp(self.capital_readiness_score, 0.0, 100.0) * 0.45)
        score -= min(len(self.evidence_required) * 5, 25)
        if self.warm_intro_path.strip():
            score += 8
        if self.status in {InvestorStatus.READY_TO_CONTACT, InvestorStatus.ACTIVE_DILIGENCE, InvestorStatus.COMMITTED}:
            score += 8
        if self.status in {InvestorStatus.PASSED}:
            score = min(score, 30)
        return round(clamp(score, 0.0, 100.0), 2)

    def patience_assessment(self) -> PatienceAssessment:
        return assess_patience(self.patience, operational_score=self.qualification_score(), context_label=self.name)


@dataclass
class GovernancePolicy:
    domain: str
    rule: str
    owner: str
    severity: GovernanceSeverity
    status: str = "active"
    review_cadence_days: int = 30
    evidence_required: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class EconomicSignal:
    name: str
    value: str
    trend: str
    confidence: float
    source: str
    impact_area: str
    observed_at: str = field(default_factory=lambda: utc_now())
    notes: str = ""


class OperationsMatrixDB:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        # PATIENCE: route through the unit of work so writes commit only after the audit append.
        return _uow.connect(self.db_path)

    def _init_db(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS matrix_cells (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workstream TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    health TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    kpi_name TEXT,
                    kpi_current_value REAL,
                    kpi_target_value REAL,
                    kpi_unit TEXT,
                    blockers_json TEXT NOT NULL,
                    dependencies_json TEXT NOT NULL,
                    notes TEXT,
                    patience_json TEXT NOT NULL DEFAULT '{}',
                    current_score REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(workstream, capability)
                )
                """
            )
            self._ensure_column(conn, "matrix_cells", "patience_json", "TEXT NOT NULL DEFAULT '{}' ")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS score_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workstream TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    score REAL NOT NULL,
                    health TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    patience_score REAL,
                    patience_mode TEXT,
                    recorded_at TEXT NOT NULL
                )
                """
            )
            self._ensure_column(conn, "score_history", "patience_score", "REAL")
            self._ensure_column(conn, "score_history", "patience_mode", "TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    status TEXT NOT NULL,
                    linked_workstream TEXT,
                    linked_capability TEXT,
                    north_star_metric TEXT,
                    current_value REAL NOT NULL,
                    target_value REAL NOT NULL,
                    blockers_json TEXT NOT NULL,
                    dependencies_json TEXT NOT NULL,
                    next_milestone TEXT,
                    next_action TEXT,
                    due_date TEXT,
                    notes TEXT,
                    patience_json TEXT NOT NULL,
                    follow_through_score REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS employment_opportunities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    organization TEXT NOT NULL,
                    role_family TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    fit_score REAL NOT NULL,
                    salary_min REAL,
                    salary_max REAL,
                    remote_type TEXT,
                    location TEXT,
                    requirements_json TEXT NOT NULL,
                    gaps_json TEXT NOT NULL,
                    next_action TEXT,
                    due_date TEXT,
                    notes TEXT,
                    patience_json TEXT NOT NULL,
                    readiness_score REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(title, organization)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS investor_pools (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    investor_type TEXT NOT NULL,
                    thesis TEXT NOT NULL,
                    status TEXT NOT NULL,
                    strategic_fit REAL NOT NULL,
                    capital_readiness_score REAL NOT NULL,
                    stage_fit TEXT,
                    check_size_min REAL,
                    check_size_max REAL,
                    geography TEXT,
                    relationship_owner TEXT,
                    warm_intro_path TEXT,
                    evidence_required_json TEXT NOT NULL,
                    next_action TEXT,
                    notes TEXT,
                    patience_json TEXT NOT NULL,
                    qualification_score REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS governance_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    review_cadence_days INTEGER NOT NULL,
                    evidence_required_json TEXT NOT NULL,
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(domain, rule)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS economic_signals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    value TEXT NOT NULL,
                    trend TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    impact_area TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(name, observed_at)
                )
                """
            )
            conn.commit()

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        existing = {row["name"] for row in rows}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # Matrix cells
    def upsert_cell(self, cell: MatrixCell) -> MatrixCell:
        self._validate_cell(cell)
        now = utc_now()
        score = cell.score()
        assessment = cell.patience_assessment()
        kpi_name = cell.kpi.name if cell.kpi else None
        kpi_current = cell.kpi.current_value if cell.kpi else None
        kpi_target = cell.kpi.target_value if cell.kpi else None
        kpi_unit = cell.kpi.unit if cell.kpi else None
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO matrix_cells (
                    workstream, capability, objective, owner, health, confidence,
                    kpi_name, kpi_current_value, kpi_target_value, kpi_unit,
                    blockers_json, dependencies_json, notes, patience_json,
                    current_score, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workstream, capability) DO UPDATE SET
                    objective=excluded.objective,
                    owner=excluded.owner,
                    health=excluded.health,
                    confidence=excluded.confidence,
                    kpi_name=excluded.kpi_name,
                    kpi_current_value=excluded.kpi_current_value,
                    kpi_target_value=excluded.kpi_target_value,
                    kpi_unit=excluded.kpi_unit,
                    blockers_json=excluded.blockers_json,
                    dependencies_json=excluded.dependencies_json,
                    notes=excluded.notes,
                    patience_json=excluded.patience_json,
                    current_score=excluded.current_score,
                    updated_at=excluded.updated_at
                """,
                (
                    clean(cell.workstream), clean(cell.capability), cell.objective.strip(), cell.owner.strip(),
                    cell.health.value, cell.confidence, kpi_name, kpi_current, kpi_target, kpi_unit,
                    json.dumps(cell.blockers), json.dumps(cell.dependencies), cell.notes.strip(),
                    json.dumps(patience_to_dict(cell.patience)), score, now, now,
                ),
            )
            conn.execute(
                """
                INSERT INTO score_history (
                    workstream, capability, score, health, confidence,
                    patience_score, patience_mode, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    clean(cell.workstream), clean(cell.capability), score, cell.health.value, cell.confidence,
                    assessment.patience_score, assessment.mode.value, now,
                ),
            )
            conn.commit()
        return self.get_cell(cell.workstream, cell.capability)

    def get_cell(self, workstream: str, capability: str) -> MatrixCell:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM matrix_cells
                WHERE lower(workstream)=lower(?) AND lower(capability)=lower(?)
                """,
                (clean(workstream), clean(capability)),
            ).fetchone()
        if not row:
            raise KeyError(f"No matrix cell found for {workstream} × {capability}")
        return row_to_cell(row)

    def delete_cell(self, workstream: str, capability: str) -> bool:
        with self.connect() as conn:
            cursor = conn.execute(
                """DELETE FROM matrix_cells WHERE lower(workstream)=lower(?) AND lower(capability)=lower(?)""",
                (clean(workstream), clean(capability)),
            )
            conn.commit()
        return cursor.rowcount > 0

    def list_cells(self) -> List[MatrixCell]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM matrix_cells ORDER BY current_score ASC, workstream ASC, capability ASC").fetchall()
        return [row_to_cell(row) for row in rows]

    def struggling_cells(self, threshold: float = 60.0) -> List[MatrixCell]:
        return [cell for cell in self.list_cells() if cell.score() < threshold]

    def workstream_score(self, workstream: str) -> float:
        with self.connect() as conn:
            row = conn.execute("SELECT AVG(current_score) AS avg_score FROM matrix_cells WHERE lower(workstream)=lower(?)", (clean(workstream),)).fetchone()
        if row["avg_score"] is None:
            raise KeyError(f"No cells found for workstream: {workstream}")
        return round(float(row["avg_score"]), 2)

    def capability_score(self, capability: str) -> float:
        with self.connect() as conn:
            row = conn.execute("SELECT AVG(current_score) AS avg_score FROM matrix_cells WHERE lower(capability)=lower(?)", (clean(capability),)).fetchone()
        if row["avg_score"] is None:
            raise KeyError(f"No cells found for capability: {capability}")
        return round(float(row["avg_score"]), 2)

    def score_history(self, workstream: str, capability: str) -> List[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT score, health, confidence, patience_score, patience_mode, recorded_at
                FROM score_history
                WHERE lower(workstream)=lower(?) AND lower(capability)=lower(?)
                ORDER BY recorded_at ASC
                """,
                (clean(workstream), clean(capability)),
            ).fetchall()
        return [dict(row) for row in rows]

    def generate_recovery_actions(self, threshold: float = 60.0) -> List[RecoveryAction]:
        actions: List[RecoveryAction] = []
        for cell in self.struggling_cells(threshold):
            score = cell.score()
            assessment = cell.patience_assessment()
            actions.append(
                RecoveryAction(
                    workstream=cell.workstream,
                    capability=cell.capability,
                    owner=cell.owner,
                    priority=max_priority(priority_from_score(score), assessment.priority),
                    score=score,
                    patience_mode=assessment.mode,
                    patience_score=assessment.patience_score,
                    reason=build_reason(cell, assessment),
                    recommended_action=build_recommendation(cell, assessment),
                    review_cadence_days=assessment.review_cadence_days,
                    escalation_deadline_days=assessment.escalation_deadline_days,
                )
            )
        return actions

    # Projects
    def upsert_project(self, project: Project) -> Project:
        self._validate_project(project)
        now = utc_now()
        score = project.follow_through_score()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO projects (
                    name, category, objective, owner, stage, status, linked_workstream, linked_capability,
                    north_star_metric, current_value, target_value, blockers_json, dependencies_json,
                    next_milestone, next_action, due_date, notes, patience_json, follow_through_score,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    category=excluded.category, objective=excluded.objective, owner=excluded.owner,
                    stage=excluded.stage, status=excluded.status, linked_workstream=excluded.linked_workstream,
                    linked_capability=excluded.linked_capability, north_star_metric=excluded.north_star_metric,
                    current_value=excluded.current_value, target_value=excluded.target_value,
                    blockers_json=excluded.blockers_json, dependencies_json=excluded.dependencies_json,
                    next_milestone=excluded.next_milestone, next_action=excluded.next_action,
                    due_date=excluded.due_date, notes=excluded.notes, patience_json=excluded.patience_json,
                    follow_through_score=excluded.follow_through_score, updated_at=excluded.updated_at
                """,
                (
                    clean(project.name), clean(project.category), project.objective.strip(), project.owner.strip(),
                    project.stage.value, project.status.value, clean(project.linked_workstream), clean(project.linked_capability),
                    project.north_star_metric.strip(), project.current_value, project.target_value,
                    json.dumps(project.blockers), json.dumps(project.dependencies), project.next_milestone.strip(),
                    project.next_action.strip(), project.due_date.strip(), project.notes.strip(),
                    json.dumps(patience_to_dict(project.patience)), score, now, now,
                ),
            )
            conn.commit()
        return self.get_project(project.name)

    def get_project(self, name: str) -> Project:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM projects WHERE lower(name)=lower(?)", (clean(name),)).fetchone()
        if not row:
            raise KeyError(f"No project found: {name}")
        return row_to_project(row)

    def list_projects(self, include_complete: bool = True) -> List[Project]:
        query = "SELECT * FROM projects"
        params: tuple = ()
        if not include_complete:
            query += " WHERE status != ?"
            params = (ProjectStatus.COMPLETE.value,)
        query += " ORDER BY follow_through_score ASC, name ASC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [row_to_project(row) for row in rows]

    def project_follow_through(self) -> List[dict]:
        rows = []
        for project in self.list_projects(include_complete=False):
            assessment = project.patience_assessment()
            rows.append({
                **project_to_dict(project),
                "patience_assessment": assessment_to_dict(assessment),
                "recommended_follow_through": build_project_follow_through(project, assessment),
            })
        return rows

    # Employment
    def upsert_employment(self, opportunity: EmploymentOpportunity) -> EmploymentOpportunity:
        self._validate_employment(opportunity)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO employment_opportunities (
                    title, organization, role_family, source, status, fit_score, salary_min, salary_max,
                    remote_type, location, requirements_json, gaps_json, next_action, due_date,
                    notes, patience_json, readiness_score, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(title, organization) DO UPDATE SET
                    role_family=excluded.role_family, source=excluded.source, status=excluded.status,
                    fit_score=excluded.fit_score, salary_min=excluded.salary_min, salary_max=excluded.salary_max,
                    remote_type=excluded.remote_type, location=excluded.location,
                    requirements_json=excluded.requirements_json, gaps_json=excluded.gaps_json,
                    next_action=excluded.next_action, due_date=excluded.due_date, notes=excluded.notes,
                    patience_json=excluded.patience_json, readiness_score=excluded.readiness_score,
                    updated_at=excluded.updated_at
                """,
                (
                    clean(opportunity.title), clean(opportunity.organization), clean(opportunity.role_family), opportunity.source.strip(),
                    opportunity.status.value, opportunity.fit_score, opportunity.salary_min, opportunity.salary_max,
                    opportunity.remote_type.strip(), opportunity.location.strip(), json.dumps(opportunity.requirements),
                    json.dumps(opportunity.gaps), opportunity.next_action.strip(), opportunity.due_date.strip(),
                    opportunity.notes.strip(), json.dumps(patience_to_dict(opportunity.patience)), opportunity.readiness_score(), now, now,
                ),
            )
            conn.commit()
        return self.get_employment(opportunity.title, opportunity.organization)

    def get_employment(self, title: str, organization: str) -> EmploymentOpportunity:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM employment_opportunities WHERE lower(title)=lower(?) AND lower(organization)=lower(?)",
                (clean(title), clean(organization)),
            ).fetchone()
        if not row:
            raise KeyError(f"No employment opportunity found: {title} at {organization}")
        return row_to_employment(row)

    def list_employment(self, active_only: bool = True) -> List[EmploymentOpportunity]:
        query = "SELECT * FROM employment_opportunities"
        params: tuple = ()
        if active_only:
            query += " WHERE status NOT IN (?, ?)"
            params = (EmploymentStatus.REJECTED.value, EmploymentStatus.ARCHIVED.value)
        query += " ORDER BY readiness_score DESC, updated_at DESC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [row_to_employment(row) for row in rows]

    def employment_path(self) -> List[dict]:
        result = []
        for opportunity in self.list_employment(active_only=True):
            assessment = opportunity.patience_assessment()
            result.append({
                **employment_to_dict(opportunity),
                "patience_assessment": assessment_to_dict(assessment),
                "recommended_next_step": build_employment_next_step(opportunity, assessment),
            })
        return result

    # Investors
    def upsert_investor_pool(self, pool: InvestorPool) -> InvestorPool:
        self._validate_investor(pool)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO investor_pools (
                    name, investor_type, thesis, status, strategic_fit, capital_readiness_score,
                    stage_fit, check_size_min, check_size_max, geography, relationship_owner,
                    warm_intro_path, evidence_required_json, next_action, notes, patience_json,
                    qualification_score, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    investor_type=excluded.investor_type, thesis=excluded.thesis, status=excluded.status,
                    strategic_fit=excluded.strategic_fit, capital_readiness_score=excluded.capital_readiness_score,
                    stage_fit=excluded.stage_fit, check_size_min=excluded.check_size_min,
                    check_size_max=excluded.check_size_max, geography=excluded.geography,
                    relationship_owner=excluded.relationship_owner, warm_intro_path=excluded.warm_intro_path,
                    evidence_required_json=excluded.evidence_required_json, next_action=excluded.next_action,
                    notes=excluded.notes, patience_json=excluded.patience_json,
                    qualification_score=excluded.qualification_score, updated_at=excluded.updated_at
                """,
                (
                    clean(pool.name), clean(pool.investor_type), pool.thesis.strip(), pool.status.value,
                    pool.strategic_fit, pool.capital_readiness_score, pool.stage_fit.strip(),
                    pool.check_size_min, pool.check_size_max, pool.geography.strip(), pool.relationship_owner.strip(),
                    pool.warm_intro_path.strip(), json.dumps(pool.evidence_required), pool.next_action.strip(),
                    pool.notes.strip(), json.dumps(patience_to_dict(pool.patience)), pool.qualification_score(), now, now,
                ),
            )
            conn.commit()
        return self.get_investor_pool(pool.name)

    def get_investor_pool(self, name: str) -> InvestorPool:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM investor_pools WHERE lower(name)=lower(?)", (clean(name),)).fetchone()
        if not row:
            raise KeyError(f"No investor pool found: {name}")
        return row_to_investor_pool(row)

    def list_investor_pools(self) -> List[InvestorPool]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM investor_pools ORDER BY qualification_score DESC, updated_at DESC").fetchall()
        return [row_to_investor_pool(row) for row in rows]

    def qualified_investor_pools(self, threshold: float = 65.0) -> List[dict]:
        result = []
        for pool in self.list_investor_pools():
            if pool.qualification_score() >= threshold or pool.status in {InvestorStatus.READY_TO_CONTACT, InvestorStatus.ACTIVE_DILIGENCE}:
                assessment = pool.patience_assessment()
                result.append({
                    **investor_pool_to_dict(pool),
                    "patience_assessment": assessment_to_dict(assessment),
                    "recommended_next_step": build_investor_next_step(pool, assessment),
                })
        return result

    # Governance
    def upsert_governance_policy(self, policy: GovernancePolicy) -> GovernancePolicy:
        self._validate_policy(policy)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO governance_policies (
                    domain, rule, owner, severity, status, review_cadence_days,
                    evidence_required_json, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain, rule) DO UPDATE SET
                    owner=excluded.owner, severity=excluded.severity, status=excluded.status,
                    review_cadence_days=excluded.review_cadence_days,
                    evidence_required_json=excluded.evidence_required_json,
                    notes=excluded.notes, updated_at=excluded.updated_at
                """,
                (
                    clean(policy.domain), policy.rule.strip(), policy.owner.strip(), policy.severity.value,
                    clean(policy.status), policy.review_cadence_days, json.dumps(policy.evidence_required),
                    policy.notes.strip(), now, now,
                ),
            )
            conn.commit()
        return self.get_governance_policy(policy.domain, policy.rule)

    def get_governance_policy(self, domain: str, rule: str) -> GovernancePolicy:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM governance_policies WHERE lower(domain)=lower(?) AND lower(rule)=lower(?)",
                (clean(domain), rule.strip().lower()),
            ).fetchone()
        if not row:
            raise KeyError(f"No governance policy found for {domain}: {rule}")
        return row_to_governance_policy(row)

    def list_governance_policies(self) -> List[GovernancePolicy]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM governance_policies ORDER BY CASE severity WHEN 'hard_stop' THEN 0 WHEN 'required' THEN 1 ELSE 2 END, domain ASC"
            ).fetchall()
        return [row_to_governance_policy(row) for row in rows]

    def governance_status(self) -> dict:
        policies = self.list_governance_policies()
        hard_stops = [policy for policy in policies if policy.severity == GovernanceSeverity.HARD_STOP and policy.status == "active"]
        required = [policy for policy in policies if policy.severity == GovernanceSeverity.REQUIRED and policy.status == "active"]
        return {
            "active_policy_count": len([p for p in policies if p.status == "active"]),
            "hard_stop_count": len(hard_stops),
            "required_policy_count": len(required),
            "hard_stops": [governance_policy_to_dict(policy) for policy in hard_stops],
            "required_controls": [governance_policy_to_dict(policy) for policy in required],
            "all_policies": [governance_policy_to_dict(policy) for policy in policies],
        }

    # Economic signals
    def upsert_economic_signal(self, signal: EconomicSignal) -> EconomicSignal:
        if not signal.name.strip() or not signal.value.strip() or not signal.source.strip():
            raise ValueError("Economic signal name, value, and source are required.")
        if not 0.0 <= signal.confidence <= 1.0:
            raise ValueError("Economic signal confidence must be between 0.0 and 1.0.")
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO economic_signals (
                    name, value, trend, confidence, source, impact_area, observed_at,
                    notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name, observed_at) DO UPDATE SET
                    value=excluded.value, trend=excluded.trend, confidence=excluded.confidence,
                    source=excluded.source, impact_area=excluded.impact_area,
                    notes=excluded.notes, updated_at=excluded.updated_at
                """,
                (
                    clean(signal.name), signal.value.strip(), clean(signal.trend), signal.confidence,
                    signal.source.strip(), clean(signal.impact_area), signal.observed_at.strip(),
                    signal.notes.strip(), now, now,
                ),
            )
            conn.commit()
        return self.get_economic_signal(signal.name, signal.observed_at)

    def get_economic_signal(self, name: str, observed_at: str) -> EconomicSignal:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM economic_signals WHERE lower(name)=lower(?) AND observed_at=?",
                (clean(name), observed_at),
            ).fetchone()
        if not row:
            raise KeyError(f"No economic signal found: {name} at {observed_at}")
        return row_to_economic_signal(row)

    def list_economic_signals(self, impact_area: str = "") -> List[EconomicSignal]:
        query = "SELECT * FROM economic_signals"
        params: tuple = ()
        if impact_area.strip():
            query += " WHERE lower(impact_area)=lower(?)"
            params = (clean(impact_area),)
        query += " ORDER BY observed_at DESC, name ASC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [row_to_economic_signal(row) for row in rows]

    def economic_trajectory(self) -> dict:
        signals = self.list_economic_signals()
        by_area: dict[str, list[dict]] = {}
        for signal in signals:
            by_area.setdefault(signal.impact_area, []).append(economic_signal_to_dict(signal))
        return {
            "generated_at": utc_now(),
            "signal_count": len(signals),
            "trajectory_summary": summarize_economic_signals(signals),
            "by_impact_area": by_area,
        }

    # Exports/seed
    def export_snapshot(self) -> dict:
        return {
            "system": "Oracle + PATIENCE Operations Matrix",
            "generated_at": utc_now(),
            "cells": [cell_to_dict(cell) for cell in self.list_cells()],
            "recovery_actions": [action_to_dict(action) for action in self.generate_recovery_actions()],
            "projects": self.project_follow_through(),
            "employment_path": self.employment_path(),
            "investor_pools": self.qualified_investor_pools(threshold=0),
            "governance": self.governance_status(),
            "economic_trajectory": self.economic_trajectory(),
        }

    def seed_demo_data(self) -> None:
        demo_cells = [
            MatrixCell(
                workstream="Oracle Platform",
                capability="Data Governance",
                objective="Create secure source tracking, permissioning, and decision logs.",
                owner="Matthew",
                health=HealthStatus.RED,
                confidence=0.62,
                kpi=KPI("governance_docs_completed", 2, 8, "documents"),
                blockers=["No finalized data classification model", "No access-control policy"],
                dependencies=["Legal/IP advisor", "Cloud architecture decision"],
                notes="Foundational control point. Weak governance creates investor, compliance, and IP risk.",
                patience=PatienceProfile(urgency=0.8, reversibility=0.35, volatility=0.7, runway_sensitivity=0.65, opportunity_half_life_days=14, evidence_quality=0.55, stakeholder_impact=0.75, compliance_sensitivity=0.9),
            ),
            MatrixCell(
                workstream="Capital Strategy",
                capability="Grant Intelligence",
                objective="Build a repeatable grant discovery and proposal workflow.",
                owner="Strategy Lead",
                health=HealthStatus.YELLOW,
                confidence=0.75,
                kpi=KPI("qualified_grants_identified", 4, 10, "grants"),
                blockers=["No standardized eligibility filter"],
                dependencies=["Research narrative", "Technical validation packet"],
                notes="High leverage area. Needs structure before institutional outreach.",
                patience=PatienceProfile(urgency=0.65, reversibility=0.7, volatility=0.55, runway_sensitivity=0.8, opportunity_half_life_days=30, evidence_quality=0.6, stakeholder_impact=0.55, compliance_sensitivity=0.6),
            ),
            MatrixCell(
                workstream="Product",
                capability="Prototype Development",
                objective="Create a working command dashboard for matrix scoring and action generation.",
                owner="Engineering Lead",
                health=HealthStatus.GREEN,
                confidence=0.84,
                kpi=KPI("prototype_modules_completed", 3, 5, "modules"),
                notes="Good early momentum.",
                patience=PatienceProfile(urgency=0.55, reversibility=0.8, volatility=0.45, runway_sensitivity=0.6, opportunity_half_life_days=45, evidence_quality=0.75, stakeholder_impact=0.45, compliance_sensitivity=0.4),
            ),
        ]
        for cell in demo_cells:
            self.upsert_cell(cell)

        demo_projects = [
            Project(
                name="PATIENCE Control Plane",
                category="patience_ai",
                objective="Make PATIENCE the auditable grounding/action layer for Oracle operations.",
                owner="Matthew",
                stage=ProjectStage.BUILD,
                status=ProjectStatus.ACTIVE,
                linked_workstream="Oracle Platform",
                linked_capability="Data Governance",
                north_star_metric="governed_decision_flows",
                current_value=2,
                target_value=6,
                blockers=["Need policy constitution v1"],
                dependencies=["Operations API", "Decision log schema"],
                next_milestone="Ship v0.4 API with patience assessments and governance endpoints.",
                next_action="Review generated README and run seed data.",
                due_date="",
                notes="PATIENCE stays consent-aware and auditable; Oracle stays interpretive.",
                patience=PatienceProfile(urgency=0.7, reversibility=0.65, volatility=0.55, runway_sensitivity=0.7, opportunity_half_life_days=21, evidence_quality=0.68, stakeholder_impact=0.9, compliance_sensitivity=0.85),
            ),
            Project(
                name="Employment Opportunity Path",
                category="employment",
                objective="Build a repeatable pipeline for roles aligned to AI operations, Oracle systems, social impact, and technical coordination.",
                owner="Matthew",
                stage=ProjectStage.DISCOVERY,
                status=ProjectStatus.WATCH,
                north_star_metric="qualified_applications_submitted",
                current_value=0,
                target_value=12,
                blockers=["Resume/portfolio needs current Oracle + PATIENCE narrative"],
                dependencies=["Role targeting", "Outreach scripts"],
                next_milestone="Define target role families and application package.",
                next_action="Add 10 target roles into employment_opportunities.",
                notes="Employment path should increase stability while keeping venture optionality alive.",
                patience=PatienceProfile(urgency=0.72, reversibility=0.75, volatility=0.55, runway_sensitivity=0.8, opportunity_half_life_days=14, evidence_quality=0.5, stakeholder_impact=0.6, compliance_sensitivity=0.3),
            ),
        ]
        for project in demo_projects:
            self.upsert_project(project)

        demo_employment = [
            EmploymentOpportunity(
                title="AI Operations Coordinator",
                organization="Target Organization",
                role_family="AI Operations / Program Coordination",
                source="manual",
                status=EmploymentStatus.TARGET,
                fit_score=78,
                remote_type="hybrid_or_remote",
                location="United States",
                requirements=["AI workflow literacy", "project coordination", "stakeholder communication"],
                gaps=["Need portfolio proof packet"],
                next_action="Prepare 1-page Oracle/PATIENCE operations case study.",
                notes="Use as a stability lane while preserving founder control.",
                patience=PatienceProfile(urgency=0.7, reversibility=0.8, volatility=0.45, runway_sensitivity=0.82, opportunity_half_life_days=10, evidence_quality=0.58, stakeholder_impact=0.45, compliance_sensitivity=0.25),
            )
        ]
        for item in demo_employment:
            self.upsert_employment(item)

        demo_investors = [
            InvestorPool(
                name="AI Infrastructure Angels",
                investor_type="angel_syndicate",
                thesis="Early AI tooling, infrastructure workflows, and human-in-the-loop governance.",
                status=InvestorStatus.RESEARCH,
                strategic_fit=74,
                capital_readiness_score=42,
                stage_fit="pre-seed / prototype",
                check_size_min=10000,
                check_size_max=100000,
                geography="US",
                relationship_owner="Matthew",
                evidence_required=["prototype demo", "use case proof", "founder narrative", "data governance policy"],
                next_action="Build investor evidence checklist before outreach.",
                notes="Do not contact cold until command packet and prototype proof are coherent.",
                patience=PatienceProfile(urgency=0.52, reversibility=0.55, volatility=0.7, runway_sensitivity=0.78, opportunity_half_life_days=45, evidence_quality=0.42, stakeholder_impact=0.7, compliance_sensitivity=0.65),
            ),
            InvestorPool(
                name="Workforce Innovation Grants",
                investor_type="grant_pool",
                thesis="Funding for job pathways, AI skills, inclusive operations, and workforce resilience.",
                status=InvestorStatus.WARMING,
                strategic_fit=82,
                capital_readiness_score=55,
                stage_fit="pilot / community proof",
                geography="US",
                relationship_owner="Matthew",
                evidence_required=["program design", "outcomes metrics", "budget", "community partner"],
                next_action="Create grant eligibility filter and partner map.",
                notes="Strong fit for employment pathway and PATIENCE training layer.",
                patience=PatienceProfile(urgency=0.6, reversibility=0.7, volatility=0.5, runway_sensitivity=0.75, opportunity_half_life_days=60, evidence_quality=0.55, stakeholder_impact=0.8, compliance_sensitivity=0.75),
            ),
        ]
        for pool in demo_investors:
            self.upsert_investor_pool(pool)

        demo_policies = [
            GovernancePolicy("Data Governance", "No sensitive data enters the system without source, permission, and purpose fields.", "Matthew", GovernanceSeverity.HARD_STOP, evidence_required=["source", "permission", "purpose"]),
            GovernancePolicy("Capital Outreach", "Investor outreach requires a current narrative, use case proof, and risk disclosure note.", "Matthew", GovernanceSeverity.REQUIRED, evidence_required=["narrative", "prototype evidence", "risk note"]),
            GovernancePolicy("Employment Path", "Every job target must include fit score, gap list, next action, and due date before application.", "Matthew", GovernanceSeverity.REQUIRED, evidence_required=["fit score", "gap list", "next action"]),
            GovernancePolicy("Oracle/PATIENCE Separation", "Oracle may interpret patterns; PATIENCE owns grounded action, consent, audit, and memory-writing.", "Matthew", GovernanceSeverity.HARD_STOP, evidence_required=["decision log", "action owner", "source trail"]),
        ]
        for policy in demo_policies:
            self.upsert_governance_policy(policy)

        demo_signals = [
            EconomicSignal("US real GDP growth", "2.0% annual rate in Q1 2026 advance estimate", "resilient_but_mixed", 0.9, "BEA, 2026-04-30", "macro"),
            EconomicSignal("Federal funds target range", "3.50% to 3.75% after April 29 2026 FOMC statement", "restrictive_stable", 0.9, "Federal Reserve, 2026-04-29", "capital_cost"),
            EconomicSignal("AI/data investment", "Investment and information processing equipment were notable contributors to Q1 2026 growth", "expanding", 0.75, "BEA technical notes, 2026-04-30", "ai_infrastructure"),
        ]
        for signal in demo_signals:
            self.upsert_economic_signal(signal)

    def _validate_cell(self, cell: MatrixCell) -> None:
        if not cell.workstream.strip():
            raise ValueError("Workstream is required.")
        if not cell.capability.strip():
            raise ValueError("Capability is required.")
        if not cell.owner.strip():
            raise ValueError("Owner is required.")
        if not cell.objective.strip():
            raise ValueError("Objective is required.")
        if not 0.0 <= cell.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0.")
        validate_patience(cell.patience)

    def _validate_project(self, project: Project) -> None:
        if not project.name.strip() or not project.objective.strip() or not project.owner.strip():
            raise ValueError("Project name, objective, and owner are required.")
        validate_patience(project.patience)

    def _validate_employment(self, opportunity: EmploymentOpportunity) -> None:
        if not opportunity.title.strip() or not opportunity.organization.strip():
            raise ValueError("Employment title and organization are required.")
        if not 0.0 <= opportunity.fit_score <= 100.0:
            raise ValueError("Employment fit_score must be between 0 and 100.")
        validate_patience(opportunity.patience)

    def _validate_investor(self, pool: InvestorPool) -> None:
        if not pool.name.strip() or not pool.thesis.strip():
            raise ValueError("Investor pool name and thesis are required.")
        if not 0.0 <= pool.strategic_fit <= 100.0:
            raise ValueError("Investor strategic_fit must be between 0 and 100.")
        if not 0.0 <= pool.capital_readiness_score <= 100.0:
            raise ValueError("Investor capital_readiness_score must be between 0 and 100.")
        validate_patience(pool.patience)

    def _validate_policy(self, policy: GovernancePolicy) -> None:
        if not policy.domain.strip() or not policy.rule.strip() or not policy.owner.strip():
            raise ValueError("Governance policy domain, rule, and owner are required.")
        if policy.review_cadence_days <= 0:
            raise ValueError("Review cadence must be positive.")


# PATIENCE logic

def assess_patience(profile: PatienceProfile, operational_score: float = 50.0, context_label: str = "") -> PatienceAssessment:
    validate_patience(profile)
    pressure = (
        profile.urgency * 0.22
        + profile.volatility * 0.18
        + profile.runway_sensitivity * 0.20
        + (1.0 - profile.reversibility) * 0.15
        + profile.stakeholder_impact * 0.10
        + profile.compliance_sensitivity * 0.15
    )
    stability = (
        profile.evidence_quality * 0.45
        + profile.reversibility * 0.20
        + (1.0 - profile.volatility) * 0.20
        + (1.0 - profile.compliance_sensitivity) * 0.15
    )
    patience_score = round(clamp(50 + ((stability - pressure) * 55), 0, 100), 2)

    priority = priority_from_score(min(operational_score, patience_score))
    if profile.compliance_sensitivity >= 0.82 and profile.evidence_quality < 0.70:
        mode = PatienceMode.CONTAIN
        priority = max_priority(priority, Priority.HIGH)
    elif profile.urgency >= 0.78 and profile.opportunity_half_life_days <= 14 and profile.evidence_quality >= 0.58:
        mode = PatienceMode.ESCALATE
        priority = max_priority(priority, Priority.HIGH)
    elif patience_score >= 72 and operational_score >= 60:
        mode = PatienceMode.OBSERVE
    elif patience_score >= 55:
        mode = PatienceMode.PREPARE
    elif operational_score >= 55 and profile.evidence_quality >= 0.55:
        mode = PatienceMode.PROCEED
    else:
        mode = PatienceMode.ESCALATE
        priority = max_priority(priority, Priority.MEDIUM)

    if profile.urgency >= 0.8 or profile.volatility >= 0.75 or mode in {PatienceMode.ESCALATE, PatienceMode.CONTAIN}:
        review_cadence = 1
    elif profile.runway_sensitivity >= 0.7 or profile.opportunity_half_life_days <= 21:
        review_cadence = 3
    elif patience_score >= 72:
        review_cadence = 14
    else:
        review_cadence = 7

    escalation_deadline = max(1, min(profile.opportunity_half_life_days, review_cadence * 3))
    if mode in {PatienceMode.ESCALATE, PatienceMode.CONTAIN}:
        escalation_deadline = min(escalation_deadline, 3)

    rationale = []
    if context_label:
        rationale.append(f"Context assessed: {context_label}.")
    rationale.append(f"Pressure index {round(pressure, 2)} versus stability index {round(stability, 2)}.")
    if profile.evidence_quality < 0.55:
        rationale.append("Evidence quality is not strong enough for irreversible expansion.")
    if profile.runway_sensitivity >= 0.70:
        rationale.append("Runway sensitivity is elevated; delays must be intentional and bounded.")
    if profile.compliance_sensitivity >= 0.75:
        rationale.append("Governance sensitivity is elevated; source, consent, and audit controls matter.")
    if profile.opportunity_half_life_days <= 14:
        rationale.append("Opportunity window is short; review cadence must tighten.")

    guardrails = [
        "Keep a named owner for every next action.",
        "Record source, evidence, and decision rationale before high-impact action.",
        "Do not escalate outreach or capital asks without a current proof packet.",
    ]
    if mode == PatienceMode.CONTAIN:
        guardrails.insert(0, "Hard stop: resolve governance, consent, legal, or trust issue before expansion.")
    if profile.compliance_sensitivity >= 0.75:
        guardrails.append("Use purpose-bound data handling and maintain an audit trail.")

    next_actions = {
        PatienceMode.OBSERVE: [
            "Maintain watch status and refresh evidence on the next review cadence.",
            "Define the trigger that would move this from observe to prepare or proceed.",
            "Avoid adding scope until signal changes.",
        ],
        PatienceMode.PREPARE: [
            "Build the missing asset, proof, policy, or relationship before public action.",
            "Remove the smallest blocker that increases optionality the most.",
            "Schedule the next decision review within the cadence window.",
        ],
        PatienceMode.PROCEED: [
            "Execute the next action with a defined owner and evidence of completion.",
            "Log the decision and expected outcome.",
            "Review result and update score after completion.",
        ],
        PatienceMode.ESCALATE: [
            "Notify the accountable owner and resolve the highest-impact blocker.",
            "Choose a go/no-go decision within the escalation deadline.",
            "Reduce the action to the smallest irreversible step.",
        ],
        PatienceMode.CONTAIN: [
            "Pause expansion until governance conditions are satisfied.",
            "Create or update the required policy, consent, or source trail.",
            "Resume only after the owner records approval and risk treatment.",
        ],
    }[mode]

    return PatienceAssessment(
        patience_score=patience_score,
        mode=mode,
        priority=priority,
        review_cadence_days=review_cadence,
        escalation_deadline_days=escalation_deadline,
        rationale=rationale,
        guardrails=guardrails,
        next_actions=next_actions,
    )


# Row converters

def row_to_cell(row: sqlite3.Row) -> MatrixCell:
    kpi = None
    if row["kpi_name"]:
        kpi = KPI(row["kpi_name"], float(row["kpi_current_value"] or 0), float(row["kpi_target_value"] or 0), row["kpi_unit"] or "")
    return MatrixCell(
        workstream=row["workstream"], capability=row["capability"], objective=row["objective"], owner=row["owner"],
        health=HealthStatus(row["health"]), confidence=float(row["confidence"]), kpi=kpi,
        blockers=json.loads(row["blockers_json"] or "[]"), dependencies=json.loads(row["dependencies_json"] or "[]"),
        notes=row["notes"] or "", patience=dict_to_patience(json.loads(row["patience_json"] or "{}")),
    )


def row_to_project(row: sqlite3.Row) -> Project:
    return Project(
        name=row["name"], category=row["category"], objective=row["objective"], owner=row["owner"],
        stage=ProjectStage(row["stage"]), status=ProjectStatus(row["status"]),
        linked_workstream=row["linked_workstream"] or "", linked_capability=row["linked_capability"] or "",
        north_star_metric=row["north_star_metric"] or "", current_value=float(row["current_value"] or 0),
        target_value=float(row["target_value"] or 0), blockers=json.loads(row["blockers_json"] or "[]"),
        dependencies=json.loads(row["dependencies_json"] or "[]"), next_milestone=row["next_milestone"] or "",
        next_action=row["next_action"] or "", due_date=row["due_date"] or "", notes=row["notes"] or "",
        patience=dict_to_patience(json.loads(row["patience_json"] or "{}")),
    )


def row_to_employment(row: sqlite3.Row) -> EmploymentOpportunity:
    return EmploymentOpportunity(
        title=row["title"], organization=row["organization"], role_family=row["role_family"], source=row["source"],
        status=EmploymentStatus(row["status"]), fit_score=float(row["fit_score"]),
        salary_min=row["salary_min"], salary_max=row["salary_max"], remote_type=row["remote_type"] or "unspecified",
        location=row["location"] or "", requirements=json.loads(row["requirements_json"] or "[]"),
        gaps=json.loads(row["gaps_json"] or "[]"), next_action=row["next_action"] or "",
        due_date=row["due_date"] or "", notes=row["notes"] or "",
        patience=dict_to_patience(json.loads(row["patience_json"] or "{}")),
    )


def row_to_investor_pool(row: sqlite3.Row) -> InvestorPool:
    return InvestorPool(
        name=row["name"], investor_type=row["investor_type"], thesis=row["thesis"], status=InvestorStatus(row["status"]),
        strategic_fit=float(row["strategic_fit"]), capital_readiness_score=float(row["capital_readiness_score"]),
        stage_fit=row["stage_fit"] or "", check_size_min=row["check_size_min"], check_size_max=row["check_size_max"],
        geography=row["geography"] or "", relationship_owner=row["relationship_owner"] or "",
        warm_intro_path=row["warm_intro_path"] or "", evidence_required=json.loads(row["evidence_required_json"] or "[]"),
        next_action=row["next_action"] or "", notes=row["notes"] or "",
        patience=dict_to_patience(json.loads(row["patience_json"] or "{}")),
    )


def row_to_governance_policy(row: sqlite3.Row) -> GovernancePolicy:
    return GovernancePolicy(
        domain=row["domain"], rule=row["rule"], owner=row["owner"], severity=GovernanceSeverity(row["severity"]),
        status=row["status"], review_cadence_days=int(row["review_cadence_days"]),
        evidence_required=json.loads(row["evidence_required_json"] or "[]"), notes=row["notes"] or "",
    )


def row_to_economic_signal(row: sqlite3.Row) -> EconomicSignal:
    return EconomicSignal(
        name=row["name"], value=row["value"], trend=row["trend"], confidence=float(row["confidence"]),
        source=row["source"], impact_area=row["impact_area"], observed_at=row["observed_at"], notes=row["notes"] or "",
    )


# Serializers

def cell_to_dict(cell: MatrixCell) -> dict:
    assessment = cell.patience_assessment()
    return {
        "workstream": cell.workstream,
        "capability": cell.capability,
        "objective": cell.objective,
        "owner": cell.owner,
        "health": cell.health.value,
        "confidence": cell.confidence,
        "score": cell.score(),
        "kpi": kpi_to_dict(cell.kpi),
        "blockers": cell.blockers,
        "dependencies": cell.dependencies,
        "notes": cell.notes,
        "patience": patience_to_dict(cell.patience),
        "patience_assessment": assessment_to_dict(assessment),
    }


def project_to_dict(project: Project) -> dict:
    return {
        "name": project.name,
        "category": project.category,
        "objective": project.objective,
        "owner": project.owner,
        "stage": project.stage.value,
        "status": project.status.value,
        "linked_workstream": project.linked_workstream,
        "linked_capability": project.linked_capability,
        "north_star_metric": project.north_star_metric,
        "current_value": project.current_value,
        "target_value": project.target_value,
        "progress_ratio": project.progress_ratio(),
        "follow_through_score": project.follow_through_score(),
        "blockers": project.blockers,
        "dependencies": project.dependencies,
        "next_milestone": project.next_milestone,
        "next_action": project.next_action,
        "due_date": project.due_date,
        "notes": project.notes,
        "patience": patience_to_dict(project.patience),
    }


def employment_to_dict(item: EmploymentOpportunity) -> dict:
    return {
        "title": item.title,
        "organization": item.organization,
        "role_family": item.role_family,
        "source": item.source,
        "status": item.status.value,
        "fit_score": item.fit_score,
        "readiness_score": item.readiness_score(),
        "salary_min": item.salary_min,
        "salary_max": item.salary_max,
        "remote_type": item.remote_type,
        "location": item.location,
        "requirements": item.requirements,
        "gaps": item.gaps,
        "next_action": item.next_action,
        "due_date": item.due_date,
        "notes": item.notes,
        "patience": patience_to_dict(item.patience),
    }


def investor_pool_to_dict(pool: InvestorPool) -> dict:
    return {
        "name": pool.name,
        "investor_type": pool.investor_type,
        "thesis": pool.thesis,
        "status": pool.status.value,
        "strategic_fit": pool.strategic_fit,
        "capital_readiness_score": pool.capital_readiness_score,
        "qualification_score": pool.qualification_score(),
        "stage_fit": pool.stage_fit,
        "check_size_min": pool.check_size_min,
        "check_size_max": pool.check_size_max,
        "geography": pool.geography,
        "relationship_owner": pool.relationship_owner,
        "warm_intro_path": pool.warm_intro_path,
        "evidence_required": pool.evidence_required,
        "next_action": pool.next_action,
        "notes": pool.notes,
        "patience": patience_to_dict(pool.patience),
    }


def governance_policy_to_dict(policy: GovernancePolicy) -> dict:
    return {
        "domain": policy.domain,
        "rule": policy.rule,
        "owner": policy.owner,
        "severity": policy.severity.value,
        "status": policy.status,
        "review_cadence_days": policy.review_cadence_days,
        "evidence_required": policy.evidence_required,
        "notes": policy.notes,
    }


def economic_signal_to_dict(signal: EconomicSignal) -> dict:
    return {
        "name": signal.name,
        "value": signal.value,
        "trend": signal.trend,
        "confidence": signal.confidence,
        "source": signal.source,
        "impact_area": signal.impact_area,
        "observed_at": signal.observed_at,
        "notes": signal.notes,
    }


def action_to_dict(action: RecoveryAction) -> dict:
    return {
        "workstream": action.workstream,
        "capability": action.capability,
        "owner": action.owner,
        "priority": action.priority.value,
        "score": action.score,
        "patience_mode": action.patience_mode.value,
        "patience_score": action.patience_score,
        "reason": action.reason,
        "recommended_action": action.recommended_action,
        "review_cadence_days": action.review_cadence_days,
        "escalation_deadline_days": action.escalation_deadline_days,
    }


def kpi_to_dict(kpi: Optional[KPI]) -> Optional[dict]:
    if not kpi:
        return None
    return {
        "name": kpi.name,
        "current_value": kpi.current_value,
        "target_value": kpi.target_value,
        "unit": kpi.unit,
        "progress_ratio": kpi.progress_ratio(),
    }


def patience_to_dict(profile: PatienceProfile) -> dict:
    return {
        "urgency": profile.urgency,
        "reversibility": profile.reversibility,
        "volatility": profile.volatility,
        "runway_sensitivity": profile.runway_sensitivity,
        "opportunity_half_life_days": profile.opportunity_half_life_days,
        "evidence_quality": profile.evidence_quality,
        "stakeholder_impact": profile.stakeholder_impact,
        "compliance_sensitivity": profile.compliance_sensitivity,
    }


def dict_to_patience(data: dict) -> PatienceProfile:
    return PatienceProfile(
        urgency=float(data.get("urgency", 0.5)),
        reversibility=float(data.get("reversibility", 0.5)),
        volatility=float(data.get("volatility", 0.5)),
        runway_sensitivity=float(data.get("runway_sensitivity", 0.5)),
        opportunity_half_life_days=int(data.get("opportunity_half_life_days", 30)),
        evidence_quality=float(data.get("evidence_quality", 0.5)),
        stakeholder_impact=float(data.get("stakeholder_impact", 0.5)),
        compliance_sensitivity=float(data.get("compliance_sensitivity", 0.5)),
    )


def assessment_to_dict(assessment: PatienceAssessment) -> dict:
    return {
        "patience_score": assessment.patience_score,
        "mode": assessment.mode.value,
        "priority": assessment.priority.value,
        "review_cadence_days": assessment.review_cadence_days,
        "escalation_deadline_days": assessment.escalation_deadline_days,
        "rationale": assessment.rationale,
        "guardrails": assessment.guardrails,
        "next_actions": assessment.next_actions,
    }


# Recommendation builders

def build_reason(cell: MatrixCell, assessment: PatienceAssessment) -> str:
    reasons = []
    if cell.health == HealthStatus.BLOCKED:
        reasons.append("cell is blocked")
    elif cell.health == HealthStatus.RED:
        reasons.append("cell is in red status")
    elif cell.health == HealthStatus.YELLOW:
        reasons.append("cell is underperforming")
    if cell.blockers:
        reasons.append(f"{len(cell.blockers)} blocker(s) present")
    if cell.dependencies:
        reasons.append(f"{len(cell.dependencies)} unresolved dependency/dependencies")
    if cell.kpi and cell.kpi.progress_ratio() < 0.5:
        reasons.append(f"KPI '{cell.kpi.name}' is below 50% of target")
    if cell.confidence < 0.5:
        reasons.append("decision confidence is low")
    reasons.append(f"PATIENCE mode is {assessment.mode.value}")
    return "; ".join(reasons)


def build_recommendation(cell: MatrixCell, assessment: PatienceAssessment) -> str:
    if assessment.mode == PatienceMode.CONTAIN:
        return "Pause expansion and resolve governance conditions first: source trail, permission, owner approval, and risk treatment."
    if assessment.mode == PatienceMode.ESCALATE:
        target = cell.blockers[0] if cell.blockers else (cell.dependencies[0] if cell.dependencies else "highest-risk open item")
        return f"Escalate '{target}' to the accountable owner and make a go/no-go decision within {assessment.escalation_deadline_days} day(s)."
    if cell.blockers:
        return f"Resolve the highest-impact blocker first: '{cell.blockers[0]}'. Convert it into an owner/deadline/evidence task."
    if cell.dependencies:
        return f"Clarify dependency: '{cell.dependencies[0]}'. Assign a dependency owner and review in {assessment.review_cadence_days} day(s)."
    if assessment.mode == PatienceMode.PREPARE:
        return "Prepare the missing proof, policy, or relationship asset before increasing external exposure."
    if assessment.mode == PatienceMode.OBSERVE:
        return "Keep watch status and define the trigger that changes this from observe to proceed."
    return "Execute the next smallest irreversible step and update the decision log after completion."


def build_project_follow_through(project: Project, assessment: PatienceAssessment) -> str:
    if project.status == ProjectStatus.BLOCKED:
        return "Unblock before adding scope. Convert the top blocker into a named task with owner, deadline, and proof of completion."
    if assessment.mode == PatienceMode.CONTAIN:
        return "Hold expansion until governance evidence is documented. Then resume through the next milestone."
    if not project.next_action.strip():
        return "Define one concrete next action; do not leave the project as a concept."
    if assessment.mode == PatienceMode.ESCALATE:
        return f"Move now: {project.next_action} Deadline should be within {assessment.escalation_deadline_days} day(s)."
    if assessment.mode == PatienceMode.PREPARE:
        return f"Prepare the asset required for the next milestone: {project.next_milestone or project.next_action}"
    return project.next_action


def build_employment_next_step(item: EmploymentOpportunity, assessment: PatienceAssessment) -> str:
    if item.status == EmploymentStatus.OFFER:
        return "Evaluate offer terms, stability value, venture optionality, and legal obligations before accepting."
    if item.status == EmploymentStatus.INTERVIEWING:
        return "Prepare interview proof packet: one story, one metric, one portfolio artifact, and one role-specific question."
    if item.gaps:
        return f"Close the top application gap first: {item.gaps[0]}"
    if assessment.mode == PatienceMode.ESCALATE:
        return f"Apply or request referral within {assessment.escalation_deadline_days} day(s)."
    return item.next_action or "Create tailored resume bullet, proof artifact, and outreach message."


def build_investor_next_step(pool: InvestorPool, assessment: PatienceAssessment) -> str:
    if pool.status == InvestorStatus.COMMITTED:
        return "Move to closing checklist, use-of-funds discipline, and reporting cadence."
    if assessment.mode == PatienceMode.CONTAIN:
        return "Do not contact. Complete governance proof, risk note, and source trail first."
    if pool.evidence_required:
        return f"Build missing investor evidence first: {pool.evidence_required[0]}"
    if pool.warm_intro_path:
        return "Use warm intro path with a concise proof-led narrative."
    return pool.next_action or "Qualify investor thesis and identify warm introduction path before outreach."


def summarize_economic_signals(signals: List[EconomicSignal]) -> str:
    if not signals:
        return "No economic signals recorded yet. Add macro, capital-cost, labor-market, and AI-infrastructure signals."
    impact_areas = sorted({signal.impact_area for signal in signals})
    trends = sorted({signal.trend for signal in signals})
    return f"Tracking {len(signals)} signal(s) across {', '.join(impact_areas)}. Current trend labels: {', '.join(trends)}."


# Utilities

def priority_from_score(score: float) -> Priority:
    if score < 25:
        return Priority.CRITICAL
    if score < 45:
        return Priority.HIGH
    if score < 60:
        return Priority.MEDIUM
    return Priority.LOW


def max_priority(a: Priority, b: Priority) -> Priority:
    order = {Priority.LOW: 0, Priority.MEDIUM: 1, Priority.HIGH: 2, Priority.CRITICAL: 3}
    return a if order[a] >= order[b] else b


def validate_patience(profile: PatienceProfile) -> None:
    fields = patience_to_dict(profile)
    for name, value in fields.items():
        if name == "opportunity_half_life_days":
            if int(value) <= 0:
                raise ValueError("opportunity_half_life_days must be positive.")
        elif not 0.0 <= float(value) <= 1.0:
            raise ValueError(f"{name} must be between 0.0 and 1.0.")


def clean(value: str) -> str:
    return " ".join((value or "").strip().split())


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(float(value), maximum))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
