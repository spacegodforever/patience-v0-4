from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


from .experience_control import (
    ControlDomain,
    ControlStatus,
    CustomerExperienceInfluence,
    EnterpriseControl,
    ExperienceControlDB,
    ExperienceSignalType,
    InnovationRiskItem,
    InnovationRiskLevel,
    InnovationStatus,
    RiskPosture,
    customer_influence_to_dict,
    enterprise_control_to_dict,
    innovation_risk_to_dict,
)

from .risk_intelligence import (
    AlgorithmicConcernType,
    AlgorithmicIntegrationConcern,
    DependencyRisk,
    DependencyStatus,
    DependencyType,
    DevelopmentFailureScenario,
    EvidenceStatus,
    ExposureType,
    IntegrationStage,
    MarketArchitectureExposure,
    RiskIntelligenceDB,
    algorithmic_concern_to_dict,
    dependency_risk_to_dict,
    failure_scenario_to_dict,
    market_exposure_to_dict,
)
from .command_logic import build_command_board, build_evolution_readiness
from .ops_matrix_db import (
    DEFAULT_DB_PATH,
    EconomicSignal,
    EmploymentOpportunity,
    EmploymentStatus,
    GovernancePolicy,
    GovernanceSeverity,
    HealthStatus,
    InvestorPool,
    InvestorStatus,
    KPI,
    MatrixCell,
    OperationsMatrixDB,
    PatienceProfile,
    Project,
    ProjectStage,
    ProjectStatus,
    action_to_dict,
    assessment_to_dict,
    assess_patience,
    cell_to_dict,
    economic_signal_to_dict,
    employment_to_dict,
    governance_policy_to_dict,
    investor_pool_to_dict,
    project_to_dict,
)


from .gate import ADVISORY_NOTE, AdvisoryRoute, board_caller, lazy_db, require_seed_permission, server_source

router = APIRouter(prefix="/v1/board", tags=["command-board"], route_class=AdvisoryRoute,
                   dependencies=[Depends(board_caller)])
VERSION = "0.7.0-patience"

db = lazy_db(OperationsMatrixDB)
experience_db = lazy_db(ExperienceControlDB)
risk_db = lazy_db(RiskIntelligenceDB)


class HealthResponse(BaseModel):
    status: str
    database_path: str
    version: str


class CustomerExperienceInfluenceInput(BaseModel):
    segment: str = Field(..., min_length=1)
    touchpoint: str = Field(..., min_length=1)
    positive_outcome: str = Field(..., min_length=1)
    signal_type: ExperienceSignalType
    metric_name: str = Field(..., min_length=1)
    baseline_value: float = 0
    current_value: float = 0
    target_value: float = 1
    evidence_source: str = Field(..., min_length=1)
    owner: str = Field(..., min_length=1)
    confidence: float = Field(..., ge=0, le=1)
    customer_quotes: List[str] = Field(default_factory=list)
    linked_project: str = ""
    follow_up_action: str = ""
    friction_removed: str = ""
    notes: str = ""
    observed_at: Optional[str] = None


class EnterpriseControlInput(BaseModel):
    domain: ControlDomain
    control_name: str = Field(..., min_length=1)
    purpose: str = Field(..., min_length=1)
    owner: str = Field(..., min_length=1)
    status: ControlStatus
    risk_level: InnovationRiskLevel
    review_cadence_days: int = Field(30, ge=1)
    evidence_required: List[str] = Field(default_factory=list)
    last_reviewed_at: str = ""
    next_review_due: str = ""
    linked_policy: str = ""
    notes: str = ""


class InnovationRiskInput(BaseModel):
    name: str = Field(..., min_length=1)
    hypothesis: str = Field(..., min_length=1)
    opportunity: str = Field(..., min_length=1)
    risk: str = Field(..., min_length=1)
    owner: str = Field(..., min_length=1)
    risk_level: InnovationRiskLevel
    posture: RiskPosture
    upside_score: float = Field(..., ge=0, le=100)
    evidence_quality: float = Field(..., ge=0, le=1)
    control_link: str = ""
    next_experiment: str = ""
    kill_criteria: str = ""
    status: InnovationStatus = InnovationStatus.ACTIVE
    notes: str = ""


class KPIInput(BaseModel):
    name: str = Field(..., min_length=1)
    current_value: float = Field(..., ge=0)
    target_value: float = Field(..., ge=0)
    unit: str = ""


class PatienceInput(BaseModel):
    urgency: float = Field(0.5, ge=0, le=1)
    reversibility: float = Field(0.5, ge=0, le=1)
    volatility: float = Field(0.5, ge=0, le=1)
    runway_sensitivity: float = Field(0.5, ge=0, le=1)
    opportunity_half_life_days: int = Field(30, ge=1)
    evidence_quality: float = Field(0.5, ge=0, le=1)
    stakeholder_impact: float = Field(0.5, ge=0, le=1)
    compliance_sensitivity: float = Field(0.5, ge=0, le=1)


class MatrixCellInput(BaseModel):
    workstream: str = Field(..., min_length=1, examples=["Oracle Platform"])
    capability: str = Field(..., min_length=1, examples=["Data Governance"])
    objective: str = Field(..., min_length=1)
    owner: str = Field(..., min_length=1)
    health: HealthStatus
    confidence: float = Field(..., ge=0, le=1)
    kpi: Optional[KPIInput] = None
    blockers: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    notes: str = ""
    patience: PatienceInput = Field(default_factory=PatienceInput)


class ProjectInput(BaseModel):
    name: str = Field(..., min_length=1)
    category: str = Field(..., min_length=1)
    objective: str = Field(..., min_length=1)
    owner: str = Field(..., min_length=1)
    stage: ProjectStage
    status: ProjectStatus
    linked_workstream: str = ""
    linked_capability: str = ""
    north_star_metric: str = ""
    current_value: float = Field(0, ge=0)
    target_value: float = Field(1, ge=0)
    blockers: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    next_milestone: str = ""
    next_action: str = ""
    due_date: str = ""
    notes: str = ""
    patience: PatienceInput = Field(default_factory=PatienceInput)


class EmploymentInput(BaseModel):
    title: str = Field(..., min_length=1)
    organization: str = Field(..., min_length=1)
    role_family: str = Field(..., min_length=1)
    source: Optional[str] = Field(None, max_length=200)  # PATIENCE: ignored; the server sets source
    status: EmploymentStatus = EmploymentStatus.TARGET
    fit_score: float = Field(..., ge=0, le=100)
    salary_min: Optional[float] = Field(None, ge=0)
    salary_max: Optional[float] = Field(None, ge=0)
    remote_type: str = "unspecified"
    location: str = ""
    requirements: List[str] = Field(default_factory=list)
    gaps: List[str] = Field(default_factory=list)
    next_action: str = ""
    due_date: str = ""
    notes: str = ""
    patience: PatienceInput = Field(default_factory=PatienceInput)


class InvestorPoolInput(BaseModel):
    name: str = Field(..., min_length=1)
    investor_type: str = Field(..., min_length=1)
    thesis: str = Field(..., min_length=1)
    status: InvestorStatus = InvestorStatus.RESEARCH
    strategic_fit: float = Field(..., ge=0, le=100)
    capital_readiness_score: float = Field(..., ge=0, le=100)
    stage_fit: str = ""
    check_size_min: Optional[float] = Field(None, ge=0)
    check_size_max: Optional[float] = Field(None, ge=0)
    geography: str = ""
    relationship_owner: str = ""
    warm_intro_path: str = ""
    evidence_required: List[str] = Field(default_factory=list)
    next_action: str = ""
    notes: str = ""
    patience: PatienceInput = Field(default_factory=PatienceInput)


class GovernancePolicyInput(BaseModel):
    domain: str = Field(..., min_length=1)
    rule: str = Field(..., min_length=1)
    owner: str = Field(..., min_length=1)
    severity: GovernanceSeverity
    status: str = "active"
    review_cadence_days: int = Field(30, ge=1)
    evidence_required: List[str] = Field(default_factory=list)
    notes: str = ""


class EconomicSignalInput(BaseModel):
    name: str = Field(..., min_length=1)
    value: str = Field(..., min_length=1)
    trend: str = Field(..., min_length=1)
    confidence: float = Field(..., ge=0, le=1)
    source: Optional[str] = Field(None, max_length=200)  # PATIENCE: ignored; the server sets source
    impact_area: str = Field(..., min_length=1)
    observed_at: Optional[str] = None
    notes: str = ""


class AlgorithmicIntegrationConcernInput(BaseModel):
    system_component: str = Field(..., min_length=1)
    algorithm_or_model: str = Field(..., min_length=1)
    integration_stage: IntegrationStage
    concern_type: AlgorithmicConcernType
    severity: float = Field(..., ge=0, le=1)
    likelihood: float = Field(..., ge=0, le=1)
    detectability: float = Field(..., ge=0, le=1)
    customer_impact: float = Field(..., ge=0, le=1)
    control_owner: str = Field(..., min_length=1)
    evidence_status: EvidenceStatus
    dependency_links: List[str] = Field(default_factory=list)
    mitigation_plan: str = ""
    fallback_mode: str = ""
    model_assumptions: List[str] = Field(default_factory=list)
    data_sensitivity: str = "unspecified"
    notes: str = ""
    observed_at: Optional[str] = None


class DependencyRiskInput(BaseModel):
    dependency_name: str = Field(..., min_length=1)
    dependency_type: DependencyType
    owner: str = Field(..., min_length=1)
    status: DependencyStatus
    criticality: float = Field(..., ge=0, le=1)
    confidence: float = Field(..., ge=0, le=1)
    alternatives: List[str] = Field(default_factory=list)
    failure_mode: str = ""
    mitigation_plan: str = ""
    due_date: str = ""
    linked_component: str = ""
    notes: str = ""
    observed_at: Optional[str] = None


class MarketArchitectureExposureInput(BaseModel):
    operator_type: str = Field(..., min_length=1)
    market_vector: str = Field(..., min_length=1)
    exposure_type: ExposureType
    probability: float = Field(..., ge=0, le=1)
    impact: float = Field(..., ge=0, le=1)
    time_horizon_months: int = Field(..., ge=1)
    current_position: str = Field(..., min_length=1)
    governance_control: str = Field(..., min_length=1)
    infrastructure_investment_signal: str = Field(..., min_length=1)
    strategic_response: str = Field(..., min_length=1)
    source: Optional[str] = Field(None, max_length=200)  # PATIENCE: ignored; the server sets source
    notes: str = ""
    observed_at: Optional[str] = None


class DevelopmentFailureScenarioInput(BaseModel):
    phase: IntegrationStage
    failure_name: str = Field(..., min_length=1)
    trigger_condition: str = Field(..., min_length=1)
    consequence: str = Field(..., min_length=1)
    avoid_by: str = Field(..., min_length=1)
    owner: str = Field(..., min_length=1)
    probability: float = Field(..., ge=0, le=1)
    impact: float = Field(..., ge=0, le=1)
    detection_quality: float = Field(..., ge=0, le=1)
    leading_indicators: List[str] = Field(default_factory=list)
    linked_concerns: List[str] = Field(default_factory=list)
    notes: str = ""
    observed_at: Optional[str] = None


class SeedResponse(BaseModel):
    seeded: bool
    message: str


class DeleteResponse(BaseModel):
    deleted: bool
    workstream: str
    capability: str


def input_to_customer_influence(payload: CustomerExperienceInfluenceInput) -> CustomerExperienceInfluence:
    data = payload.model_dump()
    if not data.get("observed_at"):
        data.pop("observed_at", None)
    return CustomerExperienceInfluence(**data)


def input_to_enterprise_control(payload: EnterpriseControlInput) -> EnterpriseControl:
    return EnterpriseControl(**payload.model_dump())


def input_to_innovation_risk(payload: InnovationRiskInput) -> InnovationRiskItem:
    return InnovationRiskItem(**payload.model_dump())


def to_patience(payload: PatienceInput) -> PatienceProfile:
    return PatienceProfile(**payload.model_dump())


def input_to_cell(payload: MatrixCellInput) -> MatrixCell:
    kpi = KPI(**payload.kpi.model_dump()) if payload.kpi else None
    return MatrixCell(
        workstream=payload.workstream,
        capability=payload.capability,
        objective=payload.objective,
        owner=payload.owner,
        health=payload.health,
        confidence=payload.confidence,
        kpi=kpi,
        blockers=payload.blockers,
        dependencies=payload.dependencies,
        notes=payload.notes,
        patience=to_patience(payload.patience),
    )


def input_to_project(payload: ProjectInput) -> Project:
    return Project(**payload.model_dump(exclude={"patience"}), patience=to_patience(payload.patience))


def input_to_employment(payload: EmploymentInput) -> EmploymentOpportunity:
    return EmploymentOpportunity(**{**payload.model_dump(exclude={"patience"}), "source": server_source()}, patience=to_patience(payload.patience))


def input_to_investor_pool(payload: InvestorPoolInput) -> InvestorPool:
    return InvestorPool(**payload.model_dump(exclude={"patience"}), patience=to_patience(payload.patience))


def input_to_policy(payload: GovernancePolicyInput) -> GovernancePolicy:
    return GovernancePolicy(**payload.model_dump())


def input_to_signal(payload: EconomicSignalInput) -> EconomicSignal:
    data = {**payload.model_dump(), "source": server_source()}  # PATIENCE: source is server-set
    if not data.get("observed_at"):
        data.pop("observed_at", None)
    return EconomicSignal(**data)


def input_to_algorithmic_concern(payload: AlgorithmicIntegrationConcernInput) -> AlgorithmicIntegrationConcern:
    data = payload.model_dump()
    if not data.get("observed_at"):
        data.pop("observed_at", None)
    return AlgorithmicIntegrationConcern(**data)


def input_to_dependency_risk(payload: DependencyRiskInput) -> DependencyRisk:
    data = payload.model_dump()
    if not data.get("observed_at"):
        data.pop("observed_at", None)
    return DependencyRisk(**data)


def input_to_market_exposure(payload: MarketArchitectureExposureInput) -> MarketArchitectureExposure:
    data = {**payload.model_dump(), "source": server_source()}  # PATIENCE: source is server-set
    if not data.get("observed_at"):
        data.pop("observed_at", None)
    return MarketArchitectureExposure(**data)


def input_to_failure_scenario(payload: DevelopmentFailureScenarioInput) -> DevelopmentFailureScenario:
    data = payload.model_dump()
    if not data.get("observed_at"):
        data.pop("observed_at", None)
    return DevelopmentFailureScenario(**data)


@router.get("/", tags=["system"])
def root() -> dict:
    return {
        "service": "Oracle + PATIENCE Operations Matrix API",
        "version": VERSION,
        "advisory": ADVISORY_NOTE,
        "docs": "/docs",
        "health": "/health",
        "core_concept": "Oracle interprets; PATIENCE governs timing, consent, audit, and grounded action.",
    }


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse(status="ok", database_path=str(db.path()), version=VERSION)


@router.post("/patience/evaluate", tags=["patience"])
def patience_evaluate(
    payload: PatienceInput,
    operational_score: float = Query(50.0, ge=0, le=100),
    context_label: str = Query("manual assessment"),
) -> dict:
    return assessment_to_dict(assess_patience(to_patience(payload), operational_score=operational_score, context_label=context_label))


@router.post("/cells", status_code=status.HTTP_201_CREATED, tags=["cells"])
def upsert_cell(payload: MatrixCellInput) -> dict:
    try:
        return cell_to_dict(db.upsert_cell(input_to_cell(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/cells", tags=["cells"])
def list_cells() -> list[dict]:
    return [cell_to_dict(cell) for cell in db.list_cells()]


@router.get("/cells/by-key", tags=["cells"])
def get_cell(workstream: str = Query(..., min_length=1), capability: str = Query(..., min_length=1)) -> dict:
    try:
        return cell_to_dict(db.get_cell(workstream, capability))
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.delete("/cells", response_model=DeleteResponse, tags=["cells"])
def delete_cell(workstream: str = Query(..., min_length=1), capability: str = Query(..., min_length=1)) -> DeleteResponse:
    deleted = db.delete_cell(workstream, capability)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"No matrix cell found for {workstream} × {capability}")
    return DeleteResponse(deleted=True, workstream=workstream, capability=capability)


@router.get("/cells/struggling", tags=["analysis"])
def struggling_cells(threshold: float = Query(60.0, ge=0, le=100)) -> list[dict]:
    return [cell_to_dict(cell) for cell in db.struggling_cells(threshold=threshold)]


@router.get("/recovery-actions", tags=["analysis"])
def recovery_actions(threshold: float = Query(60.0, ge=0, le=100)) -> list[dict]:
    return [action_to_dict(action) for action in db.generate_recovery_actions(threshold=threshold)]


@router.get("/scores/workstream", tags=["scores"])
def workstream_score(name: str = Query(..., min_length=1)) -> dict:
    try:
        return {"name": name, "score": db.workstream_score(name)}
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/scores/capability", tags=["scores"])
def capability_score(name: str = Query(..., min_length=1)) -> dict:
    try:
        return {"name": name, "score": db.capability_score(name)}
    except KeyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/history", tags=["history"])
def score_history(workstream: str = Query(..., min_length=1), capability: str = Query(..., min_length=1)) -> dict:
    history = db.score_history(workstream, capability)
    if not history:
        raise HTTPException(status_code=404, detail=f"No score history found for {workstream} × {capability}")
    return {"workstream": workstream, "capability": capability, "history": history}


@router.post("/projects", status_code=status.HTTP_201_CREATED, tags=["projects"])
def upsert_project(payload: ProjectInput) -> dict:
    try:
        return project_to_dict(db.upsert_project(input_to_project(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/projects", tags=["projects"])
def list_projects(include_complete: bool = Query(True)) -> list[dict]:
    return [project_to_dict(project) for project in db.list_projects(include_complete=include_complete)]


@router.get("/projects/follow-through", tags=["projects"])
def project_follow_through() -> list[dict]:
    return db.project_follow_through()


@router.post("/employment", status_code=status.HTTP_201_CREATED, tags=["employment"])
def upsert_employment(payload: EmploymentInput) -> dict:
    try:
        return employment_to_dict(db.upsert_employment(input_to_employment(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/employment", tags=["employment"])
def list_employment(active_only: bool = Query(True)) -> list[dict]:
    return [employment_to_dict(item) for item in db.list_employment(active_only=active_only)]


@router.get("/employment/path", tags=["employment"])
def employment_path() -> list[dict]:
    return db.employment_path()


@router.post("/investor-pools", status_code=status.HTTP_201_CREATED, tags=["investors"])
def upsert_investor_pool(payload: InvestorPoolInput) -> dict:
    try:
        return investor_pool_to_dict(db.upsert_investor_pool(input_to_investor_pool(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/investor-pools", tags=["investors"])
def list_investor_pools() -> list[dict]:
    return [investor_pool_to_dict(pool) for pool in db.list_investor_pools()]


@router.get("/investor-pools/qualified", tags=["investors"])
def qualified_investor_pools(threshold: float = Query(65.0, ge=0, le=100)) -> list[dict]:
    return db.qualified_investor_pools(threshold=threshold)


@router.post("/governance/policies", status_code=status.HTTP_201_CREATED, tags=["governance"])
def upsert_governance_policy(payload: GovernancePolicyInput) -> dict:
    try:
        return governance_policy_to_dict(db.upsert_governance_policy(input_to_policy(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/governance/policies", tags=["governance"])
def list_governance_policies() -> list[dict]:
    return [governance_policy_to_dict(policy) for policy in db.list_governance_policies()]


@router.get("/governance/status", tags=["governance"])
def governance_status() -> dict:
    return db.governance_status()


@router.post("/economic-signals", status_code=status.HTTP_201_CREATED, tags=["economic"])
def upsert_economic_signal(payload: EconomicSignalInput) -> dict:
    try:
        return economic_signal_to_dict(db.upsert_economic_signal(input_to_signal(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/economic-signals", tags=["economic"])
def list_economic_signals(impact_area: str = Query("")) -> list[dict]:
    return [economic_signal_to_dict(signal) for signal in db.list_economic_signals(impact_area=impact_area)]


@router.get("/trajectory", tags=["economic"])
def economic_trajectory() -> dict:
    return db.economic_trajectory()


@router.get("/snapshot", tags=["exports"])
def snapshot() -> dict:
    payload = db.export_snapshot()
    payload["customer_control"] = experience_db.customer_control_snapshot()
    payload["risk_intelligence"] = risk_db.risk_control_snapshot()
    return payload


@router.post("/seed", response_model=SeedResponse, tags=["system"])
def seed_demo_data(_: dict = Depends(require_seed_permission)) -> SeedResponse:
    db.seed_demo_data()
    experience_db.seed_demo_data()
    risk_db.seed_demo_data()
    return SeedResponse(seeded=True, message="Demo operations, projects, employment path, investor pools, governance, economic signals, customer experience, controls, innovation risks, algorithmic concerns, dependency risks, market exposures, and failure scenarios inserted or updated.")


@router.post("/customer-experience/influences", status_code=status.HTTP_201_CREATED, tags=["customer-experience"])
def add_customer_experience_influence(payload: CustomerExperienceInfluenceInput) -> dict:
    try:
        return customer_influence_to_dict(experience_db.add_customer_influence(input_to_customer_influence(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/customer-experience/influences", tags=["customer-experience"])
def list_customer_experience_influences(segment: str = Query(""), touchpoint: str = Query("")) -> list[dict]:
    return [
        customer_influence_to_dict(item)
        for item in experience_db.list_customer_influences(segment=segment, touchpoint=touchpoint)
    ]


@router.get("/customer-experience/positive-impact", tags=["customer-experience"])
def positive_customer_impact() -> dict:
    return experience_db.positive_customer_impact()


@router.post("/enterprise-controls", status_code=status.HTTP_201_CREATED, tags=["enterprise-control"])
def upsert_enterprise_control(payload: EnterpriseControlInput) -> dict:
    try:
        return enterprise_control_to_dict(experience_db.upsert_enterprise_control(input_to_enterprise_control(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/enterprise-controls", tags=["enterprise-control"])
def list_enterprise_controls(domain: str = Query("")) -> list[dict]:
    return [enterprise_control_to_dict(control) for control in experience_db.list_enterprise_controls(domain=domain)]


@router.get("/enterprise-controls/status", tags=["enterprise-control"])
def enterprise_control_status() -> dict:
    return experience_db.enterprise_control_status()


@router.post("/innovation-risks", status_code=status.HTTP_201_CREATED, tags=["innovation-risk"])
def upsert_innovation_risk(payload: InnovationRiskInput) -> dict:
    try:
        return innovation_risk_to_dict(experience_db.upsert_innovation_risk(input_to_innovation_risk(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/innovation-risks", tags=["innovation-risk"])
def list_innovation_risks(active_only: bool = Query(True)) -> list[dict]:
    return [innovation_risk_to_dict(item) for item in experience_db.list_innovation_risks(active_only=active_only)]


@router.get("/innovation-risks/portfolio", tags=["innovation-risk"])
def innovation_risk_portfolio() -> dict:
    return experience_db.innovation_risk_portfolio()


@router.get("/command/customer-control", tags=["command"])
def customer_control_command() -> dict:
    return experience_db.customer_control_snapshot()


@router.get("/command/act-now", tags=["command"])
def command_act_now() -> dict:
    """Return the command board for immediate execution.

    Lanes:
    - contain: governance or trust issue blocks expansion
    - act_now: time-sensitive or reversible action with enough evidence
    - prepare: build proof, policy, relationship, or asset
    - watch: monitor economic/context signal and keep cadence
    """
    return build_command_board(db, experience_db, risk_db)


@router.get("/command/evolution-readiness", tags=["command"])
def command_evolution_readiness() -> dict:
    """Return the current readiness score and the next gate for scale."""
    return build_evolution_readiness(db, experience_db)


@router.post("/algorithmic-integration/concerns", status_code=status.HTTP_201_CREATED, tags=["risk-intelligence"])
def upsert_algorithmic_integration_concern(payload: AlgorithmicIntegrationConcernInput) -> dict:
    try:
        return algorithmic_concern_to_dict(risk_db.upsert_algorithmic_concern(input_to_algorithmic_concern(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/algorithmic-integration/concerns", tags=["risk-intelligence"])
def list_algorithmic_integration_concerns(lane: str = Query("")) -> list[dict]:
    return [algorithmic_concern_to_dict(item) for item in risk_db.list_algorithmic_concerns(lane=lane)]


@router.post("/dependency-risks", status_code=status.HTTP_201_CREATED, tags=["risk-intelligence"])
def upsert_dependency_risk(payload: DependencyRiskInput) -> dict:
    try:
        return dependency_risk_to_dict(risk_db.upsert_dependency_risk(input_to_dependency_risk(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/dependency-risks", tags=["risk-intelligence"])
def list_dependency_risks(lane: str = Query("")) -> list[dict]:
    return [dependency_risk_to_dict(item) for item in risk_db.list_dependency_risks(lane=lane)]


@router.post("/market-architecture/exposures", status_code=status.HTTP_201_CREATED, tags=["risk-intelligence"])
def upsert_market_architecture_exposure(payload: MarketArchitectureExposureInput) -> dict:
    try:
        return market_exposure_to_dict(risk_db.upsert_market_exposure(input_to_market_exposure(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/market-architecture/exposures", tags=["risk-intelligence"])
def list_market_architecture_exposures(lane: str = Query("")) -> list[dict]:
    return [market_exposure_to_dict(item) for item in risk_db.list_market_exposures(lane=lane)]


@router.post("/failure-scenarios", status_code=status.HTTP_201_CREATED, tags=["risk-intelligence"])
def upsert_failure_scenario(payload: DevelopmentFailureScenarioInput) -> dict:
    try:
        return failure_scenario_to_dict(risk_db.upsert_failure_scenario(input_to_failure_scenario(payload)))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/failure-scenarios", tags=["risk-intelligence"])
def list_failure_scenarios(lane: str = Query("")) -> list[dict]:
    return [failure_scenario_to_dict(item) for item in risk_db.list_failure_scenarios(lane=lane)]


@router.get("/command/risk-ground-truth", tags=["command"])
def risk_ground_truth() -> dict:
    return risk_db.risk_control_snapshot()
