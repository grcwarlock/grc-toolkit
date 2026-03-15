"""
Pydantic v2 request/response models for the GRC Toolkit API.
"""

from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, Field

# ── Evidence ──────────────────────────────────────────────────────────

class CollectionRequest(BaseModel):
    framework: str = Field("nist_800_53", description="Framework identifier")
    control_family: str | None = Field(None, description="Filter to a single control family")
    providers: list[str] = Field(["aws"], description="Cloud providers to collect from")
    regions: list[str] | None = Field(None, description="Override provider regions")


class CollectionResponse(BaseModel):
    run_id: str
    status: str
    artifacts_collected: int
    started_at: datetime


class EvidenceResponse(BaseModel):
    id: str
    control_id: str
    check_id: str
    provider: str
    service: str
    resource_type: str
    region: str
    account_id: str
    collected_at: datetime
    status: str
    sha256_hash: str
    normalized_data: dict


class EvidenceListResponse(BaseModel):
    items: list[EvidenceResponse]
    total: int
    page: int
    page_size: int


class EvidenceVerifyResponse(BaseModel):
    evidence_id: str
    integrity_valid: bool
    stored_hash: str
    computed_hash: str


# ── Assessments ───────────────────────────────────────────────────────

class AssessmentTriggerRequest(BaseModel):
    framework: str = Field("nist_800_53")
    evidence_run_id: str | None = Field(None, description="Use evidence from a specific run")
    providers: list[str] | None = Field(None)


class AssessmentRunResponse(BaseModel):
    id: str
    framework: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    pass_rate: float | None = None
    summary: dict | None = None


class AssessmentResultResponse(BaseModel):
    id: str
    control_id: str
    check_id: str
    assertion: str
    status: str
    severity: str
    provider: str
    region: str
    findings: list[str]
    remediation: str | None = None
    remediation_steps: list[str] = []
    console_path: str | None = None
    assessed_at: datetime


class AssessmentTrendResponse(BaseModel):
    runs: list[dict]


# ── Risk ──────────────────────────────────────────────────────────────

class ThreatScenarioRequest(BaseModel):
    name: str
    description: str = ""
    category: str = ""
    frequency_min: float
    frequency_mode: float
    frequency_max: float
    impact_min: float
    impact_mode: float
    impact_max: float
    control_effectiveness: float = 0.0


class SimulationResponse(BaseModel):
    scenario_name: str
    iterations: int
    mean_ale: float
    median_ale: float
    var_90: float
    var_95: float
    var_99: float
    max_observed: float


class PortfolioRequest(BaseModel):
    scenarios: list[ThreatScenarioRequest]
    iterations: int = Field(10_000, ge=100, le=100_000)
    seed: int | None = None


class PortfolioResponse(BaseModel):
    scenarios: list[dict]
    aggregate: dict
    scenario_ranking: list[dict]


class TreatmentRequest(BaseModel):
    name: str
    effectiveness: float = Field(ge=0.0, le=1.0)
    annual_cost: float = Field(ge=0)


class TreatmentComparisonRequest(BaseModel):
    scenario: ThreatScenarioRequest
    treatments: list[TreatmentRequest]
    iterations: int = 10_000


class TreatmentComparisonResponse(BaseModel):
    treatments: list[dict]


# ── Frameworks ────────────────────────────────────────────────────────

class FrameworkResponse(BaseModel):
    id: str
    name: str
    display_name: str
    version: str
    control_count: int
    is_active: bool


class FrameworkDetailResponse(FrameworkResponse):
    description: str | None = None
    control_families: dict = {}


class CrosswalkRequest(BaseModel):
    source_framework: str
    control_id: str
    target_framework: str


class CrosswalkResponse(BaseModel):
    source_framework: str
    source_control: str
    target_controls: list[dict]


# ── Vendors ───────────────────────────────────────────────────────────

class VendorCreate(BaseModel):
    name: str
    category: str
    criticality: str
    data_classification: str
    contract_start: date
    contract_end: date
    certifications: list[str] = []
    sla_uptime_target: float = 99.9
    assessment_frequency_days: int = 365
    primary_contact: str | None = None
    notes: str | None = None


class VendorUpdate(BaseModel):
    name: str | None = None
    category: str | None = None
    criticality: str | None = None
    data_classification: str | None = None
    contract_end: date | None = None
    certifications: list[str] | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    last_assessment_date: date | None = None
    notes: str | None = None


class VendorResponse(BaseModel):
    id: str
    name: str
    category: str
    criticality: str
    data_classification: str
    contract_start: date
    contract_end: date
    last_assessment_date: date | None = None
    certifications: list[str] = []
    risk_score: float | None = None
    risk_level: str | None = None
    is_active: bool = True


class VendorDashboardResponse(BaseModel):
    total_vendors: int
    risk_distribution: dict
    vendors_needing_assessment: int
    expiring_contracts_90d: int
    vendor_scores: list[dict]


# ── Policies ──────────────────────────────────────────────────────────

class PolicyEvalRequest(BaseModel):
    provider: str
    resource_type: str
    resource_data: dict
    policy_package: str = Field("nist", description="OPA package to evaluate against")


class PolicyEvalResponse(BaseModel):
    compliant: bool
    violations: list[dict]
    policy_package: str


class PolicyViolationResponse(BaseModel):
    id: str
    policy_id: str
    policy_name: str
    resource_id: str
    resource_type: str
    provider: str
    severity: str
    status: str
    detected_at: datetime
    violation_detail: str


# ── Exports ──────────────────────────────────────────────────────────

class ExportMetadata(BaseModel):
    source_framework: str
    target_framework: str
    mapping_applied: bool
    generated_at: datetime
    assessment_run_id: str


class MappedControlResponse(BaseModel):
    source_framework: str
    source_control_id: str
    target_framework: str
    target_control_id: str
    confidence: str
    notes: str = ""
    via: list[str] = []


class FrameworkMappingResponse(BaseModel):
    source_framework: str
    target_framework: str
    mappings: list[MappedControlResponse]
    available_frameworks: list[str]


# ── Continuous Monitoring ────────────────────────────────────────────

class MonitoringScheduleCreate(BaseModel):
    name: str
    framework: str
    cadence: str = Field("daily", description="hourly, daily, weekly")
    providers: list[str] = ["aws"]
    alert_on_drift: bool = True
    alert_channels: list[str] = []


class MonitoringScheduleUpdate(BaseModel):
    name: str | None = None
    cadence: str | None = None
    providers: list[str] | None = None
    is_active: bool | None = None
    alert_on_drift: bool | None = None
    alert_channels: list[str] | None = None


class MonitoringScheduleResponse(BaseModel):
    id: str
    name: str
    framework: str
    cadence: str
    providers: list[str]
    is_active: bool
    last_run_at: datetime | None = None
    last_run_id: str | None = None
    last_pass_rate: float | None = None
    drift_detected: bool = False
    drift_details: dict | None = None
    alert_on_drift: bool
    alert_channels: list[str]
    created_at: datetime | None = None


class DriftAlertResponse(BaseModel):
    schedule_id: str
    framework: str
    drift_detected: bool
    previous_pass_rate: float | None
    current_pass_rate: float | None
    degraded_controls: list[dict]
    new_failures: list[dict]
    timestamp: datetime


# ── Security Questionnaires ──────────────────────────────────────────

class QuestionnaireCreate(BaseModel):
    title: str
    requester: str
    requester_email: str = ""
    questionnaire_type: str = Field("Custom", description="SIG, CAIQ, DDQ, Custom")
    due_date: date | None = None
    questions: list[dict] = []
    assigned_to: str | None = None
    notes: str | None = None


class QuestionnaireUpdate(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    due_date: date | None = None
    questions: list[dict] | None = None
    notes: str | None = None


class QuestionnaireResponse(BaseModel):
    id: str
    title: str
    requester: str
    requester_email: str
    questionnaire_type: str
    status: str
    due_date: date | None = None
    total_questions: int
    answered_questions: int
    auto_answered: int
    assigned_to: str | None = None
    notes: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class QuestionnaireDetailResponse(QuestionnaireResponse):
    questions: list[dict] = []


class AutoAnswerResponse(BaseModel):
    questionnaire_id: str
    total_questions: int
    auto_answered: int
    confidence_scores: list[dict]


# ── Task Assignments / Workflow ──────────────────────────────────────

class TaskCreate(BaseModel):
    title: str
    description: str = ""
    task_type: str = Field("remediation", description="remediation, review, evidence, approval, vendor_assessment")
    reference_type: str | None = None
    reference_id: str | None = None
    assigned_to: str
    priority: str = "medium"
    due_date: date | None = None


class TaskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    assigned_to: str | None = None
    priority: str | None = None
    status: str | None = None
    due_date: date | None = None


class TaskResponse(BaseModel):
    id: str
    title: str
    description: str
    task_type: str
    reference_type: str | None = None
    reference_id: str | None = None
    assigned_to: str
    assigned_by: str
    priority: str
    status: str
    due_date: date | None = None
    completed_at: datetime | None = None
    comments: list[dict] = []
    created_at: datetime | None = None


class TaskCommentCreate(BaseModel):
    author: str
    content: str


# ── Personnel & Training ────────────────────────────────────────────

class PersonnelCreate(BaseModel):
    full_name: str
    email: str
    department: str = ""
    role: str = ""
    title: str = ""
    manager: str | None = None
    start_date: date | None = None


class PersonnelUpdate(BaseModel):
    full_name: str | None = None
    department: str | None = None
    role: str | None = None
    title: str | None = None
    manager: str | None = None
    is_active: bool | None = None
    termination_date: date | None = None
    background_check_date: date | None = None
    background_check_status: str | None = None
    last_access_review: date | None = None
    access_review_status: str | None = None
    system_access: list[dict] | None = None
    notes: str | None = None


class PersonnelResponse(BaseModel):
    id: str
    full_name: str
    email: str
    department: str
    role: str
    title: str
    manager: str | None = None
    start_date: date | None = None
    termination_date: date | None = None
    is_active: bool
    background_check_date: date | None = None
    background_check_status: str
    last_access_review: date | None = None
    access_review_status: str
    training_records: list[dict] = []
    system_access: list[dict] = []
    control_mappings: list[str] = []
    created_at: datetime | None = None


class TrainingRecordCreate(BaseModel):
    training_name: str
    training_type: str = "security_awareness"  # security_awareness, role_specific, compliance, incident_response
    completed_date: date
    expiry_date: date | None = None
    score: float | None = None


class PersonnelDashboardResponse(BaseModel):
    total_personnel: int
    active_count: int
    training_compliance_rate: float
    overdue_access_reviews: int
    pending_background_checks: int
    department_breakdown: dict
    training_by_type: dict


# ── Audit Collaboration ─────────────────────────────────────────────

class AuditCommentCreate(BaseModel):
    audit_id: str
    resource_type: str
    resource_id: str
    author: str
    author_role: str = "auditor"
    comment_type: str = "comment"
    content: str


class AuditCommentResponse(BaseModel):
    id: str
    audit_id: str
    resource_type: str
    resource_id: str
    author: str
    author_role: str
    comment_type: str
    content: str
    is_resolved: bool
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    created_at: datetime | None = None


class AuditEngagementResponse(BaseModel):
    audit_id: str
    total_comments: int
    open_requests: int
    resolved_requests: int
    findings_count: int
    recent_activity: list[dict]


# ── SSP Generation ──────────────────────────────────────────────────

class SSPGenerateRequest(BaseModel):
    framework: str = "nist_800_53"
    system_name: str = "GRC Toolkit Platform"
    system_description: str = ""
    security_categorization: str = "Moderate"
    authorization_boundary: str = ""
    include_controls: list[str] | None = None
    format: str = "json"  # json, oscal


class SSPResponse(BaseModel):
    system_name: str
    framework: str
    security_categorization: str
    generated_at: datetime
    total_controls: int
    implemented_controls: int
    implementation_rate: float
    control_narratives: list[dict]


# ── OSCAL Export ────────────────────────────────────────────────────

class OSCALExportRequest(BaseModel):
    framework: str = "nist_800_53"
    document_type: str = "ssp"  # ssp, poam, assessment_results
    assessment_run_id: str | None = None
    format: str = "json"  # json, xml


class OSCALExportResponse(BaseModel):
    document_type: str
    framework: str
    format: str
    generated_at: datetime
    oscal_version: str = "1.1.2"
    document: dict


# ── Risk Graph ──────────────────────────────────────────────────────

class RiskGraphResponse(BaseModel):
    nodes: list[dict]
    edges: list[dict]
    clusters: list[dict]
    summary: dict
