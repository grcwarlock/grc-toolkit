"""
Pydantic v2 request/response models for the GRC Toolkit API.
"""

from __future__ import annotations

from datetime import datetime, date
from typing import Optional

from pydantic import BaseModel, Field


# ── Evidence ──────────────────────────────────────────────────────────

class CollectionRequest(BaseModel):
    framework: str = Field("nist_800_53", description="Framework identifier")
    control_family: Optional[str] = Field(None, description="Filter to a single control family")
    providers: list[str] = Field(["aws"], description="Cloud providers to collect from")
    regions: Optional[list[str]] = Field(None, description="Override provider regions")


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
    evidence_run_id: Optional[str] = Field(None, description="Use evidence from a specific run")
    providers: Optional[list[str]] = Field(None)


class AssessmentRunResponse(BaseModel):
    id: str
    framework: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    pass_rate: Optional[float] = None
    summary: Optional[dict] = None


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
    remediation: Optional[str] = None
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
    seed: Optional[int] = None


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
    description: Optional[str] = None
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
    primary_contact: Optional[str] = None
    notes: Optional[str] = None


class VendorUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    criticality: Optional[str] = None
    data_classification: Optional[str] = None
    contract_end: Optional[date] = None
    certifications: Optional[list[str]] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    last_assessment_date: Optional[date] = None
    notes: Optional[str] = None


class VendorResponse(BaseModel):
    id: str
    name: str
    category: str
    criticality: str
    data_classification: str
    contract_start: date
    contract_end: date
    last_assessment_date: Optional[date] = None
    certifications: list[str] = []
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
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
