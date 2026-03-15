"""
Dashboard summary endpoint for real-time GRC status overview.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.deps import get_db
from api.routers.auth import get_current_user
from db.models import (
    AssessmentResultRecord,
    AssessmentRun,
    DataSource,
    EvidenceRecord,
    PolicyViolation,
    User,
    VendorRecord,
)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


class FrameworkStatus(BaseModel):
    framework: str
    display_name: str
    total_controls: int
    passing: int
    medium: int
    critical: int
    pass_rate: float
    last_run: str | None


class IntegrationStatus(BaseModel):
    id: str
    name: str
    provider: str
    source_type: str
    is_active: bool
    last_sync_at: str | None
    last_sync_status: str


class DashboardSummary(BaseModel):
    total_controls: int
    passing: int
    medium: int
    critical: int
    overall_pass_rate: float
    total_evidence: int
    open_violations: int
    vendor_count: int
    high_risk_vendors: int
    frameworks: list[FrameworkStatus]
    integrations: list[IntegrationStatus]
    recent_activity: list[dict]
    last_updated: str


FRAMEWORK_DISPLAY = {
    "nist_800_53": "NIST SP 800-53",
    "soc2": "SOC 2 Type II",
    "iso27001": "ISO 27001",
    "hipaa": "HIPAA",
    "cmmc_l2": "CMMC Level 2",
    "pci_dss": "PCI DSS",
}


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    # Get latest assessment run per framework
    frameworks_status = []
    total_passing = 0
    total_medium = 0
    total_critical = 0
    total_controls = 0

    for framework_key, display_name in FRAMEWORK_DISPLAY.items():
        latest_run = (
            db.query(AssessmentRun)
            .filter(AssessmentRun.framework == framework_key, AssessmentRun.status == "completed")
            .order_by(AssessmentRun.started_at.desc())
            .first()
        )

        if latest_run:
            results = db.query(AssessmentResultRecord).filter(
                AssessmentResultRecord.run_id == latest_run.id
            ).all()

            passing = sum(1 for r in results if r.status == "pass")
            critical = sum(1 for r in results if r.status == "fail" and r.severity in ("critical", "high"))
            medium = sum(1 for r in results if r.status == "fail" and r.severity == "medium")
            total = len(results)

            total_passing += passing
            total_critical += critical
            total_medium += medium
            total_controls += total

            pass_rate = round((passing / total * 100) if total > 0 else 0, 1)
        else:
            passing = critical = medium = total = 0
            pass_rate = 0.0

        frameworks_status.append(FrameworkStatus(
            framework=framework_key,
            display_name=display_name,
            total_controls=total,
            passing=passing,
            medium=medium,
            critical=critical,
            pass_rate=pass_rate,
            last_run=latest_run.started_at.isoformat() if latest_run else None,
        ))

    overall_pass_rate = round((total_passing / total_controls * 100) if total_controls > 0 else 0, 1)

    # Evidence count
    evidence_count = db.query(func.count(EvidenceRecord.id)).scalar() or 0

    # Open violations
    open_violations = (
        db.query(func.count(PolicyViolation.id))
        .filter(PolicyViolation.status == "open")
        .scalar() or 0
    )

    # Vendor stats
    vendor_count = db.query(func.count(VendorRecord.id)).filter(VendorRecord.is_active.is_(True)).scalar() or 0
    high_risk_vendors = (
        db.query(func.count(VendorRecord.id))
        .filter(VendorRecord.risk_level.in_(["High", "Critical"]), VendorRecord.is_active.is_(True))
        .scalar() or 0
    )

    # Integrations
    integrations = db.query(DataSource).order_by(DataSource.created_at.desc()).limit(20).all()
    integration_list = [
        IntegrationStatus(
            id=i.id,
            name=i.name,
            provider=i.provider,
            source_type=i.source_type,
            is_active=i.is_active,
            last_sync_at=i.last_sync_at.isoformat() if i.last_sync_at else None,
            last_sync_status=i.last_sync_status,
        )
        for i in integrations
    ]

    # Recent activity (last 10 assessment runs)
    recent_runs = (
        db.query(AssessmentRun)
        .order_by(AssessmentRun.started_at.desc())
        .limit(10)
        .all()
    )
    recent_activity = [
        {
            "type": "assessment",
            "framework": r.framework,
            "display_name": FRAMEWORK_DISPLAY.get(r.framework, r.framework),
            "status": r.status,
            "pass_rate": r.pass_rate,
            "timestamp": r.started_at.isoformat(),
        }
        for r in recent_runs
    ]

    return DashboardSummary(
        total_controls=total_controls,
        passing=total_passing,
        medium=total_medium,
        critical=total_critical,
        overall_pass_rate=overall_pass_rate,
        total_evidence=evidence_count,
        open_violations=open_violations,
        vendor_count=vendor_count,
        high_risk_vendors=high_risk_vendors,
        frameworks=frameworks_status,
        integrations=integration_list,
        recent_activity=recent_activity,
        last_updated=datetime.now(UTC).isoformat(),
    )
