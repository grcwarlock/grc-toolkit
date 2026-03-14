"""
Repository pattern for GRC data access.

Each repository provides static methods for CRUD operations on a
specific domain entity. All methods accept an explicit Session so
callers control transaction boundaries.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import (
    AssessmentResultRecord,
    AssessmentRun,
    EvidenceRecord,
    PolicyViolation,
    VendorRecord,
)


class EvidenceRepository:

    @staticmethod
    def save_evidence(
        session: Session,
        evidence_id: str,
        run_id: str,
        control_id: str,
        check_id: str,
        provider: str,
        service: str,
        resource_type: str,
        region: str,
        account_id: str,
        collected_at: datetime,
        data: dict,
        normalized_data: dict,
        status: str,
        sha256_hash: str,
        error_message: str = "",
        metadata: dict | None = None,
    ) -> str:
        record = EvidenceRecord(
            id=evidence_id,
            run_id=run_id,
            control_id=control_id,
            check_id=check_id,
            provider=provider,
            service=service,
            resource_type=resource_type,
            region=region,
            account_id=account_id,
            collected_at=collected_at,
            data=data,
            normalized_data=normalized_data,
            status=status,
            sha256_hash=sha256_hash,
            error_message=error_message or None,
            metadata_=metadata or {},
        )
        session.add(record)
        session.flush()
        return record.id

    @staticmethod
    def get_evidence(session: Session, evidence_id: str) -> EvidenceRecord | None:
        return session.get(EvidenceRecord, evidence_id)

    @staticmethod
    def list_evidence(
        session: Session,
        run_id: str | None = None,
        control_id: str | None = None,
        provider: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceRecord]:
        stmt = select(EvidenceRecord)
        if run_id:
            stmt = stmt.where(EvidenceRecord.run_id == run_id)
        if control_id:
            stmt = stmt.where(EvidenceRecord.control_id == control_id)
        if provider:
            stmt = stmt.where(EvidenceRecord.provider == provider)
        stmt = stmt.order_by(EvidenceRecord.collected_at.desc()).offset(offset).limit(limit)
        return list(session.scalars(stmt))

    @staticmethod
    def get_evidence_by_run(session: Session, run_id: str) -> list[EvidenceRecord]:
        stmt = (
            select(EvidenceRecord)
            .where(EvidenceRecord.run_id == run_id)
            .order_by(EvidenceRecord.control_id)
        )
        return list(session.scalars(stmt))

    @staticmethod
    def count_evidence(
        session: Session,
        run_id: str | None = None,
        control_id: str | None = None,
        provider: str | None = None,
    ) -> int:
        stmt = select(func.count(EvidenceRecord.id))
        if run_id:
            stmt = stmt.where(EvidenceRecord.run_id == run_id)
        if control_id:
            stmt = stmt.where(EvidenceRecord.control_id == control_id)
        if provider:
            stmt = stmt.where(EvidenceRecord.provider == provider)
        return session.scalar(stmt) or 0


class AssessmentRepository:

    @staticmethod
    def create_run(
        session: Session,
        framework: str,
        triggered_by: str = "manual",
    ) -> AssessmentRun:
        run = AssessmentRun(
            id=str(uuid.uuid4()),
            framework=framework,
            started_at=datetime.now(UTC),
            status="running",
            triggered_by=triggered_by,
        )
        session.add(run)
        session.flush()
        return run

    @staticmethod
    def complete_run(
        session: Session,
        run_id: str,
        total_checks: int,
        passed: int,
        failed: int,
        errors: int,
        summary: dict | None = None,
    ) -> AssessmentRun:
        run = session.get(AssessmentRun, run_id)
        if run is None:
            raise ValueError(f"Assessment run {run_id} not found")
        run.completed_at = datetime.now(UTC)
        run.status = "completed"
        run.total_checks = total_checks
        run.passed = passed
        run.failed = failed
        run.errors = errors
        run.pass_rate = (passed / total_checks * 100) if total_checks > 0 else 0.0
        run.summary = summary
        session.flush()
        return run

    @staticmethod
    def save_result(
        session: Session,
        result_id: str,
        run_id: str,
        control_id: str,
        check_id: str,
        assertion: str,
        status: str,
        severity: str,
        provider: str,
        region: str,
        findings: list[str],
        evidence_ids: list[str],
        evidence_summary: str = "",
        remediation: str | None = None,
        remediation_steps: list[str] | None = None,
        console_path: str | None = None,
        assessed_at: datetime | None = None,
        assessor: str = "python",
        policy_id: str | None = None,
    ) -> str:
        record = AssessmentResultRecord(
            id=result_id,
            run_id=run_id,
            control_id=control_id,
            check_id=check_id,
            assertion=assertion,
            status=status,
            severity=severity,
            provider=provider,
            region=region,
            findings=findings,
            evidence_ids=evidence_ids,
            evidence_summary=evidence_summary,
            remediation=remediation,
            remediation_steps=remediation_steps or [],
            console_path=console_path,
            assessed_at=assessed_at or datetime.now(UTC),
            assessor=assessor,
            policy_id=policy_id,
        )
        session.add(record)
        session.flush()
        return record.id

    @staticmethod
    def get_run(session: Session, run_id: str) -> AssessmentRun | None:
        return session.get(AssessmentRun, run_id)

    @staticmethod
    def list_runs(
        session: Session,
        framework: str | None = None,
        limit: int = 20,
    ) -> list[AssessmentRun]:
        stmt = select(AssessmentRun)
        if framework:
            stmt = stmt.where(AssessmentRun.framework == framework)
        stmt = stmt.order_by(AssessmentRun.started_at.desc()).limit(limit)
        return list(session.scalars(stmt))

    @staticmethod
    def get_results(session: Session, run_id: str) -> list[AssessmentResultRecord]:
        stmt = (
            select(AssessmentResultRecord)
            .where(AssessmentResultRecord.run_id == run_id)
            .order_by(AssessmentResultRecord.control_id)
        )
        return list(session.scalars(stmt))

    @staticmethod
    def get_trend(
        session: Session,
        framework: str,
        last_n: int = 10,
    ) -> list[dict]:
        stmt = (
            select(AssessmentRun)
            .where(AssessmentRun.framework == framework)
            .where(AssessmentRun.status == "completed")
            .order_by(AssessmentRun.completed_at.desc())
            .limit(last_n)
        )
        runs = list(session.scalars(stmt))
        return [
            {
                "run_id": r.id,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "pass_rate": r.pass_rate,
                "total_checks": r.total_checks,
                "passed": r.passed,
                "failed": r.failed,
            }
            for r in reversed(runs)
        ]


class VendorRepository:

    @staticmethod
    def create_vendor(session: Session, **kwargs) -> VendorRecord:
        vendor = VendorRecord(id=str(uuid.uuid4()), **kwargs)
        session.add(vendor)
        session.flush()
        return vendor

    # Fields that are safe to update via the API — prevents mass assignment
    _UPDATABLE_FIELDS = frozenset({
        "name", "category", "criticality", "data_classification",
        "contract_end", "certifications", "risk_score", "risk_level",
        "last_assessment_date", "notes",
    })

    @staticmethod
    def update_vendor(
        session: Session, vendor_id: str, updates: dict
    ) -> VendorRecord:
        vendor = session.get(VendorRecord, vendor_id)
        if vendor is None:
            raise ValueError(f"Vendor {vendor_id} not found")
        for key, value in updates.items():
            if key in VendorRepository._UPDATABLE_FIELDS:
                setattr(vendor, key, value)
        session.flush()
        return vendor

    @staticmethod
    def get_vendor(session: Session, vendor_id: str) -> VendorRecord | None:
        return session.get(VendorRecord, vendor_id)

    @staticmethod
    def list_vendors(
        session: Session, active_only: bool = True
    ) -> list[VendorRecord]:
        stmt = select(VendorRecord)
        if active_only:
            stmt = stmt.where(VendorRecord.is_active == True)  # noqa: E712
        stmt = stmt.order_by(VendorRecord.name)
        return list(session.scalars(stmt))

    @staticmethod
    def get_vendors_needing_assessment(session: Session) -> list[VendorRecord]:
        now = datetime.now(UTC).date()
        cutoff = now - timedelta(days=30)
        stmt = (
            select(VendorRecord)
            .where(VendorRecord.is_active == True)  # noqa: E712
            .where(
                (VendorRecord.last_assessment_date == None)  # noqa: E711
                | (VendorRecord.last_assessment_date <= cutoff)
            )
        )
        return list(session.scalars(stmt))


class PolicyViolationRepository:

    @staticmethod
    def save_violation(session: Session, **kwargs) -> str:
        violation = PolicyViolation(id=str(uuid.uuid4()), **kwargs)
        session.add(violation)
        session.flush()
        return violation.id

    @staticmethod
    def list_violations(
        session: Session,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[PolicyViolation]:
        stmt = select(PolicyViolation)
        if status:
            stmt = stmt.where(PolicyViolation.status == status)
        if severity:
            stmt = stmt.where(PolicyViolation.severity == severity)
        stmt = stmt.order_by(PolicyViolation.detected_at.desc()).limit(limit)
        return list(session.scalars(stmt))

    @staticmethod
    def resolve_violation(session: Session, violation_id: str) -> PolicyViolation:
        violation = session.get(PolicyViolation, violation_id)
        if violation is None:
            raise ValueError(f"Violation {violation_id} not found")
        violation.status = "resolved"
        violation.resolved_at = datetime.now(UTC)
        session.flush()
        return violation
