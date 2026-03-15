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
    AuditComment,
    EvidenceRecord,
    MonitoringSchedule,
    PersonnelRecord,
    PolicyViolation,
    QuestionnaireRecord,
    TaskAssignment,
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


class MonitoringRepository:

    @staticmethod
    def create_schedule(session: Session, **kwargs) -> MonitoringSchedule:
        schedule = MonitoringSchedule(id=str(uuid.uuid4()), **kwargs)
        session.add(schedule)
        session.flush()
        return schedule

    @staticmethod
    def list_schedules(session: Session, active_only: bool = True) -> list[MonitoringSchedule]:
        stmt = select(MonitoringSchedule)
        if active_only:
            stmt = stmt.where(MonitoringSchedule.is_active == True)  # noqa: E712
        stmt = stmt.order_by(MonitoringSchedule.created_at.desc())
        return list(session.scalars(stmt))

    @staticmethod
    def get_schedule(session: Session, schedule_id: str) -> MonitoringSchedule | None:
        return session.get(MonitoringSchedule, schedule_id)

    @staticmethod
    def update_schedule(session: Session, schedule_id: str, updates: dict) -> MonitoringSchedule:
        schedule = session.get(MonitoringSchedule, schedule_id)
        if schedule is None:
            raise ValueError(f"Schedule {schedule_id} not found")
        allowed = {"name", "cadence", "providers", "is_active", "alert_on_drift",
                    "alert_channels", "last_run_at", "last_run_id", "last_pass_rate",
                    "drift_detected", "drift_details"}
        for key, value in updates.items():
            if key in allowed:
                setattr(schedule, key, value)
        session.flush()
        return schedule

    @staticmethod
    def get_due_schedules(session: Session) -> list[MonitoringSchedule]:
        now = datetime.now(UTC)
        stmt = (
            select(MonitoringSchedule)
            .where(MonitoringSchedule.is_active == True)  # noqa: E712
        )
        schedules = list(session.scalars(stmt))
        due = []
        cadence_minutes = {"hourly": 60, "daily": 1440, "weekly": 10080}
        for s in schedules:
            if s.last_run_at is None:
                due.append(s)
            else:
                interval = cadence_minutes.get(s.cadence, 1440)
                if (now - s.last_run_at).total_seconds() >= interval * 60:
                    due.append(s)
        return due


class QuestionnaireRepository:

    @staticmethod
    def create(session: Session, **kwargs) -> QuestionnaireRecord:
        q = QuestionnaireRecord(id=str(uuid.uuid4()), **kwargs)
        q.total_questions = len(q.questions) if q.questions else 0
        session.add(q)
        session.flush()
        return q

    @staticmethod
    def list_questionnaires(
        session: Session, status: str | None = None, limit: int = 50
    ) -> list[QuestionnaireRecord]:
        stmt = select(QuestionnaireRecord)
        if status:
            stmt = stmt.where(QuestionnaireRecord.status == status)
        stmt = stmt.order_by(QuestionnaireRecord.created_at.desc()).limit(limit)
        return list(session.scalars(stmt))

    @staticmethod
    def get(session: Session, qid: str) -> QuestionnaireRecord | None:
        return session.get(QuestionnaireRecord, qid)

    @staticmethod
    def update(session: Session, qid: str, updates: dict) -> QuestionnaireRecord:
        q = session.get(QuestionnaireRecord, qid)
        if q is None:
            raise ValueError(f"Questionnaire {qid} not found")
        allowed = {"status", "assigned_to", "due_date", "questions", "notes",
                    "answered_questions", "auto_answered", "total_questions"}
        for key, value in updates.items():
            if key in allowed:
                setattr(q, key, value)
        session.flush()
        return q


class TaskRepository:

    @staticmethod
    def create(session: Session, **kwargs) -> TaskAssignment:
        task = TaskAssignment(id=str(uuid.uuid4()), **kwargs)
        session.add(task)
        session.flush()
        return task

    @staticmethod
    def list_tasks(
        session: Session,
        assigned_to: str | None = None,
        status: str | None = None,
        task_type: str | None = None,
        limit: int = 100,
    ) -> list[TaskAssignment]:
        stmt = select(TaskAssignment)
        if assigned_to:
            stmt = stmt.where(TaskAssignment.assigned_to == assigned_to)
        if status:
            stmt = stmt.where(TaskAssignment.status == status)
        if task_type:
            stmt = stmt.where(TaskAssignment.task_type == task_type)
        stmt = stmt.order_by(TaskAssignment.created_at.desc()).limit(limit)
        return list(session.scalars(stmt))

    @staticmethod
    def get(session: Session, task_id: str) -> TaskAssignment | None:
        return session.get(TaskAssignment, task_id)

    @staticmethod
    def update(session: Session, task_id: str, updates: dict) -> TaskAssignment:
        task = session.get(TaskAssignment, task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        allowed = {"title", "description", "assigned_to", "priority", "status", "due_date", "comments"}
        for key, value in updates.items():
            if key in allowed:
                setattr(task, key, value)
        if updates.get("status") == "completed":
            task.completed_at = datetime.now(UTC)
        session.flush()
        return task

    @staticmethod
    def get_dashboard(session: Session) -> dict:
        all_tasks = list(session.scalars(select(TaskAssignment)))
        by_status = {"open": 0, "in_progress": 0, "review": 0, "completed": 0, "deferred": 0}
        by_priority = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        overdue = 0
        today = datetime.now(UTC).date()
        for t in all_tasks:
            by_status[t.status] = by_status.get(t.status, 0) + 1
            by_priority[t.priority] = by_priority.get(t.priority, 0) + 1
            if t.due_date and t.due_date < today and t.status not in ("completed", "deferred"):
                overdue += 1
        return {
            "total": len(all_tasks),
            "by_status": by_status,
            "by_priority": by_priority,
            "overdue": overdue,
        }


class PersonnelRepository:

    @staticmethod
    def create(session: Session, **kwargs) -> PersonnelRecord:
        person = PersonnelRecord(id=str(uuid.uuid4()), **kwargs)
        session.add(person)
        session.flush()
        return person

    @staticmethod
    def list_personnel(
        session: Session, active_only: bool = True, department: str | None = None
    ) -> list[PersonnelRecord]:
        stmt = select(PersonnelRecord)
        if active_only:
            stmt = stmt.where(PersonnelRecord.is_active == True)  # noqa: E712
        if department:
            stmt = stmt.where(PersonnelRecord.department == department)
        stmt = stmt.order_by(PersonnelRecord.full_name)
        return list(session.scalars(stmt))

    @staticmethod
    def get(session: Session, pid: str) -> PersonnelRecord | None:
        return session.get(PersonnelRecord, pid)

    @staticmethod
    def update(session: Session, pid: str, updates: dict) -> PersonnelRecord:
        person = session.get(PersonnelRecord, pid)
        if person is None:
            raise ValueError(f"Personnel {pid} not found")
        allowed = {"full_name", "department", "role", "title", "manager", "is_active",
                    "termination_date", "background_check_date", "background_check_status",
                    "last_access_review", "access_review_status", "training_records",
                    "system_access", "control_mappings", "notes"}
        for key, value in updates.items():
            if key in allowed:
                setattr(person, key, value)
        session.flush()
        return person

    @staticmethod
    def get_dashboard(session: Session) -> dict:
        personnel = list(session.scalars(
            select(PersonnelRecord).where(PersonnelRecord.is_active == True)  # noqa: E712
        ))
        total = len(personnel)
        today = datetime.now(UTC).date()
        overdue_reviews = sum(
            1 for p in personnel
            if p.last_access_review and (today - p.last_access_review).days > 90
        )
        pending_bg = sum(1 for p in personnel if p.background_check_status == "pending")
        training_compliant = sum(1 for p in personnel if p.training_records)
        depts: dict[str, int] = {}
        for p in personnel:
            depts[p.department or "Unassigned"] = depts.get(p.department or "Unassigned", 0) + 1
        return {
            "total_personnel": total,
            "active_count": total,
            "training_compliance_rate": (training_compliant / total * 100) if total else 0,
            "overdue_access_reviews": overdue_reviews,
            "pending_background_checks": pending_bg,
            "department_breakdown": depts,
            "training_by_type": {},
        }


class AuditCommentRepository:

    @staticmethod
    def create(session: Session, **kwargs) -> AuditComment:
        comment = AuditComment(id=str(uuid.uuid4()), **kwargs)
        session.add(comment)
        session.flush()
        return comment

    @staticmethod
    def list_by_resource(
        session: Session, resource_type: str, resource_id: str
    ) -> list[AuditComment]:
        stmt = (
            select(AuditComment)
            .where(AuditComment.resource_type == resource_type)
            .where(AuditComment.resource_id == resource_id)
            .order_by(AuditComment.created_at.desc())
        )
        return list(session.scalars(stmt))

    @staticmethod
    def list_by_audit(session: Session, audit_id: str) -> list[AuditComment]:
        stmt = (
            select(AuditComment)
            .where(AuditComment.audit_id == audit_id)
            .order_by(AuditComment.created_at.desc())
        )
        return list(session.scalars(stmt))

    @staticmethod
    def resolve(session: Session, comment_id: str, resolved_by: str) -> AuditComment:
        comment = session.get(AuditComment, comment_id)
        if comment is None:
            raise ValueError(f"Comment {comment_id} not found")
        comment.is_resolved = True
        comment.resolved_by = resolved_by
        comment.resolved_at = datetime.now(UTC)
        session.flush()
        return comment

    @staticmethod
    def get_engagement_summary(session: Session, audit_id: str) -> dict:
        comments = list(session.scalars(
            select(AuditComment).where(AuditComment.audit_id == audit_id)
        ))
        requests = [c for c in comments if c.comment_type == "request"]
        findings = [c for c in comments if c.comment_type == "finding"]
        return {
            "audit_id": audit_id,
            "total_comments": len(comments),
            "open_requests": sum(1 for r in requests if not r.is_resolved),
            "resolved_requests": sum(1 for r in requests if r.is_resolved),
            "findings_count": len(findings),
            "recent_activity": [
                {
                    "id": c.id,
                    "author": c.author,
                    "comment_type": c.comment_type,
                    "content": c.content[:100],
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "is_resolved": c.is_resolved,
                }
                for c in comments[:10]
            ],
        }
