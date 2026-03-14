"""
Comprehensive tests for the db package: session, models, and repository layers.

Uses in-memory SQLite for isolation and speed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

import db.session as db_session_module
from db.models import (
    AssessmentResultRecord,
    AssessmentRun,
    AssetRecord,
    AuditLog,
    Base,
    DataSource,
    EvidenceRecord,
    FrameworkDefinition,
    PolicyViolation,
    VendorRecord,
)
from db.repository import (
    AssessmentRepository,
    EvidenceRepository,
    PolicyViolationRepository,
    VendorRepository,
)
from db.session import get_db_session, get_engine, get_session_factory, init_db

DB_URL = "sqlite://"


@pytest.fixture(autouse=True)
def _reset_db():
    """Reset the global engine/session_factory before each test, create tables."""
    db_session_module._engine = None
    db_session_module._session_factory = None
    init_db(DB_URL)
    yield
    db_session_module._engine = None
    db_session_module._session_factory = None


@pytest.fixture()
def session():
    """Yield a Session for direct use in tests, then roll back."""
    with get_db_session() as s:
        yield s


# ---------------------------------------------------------------------------
# 1. Session tests
# ---------------------------------------------------------------------------


class TestSession:
    def test_init_db_creates_tables(self):
        get_engine(DB_URL)
        inspector_names = Base.metadata.tables.keys()
        assert "audit_log" in inspector_names
        assert "evidence" in inspector_names
        assert "assessment_runs" in inspector_names
        assert "vendors" in inspector_names

    def test_get_engine_returns_engine(self):
        engine = get_engine(DB_URL)
        assert isinstance(engine, Engine)

    def test_get_engine_caches(self):
        e1 = get_engine(DB_URL)
        e2 = get_engine()  # should return cached
        assert e1 is e2

    def test_get_session_factory_returns_sessionmaker(self):
        factory = get_session_factory()
        assert isinstance(factory, sessionmaker)

    def test_get_session_factory_caches(self):
        f1 = get_session_factory()
        f2 = get_session_factory()
        assert f1 is f2

    def test_get_db_session_yields_session(self):
        with get_db_session(DB_URL) as s:
            assert isinstance(s, Session)

    def test_get_db_session_commits_on_success(self):
        uid = str(uuid.uuid4())
        with get_db_session() as s:
            s.add(AuditLog(
                id=uid,
                actor="test",
                action="create",
                resource_type="widget",
                resource_id="w1",
            ))
        # Read back in a new session
        with get_db_session() as s:
            obj = s.get(AuditLog, uid)
            assert obj is not None
            assert obj.actor == "test"

    def test_get_db_session_rolls_back_on_error(self):
        uid = str(uuid.uuid4())
        with pytest.raises(RuntimeError):
            with get_db_session() as s:
                s.add(AuditLog(
                    id=uid,
                    actor="test",
                    action="create",
                    resource_type="widget",
                    resource_id="w1",
                ))
                raise RuntimeError("boom")
        with get_db_session() as s:
            obj = s.get(AuditLog, uid)
            assert obj is None


# ---------------------------------------------------------------------------
# 2. Model tests
# ---------------------------------------------------------------------------


class TestModels:
    def test_audit_log_roundtrip(self, session: Session):
        uid = str(uuid.uuid4())
        changes = {"field": "value"}
        session.add(AuditLog(
            id=uid,
            actor="admin",
            action="update",
            resource_type="policy",
            resource_id="p1",
            changes=changes,
            client_ip="127.0.0.1",
            request_id=str(uuid.uuid4()),
        ))
        session.flush()
        obj = session.get(AuditLog, uid)
        assert obj is not None
        assert obj.actor == "admin"
        assert obj.changes == changes

    def test_asset_record_json_fields(self, session: Session):
        uid = str(uuid.uuid4())
        tags = {"env": "prod", "team": "security"}
        meta = {"source": "scanner"}
        session.add(AssetRecord(
            id=uid,
            provider="aws",
            account_id="123456789012",
            resource_id="i-abc123",
            resource_type="ec2:instance",
            region="us-east-1",
            name="web-server",
            tags=tags,
            metadata_=meta,
        ))
        session.flush()
        obj = session.get(AssetRecord, uid)
        assert obj.tags == tags
        assert obj.metadata_ == meta
        assert obj.is_active is True

    def test_data_source_roundtrip(self, session: Session):
        uid = str(uuid.uuid4())
        config = {"bucket": "logs"}
        session.add(DataSource(
            id=uid,
            name="aws-prod",
            source_type="cloud",
            provider="aws",
            config=config,
        ))
        session.flush()
        obj = session.get(DataSource, uid)
        assert obj.name == "aws-prod"
        assert obj.config == config
        assert obj.sync_interval_minutes == 60

    def test_evidence_record_roundtrip(self, session: Session):
        run = AssessmentRun(
            id=str(uuid.uuid4()),
            framework="SOC2",
            started_at=datetime.now(UTC),
        )
        session.add(run)
        session.flush()

        uid = str(uuid.uuid4())
        data = {"finding": "open port"}
        session.add(EvidenceRecord(
            id=uid,
            control_id="CC6.1",
            check_id="check-1",
            provider="aws",
            service="ec2",
            region="us-east-1",
            account_id="123",
            collected_at=datetime.now(UTC),
            data=data,
            run_id=run.id,
        ))
        session.flush()
        obj = session.get(EvidenceRecord, uid)
        assert obj.data == data
        assert obj.run_id == run.id

    def test_assessment_run_results_relationship(self, session: Session):
        run = AssessmentRun(
            id=str(uuid.uuid4()),
            framework="SOC2",
            started_at=datetime.now(UTC),
        )
        session.add(run)
        session.flush()

        result = AssessmentResultRecord(
            id=str(uuid.uuid4()),
            run_id=run.id,
            control_id="CC6.1",
            check_id="check-1",
            assertion="port closed",
            status="pass",
            severity="high",
            provider="aws",
            region="us-east-1",
            assessed_at=datetime.now(UTC),
            findings=["all good"],
            evidence_ids=["e1", "e2"],
        )
        session.add(result)
        session.flush()

        assert len(run.results) == 1
        assert run.results[0].control_id == "CC6.1"
        assert result.run is run

    def test_framework_definition_self_fk(self, session: Session):
        parent_id = str(uuid.uuid4())
        child_id = str(uuid.uuid4())
        session.add(FrameworkDefinition(
            id=parent_id, name="nist-csf", display_name="NIST CSF",
            version="1.1", definition={"controls": []},
        ))
        session.flush()
        session.add(FrameworkDefinition(
            id=child_id, name="nist-csf-custom", display_name="Custom NIST",
            version="1.0", inherits_from=parent_id, definition={},
        ))
        session.flush()
        child = session.get(FrameworkDefinition, child_id)
        assert child.inherits_from == parent_id

    def test_vendor_record_roundtrip(self, session: Session):
        uid = str(uuid.uuid4())
        certs = ["SOC2", "ISO27001"]
        session.add(VendorRecord(
            id=uid,
            name="Acme Corp",
            category="SaaS",
            criticality="High",
            data_classification="Confidential",
            contract_start=date(2024, 1, 1),
            contract_end=date(2025, 12, 31),
            certifications=certs,
        ))
        session.flush()
        obj = session.get(VendorRecord, uid)
        assert obj.certifications == certs
        assert obj.is_active is True

    def test_policy_violation_roundtrip(self, session: Session):
        uid = str(uuid.uuid4())
        now = datetime.now(UTC)
        session.add(PolicyViolation(
            id=uid,
            policy_id="pol-1",
            policy_name="Encryption Required",
            resource_id="bucket-123",
            resource_type="s3:bucket",
            provider="aws",
            region="us-east-1",
            violation_detail="Bucket not encrypted",
            severity="high",
            detected_at=now,
        ))
        session.flush()
        obj = session.get(PolicyViolation, uid)
        assert obj.status == "open"
        assert obj.resolved_at is None


# ---------------------------------------------------------------------------
# 3. EvidenceRepository tests
# ---------------------------------------------------------------------------


def _make_run(session: Session, framework: str = "SOC2") -> AssessmentRun:
    """Helper to create an AssessmentRun for FK constraints."""
    run = AssessmentRun(
        id=str(uuid.uuid4()),
        framework=framework,
        started_at=datetime.now(UTC),
    )
    session.add(run)
    session.flush()
    return run


class TestEvidenceRepository:
    def test_save_and_get_evidence(self, session: Session):
        run = _make_run(session)
        eid = str(uuid.uuid4())
        now = datetime.now(UTC)
        returned_id = EvidenceRepository.save_evidence(
            session,
            evidence_id=eid,
            run_id=run.id,
            control_id="CC6.1",
            check_id="check-1",
            provider="aws",
            service="ec2",
            resource_type="instance",
            region="us-east-1",
            account_id="123",
            collected_at=now,
            data={"key": "val"},
            normalized_data={"norm": True},
            status="collected",
            sha256_hash="abc123",
        )
        assert returned_id == eid
        obj = EvidenceRepository.get_evidence(session, eid)
        assert obj is not None
        assert obj.provider == "aws"
        assert obj.data == {"key": "val"}

    def test_list_evidence_filter_by_provider(self, session: Session):
        run = _make_run(session)
        now = datetime.now(UTC)
        for provider in ["aws", "aws", "azure"]:
            EvidenceRepository.save_evidence(
                session,
                evidence_id=str(uuid.uuid4()),
                run_id=run.id,
                control_id="CC6.1",
                check_id="check-1",
                provider=provider,
                service="svc",
                resource_type="rt",
                region="us-east-1",
                account_id="123",
                collected_at=now,
                data={},
                normalized_data={},
                status="collected",
                sha256_hash="h",
            )
        results = EvidenceRepository.list_evidence(session, provider="aws")
        assert len(results) == 2

    def test_list_evidence_filter_by_control_id(self, session: Session):
        run = _make_run(session)
        now = datetime.now(UTC)
        for ctrl in ["CC6.1", "CC6.1", "CC7.2"]:
            EvidenceRepository.save_evidence(
                session,
                evidence_id=str(uuid.uuid4()),
                run_id=run.id,
                control_id=ctrl,
                check_id="check-1",
                provider="aws",
                service="svc",
                resource_type="rt",
                region="us-east-1",
                account_id="123",
                collected_at=now,
                data={},
                normalized_data={},
                status="collected",
                sha256_hash="h",
            )
        results = EvidenceRepository.list_evidence(session, control_id="CC7.2")
        assert len(results) == 1

    def test_count_evidence(self, session: Session):
        run = _make_run(session)
        now = datetime.now(UTC)
        for _ in range(3):
            EvidenceRepository.save_evidence(
                session,
                evidence_id=str(uuid.uuid4()),
                run_id=run.id,
                control_id="CC6.1",
                check_id="check-1",
                provider="aws",
                service="svc",
                resource_type="rt",
                region="us-east-1",
                account_id="123",
                collected_at=now,
                data={},
                normalized_data={},
                status="collected",
                sha256_hash="h",
            )
        assert EvidenceRepository.count_evidence(session) == 3
        assert EvidenceRepository.count_evidence(session, run_id=run.id) == 3
        assert EvidenceRepository.count_evidence(session, provider="azure") == 0

    def test_get_evidence_by_run(self, session: Session):
        run1 = _make_run(session)
        run2 = _make_run(session)
        now = datetime.now(UTC)
        for run in [run1, run1, run2]:
            EvidenceRepository.save_evidence(
                session,
                evidence_id=str(uuid.uuid4()),
                run_id=run.id,
                control_id="CC6.1",
                check_id="check-1",
                provider="aws",
                service="svc",
                resource_type="rt",
                region="us-east-1",
                account_id="123",
                collected_at=now,
                data={},
                normalized_data={},
                status="collected",
                sha256_hash="h",
            )
        results = EvidenceRepository.get_evidence_by_run(session, run1.id)
        assert len(results) == 2

    def test_get_evidence_not_found(self, session: Session):
        result = EvidenceRepository.get_evidence(session, "nonexistent")
        assert result is None

    def test_save_evidence_with_metadata(self, session: Session):
        run = _make_run(session)
        eid = str(uuid.uuid4())
        meta = {"scanner": "prowler", "version": "3.0"}
        EvidenceRepository.save_evidence(
            session,
            evidence_id=eid,
            run_id=run.id,
            control_id="CC6.1",
            check_id="check-1",
            provider="aws",
            service="ec2",
            resource_type="instance",
            region="us-east-1",
            account_id="123",
            collected_at=datetime.now(UTC),
            data={},
            normalized_data={},
            status="collected",
            sha256_hash="abc",
            metadata=meta,
        )
        obj = EvidenceRepository.get_evidence(session, eid)
        assert obj.metadata_ == meta


# ---------------------------------------------------------------------------
# 4. AssessmentRepository tests
# ---------------------------------------------------------------------------


class TestAssessmentRepository:
    def test_create_run_and_get_run(self, session: Session):
        run = AssessmentRepository.create_run(session, framework="SOC2")
        assert run.framework == "SOC2"
        assert run.status == "running"
        assert run.id is not None

        fetched = AssessmentRepository.get_run(session, run.id)
        assert fetched is not None
        assert fetched.id == run.id

    def test_complete_run(self, session: Session):
        run = AssessmentRepository.create_run(session, framework="SOC2")
        summary = {"notes": "all good"}
        completed = AssessmentRepository.complete_run(
            session,
            run_id=run.id,
            total_checks=10,
            passed=8,
            failed=1,
            errors=1,
            summary=summary,
        )
        assert completed.status == "completed"
        assert completed.completed_at is not None
        assert completed.total_checks == 10
        assert completed.passed == 8
        assert completed.failed == 1
        assert completed.errors == 1
        assert completed.pass_rate == 80.0
        assert completed.summary == summary

    def test_complete_run_not_found(self, session: Session):
        with pytest.raises(ValueError, match="not found"):
            AssessmentRepository.complete_run(
                session, run_id="nonexistent",
                total_checks=0, passed=0, failed=0, errors=0,
            )

    def test_complete_run_zero_checks(self, session: Session):
        run = AssessmentRepository.create_run(session, framework="SOC2")
        completed = AssessmentRepository.complete_run(
            session, run_id=run.id,
            total_checks=0, passed=0, failed=0, errors=0,
        )
        assert completed.pass_rate == 0.0

    def test_save_result_and_get_results(self, session: Session):
        run = AssessmentRepository.create_run(session, framework="SOC2")
        rid = str(uuid.uuid4())
        returned_id = AssessmentRepository.save_result(
            session,
            result_id=rid,
            run_id=run.id,
            control_id="CC6.1",
            check_id="check-1",
            assertion="port closed",
            status="pass",
            severity="high",
            provider="aws",
            region="us-east-1",
            findings=["finding1"],
            evidence_ids=["e1"],
            evidence_summary="summary",
            remediation="close port",
        )
        assert returned_id == rid
        results = AssessmentRepository.get_results(session, run.id)
        assert len(results) == 1
        assert results[0].assertion == "port closed"
        assert results[0].findings == ["finding1"]

    def test_list_runs_all(self, session: Session):
        AssessmentRepository.create_run(session, framework="SOC2")
        AssessmentRepository.create_run(session, framework="NIST")
        runs = AssessmentRepository.list_runs(session)
        assert len(runs) == 2

    def test_list_runs_with_framework_filter(self, session: Session):
        AssessmentRepository.create_run(session, framework="SOC2")
        AssessmentRepository.create_run(session, framework="NIST")
        AssessmentRepository.create_run(session, framework="SOC2")
        runs = AssessmentRepository.list_runs(session, framework="SOC2")
        assert len(runs) == 2

    def test_get_trend(self, session: Session):
        # Create 3 runs, complete 2
        r1 = AssessmentRepository.create_run(session, framework="SOC2")
        AssessmentRepository.complete_run(
            session, r1.id, total_checks=10, passed=7, failed=2, errors=1,
        )
        r2 = AssessmentRepository.create_run(session, framework="SOC2")
        AssessmentRepository.complete_run(
            session, r2.id, total_checks=10, passed=9, failed=1, errors=0,
        )
        # This one stays running -- should not appear in trend
        AssessmentRepository.create_run(session, framework="SOC2")

        trend = AssessmentRepository.get_trend(session, framework="SOC2")
        assert len(trend) == 2
        # Trend is returned in chronological order (reversed from desc query)
        assert trend[0]["pass_rate"] == 70.0
        assert trend[1]["pass_rate"] == 90.0
        assert "run_id" in trend[0]
        assert "completed_at" in trend[0]

    def test_get_trend_different_framework(self, session: Session):
        r = AssessmentRepository.create_run(session, framework="NIST")
        AssessmentRepository.complete_run(
            session, r.id, total_checks=5, passed=5, failed=0, errors=0,
        )
        trend = AssessmentRepository.get_trend(session, framework="SOC2")
        assert len(trend) == 0

    def test_get_run_not_found(self, session: Session):
        assert AssessmentRepository.get_run(session, "nonexistent") is None

    def test_create_run_triggered_by(self, session: Session):
        run = AssessmentRepository.create_run(
            session, framework="SOC2", triggered_by="api",
        )
        assert run.triggered_by == "api"


# ---------------------------------------------------------------------------
# 5. VendorRepository tests
# ---------------------------------------------------------------------------


def _vendor_kwargs(**overrides):
    """Default kwargs for creating a vendor."""
    defaults = {
        "name": "Acme Corp",
        "category": "SaaS",
        "criticality": "High",
        "data_classification": "Confidential",
        "contract_start": date(2024, 1, 1),
        "contract_end": date(2025, 12, 31),
    }
    defaults.update(overrides)
    return defaults


class TestVendorRepository:
    def test_create_and_get_vendor(self, session: Session):
        vendor = VendorRepository.create_vendor(session, **_vendor_kwargs())
        assert vendor.id is not None
        assert vendor.name == "Acme Corp"

        fetched = VendorRepository.get_vendor(session, vendor.id)
        assert fetched is not None
        assert fetched.name == "Acme Corp"

    def test_update_vendor_allowed_fields(self, session: Session):
        vendor = VendorRepository.create_vendor(session, **_vendor_kwargs())
        updated = VendorRepository.update_vendor(
            session, vendor.id, {"name": "New Name", "risk_score": 7.5},
        )
        assert updated.name == "New Name"
        assert updated.risk_score == 7.5

    def test_update_vendor_rejects_disallowed_fields(self, session: Session):
        vendor = VendorRepository.create_vendor(session, **_vendor_kwargs())
        original_id = vendor.id
        # 'id' and 'contract_start' are not in _UPDATABLE_FIELDS
        VendorRepository.update_vendor(
            session, vendor.id, {"id": "hacked", "contract_start": date(2000, 1, 1)},
        )
        fetched = VendorRepository.get_vendor(session, original_id)
        assert fetched is not None
        assert fetched.id == original_id
        assert fetched.contract_start == date(2024, 1, 1)

    def test_update_vendor_not_found(self, session: Session):
        with pytest.raises(ValueError, match="not found"):
            VendorRepository.update_vendor(session, "nonexistent", {"name": "x"})

    def test_list_vendors_active_only(self, session: Session):
        VendorRepository.create_vendor(session, **_vendor_kwargs(name="Active"))
        v2 = VendorRepository.create_vendor(session, **_vendor_kwargs(name="Inactive"))
        v2.is_active = False
        session.flush()

        active = VendorRepository.list_vendors(session, active_only=True)
        assert len(active) == 1
        assert active[0].name == "Active"

        all_vendors = VendorRepository.list_vendors(session, active_only=False)
        assert len(all_vendors) == 2

    def test_list_vendors_sorted_by_name(self, session: Session):
        VendorRepository.create_vendor(session, **_vendor_kwargs(name="Zebra"))
        VendorRepository.create_vendor(session, **_vendor_kwargs(name="Alpha"))
        vendors = VendorRepository.list_vendors(session, active_only=False)
        assert vendors[0].name == "Alpha"
        assert vendors[1].name == "Zebra"

    def test_get_vendors_needing_assessment_never_assessed(self, session: Session):
        VendorRepository.create_vendor(
            session, **_vendor_kwargs(last_assessment_date=None),
        )
        needing = VendorRepository.get_vendors_needing_assessment(session)
        assert len(needing) == 1

    def test_get_vendors_needing_assessment_stale(self, session: Session):
        stale_date = date.today() - timedelta(days=60)
        VendorRepository.create_vendor(
            session, **_vendor_kwargs(last_assessment_date=stale_date),
        )
        needing = VendorRepository.get_vendors_needing_assessment(session)
        assert len(needing) == 1

    def test_get_vendors_needing_assessment_recent(self, session: Session):
        recent_date = date.today() - timedelta(days=5)
        VendorRepository.create_vendor(
            session, **_vendor_kwargs(last_assessment_date=recent_date),
        )
        needing = VendorRepository.get_vendors_needing_assessment(session)
        assert len(needing) == 0

    def test_get_vendors_needing_assessment_inactive_excluded(self, session: Session):
        v = VendorRepository.create_vendor(
            session, **_vendor_kwargs(last_assessment_date=None),
        )
        v.is_active = False
        session.flush()
        needing = VendorRepository.get_vendors_needing_assessment(session)
        assert len(needing) == 0

    def test_get_vendor_not_found(self, session: Session):
        assert VendorRepository.get_vendor(session, "nonexistent") is None

    def test_update_vendor_certifications(self, session: Session):
        vendor = VendorRepository.create_vendor(session, **_vendor_kwargs())
        VendorRepository.update_vendor(
            session, vendor.id, {"certifications": ["ISO27001", "SOC2"]},
        )
        fetched = VendorRepository.get_vendor(session, vendor.id)
        assert fetched.certifications == ["ISO27001", "SOC2"]


# ---------------------------------------------------------------------------
# 6. PolicyViolationRepository tests
# ---------------------------------------------------------------------------


def _violation_kwargs(**overrides):
    """Default kwargs for creating a policy violation."""
    defaults = {
        "policy_id": "pol-encrypt",
        "policy_name": "Encryption Required",
        "resource_id": "bucket-123",
        "resource_type": "s3:bucket",
        "provider": "aws",
        "region": "us-east-1",
        "violation_detail": "Bucket not encrypted",
        "severity": "high",
        "detected_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    return defaults


class TestPolicyViolationRepository:
    def test_save_and_list_violations(self, session: Session):
        vid = PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(),
        )
        assert vid is not None

        violations = PolicyViolationRepository.list_violations(session)
        assert len(violations) == 1
        assert violations[0].policy_name == "Encryption Required"

    def test_resolve_violation(self, session: Session):
        vid = PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(),
        )
        resolved = PolicyViolationRepository.resolve_violation(session, vid)
        assert resolved.status == "resolved"
        assert resolved.resolved_at is not None

    def test_resolve_violation_not_found(self, session: Session):
        with pytest.raises(ValueError, match="not found"):
            PolicyViolationRepository.resolve_violation(session, "nonexistent")

    def test_list_violations_filter_by_status(self, session: Session):
        vid1 = PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(),
        )
        PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(),
        )
        PolicyViolationRepository.resolve_violation(session, vid1)

        open_violations = PolicyViolationRepository.list_violations(
            session, status="open",
        )
        assert len(open_violations) == 1

        resolved_violations = PolicyViolationRepository.list_violations(
            session, status="resolved",
        )
        assert len(resolved_violations) == 1

    def test_list_violations_filter_by_severity(self, session: Session):
        PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(severity="high"),
        )
        PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(severity="low"),
        )
        PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(severity="high"),
        )

        high = PolicyViolationRepository.list_violations(session, severity="high")
        assert len(high) == 2

        low = PolicyViolationRepository.list_violations(session, severity="low")
        assert len(low) == 1

    def test_list_violations_combined_filters(self, session: Session):
        vid = PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(severity="high"),
        )
        PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(severity="low"),
        )
        PolicyViolationRepository.resolve_violation(session, vid)

        results = PolicyViolationRepository.list_violations(
            session, status="resolved", severity="high",
        )
        assert len(results) == 1

    def test_list_violations_respects_limit(self, session: Session):
        for _ in range(5):
            PolicyViolationRepository.save_violation(
                session, **_violation_kwargs(),
            )
        results = PolicyViolationRepository.list_violations(session, limit=3)
        assert len(results) == 3

    def test_violation_default_status_is_open(self, session: Session):
        PolicyViolationRepository.save_violation(
            session, **_violation_kwargs(),
        )
        violations = PolicyViolationRepository.list_violations(session)
        assert violations[0].status == "open"
