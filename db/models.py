"""
SQLAlchemy ORM models for persisting GRC data.

Uses SQLAlchemy 2.0+ declarative style with mapped_column.
All tables use UUID primary keys stored as strings for portability
across SQLite (dev) and PostgreSQL (production).
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ── Audit Log ─────────────────────────────────────────────────────────

class AuditLog(Base):
    """Immutable audit trail for all data modifications."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    actor: Mapped[str] = mapped_column(String(100))  # API key hash or "anonymous"
    action: Mapped[str] = mapped_column(String(20))  # create, update, delete
    resource_type: Mapped[str] = mapped_column(String(50), index=True)
    resource_id: Mapped[str] = mapped_column(String(36), index=True)
    changes: Mapped[dict] = mapped_column(JSON, default=dict)
    client_ip: Mapped[str] = mapped_column(String(45), default="")
    request_id: Mapped[str] = mapped_column(String(36), default="")


# ── Asset Inventory ───────────────────────────────────────────────────

class AssetRecord(Base):
    """Cloud resource/asset inventory for correlation across sources."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    provider: Mapped[str] = mapped_column(String(10), index=True)
    account_id: Mapped[str] = mapped_column(String(50), index=True)
    resource_id: Mapped[str] = mapped_column(String(200), index=True)
    resource_type: Mapped[str] = mapped_column(String(50), index=True)
    region: Mapped[str] = mapped_column(String(30))
    name: Mapped[str] = mapped_column(String(200), default="")
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    criticality: Mapped[str] = mapped_column(String(20), default="Medium")
    data_classification: Mapped[str] = mapped_column(String(20), default="Internal")
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    __table_args__ = (
        Index("ix_assets_provider_account", "provider", "account_id"),
        Index("ix_assets_resource", "resource_id", "resource_type"),
    )


# ── Data Source / Connector Registry ──────────────────────────────────

class DataSource(Base):
    """Registry of connected data sources (cloud providers, security tools)."""

    __tablename__ = "data_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    source_type: Mapped[str] = mapped_column(String(30))  # cloud, siem, edr, scanner, etc.
    provider: Mapped[str] = mapped_column(String(50))  # aws, azure, gcp, splunk, crowdstrike, etc.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # Non-secret config
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[str] = mapped_column(String(20), default="never")
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class EvidenceRecord(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(20), index=True)
    check_id: Mapped[str] = mapped_column(String(30), index=True)
    provider: Mapped[str] = mapped_column(String(10), index=True)
    service: Mapped[str] = mapped_column(String(50))
    resource_type: Mapped[str] = mapped_column(String(50), default="")
    region: Mapped[str] = mapped_column(String(30))
    account_id: Mapped[str] = mapped_column(String(50), index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    normalized_data: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="collected")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), default="")
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessment_runs.id"), index=True, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_evidence_run_control", "run_id", "control_id"),
        Index("ix_evidence_provider_region", "provider", "region"),
    )


class AssessmentResultRecord(Base):
    __tablename__ = "assessment_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessment_runs.id"), index=True
    )
    control_id: Mapped[str] = mapped_column(String(20), index=True)
    check_id: Mapped[str] = mapped_column(String(30))
    assertion: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20), index=True)
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    provider: Mapped[str] = mapped_column(String(10))
    region: Mapped[str] = mapped_column(String(30))
    findings: Mapped[list] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    evidence_summary: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_steps: Mapped[list] = mapped_column(JSON, default=list)
    console_path: Mapped[str | None] = mapped_column(String(300), nullable=True)
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    assessor: Mapped[str] = mapped_column(String(20), default="python")
    policy_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    run: Mapped[AssessmentRun] = relationship(back_populates="results")

    __table_args__ = (
        Index("ix_results_run_status", "run_id", "status"),
    )


class AssessmentRun(Base):
    __tablename__ = "assessment_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    framework: Mapped[str] = mapped_column(String(50))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), default="running")
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    pass_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(20), default="manual")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    results: Mapped[list[AssessmentResultRecord]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class FrameworkDefinition(Base):
    __tablename__ = "frameworks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True)
    display_name: Mapped[str] = mapped_column(String(100))
    version: Mapped[str] = mapped_column(String(20))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    control_count: Mapped[int] = mapped_column(Integer, default=0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    inherits_from: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("frameworks.id"), nullable=True
    )
    definition: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class VendorRecord(Base):
    __tablename__ = "vendors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(50))
    criticality: Mapped[str] = mapped_column(String(20))
    data_classification: Mapped[str] = mapped_column(String(20))
    contract_start: Mapped[date] = mapped_column(Date)
    contract_end: Mapped[date] = mapped_column(Date)
    last_assessment_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    assessment_frequency_days: Mapped[int] = mapped_column(Integer, default=365)
    sla_uptime_target: Mapped[float] = mapped_column(Float, default=99.9)
    security_rating: Mapped[float | None] = mapped_column(Float, nullable=True)
    certifications: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    primary_contact: Mapped[str | None] = mapped_column(String(200), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class User(Base):
    """Application user for login and session management."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    hashed_password: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class PolicyViolation(Base):
    __tablename__ = "policy_violations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(100), index=True)
    policy_name: Mapped[str] = mapped_column(String(200))
    resource_id: Mapped[str] = mapped_column(String(200))
    resource_type: Mapped[str] = mapped_column(String(50))
    provider: Mapped[str] = mapped_column(String(10))
    region: Mapped[str] = mapped_column(String(30))
    violation_detail: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_violations_status_severity", "status", "severity"),
    )
