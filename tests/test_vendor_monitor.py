"""Tests for vendor risk monitoring."""

from datetime import UTC, datetime

import pytest

from modules.vendor_monitor import Vendor, VendorRiskEngine, VendorRiskScore


@pytest.fixture
def risk_engine():
    return VendorRiskEngine()


@pytest.fixture
def compliant_vendor():
    return Vendor(
        vendor_id="V001",
        name="GoodVendor Inc",
        category="saas",
        criticality="medium",
        data_classification="internal",
        contract_start="2024-01-01",
        contract_end="2026-12-31",
        last_assessment_date=datetime.now(UTC).isoformat(),
        certifications=["SOC 2", "ISO 27001"],
        security_rating=85.0,
    )


@pytest.fixture
def risky_vendor():
    return Vendor(
        vendor_id="V002",
        name="SketchyCorp",
        category="cloud_infrastructure",
        criticality="critical",
        data_classification="restricted",
        contract_start="2023-01-01",
        contract_end="2025-06-01",
        last_assessment_date="2023-06-01",  # Very overdue
        certifications=[],
        security_rating=35.0,
        breach_history=["2023 data breach", "2024 ransomware incident"],
    )


class TestVendorRiskScoring:

    def test_compliant_vendor_low_risk(self, risk_engine, compliant_vendor):
        score = risk_engine.score_vendor(compliant_vendor)
        assert score.risk_level() in ("Low", "Medium")
        assert score.overall_score < 50

    def test_risky_vendor_high_risk(self, risk_engine, risky_vendor):
        score = risk_engine.score_vendor(risky_vendor)
        assert score.risk_level() in ("High", "Critical")
        assert score.overall_score > 50

    def test_critical_vendor_higher_score(self, risk_engine):
        medium = Vendor(
            vendor_id="V1", name="Med", category="saas",
            criticality="medium", data_classification="internal",
            contract_start="2024-01-01", contract_end="2026-01-01",
        )
        critical = Vendor(
            vendor_id="V2", name="Crit", category="saas",
            criticality="critical", data_classification="internal",
            contract_start="2024-01-01", contract_end="2026-01-01",
        )
        med_score = risk_engine.score_vendor(medium)
        crit_score = risk_engine.score_vendor(critical)
        assert crit_score.criticality_score > med_score.criticality_score

    def test_never_assessed_max_assessment_score(self, risk_engine):
        vendor = Vendor(
            vendor_id="V1", name="New", category="saas",
            criticality="low", data_classification="public",
            contract_start="2024-01-01", contract_end="2026-01-01",
            last_assessment_date="",
        )
        score = risk_engine.score_vendor(vendor)
        assert score.assessment_currency_score == 100.0

    def test_certifications_reduce_risk(self, risk_engine):
        no_certs = Vendor(
            vendor_id="V1", name="NoCerts", category="saas",
            criticality="medium", data_classification="internal",
            contract_start="2024-01-01", contract_end="2026-01-01",
            security_rating=70.0, certifications=[],
        )
        with_certs = Vendor(
            vendor_id="V2", name="Certified", category="saas",
            criticality="medium", data_classification="internal",
            contract_start="2024-01-01", contract_end="2026-01-01",
            security_rating=70.0, certifications=["SOC 2", "ISO 27001", "FedRAMP"],
        )
        score_no = risk_engine.score_vendor(no_certs)
        score_yes = risk_engine.score_vendor(with_certs)
        assert score_yes.security_posture_score < score_no.security_posture_score

    def test_sla_metrics_affect_score(self, risk_engine, compliant_vendor):
        good_sla = {"uptime_pct": 99.99, "avg_response_hours": 1}
        bad_sla = {"uptime_pct": 98.0, "avg_response_hours": 12}

        good_score = risk_engine.score_vendor(compliant_vendor, good_sla)
        bad_score = risk_engine.score_vendor(compliant_vendor, bad_sla)
        assert bad_score.sla_compliance_score > good_score.sla_compliance_score


class TestVendorRiskScore:

    def test_risk_levels(self):
        assert VendorRiskScore("V1", "X", 80, 0, 0, 0, 0, 0).risk_level() == "Critical"
        assert VendorRiskScore("V1", "X", 60, 0, 0, 0, 0, 0).risk_level() == "High"
        assert VendorRiskScore("V1", "X", 30, 0, 0, 0, 0, 0).risk_level() == "Medium"
        assert VendorRiskScore("V1", "X", 10, 0, 0, 0, 0, 0).risk_level() == "Low"
