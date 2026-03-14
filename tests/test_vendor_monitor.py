"""Tests for vendor risk monitoring."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from modules.vendor_monitor import Vendor, VendorInventory, VendorRiskEngine, VendorRiskScore


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


class TestVendorToDict:
    """Tests for Vendor.to_dict (line 52)."""

    def test_to_dict_returns_dict(self):
        vendor = Vendor(
            vendor_id="V001",
            name="TestVendor",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end="2026-12-31",
        )
        result = vendor.to_dict()
        assert isinstance(result, dict)
        assert result["vendor_id"] == "V001"
        assert result["name"] == "TestVendor"
        assert result["category"] == "saas"
        assert result["criticality"] == "medium"
        assert result["data_classification"] == "internal"

    def test_to_dict_includes_all_fields(self):
        vendor = Vendor(
            vendor_id="V002",
            name="FullVendor",
            category="cloud_infrastructure",
            criticality="critical",
            data_classification="restricted",
            contract_start="2024-01-01",
            contract_end="2026-12-31",
            certifications=["SOC 2"],
            security_rating=80.0,
            breach_history=["2023 breach"],
        )
        result = vendor.to_dict()
        assert result["certifications"] == ["SOC 2"]
        assert result["security_rating"] == 80.0
        assert result["breach_history"] == ["2023 breach"]


class TestAssessmentCurrencyScoreErrorBranches:
    """Tests for ValueError/TypeError branches in _assessment_currency_score (lines 167-168)."""

    def test_invalid_date_string_returns_high_risk(self):
        engine = VendorRiskEngine()
        vendor = Vendor(
            vendor_id="V001",
            name="BadDate",
            category="saas",
            criticality="low",
            data_classification="public",
            contract_start="2024-01-01",
            contract_end="2026-12-31",
            last_assessment_date="not-a-date",
        )
        score = engine._assessment_currency_score(vendor)
        assert score == 75.0

    def test_none_date_value_returns_high_risk(self):
        engine = VendorRiskEngine()
        vendor = Vendor(
            vendor_id="V002",
            name="NoneDate",
            category="saas",
            criticality="low",
            data_classification="public",
            contract_start="2024-01-01",
            contract_end="2026-12-31",
            last_assessment_date="not-a-date",
        )
        # Force a TypeError by patching the attribute to a non-string
        vendor.last_assessment_date = 12345  # type: ignore[assignment]
        score = engine._assessment_currency_score(vendor)
        assert score == 75.0


@pytest.fixture
def sample_vendor():
    return Vendor(
        vendor_id="V001",
        name="SampleCo",
        category="saas",
        criticality="medium",
        data_classification="internal",
        contract_start="2024-01-01",
        contract_end="2026-12-31",
        last_assessment_date=datetime.now(UTC).isoformat(),
        certifications=["SOC 2"],
        security_rating=75.0,
    )


class TestVendorInventoryLoad:
    """Tests for VendorInventory._load and __init__ (lines 223-234)."""

    def test_load_from_nonexistent_file_starts_empty(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        assert inv.vendors == {}

    def test_load_from_existing_file(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        data = {
            "vendors": [
                {
                    "vendor_id": "V001",
                    "name": "LoadedVendor",
                    "category": "saas",
                    "criticality": "medium",
                    "data_classification": "internal",
                    "contract_start": "2024-01-01",
                    "contract_end": "2026-12-31",
                    "last_assessment_date": "",
                    "assessment_frequency_days": 365,
                    "questionnaire_status": "pending",
                    "sla_uptime_target": 99.9,
                    "sla_response_time_hours": 4,
                    "sla_resolution_time_hours": 24,
                    "security_rating": None,
                    "security_rating_source": "",
                    "certifications": [],
                    "last_incident_date": "",
                    "breach_history": [],
                    "primary_contact": "",
                    "notes": "",
                }
            ]
        }
        inventory_file.write_text(json.dumps(data))
        inv = VendorInventory(str(inventory_file))
        assert "V001" in inv.vendors
        assert inv.vendors["V001"].name == "LoadedVendor"

    def test_load_multiple_vendors(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        vendor_template = {
            "last_assessment_date": "",
            "assessment_frequency_days": 365,
            "questionnaire_status": "pending",
            "sla_uptime_target": 99.9,
            "sla_response_time_hours": 4,
            "sla_resolution_time_hours": 24,
            "security_rating": None,
            "security_rating_source": "",
            "certifications": [],
            "last_incident_date": "",
            "breach_history": [],
            "primary_contact": "",
            "notes": "",
        }
        data = {
            "vendors": [
                {
                    "vendor_id": "V001", "name": "VendorOne", "category": "saas",
                    "criticality": "medium", "data_classification": "internal",
                    "contract_start": "2024-01-01", "contract_end": "2026-12-31",
                    **vendor_template,
                },
                {
                    "vendor_id": "V002", "name": "VendorTwo", "category": "cloud_infrastructure",
                    "criticality": "critical", "data_classification": "restricted",
                    "contract_start": "2024-01-01", "contract_end": "2026-12-31",
                    **vendor_template,
                },
            ]
        }
        inventory_file.write_text(json.dumps(data))
        inv = VendorInventory(str(inventory_file))
        assert len(inv.vendors) == 2
        assert "V001" in inv.vendors
        assert "V002" in inv.vendors


class TestVendorInventorySave:
    """Tests for VendorInventory.save (lines 238-243)."""

    def test_save_creates_file(self, tmp_path, sample_vendor):
        inventory_file = tmp_path / "subdir" / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        inv.vendors[sample_vendor.vendor_id] = sample_vendor
        inv.save()
        assert inventory_file.exists()

    def test_save_and_reload(self, tmp_path, sample_vendor):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        inv.vendors[sample_vendor.vendor_id] = sample_vendor
        inv.save()

        inv2 = VendorInventory(str(inventory_file))
        assert sample_vendor.vendor_id in inv2.vendors
        assert inv2.vendors[sample_vendor.vendor_id].name == sample_vendor.name

    def test_save_creates_parent_dirs(self, tmp_path):
        inventory_file = tmp_path / "a" / "b" / "c" / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        inv.save()
        assert inventory_file.exists()
        saved = json.loads(inventory_file.read_text())
        assert saved["vendors"] == []


class TestVendorInventoryAddAndGet:
    """Tests for VendorInventory.add_vendor and get_vendor (lines 245-250)."""

    def test_add_vendor_persists(self, tmp_path, sample_vendor):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        inv.add_vendor(sample_vendor)
        assert sample_vendor.vendor_id in inv.vendors
        assert inventory_file.exists()

    def test_get_vendor_returns_vendor(self, tmp_path, sample_vendor):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        inv.add_vendor(sample_vendor)
        result = inv.get_vendor(sample_vendor.vendor_id)
        assert result is not None
        assert result.vendor_id == sample_vendor.vendor_id

    def test_get_vendor_missing_returns_none(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        result = inv.get_vendor("nonexistent")
        assert result is None

    def test_add_vendor_overwrites_existing(self, tmp_path, sample_vendor):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        inv.add_vendor(sample_vendor)
        updated = Vendor(
            vendor_id=sample_vendor.vendor_id,
            name="UpdatedName",
            category="saas",
            criticality="high",
            data_classification="confidential",
            contract_start="2024-01-01",
            contract_end="2027-12-31",
        )
        inv.add_vendor(updated)
        assert inv.vendors[sample_vendor.vendor_id].name == "UpdatedName"


class TestVendorsNeedingAssessment:
    """Tests for VendorInventory.vendors_needing_assessment (lines 252-276)."""

    def test_vendor_never_assessed_is_flagged(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        vendor = Vendor(
            vendor_id="V001",
            name="NeverAssessed",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end="2026-12-31",
            last_assessment_date="",
        )
        inv.vendors[vendor.vendor_id] = vendor
        result = inv.vendors_needing_assessment()
        assert vendor in result

    def test_recently_assessed_vendor_not_flagged(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        recent_date = (datetime.now(UTC) - timedelta(days=10)).isoformat()
        vendor = Vendor(
            vendor_id="V002",
            name="RecentlyAssessed",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end="2026-12-31",
            last_assessment_date=recent_date,
            assessment_frequency_days=365,
        )
        inv.vendors[vendor.vendor_id] = vendor
        result = inv.vendors_needing_assessment()
        assert vendor not in result

    def test_overdue_assessment_is_flagged(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        old_date = (datetime.now(UTC) - timedelta(days=400)).isoformat()
        vendor = Vendor(
            vendor_id="V003",
            name="Overdue",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end="2026-12-31",
            last_assessment_date=old_date,
            assessment_frequency_days=365,
        )
        inv.vendors[vendor.vendor_id] = vendor
        result = inv.vendors_needing_assessment()
        assert vendor in result

    def test_assessment_due_within_30_days_is_flagged(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        # Due in 15 days means last assessment was (365-15) days ago
        last_date = (datetime.now(UTC) - timedelta(days=350)).isoformat()
        vendor = Vendor(
            vendor_id="V004",
            name="DueSoon",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end="2026-12-31",
            last_assessment_date=last_date,
            assessment_frequency_days=365,
        )
        inv.vendors[vendor.vendor_id] = vendor
        result = inv.vendors_needing_assessment()
        assert vendor in result

    def test_invalid_assessment_date_is_flagged(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        vendor = Vendor(
            vendor_id="V005",
            name="BadDate",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end="2026-12-31",
            last_assessment_date="not-a-valid-date",
        )
        inv.vendors[vendor.vendor_id] = vendor
        result = inv.vendors_needing_assessment()
        assert vendor in result

    def test_empty_inventory_returns_empty(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        result = inv.vendors_needing_assessment()
        assert result == []


class TestExpiringContracts:
    """Tests for VendorInventory.expiring_contracts (lines 278-294)."""

    def test_contract_expiring_soon_is_returned(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        end_date = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%d")
        vendor = Vendor(
            vendor_id="V001",
            name="ExpiringSoon",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end=end_date,
        )
        inv.vendors[vendor.vendor_id] = vendor
        result = inv.expiring_contracts(days_ahead=90)
        assert vendor in result

    def test_contract_far_future_not_returned(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        far_date = (datetime.now(UTC) + timedelta(days=200)).strftime("%Y-%m-%d")
        vendor = Vendor(
            vendor_id="V002",
            name="FarFuture",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end=far_date,
        )
        inv.vendors[vendor.vendor_id] = vendor
        result = inv.expiring_contracts(days_ahead=90)
        assert vendor not in result

    def test_already_expired_contract_not_returned(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        past_date = (datetime.now(UTC) - timedelta(days=10)).strftime("%Y-%m-%d")
        vendor = Vendor(
            vendor_id="V003",
            name="AlreadyExpired",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2023-01-01",
            contract_end=past_date,
        )
        inv.vendors[vendor.vendor_id] = vendor
        result = inv.expiring_contracts(days_ahead=90)
        assert vendor not in result

    def test_invalid_contract_end_is_skipped(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        vendor = Vendor(
            vendor_id="V004",
            name="BadContractDate",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end="not-a-date",
        )
        inv.vendors[vendor.vendor_id] = vendor
        result = inv.expiring_contracts(days_ahead=90)
        assert vendor not in result

    def test_custom_days_ahead_window(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        # Contract ends in 60 days — inside 90-day window but outside 30-day window
        end_date = (datetime.now(UTC) + timedelta(days=60)).strftime("%Y-%m-%d")
        vendor = Vendor(
            vendor_id="V005",
            name="SixtyDays",
            category="saas",
            criticality="medium",
            data_classification="internal",
            contract_start="2024-01-01",
            contract_end=end_date,
        )
        inv.vendors[vendor.vendor_id] = vendor
        assert vendor in inv.expiring_contracts(days_ahead=90)
        assert vendor not in inv.expiring_contracts(days_ahead=30)

    def test_empty_inventory_returns_empty(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        assert inv.expiring_contracts() == []


class TestRiskDashboard:
    """Tests for VendorInventory.risk_dashboard (lines 296-329)."""

    def _make_inventory(self, tmp_path, vendors):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))
        for v in vendors:
            inv.vendors[v.vendor_id] = v
        return inv

    def test_dashboard_empty_inventory(self, tmp_path):
        inv = self._make_inventory(tmp_path, [])
        engine = VendorRiskEngine()
        dashboard = inv.risk_dashboard(engine)
        assert dashboard["total_vendors"] == 0
        assert dashboard["vendor_scores"] == []
        assert dashboard["risk_distribution"] == {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    def test_dashboard_single_vendor_structure(self, tmp_path, sample_vendor):
        inv = self._make_inventory(tmp_path, [sample_vendor])
        engine = VendorRiskEngine()
        dashboard = inv.risk_dashboard(engine)
        assert dashboard["total_vendors"] == 1
        assert len(dashboard["vendor_scores"]) == 1
        entry = dashboard["vendor_scores"][0]
        assert entry["vendor"] == sample_vendor.name
        assert entry["vendor_id"] == sample_vendor.vendor_id
        assert "risk_level" in entry
        assert "overall_score" in entry
        assert "criticality" in entry
        assert "data_classification" in entry
        assert "factors" in entry

    def test_dashboard_sorted_by_score_descending(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))

        low_risk = Vendor(
            vendor_id="V001", name="LowRisk", category="saas",
            criticality="low", data_classification="public",
            contract_start="2024-01-01", contract_end="2026-12-31",
            last_assessment_date=datetime.now(UTC).isoformat(),
            security_rating=90.0, certifications=["SOC 2", "ISO 27001"],
        )
        high_risk = Vendor(
            vendor_id="V002", name="HighRisk", category="cloud_infrastructure",
            criticality="critical", data_classification="restricted",
            contract_start="2024-01-01", contract_end="2026-12-31",
            last_assessment_date="2022-01-01",
            security_rating=20.0, breach_history=["breach1", "breach2"],
        )
        inv.vendors["V001"] = low_risk
        inv.vendors["V002"] = high_risk

        engine = VendorRiskEngine()
        dashboard = inv.risk_dashboard(engine)
        scores = dashboard["vendor_scores"]
        assert len(scores) == 2
        assert scores[0]["overall_score"] >= scores[1]["overall_score"]

    def test_dashboard_risk_distribution_counts(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))

        # A definitely critical vendor (max scores)
        critical_vendor = Vendor(
            vendor_id="V001", name="Critical", category="cloud_infrastructure",
            criticality="critical", data_classification="restricted",
            contract_start="2023-01-01", contract_end="2026-12-31",
            last_assessment_date="2020-01-01",
            security_rating=10.0,
            breach_history=["b1", "b2", "b3"],
        )
        inv.vendors["V001"] = critical_vendor

        engine = VendorRiskEngine()
        dashboard = inv.risk_dashboard(engine)
        dist = dashboard["risk_distribution"]
        total = sum(dist.values())
        assert total == 1
        assert dist["Critical"] + dist["High"] + dist["Medium"] + dist["Low"] == 1

    def test_dashboard_includes_assessment_and_contract_counts(self, tmp_path):
        inventory_file = tmp_path / "vendors.json"
        inv = VendorInventory(str(inventory_file))

        unassessed = Vendor(
            vendor_id="V001", name="Unassessed", category="saas",
            criticality="medium", data_classification="internal",
            contract_start="2024-01-01", contract_end="2026-12-31",
            last_assessment_date="",
        )
        expiring = Vendor(
            vendor_id="V002", name="Expiring", category="saas",
            criticality="low", data_classification="public",
            contract_start="2024-01-01",
            contract_end=(datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%d"),
            last_assessment_date=datetime.now(UTC).isoformat(),
        )
        inv.vendors["V001"] = unassessed
        inv.vendors["V002"] = expiring

        engine = VendorRiskEngine()
        dashboard = inv.risk_dashboard(engine)
        assert dashboard["total_vendors"] == 2
        assert dashboard["vendors_needing_assessment"] >= 1
        assert dashboard["expiring_contracts_90d"] >= 1
