"""Tests for the normalized evidence model and crosswalk engine."""

import json
import pytest
from modules.models import (
    NormalizedEvidence,
    AssessmentResult,
    ResourceNormalizer,
    FrameworkCrosswalk,
    ComplianceStatus,
    Severity,
)


class TestNormalizedEvidence:

    def test_auto_generates_id_and_hash(self):
        evidence = NormalizedEvidence(
            control_id="AC-2",
            check_id="AC-2.a",
            provider="aws",
            service="iam",
            data={"Users": [{"UserName": "alice"}]},
        )
        assert evidence.evidence_id  # UUID generated
        assert evidence.sha256_hash  # Hash computed
        assert evidence.collected_at is not None

    def test_integrity_verification(self):
        evidence = NormalizedEvidence(
            control_id="AC-2",
            check_id="AC-2.a",
            provider="aws",
            service="iam",
            data={"test": "data"},
        )
        assert evidence.verify_integrity() is True

        # Tamper with data
        evidence.data["test"] = "tampered"
        assert evidence.verify_integrity() is False

    def test_to_dict_serializable(self):
        evidence = NormalizedEvidence(
            control_id="SC-7",
            check_id="SC-7.a",
            provider="azure",
            service="network",
            data={"rules": []},
            normalized_data={"rules": [], "total_groups": 0},
        )
        d = evidence.to_dict()
        assert isinstance(d, dict)
        assert d["control_id"] == "SC-7"
        assert d["provider"] == "azure"
        # Should be JSON-serializable
        json.dumps(d)

    def test_empty_data_no_hash(self):
        evidence = NormalizedEvidence(
            control_id="AC-2",
            check_id="AC-2.a",
            provider="aws",
            service="iam",
        )
        # Empty dict data still produces a hash
        assert evidence.sha256_hash != ""


class TestAssessmentResult:

    def test_auto_generates_id(self):
        result = AssessmentResult(
            control_id="AC-2",
            check_id="AC-2.a",
            assertion="all_users_have_mfa",
            status="pass",
            provider="aws",
            region="us-east-1",
        )
        assert result.result_id
        assert result.assessed_at is not None

    def test_to_dict(self):
        result = AssessmentResult(
            control_id="SC-7",
            check_id="SC-7.a",
            assertion="no_unrestricted_ingress",
            status="fail",
            severity="high",
            provider="aws",
            region="us-east-1",
            findings=["Open port 22"],
        )
        d = result.to_dict()
        assert d["status"] == "fail"
        assert d["severity"] == "high"
        assert len(d["findings"]) == 1


class TestResourceNormalizer:

    def test_normalize_aws_iam_users(self):
        raw = {
            "Users": [
                {"UserName": "alice", "MFADevices": [{"SerialNumber": "arn:..."}]},
                {"UserName": "bob"},
            ],
            "SummaryMap": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1},
        }
        result = ResourceNormalizer.normalize_iam_users("aws", raw)
        assert result["total_users"] == 2
        assert result["users"][0]["mfa_enabled"] is True
        assert result["users"][1]["mfa_enabled"] is False
        assert result["root_account"]["access_keys_present"] is False

    def test_normalize_aws_security_groups(self):
        raw = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "test-sg",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                        }
                    ],
                }
            ],
            "NetworkAcls": [],
        }
        result = ResourceNormalizer.normalize_security_groups("aws", raw)
        assert result["total_groups"] == 1
        assert len(result["rules"]) == 1
        assert result["rules"][0]["source"] == "0.0.0.0/0"
        assert result["rules"][0]["port_range"] == [22, 22]

    def test_normalize_aws_audit_config(self):
        raw = {
            "trailList": [
                {
                    "Name": "main-trail",
                    "IsMultiRegionTrail": True,
                    "IsLogging": True,
                    "LogFileValidationEnabled": True,
                    "S3BucketName": "audit-bucket",
                }
            ]
        }
        result = ResourceNormalizer.normalize_audit_config("aws", raw)
        assert len(result["trails"]) == 1
        assert result["trails"][0]["is_multi_region"] is True
        assert result["audit_logging_enabled"] is True

    def test_normalize_unknown_provider(self):
        result = ResourceNormalizer.normalize_iam_users("unknown", {})
        assert result["total_users"] == 0


class TestFrameworkCrosswalk:

    def test_map_control(self):
        data = {
            "test_crosswalk": {
                "source": "nist_800_53",
                "target": "soc2",
                "mappings": {
                    "AC-2": [
                        {"control": "CC6.1", "confidence": "high", "notes": "test"},
                    ]
                },
            }
        }
        cw = FrameworkCrosswalk(data)
        result = cw.map_control("nist_800_53", "AC-2", "soc2")
        assert len(result) == 1
        assert result[0]["control"] == "CC6.1"

    def test_no_mapping_returns_empty(self):
        data = {
            "test": {
                "source": "nist_800_53",
                "target": "soc2",
                "mappings": {},
            }
        }
        cw = FrameworkCrosswalk(data)
        result = cw.map_control("nist_800_53", "XX-99", "soc2")
        assert result == []

    def test_get_shared_evidence(self):
        data = {
            "cw1": {
                "source": "nist_800_53",
                "target": "soc2",
                "mappings": {"AC-2": [{"control": "CC6.1", "confidence": "high"}]},
            },
            "cw2": {
                "source": "nist_800_53",
                "target": "iso27001",
                "mappings": {"AC-2": [{"control": "A.5.15", "confidence": "high"}]},
            },
        }
        cw = FrameworkCrosswalk(data)
        shared = cw.get_shared_evidence("AC-2")
        assert len(shared) == 2

    def test_list_frameworks(self):
        data = {
            "cw1": {"source": "nist_800_53", "target": "soc2", "mappings": {}},
            "cw2": {"source": "nist_800_53", "target": "iso27001", "mappings": {}},
        }
        cw = FrameworkCrosswalk(data)
        frameworks = cw.list_frameworks()
        assert "nist_800_53" in frameworks
        assert "soc2" in frameworks
        assert "iso27001" in frameworks


class TestEnums:

    def test_compliance_status(self):
        assert ComplianceStatus.COMPLIANT == "compliant"
        assert ComplianceStatus.NON_COMPLIANT == "non_compliant"

    def test_severity(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.INFO == "info"
