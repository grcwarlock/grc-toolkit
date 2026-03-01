"""Tests for the control assessment engine and assertions."""

import pytest

from modules.control_assessor import AssertionEngine, ControlAssessor, _extract_key


@pytest.fixture
def engine():
    return AssertionEngine()


class TestAssertions:

    def test_mfa_all_users_compliant(self, engine):
        data = {
            "Users": [
                {"UserName": "alice", "MFADevices": [{"SerialNumber": "arn:..."}]},
                {"UserName": "bob", "MFADevices": [{"SerialNumber": "arn:..."}]},
            ]
        }
        result = engine.evaluate("all_users_have_mfa", data, "AC-2", "AC-2.a", "aws", "us-east-1")
        assert result.status == "pass"

    def test_mfa_missing_for_user(self, engine):
        data = {
            "Users": [
                {"UserName": "alice", "MFADevices": [{"SerialNumber": "arn:..."}]},
                {"UserName": "bob"},  # No MFA
            ]
        }
        result = engine.evaluate("all_users_have_mfa", data, "AC-2", "AC-2.a", "aws", "us-east-1")
        assert result.status == "fail"
        assert any("bob" in f for f in result.findings)

    def test_no_root_access_keys_pass(self, engine):
        data = {"SummaryMap": {"AccountAccessKeysPresent": 0}}
        result = engine.evaluate("no_root_access_keys", data, "AC-2", "AC-2.a", "aws", "us-east-1")
        assert result.status == "pass"

    def test_no_root_access_keys_fail(self, engine):
        data = {"SummaryMap": {"AccountAccessKeysPresent": 2}}
        result = engine.evaluate("no_root_access_keys", data, "AC-2", "AC-2.a", "aws", "us-east-1")
        assert result.status == "fail"
        assert any("2" in f for f in result.findings)

    def test_cloudtrail_enabled_pass(self, engine):
        data = {"trailList": [{"Name": "main-trail", "IsMultiRegionTrail": True}]}
        result = engine.evaluate(
            "cloudtrail_enabled_all_regions", data, "AU-2", "AU-2.a", "aws", "us-east-1"
        )
        assert result.status == "pass"

    def test_cloudtrail_no_trails(self, engine):
        data = {"trailList": []}
        result = engine.evaluate(
            "cloudtrail_enabled_all_regions", data, "AU-2", "AU-2.a", "aws", "us-east-1"
        )
        assert result.status == "fail"

    def test_cloudtrail_single_region_only(self, engine):
        data = {"trailList": [{"Name": "regional", "IsMultiRegionTrail": False}]}
        result = engine.evaluate(
            "cloudtrail_enabled_all_regions", data, "AU-2", "AU-2.a", "aws", "us-east-1"
        )
        assert result.status == "fail"

    def test_security_groups_compliant(self, engine):
        data = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "web-server",
                    "IpPermissions": [
                        {
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        }
                    ],
                }
            ]
        }
        result = engine.evaluate(
            "no_unrestricted_ingress", data, "SC-7", "SC-7.a", "aws", "us-east-1"
        )
        assert result.status == "pass"

    def test_security_groups_open_ssh(self, engine):
        data = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-456",
                    "GroupName": "bad-sg",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }
        result = engine.evaluate(
            "no_unrestricted_ingress", data, "SC-7", "SC-7.a", "aws", "us-east-1"
        )
        assert result.status == "fail"
        assert any("0.0.0.0/0" in f for f in result.findings)

    def test_guardduty_enabled(self, engine):
        data = {"DetectorIds": ["abc123"]}
        result = engine.evaluate("guardduty_enabled", data, "AU-6", "AU-6.a", "aws", "us-east-1")
        assert result.status == "pass"

    def test_guardduty_disabled(self, engine):
        data = {"DetectorIds": []}
        result = engine.evaluate("guardduty_enabled", data, "AU-6", "AU-6.a", "aws", "us-east-1")
        assert result.status == "fail"

    def test_unknown_assertion(self, engine):
        result = engine.evaluate(
            "nonexistent_assertion", {}, "AC-1", "AC-1.a", "aws", "us-east-1"
        )
        assert result.status == "error"

    def test_none_data_returns_error(self, engine):
        result = engine.evaluate(
            "all_users_have_mfa", None, "AC-2", "AC-2.a", "aws", "us-east-1"
        )
        assert result.status == "error"


class TestExtractKey:

    def test_simple_dict(self):
        assert _extract_key({"Users": [1, 2]}, "Users") == [1, 2]

    def test_missing_key(self):
        assert _extract_key({"Other": 1}, "Users", []) == []

    def test_paginated_list(self):
        data = [
            {"Users": ["alice", "bob"]},
            {"Users": ["charlie"]},
        ]
        assert _extract_key(data, "Users") == ["alice", "bob", "charlie"]

    def test_none_data(self):
        assert _extract_key(None, "Users", "default") == "default"


class TestControlAssessor:

    def test_summarize(self):
        assessor = ControlAssessor()
        # Create mock results using AssessmentResult-like dicts
        from modules.control_assessor import AssessmentResult
        results = [
            AssessmentResult("AC-2", "AC-2.a", "test", "pass", "aws", "us-east-1"),
            AssessmentResult("AC-2", "AC-2.d", "test", "fail", "aws", "us-east-1"),
            AssessmentResult("AU-2", "AU-2.a", "test", "pass", "aws", "us-east-1"),
        ]
        summary = assessor.summarize(results)
        assert summary["total_checks"] == 3
        assert summary["passed"] == 2
        assert summary["failed"] == 1
        assert summary["pass_rate"] == "66.7%"
        assert "AC" in summary["by_control"]
        assert "AU" in summary["by_control"]
