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


    # --- no_wildcard_admin_policies ---

    def test_no_wildcard_admin_policies_pass(self, engine):
        data = {
            "Policies": [
                {"PolicyName": "ReadOnlyAccess", "IsAWSManaged": False},
                {"PolicyName": "AdministratorAccess", "IsAWSManaged": True},
            ]
        }
        result = engine.evaluate(
            "no_wildcard_admin_policies", data, "AC-6", "AC-6.a", "aws", "us-east-1"
        )
        assert result.status == "pass"
        assert any("No custom wildcard" in f for f in result.findings)

    def test_no_wildcard_admin_policies_fail_custom_admin(self, engine):
        data = {
            "Policies": [
                {"PolicyName": "MyAdministratorAccess", "IsAWSManaged": False},
            ]
        }
        result = engine.evaluate(
            "no_wildcard_admin_policies", data, "AC-6", "AC-6.a", "aws", "us-east-1"
        )
        assert result.status == "fail"
        assert any("MyAdministratorAccess" in f for f in result.findings)

    def test_no_wildcard_admin_policies_fail_custom_full_access(self, engine):
        data = {
            "Policies": [
                {"PolicyName": "S3FullAccess", "IsAWSManaged": False},
            ]
        }
        result = engine.evaluate(
            "no_wildcard_admin_policies", data, "AC-6", "AC-6.a", "aws", "us-east-1"
        )
        assert result.status == "fail"
        assert any("S3FullAccess" in f for f in result.findings)

    def test_no_wildcard_admin_policies_aws_managed_ignored(self, engine):
        data = {
            "Policies": [
                {"PolicyName": "AdministratorAccess", "IsAWSManaged": True},
                {"PolicyName": "ReadFullAccess", "IsAWSManaged": True},
            ]
        }
        result = engine.evaluate(
            "no_wildcard_admin_policies", data, "AC-6", "AC-6.a", "aws", "us-east-1"
        )
        assert result.status == "pass"

    def test_no_wildcard_admin_policies_empty(self, engine):
        data = {"Policies": []}
        result = engine.evaluate(
            "no_wildcard_admin_policies", data, "AC-6", "AC-6.a", "aws", "us-east-1"
        )
        assert result.status == "pass"

    # --- cloudtrail_logging_active ---

    def test_cloudtrail_logging_active_pass(self, engine):
        data = {"IsLogging": True, "LatestDeliveryTime": "2026-03-14T00:00:00Z"}
        result = engine.evaluate(
            "cloudtrail_logging_active", data, "AU-2", "AU-2.b", "aws", "us-east-1"
        )
        assert result.status == "pass"
        assert any("actively logging" in f for f in result.findings)
        assert any("2026-03-14" in f for f in result.findings)

    def test_cloudtrail_logging_active_fail_not_logging(self, engine):
        data = {"IsLogging": False}
        result = engine.evaluate(
            "cloudtrail_logging_active", data, "AU-2", "AU-2.b", "aws", "us-east-1"
        )
        assert result.status == "fail"
        assert any("not active" in f for f in result.findings)

    def test_cloudtrail_logging_active_fail_non_dict(self, engine):
        data = []
        result = engine.evaluate(
            "cloudtrail_logging_active", data, "AU-2", "AU-2.b", "aws", "us-east-1"
        )
        assert result.status == "fail"

    def test_cloudtrail_logging_active_missing_key(self, engine):
        data = {}
        result = engine.evaluate(
            "cloudtrail_logging_active", data, "AU-2", "AU-2.b", "aws", "us-east-1"
        )
        assert result.status == "fail"

    # --- security_hub_enabled ---

    def test_security_hub_enabled_pass(self, engine):
        data = {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"}
        result = engine.evaluate(
            "security_hub_enabled", data, "SI-4", "SI-4.a", "aws", "us-east-1"
        )
        assert result.status == "pass"
        assert any("arn:aws:securityhub" in f for f in result.findings)

    def test_security_hub_enabled_fail_empty_arn(self, engine):
        data = {"HubArn": ""}
        result = engine.evaluate(
            "security_hub_enabled", data, "SI-4", "SI-4.a", "aws", "us-east-1"
        )
        assert result.status == "fail"
        assert any("not enabled" in f for f in result.findings)

    def test_security_hub_enabled_fail_missing_key(self, engine):
        data = {}
        result = engine.evaluate(
            "security_hub_enabled", data, "SI-4", "SI-4.a", "aws", "us-east-1"
        )
        assert result.status == "fail"

    def test_security_hub_enabled_fail_non_dict(self, engine):
        data = []
        result = engine.evaluate(
            "security_hub_enabled", data, "SI-4", "SI-4.a", "aws", "us-east-1"
        )
        assert result.status == "fail"

    # --- no_unrestricted_ingress (IPv6 branch) ---

    def test_security_groups_open_ssh_ipv6(self, engine):
        data = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-789",
                    "GroupName": "bad-sg-ipv6",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [],
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        }
                    ],
                }
            ]
        }
        result = engine.evaluate(
            "no_unrestricted_ingress", data, "SC-7", "SC-7.a", "aws", "us-east-1"
        )
        assert result.status == "fail"
        assert any("::/0" in f for f in result.findings)

    def test_security_groups_ipv6_restricted(self, engine):
        data = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-abc",
                    "GroupName": "restricted-sg",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [],
                            "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}],
                        }
                    ],
                }
            ]
        }
        result = engine.evaluate(
            "no_unrestricted_ingress", data, "SC-7", "SC-7.a", "aws", "us-east-1"
        )
        assert result.status == "pass"

    # --- default_deny_ingress ---

    def test_default_deny_ingress_pass(self, engine):
        data = {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-111",
                    "Entries": [
                        {
                            "RuleNumber": 32767,
                            "Egress": False,
                            "RuleAction": "deny",
                        }
                    ],
                }
            ]
        }
        result = engine.evaluate(
            "default_deny_ingress", data, "SC-7", "SC-7.b", "aws", "us-east-1"
        )
        assert result.status == "pass"
        assert any("1" in f for f in result.findings)

    def test_default_deny_ingress_fail_no_deny(self, engine):
        data = {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-222",
                    "Entries": [
                        {
                            "RuleNumber": 32767,
                            "Egress": False,
                            "RuleAction": "allow",
                        }
                    ],
                }
            ]
        }
        result = engine.evaluate(
            "default_deny_ingress", data, "SC-7", "SC-7.b", "aws", "us-east-1"
        )
        assert result.status == "fail"
        assert any("acl-222" in f for f in result.findings)

    def test_default_deny_ingress_empty(self, engine):
        data = {"NetworkAcls": []}
        result = engine.evaluate(
            "default_deny_ingress", data, "SC-7", "SC-7.b", "aws", "us-east-1"
        )
        assert result.status == "pass"

    def test_default_deny_ingress_egress_rule_ignored(self, engine):
        """Egress rules at 32767 should not trigger a violation."""
        data = {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-333",
                    "Entries": [
                        {
                            "RuleNumber": 32767,
                            "Egress": True,   # egress — should be skipped
                            "RuleAction": "allow",
                        }
                    ],
                }
            ]
        }
        result = engine.evaluate(
            "default_deny_ingress", data, "SC-7", "SC-7.b", "aws", "us-east-1"
        )
        assert result.status == "pass"

    # --- assertion exception handling (lines 71-73) ---

    def test_assertion_exception_returns_error(self, engine):
        """An assertion that raises an exception must produce status='error'."""
        @engine.register("_raises_exception")
        def bad_assertion(data):
            raise RuntimeError("simulated failure")

        result = engine.evaluate(
            "_raises_exception", {"key": "value"}, "XX-1", "XX-1.a", "aws", "us-east-1"
        )
        assert result.status == "error"
        assert any("simulated failure" in f for f in result.findings)


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

    def test_paginated_non_list_value_returns_first_occurrence(self):
        """Line 309: a non-list value in a paginated page returns on first occurrence."""
        data = [
            {"IsLogging": True},
            {"IsLogging": False},  # Second page should never be reached
        ]
        result = _extract_key(data, "IsLogging", None)
        assert result is True

    def test_paginated_missing_key_returns_default(self):
        """Paginated list with no matching key should return the default."""
        data = [{"OtherKey": 1}, {"AnotherKey": 2}]
        result = _extract_key(data, "Missing", "fallback")
        assert result == "fallback"


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

    def test_assess_no_artifacts_produces_not_assessed(self):
        """Lines 348-357: checks with no matching artifact produce not_assessed status."""
        assessor = ControlAssessor()
        checks = [
            {
                "control_id": "AC-2",
                "check_id": "AC-2.a",
                "assertion": "all_users_have_mfa",
                "provider": "aws",
            }
        ]
        results = assessor.assess(artifacts=[], checks=checks)
        assert len(results) == 1
        assert results[0].status == "not_assessed"
        assert any("No evidence" in f for f in results[0].findings)

    def test_assess_with_matching_artifact(self):
        """Lines 360-373: matching artifact is evaluated and evidence_summary is set."""
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        assessor = ControlAssessor()
        artifact = MagicMock()
        artifact.check_id = "AC-2.a"
        artifact.provider = "aws"
        artifact.region = "us-east-1"
        artifact.service = "iam"
        artifact.method = "get_account_summary"
        artifact.collected_at = datetime.now(UTC)
        artifact.data = {"SummaryMap": {"AccountAccessKeysPresent": 0}}

        checks = [
            {
                "control_id": "AC-2",
                "check_id": "AC-2.a",
                "assertion": "no_root_access_keys",
                "provider": "aws",
            }
        ]
        results = assessor.assess(artifacts=[artifact], checks=checks)
        assert len(results) == 1
        assert results[0].status == "pass"
        assert results[0].evidence_summary != ""
        assert "iam" in results[0].evidence_summary

    def test_assess_multiple_artifacts_same_check(self):
        """Multiple artifacts for the same check produce multiple results."""
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        assessor = ControlAssessor()

        def make_artifact(region, data):
            a = MagicMock()
            a.check_id = "AU-2.a"
            a.provider = "aws"
            a.region = region
            a.service = "cloudtrail"
            a.method = "describe_trails"
            a.collected_at = datetime.now(UTC)
            a.data = data
            return a

        artifacts = [
            make_artifact("us-east-1", {"trailList": [{"Name": "trail-1", "IsMultiRegionTrail": True}]}),
            make_artifact("eu-west-1", {"trailList": []}),
        ]
        checks = [
            {
                "control_id": "AU-2",
                "check_id": "AU-2.a",
                "assertion": "cloudtrail_enabled_all_regions",
                "provider": "aws",
            }
        ]
        results = assessor.assess(artifacts=artifacts, checks=checks)
        assert len(results) == 2
        statuses = {r.region: r.status for r in results}
        assert statuses["us-east-1"] == "pass"
        assert statuses["eu-west-1"] == "fail"

    def test_summarize_empty_results(self):
        """summarize handles empty result list without error."""
        assessor = ControlAssessor()
        summary = assessor.summarize([])
        assert summary["total_checks"] == 0
        assert summary["passed"] == 0
        assert "pass_rate" not in summary

    def test_summarize_with_errors_and_not_assessed(self):
        """summarize counts error and not_assessed statuses correctly."""
        from modules.control_assessor import AssessmentResult

        assessor = ControlAssessor()
        results = [
            AssessmentResult("AC-2", "AC-2.a", "test", "error", "aws", "us-east-1"),
            AssessmentResult("AC-2", "AC-2.b", "test", "not_assessed", "aws", "us-east-1"),
        ]
        summary = assessor.summarize(results)
        assert summary["errors"] == 1
        assert summary["not_assessed"] == 1
        assert summary["passed"] == 0
        assert summary["failed"] == 0
