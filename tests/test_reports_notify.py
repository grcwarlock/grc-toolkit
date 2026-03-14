"""Tests for the report generator and notification modules."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from modules.notify import send_email_digest, send_slack_alert
from modules.report_generator import ReportGenerator

# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def generator():
    return ReportGenerator(organization="Acme Corp", system_name="WidgetApp")


@pytest.fixture
def failing_result_root():
    return {
        "control_id": "AC-6",
        "check_id": "ac-6-root-check",
        "status": "fail",
        "provider": "aws",
        "region": "us-east-1",
        "assertion": "No root access keys",
        "evidence_summary": "Root access keys found",
        "findings": ["Root access key is active for account"],
        "remediation": "Delete root access keys",
    }


@pytest.fixture
def failing_result_network():
    return {
        "control_id": "SC-7",
        "check_id": "sc-7-sg-check",
        "status": "fail",
        "provider": "aws",
        "region": "us-west-2",
        "assertion": "No unrestricted ingress",
        "evidence_summary": "Security group allows unrestricted ingress",
        "findings": ["Security group sg-123 allows 0.0.0.0/0 on port 22"],
        "remediation": "Restrict ingress to known CIDR blocks",
    }


@pytest.fixture
def passing_result():
    return {
        "control_id": "PE-1",
        "check_id": "pe-1-check",
        "status": "pass",
        "provider": "aws",
        "region": "us-east-1",
        "assertion": "Physical protection policy exists",
        "evidence_summary": "Policy document found",
        "findings": [],
    }


@pytest.fixture
def assessment_summary():
    return {
        "total_checks": 50,
        "passed": 40,
        "failed": 8,
        "errors": 2,
        "not_assessed": 0,
        "pass_rate": "80%",
        "by_control": {
            "AC": {"pass": 10, "fail": 3, "error": 0},
            "SC": {"pass": 8, "fail": 2, "error": 1},
            "AU": {"pass": 5, "fail": 1, "error": 0},
            "PE": {"pass": 4, "fail": 0, "error": 0},
        },
    }


@pytest.fixture
def smtp_config():
    return {
        "server": "smtp.example.com",
        "port": 587,
        "sender": "grc@example.com",
    }


# ===================================================================
# ReportGenerator._classify_severity
# ===================================================================

class TestClassifySeverity:

    def test_critical_root(self, generator):
        result = {"control_id": "AC-2", "findings": ["Root access key enabled"]}
        assert generator._classify_severity(result) == "Critical"

    def test_critical_network(self, generator):
        result = {"control_id": "SC-7", "findings": ["Allows 0.0.0.0/0 ingress"]}
        assert generator._classify_severity(result) == "Critical"

    def test_critical_unencrypted(self, generator):
        result = {"control_id": "SC-28", "findings": ["Volume is unencrypted"]}
        assert generator._classify_severity(result) == "Critical"

    def test_critical_wildcard(self, generator):
        result = {"control_id": "AC-6", "findings": ["Policy uses wildcard actions"]}
        assert generator._classify_severity(result) == "Critical"

    def test_critical_admin(self, generator):
        result = {"control_id": "AC-6", "findings": ["User has admin privileges"]}
        assert generator._classify_severity(result) == "Critical"

    def test_high_ac_family(self, generator):
        result = {"control_id": "AC-2", "findings": ["Inactive user found"]}
        assert generator._classify_severity(result) == "High"

    def test_high_sc_family(self, generator):
        result = {"control_id": "SC-12", "findings": ["Certificate expiring soon"]}
        assert generator._classify_severity(result) == "High"

    def test_medium_au_family(self, generator):
        result = {"control_id": "AU-2", "findings": ["Logging not enabled"]}
        assert generator._classify_severity(result) == "Medium"

    def test_medium_cm_family(self, generator):
        result = {"control_id": "CM-6", "findings": ["Config baseline drift"]}
        assert generator._classify_severity(result) == "Medium"

    def test_low_other_family(self, generator):
        result = {"control_id": "PE-3", "findings": ["Badge reader offline"]}
        assert generator._classify_severity(result) == "Low"

    def test_no_control_id_no_findings(self, generator):
        result = {"control_id": "", "findings": []}
        assert generator._classify_severity(result) == "Low"


# ===================================================================
# ReportGenerator._severity_rank
# ===================================================================

class TestSeverityRank:

    def test_critical(self, generator):
        assert generator._severity_rank("Critical") == 0

    def test_high(self, generator):
        assert generator._severity_rank("High") == 1

    def test_medium(self, generator):
        assert generator._severity_rank("Medium") == 2

    def test_low(self, generator):
        assert generator._severity_rank("Low") == 3

    def test_unknown(self, generator):
        assert generator._severity_rank("Banana") == 4


# ===================================================================
# ReportGenerator.generate_poam
# ===================================================================

class TestGeneratePoam:

    def test_basic_poam(self, generator, failing_result_root, passing_result, tmp_path):
        results = [failing_result_root, passing_result]
        out = tmp_path / "poam.txt"
        path = generator.generate_poam(results, str(out))
        assert path.exists()
        content = path.read_text()
        assert "POA&M" in content
        assert "Acme Corp" in content
        assert "POAM-0001" in content
        assert "AC-6" in content or "ac-6-root-check" in content

    def test_poam_no_failures(self, generator, passing_result, tmp_path):
        out = tmp_path / "poam_empty.txt"
        path = generator.generate_poam([passing_result], str(out))
        assert path.exists()
        content = path.read_text()
        assert "Total Findings:      0" in content

    def test_poam_with_kwargs(self, generator, failing_result_root, tmp_path):
        out = tmp_path / "poam_kwargs.txt"
        risk_acc = [{
            "control_id": "AC-6",
            "justification": "Accepted risk for legacy system",
            "accepted_by": "CISO",
            "accepted_date": "2025-12-01",
        }]
        path = generator.generate_poam(
            [failing_result_root],
            str(out),
            default_milestone="2026-06-01",
            default_responsible="Security Team",
            risk_acceptances=risk_acc,
            assessment_id="ASSESS-001",
        )
        content = path.read_text()
        assert "2026-06-01" in content
        assert "Security Team" in content
        assert "ASSESS-001" in content
        assert "Accepted risk for legacy system" in content
        assert "CISO" in content

    def test_poam_multiple_failures_sorted(self, generator, failing_result_root,
                                           failing_result_network, tmp_path):
        out = tmp_path / "poam_multi.txt"
        path = generator.generate_poam(
            [failing_result_root, failing_result_network], str(out)
        )
        content = path.read_text()
        assert "POAM-0001" in content
        assert "POAM-0002" in content


# ===================================================================
# ReportGenerator.generate_executive_summary
# ===================================================================

class TestGenerateExecutiveSummary:

    def test_basic_summary(self, generator, assessment_summary,
                           failing_result_root, passing_result, tmp_path):
        out = tmp_path / "exec_summary.txt"
        results = [failing_result_root, passing_result]
        path = generator.generate_executive_summary(
            assessment_summary, results, str(out)
        )
        assert path.exists()
        content = path.read_text()
        assert "EXECUTIVE SUMMARY" in content
        assert "Acme Corp" in content
        assert "80%" in content
        assert "NIST SP 800-53" in content

    def test_summary_with_trend(self, generator, assessment_summary,
                                failing_result_root, tmp_path):
        out = tmp_path / "exec_trend.txt"
        trend = {
            "previous_pass_rate": "70%",
            "current_pass_rate": "80%",
            "direction": "Improving",
        }
        path = generator.generate_executive_summary(
            assessment_summary, [failing_result_root], str(out), trend=trend
        )
        content = path.read_text()
        assert "70%" in content
        assert "Improving" in content

    def test_summary_no_trend(self, generator, assessment_summary, tmp_path):
        out = tmp_path / "exec_no_trend.txt"
        path = generator.generate_executive_summary(
            assessment_summary, [], str(out)
        )
        content = path.read_text()
        assert "No prior assessment data" in content


# ===================================================================
# ReportGenerator._generate_recommendations
# ===================================================================

class TestGenerateRecommendations:

    def test_low_pass_rate(self, generator):
        summary = {"pass_rate": "40%", "by_control": {}}
        recs = generator._generate_recommendations(summary, [])
        assert any("below 50%" in r for r in recs)

    def test_family_more_fails_than_passes(self, generator):
        summary = {
            "pass_rate": "60%",
            "by_control": {"AC": {"pass": 2, "fail": 5}},
        }
        recs = generator._generate_recommendations(summary, [])
        assert any("AC" in r and "more failures" in r for r in recs)

    def test_mfa_finding(self, generator):
        summary = {"pass_rate": "80%", "by_control": {}}
        failures = [{"findings": ["MFA is not enabled for user"]}]
        recs = generator._generate_recommendations(summary, failures)
        assert any("MFA" in r for r in recs)

    def test_unrestricted_network(self, generator):
        summary = {"pass_rate": "80%", "by_control": {}}
        failures = [{"findings": ["Security group allows 0.0.0.0/0"]}]
        recs = generator._generate_recommendations(summary, failures)
        assert any("Unrestricted network" in r for r in recs)

    def test_good_posture(self, generator):
        summary = {"pass_rate": "95%", "by_control": {"PE": {"pass": 5, "fail": 0}}}
        recs = generator._generate_recommendations(summary, [])
        assert any("strong compliance posture" in r for r in recs)


# ===================================================================
# ReportGenerator.generate_detailed_table
# ===================================================================

class TestGenerateDetailedTable:

    def test_returns_grid(self, generator, failing_result_root, passing_result):
        table = generator.generate_detailed_table([failing_result_root, passing_result])
        assert isinstance(table, str)
        assert "+" in table  # grid format uses + for corners
        assert "Control" in table
        assert "FAIL" in table
        assert "PASS" in table

    def test_empty_results(self, generator):
        table = generator.generate_detailed_table([])
        assert isinstance(table, str)
        assert "Control" in table

    def test_long_finding_truncated(self, generator):
        result = {
            "control_id": "AC-2",
            "check_id": "ac-2-check",
            "assertion": "Test",
            "status": "fail",
            "provider": "aws",
            "region": "us-east-1",
            "findings": ["A" * 100],
        }
        table = generator.generate_detailed_table([result])
        # Finding should be truncated to 60 chars + "..."
        assert "..." in table


# ===================================================================
# ReportGenerator.export_json
# ===================================================================

class TestExportJson:

    def test_valid_json(self, generator, assessment_summary,
                        failing_result_root, tmp_path):
        out = tmp_path / "export.json"
        path = generator.export_json(
            [failing_result_root], assessment_summary, str(out)
        )
        assert path.exists()
        data = json.loads(path.read_text())
        assert "metadata" in data
        assert "summary" in data
        assert "results" in data
        assert data["metadata"]["organization"] == "Acme Corp"
        assert data["metadata"]["system"] == "WidgetApp"
        assert data["metadata"]["version"] == "1.0"
        assert len(data["results"]) == 1

    def test_creates_parent_dirs(self, generator, tmp_path):
        out = tmp_path / "sub" / "dir" / "export.json"
        path = generator.export_json([], {}, str(out))
        assert path.exists()


# ===================================================================
# send_slack_alert
# ===================================================================

class TestSendSlackAlert:

    @patch("modules.notify.requests.post")
    def test_green_high_pass_rate(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        summary = {"pass_rate": "95%", "total_checks": 50, "passed": 47, "failed": 3}
        send_slack_alert("https://hooks.slack.com/test", summary, [])
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["attachments"][0]["color"] == "#36a64f"

    @patch("modules.notify.requests.post")
    def test_yellow_medium_pass_rate(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        summary = {"pass_rate": "75%", "total_checks": 40, "passed": 30, "failed": 10}
        send_slack_alert("https://hooks.slack.com/test", summary, [])
        payload = mock_post.call_args[1]["json"]
        assert payload["attachments"][0]["color"] == "#ff9900"

    @patch("modules.notify.requests.post")
    def test_red_low_pass_rate(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        summary = {"pass_rate": "50%", "total_checks": 40, "passed": 20, "failed": 20}
        send_slack_alert("https://hooks.slack.com/test", summary, [])
        payload = mock_post.call_args[1]["json"]
        assert payload["attachments"][0]["color"] == "#ff0000"

    @patch("modules.notify.requests.post")
    def test_with_failures(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        summary = {"pass_rate": "60%", "total_checks": 10, "passed": 6, "failed": 4}
        failures = [
            {"control_id": "AC-2", "check_id": "ac-2-check",
             "findings": ["User has no MFA"]},
        ]
        send_slack_alert("https://hooks.slack.com/test", summary, failures)
        payload = mock_post.call_args[1]["json"]
        blocks = payload["attachments"][0]["blocks"]
        assert len(blocks) == 3  # header + section + findings
        assert "Top Findings" in blocks[2]["text"]["text"]

    @patch("modules.notify.requests.post")
    def test_with_empty_failures(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        summary = {"pass_rate": "90%", "total_checks": 10, "passed": 9, "failed": 1}
        send_slack_alert("https://hooks.slack.com/test", summary, [])
        payload = mock_post.call_args[1]["json"]
        blocks = payload["attachments"][0]["blocks"]
        assert len(blocks) == 2  # header + section only

    @patch("modules.notify.requests.post")
    def test_request_exception_caught(self, mock_post):
        import requests as req
        mock_post.side_effect = req.RequestException("Connection refused")
        summary = {"pass_rate": "80%", "total_checks": 10, "passed": 8, "failed": 2}
        # Should not raise
        send_slack_alert("https://hooks.slack.com/test", summary, [])

    @patch("modules.notify.requests.post")
    def test_boundary_90_is_green(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        summary = {"pass_rate": "90%", "total_checks": 10, "passed": 9, "failed": 1}
        send_slack_alert("https://hooks.slack.com/test", summary, [])
        payload = mock_post.call_args[1]["json"]
        assert payload["attachments"][0]["color"] == "#36a64f"

    @patch("modules.notify.requests.post")
    def test_boundary_70_is_yellow(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        summary = {"pass_rate": "70%", "total_checks": 10, "passed": 7, "failed": 3}
        send_slack_alert("https://hooks.slack.com/test", summary, [])
        payload = mock_post.call_args[1]["json"]
        assert payload["attachments"][0]["color"] == "#ff9900"


# ===================================================================
# send_email_digest
# ===================================================================

class TestSendEmailDigest:

    def test_no_password_returns_early(self, monkeypatch, smtp_config):
        monkeypatch.delenv("GRC_SMTP_PASSWORD", raising=False)
        with patch("modules.notify.smtplib.SMTP") as mock_smtp:
            send_email_digest(smtp_config, {"pass_rate": "80%", "failed": 2,
                              "total_checks": 10, "passed": 8, "errors": 0},
                              ["admin@example.com"])
            mock_smtp.assert_not_called()

    @patch("modules.notify.smtplib.SMTP")
    def test_sends_with_password(self, mock_smtp_cls, monkeypatch, smtp_config):
        monkeypatch.setenv("GRC_SMTP_PASSWORD", "s3cret")
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
        summary = {
            "pass_rate": "80%", "total_checks": 10, "passed": 8,
            "failed": 2, "errors": 0, "by_control": {},
        }
        send_email_digest(smtp_config, summary, ["admin@example.com"])
        mock_smtp_cls.assert_called_once_with("smtp.example.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("grc@example.com", "s3cret")
        mock_server.sendmail.assert_called_once()
        args = mock_server.sendmail.call_args[0]
        assert args[0] == "grc@example.com"
        assert args[1] == ["admin@example.com"]

    @patch("modules.notify.smtplib.SMTP")
    def test_email_with_failures(self, mock_smtp_cls, monkeypatch, smtp_config):
        monkeypatch.setenv("GRC_SMTP_PASSWORD", "s3cret")
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
        summary = {
            "pass_rate": "70%", "total_checks": 10, "passed": 7,
            "failed": 3, "errors": 0, "by_control": {},
        }
        failures = [
            {"control_id": "AC-2", "findings": ["User without MFA"]},
            {"control_id": "SC-7", "findings": ["Open security group"]},
        ]
        send_email_digest(smtp_config, summary, ["a@b.com"], failures=failures)
        sent_msg = mock_server.sendmail.call_args[0][2]
        assert "Top Findings" in sent_msg
        assert "AC-2" in sent_msg

    @patch("modules.notify.smtplib.SMTP")
    def test_smtp_exception_caught(self, mock_smtp_cls, monkeypatch, smtp_config):
        monkeypatch.setenv("GRC_SMTP_PASSWORD", "s3cret")
        mock_smtp_cls.return_value.__enter__ = MagicMock(
            side_effect=Exception("Connection timeout")
        )
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
        summary = {
            "pass_rate": "80%", "total_checks": 10, "passed": 8,
            "failed": 2, "errors": 0, "by_control": {},
        }
        # Should not raise
        send_email_digest(smtp_config, summary, ["admin@example.com"])
