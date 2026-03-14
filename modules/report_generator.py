"""
report_generator.py
Generates compliance reports and POA&M documents from assessment data.

Turns structured assessment results into formatted documents that
auditors and leadership can actually use, without anyone having to
manually update a 300-page SSP ever again.
"""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Template
from tabulate import tabulate

logger = logging.getLogger(__name__)


# ===================================================================
# Report Templates (Jinja2)
# ===================================================================

POAM_TEMPLATE = """
PLAN OF ACTION AND MILESTONES (POA&M)
======================================
Organization: {{ organization }}
System:       {{ system_name }}
Generated:    {{ generated_at }}
Assessment:   {{ assessment_id }}

SUMMARY
-------
Total Findings:      {{ summary.total_findings }}
Critical/High:       {{ summary.critical_high }}
Medium:              {{ summary.medium }}
Low:                 {{ summary.low }}

FINDINGS
--------
{% for finding in findings %}
-------------------------------------------------------------------------------
POA&M ID:       {{ finding.poam_id }}
Control:        {{ finding.control_id }}
Check:          {{ finding.check_id }}
Severity:       {{ finding.severity }}
Status:         {{ finding.status }}
Provider:       {{ finding.provider }} ({{ finding.region }})

Description:
{{ finding.description }}

Findings:
{% for f in finding.details %}  - {{ f }}
{% endfor %}

Remediation:    {{ finding.remediation }}
Milestone Date: {{ finding.milestone_date }}
Responsible:    {{ finding.responsible_party }}
-------------------------------------------------------------------------------
{% endfor %}

RISK ACCEPTANCE
---------------
{% if risk_acceptances %}
{% for ra in risk_acceptances %}
Control {{ ra.control_id }}: {{ ra.justification }}
Accepted by: {{ ra.accepted_by }} on {{ ra.accepted_date }}
{% endfor %}
{% else %}
No risk acceptances documented.
{% endif %}
"""

EXECUTIVE_SUMMARY_TEMPLATE = """
COMPLIANCE ASSESSMENT EXECUTIVE SUMMARY
========================================
Organization: {{ organization }}
Framework:    {{ framework }}
Date:         {{ generated_at }}

OVERALL COMPLIANCE POSTURE
--------------------------
Controls Assessed:  {{ summary.total_checks }}
Passing:            {{ summary.passed }} ({{ summary.pass_rate }})
Failing:            {{ summary.failed }}
Errors:             {{ summary.errors }}
Not Assessed:       {{ summary.not_assessed }}

COMPLIANCE BY CONTROL FAMILY
-----------------------------
{% for family, counts in summary.by_control.items() %}
{{ family }}:  {{ counts.pass }} passed | {{ counts.fail }} failed | {{ counts.error }} errors
{% endfor %}

TOP FINDINGS REQUIRING ATTENTION
---------------------------------
{% for finding in top_findings %}
{{ loop.index }}. [{{ finding.severity }}] {{ finding.control_id }} - {{ finding.assertion }}
   {{ finding.findings[0] if finding.findings else 'No detail available' }}
{% endfor %}

TREND (if prior assessments available)
------
{% if trend %}
Previous pass rate: {{ trend.previous_pass_rate }}
Current pass rate:  {{ trend.current_pass_rate }}
Direction:          {{ trend.direction }}
{% else %}
No prior assessment data available for trend comparison.
{% endif %}

RECOMMENDATIONS
---------------
{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
"""


class ReportGenerator:
    """
    Produces formatted compliance reports from assessment results.

    Supports text-based reports (for quick review and version control),
    with hooks for DOCX and XLSX generation through python-docx and
    openpyxl when formatted output is needed for stakeholders.
    """

    def __init__(self, organization: str = "", system_name: str = ""):
        self.organization = organization
        self.system_name = system_name

    def generate_poam(self, assessment_results: list[dict],
                      output_path: str, **kwargs) -> Path:
        """
        Generate a Plan of Action and Milestones document.

        Takes failing assessment results and structures them as
        actionable items with milestone dates and responsible parties.
        """
        failures = [r for r in assessment_results if r.get("status") == "fail"]

        findings = []
        for i, result in enumerate(failures, 1):
            severity = self._classify_severity(result)
            findings.append({
                "poam_id": f"POAM-{i:04d}",
                "control_id": result.get("control_id", ""),
                "check_id": result.get("check_id", ""),
                "severity": severity,
                "status": "Open",
                "provider": result.get("provider", ""),
                "region": result.get("region", ""),
                "description": result.get("evidence_summary", ""),
                "details": result.get("findings", []),
                "remediation": result.get("remediation", "See framework guidance"),
                "milestone_date": kwargs.get("default_milestone", "TBD"),
                "responsible_party": kwargs.get("default_responsible", "TBD"),
            })

        summary = {
            "total_findings": len(findings),
            "critical_high": sum(1 for f in findings if f["severity"] in ("Critical", "High")),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low"),
        }

        template = Template(POAM_TEMPLATE)
        content = template.render(
            organization=self.organization,
            system_name=self.system_name,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            assessment_id=kwargs.get("assessment_id", "N/A"),
            summary=summary,
            findings=findings,
            risk_acceptances=kwargs.get("risk_acceptances", []),
        )

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content)
        logger.info("POA&M generated: %s (%d findings)", output, len(findings))
        return output

    def generate_executive_summary(self, assessment_summary: dict,
                                   assessment_results: list[dict],
                                   output_path: str, **kwargs) -> Path:
        """
        Generate an executive summary for leadership consumption.

        Focuses on overall posture, top risks, and actionable
        recommendations rather than individual control details.
        """
        # Pull out the most important failures for the top findings section
        failures = [r for r in assessment_results if r.get("status") == "fail"]
        top_findings = sorted(
            failures,
            key=lambda x: self._severity_rank(self._classify_severity(x)),
        )[:10]

        for finding in top_findings:
            finding["severity"] = self._classify_severity(finding)

        recommendations = self._generate_recommendations(assessment_summary, failures)

        template = Template(EXECUTIVE_SUMMARY_TEMPLATE)
        content = template.render(
            organization=self.organization,
            framework=kwargs.get("framework", "NIST SP 800-53"),
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            summary=assessment_summary,
            top_findings=top_findings,
            trend=kwargs.get("trend", None),
            recommendations=recommendations,
        )

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content)
        logger.info("Executive summary generated: %s", output)
        return output

    def generate_detailed_table(self, assessment_results: list[dict]) -> str:
        """
        Generate a formatted table of all assessment results.
        Useful for quick terminal review or embedding in other docs.
        """
        rows = []
        for result in assessment_results:
            rows.append([
                result.get("control_id", ""),
                result.get("check_id", ""),
                result.get("assertion", ""),
                result.get("status", "").upper(),
                result.get("provider", ""),
                result.get("region", ""),
                (result.get("findings", [""])[0][:60] + "..."
                 if result.get("findings") and len(result["findings"][0]) > 60
                 else result.get("findings", [""])[0] if result.get("findings") else ""),
            ])

        headers = ["Control", "Check", "Assertion", "Status", "Provider", "Region", "Finding"]
        return tabulate(rows, headers=headers, tablefmt="grid")

    def export_json(self, assessment_results: list[dict],
                    summary: dict, output_path: str) -> Path:
        """Export full assessment data as JSON for integration with other tools."""
        export = {
            "metadata": {
                "organization": self.organization,
                "system": self.system_name,
                "generated_at": datetime.now(UTC).isoformat(),
                "version": "1.0",
            },
            "summary": summary,
            "results": assessment_results,
        }

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            json.dump(export, f, indent=2, default=str)

        logger.info("JSON export: %s", output)
        return output

    def _classify_severity(self, result: dict) -> str:
        """
        Classify finding severity based on control family and finding type.

        A more sophisticated version would use CVSS-like scoring,
        but for GRC purposes, mapping control families to inherent
        risk levels and adjusting based on findings works well.
        """
        control_id = result.get("control_id", "")
        findings = result.get("findings", [])
        findings_text = " ".join(findings).lower()

        # Critical: root access, unrestricted admin, no encryption
        critical_indicators = ["root", "wildcard", "0.0.0.0/0", "admin", "unencrypted"]
        if any(indicator in findings_text for indicator in critical_indicators):
            return "Critical"

        # High: core security controls failing
        high_families = {"AC", "SC", "SI", "IA"}
        family = control_id.split("-")[0] if control_id else ""
        if family in high_families:
            return "High"

        # Medium: audit and logging gaps
        medium_families = {"AU", "CA", "CM"}
        if family in medium_families:
            return "Medium"

        return "Low"

    def _severity_rank(self, severity: str) -> int:
        """Numeric rank for sorting (lower = more severe)."""
        return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(severity, 4)

    def _generate_recommendations(self, summary: dict,
                                  failures: list[dict]) -> list[str]:
        """Generate actionable recommendations based on assessment results."""
        recommendations = []

        pass_rate = summary.get("pass_rate", "0%")
        rate_num = float(pass_rate.replace("%", "")) if pass_rate else 0

        if rate_num < 50:
            recommendations.append(
                "Overall compliance posture is below 50%. Recommend a focused "
                "remediation sprint targeting Critical and High severity findings."
            )

        # Check for specific problem areas
        by_control = summary.get("by_control", {})
        for family, counts in by_control.items():
            if counts.get("fail", 0) > counts.get("pass", 0):
                recommendations.append(
                    f"Control family {family} has more failures than passes. "
                    f"Prioritize remediation in this area."
                )

        # Check for common patterns in failures
        findings_text = " ".join(
            " ".join(f.get("findings", [])) for f in failures
        ).lower()

        if "mfa" in findings_text:
            recommendations.append(
                "Multiple MFA-related findings detected. Enforce MFA across "
                "all user accounts as an immediate remediation action."
            )

        if "0.0.0.0/0" in findings_text:
            recommendations.append(
                "Unrestricted network access detected. Review all security "
                "groups and NACLs, restricting ingress to known IP ranges."
            )

        if not recommendations:
            recommendations.append(
                "Assessment shows strong compliance posture. Focus on maintaining "
                "continuous monitoring and addressing any remaining gaps."
            )

        return recommendations
