"""Assessment run and result endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    AssessmentResultResponse,
    AssessmentRunResponse,
    AssessmentTrendResponse,
    AssessmentTriggerRequest,
)
from api.security import require_api_key
from db.repository import AssessmentRepository

router = APIRouter(prefix="/api/v1/assessments", tags=["assessments"])

REMEDIATION_GUIDE: dict[str, dict] = {
    "AC-2":  {"title": "Account Management", "steps": ["Audit all active user accounts and remove stale/unused accounts", "Implement automated account provisioning and de-provisioning workflows", "Ensure accounts have documented approvals and business justifications", "Review privileged account assignments quarterly"], "references": ["NIST SP 800-53 Rev 5 AC-2", "CIS Control 5"]},
    "AC-3":  {"title": "Access Enforcement", "steps": ["Enforce least-privilege across all systems — review and reduce overly broad permissions", "Implement role-based access control (RBAC) for all applications", "Audit IAM policies for wildcard permissions (e.g., `*` actions in AWS)", "Test access controls via regular entitlement reviews"], "references": ["NIST SP 800-53 Rev 5 AC-3", "CIS Control 6"]},
    "AC-6":  {"title": "Least Privilege", "steps": ["Remove administrative rights from standard user accounts", "Implement just-in-time (JIT) access for privileged operations", "Use separate accounts for admin vs. day-to-day tasks", "Review sudo/admin group memberships monthly"], "references": ["NIST SP 800-53 Rev 5 AC-6"]},
    "AC-17": {"title": "Remote Access", "steps": ["Enforce MFA for all remote access sessions", "Terminate idle VPN sessions after 30 minutes", "Log and monitor all remote access connections", "Restrict remote access to approved devices only via certificate-based auth"], "references": ["NIST SP 800-53 Rev 5 AC-17"]},
    "AU-2":  {"title": "Event Logging", "steps": ["Enable logging on all critical systems (authentication, privilege escalation, data access)", "Configure CloudTrail / audit logs to cover all regions and services", "Ensure logs are shipped to a centralized, tamper-resistant SIEM", "Define and document minimum log retention period (90 days online, 1 year archive)"], "references": ["NIST SP 800-53 Rev 5 AU-2", "CIS Control 8"]},
    "AU-9":  {"title": "Protection of Audit Information", "steps": ["Restrict write access to log storage to authorized log aggregation services only", "Enable log integrity verification (e.g., CloudTrail log file validation)", "Store logs in a separate account or immutable storage (S3 Object Lock)", "Alert on any modification or deletion of audit logs"], "references": ["NIST SP 800-53 Rev 5 AU-9"]},
    "AU-12": {"title": "Audit Record Generation", "steps": ["Verify that all defined audit events (AU-2) are actually being captured", "Test log pipeline end-to-end — generate a test event and verify it appears in SIEM", "Enable VPC Flow Logs, DNS logs, and API gateway access logs", "Document log sources and ensure coverage gaps are identified"], "references": ["NIST SP 800-53 Rev 5 AU-12"]},
    "CM-2":  {"title": "Baseline Configuration", "steps": ["Define and document approved baseline configurations for all system types", "Implement infrastructure-as-code (Terraform/CloudFormation) to enforce baselines", "Scan for configuration drift against baselines weekly", "Store baseline configs in version-controlled repositories"], "references": ["NIST SP 800-53 Rev 5 CM-2", "CIS Control 4"]},
    "CM-6":  {"title": "Configuration Settings", "steps": ["Apply CIS Benchmarks or vendor security hardening guides to all systems", "Disable unused services, ports, and protocols", "Enforce configuration settings via policy-as-code (AWS Config rules, Azure Policy)", "Remediate non-compliant resources within SLA (critical: 24h, high: 7 days)"], "references": ["NIST SP 800-53 Rev 5 CM-6", "CIS Benchmarks"]},
    "CM-7":  {"title": "Least Functionality", "steps": ["Inventory all installed software and disable/remove unnecessary components", "Block unapproved software via allowlist (application control)", "Disable unused cloud service features and APIs", "Review and close unused network ports and protocols monthly"], "references": ["NIST SP 800-53 Rev 5 CM-7"]},
    "IA-2":  {"title": "Multi-Factor Authentication", "steps": ["Enforce MFA on all user accounts, especially privileged/admin accounts", "Use phishing-resistant MFA (FIDO2/WebAuthn) for high-risk accounts", "Remove SMS-based MFA in favor of authenticator apps or hardware keys", "Audit MFA enrollment status and force enrollment for non-compliant accounts"], "references": ["NIST SP 800-53 Rev 5 IA-2", "CISA MFA Guidance"]},
    "IA-5":  {"title": "Authenticator Management", "steps": ["Enforce minimum password complexity and length requirements (16+ chars)", "Implement password rotation policies with breach-detection checks (HaveIBeenPwned)", "Eliminate default/shared credentials across all systems", "Scan for and rotate any exposed secrets or API keys immediately"], "references": ["NIST SP 800-53 Rev 5 IA-5", "NIST SP 800-63B"]},
    "SC-7":  {"title": "Boundary Protection", "steps": ["Review all security group and firewall rules — remove `0.0.0.0/0` ingress rules", "Implement network segmentation (VPCs, subnets, NACLs) separating production from dev", "Deploy a WAF in front of all public-facing web applications", "Enable GuardDuty / Azure Defender for network threat detection"], "references": ["NIST SP 800-53 Rev 5 SC-7", "CIS Control 12"]},
    "SC-8":  {"title": "Transmission Confidentiality", "steps": ["Enforce TLS 1.2+ for all data in transit — disable TLS 1.0/1.1 and SSL", "Configure HSTS headers on all web endpoints", "Audit load balancer/CDN TLS policies and update cipher suites", "Scan for unencrypted HTTP endpoints and redirect to HTTPS"], "references": ["NIST SP 800-53 Rev 5 SC-8"]},
    "SC-28": {"title": "Protection of Information at Rest", "steps": ["Enable encryption at rest for all S3 buckets, RDS instances, and EBS volumes", "Use customer-managed KMS keys for sensitive data", "Audit and remediate unencrypted storage resources via AWS Config / Azure Policy", "Implement database-level encryption for sensitive fields (PII, PHI, financial data)"], "references": ["NIST SP 800-53 Rev 5 SC-28"]},
    "IR-4":  {"title": "Incident Handling", "steps": ["Document and test incident response procedures annually", "Establish escalation paths and communication templates for each incident type", "Conduct tabletop exercises for top 3 threat scenarios", "Integrate SIEM alerts with ticketing/on-call system for automatic escalation"], "references": ["NIST SP 800-53 Rev 5 IR-4", "NIST SP 800-61"]},
    "IR-6":  {"title": "Incident Reporting", "steps": ["Define incident classification criteria and reporting thresholds", "Configure automated alerting for critical findings to security team", "Maintain an incident log and conduct post-incident reviews", "Establish breach notification procedures per applicable regulations (GDPR, HIPAA)"], "references": ["NIST SP 800-53 Rev 5 IR-6"]},
    "SI-2":  {"title": "Flaw Remediation", "steps": ["Establish vulnerability SLAs: critical (24h), high (7 days), medium (30 days)", "Integrate vulnerability scanning into CI/CD pipeline (Snyk, Trivy, etc.)", "Maintain a patching schedule and track remediation progress", "Review open CVEs for critical services weekly"], "references": ["NIST SP 800-53 Rev 5 SI-2", "CIS Control 7"]},
    "SI-3":  {"title": "Malware Defense", "steps": ["Deploy EDR (CrowdStrike/SentinelOne) on all endpoints and servers", "Enable real-time scanning and behavioral analysis", "Configure automatic quarantine for detected malware", "Review and act on EDR alerts within 4 hours for critical detections"], "references": ["NIST SP 800-53 Rev 5 SI-3", "CIS Control 10"]},
    "CC6.1": {"title": "Logical Access Controls", "steps": ["Implement SSO + MFA for all application access", "Review and restrict user access to minimum necessary", "Audit user provisioning and de-provisioning processes", "Document access control policies and review annually"], "references": ["SOC 2 CC6.1", "ISO 27001 A.9"]},
    "CC6.6": {"title": "Unauthorized Access Prevention", "steps": ["Enable intrusion detection and prevention systems", "Monitor for unauthorized access attempts and anomalous login patterns", "Implement geofencing or IP allowlisting for sensitive systems", "Review failed login reports daily"], "references": ["SOC 2 CC6.6"]},
    "CC7.2": {"title": "System Monitoring", "steps": ["Deploy SIEM with correlation rules for critical threat scenarios", "Configure alerts for baseline deviations (unusual access times, data exfiltration patterns)", "Review security dashboard daily and investigate anomalies within 2 hours", "Document monitoring procedures and assign ownership"], "references": ["SOC 2 CC7.2"]},
}


def _enrich_remediation(control_id: str, existing: str | None) -> dict:
    guide = REMEDIATION_GUIDE.get(control_id)
    if guide:
        return {
            "title": guide["title"],
            "steps": guide["steps"],
            "references": guide["references"],
            "raw": existing,
        }
    prefix = control_id.split("-")[0].split(".")[0].upper()
    generic_map = {
        "AC": "Review and tighten access control policies, enforce least privilege, and audit user account lifecycles.",
        "AU": "Verify audit logging is enabled, centralized, and retained per policy.",
        "CM": "Compare current configuration against approved baseline and remediate drift.",
        "IA": "Enforce MFA, review credential policies, and rotate any exposed secrets.",
        "SC": "Review network segmentation, encryption in transit/at rest, and boundary controls.",
        "SI": "Apply patches within SLA windows and verify malware defenses are active.",
        "IR": "Test incident response procedures and ensure escalation paths are documented.",
        "CA": "Schedule and complete the required assessment activity and document results.",
        "RA": "Conduct or update the risk assessment to reflect current threat landscape.",
        "SA": "Review system/service acquisition security requirements and vendor assessments.",
        "PE": "Audit physical access controls and visitor logs.",
        "PS": "Review personnel security policies including background checks and offboarding.",
    }
    desc = generic_map.get(prefix, "Review the applicable control requirement and develop a remediation plan.")
    return {
        "title": control_id,
        "steps": [
            f"Review the full control requirement for {control_id}",
            desc,
            "Document findings and assign a responsible owner with a due date",
            "Re-assess after remediation to confirm the control is passing",
        ],
        "references": [f"NIST SP 800-53 Rev 5 {control_id}"],
        "raw": existing,
    }


@router.get("/remediation/{control_id}")
async def get_remediation(control_id: str, api_key: str = Depends(require_api_key)):
    """Return detailed remediation guidance for a control ID."""
    return _enrich_remediation(control_id, None)


@router.post("/run", response_model=AssessmentRunResponse, status_code=202)
async def trigger_assessment(
    request: AssessmentTriggerRequest, db: Session = Depends(get_db), api_key: str = Depends(require_api_key),
):
    """Trigger a compliance assessment run.

    Returns 202 Accepted — assessment runs asynchronously.
    """
    run = AssessmentRepository.create_run(
        db, framework=request.framework, triggered_by="api"
    )
    return AssessmentRunResponse(
        id=run.id,
        framework=run.framework,
        started_at=run.started_at,
        status=run.status,
    )


@router.get("/runs", response_model=list[AssessmentRunResponse])
async def list_runs(
    framework: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    runs = AssessmentRepository.list_runs(db, framework=framework, limit=limit)
    return [
        AssessmentRunResponse(
            id=r.id, framework=r.framework, started_at=r.started_at,
            completed_at=r.completed_at, status=r.status,
            total_checks=r.total_checks, passed=r.passed,
            failed=r.failed, errors=r.errors, pass_rate=r.pass_rate,
            summary=r.summary,
        )
        for r in runs
    ]


@router.get("/runs/{run_id}", response_model=AssessmentRunResponse)
async def get_run(run_id: str, db: Session = Depends(get_db), api_key: str = Depends(require_api_key)):
    run = AssessmentRepository.get_run(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Assessment run not found")
    return AssessmentRunResponse(
        id=run.id, framework=run.framework, started_at=run.started_at,
        completed_at=run.completed_at, status=run.status,
        total_checks=run.total_checks, passed=run.passed,
        failed=run.failed, errors=run.errors, pass_rate=run.pass_rate,
        summary=run.summary,
    )


@router.get("/runs/{run_id}/results", response_model=list[AssessmentResultResponse])
async def get_results(run_id: str, db: Session = Depends(get_db), api_key: str = Depends(require_api_key)):
    results = AssessmentRepository.get_results(db, run_id)
    return [
        AssessmentResultResponse(
            id=r.id, control_id=r.control_id, check_id=r.check_id,
            assertion=r.assertion, status=r.status, severity=r.severity,
            provider=r.provider, region=r.region, findings=r.findings,
            remediation=r.remediation,
            remediation_steps=r.remediation_steps or [],
            console_path=r.console_path,
            assessed_at=r.assessed_at,
        )
        for r in results
    ]


@router.get("/trend", response_model=AssessmentTrendResponse)
async def get_trend(
    framework: str = Query("nist_800_53"),
    last_n: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    trend = AssessmentRepository.get_trend(db, framework=framework, last_n=last_n)
    return AssessmentTrendResponse(runs=trend)
