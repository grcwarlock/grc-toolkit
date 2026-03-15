"""SSP (System Security Plan) generation & OSCAL export endpoints."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import yaml
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    OSCALExportRequest,
    OSCALExportResponse,
    SSPGenerateRequest,
    SSPResponse,
)
from api.security import require_api_key
from db.repository import AssessmentRepository

router = APIRouter(prefix="/api/v1/ssp", tags=["ssp"])


def _load_framework_controls(framework: str) -> list[dict]:
    """Load control definitions from YAML config."""
    config_dir = os.path.join(os.path.dirname(__file__), "..", "..", "config")
    framework_files = {
        "nist_800_53": "nist_800_53.yaml",
        "soc2": "soc2.yaml",
        "iso_27001": "iso_27001.yaml",
    }
    fname = framework_files.get(framework)
    if not fname:
        return []
    path = os.path.join(config_dir, fname)
    if not os.path.exists(path):
        return []
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    controls = []
    families = data.get("control_families", data.get("controls", {}))
    if isinstance(families, dict):
        for family_id, family_data in families.items():
            if isinstance(family_data, dict):
                for ctrl in family_data.get("controls", []):
                    controls.append({
                        "family": family_id,
                        "family_name": family_data.get("name", family_id),
                        **ctrl,
                    })
    return controls


def _generate_narrative(control: dict, assessment_data: dict | None = None) -> str:
    """Generate a control implementation narrative."""
    ctrl_id = control.get("id", "")
    title = control.get("title", control.get("name", ""))
    desc = control.get("description", "")

    status = "Implemented"
    if assessment_data:
        if assessment_data.get("status") == "fail":
            status = "Partially Implemented"
        elif assessment_data.get("status") == "error":
            status = "Planned"

    narrative = f"Control {ctrl_id} ({title}) is {status.lower()}. "
    if desc:
        narrative += f"This control addresses: {desc[:200]}. "

    # Generate implementation details based on control family
    family = control.get("family", "")
    impl_details = {
        "AC": "Access control policies are enforced through role-based access control (RBAC) with least-privilege principles. All access is authenticated via multi-factor authentication and logged.",
        "AU": "Audit logging is enabled across all system components. Logs are collected centrally, retained for the required period, and monitored for anomalous activity.",
        "SC": "System and communications are protected using encryption (AES-256 at rest, TLS 1.2+ in transit), network segmentation, and boundary protection mechanisms.",
        "IA": "Identification and authentication is enforced through centralized identity management with MFA, password complexity requirements, and automated account management.",
        "CM": "Configuration management follows a baseline configuration with automated compliance checking. All changes go through a formal change control process.",
        "SI": "System integrity is maintained through continuous monitoring, vulnerability scanning, patch management, and malware protection across all endpoints.",
        "IR": "Incident response capabilities include a documented IR plan, trained response team, automated detection and alerting, and regular tabletop exercises.",
        "RA": "Risk assessments are conducted regularly using quantitative methods (FAIR-based Monte Carlo simulation) to evaluate threats and inform control prioritization.",
        "CA": "Security assessments are conducted through continuous automated monitoring, periodic manual reviews, and annual third-party audits.",
        "SA": "System acquisition follows secure development lifecycle practices with security requirements, design reviews, code scanning, and supply chain risk management.",
        "CP": "Contingency planning includes documented BCP/DRP, automated backups with geographic redundancy, and regular testing of recovery procedures.",
        "PS": "Personnel security includes background checks, security awareness training, role-based training, and access review upon role change or termination.",
        "AT": "Security awareness training is provided to all personnel annually and upon onboarding. Role-specific training is provided for privileged users.",
        "MA": "System maintenance is performed through automated patch management with testing in staging environments before production deployment.",
        "MP": "Media protection policies govern the handling, transport, and sanitization of media containing sensitive information.",
        "PE": "Physical and environmental protections are managed by our cloud service providers with SOC 2 and ISO 27001 certified data centers.",
        "PL": "Security planning is documented in this SSP and supporting policies, reviewed annually, and updated to reflect system and organizational changes.",
    }
    detail = impl_details.get(family, "Implementation details are documented in supporting procedures and evidence artifacts.")
    narrative += detail

    return narrative


@router.post("/generate", response_model=SSPResponse)
async def generate_ssp(
    request: SSPGenerateRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Generate a System Security Plan from control data and assessments."""
    controls = _load_framework_controls(request.framework)

    # Get latest assessment data for implementation status
    runs = AssessmentRepository.list_runs(db, framework=request.framework, limit=1)
    assessment_map = {}
    if runs:
        results = AssessmentRepository.get_results(db, runs[0].id)
        for r in results:
            assessment_map[r.control_id] = {"status": r.status, "severity": r.severity}

    narratives = []
    implemented = 0
    for ctrl in controls:
        ctrl_id = ctrl.get("id", "")
        if request.include_controls and ctrl_id not in request.include_controls:
            continue
        assessment_data = assessment_map.get(ctrl_id)
        narrative = _generate_narrative(ctrl, assessment_data)
        status = "implemented"
        if assessment_data:
            if assessment_data["status"] == "fail":
                status = "partially_implemented"
            elif assessment_data["status"] == "error":
                status = "planned"
        else:
            status = "implemented"
        if status == "implemented":
            implemented += 1
        narratives.append({
            "control_id": ctrl_id,
            "title": ctrl.get("title", ctrl.get("name", "")),
            "family": ctrl.get("family", ""),
            "family_name": ctrl.get("family_name", ""),
            "status": status,
            "narrative": narrative,
            "responsible_role": "Information System Security Officer (ISSO)",
        })

    total = len(narratives) or 1
    return SSPResponse(
        system_name=request.system_name,
        framework=request.framework,
        security_categorization=request.security_categorization,
        generated_at=datetime.now(UTC),
        total_controls=total,
        implemented_controls=implemented,
        implementation_rate=round(implemented / total * 100, 1),
        control_narratives=narratives,
    )


@router.post("/oscal", response_model=OSCALExportResponse)
async def export_oscal(
    request: OSCALExportRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Export compliance data in OSCAL format (NIST Open Security Controls Assessment Language)."""
    now = datetime.now(UTC)

    if request.document_type == "ssp":
        controls = _load_framework_controls(request.framework)
        runs = AssessmentRepository.list_runs(db, framework=request.framework, limit=1)
        assessment_map = {}
        if runs:
            results = AssessmentRepository.get_results(db, runs[0].id)
            for r in results:
                assessment_map[r.control_id] = {"status": r.status}

        implemented_reqs = []
        for ctrl in controls:
            ctrl_id = ctrl.get("id", "")
            assessment_data = assessment_map.get(ctrl_id, {})
            impl_status = "implemented"
            if assessment_data.get("status") == "fail":
                impl_status = "partial"
            elif assessment_data.get("status") == "error":
                impl_status = "planned"
            implemented_reqs.append({
                "control-id": ctrl_id,
                "uuid": f"impl-{ctrl_id.lower().replace('.', '-').replace('(', '').replace(')', '')}",
                "description": _generate_narrative(ctrl, assessment_data),
                "implementation-status": {"state": impl_status},
            })

        document = {
            "system-security-plan": {
                "uuid": "ssp-grc-toolkit-001",
                "metadata": {
                    "title": "GRC Toolkit System Security Plan",
                    "last-modified": now.isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "system-characteristics": {
                    "system-name": "GRC Toolkit Platform",
                    "security-sensitivity-level": "moderate",
                    "system-information": {
                        "information-types": [{
                            "title": "Compliance and Audit Data",
                            "categorization": "moderate",
                        }],
                    },
                    "security-impact-level": {
                        "security-objective-confidentiality": "moderate",
                        "security-objective-integrity": "moderate",
                        "security-objective-availability": "moderate",
                    },
                    "authorization-boundary": {
                        "description": "The authorization boundary includes all components of the GRC Toolkit platform.",
                    },
                },
                "control-implementation": {
                    "description": "NIST 800-53 Rev 5 control implementation",
                    "implemented-requirements": implemented_reqs,
                },
            }
        }

    elif request.document_type == "poam":
        runs = AssessmentRepository.list_runs(db, framework=request.framework, limit=1)
        poam_items = []
        if runs:
            results = AssessmentRepository.get_results(db, runs[0].id)
            for r in results:
                if r.status == "fail":
                    poam_items.append({
                        "uuid": f"poam-{r.id[:8]}",
                        "title": f"Remediate {r.control_id}",
                        "description": r.remediation or f"Address finding for {r.control_id}",
                        "poam-item-id": r.control_id,
                        "related-findings": [{
                            "finding-id": r.id,
                            "objective-status": {"state": "not-satisfied"},
                        }],
                    })

        document = {
            "plan-of-action-and-milestones": {
                "uuid": "poam-grc-toolkit-001",
                "metadata": {
                    "title": "GRC Toolkit Plan of Action & Milestones",
                    "last-modified": now.isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "poam-items": poam_items,
            }
        }

    elif request.document_type == "assessment_results":
        runs = AssessmentRepository.list_runs(db, framework=request.framework, limit=1)
        findings = []
        if runs:
            results = AssessmentRepository.get_results(db, runs[0].id)
            for r in results:
                findings.append({
                    "uuid": f"finding-{r.id[:8]}",
                    "title": f"{r.control_id} - {r.assertion}",
                    "description": r.evidence_summary or "",
                    "target": {
                        "type": "objective-id",
                        "target-id": r.control_id,
                        "status": {"state": "satisfied" if r.status == "pass" else "not-satisfied"},
                    },
                })

        document = {
            "assessment-results": {
                "uuid": "ar-grc-toolkit-001",
                "metadata": {
                    "title": "GRC Toolkit Assessment Results",
                    "last-modified": now.isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "results": [{
                    "uuid": f"result-{runs[0].id[:8]}" if runs else "result-none",
                    "title": f"{request.framework} Assessment",
                    "start": runs[0].started_at.isoformat() if runs else now.isoformat(),
                    "end": runs[0].completed_at.isoformat() if runs and runs[0].completed_at else now.isoformat(),
                    "findings": findings,
                }],
            }
        }
    else:
        document = {"error": f"Unsupported document type: {request.document_type}"}

    return OSCALExportResponse(
        document_type=request.document_type,
        framework=request.framework,
        format=request.format,
        generated_at=now,
        oscal_version="1.1.2",
        document=document,
    )
