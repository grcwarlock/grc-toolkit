"""
Customer Trust Hub API — public-facing compliance transparency portal.
No authentication required for public endpoints.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/trust", tags=["trust"])


TRUST_CONFIG = {
    "company_name": "Acme Corp",
    "company_tagline": "Building trust through transparency",
    "logo_url": None,
    "primary_color": "#3B82F6",
    "show_pass_rates": True,
    "show_last_audit": True,
    "show_evidence_requests": True,
    "published": True,
    "custom_domain": None,
    "contact_email": "security@acmecorp.com",
    "description": "Acme Corp is committed to the highest standards of security and compliance. Review our current certification status and control posture below.",
}

CERTIFICATIONS = [
    {
        "id": "cert-soc2",
        "name": "SOC 2 Type II",
        "issuer": "Deloitte & Touche LLP",
        "framework": "soc2",
        "status": "certified",
        "valid_from": "2025-01-01",
        "valid_until": "2026-01-01",
        "report_available": True,
        "description": "Our SOC 2 Type II report covers the Security, Availability, and Confidentiality trust service criteria.",
        "badge_color": "blue",
    },
    {
        "id": "cert-iso27001",
        "name": "ISO 27001:2022",
        "issuer": "BSI Group",
        "framework": "iso27001",
        "status": "certified",
        "valid_from": "2024-06-01",
        "valid_until": "2027-06-01",
        "report_available": False,
        "description": "ISO/IEC 27001 certification covering our Information Security Management System.",
        "badge_color": "green",
    },
    {
        "id": "cert-hipaa",
        "name": "HIPAA Compliance",
        "issuer": "Internal + Third-Party Audit",
        "framework": "hipaa",
        "status": "compliant",
        "valid_from": "2025-03-01",
        "valid_until": "2026-03-01",
        "report_available": True,
        "description": "Annual HIPAA compliance assessment covering Privacy Rule, Security Rule, and Breach Notification requirements.",
        "badge_color": "purple",
    },
    {
        "id": "cert-nist",
        "name": "NIST SP 800-53",
        "issuer": "Internal Assessment",
        "framework": "nist_800_53",
        "status": "in_progress",
        "valid_from": "2025-01-01",
        "valid_until": "2026-01-01",
        "report_available": False,
        "description": "Continuous monitoring against NIST SP 800-53 Rev 5 control baseline.",
        "badge_color": "orange",
    },
    {
        "id": "cert-cmmc",
        "name": "CMMC Level 2",
        "issuer": "C3PAO Assessment",
        "framework": "cmmc",
        "status": "in_progress",
        "valid_from": None,
        "valid_until": None,
        "report_available": False,
        "description": "Cybersecurity Maturity Model Certification Level 2 assessment in progress for DoD contract requirements.",
        "badge_color": "red",
    },
]

FRAMEWORK_PUBLIC_STATUS = [
    {
        "framework": "soc2",
        "display_name": "SOC 2 Type II",
        "pass_rate": 76.9,
        "total_controls": 26,
        "passing": 20,
        "last_assessed": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
        "trend": "stable",
    },
    {
        "framework": "iso27001",
        "display_name": "ISO 27001",
        "pass_rate": 57.7,
        "total_controls": 26,
        "passing": 15,
        "last_assessed": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
        "trend": "improving",
    },
    {
        "framework": "hipaa",
        "display_name": "HIPAA",
        "pass_rate": 70.8,
        "total_controls": 24,
        "passing": 17,
        "last_assessed": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
        "trend": "stable",
    },
    {
        "framework": "nist_800_53",
        "display_name": "NIST SP 800-53",
        "pass_rate": 73.7,
        "total_controls": 38,
        "passing": 28,
        "last_assessed": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
        "trend": "improving",
    },
    {
        "framework": "cmmc",
        "display_name": "CMMC Level 2",
        "pass_rate": 65.5,
        "total_controls": 28,
        "passing": 18,
        "last_assessed": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
        "trend": "improving",
    },
]

SECURITY_UPDATES = [
    {
        "date": (datetime.utcnow() - timedelta(days=2)).isoformat(),
        "title": "SOC 2 Annual Audit Completed",
        "description": "We successfully completed our annual SOC 2 Type II audit with no exceptions noted.",
        "type": "certification",
    },
    {
        "date": (datetime.utcnow() - timedelta(days=14)).isoformat(),
        "title": "Penetration Test Results Published",
        "description": "Annual third-party penetration test completed. All critical findings remediated within 48 hours.",
        "type": "security",
    },
    {
        "date": (datetime.utcnow() - timedelta(days=30)).isoformat(),
        "title": "ISO 27001 Surveillance Audit Passed",
        "description": "Passed ISO 27001 annual surveillance audit with zero non-conformances.",
        "type": "certification",
    },
    {
        "date": (datetime.utcnow() - timedelta(days=45)).isoformat(),
        "title": "MFA Enforcement Expanded",
        "description": "Mandatory MFA now enforced across all internal systems and third-party vendor access.",
        "type": "improvement",
    },
]

_access_requests: list[dict] = []


class AccessRequest(BaseModel):
    name: str
    email: str
    company: str
    report_id: str
    reason: str | None = None


class TrustConfigUpdate(BaseModel):
    company_name: str | None = None
    company_tagline: str | None = None
    show_pass_rates: bool | None = None
    show_last_audit: bool | None = None
    show_evidence_requests: bool | None = None
    published: bool | None = None
    contact_email: str | None = None
    description: str | None = None


@router.get("/public")
async def get_public_trust_hub():
    """Public endpoint — no auth required."""
    config = {**TRUST_CONFIG}
    if not config["show_pass_rates"]:
        for fw in FRAMEWORK_PUBLIC_STATUS:
            fw["pass_rate"] = None
            fw["passing"] = None
    if not config["show_last_audit"]:
        for fw in FRAMEWORK_PUBLIC_STATUS:
            fw["last_assessed"] = None

    return {
        "config": config,
        "certifications": CERTIFICATIONS,
        "framework_status": FRAMEWORK_PUBLIC_STATUS,
        "security_updates": SECURITY_UPDATES[:5],
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.post("/public/access-request")
async def request_report_access(req: AccessRequest):
    """Public endpoint — lets customers request access to audit reports."""
    record = {
        "id": f"req-{len(_access_requests)+1:04d}",
        "name": req.name,
        "email": req.email,
        "company": req.company,
        "report_id": req.report_id,
        "reason": req.reason,
        "status": "pending",
        "requested_at": datetime.utcnow().isoformat(),
    }
    _access_requests.append(record)
    return {"message": "Access request submitted. You will receive an email within 1 business day.", "request_id": record["id"]}


@router.get("/admin/config", dependencies=[Depends(get_current_user)])
async def get_trust_config():
    return TRUST_CONFIG


@router.put("/admin/config", dependencies=[Depends(get_current_user)])
async def update_trust_config(update: TrustConfigUpdate):
    updated = update.model_dump(exclude_none=True)
    TRUST_CONFIG.update(updated)
    return TRUST_CONFIG


@router.get("/admin/access-requests", dependencies=[Depends(get_current_user)])
async def list_access_requests():
    return {"requests": _access_requests, "total": len(_access_requests), "pending": sum(1 for r in _access_requests if r["status"] == "pending")}


@router.patch("/admin/access-requests/{req_id}", dependencies=[Depends(get_current_user)])
async def update_access_request(req_id: str, status: str):
    req = next((r for r in _access_requests if r["id"] == req_id), None)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    if status not in ("approved", "denied", "pending"):
        raise HTTPException(status_code=400, detail="Invalid status")
    req["status"] = status
    req["reviewed_at"] = datetime.utcnow().isoformat()
    return req
