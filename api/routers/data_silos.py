"""
Data Silo Scanning API — discovers and classifies sensitive data
across connected sources (databases, S3, SharePoint, GitHub, etc.)
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/data-silos", tags=["data-silos"])


DATA_SILO_CATALOG = [
    {
        "id": "silo-aws-s3",
        "name": "AWS S3 — Production Buckets",
        "source_type": "cloud_storage",
        "provider": "aws",
        "icon": "aws",
        "connected": True,
        "last_scanned": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
        "status": "completed",
        "risk_level": "high",
        "total_objects": 142830,
        "flagged_objects": 47,
        "data_types": ["PII", "PHI", "Credentials"],
        "frameworks": ["HIPAA", "SOC 2", "NIST 800-53"],
        "findings": [
            {"type": "PII", "count": 31, "severity": "high", "description": "Social Security Numbers found in unencrypted CSV files"},
            {"type": "PHI", "count": 12, "severity": "critical", "description": "Patient health records in publicly accessible bucket"},
            {"type": "Credentials", "count": 4, "severity": "critical", "description": "AWS access keys committed to bucket objects"},
        ],
    },
    {
        "id": "silo-github",
        "name": "GitHub — Engineering Repos",
        "source_type": "source_control",
        "provider": "github",
        "icon": "github",
        "connected": True,
        "last_scanned": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
        "status": "completed",
        "risk_level": "medium",
        "total_objects": 58421,
        "flagged_objects": 18,
        "data_types": ["Secrets", "PII", "API Keys"],
        "frameworks": ["SOC 2", "NIST 800-53"],
        "findings": [
            {"type": "Secrets", "count": 9, "severity": "critical", "description": "Hardcoded database passwords in config files"},
            {"type": "API Keys", "count": 7, "severity": "high", "description": "Third-party API keys in environment files"},
            {"type": "PII", "count": 2, "severity": "medium", "description": "Test fixtures contain real email addresses"},
        ],
    },
    {
        "id": "silo-postgres-prod",
        "name": "PostgreSQL — Production DB",
        "source_type": "database",
        "provider": "postgresql",
        "icon": "postgresql",
        "connected": True,
        "last_scanned": (datetime.utcnow() - timedelta(days=1)).isoformat(),
        "status": "completed",
        "risk_level": "high",
        "total_objects": 2841000,
        "flagged_objects": 156,
        "data_types": ["PII", "Financial", "PHI"],
        "frameworks": ["HIPAA", "PCI DSS", "SOC 2", "NIST 800-53"],
        "findings": [
            {"type": "PII", "count": 98, "severity": "high", "description": "Customer names and emails in plaintext columns"},
            {"type": "Financial", "count": 43, "severity": "critical", "description": "Full credit card numbers stored without tokenization"},
            {"type": "PHI", "count": 15, "severity": "critical", "description": "Diagnosis codes linked to identified patients"},
        ],
    },
    {
        "id": "silo-sharepoint",
        "name": "SharePoint — Corporate Docs",
        "source_type": "document_store",
        "provider": "microsoft",
        "icon": "microsoftsqlserver",
        "connected": True,
        "last_scanned": (datetime.utcnow() - timedelta(hours=18)).isoformat(),
        "status": "completed",
        "risk_level": "medium",
        "total_objects": 34520,
        "flagged_objects": 23,
        "data_types": ["PII", "Confidential"],
        "frameworks": ["ISO 27001", "SOC 2"],
        "findings": [
            {"type": "PII", "count": 19, "severity": "medium", "description": "Employee personal data in shared HR documents"},
            {"type": "Confidential", "count": 4, "severity": "high", "description": "Board meeting notes with unrestricted access"},
        ],
    },
    {
        "id": "silo-snowflake",
        "name": "Snowflake — Analytics DW",
        "source_type": "data_warehouse",
        "provider": "snowflake",
        "icon": "snowflake",
        "connected": True,
        "last_scanned": (datetime.utcnow() - timedelta(hours=12)).isoformat(),
        "status": "completed",
        "risk_level": "low",
        "total_objects": 10200000,
        "flagged_objects": 8,
        "data_types": ["PII"],
        "frameworks": ["SOC 2", "NIST 800-53"],
        "findings": [
            {"type": "PII", "count": 8, "severity": "low", "description": "Anonymized user IDs that can be re-identified via join"},
        ],
    },
    {
        "id": "silo-slack",
        "name": "Slack — Workspace Messages",
        "source_type": "messaging",
        "provider": "slack",
        "icon": "slack",
        "connected": False,
        "last_scanned": None,
        "status": "not_configured",
        "risk_level": "unknown",
        "total_objects": 0,
        "flagged_objects": 0,
        "data_types": [],
        "frameworks": ["SOC 2"],
        "findings": [],
    },
    {
        "id": "silo-azure-blob",
        "name": "Azure Blob Storage",
        "source_type": "cloud_storage",
        "provider": "azure",
        "icon": "azure",
        "connected": False,
        "last_scanned": None,
        "status": "not_configured",
        "risk_level": "unknown",
        "total_objects": 0,
        "flagged_objects": 0,
        "data_types": [],
        "frameworks": ["SOC 2", "ISO 27001"],
        "findings": [],
    },
]

_scan_jobs: dict[str, dict] = {}


class ScanRequest(BaseModel):
    silo_id: str
    scan_depth: str | None = "standard"


@router.get("/")
async def list_data_silos(current_user=Depends(get_current_user)):
    summary = {
        "total_silos": len(DATA_SILO_CATALOG),
        "connected": sum(1 for s in DATA_SILO_CATALOG if s["connected"]),
        "total_flagged": sum(s["flagged_objects"] for s in DATA_SILO_CATALOG),
        "critical_findings": sum(
            f["count"] for s in DATA_SILO_CATALOG for f in s["findings"] if f["severity"] == "critical"
        ),
        "high_risk_silos": sum(1 for s in DATA_SILO_CATALOG if s["risk_level"] in ("high",)),
        "silos": DATA_SILO_CATALOG,
    }
    return summary


@router.get("/{silo_id}")
async def get_data_silo(silo_id: str, current_user=Depends(get_current_user)):
    silo = next((s for s in DATA_SILO_CATALOG if s["id"] == silo_id), None)
    if not silo:
        raise HTTPException(status_code=404, detail="Data silo not found")
    return silo


@router.post("/{silo_id}/scan")
async def trigger_scan(silo_id: str, current_user=Depends(get_current_user)):
    silo = next((s for s in DATA_SILO_CATALOG if s["id"] == silo_id), None)
    if not silo:
        raise HTTPException(status_code=404, detail="Data silo not found")
    if not silo["connected"]:
        raise HTTPException(status_code=400, detail="Silo not connected — configure credentials first")

    job_id = str(uuid.uuid4())
    _scan_jobs[job_id] = {
        "job_id": job_id,
        "silo_id": silo_id,
        "silo_name": silo["name"],
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "progress": 0,
    }
    silo["status"] = "scanning"
    silo["last_scanned"] = datetime.utcnow().isoformat()

    return {
        "job_id": job_id,
        "silo_id": silo_id,
        "status": "running",
        "message": f"Scan initiated for {silo['name']}",
    }


@router.get("/scan-job/{job_id}")
async def get_scan_job(job_id: str, current_user=Depends(get_current_user)):
    job = _scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    job["progress"] = min(job.get("progress", 0) + random.randint(15, 35), 100)
    if job["progress"] >= 100:
        job["status"] = "completed"
        job["completed_at"] = datetime.utcnow().isoformat()
        silo = next((s for s in DATA_SILO_CATALOG if s["id"] == job["silo_id"]), None)
        if silo:
            silo["status"] = "completed"
    return job


@router.get("/findings/summary")
async def findings_summary(current_user=Depends(get_current_user)):
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_framework: dict[str, int] = {}

    for silo in DATA_SILO_CATALOG:
        for finding in silo["findings"]:
            by_type[finding["type"]] = by_type.get(finding["type"], 0) + finding["count"]
            by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + finding["count"]
        for fw in silo["frameworks"]:
            if silo["flagged_objects"] > 0:
                by_framework[fw] = by_framework.get(fw, 0) + silo["flagged_objects"]

    return {
        "by_type": [{"type": k, "count": v} for k, v in sorted(by_type.items(), key=lambda x: -x[1])],
        "by_severity": [{"severity": k, "count": v} for k, v in sorted(by_severity.items(), key=lambda x: -x[1])],
        "by_framework": [{"framework": k, "count": v} for k, v in sorted(by_framework.items(), key=lambda x: -x[1])],
    }
