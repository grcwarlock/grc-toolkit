"""
Settings API — organization settings, notifications, API keys, user management.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.routers.auth import get_current_user

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

ORG_SETTINGS = {
    "org_name": "Acme Corp",
    "org_domain": "acmecorp.com",
    "industry": "Technology",
    "company_size": "201-500",
    "timezone": "America/New_York",
    "fiscal_year_start": "January",
    "data_retention_days": 365,
    "auto_remediation": False,
    "slack_notifications": True,
    "email_notifications": True,
    "notification_email": "grc-team@acmecorp.com",
    "assessment_frequency": "weekly",
    "risk_threshold_critical": 80,
    "risk_threshold_high": 60,
    "trust_hub_enabled": True,
    "ai_reasoning_enabled": False,
}

NOTIFICATION_SETTINGS = {
    "critical_findings": True,
    "new_violations": True,
    "assessment_complete": True,
    "vendor_risk_change": True,
    "evidence_expiring": True,
    "access_requests": True,
    "weekly_digest": True,
    "channels": {
        "email": True,
        "slack": True,
        "in_app": True,
    }
}

_api_keys = [
    {
        "id": "key-001",
        "name": "CI/CD Pipeline",
        "key_preview": "grc_live_sk_...4f8a",
        "created_at": "2026-01-15T10:00:00",
        "last_used": (datetime.utcnow()).isoformat(),
        "scopes": ["evidence:write", "assessments:read"],
        "is_active": True,
    },
    {
        "id": "key-002",
        "name": "SIEM Integration",
        "key_preview": "grc_live_sk_...9c2d",
        "created_at": "2026-02-01T14:30:00",
        "last_used": (datetime.utcnow()).isoformat(),
        "scopes": ["evidence:read", "violations:read"],
        "is_active": True,
    },
]

_audit_log = [
    {"id": "al-001", "user": "admin@grc-demo.com", "action": "Updated org settings", "resource": "settings", "timestamp": (datetime.utcnow()).isoformat(), "ip": "10.0.0.1"},
    {"id": "al-002", "user": "admin@grc-demo.com", "action": "Triggered assessment run", "resource": "assessments", "timestamp": (datetime.utcnow()).isoformat(), "ip": "10.0.0.1"},
    {"id": "al-003", "user": "analyst@grc-demo.com", "action": "Exported POAM report", "resource": "exports", "timestamp": (datetime.utcnow()).isoformat(), "ip": "10.0.0.2"},
    {"id": "al-004", "user": "admin@grc-demo.com", "action": "Connected GitHub integration", "resource": "integrations", "timestamp": (datetime.utcnow()).isoformat(), "ip": "10.0.0.1"},
    {"id": "al-005", "user": "analyst@grc-demo.com", "action": "Uploaded evidence file", "resource": "evidence", "timestamp": (datetime.utcnow()).isoformat(), "ip": "10.0.0.2"},
]


class OrgSettingsUpdate(BaseModel):
    org_name: str | None = None
    org_domain: str | None = None
    industry: str | None = None
    company_size: str | None = None
    timezone: str | None = None
    fiscal_year_start: str | None = None
    data_retention_days: int | None = None
    auto_remediation: bool | None = None
    assessment_frequency: str | None = None
    risk_threshold_critical: int | None = None
    risk_threshold_high: int | None = None
    trust_hub_enabled: bool | None = None
    ai_reasoning_enabled: bool | None = None


class NotificationUpdate(BaseModel):
    critical_findings: bool | None = None
    new_violations: bool | None = None
    assessment_complete: bool | None = None
    vendor_risk_change: bool | None = None
    evidence_expiring: bool | None = None
    access_requests: bool | None = None
    weekly_digest: bool | None = None


class CreateApiKey(BaseModel):
    name: str
    scopes: list[str]


@router.get("/org")
async def get_org_settings(current_user=Depends(get_current_user)):
    return ORG_SETTINGS


@router.put("/org")
async def update_org_settings(update: OrgSettingsUpdate, current_user=Depends(get_current_user)):
    updated = update.model_dump(exclude_none=True)
    ORG_SETTINGS.update(updated)
    return ORG_SETTINGS


@router.get("/notifications")
async def get_notification_settings(current_user=Depends(get_current_user)):
    return NOTIFICATION_SETTINGS


@router.put("/notifications")
async def update_notification_settings(update: NotificationUpdate, current_user=Depends(get_current_user)):
    updated = update.model_dump(exclude_none=True)
    NOTIFICATION_SETTINGS.update(updated)
    return NOTIFICATION_SETTINGS


@router.get("/api-keys")
async def list_api_keys(current_user=Depends(get_current_user)):
    return {"keys": _api_keys, "total": len(_api_keys)}


@router.post("/api-keys")
async def create_api_key(body: CreateApiKey, current_user=Depends(get_current_user)):
    raw_key = f"grc_live_sk_{secrets.token_hex(24)}"
    key_record = {
        "id": f"key-{str(uuid.uuid4())[:8]}",
        "name": body.name,
        "key_preview": f"grc_live_sk_...{raw_key[-4:]}",
        "full_key": raw_key,
        "created_at": datetime.utcnow().isoformat(),
        "last_used": None,
        "scopes": body.scopes,
        "is_active": True,
    }
    _api_keys.append({k: v for k, v in key_record.items() if k != "full_key"})
    return {"message": "API key created. Copy it now — it will not be shown again.", "key": raw_key, "record": key_record}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, current_user=Depends(get_current_user)):
    key = next((k for k in _api_keys if k["id"] == key_id), None)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key["is_active"] = False
    _api_keys.remove(key)
    return {"message": "API key revoked"}


@router.get("/audit-log")
async def get_audit_log(current_user=Depends(get_current_user)):
    return {"log": _audit_log, "total": len(_audit_log)}
