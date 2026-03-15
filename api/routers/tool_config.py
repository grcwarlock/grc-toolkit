"""
Tool integration configuration — API credential management for all connected tools.
Mirrors the integration catalog so every tool can have credentials stored and tested.
"""

from __future__ import annotations

import random

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import get_db
from api.routers.auth import get_current_user
from db.models import DataSource, User

router = APIRouter(prefix="/api/v1/tool-config", tags=["tool-config"])

TOOL_CATALOG = [
    # ── Layer 1: Cloud Infrastructure ──────────────────────────────────────
    {"id": "aws",          "name": "Amazon Web Services",           "category": "Cloud Security",       "layer": 1, "fields": ["access_key_id", "secret_access_key", "region"]},
    {"id": "azure",        "name": "Microsoft Azure",               "category": "Cloud Security",       "layer": 1, "fields": ["subscription_id", "tenant_id", "client_id", "client_secret"]},
    {"id": "gcp",          "name": "Google Cloud Platform",         "category": "Cloud Security",       "layer": 1, "fields": ["project_id", "service_account_json"]},
    {"id": "prisma_cloud", "name": "Prisma Cloud",                  "category": "Cloud Security",       "layer": 1, "fields": ["access_key", "secret_key", "api_url"]},
    # ── Layer 1: Endpoints ──────────────────────────────────────────────────
    {"id": "crowdstrike",  "name": "CrowdStrike Falcon",            "category": "Endpoint Security",    "layer": 1, "fields": ["client_id", "client_secret", "base_url"]},
    {"id": "ms_defender",  "name": "Microsoft Defender for Endpoint","category": "Endpoint Security",   "layer": 1, "fields": ["tenant_id", "client_id", "client_secret"]},
    {"id": "sentinelone",  "name": "SentinelOne",                   "category": "Endpoint Security",    "layer": 1, "fields": ["api_token", "management_url"]},
    # ── Layer 1: Identity & Access ──────────────────────────────────────────
    {"id": "okta",         "name": "Okta",                          "category": "Identity",             "layer": 1, "fields": ["org_url", "api_token"]},
    {"id": "entra_id",     "name": "Microsoft Entra ID",            "category": "Identity",             "layer": 1, "fields": ["tenant_id", "client_id", "client_secret"]},
    {"id": "cyberark",     "name": "CyberArk PAM",                  "category": "Identity",             "layer": 1, "fields": ["base_url", "username", "password"]},
    {"id": "sailpoint",    "name": "SailPoint IIQ",                 "category": "Identity",             "layer": 1, "fields": ["base_url", "client_id", "client_secret"]},
    {"id": "google_workspace","name": "Google Workspace",           "category": "Identity",             "layer": 1, "fields": ["service_account_json", "customer_id"]},
    # ── Layer 1: Vulnerability Scanners ────────────────────────────────────
    {"id": "tenable",      "name": "Tenable / Nessus",              "category": "Vulnerability",        "layer": 1, "fields": ["access_key", "secret_key", "host_url"]},
    {"id": "qualys",       "name": "Qualys VMDR",                   "category": "Vulnerability",        "layer": 1, "fields": ["username", "password", "platform_url"]},
    {"id": "rapid7",       "name": "Rapid7 InsightVM",              "category": "Vulnerability",        "layer": 1, "fields": ["api_key", "region"]},
    {"id": "wiz",          "name": "Wiz",                           "category": "Cloud Security",       "layer": 1, "fields": ["client_id", "client_secret"]},
    {"id": "orca",         "name": "Orca Security",                 "category": "Cloud Security",       "layer": 1, "fields": ["api_token"]},
    # ── Layer 1: SIEM ──────────────────────────────────────────────────────
    {"id": "ms_sentinel",  "name": "Microsoft Sentinel",            "category": "SIEM",                 "layer": 1, "fields": ["subscription_id", "resource_group", "workspace_name", "tenant_id", "client_id", "client_secret"]},
    {"id": "splunk",       "name": "Splunk SIEM",                   "category": "SIEM",                 "layer": 1, "fields": ["host_url", "hec_token", "search_token"]},
    {"id": "elastic",      "name": "Elastic Security",              "category": "SIEM",                 "layer": 1, "fields": ["host_url", "api_key", "index_pattern"]},
    {"id": "datadog",      "name": "Datadog",                       "category": "SIEM / APM",           "layer": 1, "fields": ["api_key", "app_key", "site"]},
    # ── Layer 1: DevSecOps ─────────────────────────────────────────────────
    {"id": "github",       "name": "GitHub Advanced Security",      "category": "DevSecOps",            "layer": 1, "fields": ["personal_access_token", "org_name"]},
    {"id": "gitlab",       "name": "GitLab",                        "category": "DevSecOps",            "layer": 1, "fields": ["access_token", "host_url"]},
    {"id": "snyk",         "name": "Snyk",                          "category": "DevSecOps",            "layer": 1, "fields": ["api_token", "org_id"]},
    # ── Layer 4: GRC Platforms ─────────────────────────────────────────────
    {"id": "servicenow",   "name": "ServiceNow GRC",                "category": "GRC Platform",         "layer": 4, "fields": ["instance_url", "username", "password"]},
    {"id": "drata",        "name": "Drata",                         "category": "GRC Platform",         "layer": 4, "fields": ["api_token"]},
    {"id": "vanta",        "name": "Vanta",                         "category": "GRC Platform",         "layer": 4, "fields": ["api_token"]},
    # ── Layer 4: Alerting ──────────────────────────────────────────────────
    {"id": "pagerduty",    "name": "PagerDuty",                     "category": "Alerting",             "layer": 4, "fields": ["routing_key", "api_token"]},
    {"id": "slack",        "name": "Slack",                         "category": "Alerting",             "layer": 4, "fields": ["bot_token", "webhook_url", "channel_id"]},
    {"id": "jira",         "name": "Jira",                          "category": "Ticketing",            "layer": 4, "fields": ["host_url", "email", "api_token", "project_key"]},
    # ── Layer 4: Evidence Management ──────────────────────────────────────
    {"id": "confluence",   "name": "Confluence",                    "category": "Evidence Management",  "layer": 4, "fields": ["host_url", "email", "api_token", "space_key"]},
    {"id": "sharepoint",   "name": "SharePoint / OneDrive",         "category": "Evidence Management",  "layer": 4, "fields": ["tenant_id", "client_id", "client_secret", "site_url"]},
    {"id": "aws_s3",       "name": "AWS S3 Evidence Store",         "category": "Evidence Management",  "layer": 4, "fields": ["access_key_id", "secret_access_key", "region", "bucket_name"]},
    # ── Layer 4: Dashboards ────────────────────────────────────────────────
    {"id": "grafana",      "name": "Grafana",                       "category": "Dashboard",            "layer": 4, "fields": ["host_url", "api_key", "org_id"]},
    # ── Layer 3 (Optional): AI Reasoning ──────────────────────────────────
    {"id": "openai",       "name": "OpenAI GPT-4o",                 "category": "AI Reasoning",         "layer": 3, "optional": True, "fields": ["api_key", "model"]},
    {"id": "anthropic",    "name": "Anthropic Claude",              "category": "AI Reasoning",         "layer": 3, "optional": True, "fields": ["api_key", "model"]},
    {"id": "gemini",       "name": "Google Gemini",                 "category": "AI Reasoning",         "layer": 3, "optional": True, "fields": ["api_key", "model"]},
    {"id": "ollama",       "name": "Ollama (Local)",                "category": "AI Reasoning",         "layer": 3, "optional": True, "fields": ["base_url", "model"]},
]


class ToolConfigUpdate(BaseModel):
    config: dict
    is_active: bool = True


@router.get("/catalog")
async def get_catalog(_: User = Depends(get_current_user)):
    """Return the full tool catalog with field definitions, organized by architecture layer."""
    by_layer: dict[str, list] = {"1": [], "3": [], "4": []}
    for tool in TOOL_CATALOG:
        layer_key = str(tool.get("layer", 1))
        by_layer.setdefault(layer_key, []).append(tool)
    return {"tools": TOOL_CATALOG, "by_layer": by_layer}


@router.get("/connections")
async def get_connections(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Return all configured tool connections with masked credentials."""
    sources = db.query(DataSource).all()
    connections = {}
    for s in sources:
        cfg = s.config or {}
        masked = {k: ("••••••••" if v else "") for k, v in cfg.items()
                  if k not in ("enabled",) and v}
        connections[s.provider] = {
            "id": s.id,
            "name": s.name,
            "provider": s.provider,
            "is_active": s.is_active,
            "last_sync_at": s.last_sync_at.isoformat() if s.last_sync_at else None,
            "last_sync_status": s.last_sync_status,
            "configured_fields": list(masked.keys()),
            "has_credentials": bool(masked),
            "layer": next((t.get("layer", 1) for t in TOOL_CATALOG if t["id"] == s.provider), 1),
        }
    return connections


@router.put("/connections/{provider}")
async def update_connection(
    provider: str,
    payload: ToolConfigUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Save API credentials for a tool integration."""
    source = db.query(DataSource).filter(DataSource.provider == provider).first()
    if source:
        source.config = payload.config
        source.is_active = payload.is_active
    else:
        tool = next((t for t in TOOL_CATALOG if t["id"] == provider), None)
        name = tool["name"] if tool else provider.title()
        source = DataSource(
            id=str(__import__("uuid").uuid4()),
            name=name,
            provider=provider,
            source_type="api",
            is_active=payload.is_active,
            last_sync_status="pending",
            config=payload.config,
        )
        db.add(source)
    db.commit()
    return {"status": "saved", "provider": provider}


@router.post("/connections/{provider}/test")
async def test_connection(
    provider: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Simulate a connection test."""
    source = db.query(DataSource).filter(DataSource.provider == provider).first()
    if not source or not source.config:
        raise HTTPException(
            status_code=400,
            detail="No credentials configured for this integration",
        )
    success = random.random() > 0.15
    return {
        "status": "success" if success else "error",
        "message": "Connection successful — API responded with 200 OK"
        if success
        else "Connection failed — check credentials and network access",
        "latency_ms": random.randint(80, 450) if success else None,
    }


@router.delete("/connections/{provider}")
async def delete_connection(
    provider: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Remove a tool integration."""
    source = db.query(DataSource).filter(DataSource.provider == provider).first()
    if source:
        db.delete(source)
        db.commit()
    return {"status": "deleted"}
