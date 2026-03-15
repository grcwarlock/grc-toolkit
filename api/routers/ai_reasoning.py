"""
AI Reasoning API — optional LLM-powered compliance analysis.

All endpoints check the global ai_reasoning_enabled setting before
processing.  When disabled, they return 403 with a clear message
directing the user to Settings.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.routers.auth import get_current_user
from api.routers.settings import ORG_SETTINGS
from db.models import User
from modules.ai_reasoning import (
    AIProvider,
    AIReasoningEngine,
    ProviderConfig,
    ReasoningRequest,
    ReasoningTask,
    demo_reason,
)

router = APIRouter(prefix="/api/v1/ai-reasoning", tags=["ai-reasoning"])


# ── In-memory history (demo) ──────────────────────────────────────────
_reasoning_history: list[dict] = []

# ── AI Reasoning settings (in-memory, mirrors pattern in settings.py) ─
AI_REASONING_SETTINGS: dict = {
    "enabled": False,
    "provider": "openai",
    "model": "",
    "api_key": "",
    "base_url": "",
    "demo_mode": True,
    "max_tokens": 2048,
    "temperature": 0.2,
}


# ── Request / Response schemas ────────────────────────────────────────

class AIReasoningSettingsUpdate(BaseModel):
    enabled: bool | None = None
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    demo_mode: bool | None = None
    max_tokens: int | None = None


class ReasoningRequestBody(BaseModel):
    task: str = Field(description="One of: control_narrative, gap_analysis, poam_narrative, evidence_mapping, risk_narrative, questionnaire_answer")
    context: dict = Field(default_factory=dict, description="Task-specific context data")
    framework: str = Field("nist_800_53", description="Target compliance framework")
    max_tokens: int = Field(2048, ge=256, le=8192)


class ReasoningResponse(BaseModel):
    id: str
    task: str
    provider: str
    model: str
    content: str
    structured: dict
    tokens_used: int
    latency_ms: int
    success: bool
    error: str
    timestamp: str


# ── Guard: check if AI reasoning is enabled ───────────────────────────

def _require_enabled():
    if not AI_REASONING_SETTINGS.get("enabled", False):
        raise HTTPException(
            status_code=403,
            detail="AI Reasoning Layer is disabled. Enable it in Settings → AI Reasoning.",
        )


def _get_provider_config() -> ProviderConfig:
    s = AI_REASONING_SETTINGS
    return ProviderConfig(
        provider=AIProvider(s.get("provider", "openai")),
        api_key=s.get("api_key", ""),
        model=s.get("model", ""),
        base_url=s.get("base_url", ""),
    )


# ── Settings endpoints ────────────────────────────────────────────────

@router.get("/settings")
async def get_ai_settings(_: User = Depends(get_current_user)):
    """Return AI Reasoning settings (API key masked)."""
    safe = {**AI_REASONING_SETTINGS}
    if safe.get("api_key"):
        key = safe["api_key"]
        safe["api_key"] = f"{key[:8]}••••••••{key[-4:]}" if len(key) > 12 else "••••••••"
    return safe


@router.put("/settings")
async def update_ai_settings(
    update: AIReasoningSettingsUpdate,
    _: User = Depends(get_current_user),
):
    """Update AI Reasoning settings."""
    updated = update.model_dump(exclude_none=True)
    AI_REASONING_SETTINGS.update(updated)
    # Also sync the enabled flag into ORG_SETTINGS for cross-module visibility
    if "enabled" in updated:
        ORG_SETTINGS["ai_reasoning_enabled"] = updated["enabled"]
    safe = {**AI_REASONING_SETTINGS}
    if safe.get("api_key"):
        key = safe["api_key"]
        safe["api_key"] = f"{key[:8]}••••••••{key[-4:]}" if len(key) > 12 else "••••••••"
    return safe


# ── Core reasoning endpoint ───────────────────────────────────────────

@router.post("/analyze", response_model=ReasoningResponse)
async def analyze(
    body: ReasoningRequestBody,
    _: User = Depends(get_current_user),
):
    """
    Run an AI reasoning task.

    Requires AI Reasoning to be enabled in settings.
    In demo_mode, returns realistic simulated responses without calling an LLM.
    """
    _require_enabled()

    try:
        task_enum = ReasoningTask(body.task)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid task '{body.task}'. Valid tasks: {[t.value for t in ReasoningTask]}",
        )

    request = ReasoningRequest(
        task=task_enum,
        context=body.context,
        framework=body.framework,
        max_tokens=body.max_tokens,
    )

    if AI_REASONING_SETTINGS.get("demo_mode", True):
        result = await demo_reason(request)
    else:
        config = _get_provider_config()
        engine = AIReasoningEngine(config)
        result = await engine.reason(request)

    entry = {
        "id": str(uuid.uuid4()),
        "task": result.task,
        "provider": result.provider,
        "model": result.model,
        "content": result.content,
        "structured": result.structured,
        "tokens_used": result.tokens_used,
        "latency_ms": result.latency_ms,
        "success": result.success,
        "error": result.error,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    _reasoning_history.insert(0, entry)
    # Keep last 100 entries
    if len(_reasoning_history) > 100:
        _reasoning_history.pop()

    return entry


# ── History endpoint ──────────────────────────────────────────────────

@router.get("/history")
async def get_history(
    limit: int = 20,
    _: User = Depends(get_current_user),
):
    """Return recent AI reasoning results."""
    return {"results": _reasoning_history[:limit], "total": len(_reasoning_history)}


# ── Available tasks metadata ──────────────────────────────────────────

TASK_METADATA = {
    "control_narrative": {
        "name": "Control Narrative",
        "description": "Generate audit-ready implementation narratives for SSP controls",
        "icon": "FileText",
        "example_context": {
            "control_id": "AC-2",
            "control_name": "Account Management",
            "control_description": "The organization manages information system accounts...",
            "evidence": ["okta_user_lifecycle_report", "access_review_Q1_2026"],
        },
    },
    "gap_analysis": {
        "name": "Gap Analysis",
        "description": "Analyze assessment findings and produce prioritized gap report",
        "icon": "Search",
        "example_context": {
            "findings": [
                {"control": "AC-12", "status": "failed", "severity": "critical"},
                {"control": "SI-4", "status": "failed", "severity": "critical"},
            ],
            "framework": "nist_800_53",
        },
    },
    "poam_narrative": {
        "name": "POA&M Narrative",
        "description": "Draft remediation plans with milestones for failed controls",
        "icon": "ClipboardList",
        "example_context": {
            "control_id": "AC-12",
            "finding": "No automated session termination on production hosts",
            "severity": "high",
        },
    },
    "evidence_mapping": {
        "name": "Evidence Mapping",
        "description": "Map collected evidence artifacts to compliance controls with rationale",
        "icon": "GitBranch",
        "example_context": {
            "evidence_items": [
                {"id": "cloudtrail_config", "type": "aws_config", "description": "CloudTrail logging configuration"},
            ],
            "target_framework": "nist_800_53",
        },
    },
    "risk_narrative": {
        "name": "Risk Narrative",
        "description": "Generate executive-level summaries from quantitative risk data",
        "icon": "TrendingUp",
        "example_context": {
            "simulation_results": {
                "mean_ale": 1870000,
                "var_95": 4200000,
                "top_scenarios": ["Ransomware", "Data Breach"],
            },
        },
    },
    "questionnaire_answer": {
        "name": "Questionnaire Answer",
        "description": "Auto-answer security questionnaire questions using compliance posture",
        "icon": "MessageSquare",
        "example_context": {
            "question": "Does the organization encrypt all data at rest?",
            "category": "Data Protection",
        },
    },
}


@router.get("/tasks")
async def get_available_tasks(_: User = Depends(get_current_user)):
    """Return metadata for all available reasoning tasks."""
    return {
        "tasks": TASK_METADATA,
        "enabled": AI_REASONING_SETTINGS.get("enabled", False),
        "provider": AI_REASONING_SETTINGS.get("provider", "openai"),
        "demo_mode": AI_REASONING_SETTINGS.get("demo_mode", True),
    }


# ── Quick test endpoint ───────────────────────────────────────────────

@router.post("/test-connection")
async def test_connection(_: User = Depends(get_current_user)):
    """Test the configured AI provider connection."""
    _require_enabled()

    if AI_REASONING_SETTINGS.get("demo_mode", True):
        return {
            "status": "success",
            "message": "Demo mode active — no external API call made.",
            "provider": "demo",
            "model": "grc-demo-v1",
        }

    config = _get_provider_config()
    if not config.is_configured:
        return {
            "status": "error",
            "message": f"Provider {config.provider.value} is not fully configured. Check API key and model.",
            "provider": config.provider.value,
            "model": config.model,
        }

    engine = AIReasoningEngine(config)
    result = await engine.reason(ReasoningRequest(
        task=ReasoningTask.CONTROL_NARRATIVE,
        context={"control_id": "TEST-1", "control_name": "Connection Test", "control_description": "Test control", "evidence": []},
        max_tokens=256,
    ))

    if result.success:
        return {
            "status": "success",
            "message": f"Successfully connected to {config.provider.value} ({config.model}). Response in {result.latency_ms}ms.",
            "provider": config.provider.value,
            "model": config.model,
            "latency_ms": result.latency_ms,
            "tokens_used": result.tokens_used,
        }
    else:
        return {
            "status": "error",
            "message": result.error,
            "provider": config.provider.value,
            "model": config.model,
        }
