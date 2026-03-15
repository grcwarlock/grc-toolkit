"""
ai_reasoning.py
Optional AI Reasoning Layer for GRC Toolkit.

Calls a configured LLM provider (OpenAI, Anthropic, Gemini, or Ollama)
to perform compliance-focused reasoning tasks:
  - Control narrative generation for SSPs
  - Gap analysis summaries from assessment findings
  - POA&M remediation narrative drafting
  - Evidence-to-control mapping rationale
  - Risk analysis narrative summaries

The layer is gated behind a settings toggle — it does nothing unless
explicitly enabled by an admin via Settings → AI Reasoning.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum

import httpx

logger = logging.getLogger(__name__)


# ── Types ──────────────────────────────────────────────────────────────

class AIProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"


class ReasoningTask(str, Enum):
    CONTROL_NARRATIVE = "control_narrative"
    GAP_ANALYSIS = "gap_analysis"
    POAM_NARRATIVE = "poam_narrative"
    EVIDENCE_MAPPING = "evidence_mapping"
    RISK_NARRATIVE = "risk_narrative"
    QUESTIONNAIRE_ANSWER = "questionnaire_answer"


@dataclass
class ProviderConfig:
    provider: AIProvider
    api_key: str = ""
    model: str = ""
    base_url: str = ""

    @property
    def is_configured(self) -> bool:
        if self.provider == AIProvider.OLLAMA:
            return bool(self.base_url and self.model)
        return bool(self.api_key and self.model)


@dataclass
class ReasoningRequest:
    task: ReasoningTask
    context: dict = field(default_factory=dict)
    framework: str = "nist_800_53"
    max_tokens: int = 2048


@dataclass
class ReasoningResult:
    task: str
    provider: str
    model: str
    content: str
    structured: dict = field(default_factory=dict)
    tokens_used: int = 0
    latency_ms: int = 0
    success: bool = True
    error: str = ""


# ── System prompts per task ────────────────────────────────────────────

SYSTEM_PROMPTS: dict[ReasoningTask, str] = {
    ReasoningTask.CONTROL_NARRATIVE: (
        "You are a GRC compliance engineer writing control implementation narratives "
        "for a System Security Plan (SSP). Given a control ID, control description, "
        "and implementation evidence, produce a concise, audit-ready narrative that "
        "describes HOW the organization implements the control. Use factual, specific "
        "language referencing the evidence provided. Output JSON with keys: "
        '"narrative", "implementation_status" (implemented|partially_implemented|planned|not_applicable), '
        '"evidence_references" (list of strings).'
    ),
    ReasoningTask.GAP_ANALYSIS: (
        "You are a GRC analyst performing gap analysis. Given assessment findings "
        "(failed controls, severity, evidence), produce a structured gap analysis. "
        "Prioritize gaps by risk impact. Output JSON with keys: "
        '"summary", "critical_gaps" (list), "high_gaps" (list), "recommendations" (list), '
        '"estimated_remediation_effort" (string).'
    ),
    ReasoningTask.POAM_NARRATIVE: (
        "You are a GRC engineer drafting a Plan of Action & Milestones (POA&M) entry. "
        "Given a failed control finding with severity and evidence, produce a structured "
        "POA&M narrative. Output JSON with keys: "
        '"weakness_description", "risk_level", "remediation_plan", "milestones" (list of '
        '{"milestone", "target_date_offset_days"}), "resources_required", "estimated_completion_days".'
    ),
    ReasoningTask.EVIDENCE_MAPPING: (
        "You are a GRC analyst mapping collected evidence to compliance controls. "
        "Given evidence artifacts and a target framework, determine which controls "
        "each piece of evidence satisfies and the confidence level. Output JSON with keys: "
        '"mappings" (list of {"evidence_id", "control_id", "confidence", "rationale"}).'
    ),
    ReasoningTask.RISK_NARRATIVE: (
        "You are a risk analyst producing executive-level risk summaries. "
        "Given quantitative risk simulation results (Monte Carlo outputs), produce "
        "a narrative suitable for a board presentation. Output JSON with keys: "
        '"executive_summary", "key_risks" (list), "risk_appetite_alignment", "recommended_actions" (list).'
    ),
    ReasoningTask.QUESTIONNAIRE_ANSWER: (
        "You are a GRC analyst answering a security questionnaire on behalf of "
        "the organization. Given a question, the organization's compliance posture, "
        "and relevant evidence, produce an accurate answer. Output JSON with keys: "
        '"answer", "confidence" (high|medium|low), "evidence_references" (list), "notes" (string).'
    ),
}


# ── Provider call implementations ──────────────────────────────────────

async def _call_openai(config: ProviderConfig, system: str, user_msg: str, max_tokens: int) -> dict:
    """Call OpenAI Chat Completions API."""
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {config.api_key}"},
            json={
                "model": config.model or "gpt-4o",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
            },
        )
        resp.raise_for_status()
        data = resp.json()
        choice = data["choices"][0]["message"]
        return {
            "content": choice["content"],
            "tokens": data.get("usage", {}).get("total_tokens", 0),
        }


async def _call_anthropic(config: ProviderConfig, system: str, user_msg: str, max_tokens: int) -> dict:
    """Call Anthropic Messages API."""
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": config.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": config.model or "claude-sonnet-4-20250514",
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user_msg}],
                "temperature": 0.2,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        content = data["content"][0]["text"]
        tokens = data.get("usage", {})
        return {
            "content": content,
            "tokens": tokens.get("input_tokens", 0) + tokens.get("output_tokens", 0),
        }


async def _call_gemini(config: ProviderConfig, system: str, user_msg: str, max_tokens: int) -> dict:
    """Call Google Gemini generateContent API."""
    model = config.model or "gemini-1.5-pro"
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            params={"key": config.api_key},
            json={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"parts": [{"text": user_msg}]}],
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                    "temperature": 0.2,
                    "responseMimeType": "application/json",
                },
            },
        )
        resp.raise_for_status()
        data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        tokens = data.get("usageMetadata", {}).get("totalTokenCount", 0)
        return {"content": text, "tokens": tokens}


async def _call_ollama(config: ProviderConfig, system: str, user_msg: str, max_tokens: int) -> dict:
    """Call Ollama local REST API (OpenAI-compatible endpoint)."""
    base = config.base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            f"{base}/api/chat",
            json={
                "model": config.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg},
                ],
                "stream": False,
                "options": {"num_predict": max_tokens, "temperature": 0.2},
                "format": "json",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        content = data.get("message", {}).get("content", "")
        tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)
        return {"content": content, "tokens": tokens}


PROVIDER_HANDLERS = {
    AIProvider.OPENAI: _call_openai,
    AIProvider.ANTHROPIC: _call_anthropic,
    AIProvider.GEMINI: _call_gemini,
    AIProvider.OLLAMA: _call_ollama,
}


# ── Main engine ────────────────────────────────────────────────────────

class AIReasoningEngine:
    """
    Orchestrates AI reasoning calls for GRC tasks.

    Usage:
        engine = AIReasoningEngine(config)
        result = await engine.reason(request)
    """

    def __init__(self, config: ProviderConfig):
        self.config = config

    def _build_user_message(self, request: ReasoningRequest) -> str:
        """Serialize request context into a structured user message."""
        parts = [f"Framework: {request.framework}"]
        for key, value in request.context.items():
            if isinstance(value, (dict, list)):
                parts.append(f"{key}: {json.dumps(value, default=str)}")
            else:
                parts.append(f"{key}: {value}")
        return "\n".join(parts)

    async def reason(self, request: ReasoningRequest) -> ReasoningResult:
        """Execute a reasoning task against the configured provider."""
        handler = PROVIDER_HANDLERS.get(self.config.provider)
        if not handler:
            return ReasoningResult(
                task=request.task.value,
                provider=self.config.provider.value,
                model=self.config.model,
                content="",
                success=False,
                error=f"Unsupported provider: {self.config.provider}",
            )

        if not self.config.is_configured:
            return ReasoningResult(
                task=request.task.value,
                provider=self.config.provider.value,
                model=self.config.model,
                content="",
                success=False,
                error="Provider not fully configured — check API key and model in Tool Config.",
            )

        system_prompt = SYSTEM_PROMPTS.get(request.task, "You are a helpful GRC compliance assistant.")
        user_message = self._build_user_message(request)

        start = time.monotonic()
        try:
            raw = await handler(self.config, system_prompt, user_message, request.max_tokens)
            latency = int((time.monotonic() - start) * 1000)

            content = raw["content"]
            # Try to parse as JSON for structured output
            structured = {}
            try:
                structured = json.loads(content)
            except (json.JSONDecodeError, TypeError):
                pass

            return ReasoningResult(
                task=request.task.value,
                provider=self.config.provider.value,
                model=self.config.model,
                content=content,
                structured=structured,
                tokens_used=raw.get("tokens", 0),
                latency_ms=latency,
            )

        except httpx.HTTPStatusError as exc:
            latency = int((time.monotonic() - start) * 1000)
            error_body = exc.response.text[:500]
            logger.error("AI provider %s returned %s: %s", self.config.provider, exc.response.status_code, error_body)
            return ReasoningResult(
                task=request.task.value,
                provider=self.config.provider.value,
                model=self.config.model,
                content="",
                success=False,
                error=f"Provider returned HTTP {exc.response.status_code}",
                latency_ms=latency,
            )
        except Exception as exc:
            latency = int((time.monotonic() - start) * 1000)
            logger.exception("AI reasoning failed for %s", request.task)
            return ReasoningResult(
                task=request.task.value,
                provider=self.config.provider.value,
                model=self.config.model,
                content="",
                success=False,
                error=str(exc),
                latency_ms=latency,
            )


# ── Demo / simulation mode ────────────────────────────────────────────

DEMO_RESPONSES: dict[ReasoningTask, dict] = {
    ReasoningTask.CONTROL_NARRATIVE: {
        "narrative": (
            "The organization enforces multi-factor authentication (MFA) for all privileged users "
            "through Okta Universal Directory integrated with hardware FIDO2 tokens. Conditional access "
            "policies require step-up authentication for administrative actions. Evidence from Okta system "
            "logs confirms 100% MFA enrollment for admin-tier accounts as of the last quarterly review."
        ),
        "implementation_status": "implemented",
        "evidence_references": ["okta_mfa_enrollment_report_Q1_2026", "conditional_access_policy_v3.2"],
    },
    ReasoningTask.GAP_ANALYSIS: {
        "summary": (
            "Assessment identified 3 critical and 7 high-severity gaps concentrated in Access Control (AC) "
            "and System & Information Integrity (SI) families. The most urgent gap is the lack of automated "
            "session termination after 15 minutes of inactivity across production systems."
        ),
        "critical_gaps": [
            {"control": "AC-12", "gap": "No automated session termination on production hosts", "impact": "Unauthorized access via abandoned sessions"},
            {"control": "SI-4", "gap": "Network IDS coverage missing in east-us-2 region", "impact": "Lateral movement undetected in secondary region"},
            {"control": "IA-5", "gap": "Service accounts using static credentials without rotation", "impact": "Credential compromise with unlimited validity"},
        ],
        "high_gaps": [
            {"control": "AU-6", "gap": "Log review cadence is monthly, not weekly as required"},
            {"control": "CM-7", "gap": "Three unauthorized services running in production"},
            {"control": "SC-8", "gap": "Internal east-west traffic not encrypted between microservices"},
        ],
        "recommendations": [
            "Implement idle session timeout via group policy — 2 week effort",
            "Deploy Suricata IDS in east-us-2 — 1 sprint with existing infra team",
            "Rotate all service account credentials and implement Vault-based dynamic secrets",
            "Increase log review cadence to weekly with automated anomaly pre-filtering",
        ],
        "estimated_remediation_effort": "6-8 weeks for critical gaps, 12 weeks for full remediation",
    },
    ReasoningTask.POAM_NARRATIVE: {
        "weakness_description": (
            "AC-12: The organization has not implemented automated session termination for interactive "
            "sessions on production Linux hosts and Kubernetes admin consoles. Sessions remain active "
            "indefinitely, creating risk of unauthorized access through unattended terminals."
        ),
        "risk_level": "high",
        "remediation_plan": (
            "Deploy TMOUT environment variable (900 seconds) via Ansible across all production hosts. "
            "Configure Kubernetes RBAC with token expiry of 15 minutes. Update SSH daemon config to "
            "enforce ClientAliveInterval=300 and ClientAliveCountMax=3."
        ),
        "milestones": [
            {"milestone": "SSH and shell timeout deployed to staging", "target_date_offset_days": 14},
            {"milestone": "Production rollout complete", "target_date_offset_days": 28},
            {"milestone": "Kubernetes token expiry configured", "target_date_offset_days": 35},
            {"milestone": "Validation scan confirms compliance", "target_date_offset_days": 42},
        ],
        "resources_required": "Platform engineering (1 FTE × 3 weeks), security review (0.5 FTE × 1 week)",
        "estimated_completion_days": 42,
    },
    ReasoningTask.EVIDENCE_MAPPING: {
        "mappings": [
            {"evidence_id": "cloudtrail_logging_config", "control_id": "AU-2", "confidence": "high", "rationale": "CloudTrail configuration demonstrates audit event selection capability"},
            {"evidence_id": "guardduty_findings_report", "control_id": "SI-4", "confidence": "high", "rationale": "GuardDuty findings show active monitoring for malicious activity"},
            {"evidence_id": "iam_password_policy", "control_id": "IA-5", "confidence": "medium", "rationale": "Password policy enforces complexity but rotation policy not evident"},
            {"evidence_id": "s3_encryption_status", "control_id": "SC-28", "confidence": "high", "rationale": "All S3 buckets show SSE-KMS encryption enabled at rest"},
        ],
    },
    ReasoningTask.RISK_NARRATIVE: {
        "executive_summary": (
            "Monte Carlo simulation across 5 threat scenarios projects a mean annual loss exposure of $1.87M "
            "with a 95th percentile VaR of $4.2M. Ransomware and data breach scenarios dominate the risk "
            "portfolio, accounting for 73% of aggregate expected loss. Current control investments reduce "
            "baseline exposure by approximately 40%."
        ),
        "key_risks": [
            "Ransomware: $1.1M mean ALE — highest single-scenario exposure",
            "Data breach: $620K mean ALE — driven by PII volume in cloud databases",
            "Compliance violation: $280K mean ALE — GDPR enforcement probability increasing",
        ],
        "risk_appetite_alignment": "Current exposure exceeds the board-approved $3M VaR-95 threshold by $1.2M. Recommend additional investment in ransomware resilience to bring within appetite.",
        "recommended_actions": [
            "Invest in immutable backup infrastructure ($150K) — projected 35% ransomware ALE reduction",
            "Deploy DLP solution for cloud databases ($200K) — projected 25% data breach ALE reduction",
            "Accelerate GDPR Article 30 records completion — reduces regulatory fine probability by 40%",
        ],
    },
    ReasoningTask.QUESTIONNAIRE_ANSWER: {
        "answer": (
            "Yes, the organization encrypts all data at rest using AES-256 encryption. Cloud storage (AWS S3) "
            "uses server-side encryption with AWS KMS customer-managed keys (SSE-KMS). Database encryption "
            "is enforced via RDS encryption with automated key rotation every 365 days. Laptop endpoints "
            "use BitLocker (Windows) and FileVault (macOS) with centrally managed recovery keys."
        ),
        "confidence": "high",
        "evidence_references": ["s3_encryption_audit_Q1", "rds_encryption_config", "endpoint_encryption_policy_v2"],
        "notes": "Key rotation frequency meets NIST 800-53 SC-28 requirements. Consider reducing to 90 days for PCI DSS scope.",
    },
}


async def demo_reason(request: ReasoningRequest) -> ReasoningResult:
    """Return a realistic simulated response for demo mode."""
    import asyncio
    import random

    # Simulate latency
    await asyncio.sleep(random.uniform(0.8, 2.5))

    demo = DEMO_RESPONSES.get(request.task, {})
    content = json.dumps(demo, indent=2)

    return ReasoningResult(
        task=request.task.value,
        provider="demo",
        model="grc-demo-v1",
        content=content,
        structured=demo,
        tokens_used=random.randint(800, 2400),
        latency_ms=random.randint(900, 3200),
    )
