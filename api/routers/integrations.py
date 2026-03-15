"""
Integrations management — register and manage external tool connections.
Each integration carries explicit framework/control-family coverage so syncs
can be mapped to assessment findings.
"""

from __future__ import annotations

import random
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import get_db
from api.routers.auth import get_current_user
from db.models import DataSource, User

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


# ── Control-family coverage: tool_type → framework → [control families] ────
CONTROL_COVERAGE: dict[str, dict[str, list[str]]] = {
    "cloud": {
        "nist_800_53": ["AC", "AU", "CM", "IA", "SC", "SI", "RA", "CA", "SA"],
        "soc2":        ["CC6", "CC7", "CC8", "A1"],
        "iso27001":    ["A5", "A8"],
        "hipaa":       ["164.312", "164.308"],
        "cmmc_l2":     ["AC", "AU", "CM", "IA", "SC", "SI"],
    },
    "edr": {
        "nist_800_53": ["SI", "IR", "AU", "CM", "SC"],
        "soc2":        ["CC6", "CC7"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.312", "164.308"],
        "cmmc_l2":     ["SI", "IR", "AU"],
    },
    "identity": {
        "nist_800_53": ["IA", "AC", "AU", "PS"],
        "soc2":        ["CC6", "CC5"],
        "iso27001":    ["A5", "A6", "A8"],
        "hipaa":       ["164.312", "164.308"],
        "cmmc_l2":     ["IA", "AC"],
    },
    "scanner": {
        "nist_800_53": ["RA", "SI", "CM", "SA"],
        "soc2":        ["CC7", "CC8"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.308"],
        "cmmc_l2":     ["RA", "SI", "CA"],
    },
    "siem": {
        "nist_800_53": ["AU", "IR", "SI", "RA"],
        "soc2":        ["CC7", "A1"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.312"],
        "cmmc_l2":     ["AU", "IR"],
    },
    "cspm": {
        "nist_800_53": ["CM", "RA", "SC", "SI", "AC"],
        "soc2":        ["CC6", "CC7", "CC8"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.312"],
        "cmmc_l2":     ["CM", "RA", "SC"],
    },
    "appsec": {
        "nist_800_53": ["SA", "SI", "RA", "CM"],
        "soc2":        ["CC8"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.308"],
        "cmmc_l2":     ["SA", "SI", "CM"],
    },
    "devops": {
        "nist_800_53": ["CM", "SA", "SI", "AC"],
        "soc2":        ["CC8", "CC7"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.308"],
        "cmmc_l2":     ["CM", "SA"],
    },
    "ticketing": {
        "nist_800_53": ["IR", "CA", "PL"],
        "soc2":        ["CC7"],
        "iso27001":    ["A5"],
        "hipaa":       ["164.308"],
        "cmmc_l2":     ["IR", "CA"],
    },
    "alerting": {
        "nist_800_53": ["IR", "SI"],
        "soc2":        ["CC7"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.308"],
        "cmmc_l2":     ["IR"],
    },
    "grc_platform": {
        "nist_800_53": ["CA", "PL", "PM", "RA"],
        "soc2":        ["CC1", "CC2", "CC3", "CC4", "CC5"],
        "iso27001":    ["A5"],
        "hipaa":       ["164.308", "164.316"],
        "cmmc_l2":     ["CA"],
    },
    "dashboard": {
        "nist_800_53": ["AU", "CA"],
        "soc2":        ["CC7", "A1"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.312"],
        "cmmc_l2":     ["AU"],
    },
    "evidence_store": {
        "nist_800_53": ["AU", "CA", "MP", "SC"],
        "soc2":        ["CC7", "C1"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.312", "164.314"],
        "cmmc_l2":     ["AU", "MP"],
    },
    "ai_reasoning": {
        "nist_800_53": ["RA", "SI", "CA"],
        "soc2":        ["CC7"],
        "iso27001":    ["A8"],
        "hipaa":       ["164.308"],
        "cmmc_l2":     ["RA", "CA"],
    },
}


# ── Complete integration catalog ──────────────────────────────────────────────
SUPPORTED_INTEGRATIONS = [
    # ── Layer 1: Cloud Infrastructure ─────────────────────────────────────
    {
        "id": "aws", "name": "Amazon Web Services", "type": "cloud",
        "category": "CLOUD",
        "description": "IAM, CloudTrail, Config, Security Hub, GuardDuty, Macie — full AWS compliance posture",
        "icon": "aws",
        "auth_fields": ["access_key_id", "secret_access_key", "region"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://docs.aws.amazon.com/config/latest/developerguide/",
        "layer": 1,
    },
    {
        "id": "azure", "name": "Microsoft Azure", "type": "cloud",
        "category": "CLOUD",
        "description": "Defender for Cloud, Monitor, Policy, Security Center — Azure compliance",
        "icon": "azure",
        "auth_fields": ["subscription_id", "tenant_id", "client_id", "client_secret"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/",
        "layer": 1,
    },
    {
        "id": "gcp", "name": "Google Cloud Platform", "type": "cloud",
        "category": "CLOUD",
        "description": "Security Command Center, Cloud Audit Logs, IAM Recommender",
        "icon": "gcp",
        "auth_fields": ["project_id", "service_account_json"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa"],
        "doc_url": "https://cloud.google.com/security-command-center/docs",
        "layer": 1,
    },
    {
        "id": "prisma_cloud", "name": "Prisma Cloud", "type": "cspm",
        "category": "CLOUD",
        "description": "Palo Alto Prisma Cloud — CSPM, CWPP, and compliance alerts via REST API",
        "icon": "prisma",
        "auth_fields": ["access_key", "secret_key", "api_url"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://pan.dev/prisma-cloud/api/cspm/",
        "layer": 1,
    },
    # ── Layer 1: Endpoints ─────────────────────────────────────────────────
    {
        "id": "crowdstrike", "name": "CrowdStrike Falcon", "type": "edr",
        "category": "EDR",
        "description": "Endpoint detections, device posture, spotlight vulnerabilities via FalconPy SDK",
        "icon": "crowdstrike",
        "auth_fields": ["client_id", "client_secret", "base_url"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://falconpy.io/",
        "layer": 1,
    },
    {
        "id": "ms_defender", "name": "Microsoft Defender for Endpoint", "type": "edr",
        "category": "EDR",
        "description": "Device compliance, threat detections, and vulnerability data via Microsoft Graph / Defender API",
        "icon": "defender",
        "auth_fields": ["tenant_id", "client_id", "client_secret"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-hello-world",
        "layer": 1,
    },
    {
        "id": "sentinelone", "name": "SentinelOne", "type": "edr",
        "category": "EDR",
        "description": "Endpoint threat detections, device inventory, behavioral AI via REST API",
        "icon": "sentinelone",
        "auth_fields": ["api_token", "management_url"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://community.sentinelone.com/s/article/000004716",
        "layer": 1,
    },
    # ── Layer 1: Identity & Access ─────────────────────────────────────────
    {
        "id": "okta", "name": "Okta", "type": "identity",
        "category": "IDENTITY",
        "description": "User lifecycle, MFA enforcement, access reviews, system log polling via Okta API",
        "icon": "okta",
        "auth_fields": ["org_url", "api_token"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://developer.okta.com/docs/reference/api/system-log/",
        "layer": 1,
    },
    {
        "id": "entra_id", "name": "Microsoft Entra ID", "type": "identity",
        "category": "IDENTITY",
        "description": "Sign-in logs, risky users, directory audits, conditional access via Microsoft Graph API",
        "icon": "entra",
        "auth_fields": ["tenant_id", "client_id", "client_secret"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://learn.microsoft.com/en-us/graph/api/resources/signin",
        "layer": 1,
    },
    {
        "id": "cyberark", "name": "CyberArk PAM", "type": "identity",
        "category": "IDENTITY",
        "description": "Privileged account inventory, session monitoring, vault audit via CyberArk REST API",
        "icon": "cyberark",
        "auth_fields": ["base_url", "username", "password"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://docs.cyberark.com/PAS/Latest/en/Content/WebServices/Implementing%20Privileged%20Account%20Security%20Web%20Services%20SDK.htm",
        "layer": 1,
    },
    {
        "id": "sailpoint", "name": "SailPoint IIQ", "type": "identity",
        "category": "IDENTITY",
        "description": "Access certifications, role mining, and entitlement reviews via SailPoint REST API",
        "icon": "sailpoint",
        "auth_fields": ["base_url", "client_id", "client_secret"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa"],
        "doc_url": "https://developer.sailpoint.com/idn/api/v3",
        "layer": 1,
    },
    {
        "id": "google_workspace", "name": "Google Workspace", "type": "identity",
        "category": "IDENTITY",
        "description": "Admin SDK audit logs, user management, DLP, and access controls",
        "icon": "google",
        "auth_fields": ["service_account_json", "customer_id"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa"],
        "doc_url": "https://developers.google.com/admin-sdk/reports/v1/guides/delegation",
        "layer": 1,
    },
    # ── Layer 1: Vulnerability Scanners ────────────────────────────────────
    {
        "id": "tenable", "name": "Tenable / Nessus", "type": "scanner",
        "category": "SCANNER",
        "description": "Vulnerability scan findings, asset exposure, and compliance checks via Tenable.io SDK",
        "icon": "tenable",
        "auth_fields": ["access_key", "secret_key", "host_url"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://pypi.org/project/pyTenable/",
        "layer": 1,
    },
    {
        "id": "qualys", "name": "Qualys VMDR", "type": "scanner",
        "category": "SCANNER",
        "description": "VM scan results, host detections, policy compliance checks via Qualys API",
        "icon": "qualys",
        "auth_fields": ["username", "password", "platform_url"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf",
        "layer": 1,
    },
    {
        "id": "rapid7", "name": "Rapid7 InsightVM", "type": "scanner",
        "category": "SCANNER",
        "description": "Risk-prioritized vulnerability data, asset inventory, and remediation projects",
        "icon": "rapid7",
        "auth_fields": ["api_key", "region"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa"],
        "doc_url": "https://docs.rapid7.com/insightvm/api/",
        "layer": 1,
    },
    {
        "id": "wiz", "name": "Wiz", "type": "cspm",
        "category": "SCANNER",
        "description": "Cloud security posture, attack path analysis, and compliance via Wiz GraphQL API",
        "icon": "wiz",
        "auth_fields": ["client_id", "client_secret"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://docs.wiz.io/wiz-docs/docs/using-the-wiz-api",
        "layer": 1,
    },
    {
        "id": "orca", "name": "Orca Security", "type": "cspm",
        "category": "SCANNER",
        "description": "Agentless cloud security posture, risk prioritization, and compliance checks",
        "icon": "orca",
        "auth_fields": ["api_token"],
        "frameworks": ["nist_800_53", "soc2", "iso27001"],
        "doc_url": "https://docs.orcasecurity.io/docs/orca-api",
        "layer": 1,
    },
    # ── Layer 1: SIEM ──────────────────────────────────────────────────────
    {
        "id": "ms_sentinel", "name": "Microsoft Sentinel", "type": "siem",
        "category": "SIEM",
        "description": "Security incidents, analytics rules, and threat intelligence via Azure Management API",
        "icon": "sentinel",
        "auth_fields": ["subscription_id", "resource_group", "workspace_name", "tenant_id", "client_id", "client_secret"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://learn.microsoft.com/en-us/rest/api/securityinsights/",
        "layer": 1,
    },
    {
        "id": "splunk", "name": "Splunk SIEM", "type": "siem",
        "category": "SIEM",
        "description": "Notable events, security alerts, and compliance reports via Splunk REST / Python SDK",
        "icon": "splunk",
        "auth_fields": ["host_url", "hec_token", "search_token"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://docs.splunk.com/Documentation/Splunk/latest/RESTTUT/RESTusing",
        "layer": 1,
    },
    {
        "id": "elastic", "name": "Elastic Security", "type": "siem",
        "category": "SIEM",
        "description": "SIEM alerts, endpoint events, and vulnerability findings via Elasticsearch API",
        "icon": "elastic",
        "auth_fields": ["host_url", "api_key", "index_pattern"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa"],
        "doc_url": "https://www.elastic.co/guide/en/security/current/detections-api-overview.html",
        "layer": 1,
    },
    {
        "id": "datadog", "name": "Datadog", "type": "siem",
        "category": "SIEM",
        "description": "Security signals, compliance posture, anomaly monitors via Datadog API client",
        "icon": "datadog",
        "auth_fields": ["api_key", "app_key", "site"],
        "frameworks": ["nist_800_53", "soc2", "iso27001"],
        "doc_url": "https://docs.datadoghq.com/api/latest/",
        "layer": 1,
    },
    # ── Layer 1: Source Control / DevSecOps ───────────────────────────────
    {
        "id": "github", "name": "GitHub Advanced Security", "type": "devops",
        "category": "DEVSECOPS",
        "description": "Secret scanning, Dependabot alerts, SAST code scanning via GitHub REST / GraphQL API",
        "icon": "github",
        "auth_fields": ["personal_access_token", "org_name"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "cmmc_l2"],
        "doc_url": "https://docs.github.com/en/rest/code-scanning",
        "layer": 1,
    },
    {
        "id": "gitlab", "name": "GitLab", "type": "devops",
        "category": "DEVSECOPS",
        "description": "CI/CD pipeline security, DAST, container scanning, dependency scanning",
        "icon": "gitlab",
        "auth_fields": ["access_token", "host_url"],
        "frameworks": ["nist_800_53", "soc2", "iso27001"],
        "doc_url": "https://docs.gitlab.com/ee/api/",
        "layer": 1,
    },
    {
        "id": "snyk", "name": "Snyk", "type": "appsec",
        "category": "DEVSECOPS",
        "description": "Open source vulnerabilities, container security, and IaC scanning via Snyk API",
        "icon": "snyk",
        "auth_fields": ["api_token", "org_id"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "cmmc_l2"],
        "doc_url": "https://snyk.docs.apiary.io/",
        "layer": 1,
    },
    # ── Layer 4: GRC Platforms ─────────────────────────────────────────────
    {
        "id": "servicenow", "name": "ServiceNow GRC", "type": "grc_platform",
        "category": "GRC",
        "description": "Auto-create POA&M records, sync findings, and push remediation tasks via pysnow",
        "icon": "servicenow",
        "auth_fields": ["instance_url", "username", "password"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI",
        "layer": 4,
    },
    {
        "id": "drata", "name": "Drata", "type": "grc_platform",
        "category": "GRC",
        "description": "Sync findings, upload evidence, and map controls via Drata Public API v1",
        "icon": "drata",
        "auth_fields": ["api_token"],
        "frameworks": ["soc2", "iso27001", "hipaa", "nist_800_53"],
        "doc_url": "https://docs.drata.com/reference/introduction",
        "layer": 4,
    },
    {
        "id": "vanta", "name": "Vanta", "type": "grc_platform",
        "category": "GRC",
        "description": "Push custom evidence and update test results via Vanta API v1",
        "icon": "vanta",
        "auth_fields": ["api_token"],
        "frameworks": ["soc2", "iso27001", "hipaa"],
        "doc_url": "https://developer.vanta.com/docs/",
        "layer": 4,
    },
    # ── Layer 4: Alerting ──────────────────────────────────────────────────
    {
        "id": "pagerduty", "name": "PagerDuty", "type": "alerting",
        "category": "ALERTING",
        "description": "Create critical compliance incidents and route by severity via PagerDuty Events API v2",
        "icon": "pagerduty",
        "auth_fields": ["routing_key", "api_token"],
        "frameworks": ["nist_800_53", "soc2"],
        "doc_url": "https://developer.pagerduty.com/api-reference/",
        "layer": 4,
    },
    {
        "id": "slack", "name": "Slack", "type": "alerting",
        "category": "ALERTING",
        "description": "Severity-routed compliance alerts and daily digests via Slack Incoming Webhooks / Web API",
        "icon": "slack",
        "auth_fields": ["bot_token", "webhook_url", "channel_id"],
        "frameworks": ["nist_800_53", "soc2"],
        "doc_url": "https://api.slack.com/messaging/webhooks",
        "layer": 4,
    },
    {
        "id": "jira", "name": "Jira", "type": "ticketing",
        "category": "TICKETING",
        "description": "Sync POA&M items and remediation tickets to Jira projects via Jira REST API v3",
        "icon": "jira",
        "auth_fields": ["host_url", "email", "api_token", "project_key"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://developer.atlassian.com/cloud/jira/platform/rest/v3/",
        "layer": 4,
    },
    # ── Layer 4: Evidence Management ──────────────────────────────────────
    {
        "id": "confluence", "name": "Confluence", "type": "evidence_store",
        "category": "EVIDENCE",
        "description": "Store and retrieve compliance evidence pages and attachments via Confluence REST API",
        "icon": "confluence",
        "auth_fields": ["host_url", "email", "api_token", "space_key"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa"],
        "doc_url": "https://developer.atlassian.com/cloud/confluence/rest/v2/intro/",
        "layer": 4,
    },
    {
        "id": "sharepoint", "name": "SharePoint / OneDrive", "type": "evidence_store",
        "category": "EVIDENCE",
        "description": "Evidence document management via Microsoft Graph Files API and SharePoint REST",
        "icon": "sharepoint",
        "auth_fields": ["tenant_id", "client_id", "client_secret", "site_url"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa"],
        "doc_url": "https://learn.microsoft.com/en-us/graph/api/resources/onedrive",
        "layer": 4,
    },
    {
        "id": "aws_s3", "name": "AWS S3 Evidence Store", "type": "evidence_store",
        "category": "EVIDENCE",
        "description": "Upload and retrieve compliance evidence artifacts to/from S3 buckets via boto3",
        "icon": "aws",
        "auth_fields": ["access_key_id", "secret_access_key", "region", "bucket_name"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html",
        "layer": 4,
    },
    # ── Layer 4: Dashboards ────────────────────────────────────────────────
    {
        "id": "grafana", "name": "Grafana", "type": "dashboard",
        "category": "DASHBOARD",
        "description": "Push compliance metrics and control-pass-rate panels to Grafana via HTTP API",
        "icon": "grafana",
        "auth_fields": ["host_url", "api_key", "org_id"],
        "frameworks": ["nist_800_53", "soc2"],
        "doc_url": "https://grafana.com/docs/grafana/latest/developers/http_api/",
        "layer": 4,
    },
    # ── Layer 3 (Optional): AI Reasoning ──────────────────────────────────
    {
        "id": "openai", "name": "OpenAI GPT-4o", "type": "ai_reasoning",
        "category": "AI",
        "description": "GPT-4o evaluates findings against control baselines and generates POAM narratives",
        "icon": "openai",
        "auth_fields": ["api_key", "model"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://platform.openai.com/docs/api-reference/chat",
        "layer": 3,
        "optional": True,
    },
    {
        "id": "anthropic", "name": "Anthropic Claude", "type": "ai_reasoning",
        "category": "AI",
        "description": "Claude evaluates findings vs control descriptions and returns structured compliance JSON",
        "icon": "anthropic",
        "auth_fields": ["api_key", "model"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://docs.anthropic.com/en/api/getting-started",
        "layer": 3,
        "optional": True,
    },
    {
        "id": "gemini", "name": "Google Gemini", "type": "ai_reasoning",
        "category": "AI",
        "description": "Gemini 1.5 Pro evaluates control compliance with structured JSON output via generative AI API",
        "icon": "google",
        "auth_fields": ["api_key", "model"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa"],
        "doc_url": "https://ai.google.dev/api/generate-content",
        "layer": 3,
        "optional": True,
    },
    {
        "id": "ollama", "name": "Ollama (Local)", "type": "ai_reasoning",
        "category": "AI",
        "description": "Self-hosted Llama / Mistral for air-gapped compliance reasoning via Ollama REST API",
        "icon": "ollama",
        "auth_fields": ["base_url", "model"],
        "frameworks": ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"],
        "doc_url": "https://github.com/ollama/ollama/blob/main/docs/api.md",
        "layer": 3,
        "optional": True,
    },
]


# ── Realistic finding templates per integration type ─────────────────────────
FINDING_TEMPLATES: dict[str, list[dict]] = {
    "cloud": [
        {"check": "S3 bucket public ACL detected", "severity": "critical", "family": "SC",
         "controls": {"nist_800_53": "SC-8", "soc2": "CC6.1", "iso27001": "A8.3", "hipaa": "164.312(a)(2)(iv)", "cmmc_l2": "SC.3.177"}},
        {"check": "CloudTrail logging disabled in region", "severity": "high", "family": "AU",
         "controls": {"nist_800_53": "AU-2", "soc2": "CC7.2", "iso27001": "A8.15", "hipaa": "164.312(b)", "cmmc_l2": "AU.2.041"}},
        {"check": "Root account MFA not enabled", "severity": "critical", "family": "IA",
         "controls": {"nist_800_53": "IA-5", "soc2": "CC6.1", "iso27001": "A8.5", "hipaa": "164.312(d)", "cmmc_l2": "IA.3.083"}},
        {"check": "Security group allows SSH from 0.0.0.0/0", "severity": "high", "family": "SC",
         "controls": {"nist_800_53": "SC-7", "soc2": "CC6.6", "iso27001": "A8.20", "hipaa": "164.312(e)(1)", "cmmc_l2": "SC.3.180"}},
        {"check": "KMS key rotation disabled", "severity": "medium", "family": "SC",
         "controls": {"nist_800_53": "SC-28", "soc2": "CC6.7", "iso27001": "A8.24", "hipaa": "164.312(a)(2)(iv)", "cmmc_l2": "SC.3.177"}},
    ],
    "edr": [
        {"check": "Endpoint protection agent offline > 24h", "severity": "high", "family": "SI",
         "controls": {"nist_800_53": "SI-3", "soc2": "CC6.8", "iso27001": "A8.7", "hipaa": "164.308(a)(5)", "cmmc_l2": "SI.1.210"}},
        {"check": "Malware detected and quarantined", "severity": "critical", "family": "IR",
         "controls": {"nist_800_53": "IR-5", "soc2": "CC7.3", "iso27001": "A8.8", "hipaa": "164.308(a)(6)", "cmmc_l2": "IR.2.092"}},
        {"check": "Lateral movement detected — Pass-the-Hash", "severity": "critical", "family": "SI",
         "controls": {"nist_800_53": "SI-4", "soc2": "CC7.2", "iso27001": "A8.16", "hipaa": "164.308(a)(6)", "cmmc_l2": "SI.2.217"}},
        {"check": "Unpatched CVE (CVSS ≥ 9.0) on endpoint", "severity": "critical", "family": "RA",
         "controls": {"nist_800_53": "RA-5", "soc2": "CC7.1", "iso27001": "A8.8", "hipaa": "164.308(a)(5)", "cmmc_l2": "RA.2.141"}},
    ],
    "identity": [
        {"check": "Privileged user without MFA", "severity": "critical", "family": "IA",
         "controls": {"nist_800_53": "IA-2", "soc2": "CC6.1", "iso27001": "A8.5", "hipaa": "164.312(d)", "cmmc_l2": "IA.3.083"}},
        {"check": "Inactive account active > 90 days", "severity": "medium", "family": "AC",
         "controls": {"nist_800_53": "AC-2", "soc2": "CC6.2", "iso27001": "A8.2", "hipaa": "164.308(a)(3)", "cmmc_l2": "AC.2.006"}},
        {"check": "Admin privilege granted without ticket", "severity": "high", "family": "AC",
         "controls": {"nist_800_53": "AC-6", "soc2": "CC6.3", "iso27001": "A8.2", "hipaa": "164.308(a)(4)", "cmmc_l2": "AC.2.007"}},
        {"check": "Password policy below minimum complexity", "severity": "high", "family": "IA",
         "controls": {"nist_800_53": "IA-5", "soc2": "CC6.1", "iso27001": "A8.5", "hipaa": "164.308(a)(5)", "cmmc_l2": "IA.1.076"}},
        {"check": "Service account with interactive login enabled", "severity": "medium", "family": "AC",
         "controls": {"nist_800_53": "AC-3", "soc2": "CC6.3", "iso27001": "A8.18", "hipaa": "164.312(a)(1)", "cmmc_l2": "AC.1.001"}},
    ],
    "scanner": [
        {"check": "Critical CVE unpatched > 30 days", "severity": "critical", "family": "RA",
         "controls": {"nist_800_53": "RA-5", "soc2": "CC7.1", "iso27001": "A8.8", "hipaa": "164.308(a)(5)", "cmmc_l2": "RA.2.141"}},
        {"check": "High CVE unpatched > 60 days", "severity": "high", "family": "SI",
         "controls": {"nist_800_53": "SI-2", "soc2": "CC7.1", "iso27001": "A8.8", "hipaa": "164.308(a)(5)", "cmmc_l2": "SI.1.211"}},
        {"check": "End-of-life OS detected on production host", "severity": "critical", "family": "CM",
         "controls": {"nist_800_53": "CM-2", "soc2": "CC8.1", "iso27001": "A8.8", "hipaa": "164.308(a)(5)", "cmmc_l2": "CM.2.061"}},
        {"check": "Unauthenticated network service exposed", "severity": "high", "family": "SC",
         "controls": {"nist_800_53": "SC-7", "soc2": "CC6.6", "iso27001": "A8.20", "hipaa": "164.312(e)(1)", "cmmc_l2": "SC.1.175"}},
    ],
    "siem": [
        {"check": "Brute-force attack detected — threshold exceeded", "severity": "high", "family": "AU",
         "controls": {"nist_800_53": "AU-6", "soc2": "CC7.2", "iso27001": "A8.16", "hipaa": "164.308(a)(6)", "cmmc_l2": "AU.2.042"}},
        {"check": "Anomalous data exfiltration pattern detected", "severity": "critical", "family": "SI",
         "controls": {"nist_800_53": "SI-4", "soc2": "CC7.3", "iso27001": "A8.16", "hipaa": "164.308(a)(6)", "cmmc_l2": "SI.2.217"}},
        {"check": "Alert correlation rule returning false positives", "severity": "medium", "family": "IR",
         "controls": {"nist_800_53": "IR-4", "soc2": "CC7.4", "iso27001": "A8.16", "hipaa": "164.308(a)(6)", "cmmc_l2": "IR.2.093"}},
        {"check": "Log retention below required 365-day minimum", "severity": "high", "family": "AU",
         "controls": {"nist_800_53": "AU-11", "soc2": "CC7.2", "iso27001": "A8.15", "hipaa": "164.312(b)", "cmmc_l2": "AU.3.045"}},
    ],
    "cspm": [
        {"check": "Container image with critical CVE in production", "severity": "critical", "family": "CM",
         "controls": {"nist_800_53": "CM-7", "soc2": "CC8.1", "iso27001": "A8.8", "hipaa": "164.308(a)(5)", "cmmc_l2": "CM.2.061"}},
        {"check": "Cloud resource misconfiguration — overly permissive IAM", "severity": "high", "family": "AC",
         "controls": {"nist_800_53": "AC-6", "soc2": "CC6.3", "iso27001": "A8.2", "hipaa": "164.312(a)(1)", "cmmc_l2": "AC.2.007"}},
        {"check": "Network security group allows unrestricted inbound", "severity": "high", "family": "SC",
         "controls": {"nist_800_53": "SC-7", "soc2": "CC6.6", "iso27001": "A8.20", "hipaa": "164.312(e)(1)", "cmmc_l2": "SC.3.180"}},
    ],
    "appsec": [
        {"check": "SQL injection vulnerability in production code", "severity": "critical", "family": "SA",
         "controls": {"nist_800_53": "SA-11", "soc2": "CC8.1", "iso27001": "A8.28", "hipaa": "164.308(a)(5)", "cmmc_l2": "SA.3.169"}},
        {"check": "Exposed API key in source code commit", "severity": "critical", "family": "IA",
         "controls": {"nist_800_53": "IA-5", "soc2": "CC6.1", "iso27001": "A8.12", "hipaa": "164.312(a)(2)(i)", "cmmc_l2": "IA.1.076"}},
        {"check": "High-severity dependency vulnerability", "severity": "high", "family": "RA",
         "controls": {"nist_800_53": "RA-5", "soc2": "CC7.1", "iso27001": "A8.8", "hipaa": "164.308(a)(5)", "cmmc_l2": "RA.2.141"}},
    ],
    "devops": [
        {"check": "Unprotected main branch — force push allowed", "severity": "medium", "family": "CM",
         "controls": {"nist_800_53": "CM-3", "soc2": "CC8.1", "iso27001": "A8.9", "hipaa": "164.308(a)(5)", "cmmc_l2": "CM.2.064"}},
        {"check": "No code review required for production merges", "severity": "high", "family": "SA",
         "controls": {"nist_800_53": "SA-10", "soc2": "CC8.1", "iso27001": "A8.32", "hipaa": "164.308(a)(5)", "cmmc_l2": "SA.3.169"}},
        {"check": "CI/CD pipeline without SAST stage", "severity": "medium", "family": "SA",
         "controls": {"nist_800_53": "SA-11", "soc2": "CC8.1", "iso27001": "A8.28", "hipaa": "164.308(a)(5)", "cmmc_l2": "SA.3.169"}},
    ],
    "ticketing": [
        {"check": "Open POA&M items past scheduled completion", "severity": "high", "family": "CA",
         "controls": {"nist_800_53": "CA-5", "soc2": "CC5.2", "iso27001": "A5.36", "hipaa": "164.308(a)(8)", "cmmc_l2": "CA.2.158"}},
    ],
    "alerting": [
        {"check": "Critical alert not acknowledged within SLA", "severity": "high", "family": "IR",
         "controls": {"nist_800_53": "IR-6", "soc2": "CC7.4", "iso27001": "A8.16", "hipaa": "164.308(a)(6)", "cmmc_l2": "IR.2.092"}},
    ],
    "grc_platform": [
        {"check": "Control evidence not refreshed within 90 days", "severity": "medium", "family": "CA",
         "controls": {"nist_800_53": "CA-2", "soc2": "CC4.2", "iso27001": "A5.36", "hipaa": "164.308(a)(8)", "cmmc_l2": "CA.2.157"}},
    ],
    "evidence_store": [
        {"check": "Evidence bucket lacks object versioning", "severity": "medium", "family": "AU",
         "controls": {"nist_800_53": "AU-9", "soc2": "CC7.2", "iso27001": "A8.15", "hipaa": "164.312(c)(1)", "cmmc_l2": "AU.2.042"}},
    ],
    "ai_reasoning": [],
    "dashboard": [],
}


class IntegrationCreate(BaseModel):
    integration_id: str
    name: str | None = None
    config: dict = {}
    sync_interval_minutes: int = 60


class IntegrationResponse(BaseModel):
    id: str
    name: str
    provider: str
    source_type: str
    is_active: bool
    config: dict
    last_sync_at: str | None
    last_sync_status: str
    sync_interval_minutes: int
    created_at: str


@router.get("/catalog")
async def get_catalog(current_user: Annotated[User, Depends(get_current_user)]):
    """Return full integration catalog with framework coverage and control families."""
    result = []
    for item in SUPPORTED_INTEGRATIONS:
        coverage = CONTROL_COVERAGE.get(item["type"], {})
        result.append({
            **item,
            "control_families": coverage,
            "frameworks_count": len(item.get("frameworks", [])),
        })
    return {"integrations": result}


@router.get("/", response_model=list[IntegrationResponse])
async def list_integrations(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    sources = db.query(DataSource).order_by(DataSource.created_at.desc()).all()
    return [_source_to_response(s) for s in sources]


@router.post("/", response_model=IntegrationResponse, status_code=201)
async def create_integration(
    request: IntegrationCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    catalog_entry = next(
        (i for i in SUPPORTED_INTEGRATIONS if i["id"] == request.integration_id), None
    )
    if not catalog_entry:
        raise HTTPException(
            status_code=404,
            detail=f"Integration '{request.integration_id}' not found in catalog",
        )
    name = request.name or catalog_entry["name"]
    source = DataSource(
        id=str(uuid.uuid4()),
        name=name,
        source_type=catalog_entry["type"],
        provider=request.integration_id,
        is_active=True,
        config=request.config,
        last_sync_status="pending",
        sync_interval_minutes=request.sync_interval_minutes,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return _source_to_response(source)


@router.delete("/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    source = db.get(DataSource, integration_id)
    if not source:
        raise HTTPException(status_code=404, detail="Integration not found")
    db.delete(source)
    db.commit()


@router.post("/{integration_id}/sync")
async def trigger_sync(
    integration_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    """
    Trigger a sync for a connected integration.
    Returns simulated findings mapped to framework controls.
    """
    source = db.get(DataSource, integration_id)
    if not source:
        raise HTTPException(status_code=404, detail="Integration not found")

    catalog_entry = next(
        (i for i in SUPPORTED_INTEGRATIONS if i["id"] == source.provider), None
    )
    tool_type = catalog_entry["type"] if catalog_entry else "cloud"
    templates = FINDING_TEMPLATES.get(tool_type, [])
    coverage = CONTROL_COVERAGE.get(tool_type, {})

    # Generate simulated findings
    synced_findings = []
    for tmpl in templates:
        if random.random() < 0.6:  # 60% chance each finding appears
            finding = {
                "check_id": tmpl["check"].lower().replace(" ", "_")[:40],
                "description": tmpl["check"],
                "severity": tmpl["severity"],
                "control_family": tmpl["family"],
                "control_mappings": tmpl["controls"],
                "status": "non_compliant",
                "source": source.provider,
                "asset": f"{source.provider}-resource-{random.randint(1,99):02d}",
            }
            synced_findings.append(finding)

    source.last_sync_at = datetime.now(UTC)
    source.last_sync_status = "success"
    source.is_active = True
    db.commit()

    return {
        "message": "Sync completed",
        "integration_id": integration_id,
        "provider": source.provider,
        "status": "success",
        "findings_synced": len(synced_findings),
        "control_families_covered": {fw: fams for fw, fams in coverage.items()},
        "findings": synced_findings,
        "synced_at": source.last_sync_at.isoformat(),
    }


@router.get("/{integration_id}/coverage")
async def get_coverage(
    integration_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    """Return framework/control-family coverage for a connected integration."""
    source = db.get(DataSource, integration_id)
    if not source:
        raise HTTPException(status_code=404, detail="Integration not found")

    catalog_entry = next(
        (i for i in SUPPORTED_INTEGRATIONS if i["id"] == source.provider), None
    )
    if not catalog_entry:
        raise HTTPException(status_code=404, detail="Catalog entry not found")

    tool_type = catalog_entry["type"]
    coverage = CONTROL_COVERAGE.get(tool_type, {})

    return {
        "provider": source.provider,
        "name": catalog_entry["name"],
        "frameworks": catalog_entry.get("frameworks", []),
        "control_families": coverage,
        "layer": catalog_entry.get("layer", 1),
        "doc_url": catalog_entry.get("doc_url", ""),
        "optional": catalog_entry.get("optional", False),
    }


def _source_to_response(s: DataSource) -> IntegrationResponse:
    return IntegrationResponse(
        id=s.id,
        name=s.name,
        provider=s.provider,
        source_type=s.source_type,
        is_active=s.is_active,
        config={
            k: v
            for k, v in (s.config or {}).items()
            if "key" not in k.lower()
            and "secret" not in k.lower()
            and "password" not in k.lower()
            and "token" not in k.lower()
            and "json" not in k.lower()
        },
        last_sync_at=s.last_sync_at.isoformat() if s.last_sync_at else None,
        last_sync_status=s.last_sync_status,
        sync_interval_minutes=s.sync_interval_minutes,
        created_at=s.created_at.isoformat(),
    )
