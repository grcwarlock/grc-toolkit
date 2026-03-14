# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-14

### Added
- API key authentication on all endpoints (X-API-Key header)
- Rate limiting middleware (token bucket, configurable via GRC_RATE_LIMIT_RPM)
- Security headers middleware (HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
- Audit logging middleware with structured request/response logging
- Frontend dashboard UI with 7 pages (Dashboard, Frameworks, Assessments, Risk, Vendors, Evidence, Policies)
- XSS prevention with HTML escaping across all frontend dynamic content
- Generic connector framework for multi-source telemetry ingestion (BaseConnector, ConnectorRegistry)
- CloudProviderConnector adapter wrapping existing AWS/Azure/GCP collectors
- Asset inventory data model for cross-source resource correlation
- Data source registry for connected systems
- Audit log table for immutable change tracking
- 5 new OPA policies: AC-3 (access enforcement), IA-5 (authenticator management), SC-8 (transmission confidentiality), SC-12 (cryptographic key management), SC-28 (protection at rest)
- Bandit SAST scanning in CI/CD
- pip-audit dependency vulnerability scanning in CI/CD
- Docker image scanning (not just filesystem) in CI/CD
- Hardcoded secrets detection in CI/CD
- .env.example template for environment configuration
- .gitignore for security-sensitive files
- Replit deployment support (.replit, replit.nix, requirements-replit.txt)
- Input validation with enum checks on vendor fields and provider names
- Minimum test coverage threshold (60%) in CI

### Changed
- CORS configuration moved from wildcard to explicit origin whitelist (GRC_CORS_ORIGINS env var)
- Docker services (PostgreSQL, Redis, OPA) no longer exposed to host network — internal only
- Redis now requires password authentication
- Docker images pinned to specific versions/SHAs (no more :latest)
- All services now have health checks in docker-compose
- Dockerfile: added HEALTHCHECK, read-only root filesystem, version-pinned base image
- SMTP password loaded from GRC_SMTP_PASSWORD env var instead of config dict
- API host defaults to 127.0.0.1 instead of 0.0.0.0
- Health endpoint no longer exposes version number
- API version bumped to 0.3.0
- CI/CD uses GitHub Secrets for database password instead of hardcoded values
- OPA pinned to version 0.62.1
- Conftest job now runs real policy validation instead of placeholder echo
- Compliance gate checks policy count and test coverage

### Fixed
- Mass assignment vulnerability in vendor update endpoint (now uses explicit field allowlist)
- CORS misconfiguration (allow_origins=* with allow_credentials=True)
- Hardcoded database password in settings.yaml and docker-compose.yaml
- Hardcoded test password in CI workflow
- Error logging in notify.py could leak SMTP credentials

### Security
- Database session now warns when PostgreSQL connections lack SSL
- PostgreSQL statement timeout set to 30 seconds to prevent DoS via long queries
- Vendor update restricted to explicit allowlist of fields
- Policy evaluation validates provider input against known providers

## [0.1.0] - 2025-03-01

### Added
- Initial release of the GRC Automation Toolkit
- Evidence collection module with AWS support (IAM, CloudTrail, EC2, GuardDuty, Security Hub)
- Control assessment engine with assertion registry pattern
- NIST 800-53 framework definitions for AC, AU, and SC control families
- FedRAMP Moderate baseline overlay structure
- Monte Carlo risk engine with PERT distributions
- Treatment comparison analysis for investment decisions
- Report generator producing POA&M, executive summaries, and JSON exports
- Vendor risk monitoring with composite scoring
- Slack and email notification handlers
- AWS Lambda handler for serverless deployment
- Docker support for containerized deployment
- GitHub Actions workflow for CI/CD compliance checking
- Comprehensive deployment and operations guide
