# GRC Toolkit

An end-to-end Governance, Risk, and Compliance engineering platform. Multi-cloud evidence collection, policy-as-code enforcement, quantitative risk analysis, framework crosswalks, and a connector framework for multi-source telemetry -- all exposed through a secured REST API with a frontend dashboard and backed by a persistent data layer.

**Version 0.3.0** | Python 3.11+

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │            Frontend Dashboard               │
                    │  Dashboard · Frameworks · Assessments       │
                    │  Risk Analysis · Vendors · Evidence · Policies│
                    └──────────────────┬──────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────┐
                    │         Security Middleware Layer            │
                    │  API Key Auth · Rate Limiting · CORS        │
                    │  Security Headers · Audit Logging           │
                    │  Input Validation · Mass Assignment Guard   │
                    └──────────────────┬──────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────┐
                    │           FastAPI REST API                   │
                    │  /api/v1/evidence  /api/v1/assessments      │
                    │  /api/v1/risk  /api/v1/frameworks           │
                    │  /api/v1/vendors  /api/v1/policies          │
                    └──────────────────┬──────────────────────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            │                          │                          │
 ┌──────────▼──────────┐  ┌───────────▼──────────┐  ┌───────────▼───────────┐
 │  Connector Framework │  │    Policy Engine     │  │    Risk Engine        │
 │  Cloud · SIEM · EDR  │  │    OPA + Rego        │  │   Monte Carlo Sim    │
 │  Scanner · Custom    │  │                      │  │                      │
 └──────────┬──────────┘  └───────────┬──────────┘  └───────────┬──────────┘
            │                          │                          │
 ┌──────────▼──────────┐               │                          │
 │  Cloud Collectors    │              │                          │
 │  AWS · Azure · GCP   │              │                          │
 └──────────┬──────────┘               │                          │
            │                          │                          │
            ▼                          ▼                          ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Normalized Evidence Model                         │
 │          SHA-256 integrity · Provider-agnostic schema                  │
 └───────────────────────────┬────────────────────────────────────────────┘
                             │
            ┌────────────────┼────────────────────┐
            │                │                    │
 ┌──────────▼────┐   ┌──────▼───────┐   ┌────────▼────────┐
 │  PostgreSQL   │   │ Framework    │   │  Terraform      │
 │  (SQLAlchemy) │   │ Crosswalks   │   │  Compliance     │
 │               │   │ NIST·SOC2    │   │  Modules        │
 │               │   │ ISO·CMMC     │   │  AWS·Azure·GCP  │
 │               │   │ HIPAA        │   │                 │
 └───────────────┘   └──────────────┘   └─────────────────┘
```

## Project Structure

```
grc-toolkit/
├── api/                              # FastAPI REST application
│   ├── main.py                       # App entrypoint, middleware, lifespan
│   ├── schemas.py                    # Pydantic v2 request/response models
│   ├── deps.py                       # Dependency injection (DB, settings)
│   ├── security.py                   # API key auth, rate limiting, security
│   │                                 # headers, audit logging, input validation
│   └── routers/
│       ├── evidence.py               # Evidence collection & integrity
│       ├── assessments.py            # Control assessment runs
│       ├── risk.py                   # Monte Carlo risk simulation
│       ├── frameworks.py             # Framework listing & crosswalks
│       ├── vendors.py                # Vendor risk CRUD & dashboard
│       └── policies.py              # OPA policy evaluation
│
├── modules/                          # Core business logic
│   ├── models.py                     # NormalizedEvidence, CloudCollector protocol,
│   │                                 # ResourceNormalizer, FrameworkCrosswalk
│   ├── collectors/
│   │   ├── base.py                   # Shared utilities (create_evidence, safe_collect)
│   │   ├── aws_collector.py          # AWSCollectorV2 — boto3
│   │   ├── azure_collector.py        # AzureCollector — azure-mgmt-*
│   │   └── gcp_collector.py          # GCPCollector — google-cloud-*
│   ├── connectors/
│   │   ├── base.py                   # BaseConnector ABC, ConnectorConfig,
│   │   │                             # IngestEvent, ConnectorResult, ConnectorRegistry
│   │   └── cloud_adapter.py          # CloudProviderConnector — wraps existing collectors
│   ├── control_assessor.py           # Assertion engine (AC/AU/SC families)
│   ├── risk_engine.py                # PERT Monte Carlo simulation
│   ├── evidence_collector.py         # Legacy AWS collector (v0.1)
│   ├── report_generator.py           # Jinja2 POA&M / executive summary
│   ├── vendor_monitor.py             # Vendor risk scoring
│   └── notify.py                     # Slack/email notifications
│
├── db/                               # Persistence layer
│   ├── models.py                     # SQLAlchemy 2.0 ORM models
│   │                                 # AuditLog, AssetRecord, DataSource,
│   │                                 # EvidenceRecord, AssessmentRun, VendorRecord,
│   │                                 # PolicyViolation, FrameworkDefinition
│   ├── session.py                    # Engine/session management
│   └── repository.py                 # Repository pattern (evidence, assessments,
│                                     # vendors, policy violations)
│
├── policies/                         # Policy-as-Code (OPA/Rego)
│   ├── nist-800-53/
│   │   ├── ac/                       # AC-2 account management, AC-3 access
│   │   │                             # enforcement, AC-6 least privilege
│   │   ├── au/                       # AU-2 event logging, AU-6 audit review
│   │   ├── sc/                       # SC-7 boundary protection, SC-8 transmission
│   │   │                             # confidentiality, SC-12 crypto key mgmt,
│   │   │                             # SC-28 protection at rest
│   │   ├── ia/                       # IA-2 identification, IA-5 authenticator mgmt
│   │   ├── cm/                       # CM-6 configuration settings
│   │   └── si/                       # SI-4 system monitoring
│   ├── soc2/                         # CC6 logical access, CC7 system operations
│   └── terraform/                    # Conftest policies (AWS, Azure, GCP baselines)
│
├── static/
│   └── index.html                    # Frontend dashboard UI (single-page)
│
├── terraform/modules/                # Compliance-enforcing infrastructure
│   ├── aws/
│   │   ├── secure-account-baseline/  # CloudTrail, GuardDuty, Security Hub, IAM
│   │   ├── compliant-vpc/            # VPC, flow logs, NAT, default-deny SGs
│   │   └── iam-baseline/             # Auditor role, MFA enforcement, root alerts
│   ├── azure/
│   │   └── secure-subscription-baseline/  # Log Analytics, Activity Log, encryption
│   └── gcp/
│       └── secure-project-baseline/  # Audit log sink, org policy constraints
│
├── config/
│   ├── frameworks.yaml               # NIST 800-53 control definitions (AC, AU, SC)
│   ├── crosswalks.yaml               # NIST → SOC 2, ISO 27001, CMMC L2, HIPAA
│   └── settings.yaml                 # Environment configuration
│
├── tests/
│   ├── test_models.py                # Evidence, normalizer, crosswalk tests
│   ├── test_control_assessor.py      # Assertion engine tests
│   ├── test_risk_engine.py           # Monte Carlo simulation tests
│   └── test_vendor_monitor.py        # Vendor scoring tests
│
├── .github/workflows/
│   ├── ci.yaml                       # Tests, security scan, OPA, Terraform, conftest
│   └── compliance-gate.yaml          # PR gate for terraform/policies changes
│
├── .env.example                      # Environment variable template
├── .gitignore                        # Git ignore rules
├── docker-compose.yaml               # API + PostgreSQL + OPA + Redis
├── Dockerfile                        # Python 3.12 container
├── requirements.txt                  # Production dependencies
├── requirements-dev.txt              # Dev/test dependencies
├── requirements-replit.txt           # Lightweight deps for Replit deployment
├── .replit                           # Replit run configuration
├── replit.nix                        # Replit Nix environment
├── pyproject.toml                    # Ruff, mypy, pytest config
└── setup.py                          # Package setup with extras
```

## Setup

### Environment Variables

Copy the template and fill in your values. Never commit `.env` to version control.

```bash
cp .env.example .env
# Edit .env with your secrets
```

| Variable                | Default                              | Description                              |
|------------------------|--------------------------------------|------------------------------------------|
| `GRC_DATABASE_URL`     | `sqlite:///grc_toolkit.db`           | Database connection string               |
| `GRC_OPA_URL`          | `http://localhost:8181`              | OPA server URL                           |
| `GRC_API_KEYS`         | *(unset = dev mode, no auth)*        | Comma-separated API keys                 |
| `GRC_CORS_ORIGINS`     | `http://localhost:3000,...`           | Comma-separated allowed CORS origins     |
| `GRC_RATE_LIMIT_RPM`   | `120`                                | Requests per minute per client IP        |
| `GRC_RATE_LIMIT_BURST` | `20`                                 | Burst size for rate limiter              |
| `GRC_ENABLE_DOCS`      | `false`                              | Enable Swagger/ReDoc in production       |
| `GRC_SMTP_PASSWORD`    | *(unset)*                            | SMTP password for email notifications    |
| `GRC_SLACK_WEBHOOK_URL`| *(unset)*                            | Slack webhook for notifications          |
| `POSTGRES_PASSWORD`    | *(required for Docker)*              | PostgreSQL password                      |
| `REDIS_PASSWORD`       | *(required for Docker)*              | Redis password                           |

### Local Development

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
# Edit .env, then:
uvicorn api.main:app --reload
```

### Docker (Full Stack)

```bash
cp .env.example .env
# Fill in POSTGRES_PASSWORD, REDIS_PASSWORD, and other secrets
docker compose up -d
```

This starts four services. All service ports are internal by default; only the API is exposed to the host.

| Service      | Port  | Purpose                        |
|-------------|-------|--------------------------------|
| **api**     | 8000  | FastAPI REST API                |
| **db**      | 5432  | PostgreSQL 16                   |
| **opa**     | 8181  | Open Policy Agent server        |
| **redis**   | 6379  | Celery task queue broker        |

You must configure `.env` before starting Docker. The compose file reads secrets from environment variables -- they are never baked into images or config files.

### Replit Deployment

The repository includes `.replit` and `replit.nix` for one-click deployment on Replit. Dependencies are managed via `requirements-replit.txt` (a lightweight subset that excludes cloud SDKs and heavy drivers).

## Security

### API Key Authentication

All endpoints require an `X-API-Key` header when `GRC_API_KEYS` is set. If `GRC_API_KEYS` is unset or empty, the API runs in development mode with no authentication enforced.

Generate keys:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set one or more keys (comma-separated) in your `.env`:

```
GRC_API_KEYS=key1,key2,key3
```

Keys are compared using constant-time comparison to prevent timing attacks.

### Rate Limiting

Token bucket rate limiter per client IP. Configurable via `GRC_RATE_LIMIT_RPM` (requests per minute) and `GRC_RATE_LIMIT_BURST` (burst size). Rate-limited responses return HTTP 429 with a `Retry-After` header. All responses include `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers.

### Security Headers

All responses include OWASP-recommended security headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Cache-Control: no-store, no-cache, must-revalidate`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (when behind TLS)

### Audit Logging

Every API request is logged with structured metadata: timestamp, request ID, method, path, client IP, user agent, status code, and response time. Sensitive headers (Authorization, X-API-Key, Cookie) are redacted. Each response includes an `X-Request-Id` header for traceability.

### Input Validation and Mass Assignment Protection

Pydantic v2 models validate all request payloads. Enum-like fields (provider, severity, status, criticality, data classification) are validated against known-good value sets. Vendor updates are restricted to an explicit allowlist of updatable fields, preventing mass assignment attacks.

### CORS Configuration

CORS origins are configured via `GRC_CORS_ORIGINS` (comma-separated). Only listed origins are allowed.

### Secrets Management

All secrets are managed through environment variables. The `.env.example` template documents every required variable. Secrets are never stored in config files, source code, or Docker images.

## API Reference

Base URL: `http://localhost:8000`

All endpoints under `/api/v1/` require the `X-API-Key` header when `GRC_API_KEYS` is configured. If `GRC_API_KEYS` is unset, all requests are allowed (development mode).

### Health Check
```
GET /health
```

### Evidence Collection
```
POST /api/v1/evidence/collect          # Trigger cloud evidence collection (202)
GET  /api/v1/evidence/                 # List evidence (paginated)
GET  /api/v1/evidence/{id}             # Get single evidence record
GET  /api/v1/evidence/{id}/verify      # SHA-256 integrity verification
```

### Control Assessments
```
POST /api/v1/assessments/run           # Start assessment run (202)
GET  /api/v1/assessments/runs          # List assessment runs
GET  /api/v1/assessments/runs/{id}     # Get run details
GET  /api/v1/assessments/runs/{id}/results  # Get run results
GET  /api/v1/assessments/trend         # Compliance trend over time
```

### Risk Analysis
```
POST /api/v1/risk/simulate             # Run Monte Carlo simulation
POST /api/v1/risk/portfolio            # Portfolio-level risk aggregation
POST /api/v1/risk/treatments           # Treatment effectiveness analysis
GET  /api/v1/risk/scenarios            # List predefined scenarios
```

### Framework Management
```
GET  /api/v1/frameworks/               # List all frameworks
GET  /api/v1/frameworks/{id}           # Framework details
GET  /api/v1/frameworks/{id}/controls  # Controls for a framework
POST /api/v1/frameworks/crosswalk      # Map controls across frameworks
```

### Vendor Risk
```
POST /api/v1/vendors/                  # Create vendor
GET  /api/v1/vendors/                  # List vendors
GET  /api/v1/vendors/dashboard         # Risk dashboard
GET  /api/v1/vendors/needing-assessment  # Vendors due for assessment
GET  /api/v1/vendors/{id}              # Vendor details
PUT  /api/v1/vendors/{id}              # Update vendor
```

### Policy Evaluation
```
POST /api/v1/policies/evaluate         # Evaluate data against OPA policies
GET  /api/v1/policies/violations       # List policy violations
POST /api/v1/policies/violations/{id}/resolve  # Resolve a violation
GET  /api/v1/policies/bundles          # List available policy bundles
```

## Frontend Dashboard

The single-page frontend is served from `static/index.html` and provides a browser-based interface to the API. Pages include:

- **Dashboard** -- overview of compliance posture and key metrics
- **Frameworks** -- browse framework definitions and control mappings
- **Assessments** -- view and trigger assessment runs, review results
- **Risk Analysis** -- run simulations and view risk distributions
- **Vendors** -- manage vendor inventory and risk ratings
- **Evidence** -- browse collected evidence and verify integrity
- **Policies** -- evaluate policies and review violations

The sidebar includes an API key entry field for authenticating against secured deployments.

## Connector Framework

The connector framework (`modules/connectors/`) provides a unified interface for ingesting telemetry from any data source -- cloud providers, SIEM platforms, EDR tools, vulnerability scanners, and custom sources.

### Core Types

- **`ConnectorConfig`** -- configuration for a data source (name, type, provider, settings, secret env var references, field mappings)
- **`IngestEvent`** -- canonical normalized event format with SHA-256 integrity hashing; maps to the NormalizedEvidence model
- **`ConnectorResult`** -- result of a sync operation (events, status, errors, timing)
- **`BaseConnector`** -- abstract base class with `validate_config()`, `collect()`, and `health_check()` methods
- **`ConnectorRegistry`** -- registration and lifecycle management for connector instances

### Cloud Provider Adapter

`CloudProviderConnector` wraps the existing AWS/Azure/GCP collectors into the connector interface, bridging legacy collectors without rewriting them.

### Adding a New Connector

To integrate a new source (e.g., Splunk, CrowdStrike, Tenable):

1. Subclass `BaseConnector`
2. Implement `validate_config()`, `collect()`, and `health_check()`
3. Normalize source data into `IngestEvent` objects
4. Register the connector type with `ConnectorRegistry`

```python
from modules.connectors.base import BaseConnector, ConnectorResult, IngestEvent, IngestStatus

class SplunkConnector(BaseConnector):
    def validate_config(self) -> list[str]:
        errors = []
        if "base_url" not in self.config.settings:
            errors.append("Missing 'base_url' in settings")
        return errors

    def health_check(self) -> bool:
        # Check Splunk API reachability
        ...

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(connector_name=self.config.name, status=IngestStatus.SUCCESS)
        # Fetch and normalize events...
        result.complete()
        return result
```

## Policy-as-Code

Rego policies are organized by framework and consumable three ways:

1. **OPA Server** -- Loaded as a bundle in Docker Compose, queried by the API
2. **Conftest** -- Terraform plan validation in CI (`policies/terraform/`)
3. **K8s Admission** -- Same Rego policies can be used with Gatekeeper/OPA

### Policy Coverage (NIST 800-53)

| Family | Controls                           |
|--------|------------------------------------|
| AC     | AC-2, AC-3, AC-6                   |
| AU     | AU-2, AU-6                         |
| SC     | SC-7, SC-8, SC-12, SC-28           |
| IA     | IA-2, IA-5                         |
| CM     | CM-6                               |
| SI     | SI-4                               |

### Running OPA Tests

```bash
opa test policies/ -v
```

### Terraform Policy Checks

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
conftest test tfplan.json --policy policies/terraform/
```

## Framework Crosswalks

Evidence collected against NIST 800-53 controls automatically maps to:

| Source Control | SOC 2     | ISO 27001 | CMMC L2         | HIPAA            |
|---------------|-----------|-----------|-----------------|------------------|
| AC-2          | CC6.1/6.2 | A.5.15    | AC.L2-3.1.1     | 164.312(a)(1)    |
| AC-6          | CC6.1/6.3 | A.8.2     | AC.L2-3.1.5     | 164.312(a)(1)    |
| AU-2          | CC7.1/7.2 | A.8.15    | AU.L2-3.3.1     | 164.312(b)       |
| SC-7          | CC6.1/6.6 | A.8.20/21 | SC.L2-3.13.1    | 164.312(e)(1)    |
| IA-2          | CC6.1     | A.8.5     | IA.L2-3.5.1     | 164.312(d)       |

Crosswalk definitions live in `config/crosswalks.yaml`.

## Terraform Modules

Pre-built compliance modules that enforce NIST controls at deploy time:

- **AWS**: Account baseline (CloudTrail, GuardDuty, Security Hub), compliant VPC (flow logs, default-deny), IAM baseline (MFA enforcement, root alerts)
- **Azure**: Subscription baseline (Log Analytics, Activity Log diagnostics, encrypted storage)
- **GCP**: Project baseline (audit log sink, org policy constraints for bucket-level access and OS login)

```bash
# Example usage
module "secure_baseline" {
  source         = "./terraform/modules/aws/secure-account-baseline"
  trail_name     = "grc-audit-trail"
  log_bucket     = "my-audit-logs"
  alert_email    = "security@example.com"
}
```

## CI/CD

GitHub Actions runs on every push to `main`/`develop` and on PRs:

| Job                    | What it does                                                    |
|-----------------------|-----------------------------------------------------------------|
| **test**              | Lint (ruff), type check (mypy), pytest with 60% minimum coverage |
| **security-scan**     | Bandit SAST, pip-audit dependency scan, Trivy filesystem scan, Docker image scan, hardcoded secrets detection |
| **opa-test**          | `opa test policies/ -v`, OPA format check (`opa fmt --diff`)    |
| **terraform-validate**| `terraform validate` across all 5 modules                       |
| **conftest**          | `opa check` on policy files, `conftest verify` for real policy validation |

## Requirements

- Python 3.11+
- Docker and Docker Compose (for full stack)
- Cloud credentials configured per provider SDK (AWS, Azure, GCP)
- OPA CLI (for local policy testing)
- Terraform (for infrastructure modules)

## License

See [LICENSE](LICENSE) for details.
