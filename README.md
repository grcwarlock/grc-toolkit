# GRC Toolkit

An end-to-end Governance, Risk, and Compliance engineering platform. Multi-cloud evidence collection, policy-as-code enforcement, quantitative risk analysis, and framework crosswalks — all exposed through a REST API and backed by a persistent data layer.

## Architecture

```
                         ┌──────────────────────────────────┐
                         │          FastAPI REST API         │
                         │    /evidence  /assessments /risk  │
                         │  /frameworks  /vendors  /policies │
                         └────────────┬─────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
   ┌──────────▼──────────┐ ┌─────────▼─────────┐ ┌──────────▼──────────┐
   │   Cloud Collectors   │ │   Policy Engine   │ │   Risk Engine       │
   │  AWS · Azure · GCP   │ │   OPA + Rego      │ │  Monte Carlo Sim    │
   └──────────┬──────────┘ └─────────┬─────────┘ └──────────┬──────────┘
              │                       │                       │
              ▼                       ▼                       ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                    Normalized Evidence Model                     │
   │         SHA-256 integrity · Provider-agnostic schema             │
   └──────────────────────────┬───────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────────┐
              │               │                   │
   ┌──────────▼────┐  ┌──────▼───────┐  ┌────────▼────────┐
   │  PostgreSQL   │  │ Framework    │  │  Terraform      │
   │  (SQLAlchemy) │  │ Crosswalks   │  │  Compliance     │
   │               │  │ NIST·SOC2    │  │  Modules        │
   │               │  │ ISO·CMMC     │  │  AWS·Azure·GCP  │
   │               │  │ HIPAA        │  │                 │
   └───────────────┘  └──────────────┘  └─────────────────┘
```

## Project Structure

```
grc-toolkit/
├── api/                              # FastAPI REST application
│   ├── main.py                       # App entrypoint, middleware, lifespan
│   ├── schemas.py                    # Pydantic v2 request/response models
│   ├── deps.py                       # Dependency injection (DB, settings)
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
│   ├── control_assessor.py           # Assertion engine (AC/AU/SC families)
│   ├── risk_engine.py                # PERT Monte Carlo simulation
│   ├── evidence_collector.py         # Legacy AWS collector (v0.1)
│   ├── report_generator.py           # Jinja2 POA&M / executive summary
│   ├── vendor_monitor.py             # Vendor risk scoring
│   └── notify.py                     # Slack/email notifications
│
├── db/                               # Persistence layer
│   ├── models.py                     # SQLAlchemy 2.0 ORM models
│   ├── session.py                    # Engine/session management
│   └── repository.py                 # Repository pattern (evidence, assessments,
│                                     # vendors, policy violations)
│
├── policies/                         # Policy-as-Code (OPA/Rego)
│   ├── nist-800-53/
│   │   ├── ac/                       # AC-2 account management, AC-6 least privilege
│   │   ├── au/                       # AU-2 event logging, AU-6 audit review
│   │   ├── sc/                       # SC-7 boundary protection
│   │   ├── ia/                       # IA-2 identification & authentication
│   │   ├── cm/                       # CM-6 configuration settings
│   │   └── si/                       # SI-4 system monitoring
│   ├── soc2/                         # CC6 logical access, CC7 system operations
│   └── terraform/                    # Conftest policies (AWS, Azure, GCP baselines)
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
│   ├── ci.yaml                       # Python tests, OPA tests, Terraform validate,
│   │                                 # security scanning, conftest
│   └── compliance-gate.yaml          # PR gate for terraform/policies changes
│
├── docker-compose.yaml               # API + PostgreSQL + OPA + Redis
├── Dockerfile                        # Python 3.12 container
├── requirements.txt                  # Production dependencies
├── requirements-dev.txt              # Dev/test dependencies
├── pyproject.toml                    # Ruff, mypy, pytest config
└── setup.py                          # Package setup with extras
```

## Setup

### Local Development

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

### Docker (Full Stack)

```bash
docker compose up -d
```

This starts four services:

| Service      | Port  | Purpose                        |
|-------------|-------|--------------------------------|
| **api**     | 8000  | FastAPI REST API                |
| **db**      | 5432  | PostgreSQL 16                   |
| **opa**     | 8181  | Open Policy Agent server        |
| **redis**   | 6379  | Celery task queue broker        |

### Environment Variables

| Variable            | Default                                      | Description                  |
|--------------------|----------------------------------------------|------------------------------|
| `GRC_DATABASE_URL` | `sqlite:///grc_toolkit.db`                    | Database connection string   |
| `GRC_OPA_URL`      | `http://localhost:8181`                       | OPA server URL               |

## API Reference

Base URL: `http://localhost:8000`

### Health Check
```
GET /health
```

### Evidence Collection
```
POST /evidence/collect          # Trigger cloud evidence collection (202)
GET  /evidence/                 # List evidence (paginated)
GET  /evidence/{id}             # Get single evidence record
GET  /evidence/{id}/verify      # SHA-256 integrity verification
```

### Control Assessments
```
POST /assessments/run           # Start assessment run (202)
GET  /assessments/runs          # List assessment runs
GET  /assessments/runs/{id}     # Get run details
GET  /assessments/runs/{id}/results  # Get run results
GET  /assessments/trend         # Compliance trend over time
```

### Risk Analysis
```
POST /risk/simulate             # Run Monte Carlo simulation
POST /risk/portfolio            # Portfolio-level risk aggregation
POST /risk/treatments           # Treatment effectiveness analysis
GET  /risk/scenarios            # List predefined scenarios
```

### Framework Management
```
GET  /frameworks/               # List all frameworks
GET  /frameworks/{id}           # Framework details
GET  /frameworks/{id}/controls  # Controls for a framework
POST /frameworks/crosswalk      # Map controls across frameworks
```

### Vendor Risk
```
POST /vendors/                  # Create vendor
GET  /vendors/                  # List vendors
GET  /vendors/dashboard         # Risk dashboard
GET  /vendors/needing-assessment  # Vendors due for assessment
GET  /vendors/{id}              # Vendor details
PUT  /vendors/{id}              # Update vendor
```

### Policy Evaluation
```
POST /policies/evaluate         # Evaluate data against OPA policies
GET  /policies/violations       # List policy violations
POST /policies/violations/{id}/resolve  # Resolve a violation
GET  /policies/bundles          # List available policy bundles
```

## Policy-as-Code

Rego policies are organized by framework and consumable three ways:

1. **OPA Server** — Loaded as a bundle in Docker Compose, queried by the API
2. **Conftest** — Terraform plan validation in CI (`policies/terraform/`)
3. **K8s Admission** — Same Rego policies can be used with Gatekeeper/OPA

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

| Job                    | What it does                                    |
|-----------------------|-------------------------------------------------|
| **test**              | Lint (ruff), type check (mypy), pytest + coverage |
| **opa-test**          | `opa test policies/ -v`                          |
| **terraform-validate**| `terraform validate` across all 5 modules        |
| **conftest**          | Rego policy checks against Terraform plans        |
| **security-scan**     | Trivy filesystem scan (HIGH/CRITICAL)             |

## Requirements

- Python 3.10+
- Docker & Docker Compose (for full stack)
- Cloud credentials configured per provider SDK (AWS, Azure, GCP)
- OPA CLI (for local policy testing)
- Terraform (for infrastructure modules)

## License

See [LICENSE](LICENSE) for details.
