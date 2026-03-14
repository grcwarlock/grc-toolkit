# GRC Toolkit: Deployment & Operations Guide

## Phase 1: Local Setup and First Run

### Prerequisites

You need Python 3.10+ and an AWS account with programmatic access. The toolkit starts with AWS because that's where most of the mature audit APIs live, but the architecture supports Azure and GCP once you're ready.

### Install and Configure

```bash
# Clone or copy the toolkit to your working directory
cd grc-toolkit

# Create a virtual environment (keeps dependencies isolated)
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### AWS Credentials

The toolkit uses the standard boto3 credential chain, so you have several options depending on your environment.

**Option A: AWS CLI profile (simplest for local development)**

```bash
aws configure --profile grc-audit
# Enter your Access Key, Secret Key, region (us-east-1), and output format (json)

# Tell the toolkit to use this profile
export AWS_PROFILE=grc-audit
```

**Option B: Environment variables (good for containers and CI/CD)**

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

**Option C: IAM Role assumption (recommended for production)**

If you're running this from an EC2 instance or ECS task, attach an IAM role directly. For cross-account auditing, configure the `assume_role_arn` in `config/settings.yaml` and create a trust relationship in each target account.

### Required IAM Permissions

Create a dedicated IAM policy for the toolkit. This follows least privilege by granting read-only access to the specific APIs the framework checks call.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "GRCToolkitAuditAccess",
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListPolicies",
                "iam:ListMFADevices",
                "iam:ListAttachedUserPolicies",
                "iam:GetAccountSummary",
                "iam:GetCredentialReport",
                "iam:GenerateCredentialReport",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeNetworkAcls",
                "guardduty:ListDetectors",
                "securityhub:DescribeHub",
                "sts:GetCallerIdentity",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
```

As you add control families and checks to `frameworks.yaml`, extend this policy to cover the new API calls. The pattern is always read-only Describe/List/Get actions.

### Configure settings.yaml

```bash
cp config/settings.yaml config/settings.local.yaml
```

Edit `config/settings.local.yaml` with your actual values:

```yaml
environment:
  name: "production"
  organization: "Your Org Name"
  timezone: "America/Denver"

cloud_providers:
  aws:
    enabled: true
    regions:
      - "us-east-1"
      - "us-west-2"
    assume_role_arn: ""  # Fill in if using cross-account roles
```

### First Collection Run

Start with a dry run to see what the toolkit plans to do without actually calling any APIs:

```bash
python scripts/run_collection.py --framework nist_800_53 --control-family AC --dry-run
```

This prints a table showing every API call it would make, which controls they map to, and which regions it would query. Once that looks right:

```bash
python scripts/run_collection.py --framework nist_800_53 --control-family AC \
    --config config/settings.local.yaml
```

Evidence gets saved to `evidence/{timestamp}/` as individual JSON files with a manifest. Each file is self-describing: it contains the control ID, check ID, provider, region, timestamp, and the raw API response.

### First Assessment Run

```bash
python scripts/run_assessment.py --config config/settings.local.yaml
```

This loads the most recent evidence collection, evaluates each artifact against its assertion, and generates three reports in `reports/`:

- A POA&M document listing every failing control with severity classification
- An executive summary with pass rates by control family and recommendations
- A JSON export for programmatic consumption or integration with other tools

### First Risk Analysis

This one doesn't need cloud credentials since it works with scenario definitions:

```bash
# Basic portfolio analysis
python scripts/run_risk_analysis.py

# With treatment comparison (shows cost-benefit of different controls)
python scripts/run_risk_analysis.py --compare-treatments

# Higher precision with more iterations
python scripts/run_risk_analysis.py --iterations 50000 --seed 42
```

The example scenarios in `risk_engine.py` use industry benchmarks as defaults. Replace these with your organization's actual data for meaningful results. The key inputs for each scenario are frequency (how often per year) and impact (dollar cost per event), each expressed as min/mode/max to capture uncertainty.


## Phase 2: Scheduling for Continuous Monitoring

Running these scripts manually is fine for getting started, but the real value comes from putting them on a schedule so compliance monitoring happens continuously rather than in quarterly audit panics.

### Option A: Cron (Simplest)

For a single server or VM, cron handles this cleanly.

```bash
# Edit crontab
crontab -e

# Run full evidence collection daily at 2 AM
0 2 * * * cd /opt/grc-toolkit && /opt/grc-toolkit/venv/bin/python scripts/run_collection.py --config config/settings.local.yaml >> /var/log/grc-collection.log 2>&1

# Run assessment immediately after collection (2:30 AM gives plenty of buffer)
30 2 * * * cd /opt/grc-toolkit && /opt/grc-toolkit/venv/bin/python scripts/run_assessment.py --config config/settings.local.yaml >> /var/log/grc-assessment.log 2>&1

# Run risk analysis weekly on Monday mornings
0 6 * * 1 cd /opt/grc-toolkit && /opt/grc-toolkit/venv/bin/python scripts/run_risk_analysis.py --compare-treatments >> /var/log/grc-risk.log 2>&1
```

### Option B: Systemd Timers (Better for Linux servers)

Systemd timers give you better logging, failure handling, and dependency management than cron.

Create `/etc/systemd/system/grc-collection.service`:

```ini
[Unit]
Description=GRC Toolkit Evidence Collection
After=network-online.target

[Service]
Type=oneshot
User=grc-toolkit
WorkingDirectory=/opt/grc-toolkit
ExecStart=/opt/grc-toolkit/venv/bin/python scripts/run_collection.py --config config/settings.local.yaml
Environment=AWS_PROFILE=grc-audit
StandardOutput=journal
StandardError=journal
```

Create `/etc/systemd/system/grc-collection.timer`:

```ini
[Unit]
Description=Daily GRC Evidence Collection

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now grc-collection.timer
sudo systemctl status grc-collection.timer

# Check logs
journalctl -u grc-collection.service --since today
```

### Option C: AWS Lambda + EventBridge (Serverless)

For an AWS-native deployment that doesn't require a running server, package the toolkit as a Lambda function triggered by EventBridge (formerly CloudWatch Events).

```bash
# Package the toolkit for Lambda
mkdir -p lambda-package
pip install -r requirements.txt -t lambda-package/
cp -r modules/ lambda-package/
cp -r config/ lambda-package/
cp lambda_handler.py lambda-package/
cd lambda-package && zip -r ../grc-toolkit-lambda.zip .
```

Create a `lambda_handler.py` in the project root:

```python
"""Lambda handler for serverless GRC toolkit execution."""

import json
import boto3
from modules.evidence_collector import AWSCollector, EvidenceStore, load_framework_checks
from modules.control_assessor import ControlAssessor
from modules.report_generator import ReportGenerator


def handler(event, context):
    """
    Triggered by EventBridge on a schedule.
    Collects evidence, runs assessment, stores results in S3.
    """
    # Parse configuration from event or environment
    framework = event.get("framework", "nist_800_53")
    control_family = event.get("control_family", "")
    s3_bucket = event.get("s3_bucket", "grc-toolkit-evidence")

    # Load checks
    checks = load_framework_checks("config/frameworks.yaml", framework, control_family)
    aws_checks = [c for c in checks if c["provider"] == "aws"]

    # Collect evidence
    collector = AWSCollector(regions=["us-east-1", "us-west-2"])
    artifacts = []
    for check in aws_checks:
        artifacts.extend(collector.collect(
            service=check["service"],
            method=check["method"],
            control_id=check["control_id"],
            check_id=check["check_id"],
        ))

    # Save evidence locally (Lambda has /tmp)
    store = EvidenceStore("/tmp/evidence")
    run_dir = store.save(artifacts)

    # Run assessment
    assessor = ControlAssessor()
    results = assessor.assess(artifacts, checks)
    summary = assessor.summarize(results)

    # Upload results to S3
    s3 = boto3.client("s3")
    results_json = json.dumps({
        "summary": summary,
        "results": [r.to_dict() for r in results],
    }, indent=2, default=str)

    run_id = run_dir.name
    s3.put_object(
        Bucket=s3_bucket,
        Key=f"assessments/{run_id}/results.json",
        Body=results_json,
        ContentType="application/json",
    )

    return {
        "statusCode": 200,
        "body": {
            "run_id": run_id,
            "total_checks": summary["total_checks"],
            "pass_rate": summary.get("pass_rate", "N/A"),
            "s3_location": f"s3://{s3_bucket}/assessments/{run_id}/",
        },
    }
```

EventBridge rule (via CloudFormation or Terraform):

```yaml
# CloudFormation snippet
GRCScheduleRule:
  Type: AWS::Events::Rule
  Properties:
    Description: "Daily GRC evidence collection and assessment"
    ScheduleExpression: "cron(0 2 * * ? *)"
    State: ENABLED
    Targets:
      - Arn: !GetAtt GRCToolkitFunction.Arn
        Id: "GRCDailyCollection"
        Input: |
          {
            "framework": "nist_800_53",
            "s3_bucket": "grc-toolkit-evidence"
          }
```

### Option D: Docker + ECS/Kubernetes (Scalable)

For organizations running containerized workloads, package the toolkit as a Docker image.

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY modules/ modules/
COPY scripts/ scripts/
COPY config/ config/

# Default: run full collection + assessment pipeline
CMD ["python", "scripts/run_collection.py", "--config", "config/settings.yaml"]
```

```bash
docker build -t grc-toolkit:latest .

# Run locally to test
docker run --rm \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION \
    -v $(pwd)/evidence:/app/evidence \
    -v $(pwd)/reports:/app/reports \
    grc-toolkit:latest
```

Deploy as a scheduled ECS task or Kubernetes CronJob for production.


## Phase 3: Alerting and Notifications

Knowing about failures after the fact is table stakes. The real value is getting notified the moment something drifts out of compliance.

### Slack Notifications

Add this to your pipeline after the assessment step. Create a Slack incoming webhook and drop the URL into your settings.

```python
"""notify.py - Send assessment results to Slack."""

import json
import requests


def send_slack_alert(webhook_url: str, summary: dict, failures: list[dict]):
    """Post assessment results to a Slack channel."""

    # Color-code based on pass rate
    pass_rate = float(summary.get("pass_rate", "0%").replace("%", ""))
    color = "#36a64f" if pass_rate >= 90 else "#ff9900" if pass_rate >= 70 else "#ff0000"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "GRC Assessment Results"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Pass Rate:* {summary.get('pass_rate', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Total Checks:* {summary['total_checks']}"},
                {"type": "mrkdwn", "text": f"*Passed:* {summary['passed']}"},
                {"type": "mrkdwn", "text": f"*Failed:* {summary['failed']}"},
            ]
        },
    ]

    # Add top failures if any exist
    if failures:
        failure_text = "\n".join(
            f"• *{f['control_id']}* ({f['check_id']}): {f.get('findings', [''])[0][:100]}"
            for f in failures[:5]
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top Findings:*\n{failure_text}"}
        })

    payload = {
        "attachments": [{"color": color, "blocks": blocks}]
    }

    response = requests.post(webhook_url, json=payload)
    response.raise_for_status()
```

### Email Notifications

For organizations that prefer email (or need it for audit trail purposes):

```python
"""email_notify.py - Send assessment digest via email."""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email_digest(smtp_config: dict, summary: dict, recipients: list[str]):
    """Send a formatted assessment digest email."""

    pass_rate = summary.get("pass_rate", "N/A")
    subject = f"GRC Assessment: {pass_rate} Pass Rate - {summary['failed']} Findings"

    body = f"""
    GRC Compliance Assessment Results
    ==================================

    Pass Rate:      {pass_rate}
    Total Checks:   {summary['total_checks']}
    Passed:         {summary['passed']}
    Failed:         {summary['failed']}
    Errors:         {summary['errors']}

    Control Family Breakdown:
    """

    for family, counts in summary.get("by_control", {}).items():
        body += f"    {family}: {counts['pass']} pass / {counts['fail']} fail / {counts['error']} error\n"

    body += "\n    Full report available in the reports/ directory."

    msg = MIMEMultipart()
    msg["From"] = smtp_config["sender"]
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(smtp_config["server"], smtp_config["port"]) as server:
        server.starttls()
        server.login(smtp_config["sender"], smtp_config["password"])
        server.sendmail(smtp_config["sender"], recipients, msg.as_string())
```


## Phase 4: Expanding the Framework

### Adding New Control Families

The toolkit is designed so that adding coverage for a new control family follows a repeatable two-step process.

**Step 1: Define the checks in frameworks.yaml**

```yaml
# Add under nist_800_53 > control_families
CM:
  name: "Configuration Management"
  controls:
    CM-2:
      title: "Baseline Configuration"
      description: "Develop, document, and maintain baseline configurations."
      checks:
        - id: "CM-2.a"
          description: "Establish and document baseline configurations"
          evidence_type: "config_baseline"
          cloud_checks:
            aws:
              - service: "config"
                method: "describe_config_rules"
                assertion: "config_rules_active"
              - service: "ssm"
                method: "describe_instance_information"
                assertion: "all_instances_managed"
```

**Step 2: Register the assertion functions in control_assessor.py**

```python
@self.register("config_rules_active")
def check_config_rules(data):
    """Verify AWS Config rules are active and evaluating."""
    findings = []
    rules = _extract_key(data, "ConfigRules", [])

    if not rules:
        findings.append("No AWS Config rules configured")
        return False, findings

    inactive = [r for r in rules if r.get("ConfigRuleState") != "ACTIVE"]
    if inactive:
        names = [r.get("ConfigRuleName", "unknown") for r in inactive]
        findings.append(f"Inactive Config rules: {', '.join(names)}")
        return False, findings

    findings.append(f"All {len(rules)} AWS Config rules are active")
    return True, findings
```

**Step 3: Update the IAM policy** to include the new API actions (`config:DescribeConfigRules`, `ssm:DescribeInstanceInformation`).

That's the whole cycle. Framework YAML defines what to check, assertions define how to evaluate it, and the IAM policy grants access to do it.

### Adding Azure and GCP Collectors

The evidence collector architecture makes it straightforward to add new cloud providers. Create an `AzureCollector` or `GCPCollector` class following the same interface as `AWSCollector`:

```python
class AzureCollector:
    def __init__(self, subscription_id: str, tenant_id: str):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()

    def collect(self, service: str, method: str,
                control_id: str, check_id: str) -> list[EvidenceArtifact]:
        # Same return type as AWSCollector
        ...
```

The `run_collection.py` script already checks `settings.yaml` for enabled providers, so once you wire up the collector, it integrates automatically.

### Customizing Risk Scenarios

Replace the example scenarios in `risk_engine.py` with your own. The most important thing is getting realistic frequency and impact ranges. Good sources include your organization's incident history, industry reports (IBM Cost of a Data Breach, Verizon DBIR), and input from your security team expressed as min/mode/max estimates.

```python
ThreatScenario(
    name="Your Specific Scenario",
    description="Tailored to your threat landscape",
    category="your_category",
    frequency_min=0.1,      # Optimistic: could happen as rarely as once per decade
    frequency_mode=0.5,     # Most likely: about once every two years
    frequency_max=2.0,      # Pessimistic: could happen twice in a bad year
    impact_min=50_000,      # Best case cost
    impact_mode=300_000,    # Most likely cost
    impact_max=2_000_000,   # Worst case cost
    control_effectiveness=0.4,  # Existing controls reduce frequency by 40%
    data_source="Internal incident data 2022-2025",
)
```


## Phase 5: Integration Points

### Feeding Results into a GRC Platform

If your organization uses a GRC platform (ServiceNow GRC, Archer, Jira for compliance tracking), the JSON export from the assessment pipeline becomes your integration point.

```python
# Example: Push findings to ServiceNow via REST API
import requests

def push_to_servicenow(instance_url: str, credentials: tuple,
                       assessment_results: list[dict]):
    """Create GRC findings in ServiceNow."""
    for result in assessment_results:
        if result["status"] != "fail":
            continue

        payload = {
            "short_description": f"{result['control_id']}: {result['assertion']}",
            "description": "\n".join(result.get("findings", [])),
            "priority": severity_to_priority(result),
            "category": "Compliance",
            "u_control_id": result["control_id"],
            "u_check_id": result["check_id"],
            "u_provider": result["provider"],
        }

        response = requests.post(
            f"{instance_url}/api/now/table/sn_grc_finding",
            auth=credentials,
            json=payload,
        )
        response.raise_for_status()
```

### Storing Historical Data

For trend analysis over time, push assessment summaries into a database. SQLite works fine for single-server deployments; PostgreSQL or DynamoDB for production scale.

```python
import sqlite3
from datetime import datetime

def store_assessment_history(db_path: str, run_id: str, summary: dict):
    """Store assessment summary for trend tracking."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS assessment_history (
            run_id TEXT PRIMARY KEY,
            assessed_at TEXT,
            total_checks INTEGER,
            passed INTEGER,
            failed INTEGER,
            errors INTEGER,
            pass_rate TEXT,
            summary_json TEXT
        )
    """)
    conn.execute(
        "INSERT INTO assessment_history VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, datetime.utcnow().isoformat(), summary["total_checks"],
         summary["passed"], summary["failed"], summary["errors"],
         summary.get("pass_rate", ""), json.dumps(summary)),
    )
    conn.commit()
    conn.close()
```

### CI/CD Integration

Run compliance checks as part of your infrastructure deployment pipeline. If a Terraform apply would create a security group with unrestricted ingress, catch it before it hits production.

```yaml
# GitHub Actions example
name: Compliance Check
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Collect evidence
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_AUDIT_KEY }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_AUDIT_SECRET }}
        run: python scripts/run_collection.py --config config/settings.yaml

      - name: Run assessment
        run: python scripts/run_assessment.py --output reports/

      - name: Check pass rate
        run: |
          PASS_RATE=$(python -c "
          import json
          with open('reports/assessment_*.json') as f:
              data = json.load(f)
          rate = float(data['summary']['pass_rate'].replace('%',''))
          print(rate)
          ")
          if (( $(echo "$PASS_RATE < 80" | bc -l) )); then
            echo "::error::Compliance pass rate ($PASS_RATE%) below 80% threshold"
            exit 1
          fi

      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: compliance-reports
          path: reports/
```


## Quick Reference: File Locations

| What | Where | Purpose |
|------|-------|---------|
| Framework definitions | `config/frameworks.yaml` | Control requirements and cloud API mappings |
| Environment config | `config/settings.yaml` | Credentials, regions, paths |
| Evidence artifacts | `evidence/{run_id}/` | Raw API responses with provenance |
| Assessment reports | `reports/` | POA&M, executive summaries, JSON exports |
| Risk analysis | `reports/risk_analysis.json` | Monte Carlo simulation results |
| Logs | `grc-toolkit.log` | Runtime logging |


## Troubleshooting

**"No AWS credentials configured"**
The boto3 credential chain isn't finding credentials. Verify with `aws sts get-caller-identity` that your CLI is authenticated, and check that `AWS_PROFILE` is set if using named profiles.

**"ClientError: AccessDenied"**
The IAM policy attached to your credentials is missing the required action. Check the error message for the specific API call that failed and add it to your policy.

**"No checks found for framework"**
The framework identifier in your command doesn't match what's in `frameworks.yaml`. Use underscores: `nist_800_53`, not `nist-800-53`.

**Assessment shows all "not_assessed"**
The evidence collection likely failed silently. Check the evidence manifest for artifacts with `"status": "error"` and review the error messages.

**Risk engine produces unrealistic numbers**
The example scenarios use industry averages. Replace them with your organization's actual incident data and loss estimates. Garbage in, garbage out applies doubly to Monte Carlo simulation.
