"""
lambda_handler.py
AWS Lambda entry point for serverless GRC toolkit execution.

Triggered by EventBridge on a schedule. Collects evidence,
runs assessment, and stores results in S3.

Deploy with:
    mkdir lambda-package
    pip install -r requirements.txt -t lambda-package/
    cp -r modules/ config/ lambda_handler.py lambda-package/
    cd lambda-package && zip -r ../grc-toolkit-lambda.zip .
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

from modules.evidence_collector import AWSCollector, EvidenceStore, load_framework_checks
from modules.control_assessor import ControlAssessor
from modules.report_generator import ReportGenerator

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    """
    Lambda handler triggered by EventBridge.

    Expected event format:
    {
        "framework": "nist_800_53",
        "control_family": "",          # optional, empty = all families
        "s3_bucket": "grc-toolkit-evidence",
        "regions": ["us-east-1"],      # optional, overrides config
        "notify_slack": true,          # optional
        "slack_webhook": "https://..."  # optional
    }
    """
    framework = event.get("framework", "nist_800_53")
    control_family = event.get("control_family", "")
    s3_bucket = event.get("s3_bucket", os.environ.get("GRC_S3_BUCKET", "grc-toolkit-evidence"))
    regions = event.get("regions", ["us-east-1"])

    logger.info(
        "Starting GRC assessment: framework=%s, family=%s, regions=%s",
        framework, control_family, regions
    )

    # Load framework checks
    checks = load_framework_checks("config/frameworks.yaml", framework, control_family)
    aws_checks = [c for c in checks if c["provider"] == "aws"]

    if not aws_checks:
        return {
            "statusCode": 400,
            "body": {"error": f"No AWS checks found for {framework}/{control_family}"},
        }

    # Collect evidence
    collector = AWSCollector(regions=regions)
    artifacts = []

    for check in aws_checks:
        try:
            result = collector.collect(
                service=check["service"],
                method=check["method"],
                control_id=check["control_id"],
                check_id=check["check_id"],
            )
            artifacts.extend(result)
        except Exception as e:
            logger.error("Collection failed for %s: %s", check["check_id"], e)

    # Save evidence locally (Lambda provides /tmp with up to 10GB)
    store = EvidenceStore("/tmp/evidence")
    run_dir = store.save(artifacts)
    run_id = run_dir.name

    logger.info("Collected %d artifacts, run_id=%s", len(artifacts), run_id)

    # Run assessment
    assessor = ControlAssessor()
    results = assessor.assess(artifacts, checks)
    summary = assessor.summarize(results)

    results_dicts = [r.to_dict() for r in results]

    # Generate reports
    generator = ReportGenerator(
        organization=os.environ.get("GRC_ORGANIZATION", ""),
        system_name=os.environ.get("GRC_SYSTEM_NAME", "Primary System"),
    )

    generator.generate_poam(results_dicts, f"/tmp/reports/poam_{run_id}.txt")
    generator.generate_executive_summary(
        summary, results_dicts, f"/tmp/reports/exec_{run_id}.txt"
    )

    # Upload everything to S3
    s3 = boto3.client("s3")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Assessment results JSON
    s3.put_object(
        Bucket=s3_bucket,
        Key=f"assessments/{timestamp}/{run_id}/results.json",
        Body=json.dumps({
            "metadata": {
                "run_id": run_id,
                "framework": framework,
                "assessed_at": datetime.now(timezone.utc).isoformat(),
            },
            "summary": summary,
            "results": results_dicts,
        }, indent=2, default=str),
        ContentType="application/json",
    )

    # Upload report files
    for report_file in [f"/tmp/reports/poam_{run_id}.txt", f"/tmp/reports/exec_{run_id}.txt"]:
        try:
            with open(report_file) as f:
                filename = report_file.split("/")[-1]
                s3.put_object(
                    Bucket=s3_bucket,
                    Key=f"assessments/{timestamp}/{run_id}/{filename}",
                    Body=f.read(),
                    ContentType="text/plain",
                )
        except FileNotFoundError:
            logger.warning("Report file not found: %s", report_file)

    # Optional Slack notification
    if event.get("notify_slack") and event.get("slack_webhook"):
        try:
            from modules.notify import send_slack_alert
            failures = [r for r in results_dicts if r["status"] == "fail"]
            send_slack_alert(event["slack_webhook"], summary, failures)
        except Exception as e:
            logger.error("Slack notification failed: %s", e)

    response_body = {
        "run_id": run_id,
        "total_checks": summary["total_checks"],
        "passed": summary["passed"],
        "failed": summary["failed"],
        "pass_rate": summary.get("pass_rate", "N/A"),
        "s3_location": f"s3://{s3_bucket}/assessments/{timestamp}/{run_id}/",
    }

    logger.info("Assessment complete: %s", json.dumps(response_body))

    return {
        "statusCode": 200,
        "body": response_body,
    }
