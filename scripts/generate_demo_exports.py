#!/usr/bin/env python3
"""
Generate demo audit export artifacts using the GRC Toolkit.

Produces example exports for every supported framework using realistic
AWS assessment data:
  - Full audit ZIP packages (per framework)
  - POA&M documents (txt + json)
  - Evidence exports (json + csv)
  - Executive summaries

Output goes to demo_exports/ in the project root.
"""

from __future__ import annotations

import csv
import io
import json
import shutil
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.framework_mapper import FrameworkMapper
from modules.report_generator import ReportGenerator

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "demo_exports"

# ── Realistic AWS assessment data ────────────────────────────────────

NOW = datetime.now(UTC)
RUN_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

DEMO_RESULTS = [
    {
        "id": "r-001", "control_id": "AC-2", "check_id": "iam_user_mfa",
        "assertion": "All IAM users have MFA enabled", "status": "fail",
        "severity": "high", "provider": "aws", "region": "us-east-1",
        "findings": [
            "3 IAM users without MFA: svc-deploy, svc-monitoring, dev-intern",
            "MFA adoption rate: 87% (26/30 users)",
        ],
        "evidence_summary": "IAM credential report shows 3 users without virtual or hardware MFA device",
        "remediation": "Enable MFA for all IAM users. Use hardware tokens for privileged accounts per AC-2(1).",
        "remediation_steps": [
            "Run: aws iam list-users | jq '.Users[] | select(.UserName)' to list all users",
            "For each user without MFA, create a virtual MFA device: aws iam create-virtual-mfa-device --virtual-mfa-device-name <user>-mfa --outfile qr.png",
            "Enable MFA: aws iam enable-mfa-device --user-name <user> --serial-number <arn> --authentication-code1 <code1> --authentication-code2 <code2>",
            "For privileged accounts (svc-deploy), use hardware tokens and register via the IAM console under Security Credentials",
            "Add an SCP or IAM policy condition: aws:MultiFactorAuthPresent to enforce MFA for sensitive operations",
            "Set up an AWS Config rule 'iam-user-mfa-enabled' to continuously monitor compliance",
        ],
        "aws_console_path": "IAM → Users → Select user → Security credentials → Assign MFA device",
        "assessed_at": (NOW - timedelta(minutes=15)).isoformat(),
    },
    {
        "id": "r-002", "control_id": "AC-2", "check_id": "iam_inactive_users",
        "assertion": "No IAM users inactive > 90 days", "status": "fail",
        "severity": "medium", "provider": "aws", "region": "us-east-1",
        "findings": [
            "2 users inactive > 90 days: former-contractor (142d), test-user (203d)",
        ],
        "evidence_summary": "IAM credential report last-activity analysis",
        "remediation": "Disable or remove inactive IAM users. Implement automated deprovisioning workflow.",
        "remediation_steps": [
            "Run: aws iam generate-credential-report && aws iam get-credential-report to identify inactive users",
            "For user 'former-contractor' (142d inactive): aws iam delete-login-profile --user-name former-contractor",
            "Deactivate access keys: aws iam update-access-key --user-name former-contractor --access-key-id <key> --status Inactive",
            "For user 'test-user' (203d inactive): aws iam delete-user --user-name test-user (after removing all attached resources)",
            "Implement Lambda-based automation: trigger on CloudWatch Events rule to flag users inactive > 90 days",
            "Create an AWS Config rule 'iam-user-unused-credentials-check' with maxCredentialUsageAge set to 90",
        ],
        "aws_console_path": "IAM → Users → Sort by 'Last activity' → Select inactive users → Delete or Disable",
        "assessed_at": (NOW - timedelta(minutes=14)).isoformat(),
    },
    {
        "id": "r-003", "control_id": "AC-6", "check_id": "iam_admin_policy",
        "assertion": "No IAM users have AdministratorAccess", "status": "fail",
        "severity": "high", "provider": "aws", "region": "us-east-1",
        "findings": [
            "1 IAM user with AdministratorAccess: legacy-admin (direct policy attachment)",
            "Wildcard admin policy found on user legacy-admin",
        ],
        "evidence_summary": "IAM policy audit via GetAccountAuthorizationDetails",
        "remediation": "Replace AdministratorAccess with scoped policies. Use roles with session duration limits.",
        "remediation_steps": [
            "Identify policy attachment: aws iam list-attached-user-policies --user-name legacy-admin",
            "Detach AdministratorAccess: aws iam detach-user-policy --user-name legacy-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "Review actual permissions needed using IAM Access Analyzer: aws accessanalyzer start-policy-generation --policy-generation-details ...",
            "Create scoped policy with only required permissions and attach: aws iam attach-user-policy --user-name legacy-admin --policy-arn <new-policy-arn>",
            "Migrate user to an IAM role with a max session duration: aws iam create-role --max-session-duration 3600 ...",
            "Enable CloudTrail data events to audit the legacy-admin's API activity during transition",
        ],
        "aws_console_path": "IAM → Users → legacy-admin → Permissions → Remove AdministratorAccess → Add scoped policy",
        "assessed_at": (NOW - timedelta(minutes=13)).isoformat(),
    },
    {
        "id": "r-004", "control_id": "AC-6", "check_id": "iam_role_least_priv",
        "assertion": "IAM roles follow least privilege", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": [],
        "evidence_summary": "Access Analyzer found no overly permissive role policies",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=12)).isoformat(),
    },
    {
        "id": "r-005", "control_id": "AU-2", "check_id": "cloudtrail_enabled",
        "assertion": "CloudTrail logging enabled in all regions", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": [],
        "evidence_summary": "Multi-region trail 'org-trail' active with management events enabled",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=11)).isoformat(),
    },
    {
        "id": "r-006", "control_id": "AU-2", "check_id": "cloudtrail_s3_logging",
        "assertion": "CloudTrail logs delivered to secured S3 bucket", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": [],
        "evidence_summary": "Trail delivers to s3://org-cloudtrail-logs with SSE-KMS encryption",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=10)).isoformat(),
    },
    {
        "id": "r-007", "control_id": "AU-6", "check_id": "guardduty_enabled",
        "assertion": "GuardDuty enabled for threat detection", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": [],
        "evidence_summary": "GuardDuty detector active with S3 protection and EKS audit log monitoring",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=9)).isoformat(),
    },
    {
        "id": "r-008", "control_id": "SC-7", "check_id": "sg_unrestricted_ssh",
        "assertion": "No security groups allow unrestricted SSH", "status": "fail",
        "severity": "high", "provider": "aws", "region": "us-east-1",
        "findings": [
            "Security group sg-0abc123def allows SSH (port 22) from 0.0.0.0/0",
            "Attached to 2 EC2 instances in prod VPC",
        ],
        "evidence_summary": "Security group ingress rule analysis via DescribeSecurityGroups",
        "remediation": "Restrict SSH access to known bastion/VPN CIDR ranges. Use SSM Session Manager instead.",
        "remediation_steps": [
            "Identify the security group: aws ec2 describe-security-groups --group-ids sg-0abc123def",
            "Remove the open SSH rule: aws ec2 revoke-security-group-ingress --group-id sg-0abc123def --protocol tcp --port 22 --cidr 0.0.0.0/0",
            "Add restricted rule for your VPN/bastion: aws ec2 authorize-security-group-ingress --group-id sg-0abc123def --protocol tcp --port 22 --cidr 10.0.0.0/8",
            "Install SSM Agent on the 2 affected EC2 instances and attach the AmazonSSMManagedInstanceCore role",
            "Use 'aws ssm start-session --target <instance-id>' instead of SSH for shell access",
            "Create an AWS Config rule 'restricted-ssh' to alert on future 0.0.0.0/0 SSH rules",
        ],
        "aws_console_path": "VPC → Security Groups → sg-0abc123def → Inbound rules → Edit → Remove 0.0.0.0/0 SSH rule",
        "assessed_at": (NOW - timedelta(minutes=8)).isoformat(),
    },
    {
        "id": "r-009", "control_id": "SC-7", "check_id": "vpc_flow_logs",
        "assertion": "VPC flow logs enabled on all VPCs", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": [],
        "evidence_summary": "All 3 VPCs have flow logs enabled (delivered to CloudWatch Logs)",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=7)).isoformat(),
    },
    {
        "id": "r-010", "control_id": "IA-2", "check_id": "root_mfa",
        "assertion": "Root account MFA enabled", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": [],
        "evidence_summary": "Root account has hardware MFA device enrolled",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=6)).isoformat(),
    },
    {
        "id": "r-011", "control_id": "IA-2", "check_id": "password_policy",
        "assertion": "Strong password policy configured", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": [],
        "evidence_summary": "Password policy: 14 char min, uppercase, lowercase, number, symbol, 90-day expiry",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=5)).isoformat(),
    },
    {
        "id": "r-012", "control_id": "CM-6", "check_id": "s3_public_access",
        "assertion": "S3 public access block enabled on all buckets", "status": "fail",
        "severity": "high", "provider": "aws", "region": "us-east-1",
        "findings": [
            "Bucket 'marketing-assets-prod' has public access block disabled",
            "Bucket contains 1,247 objects; review for sensitive data exposure",
        ],
        "evidence_summary": "S3 GetPublicAccessBlock analysis across 18 buckets in account",
        "remediation": "Enable S3 Block Public Access at account level. Review bucket for sensitive data.",
        "remediation_steps": [
            "Check current public access settings: aws s3api get-public-access-block --bucket marketing-assets-prod",
            "Enable public access block: aws s3api put-public-access-block --bucket marketing-assets-prod --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "Enable account-level block: aws s3control put-public-access-block --account-id 123456789012 --public-access-block-configuration ...",
            "Audit bucket contents for sensitive data: aws s3 ls s3://marketing-assets-prod --recursive | wc -l (1,247 objects)",
            "Run Macie classification scan: aws macie2 create-classification-job --job-type ONE_TIME --s3-job-definition ...",
            "Add bucket policy denying public access and enable S3 server access logging",
        ],
        "aws_console_path": "S3 → marketing-assets-prod → Permissions → Block public access → Edit → Enable all",
        "assessed_at": (NOW - timedelta(minutes=4)).isoformat(),
    },
    {
        "id": "r-013", "control_id": "CM-6", "check_id": "ebs_encryption",
        "assertion": "EBS default encryption enabled", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": [],
        "evidence_summary": "EBS default encryption enabled with aws/ebs KMS key",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=3)).isoformat(),
    },
    {
        "id": "r-014", "control_id": "SI-4", "check_id": "config_enabled",
        "assertion": "AWS Config enabled with required rules", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": [],
        "evidence_summary": "AWS Config recorder active with 42 managed rules deployed",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=2)).isoformat(),
    },
    {
        "id": "r-015", "control_id": "SI-4", "check_id": "securityhub_enabled",
        "assertion": "Security Hub enabled with standards", "status": "pass",
        "severity": "low", "provider": "aws", "region": "us-east-1",
        "findings": ["Security Hub score: 82%"],
        "evidence_summary": "Security Hub enabled with CIS AWS Foundations and AWS Foundational Security Best Practices",
        "remediation": None, "assessed_at": (NOW - timedelta(minutes=1)).isoformat(),
    },
]

DEMO_EVIDENCE = [
    {
        "id": "e-001", "control_id": "AC-2", "check_id": "iam_user_mfa",
        "provider": "aws", "service": "iam", "resource_type": "AWS::IAM::User",
        "region": "us-east-1", "account_id": "123456789012",
        "collected_at": NOW.isoformat(), "status": "fail",
        "normalized_data": {
            "total_users": 30, "mfa_enabled": 27,
            "mfa_disabled": ["svc-deploy", "svc-monitoring", "dev-intern"],
            "adoption_rate": "90%",
        },
    },
    {
        "id": "e-002", "control_id": "AC-6", "check_id": "iam_admin_policy",
        "provider": "aws", "service": "iam", "resource_type": "AWS::IAM::Policy",
        "region": "us-east-1", "account_id": "123456789012",
        "collected_at": NOW.isoformat(), "status": "fail",
        "normalized_data": {
            "users_with_admin": ["legacy-admin"],
            "admin_policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "attachment_type": "direct",
        },
    },
    {
        "id": "e-003", "control_id": "AU-2", "check_id": "cloudtrail_enabled",
        "provider": "aws", "service": "cloudtrail", "resource_type": "AWS::CloudTrail::Trail",
        "region": "us-east-1", "account_id": "123456789012",
        "collected_at": NOW.isoformat(), "status": "pass",
        "normalized_data": {
            "trail_name": "org-trail", "is_multi_region": True,
            "s3_bucket": "org-cloudtrail-logs",
            "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
            "log_file_validation": True,
        },
    },
    {
        "id": "e-004", "control_id": "SC-7", "check_id": "sg_unrestricted_ssh",
        "provider": "aws", "service": "ec2", "resource_type": "AWS::EC2::SecurityGroup",
        "region": "us-east-1", "account_id": "123456789012",
        "collected_at": NOW.isoformat(), "status": "fail",
        "normalized_data": {
            "security_group_id": "sg-0abc123def", "group_name": "legacy-web-sg",
            "vpc_id": "vpc-0def456abc",
            "offending_rule": {"protocol": "tcp", "port_range": "22", "source": "0.0.0.0/0"},
            "attached_instances": ["i-0123456789abcdef0", "i-0fedcba9876543210"],
        },
    },
    {
        "id": "e-005", "control_id": "CM-6", "check_id": "s3_public_access",
        "provider": "aws", "service": "s3", "resource_type": "AWS::S3::Bucket",
        "region": "us-east-1", "account_id": "123456789012",
        "collected_at": NOW.isoformat(), "status": "fail",
        "normalized_data": {
            "bucket_name": "marketing-assets-prod",
            "public_access_block": {
                "block_public_acls": False, "ignore_public_acls": False,
                "block_public_policy": False, "restrict_public_buckets": False,
            },
            "object_count": 1247, "total_size_gb": 3.8,
        },
    },
    {
        "id": "e-006", "control_id": "SI-4", "check_id": "securityhub_enabled",
        "provider": "aws", "service": "securityhub", "resource_type": "AWS::SecurityHub::Hub",
        "region": "us-east-1", "account_id": "123456789012",
        "collected_at": NOW.isoformat(), "status": "pass",
        "normalized_data": {
            "hub_arn": "arn:aws:securityhub:us-east-1:123456789012:hub/default",
            "standards_enabled": [
                "CIS AWS Foundations Benchmark v1.4.0",
                "AWS Foundational Security Best Practices v1.0.0",
            ],
            "overall_score": 82,
            "finding_count": {"CRITICAL": 2, "HIGH": 8, "MEDIUM": 15, "LOW": 23},
        },
    },
    {
        "id": "e-007", "control_id": "IA-2", "check_id": "root_mfa",
        "provider": "aws", "service": "iam", "resource_type": "AWS::IAM::RootUser",
        "region": "us-east-1", "account_id": "123456789012",
        "collected_at": NOW.isoformat(), "status": "pass",
        "normalized_data": {
            "mfa_active": True, "mfa_type": "hardware",
            "last_used": "never (best practice)",
        },
    },
    {
        "id": "e-008", "control_id": "AU-6", "check_id": "guardduty_enabled",
        "provider": "aws", "service": "guardduty", "resource_type": "AWS::GuardDuty::Detector",
        "region": "us-east-1", "account_id": "123456789012",
        "collected_at": NOW.isoformat(), "status": "pass",
        "normalized_data": {
            "detector_id": "abc123def456", "status": "ENABLED",
            "features": {
                "s3_protection": True, "eks_audit_logs": True,
                "malware_protection": True, "rds_login_events": True,
            },
        },
    },
]


def build_summary(results: list[dict]) -> dict:
    """Build assessment summary stats from result dicts."""
    total = len(results)
    passed = sum(1 for r in results if r.get("status") == "pass")
    failed = sum(1 for r in results if r.get("status") == "fail")
    errors = sum(1 for r in results if r.get("status") == "error")

    by_control: dict[str, dict[str, int]] = {}
    for r in results:
        ctrl = r.get("control_id", "")
        family = ctrl.split("-")[0] if "-" in ctrl else ctrl
        if family not in by_control:
            by_control[family] = {"pass": 0, "fail": 0, "error": 0}
        status = r.get("status", "")
        if status in by_control[family]:
            by_control[family][status] += 1

    return {
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "not_assessed": total - passed - failed - errors,
        "pass_rate": f"{passed / total * 100:.1f}%" if total > 0 else "N/A",
        "by_control": by_control,
    }


def generate_all():
    """Generate all demo export artifacts."""
    mapper = FrameworkMapper.from_yaml()
    report_gen = ReportGenerator(
        organization="Acme Cloud Corp",
        system_name="Production AWS Environment",
    )
    target_frameworks = mapper.frameworks
    print(f"  Frameworks: {', '.join(target_frameworks)}")

    # ── Audit packages (ZIP per framework) ────────────────────────────
    pkg_dir = OUTPUT_DIR / "audit_packages"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    for fw in target_frameworks:
        mapped_results = mapper.map_results(
            [dict(r) for r in DEMO_RESULTS], "nist_800_53", fw
        )
        mapped_evidence = mapper.map_evidence(
            [dict(e) for e in DEMO_EVIDENCE], "nist_800_53", fw
        )
        summary = build_summary(mapped_results)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            manifest = {
                "source_framework": "nist_800_53",
                "target_framework": fw,
                "mapping_applied": fw != "nist_800_53",
                "assessment_run_id": RUN_ID,
                "generated_at": NOW.isoformat(),
                "files": [],
            }

            # Assessment results
            zf.writestr("assessment_results.json", json.dumps(mapped_results, indent=2, default=str))
            manifest["files"].append("assessment_results.json")

            # Summary
            zf.writestr("summary.json", json.dumps(summary, indent=2))
            manifest["files"].append("summary.json")

            # POA&M
            import tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                poam_path = f"{tmpdir}/poam.txt"
                report_gen.generate_poam(mapped_results, poam_path, assessment_id=RUN_ID)
                with open(poam_path) as f:
                    zf.writestr("poam.txt", f.read())
            manifest["files"].append("poam.txt")

            # Executive summary
            with tempfile.TemporaryDirectory() as tmpdir:
                es_path = f"{tmpdir}/executive_summary.txt"
                report_gen.generate_executive_summary(summary, mapped_results, es_path, framework=fw)
                with open(es_path) as f:
                    zf.writestr("executive_summary.txt", f.read())
            manifest["files"].append("executive_summary.txt")

            # Evidence files
            for ev in mapped_evidence:
                ctrl = ev.get("control_id", "unknown")
                eid = ev.get("id", "unknown")
                zf.writestr(f"evidence/{ctrl}_{eid}.json", json.dumps(ev, indent=2, default=str))
            manifest["files"].append(f"evidence/ ({len(mapped_evidence)} files)")

            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        buf.seek(0)
        path = pkg_dir / f"audit_package_{fw}.zip"
        path.write_bytes(buf.getvalue())
        print(f"  [ZIP]  {path.name} ({len(buf.getvalue()):,} bytes)")

    # ── POA&M exports ─────────────────────────────────────────────────
    poam_dir = OUTPUT_DIR / "poam"
    poam_dir.mkdir(parents=True, exist_ok=True)

    for fw in ["nist_800_53", "soc2", "iso27001", "cmmc_l2", "hipaa"]:
        mapped = mapper.map_results([dict(r) for r in DEMO_RESULTS], "nist_800_53", fw)
        summary = build_summary(mapped)

        # Text format
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            poam_path = f"{tmpdir}/poam.txt"
            report_gen.generate_poam(mapped, poam_path, assessment_id=RUN_ID)
            with open(poam_path) as f:
                content = f.read()
        path = poam_dir / f"poam_{fw}.txt"
        path.write_text(content)
        print(f"  [POAM] {path.name}")

        # JSON format
        failures = [r for r in mapped if r.get("status") == "fail"]
        poam_items = []
        for i, result in enumerate(failures, 1):
            poam_items.append({
                "poam_id": f"POAM-{i:04d}",
                "control_id": result.get("control_id", ""),
                "original_control_id": result.get("original_control_id", result.get("control_id", "")),
                "check_id": result.get("check_id", ""),
                "status": "Open",
                "severity": result.get("severity", "medium"),
                "provider": result.get("provider", ""),
                "region": result.get("region", ""),
                "findings": result.get("findings", []),
                "remediation": result.get("remediation", "See framework guidance"),
            })
        poam_json = {
            "metadata": {
                "assessment_run_id": RUN_ID,
                "framework": fw,
                "generated_at": NOW.isoformat(),
            },
            "total_findings": len(poam_items),
            "items": poam_items,
        }
        path = poam_dir / f"poam_{fw}.json"
        path.write_text(json.dumps(poam_json, indent=2, default=str))
        print(f"  [POAM] {path.name}")

    # ── Evidence exports ──────────────────────────────────────────────
    ev_dir = OUTPUT_DIR / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)

    # All evidence — JSON
    ev_export = {
        "metadata": {
            "total": len(DEMO_EVIDENCE),
            "assessment_run_id": RUN_ID,
            "generated_at": NOW.isoformat(),
        },
        "evidence": DEMO_EVIDENCE,
    }
    path = ev_dir / "evidence_all.json"
    path.write_text(json.dumps(ev_export, indent=2, default=str))
    print(f"  [EVID] {path.name}")

    # All evidence — CSV
    output = io.StringIO()
    flat_keys = ["id", "control_id", "check_id", "provider", "service",
                 "resource_type", "region", "account_id", "collected_at",
                 "status", "normalized_data"]
    writer = csv.DictWriter(output, fieldnames=flat_keys)
    writer.writeheader()
    for ev in DEMO_EVIDENCE:
        flat = {}
        for k in flat_keys:
            v = ev.get(k, "")
            flat[k] = json.dumps(v) if isinstance(v, (dict, list)) else v
        writer.writerow(flat)
    path = ev_dir / "evidence_all.csv"
    path.write_text(output.getvalue())
    print(f"  [EVID] {path.name}")

    # Evidence filtered by AC family
    ac_evidence = [e for e in DEMO_EVIDENCE if e["control_id"].startswith("AC")]
    ac_export = {
        "metadata": {
            "total": len(ac_evidence),
            "control_family_filter": "AC",
            "generated_at": NOW.isoformat(),
        },
        "evidence": ac_evidence,
    }
    path = ev_dir / "evidence_AC_family.json"
    path.write_text(json.dumps(ac_export, indent=2, default=str))
    print(f"  [EVID] {path.name} (filtered: AC family)")

    # Evidence mapped to SOC2
    mapped_ev = mapper.map_evidence([dict(e) for e in DEMO_EVIDENCE], "nist_800_53", "soc2")
    soc2_export = {
        "metadata": {
            "total": len(mapped_ev),
            "target_framework": "soc2",
            "generated_at": NOW.isoformat(),
        },
        "evidence": mapped_ev,
    }
    path = ev_dir / "evidence_mapped_soc2.json"
    path.write_text(json.dumps(soc2_export, indent=2, default=str))
    print(f"  [EVID] {path.name} (crosswalk: NIST->SOC2)")

    # ── Executive summaries ───────────────────────────────────────────
    summary_dir = OUTPUT_DIR / "executive_summaries"
    summary_dir.mkdir(parents=True, exist_ok=True)

    for fw in ["nist_800_53", "soc2", "iso27001", "cmmc_l2", "hipaa"]:
        mapped = mapper.map_results([dict(r) for r in DEMO_RESULTS], "nist_800_53", fw)
        summary = build_summary(mapped)

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            es_path = f"{tmpdir}/executive_summary.txt"
            report_gen.generate_executive_summary(summary, mapped, es_path, framework=fw)
            with open(es_path) as f:
                content = f.read()
        path = summary_dir / f"executive_summary_{fw}.txt"
        path.write_text(content)
        print(f"  [EXEC] {path.name}")

    # ── Framework mappings info ───────────────────────────────────────
    fw_info = {"frameworks": mapper.frameworks}
    for fw in mapper.frameworks:
        fw_info[fw] = {"available_targets": mapper.get_available_mappings(fw)}
    path = OUTPUT_DIR / "framework_mappings.json"
    path.write_text(json.dumps(fw_info, indent=2))
    print(f"  [MAP]  {path.name}")


def main():
    print("=" * 60)
    print("GRC Toolkit — Demo Export Generator")
    print("=" * 60)

    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)

    print("\nGenerating exports for all frameworks...")
    generate_all()

    print(f"\n{'=' * 60}")
    print(f"Done! All exports in: {OUTPUT_DIR.relative_to(Path.cwd())}/")
    print(f"{'=' * 60}")

    for p in sorted(OUTPUT_DIR.rglob("*")):
        if p.is_file():
            rel = p.relative_to(OUTPUT_DIR)
            size = p.stat().st_size
            print(f"  {rel}  ({size:,} bytes)")


if __name__ == "__main__":
    main()
