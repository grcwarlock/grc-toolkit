"""
evidence_collector.py
Automated evidence collection from cloud environments.

Pulls configuration state from AWS, Azure, and GCP APIs,
structures the output as timestamped evidence artifacts,
and stores them for downstream control assessment.
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
import yaml
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


@dataclass
class EvidenceArtifact:
    """A single piece of collected evidence tied to a control check."""
    control_id: str
    check_id: str
    provider: str
    service: str
    method: str
    region: str
    collected_at: str
    data: Any
    status: str = "collected"  # collected, error, timeout
    error_message: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class AWSCollector:
    """
    Collects evidence from AWS environments.

    Each method corresponds to an AWS API call defined in the
    framework configuration. Results get wrapped in EvidenceArtifact
    objects with full provenance metadata.
    """

    def __init__(self, regions: list[str], assume_role_arn: str = ""):
        self.regions = regions
        self.assume_role_arn = assume_role_arn
        self._sessions: dict[str, boto3.Session] = {}

    def _get_session(self, region: str) -> boto3.Session:
        """Get or create a boto3 session for a region, with optional role assumption."""
        if region in self._sessions:
            return self._sessions[region]

        if self.assume_role_arn:
            sts = boto3.client("sts", region_name=region)
            creds = sts.assume_role(
                RoleArn=self.assume_role_arn,
                RoleSessionName="grc-toolkit-audit"
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        else:
            session = boto3.Session(region_name=region)

        self._sessions[region] = session
        return session

    def collect(self, service: str, method: str, control_id: str,
                check_id: str) -> list[EvidenceArtifact]:
        """
        Run a single evidence collection across all configured regions.

        For global services like IAM, only the first region is used.
        Regional services like EC2 get queried in every region.
        """
        global_services = {"iam", "s3", "cloudfront", "route53", "organizations"}
        regions = [self.regions[0]] if service in global_services else self.regions
        artifacts = []

        for region in regions:
            artifact = self._collect_single(
                service, method, control_id, check_id, region
            )
            artifacts.append(artifact)

        return artifacts

    def _collect_single(self, service: str, method: str, control_id: str,
                        check_id: str, region: str) -> EvidenceArtifact:
        """Execute a single API call and wrap the result."""
        timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            session = self._get_session(region)
            client = session.client(service)

            # Handle paginated responses automatically
            data = self._paginated_call(client, method)

            return EvidenceArtifact(
                control_id=control_id,
                check_id=check_id,
                provider="aws",
                service=service,
                method=method,
                region=region,
                collected_at=timestamp,
                data=data,
                status="collected",
                metadata={
                    "account_id": session.client("sts").get_caller_identity()["Account"],
                    "api_call": f"{service}:{method}",
                },
            )

        except NoCredentialsError:
            logger.error("No AWS credentials found for region %s", region)
            return EvidenceArtifact(
                control_id=control_id, check_id=check_id, provider="aws",
                service=service, method=method, region=region,
                collected_at=timestamp, data=None, status="error",
                error_message="No AWS credentials configured",
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error("AWS API error %s for %s:%s in %s", error_code, service, method, region)
            return EvidenceArtifact(
                control_id=control_id, check_id=check_id, provider="aws",
                service=service, method=method, region=region,
                collected_at=timestamp, data=None, status="error",
                error_message=f"ClientError: {error_code} - {e.response['Error']['Message']}",
            )

    def _paginated_call(self, client, method: str) -> list | dict:
        """
        Attempt to paginate an API call. Falls back to a direct
        call if the method doesn't support pagination.
        """
        try:
            paginator = client.get_paginator(method)
            results = []
            for page in paginator.paginate():
                # Strip ResponseMetadata from each page
                page.pop("ResponseMetadata", None)
                results.append(page)
            return results if len(results) > 1 else results[0]
        except Exception:
            # Not a paginated operation, call directly
            func = getattr(client, method)
            response = func()
            response.pop("ResponseMetadata", None)
            return response


class EvidenceStore:
    """
    Persists evidence artifacts to the local filesystem as JSON files.

    Each collection run creates a dated directory, and each artifact
    gets its own file with a descriptive name built from the control
    and check identifiers.
    """

    def __init__(self, base_path: str, timestamp_format: str = "%Y-%m-%dT%H:%M:%SZ"):
        self.base_path = Path(base_path)
        self.timestamp_format = timestamp_format

    def save(self, artifacts: list[EvidenceArtifact], run_id: str = "") -> Path:
        """Save a batch of artifacts from a collection run."""
        if not run_id:
            run_id = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

        run_dir = self.base_path / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        manifest_artifacts: list[dict[str, str]] = []
        manifest = {
            "run_id": run_id,
            "collected_at": datetime.now(UTC).strftime(self.timestamp_format),
            "artifact_count": len(artifacts),
            "artifacts": manifest_artifacts,
        }

        for artifact in artifacts:
            filename = f"{artifact.check_id}_{artifact.provider}_{artifact.region}.json"
            filepath = run_dir / filename

            with open(filepath, "w") as f:
                json.dump(artifact.to_dict(), f, indent=2, default=str)

            manifest_artifacts.append({
                "file": filename,
                "control_id": artifact.control_id,
                "check_id": artifact.check_id,
                "status": artifact.status,
            })

        manifest_path = run_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        logger.info("Saved %d artifacts to %s", len(artifacts), run_dir)
        return run_dir

    def load_run(self, run_id: str) -> list[EvidenceArtifact]:
        """Load all artifacts from a previous collection run."""
        run_dir = self.base_path / run_id
        manifest_path = run_dir / "manifest.json"

        with open(manifest_path) as f:
            manifest = json.load(f)

        artifacts = []
        for entry in manifest["artifacts"]:
            filepath = run_dir / entry["file"]
            with open(filepath) as f:
                data = json.load(f)
                artifacts.append(EvidenceArtifact(**data))

        return artifacts

    def list_runs(self) -> list[dict]:
        """List all collection runs with summary info."""
        runs = []
        for run_dir in sorted(self.base_path.iterdir()):
            manifest_path = run_dir / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path) as f:
                    manifest = json.load(f)
                    runs.append({
                        "run_id": manifest["run_id"],
                        "collected_at": manifest["collected_at"],
                        "artifact_count": manifest["artifact_count"],
                    })
        return runs


def load_framework_checks(framework_path: str, framework: str = "nist_800_53",
                          control_family: str = "") -> list[dict]:
    """
    Parse the framework YAML and return a flat list of checks to execute.

    Optionally filters to a single control family (e.g., "AC", "AU").
    Each check in the returned list has everything needed for the
    collector to know what API call to make and where the result fits.
    """
    with open(framework_path) as f:
        frameworks = yaml.safe_load(f)

    fw = frameworks.get(framework, {})
    families = fw.get("control_families", {})

    if control_family:
        families = {k: v for k, v in families.items() if k == control_family}

    checks = []
    for family_id, family in families.items():
        for control_id, control in family.get("controls", {}).items():
            for check in control.get("checks", []):
                for provider, provider_checks in check.get("cloud_checks", {}).items():
                    for cloud_check in provider_checks:
                        checks.append({
                            "control_id": control_id,
                            "check_id": check["id"],
                            "control_title": control["title"],
                            "check_description": check["description"],
                            "provider": provider,
                            "service": cloud_check["service"],
                            "method": cloud_check["method"],
                            "assertion": cloud_check["assertion"],
                        })
    return checks
