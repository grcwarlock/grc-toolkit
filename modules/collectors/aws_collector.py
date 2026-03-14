"""
Refactored AWS collector using the normalized evidence model.

Conforms to the CloudCollector protocol — returns NormalizedEvidence
with both raw API data and provider-agnostic normalized_data.
"""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import ClientError

from modules.collectors.base import create_evidence, safe_collect
from modules.models import NormalizedEvidence, ResourceNormalizer

logger = logging.getLogger(__name__)


class AWSCollectorV2:
    """AWS evidence collector using boto3 with normalized output."""

    provider = "aws"

    def __init__(self, regions: list[str] | None = None, assume_role_arn: str = ""):
        self.regions = regions or ["us-east-1"]
        self.assume_role_arn = assume_role_arn
        self._sessions: dict[str, boto3.Session] = {}
        self._account_id: str = ""

    def _get_session(self, region: str) -> boto3.Session:
        if region in self._sessions:
            return self._sessions[region]

        if self.assume_role_arn:
            sts = boto3.client("sts", region_name=region)
            creds = sts.assume_role(
                RoleArn=self.assume_role_arn,
                RoleSessionName="grc-toolkit-audit",
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

    def _paginated_call(self, client, method: str) -> dict | list:
        try:
            paginator = client.get_paginator(method)
            results = []
            for page in paginator.paginate():
                page.pop("ResponseMetadata", None)
                results.append(page)
            return results if len(results) > 1 else results[0]
        except Exception:
            func = getattr(client, method)
            response = func()
            response.pop("ResponseMetadata", None)
            return response

    def get_account_id(self) -> str:
        if self._account_id:
            return self._account_id
        session = self._get_session(self.regions[0])
        self._account_id = session.client("sts").get_caller_identity()["Account"]
        return self._account_id

    def collect_identity_inventory(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        region = self.regions[0]  # IAM is global

        def _collect():
            session = self._get_session(region)
            iam = session.client("iam")

            users_data = self._paginated_call(iam, "list_users")
            summary_data = iam.get_account_summary()
            summary_data.pop("ResponseMetadata", None)

            raw = {**users_data, **summary_data} if isinstance(users_data, dict) else {**summary_data}
            if isinstance(users_data, dict):
                raw.update(users_data)
            else:
                raw["Users"] = []
                for page in users_data:
                    raw["Users"].extend(page.get("Users", []))

            normalized = ResourceNormalizer.normalize_iam_users("aws", raw)

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="aws", service="iam", resource_type="iam_user",
                region=region, account_id=self.get_account_id(),
                data=raw, normalized_data=normalized,
            )

        return [safe_collect(_collect, control_id, check_id, "aws", "iam", region, self.get_account_id())]

    def collect_network_boundaries(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        artifacts = []
        for region in self.regions:
            def _collect(r=region):
                session = self._get_session(r)
                ec2 = session.client("ec2")
                sgs = self._paginated_call(ec2, "describe_security_groups")
                nacls = self._paginated_call(ec2, "describe_network_acls")

                raw = {}
                if isinstance(sgs, dict):
                    raw.update(sgs)
                if isinstance(nacls, dict):
                    raw.update(nacls)

                normalized = ResourceNormalizer.normalize_security_groups("aws", raw)

                return create_evidence(
                    control_id=control_id, check_id=check_id,
                    provider="aws", service="ec2", resource_type="security_group",
                    region=r, account_id=self.get_account_id(),
                    data=raw, normalized_data=normalized,
                )

            artifacts.append(
                safe_collect(_collect, control_id, check_id, "aws", "ec2", region, self.get_account_id())
            )
        return artifacts

    def collect_audit_configuration(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        region = self.regions[0]

        def _collect():
            session = self._get_session(region)
            ct = session.client("cloudtrail")
            trails = ct.describe_trails()
            trails.pop("ResponseMetadata", None)

            # Get status for each trail
            for trail in trails.get("trailList", []):
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    status.pop("ResponseMetadata", None)
                    trail.update(status)
                except ClientError:
                    trail["IsLogging"] = False

            normalized = ResourceNormalizer.normalize_audit_config("aws", trails)

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="aws", service="cloudtrail", resource_type="trail",
                region=region, account_id=self.get_account_id(),
                data=trails, normalized_data=normalized,
            )

        return [safe_collect(_collect, control_id, check_id, "aws", "cloudtrail", region, self.get_account_id())]

    def collect_encryption_status(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        artifacts = []
        for region in self.regions:
            def _collect(r=region):
                session = self._get_session(r)
                ec2 = session.client("ec2")
                volumes = self._paginated_call(ec2, "describe_volumes")

                resources = []
                for vol in volumes.get("Volumes", []) if isinstance(volumes, dict) else []:
                    resources.append({
                        "id": vol.get("VolumeId", ""),
                        "type": "ebs_volume",
                        "encrypted": vol.get("Encrypted", False),
                        "encryption_type": "aws_managed" if vol.get("Encrypted") else "none",
                        "key_id": vol.get("KmsKeyId", ""),
                    })

                raw = volumes if isinstance(volumes, dict) else {}
                normalized = ResourceNormalizer.normalize_encryption("aws", {"resources": resources})

                return create_evidence(
                    control_id=control_id, check_id=check_id,
                    provider="aws", service="ec2", resource_type="ebs_volume",
                    region=r, account_id=self.get_account_id(),
                    data=raw, normalized_data=normalized,
                )

            artifacts.append(
                safe_collect(_collect, control_id, check_id, "aws", "ec2", region, self.get_account_id())
            )
        return artifacts

    def collect_logging_configuration(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        artifacts = []
        for region in self.regions:
            def _collect(r=region):
                session = self._get_session(r)
                gd = session.client("guardduty")
                detectors = gd.list_detectors()
                detectors.pop("ResponseMetadata", None)

                try:
                    sh = session.client("securityhub")
                    hub = sh.describe_hub()
                    hub.pop("ResponseMetadata", None)
                except ClientError:
                    hub = {}

                raw = {"guardduty": detectors, "securityhub": hub}
                normalized = {
                    "guardduty_enabled": len(detectors.get("DetectorIds", [])) > 0,
                    "security_hub_enabled": bool(hub.get("HubArn")),
                    "detector_count": len(detectors.get("DetectorIds", [])),
                }

                return create_evidence(
                    control_id=control_id, check_id=check_id,
                    provider="aws", service="guardduty", resource_type="detector",
                    region=r, account_id=self.get_account_id(),
                    data=raw, normalized_data=normalized,
                )

            artifacts.append(
                safe_collect(_collect, control_id, check_id, "aws", "guardduty", region, self.get_account_id())
            )
        return artifacts

    def collect_by_service(
        self, service: str, method: str, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        """Generic collection — backward compatible with v1 framework YAML."""
        global_services = {"iam", "s3", "cloudfront", "route53", "organizations"}
        regions = [self.regions[0]] if service in global_services else self.regions
        artifacts = []

        for region in regions:
            def _collect(r=region):
                session = self._get_session(r)
                client = session.client(service)
                data = self._paginated_call(client, method)
                raw = data if isinstance(data, dict) else {"pages": data}

                return create_evidence(
                    control_id=control_id, check_id=check_id,
                    provider="aws", service=service, resource_type=method,
                    region=r, account_id=self.get_account_id(),
                    data=raw, normalized_data=raw,
                )

            artifacts.append(
                safe_collect(_collect, control_id, check_id, "aws", service, region, self.get_account_id())
            )
        return artifacts
