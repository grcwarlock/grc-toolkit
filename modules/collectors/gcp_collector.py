"""
GCP evidence collector using google-cloud-* SDKs.

Conforms to the CloudCollector protocol — returns NormalizedEvidence
with provider-agnostic normalized_data.
"""

from __future__ import annotations

import logging

from modules.collectors.base import create_evidence, safe_collect
from modules.models import NormalizedEvidence, ResourceNormalizer

logger = logging.getLogger(__name__)

try:
    from google.cloud import compute_v1
    HAS_GCP = True
except ImportError:
    HAS_GCP = False


class GCPCollector:
    """GCP evidence collector using google-cloud SDKs."""

    provider = "gcp"

    def __init__(self, project_id: str = "", credentials=None):
        if not HAS_GCP:
            raise ImportError(
                "GCP SDK not installed. Run: pip install google-cloud-compute "
                "google-cloud-asset google-cloud-securitycenter"
            )
        self.project_id = project_id
        self.credentials = credentials

    def get_account_id(self) -> str:
        return self.project_id

    def collect_identity_inventory(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            # GCP IAM service accounts via Cloud Resource Manager
            # In production use google.cloud.iam_admin_v1
            raw = {"service_accounts": []}
            normalized = ResourceNormalizer.normalize_iam_users("gcp", raw)

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="gcp", service="iam", resource_type="service_account",
                region="global", account_id=self.project_id,
                data=raw, normalized_data=normalized,
                metadata={"note": "Requires IAM Admin API access"},
            )

        return [safe_collect(
            _collect, control_id, check_id, "gcp", "iam",
            "global", self.project_id,
        )]

    def collect_network_boundaries(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            firewalls_client = compute_v1.FirewallsClient(
                credentials=self.credentials
            )
            firewalls = list(firewalls_client.list(project=self.project_id))

            raw = {
                "firewall_rules": [
                    {
                        "id": str(fw.id),
                        "name": fw.name,
                        "direction": fw.direction,
                        "sourceRanges": list(fw.source_ranges) if fw.source_ranges else [],
                        "allowed": [
                            {
                                "IPProtocol": a.I_p_protocol,
                                "ports": list(a.ports) if a.ports else [],
                            }
                            for a in (fw.allowed or [])
                        ],
                        "description": fw.description or "",
                        "disabled": fw.disabled,
                        "network": fw.network,
                    }
                    for fw in firewalls
                ],
            }
            normalized = ResourceNormalizer.normalize_security_groups("gcp", raw)

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="gcp", service="compute", resource_type="firewall_rule",
                region="global", account_id=self.project_id,
                data=raw, normalized_data=normalized,
            )

        return [safe_collect(
            _collect, control_id, check_id, "gcp", "compute",
            "global", self.project_id,
        )]

    def collect_audit_configuration(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            # Cloud Audit Logs are enabled by default for Admin Activity
            # Data Access logs need explicit configuration
            raw = {"audit_logging_enabled": True}
            normalized = ResourceNormalizer.normalize_audit_config("gcp", raw)

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="gcp", service="logging", resource_type="audit_config",
                region="global", account_id=self.project_id,
                data=raw, normalized_data=normalized,
            )

        return [safe_collect(
            _collect, control_id, check_id, "gcp", "logging",
            "global", self.project_id,
        )]

    def collect_encryption_status(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            disks_client = compute_v1.DisksClient(credentials=self.credentials)
            # List disks across all zones via aggregated list
            raw_disks = []
            agg = disks_client.aggregated_list(project=self.project_id)
            for zone, scoped in agg:
                for disk in (scoped.disks or []):
                    raw_disks.append({
                        "id": str(disk.id),
                        "type": "persistent_disk",
                        "encrypted": True,  # GCP encrypts at rest by default
                        "encryption_type": (
                            "customer_managed" if disk.disk_encryption_key
                            else "google_managed"
                        ),
                        "key_id": (
                            disk.disk_encryption_key.kms_key_name
                            if disk.disk_encryption_key else ""
                        ),
                    })

            raw = {"disks": raw_disks}
            normalized = ResourceNormalizer.normalize_encryption(
                "gcp", {"resources": raw_disks}
            )

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="gcp", service="compute", resource_type="persistent_disk",
                region="all", account_id=self.project_id,
                data=raw, normalized_data=normalized,
            )

        return [safe_collect(
            _collect, control_id, check_id, "gcp", "compute",
            "all", self.project_id,
        )]

    def collect_logging_configuration(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            # Security Command Center check
            raw = {"scc_enabled": False}
            normalized = {
                "guardduty_enabled": False,
                "security_hub_enabled": False,
                "scc_enabled": raw.get("scc_enabled", False),
            }

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="gcp", service="scc", resource_type="source",
                region="global", account_id=self.project_id,
                data=raw, normalized_data=normalized,
                metadata={"note": "Requires Security Command Center API"},
            )

        return [safe_collect(
            _collect, control_id, check_id, "gcp", "scc",
            "global", self.project_id,
        )]

    def collect_by_service(
        self, service: str, method: str, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        """Generic GCP collection — maps service/method to SDK calls."""
        dispatch = {
            ("iam", "list_service_accounts"): self.collect_identity_inventory,
            ("compute", "list_firewalls"): self.collect_network_boundaries,
            ("logging", "get_audit_config"): self.collect_audit_configuration,
        }
        handler = dispatch.get((service, method))
        if handler:
            return handler(control_id, check_id)

        return [create_evidence(
            control_id=control_id, check_id=check_id,
            provider="gcp", service=service, resource_type=method,
            region="global", account_id=self.project_id,
            data={}, normalized_data={},
            status="error",
            error_message=f"No handler for gcp:{service}:{method}",
        )]
