"""
Azure evidence collector using azure-mgmt-* SDKs.

Conforms to the CloudCollector protocol — returns NormalizedEvidence
with provider-agnostic normalized_data for framework-neutral assessment.
"""

from __future__ import annotations

import logging

from modules.models import NormalizedEvidence, ResourceNormalizer
from modules.collectors.base import create_evidence, safe_collect

logger = logging.getLogger(__name__)

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False


class AzureCollector:
    """Azure evidence collector using azure-mgmt SDKs."""

    provider = "azure"

    def __init__(
        self,
        subscription_id: str = "",
        tenant_id: str = "",
        credential=None,
    ):
        if not HAS_AZURE:
            raise ImportError(
                "Azure SDK not installed. Run: pip install azure-identity "
                "azure-mgmt-network azure-mgmt-compute azure-mgmt-monitor"
            )
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.credential = credential or DefaultAzureCredential()

    def get_account_id(self) -> str:
        return self.subscription_id

    def collect_identity_inventory(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            # Microsoft Graph API for Entra ID users
            # In production, use msgraph-sdk-python
            raw = {"users": [], "service_principals": []}
            normalized = ResourceNormalizer.normalize_iam_users("azure", raw)

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="azure", service="entra_id", resource_type="user",
                region="global", account_id=self.subscription_id,
                data=raw, normalized_data=normalized,
                metadata={"note": "Requires Microsoft Graph API access"},
            )

        return [safe_collect(
            _collect, control_id, check_id, "azure", "entra_id",
            "global", self.subscription_id,
        )]

    def collect_network_boundaries(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            network_client = NetworkManagementClient(
                self.credential, self.subscription_id
            )
            nsgs = list(network_client.network_security_groups.list_all())
            raw = {
                "network_security_groups": [
                    {
                        "id": nsg.id,
                        "name": nsg.name,
                        "location": nsg.location,
                        "security_rules": [
                            {
                                "name": rule.name,
                                "direction": rule.direction,
                                "protocol": rule.protocol,
                                "source_address_prefix": rule.source_address_prefix,
                                "destination_port_range": rule.destination_port_range,
                                "access": rule.access,
                                "priority": rule.priority,
                                "description": rule.description or "",
                            }
                            for rule in (nsg.security_rules or [])
                        ],
                    }
                    for nsg in nsgs
                ],
            }
            normalized = ResourceNormalizer.normalize_security_groups("azure", raw)

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="azure", service="network", resource_type="nsg",
                region="all", account_id=self.subscription_id,
                data=raw, normalized_data=normalized,
            )

        return [safe_collect(
            _collect, control_id, check_id, "azure", "network",
            "all", self.subscription_id,
        )]

    def collect_audit_configuration(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            monitor_client = MonitorManagementClient(
                self.credential, self.subscription_id
            )
            # Check diagnostic settings at subscription level
            try:
                settings = list(
                    monitor_client.diagnostic_settings.list(
                        resource_uri=f"/subscriptions/{self.subscription_id}"
                    )
                )
                activity_log_enabled = len(settings) > 0
            except Exception:
                settings = []
                activity_log_enabled = False

            raw = {
                "diagnostic_settings": [
                    {"name": s.name, "id": s.id} for s in settings
                ],
                "activity_log_enabled": activity_log_enabled,
            }
            normalized = ResourceNormalizer.normalize_audit_config("azure", raw)

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="azure", service="monitor", resource_type="diagnostic_setting",
                region="global", account_id=self.subscription_id,
                data=raw, normalized_data=normalized,
            )

        return [safe_collect(
            _collect, control_id, check_id, "azure", "monitor",
            "global", self.subscription_id,
        )]

    def collect_encryption_status(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            compute_client = ComputeManagementClient(
                self.credential, self.subscription_id
            )
            disks = list(compute_client.disks.list())
            resources = [
                {
                    "id": d.id,
                    "type": "managed_disk",
                    "encrypted": d.encryption is not None,
                    "encryption_type": (
                        d.encryption.type if d.encryption else "none"
                    ),
                    "key_id": "",
                }
                for d in disks
            ]

            raw = {"disks": [{"id": d.id, "name": d.name} for d in disks]}
            normalized = ResourceNormalizer.normalize_encryption(
                "azure", {"resources": resources}
            )

            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="azure", service="compute", resource_type="managed_disk",
                region="all", account_id=self.subscription_id,
                data=raw, normalized_data=normalized,
            )

        return [safe_collect(
            _collect, control_id, check_id, "azure", "compute",
            "all", self.subscription_id,
        )]

    def collect_logging_configuration(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        def _collect():
            # Check Microsoft Defender for Cloud status
            raw = {"defender_enabled": False}
            normalized = {
                "guardduty_enabled": False,  # Azure equivalent: Defender
                "security_hub_enabled": False,
                "defender_enabled": raw.get("defender_enabled", False),
            }
            return create_evidence(
                control_id=control_id, check_id=check_id,
                provider="azure", service="defender", resource_type="defender_plan",
                region="global", account_id=self.subscription_id,
                data=raw, normalized_data=normalized,
                metadata={"note": "Requires azure-mgmt-security SDK"},
            )

        return [safe_collect(
            _collect, control_id, check_id, "azure", "defender",
            "global", self.subscription_id,
        )]

    def collect_by_service(
        self, service: str, method: str, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]:
        """Generic Azure collection — maps service/method to SDK calls."""
        dispatch = {
            ("entra_id", "list_users"): self.collect_identity_inventory,
            ("network", "list_network_security_groups"): self.collect_network_boundaries,
            ("monitor", "list_diagnostic_settings"): self.collect_audit_configuration,
        }
        handler = dispatch.get((service, method))
        if handler:
            return handler(control_id, check_id)

        return [create_evidence(
            control_id=control_id, check_id=check_id,
            provider="azure", service=service, resource_type=method,
            region="global", account_id=self.subscription_id,
            data={}, normalized_data={},
            status="error",
            error_message=f"No handler for azure:{service}:{method}",
        )]
