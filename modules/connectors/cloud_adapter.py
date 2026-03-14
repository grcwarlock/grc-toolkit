"""
Cloud provider adapter — wraps existing AWS/Azure/GCP collectors
into the unified connector interface.
"""

from __future__ import annotations

import logging

from modules.collectors import get_collector
from modules.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorResult,
    IngestEvent,
    IngestStatus,
)

logger = logging.getLogger(__name__)


class CloudProviderConnector(BaseConnector):
    """Adapter that wraps existing CloudCollector implementations.

    Bridges the legacy collectors (AWSCollectorV2, AzureCollector,
    GCPCollector) into the new connector framework without rewriting them.
    """

    def validate_config(self) -> list[str]:
        errors = []
        provider = self.config.provider
        if provider not in ("aws", "azure", "gcp"):
            errors.append(f"Unsupported cloud provider: {provider}")
        return errors

    def health_check(self) -> bool:
        try:
            provider = self.config.provider
            regions = self.config.settings.get("regions", ["us-east-1"])
            collector = get_collector(provider, regions=regions)
            collector.get_account_id()
            return True
        except Exception as e:
            self.logger.error("Health check failed: %s", e)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.config.name,
            status=IngestStatus.SUCCESS,
        )

        provider = self.config.provider
        regions = self.config.settings.get("regions", ["us-east-1"])
        service = self.config.settings.get("service", "iam")
        method = self.config.settings.get("method", "list_users")
        control_id = self.config.settings.get("control_id", "")
        check_id = self.config.settings.get("check_id", "")

        try:
            collector = get_collector(provider, regions=regions)
            artifacts = collector.collect_by_service(
                service=service,
                method=method,
                control_id=control_id,
                check_id=check_id,
            )

            for artifact in artifacts:
                event = IngestEvent(
                    source=self.config.name,
                    source_type="cloud",
                    provider=provider,
                    event_type=artifact.resource_type or service,
                    severity="info",
                    timestamp=artifact.collected_at,
                    resource_type=artifact.resource_type,
                    region=artifact.region,
                    account_id=artifact.account_id,
                    data=artifact.normalized_data,
                    raw_data=artifact.data,
                    control_ids=[artifact.control_id] if artifact.control_id else [],
                    sha256_hash=artifact.sha256_hash,
                )
                result.events.append(event)

        except Exception as e:
            result.errors.append(str(e))
            self.logger.error("Cloud collection failed: %s", e)

        result.complete()
        return result
