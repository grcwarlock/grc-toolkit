"""Cloud evidence collectors — AWS, Azure, GCP."""

from modules.collectors.aws_collector import AWSCollectorV2
from modules.collectors.azure_collector import AzureCollector
from modules.collectors.gcp_collector import GCPCollector


def get_collector(provider: str, **kwargs):
    """Factory function to get the right collector for a provider."""
    collectors = {
        "aws": AWSCollectorV2,
        "azure": AzureCollector,
        "gcp": GCPCollector,
    }
    if provider not in collectors:
        raise ValueError(f"Unknown provider: {provider}. Supported: {list(collectors)}")
    return collectors[provider](**kwargs)
