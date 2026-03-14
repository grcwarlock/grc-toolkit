#!/usr/bin/env python3
"""
run_collection.py
Entry point for automated evidence collection.

Usage:
    python scripts/run_collection.py --framework nist-800-53 --control-family AC
    python scripts/run_collection.py --framework nist-800-53  # all families
"""

import logging
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.evidence_collector import (
    AWSCollector,
    EvidenceStore,
    load_framework_checks,
)

console = Console()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


@click.command()
@click.option("--framework", default="nist_800_53", help="Framework identifier")
@click.option("--control-family", default="", help="Specific control family (e.g., AC, AU)")
@click.option("--config", default="config/settings.yaml", help="Path to settings file")
@click.option("--dry-run", is_flag=True, help="Show what would be collected without running")
def main(framework: str, control_family: str, config: str, dry_run: bool):
    """Collect evidence from cloud environments for GRC assessment."""

    console.print("\n[bold blue]GRC Toolkit - Evidence Collection[/bold blue]\n")

    # Load configuration
    config_path = Path(config)
    if not config_path.exists():
        console.print(f"[red]Config file not found: {config}[/red]")
        console.print("Copy config/settings.yaml and fill in your environment details.")
        sys.exit(1)

    with open(config_path) as f:
        settings = yaml.safe_load(f)

    # Load framework checks
    framework_path = Path("config/frameworks.yaml")
    checks = load_framework_checks(str(framework_path), framework, control_family)

    if not checks:
        console.print(f"[yellow]No checks found for framework '{framework}'", end="")
        if control_family:
            console.print(f" family '{control_family}'", end="")
        console.print("[/yellow]")
        sys.exit(1)

    # Display what we're about to collect
    table = Table(title="Evidence Collection Plan")
    table.add_column("Control", style="cyan")
    table.add_column("Check", style="green")
    table.add_column("Provider")
    table.add_column("Service")
    table.add_column("API Call")

    for check in checks:
        table.add_row(
            check["control_id"],
            check["check_id"],
            check["provider"],
            check["service"],
            check["method"],
        )

    console.print(table)
    console.print(f"\n[bold]Total checks to execute: {len(checks)}[/bold]\n")

    if dry_run:
        console.print("[yellow]Dry run mode - no evidence collected.[/yellow]")
        return

    # Initialize collectors for enabled providers
    collectors = {}
    aws_config = settings.get("cloud_providers", {}).get("aws", {})
    if aws_config.get("enabled"):
        collectors["aws"] = AWSCollector(
            regions=aws_config.get("regions", ["us-east-1"]),
            assume_role_arn=aws_config.get("assume_role_arn", ""),
        )

    # Initialize evidence store
    evidence_config = settings.get("evidence", {})
    store = EvidenceStore(evidence_config.get("local_path", "./evidence"))

    # Run collection
    all_artifacts = []
    aws_checks = [c for c in checks if c["provider"] == "aws"]

    if "aws" in collectors and aws_checks:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Collecting AWS evidence...", total=len(aws_checks))

            for check in aws_checks:
                progress.update(
                    task,
                    description=f"Collecting {check['service']}:{check['method']}...",
                )
                artifacts = collectors["aws"].collect(
                    service=check["service"],
                    method=check["method"],
                    control_id=check["control_id"],
                    check_id=check["check_id"],
                )
                all_artifacts.extend(artifacts)
                progress.advance(task)

    # Save collected evidence
    if all_artifacts:
        run_dir = store.save(all_artifacts)
        console.print(f"\n[green]Evidence saved to: {run_dir}[/green]")

        # Summary
        collected = sum(1 for a in all_artifacts if a.status == "collected")
        errors = sum(1 for a in all_artifacts if a.status == "error")
        console.print(f"  Collected: {collected}")
        console.print(f"  Errors:    {errors}")

        if errors:
            console.print("\n[yellow]Errors encountered:[/yellow]")
            for a in all_artifacts:
                if a.status == "error":
                    console.print(f"  {a.check_id} ({a.region}): {a.error_message}")
    else:
        console.print("[yellow]No evidence collected. Check provider configuration.[/yellow]")


if __name__ == "__main__":
    main()
