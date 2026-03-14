#!/usr/bin/env python3
"""
run_assessment.py
Entry point for running control assessments against collected evidence.

Usage:
    python scripts/run_assessment.py --evidence-dir evidence/ --output reports/
    python scripts/run_assessment.py --run-id 20250301_143022 --output reports/
"""

import logging
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.control_assessor import ControlAssessor
from modules.evidence_collector import EvidenceStore, load_framework_checks
from modules.report_generator import ReportGenerator

console = Console()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


@click.command()
@click.option("--evidence-dir", default="evidence", help="Base evidence directory")
@click.option("--run-id", default="", help="Specific collection run ID (uses latest if empty)")
@click.option("--output", default="reports", help="Output directory for reports")
@click.option("--framework", default="nist_800_53", help="Framework identifier")
@click.option("--config", default="config/settings.yaml", help="Path to settings file")
def main(evidence_dir: str, run_id: str, output: str, framework: str, config: str):
    """Assess collected evidence against framework controls."""

    console.print("\n[bold blue]GRC Toolkit - Control Assessment[/bold blue]\n")

    # Load settings
    with open(config) as f:
        settings = yaml.safe_load(f)

    # Load evidence
    store = EvidenceStore(evidence_dir)
    runs = store.list_runs()

    if not runs:
        console.print("[red]No evidence collection runs found.[/red]")
        console.print("Run evidence collection first: python scripts/run_collection.py")
        sys.exit(1)

    if not run_id:
        run_id = runs[-1]["run_id"]
        console.print(f"Using latest collection run: [cyan]{run_id}[/cyan]")

    artifacts = store.load_run(run_id)
    console.print(f"Loaded {len(artifacts)} evidence artifacts\n")

    # Load framework checks for context
    checks = load_framework_checks("config/frameworks.yaml", framework)

    # Run assessment
    assessor = ControlAssessor()
    results = assessor.assess(artifacts, checks)

    # Display results table
    table = Table(title="Assessment Results")
    table.add_column("Control", style="cyan")
    table.add_column("Check", style="dim")
    table.add_column("Assertion")
    table.add_column("Status", justify="center")
    table.add_column("Provider")
    table.add_column("Key Finding")

    status_colors = {
        "pass": "[green]PASS[/green]",
        "fail": "[red]FAIL[/red]",
        "error": "[yellow]ERROR[/yellow]",
        "not_assessed": "[dim]N/A[/dim]",
    }

    for result in results:
        finding = result.findings[0][:50] + "..." if result.findings else ""
        table.add_row(
            result.control_id,
            result.check_id,
            result.assertion,
            status_colors.get(result.status, result.status),
            f"{result.provider}/{result.region}",
            finding,
        )

    console.print(table)

    # Summary
    summary = assessor.summarize(results)
    console.print("\n[bold]Assessment Summary[/bold]")
    console.print(f"  Total Checks:  {summary['total_checks']}")
    console.print(f"  [green]Passed:      {summary['passed']}[/green]")
    console.print(f"  [red]Failed:      {summary['failed']}[/red]")
    console.print(f"  [yellow]Errors:      {summary['errors']}[/yellow]")
    console.print(f"  Pass Rate:     {summary.get('pass_rate', 'N/A')}")

    # Generate reports
    org = settings.get("environment", {}).get("organization", "")
    generator = ReportGenerator(organization=org, system_name="Primary System")
    results_dicts = [r.to_dict() for r in results]

    # POA&M for failures
    poam_path = generator.generate_poam(
        results_dicts,
        f"{output}/poam_{run_id}.txt",
        assessment_id=run_id,
    )

    # Executive summary
    exec_path = generator.generate_executive_summary(
        summary, results_dicts,
        f"{output}/executive_summary_{run_id}.txt",
        framework="NIST SP 800-53 Rev 5",
    )

    # JSON export
    json_path = generator.export_json(
        results_dicts, summary,
        f"{output}/assessment_{run_id}.json",
    )

    console.print("\n[bold green]Reports generated:[/bold green]")
    console.print(f"  POA&M:             {poam_path}")
    console.print(f"  Executive Summary: {exec_path}")
    console.print(f"  JSON Export:       {json_path}")


if __name__ == "__main__":
    main()
