#!/usr/bin/env python3
"""
run_risk_analysis.py
Entry point for quantitative risk analysis.

Usage:
    python scripts/run_risk_analysis.py
    python scripts/run_risk_analysis.py --iterations 50000
    python scripts/run_risk_analysis.py --compare-treatments
"""

import sys
import json
import logging
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.risk_engine import RiskEngine, EXAMPLE_SCENARIOS

console = Console()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def format_currency(value: float) -> str:
    """Format a number as USD currency."""
    if value >= 1_000_000:
        return f"${value / 1_000_000:,.1f}M"
    if value >= 1_000:
        return f"${value / 1_000:,.0f}K"
    return f"${value:,.0f}"


@click.command()
@click.option("--iterations", default=10000, help="Monte Carlo iterations")
@click.option("--seed", default=None, type=int, help="Random seed for reproducibility")
@click.option("--compare-treatments", is_flag=True, help="Run treatment comparison analysis")
@click.option("--output", default="reports", help="Output directory")
def main(iterations: int, seed: int, compare_treatments: bool, output: str):
    """Run quantitative risk analysis using Monte Carlo simulation."""

    console.print("\n[bold blue]GRC Toolkit - Quantitative Risk Analysis[/bold blue]")
    console.print(f"Running {iterations:,} Monte Carlo iterations\n")

    engine = RiskEngine(iterations=iterations, seed=seed)

    # Run portfolio simulation
    results = engine.simulate_portfolio(EXAMPLE_SCENARIOS)

    # Individual scenario results
    table = Table(title="Risk Scenario Analysis")
    table.add_column("Scenario", style="cyan", max_width=30)
    table.add_column("Mean ALE", justify="right")
    table.add_column("Median ALE", justify="right")
    table.add_column("VaR 90%", justify="right")
    table.add_column("VaR 95%", justify="right")
    table.add_column("VaR 99%", justify="right")
    table.add_column("Worst Case", justify="right", style="red")

    for scenario in results["scenario_ranking"]:
        table.add_row(
            scenario["scenario"],
            format_currency(scenario["mean_annual_loss"]),
            format_currency(scenario["median_annual_loss"]),
            format_currency(scenario["value_at_risk_90"]),
            format_currency(scenario["value_at_risk_95"]),
            format_currency(scenario["value_at_risk_99"]),
            format_currency(scenario["worst_case_observed"]),
        )

    console.print(table)

    # Aggregate portfolio risk
    agg = results["aggregate"]
    console.print(Panel(
        f"[bold]Mean Annual Loss:[/bold]  {format_currency(agg['mean_annual_loss'])}\n"
        f"[bold]VaR 95%:[/bold]           {format_currency(agg['value_at_risk_95'])}\n"
        f"[bold]VaR 99%:[/bold]           {format_currency(agg['value_at_risk_99'])}\n"
        f"[bold]Worst Case:[/bold]        {format_currency(agg['worst_case_observed'])}",
        title="[bold green]Aggregate Portfolio Risk[/bold green]",
        border_style="green",
    ))

    # Treatment comparison
    if compare_treatments:
        console.print("\n[bold blue]Treatment Comparison - Data Breach Scenario[/bold blue]\n")

        treatments = [
            {"name": "Enhanced MFA + SIEM", "effectiveness": 0.35, "annual_cost": 75_000},
            {"name": "Zero Trust Architecture", "effectiveness": 0.55, "annual_cost": 250_000},
            {"name": "Full MDR Service", "effectiveness": 0.70, "annual_cost": 500_000},
            {"name": "Basic Controls Only", "effectiveness": 0.15, "annual_cost": 25_000},
        ]

        comparison = engine.compare_treatments(EXAMPLE_SCENARIOS[0], treatments)

        treat_table = Table(title="Treatment Cost-Benefit Analysis")
        treat_table.add_column("Treatment", style="cyan")
        treat_table.add_column("Annual Cost", justify="right")
        treat_table.add_column("Effectiveness", justify="center")
        treat_table.add_column("Residual Loss", justify="right")
        treat_table.add_column("Total Cost of Risk", justify="right")
        treat_table.add_column("Net Benefit", justify="right")

        for t in comparison:
            benefit_style = "green" if t["net_benefit_vs_baseline"] > 0 else "red"
            treat_table.add_row(
                t["treatment"],
                format_currency(t["annual_cost"]),
                t.get("effectiveness", "N/A"),
                format_currency(t["mean_annual_loss"]),
                format_currency(t["total_cost_of_risk"]),
                f"[{benefit_style}]{format_currency(t['net_benefit_vs_baseline'])}[/{benefit_style}]",
            )

        console.print(treat_table)
        console.print(
            "\n[dim]Net benefit = baseline mean ALE - (treatment cost + residual mean ALE)[/dim]"
        )

    # Save results
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "risk_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    console.print(f"\n[green]Full results saved to: {output_file}[/green]")


if __name__ == "__main__":
    main()
