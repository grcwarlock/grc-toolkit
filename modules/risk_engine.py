"""
risk_engine.py
Quantitative risk analysis using Monte Carlo simulation.

Replaces the typical red/yellow/green heat map with actual probability
distributions and dollar figures that executives can use to make
informed decisions about risk treatment.
"""

import logging
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class ThreatScenario:
    """
    A single risk scenario with probability and impact distributions.

    Instead of a single number for likelihood and impact, each scenario
    uses statistical distributions that capture the uncertainty inherent
    in risk estimation. An analyst might say "this happens between 1 and
    5 times per year, most likely around 2" which maps to a PERT
    distribution with min=1, mode=2, max=5.
    """
    name: str
    description: str
    category: str  # e.g., "data_breach", "insider_threat", "service_disruption"

    # Frequency: how many times per year this event occurs
    frequency_min: float        # Optimistic (lowest reasonable estimate)
    frequency_mode: float       # Most likely
    frequency_max: float        # Pessimistic (worst reasonable case)

    # Impact: cost per occurrence in dollars
    impact_min: float
    impact_mode: float
    impact_max: float

    # Optional: control effectiveness reduces frequency or impact
    control_effectiveness: float = 0.0  # 0.0 to 1.0 (percentage reduction)
    control_description: str = ""

    # Metadata
    data_source: str = ""       # Where the estimates came from
    confidence: str = "medium"  # low, medium, high
    last_updated: str = ""


@dataclass
class SimulationResult:
    """Results from a Monte Carlo simulation of a single threat scenario."""
    scenario_name: str
    iterations: int
    annual_loss_values: np.ndarray = field(repr=False)

    # Summary statistics (populated after simulation)
    mean_ale: float = 0.0           # Average annual loss expectancy
    median_ale: float = 0.0
    std_dev: float = 0.0
    percentile_90: float = 0.0
    percentile_95: float = 0.0
    percentile_99: float = 0.0
    max_observed: float = 0.0
    min_observed: float = 0.0

    # Value at Risk figures
    var_90: float = 0.0             # 90% of the time, losses won't exceed this
    var_95: float = 0.0
    var_99: float = 0.0

    def compute_statistics(self):
        """Calculate summary statistics from the raw simulation data."""
        self.mean_ale = float(np.mean(self.annual_loss_values))
        self.median_ale = float(np.median(self.annual_loss_values))
        self.std_dev = float(np.std(self.annual_loss_values))
        self.percentile_90 = float(np.percentile(self.annual_loss_values, 90))
        self.percentile_95 = float(np.percentile(self.annual_loss_values, 95))
        self.percentile_99 = float(np.percentile(self.annual_loss_values, 99))
        self.max_observed = float(np.max(self.annual_loss_values))
        self.min_observed = float(np.min(self.annual_loss_values))
        self.var_90 = self.percentile_90
        self.var_95 = self.percentile_95
        self.var_99 = self.percentile_99

    def to_dict(self) -> dict:
        """Serializable summary without the raw numpy array."""
        return {
            "scenario": self.scenario_name,
            "iterations": self.iterations,
            "mean_annual_loss": round(self.mean_ale, 2),
            "median_annual_loss": round(self.median_ale, 2),
            "standard_deviation": round(self.std_dev, 2),
            "value_at_risk_90": round(self.var_90, 2),
            "value_at_risk_95": round(self.var_95, 2),
            "value_at_risk_99": round(self.var_99, 2),
            "worst_case_observed": round(self.max_observed, 2),
        }


class RiskEngine:
    """
    Monte Carlo simulation engine for quantitative risk analysis.

    For each threat scenario, the engine samples from probability
    distributions for both event frequency and per-event impact,
    then multiplies them to get annual loss expectancy. Running
    thousands of iterations produces a distribution of possible
    outcomes rather than a single point estimate.

    The math follows the FAIR (Factor Analysis of Information Risk)
    methodology: ALE = frequency × impact, but with distributions
    instead of single values.
    """

    def __init__(self, iterations: int = 10_000, seed: int | None = None):
        self.iterations = iterations
        self.rng = np.random.default_rng(seed)

    def simulate_scenario(self, scenario: ThreatScenario) -> SimulationResult:
        """
        Run Monte Carlo simulation for a single threat scenario.

        Uses PERT distributions for both frequency and impact, which
        give more weight to the "most likely" value than a simple
        triangular distribution. This better models expert estimates
        where the mode represents genuine experience.
        """
        # Sample event frequencies using PERT distribution
        frequencies = self._sample_pert(
            scenario.frequency_min,
            scenario.frequency_mode,
            scenario.frequency_max,
            self.iterations,
        )

        # Apply control effectiveness to reduce frequency
        if scenario.control_effectiveness > 0:
            frequencies = frequencies * (1 - scenario.control_effectiveness)

        # For each iteration, sample the number of events from a Poisson
        # distribution parameterized by the sampled frequency. This adds
        # realistic stochastic variation: even if you expect 3 events/year
        # on average, some years you'll get 1 and some years 6.
        event_counts = self.rng.poisson(lam=np.maximum(frequencies, 0))

        # Sample per-event impact using PERT distribution
        impacts = self._sample_pert(
            scenario.impact_min,
            scenario.impact_mode,
            scenario.impact_max,
            self.iterations,
        )

        # Annual loss = number of events × cost per event
        annual_losses = event_counts * impacts

        result = SimulationResult(
            scenario_name=scenario.name,
            iterations=self.iterations,
            annual_loss_values=annual_losses,
        )
        result.compute_statistics()

        logger.info(
            "Simulated '%s': mean ALE=$%,.0f, 95th percentile=$%,.0f",
            scenario.name, result.mean_ale, result.var_95,
        )
        return result

    def simulate_portfolio(self, scenarios: list[ThreatScenario]) -> dict:
        """
        Simulate all scenarios and compute aggregate risk.

        Returns individual results plus a combined view of total
        organizational risk exposure. Because losses from different
        scenarios can compound in the same year, the aggregate
        distribution captures correlation effects.
        """
        individual_results = []
        combined_losses = np.zeros(self.iterations)

        for scenario in scenarios:
            result = self.simulate_scenario(scenario)
            individual_results.append(result)
            combined_losses += result.annual_loss_values

        aggregate = SimulationResult(
            scenario_name="AGGREGATE_PORTFOLIO",
            iterations=self.iterations,
            annual_loss_values=combined_losses,
        )
        aggregate.compute_statistics()

        return {
            "scenarios": [r.to_dict() for r in individual_results],
            "aggregate": aggregate.to_dict(),
            "scenario_ranking": sorted(
                [r.to_dict() for r in individual_results],
                key=lambda x: x["mean_annual_loss"],
                reverse=True,
            ),
        }

    def compare_treatments(self, scenario: ThreatScenario,
                           treatments: list[dict]) -> list[dict]:
        """
        Compare different risk treatment options for a scenario.

        Each treatment specifies a control_effectiveness and annual_cost.
        The engine simulates each treatment and calculates the net benefit
        (risk reduction minus treatment cost) to support investment decisions.

        treatments format:
        [
            {"name": "Enhanced MFA", "effectiveness": 0.4, "annual_cost": 50000},
            {"name": "DLP Solution", "effectiveness": 0.6, "annual_cost": 200000},
        ]
        """
        # Baseline: no treatment
        baseline = self.simulate_scenario(scenario)

        comparisons = [{
            "treatment": "No Treatment (Baseline)",
            "annual_cost": 0,
            "mean_annual_loss": round(baseline.mean_ale, 2),
            "var_95": round(baseline.var_95, 2),
            "total_cost_of_risk": round(baseline.mean_ale, 2),
            "net_benefit_vs_baseline": 0,
        }]

        for treatment in treatments:
            treated_scenario = ThreatScenario(
                name=scenario.name,
                description=scenario.description,
                category=scenario.category,
                frequency_min=scenario.frequency_min,
                frequency_mode=scenario.frequency_mode,
                frequency_max=scenario.frequency_max,
                impact_min=scenario.impact_min,
                impact_mode=scenario.impact_mode,
                impact_max=scenario.impact_max,
                control_effectiveness=treatment["effectiveness"],
            )
            result = self.simulate_scenario(treated_scenario)

            total_cost = result.mean_ale + treatment["annual_cost"]
            net_benefit = baseline.mean_ale - total_cost

            comparisons.append({
                "treatment": treatment["name"],
                "annual_cost": treatment["annual_cost"],
                "effectiveness": f"{treatment['effectiveness']:.0%}",
                "mean_annual_loss": round(result.mean_ale, 2),
                "var_95": round(result.var_95, 2),
                "total_cost_of_risk": round(total_cost, 2),
                "net_benefit_vs_baseline": round(net_benefit, 2),
            })

        # Sort by total cost of risk (lower is better)
        comparisons.sort(key=lambda x: x["total_cost_of_risk"])
        return comparisons

    def _sample_pert(self, minimum: float, mode: float,
                     maximum: float, size: int) -> np.ndarray:
        """
        Sample from a PERT (Program Evaluation and Review Technique) distribution.

        PERT is a Beta distribution rescaled to [min, max] with shape
        parameters derived from the mode. It gives 4x the weight to
        the most likely value compared to a uniform distribution,
        which aligns well with expert estimation.
        """
        if minimum >= maximum:
            return np.full(size, mode)

        # PERT shape parameter (lambda=4 is standard)
        lam = 4
        mean = (minimum + lam * mode + maximum) / (lam + 2)

        # Avoid division by zero for degenerate cases
        if maximum == minimum:
            return np.full(size, minimum)

        # Beta distribution parameters
        # Guard against division by zero when mode equals the PERT mean
        denominator = (mode - mean) * (maximum - minimum)
        if abs(denominator) < 1e-10:
            # When mode == mean, use symmetric beta (alpha = beta)
            alpha = 4.0
            beta = 4.0
        else:
            alpha = ((mean - minimum) * (2 * mode - minimum - maximum)) / denominator

            # Guard against negative alpha (can happen with extreme inputs)
            if alpha <= 0:
                alpha = 1.0

            beta = alpha * (maximum - mean) / (mean - minimum) if (mean - minimum) > 0 else 1.0

            if beta <= 0:
                beta = 1.0

        # Sample from Beta and rescale to [min, max]
        samples = self.rng.beta(alpha, beta, size=size)
        return minimum + samples * (maximum - minimum)


# ===================================================================
# Example scenarios for common GRC risk categories
# ===================================================================

EXAMPLE_SCENARIOS = [
    ThreatScenario(
        name="Data Breach - External Attack",
        description="Unauthorized access to PII/PHI through external threat actor",
        category="data_breach",
        frequency_min=0.1,
        frequency_mode=0.5,
        frequency_max=2.0,
        impact_min=100_000,
        impact_mode=500_000,
        impact_max=5_000_000,
        data_source="IBM Cost of a Data Breach Report 2024, industry benchmarks",
        confidence="medium",
    ),
    ThreatScenario(
        name="Insider Threat - Data Exfiltration",
        description="Employee or contractor intentionally exfiltrating sensitive data",
        category="insider_threat",
        frequency_min=0.2,
        frequency_mode=1.0,
        frequency_max=3.0,
        impact_min=50_000,
        impact_mode=200_000,
        impact_max=2_000_000,
        data_source="Ponemon Insider Threat Report, internal incident history",
        confidence="medium",
    ),
    ThreatScenario(
        name="Cloud Service Disruption",
        description="Major cloud provider outage affecting business operations",
        category="service_disruption",
        frequency_min=1.0,
        frequency_mode=3.0,
        frequency_max=6.0,
        impact_min=10_000,
        impact_mode=75_000,
        impact_max=500_000,
        data_source="Historical cloud provider incident reports",
        confidence="high",
    ),
    ThreatScenario(
        name="Compliance Violation - Regulatory Fine",
        description="GDPR, CCPA, or other regulatory enforcement action",
        category="compliance",
        frequency_min=0.05,
        frequency_mode=0.2,
        frequency_max=1.0,
        impact_min=50_000,
        impact_mode=250_000,
        impact_max=10_000_000,
        data_source="GDPR enforcement tracker, FTC settlement history",
        confidence="low",
    ),
    ThreatScenario(
        name="Ransomware Attack",
        description="Ransomware deployment leading to operational disruption and potential payment",
        category="malware",
        frequency_min=0.1,
        frequency_mode=0.3,
        frequency_max=1.5,
        impact_min=200_000,
        impact_mode=1_000_000,
        impact_max=8_000_000,
        data_source="Coveware quarterly reports, Chainalysis ransomware data",
        confidence="medium",
    ),
]
