"""Tests for the Monte Carlo risk engine."""

import numpy as np
import pytest

from modules.risk_engine import EXAMPLE_SCENARIOS, RiskEngine, ThreatScenario


@pytest.fixture
def engine():
    """Seeded engine for reproducible tests."""
    return RiskEngine(iterations=5000, seed=42)


@pytest.fixture
def sample_scenario():
    return ThreatScenario(
        name="Test Scenario",
        description="A test threat scenario",
        category="test",
        frequency_min=1.0,
        frequency_mode=3.0,
        frequency_max=5.0,
        impact_min=10_000,
        impact_mode=50_000,
        impact_max=200_000,
    )


class TestRiskEngine:

    def test_simulation_produces_results(self, engine, sample_scenario):
        result = engine.simulate_scenario(sample_scenario)
        assert result.scenario_name == "Test Scenario"
        assert result.iterations == 5000
        assert len(result.annual_loss_values) == 5000

    def test_statistics_are_computed(self, engine, sample_scenario):
        result = engine.simulate_scenario(sample_scenario)
        assert result.mean_ale > 0
        assert result.median_ale > 0
        assert result.var_95 >= result.var_90
        assert result.var_99 >= result.var_95

    def test_mean_in_reasonable_range(self, engine, sample_scenario):
        """Mean ALE should be roughly frequency_mode * impact_mode."""
        result = engine.simulate_scenario(sample_scenario)
        # Allow wide tolerance since Monte Carlo has variance
        assert 50_000 < result.mean_ale < 500_000

    def test_control_effectiveness_reduces_loss(self, engine, sample_scenario):
        baseline = engine.simulate_scenario(sample_scenario)

        controlled = ThreatScenario(
            **{**sample_scenario.__dict__, "control_effectiveness": 0.5}
        )
        result = engine.simulate_scenario(controlled)

        # 50% control effectiveness should roughly halve the mean ALE
        assert result.mean_ale < baseline.mean_ale

    def test_portfolio_simulation(self, engine):
        results = engine.simulate_portfolio(EXAMPLE_SCENARIOS)
        assert "scenarios" in results
        assert "aggregate" in results
        assert "scenario_ranking" in results
        assert len(results["scenarios"]) == len(EXAMPLE_SCENARIOS)
        # Aggregate should be >= largest individual scenario
        agg_mean = results["aggregate"]["mean_annual_loss"]
        max_individual = max(s["mean_annual_loss"] for s in results["scenarios"])
        assert agg_mean >= max_individual

    def test_treatment_comparison(self, engine, sample_scenario):
        treatments = [
            {"name": "Basic", "effectiveness": 0.2, "annual_cost": 10_000},
            {"name": "Advanced", "effectiveness": 0.6, "annual_cost": 50_000},
        ]
        comparison = engine.compare_treatments(sample_scenario, treatments)
        assert len(comparison) == 3  # baseline + 2 treatments
        # Baseline should have 0 net benefit
        baseline = [c for c in comparison if "Baseline" in c["treatment"]][0]
        assert baseline["net_benefit_vs_baseline"] == 0

    def test_to_dict_serializable(self, engine, sample_scenario):
        result = engine.simulate_scenario(sample_scenario)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "scenario" in d
        assert "mean_annual_loss" in d
        # Should not contain numpy arrays
        for value in d.values():
            assert not isinstance(value, np.ndarray)

    def test_degenerate_scenario(self, engine):
        """Scenario where min == max should produce consistent results."""
        scenario = ThreatScenario(
            name="Fixed", description="test", category="test",
            frequency_min=1.0, frequency_mode=1.0, frequency_max=1.0,
            impact_min=100_000, impact_mode=100_000, impact_max=100_000,
        )
        result = engine.simulate_scenario(scenario)
        # With fixed inputs, mean should be close to 1 * 100,000
        assert 50_000 < result.mean_ale < 200_000


class TestThreatScenario:

    def test_example_scenarios_valid(self):
        """All example scenarios should have valid ranges."""
        for scenario in EXAMPLE_SCENARIOS:
            assert scenario.frequency_min <= scenario.frequency_mode <= scenario.frequency_max
            assert scenario.impact_min <= scenario.impact_mode <= scenario.impact_max
            assert 0.0 <= scenario.control_effectiveness <= 1.0
            assert scenario.name
            assert scenario.category
