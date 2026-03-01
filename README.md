# GRC Automation Toolkit

A practical Python-based toolkit for automating Governance, Risk, and Compliance workflows. Built for GRC professionals who want to stop spending their weeks on manual evidence collection, copy-paste reporting, and spreadsheet-driven risk tracking.

## What This Toolkit Does

- **Evidence Collection**: Pulls configuration data from AWS, Azure, and GCP via their APIs and stores structured evidence artifacts
- **Control Assessment**: Evaluates collected evidence against codified NIST 800-53 control requirements
- **Risk Quantification**: Runs Monte Carlo simulations to move beyond red/yellow/green heat maps
- **Report Generation**: Produces POA&M documents and compliance summaries from structured data
- **Vendor Risk Tracking**: Monitors third-party risk indicators and SLA compliance

## Project Structure

```
grc-toolkit/
├── config/
│   ├── frameworks.yaml          # Control framework definitions
│   └── settings.yaml            # Environment and connection settings
├── modules/
│   ├── evidence_collector.py    # Cloud API evidence gathering
│   ├── control_assessor.py      # Automated control evaluation
│   ├── risk_engine.py           # Quantitative risk analysis
│   ├── report_generator.py      # Compliance report builder
│   └── vendor_monitor.py        # Third-party risk tracking
├── scripts/
│   ├── run_collection.py        # Entry point: collect evidence
│   ├── run_assessment.py        # Entry point: assess controls
│   └── run_risk_analysis.py     # Entry point: quantify risk
├── evidence/                    # Collected evidence artifacts (gitignored)
├── reports/                     # Generated reports (gitignored)
├── requirements.txt
└── README.md
```

## Setup

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Copy `config/settings.yaml` and fill in your cloud credentials and environment details.

## Quick Start

```bash
# Collect evidence from your cloud environments
python scripts/run_collection.py --framework nist-800-53 --control-family AC

# Assess collected evidence against controls
python scripts/run_assessment.py --evidence-dir evidence/ --output reports/

# Run quantitative risk analysis
python scripts/run_risk_analysis.py --scenarios config/risk_scenarios.yaml
```

## Requirements

- Python 3.10+
- Cloud provider credentials (AWS, Azure, GCP) configured per provider SDK requirements
- See requirements.txt for Python package dependencies
