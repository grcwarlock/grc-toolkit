# Contributing to GRC Toolkit

Thanks for your interest in contributing. This project aims to make compliance automation accessible to GRC professionals who may not have a dedicated engineering team but know enough Python to be dangerous.

## How to Contribute

### Reporting Bugs

Open an issue with:
- What you were trying to do
- What happened instead
- Your Python version and OS
- The relevant error output

### Adding New Control Families

This is the most impactful contribution you can make. The process is:

1. **Define checks in `config/frameworks.yaml`** following the existing pattern. Each check needs a control ID, check ID, description, cloud provider, service, API method, and assertion name.

2. **Register assertion functions in `modules/control_assessor.py`** using the `@self.register("assertion_name")` decorator. Each assertion takes raw API response data and returns `(passed: bool, findings: list[str])`.

3. **Document the required IAM permissions** for any new API calls.

4. **Submit a PR** with the YAML additions, assertion functions, and updated IAM policy documentation.

### Adding Cloud Provider Support

Azure and GCP collectors follow the same interface as `AWSCollector`. Collectors can now be wrapped using the connector framework in `modules/connectors/`. The `BaseConnector` ABC provides `collect()`, `health_check()`, and `validate_config()` methods. See `modules/connectors/cloud_adapter.py` for how existing collectors are wrapped.

If you're building a new collector:

- Implement `collect(service, method, control_id, check_id)` returning `list[EvidenceArtifact]`
- Handle authentication through the provider's standard credential chain
- Handle pagination for APIs that require it
- Return structured error information when calls fail

### Code Style

- Type hints on function signatures
- Docstrings on classes and public methods
- Meaningful variable names over comments explaining what something does
- Keep assertion functions focused: one assertion checks one thing

### Testing

Add tests in `tests/` using pytest. At minimum, assertion functions should have test cases covering pass, fail, and edge cases (empty data, malformed responses, paginated results).

```bash
python -m pytest tests/ -v
```

### Security Guidelines

- **Never commit secrets.** API keys, passwords, and credentials go in environment variables. Use `.env.example` as the template — never add values to tracked config files.
- **All new endpoints must include authentication.** Add `api_key: str = Depends(require_api_key)` to every route handler.
- **Validate all input.** Use Pydantic models for request bodies and `validate_enum()` from `api.security` for enum-like fields.
- **No mass assignment.** When accepting update dicts, explicitly allowlist which fields can be modified.
- **Escape output.** The frontend uses `esc()` for all dynamic content. Never insert API response data directly into innerHTML.
- **Run security scans before submitting PRs.** `bandit -r modules/ api/ db/ -ll -ii` should pass clean.
- **Secrets in notifications.** SMTP and webhook credentials must come from environment variables, never from config dicts passed through function parameters.

## What We're Looking For

- Additional NIST 800-53 control family coverage (CM, IA, SI, PE, PS are all needed)
- Azure and GCP collector implementations
- FedRAMP-specific overlay checks
- CMMC 2.0 framework definitions
- SOC 2 trust service criteria mappings
- Integration examples for GRC platforms (ServiceNow, Archer, etc.)
- Better risk scenario data from industry benchmarks

## What We're Not Looking For

- Dependencies on commercial GRC platforms for core functionality
- Vendor-specific security rating integrations without free tier access
- Changes that require paid API keys to run basic functionality
