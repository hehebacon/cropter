# CROPTer

**CROPTer** is an all-in-one vulnerability research platform focused on authorized security testing, source-code analysis, safe fuzzing workflows, evidence management, and responsible disclosure.

> CROPTer does not promise to discover zero-days or guarantee bounty income. Findings must be validated by a researcher and reported only through the asset owner's approved process.

## Initial scope

The first milestone is a small, testable Python CLI foundation:

- Explicit target scope and allowlist checks before any network action.
- Local source/repository inventory and safe static checks.
- Structured findings with evidence, confidence, and remediation notes.
- JSON report output.
- Unit tests and documented setup.

## Safety model

- Default to offline/local analysis.
- Network testing is disabled unless an explicit scope file is supplied.
- Never test systems without authorization; follow the program's scope, rate limits, and disclosure policy.
- No exploit deployment, persistence, credential theft, or destructive testing.

## Planned modules

- `core`: configuration, scope validation, job orchestration.
- `analyzer`: local source and dependency analysis adapters.
- `fuzzing`: isolated test harness integrations.
- `evidence`: finding models and report generation.
- `cli`: user-facing commands.

## Status

Repository initialized. Implementation will proceed incrementally with tests; integrations are not considered complete until verified.

run code
""" sh
git clone https://github.com/hehebacon/cropter.git
cd cropter

python -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
pytest -q
"""
