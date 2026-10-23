# CROPTer

**CROPTer** is an all-in-one vulnerability research platform focused on authorized security testing, source-code analysis, safe fuzzing workflows, evidence management, and responsible disclosure.

> CROPTer does not promise to discover zero-days or guarantee bounty income. Findings must be validated by a researcher and reported only through the asset owner's approved process.

## Launch the interactive terminal UI

From the repository root, run:

```bash
bash run.sh
```

The launcher creates a project-local `.venv` when missing and installs CROPTer into that environment before starting the menu. It does not install packages into Kali's system Python. The first launch may need internet access to install the local package's build requirements.

You can also launch the UI manually after installing the project with `python -m pip install -e .`:

```bash
python -m cropter.tui
```

The current menu provides a **low-impact passive web posture review**. It asks for one target URL and derives a narrow allowlist from that URL's hostname, so a separate scope file is not required for this mode. Before requests, it asks for confirmation that you own the target or have permission. It follows same-origin links only (up to 15 pages), uses ordinary GET requests, records selected response headers as evidence, checks common security-header posture, and writes both a JSON evidence report and a readable Markdown report with affected URLs, confidence, limitations, and suggested next steps. The terminal shows finding details and evidence. It does not enumerate subdomains, crawl third-party hosts, submit forms, brute-force, or send exploit payloads.

**Important:** this is still a posture-review milestone, not an autonomous vulnerability discovery engine. Missing headers and HTML heuristics are low-confidence leads, not confirmed vulnerabilities. It cannot reliably detect business-logic flaws, authenticated-only issues, access-control bugs, SSRF, SQL injection, or XSS. Validate manually, stay within the published program scope, and report only reproducible issues with meaningful impact. The boot animation is cosmetic.

## Initial scope

The first milestone is a small, testable Python CLI foundation:

- Explicit target scope and allowlist checks before any network action.
- Local source/repository inventory and safe static checks.
- Structured findings with evidence, confidence, and remediation notes.
- JSON report output.
- Unit tests and documented setup.

## Safety model

- Default to offline/local analysis.
- The passive web review derives scope from the entered URL and requires a confirmation prompt before sending requests. It does not automatically expand scope to sibling subdomains or third-party services.
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
