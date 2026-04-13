# Contributing to GRIMSEC

Thank you for your interest in contributing. GRIMSEC is an open-source DevSecOps agent suite and welcomes contributions of all kinds.

---

## Code of Conduct

Be professional and respectful. Security tools can be misused — we expect contributors to uphold ethical standards and only contribute features intended for authorized security testing.

---

## How to Contribute

### Reporting Issues

- Use GitHub Issues
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not open a public issue
- Include: OS, Python version, tool versions (`python grimsec.py status`), and steps to reproduce

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Test locally: `python grimsec.py status`
5. Open a PR with a clear description of what changed and why

### PR Guidelines

- Keep PRs focused — one feature or fix per PR
- Add a description explaining the security rationale for any new detection logic
- Do not include hardcoded credentials, API keys, or personal data in any file
- Do not include hardcoded target hostnames, IP addresses, or internal repository names
- Scripts must be idempotent (safe to run multiple times)
- Bash scripts must pass `shellcheck` without errors

---

## Areas for Contribution

### High Priority

- **New Semgrep rules** — additional SAST rules for Python, Go, Rust, TypeScript
- **New Nuclei templates** — DAST coverage for additional vulnerability classes
- **OPA policies** — new IaC security policies for cloud providers (AWS, GCP, Azure)
- **Dashboard integrations** — Grafana dashboards, Metabase reports, Kibana configurations
- **CI/CD integrations** — GitHub Actions workflow, GitLab CI, Jenkins pipeline

### Medium Priority

- **Additional agent SKILL.md files** — new agents for specific security domains
- **Output format improvements** — SARIF output, OCSF format, CycloneDX SBOM
- **Language support** — scanner configurations for additional tech stacks
- **Documentation** — tutorials, blog posts, usage examples

### Low Priority

- **UI improvements** — terminal output formatting, progress bars
- **Performance** — parallel scanning, caching, incremental analysis

---

## Agent Development

To add a new agent:

1. Create a directory: `agents/NN-agent-name/`
2. Write a `SKILL.md` following the format of existing agents
3. Add scripts to `agents/NN-agent-name/scripts/`
4. Add references to `agents/NN-agent-name/references/`
5. Update `grimsec.py` to add the CLI subcommand
6. Document in `docs/agent-reference.md`

### SKILL.md Format

Each SKILL.md must include:
- `name:` — skill name
- `description:` — trigger description for Perplexity Computer
- Trigger conditions
- Step-by-step instructions for the agent
- Output format specification
- Required tools
- Example output

See existing agents for reference. Keep agent instructions generic — no hardcoded repository names, hostnames, or API keys.

---

## Style Guide

### Python

- Follow PEP 8
- Use type hints for function signatures
- No hardcoded credentials or personal data
- ANSI color codes must be gracefully disabled when terminal doesn't support them

### Bash

- Use `set -euo pipefail` at the top of all scripts
- Quote all variable expansions: `"$VAR"` not `$VAR`
- Use `command -v tool` to check for tool existence, not `which`
- All installs must be idempotent — check before installing

### Markdown

- Use ATX headings (`##` not underline style)
- Code blocks must specify language for syntax highlighting
- No trailing whitespace

---

## Testing

Before submitting a PR, verify:

```bash
python grimsec.py status        # All tools detected correctly
python grimsec.py --help        # Help text renders correctly
python grimsec.py analyze --help
bash -n scripts/install-tools.sh  # Bash syntax check
bash -n setup.sh
```

For script linting (if you have shellcheck):

```bash
shellcheck scripts/install-tools.sh
shellcheck scripts/run-pipeline.sh
shellcheck setup.sh
```

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
