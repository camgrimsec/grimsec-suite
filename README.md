# GRIMSEC — AI-Powered DevSecOps Agent Suite

> 12 autonomous security agents that analyze, audit, validate, and remediate vulnerabilities in any GitHub repository. Context-aware. Noise-reduced. PR-ready.

---

## Why GRIMSEC?

Traditional scanners dump hundreds of CVEs. GRIMSEC's 12-agent pipeline tells you which ones actually matter.

**The problem:** Run Trivy on any repo → get 500+ findings. How many are actually exploitable? Maybe 5.

**GRIMSEC's answer:** 6-stage reachability analysis → Real Risk Scores → exploit validation → auto-generated PRs → executive reports. **89-96% noise reduction.**

---

## Quick Start

```bash
git clone https://github.com/yourusername/grimsec-suite.git
cd grimsec-suite
bash setup.sh
python grimsec.py analyze https://github.com/org/repo
```

See [docs/quickstart.md](docs/quickstart.md) for a detailed 5-minute guide.

---

## The 12 Agents

| # | Agent | What It Does |
|---|-------|-------------|
| 1 | [Repo Analyzer](agents/01-devsecops-repo-analyzer/SKILL.md) | 6-stage pipeline: inventory → STRIDE → scan → reachability → remediate → report |
| 2 | [CI/CD Auditor](agents/02-cicd-pipeline-auditor/SKILL.md) | Supply chain security: unpinned actions, expression injection, PPE, secrets |
| 3 | [Vuln Enricher](agents/03-vulnerability-context-enricher/SKILL.md) | NVD + EPSS + CISA KEV + ATT&CK mapping per CVE |
| 4 | [Doc Intelligence](agents/04-doc-intelligence-agent/SKILL.md) | Reads project docs to validate/downgrade scanner findings |
| 5 | [Threat Intel Monitor](agents/05-threat-intel-monitor/SKILL.md) | Continuous CVE monitoring against your dependency inventory |
| 6 | [Executive Reporter](agents/06-executive-reporting-agent/SKILL.md) | Translates findings into $$ risk, compliance mapping, board-ready reports |
| 7 | [DAST Scanner](agents/07-dast-scanner/SKILL.md) | Nuclei + ZAP against running applications |
| 8 | [Exploit Validator](agents/08-exploit-validation-agent/SKILL.md) | Generates PoCs proving findings are actually exploitable |
| 9 | [Code Understanding](agents/09-code-understanding-agent/SKILL.md) | Attack surface mapping, source-to-sink tracing, variant hunting |
| 10 | [IaC Policy](agents/10-iac-policy-agent/SKILL.md) | Checkov + OPA: Docker, K8s, Terraform, GitHub Actions policies |
| 11 | [OSS Forensics](agents/11-oss-forensics-agent/SKILL.md) | Supply chain investigation: evidence collection, IOC detection, timeline |
| 12 | [Adversary Sim](agents/12-adversary-simulation-agent/SKILL.md) | Controlled exploitation + ATT&CK mapping |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GRIMSEC PIPELINE                             │
│                                                                 │
│  INPUT: GitHub Repo URL                                         │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  Agent 01   │    │  Agent 02   │    │     Agent 03        │ │
│  │  Repo       │───▶│  CI/CD      │───▶│  Vuln Enricher      │ │
│  │  Analyzer   │    │  Auditor    │    │  (NVD+EPSS+KEV)     │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│         │                  │                      │             │
│         ▼                  ▼                      ▼             │
│  inventory.json     cicd-findings.json    enriched-cvelist.json │
│         │                                         │             │
│         ▼                                         ▼             │
│  ┌─────────────┐                        ┌─────────────────────┐ │
│  │  Agent 04   │                        │     Agent 05        │ │
│  │  Doc Intel  │                        │  Threat Intel       │ │
│  │  (context)  │                        │  Monitor            │ │
│  └─────────────┘                        └─────────────────────┘ │
│         │                                         │             │
│         └───────────────────┬───────────────────-─┘             │
│                             ▼                                   │
│              ┌──────────────────────────┐                       │
│              │  Agent 06: Exec Reporter │                       │
│              │  • $$ Risk quantification│                       │
│              │  • Compliance mapping    │                       │
│              │  • Board-ready deck      │                       │
│              └──────────────────────────┘                       │
│                                                                 │
│  ── DEEP MODE adds ─────────────────────────────────────────── │
│                                                                 │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐ │
│  │ Agent 07   │  │ Agent 08   │  │ Agent 09   │  │Agent 10  │ │
│  │ DAST       │  │ Exploit    │  │ Code       │  │ IaC      │ │
│  │ Scanner    │  │ Validator  │  │ Understanding│ │ Policy   │ │
│  └────────────┘  └────────────┘  └────────────┘  └──────────┘ │
│                                                                 │
│  ┌────────────┐  ┌────────────┐                                │
│  │ Agent 11   │  │ Agent 12   │                                │
│  │ OSS        │  │ Adversary  │                                │
│  │ Forensics  │  │ Simulation │                                │
│  └────────────┘  └────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for detailed agent chaining and data flow.

---

## Usage with Perplexity Computer

Each agent is a Perplexity Computer skill. To import them:

1. Go to [perplexity.ai](https://perplexity.ai) → Computer → Skills
2. Upload the `SKILL.md` from the agent directory (or zip the whole agent folder)
3. Trigger with natural language:
   - `"analyze this repo for security issues: https://github.com/org/repo"`
   - `"audit the CI/CD pipeline at this URL"`
   - `"enrich CVE-2024-1234"`
   - `"generate an executive security report"`

### Skill Loading Reference

| Command | Skill to Load | Trigger Phrase |
|---------|--------------|----------------|
| `analyze` | devsecops-repo-analyzer | "analyze this repo for security issues" |
| `audit` | cicd-pipeline-auditor | "audit the CI/CD pipeline" |
| `enrich` | vulnerability-context-enricher | "enrich CVE-XXXX-XXXXX" |
| `doc` | doc-intelligence-agent | "read the project documentation" |
| `monitor` | threat-intel-monitor | "run threat intel check" |
| `report` | executive-reporting-agent | "generate executive report" |
| `dast` | dast-scanner | "run DAST scan against this URL" |
| `validate` | exploit-validation-agent | "validate these findings" |
| `understand` | code-understanding-agent | "map the attack surface" |
| `iac` | iac-policy-agent | "run IaC policy scan" |
| `forensics` | oss-forensics-agent | "investigate this package for supply chain compromise" |
| `simulate` | adversary-simulation-agent | "run adversary simulation" |

---

## CLI Usage

```bash
# Full 12-agent pipeline
python grimsec.py analyze https://github.com/org/repo

# Quick scan (Agents 1-3 only, ~10 min)
python grimsec.py analyze https://github.com/org/repo --quick

# Deep scan (all agents + DAST + adversary sim)
python grimsec.py analyze https://github.com/org/repo --deep

# Individual agent commands
python grimsec.py scan https://github.com/org/repo      # Agent 1 (SCA+SAST+secrets)
python grimsec.py audit https://github.com/org/repo     # Agent 2 (CI/CD audit)
python grimsec.py enrich CVE-2024-1234                  # Agent 3 (CVE enrichment)
python grimsec.py monitor                               # Agent 5 (threat intel)
python grimsec.py report grimsec-output/repo/2026-01-01 # Agent 6 (exec report)
python grimsec.py dast https://staging.example.com      # Agent 7 (DAST)
python grimsec.py validate grimsec-output/repo/2026-01-01 # Agent 8 (PoC validation)
python grimsec.py understand https://github.com/org/repo # Agent 9 (attack surface)
python grimsec.py iac /path/to/repo                     # Agent 10 (IaC policy)
python grimsec.py forensics https://github.com/org/repo # Agent 11 (supply chain)
python grimsec.py simulate staging.example.com          # Agent 12 (adversary sim)

# Utilities
python grimsec.py status    # Check all tools installed
python grimsec.py install   # Install all tools
python grimsec.py dashboard # Dashboard setup instructions
```

---

## Output Structure

After a run, findings are organized at `grimsec-output/<repo-name>/<timestamp>/`:

```
grimsec-output/example-repo/2026-01-01T12-00-00/
├── inventory.json                # Dependencies, tech stack, entry points
├── app-context.json              # Application type, architecture, threat model
├── stride-threats.json           # STRIDE threat enumeration
├── scan-results/
│   ├── trivy-sca.json            # SCA findings
│   ├── semgrep-sast.json         # SAST findings
│   ├── gitleaks-secrets.json     # Secrets scan
│   └── grype-sbom.json           # SBOM + SCA
├── reachability-analysis.json    # Which findings are actually reachable
├── enriched-findings.json        # CVEs enriched with EPSS + KEV + ATT&CK
├── cicd-findings.json            # CI/CD audit results
├── doc-context.json              # Documentation intelligence
├── iac-findings.json             # IaC policy violations
├── dast-results/                 # DAST scan output
├── exploit-validation.json       # PoC-backed validation results
├── attack-surface-map.json       # Attack surface + data flow
├── forensics-report.json         # Supply chain forensics
├── simulation-report.json        # Adversary simulation results
└── executive-summary.json        # Board-ready executive report
```

See [examples/sample-output/README.md](examples/sample-output/README.md) for full structure.

---

## Proven Results

| Metric | Value |
|--------|-------|
| Average noise reduction | 89-96% |
| Finding validation method | PoC-backed |
| Compliance frameworks covered | SOC 2, ISO 27001, NIST CSF, OWASP SAMM |
| CVE enrichment sources | NVD, EPSS, CISA KEV, MITRE ATT&CK |
| Supported languages | Python, JavaScript/TypeScript, Go, Java, Ruby, Rust |
| IaC targets | Dockerfile, Kubernetes, Terraform, GitHub Actions |

---

## Requirements

| Tool | Purpose | Required? |
|------|---------|-----------|
| Python 3.8+ | CLI runner | Yes |
| Trivy | SCA + container scanning | Yes |
| Semgrep | SAST | Yes |
| Gitleaks | Secrets detection | Yes |
| Grype | SCA (SBOM-based) | Yes |
| Nuclei | DAST (Agent 7) | For DAST |
| httpx | HTTP probing (Agent 7) | For DAST |
| Checkov | IaC scanning (Agent 10) | For IaC |
| OPA | Policy engine (Agent 10) | For IaC |
| Conftest | Config testing (Agent 10) | For IaC |
| Syft | SBOM generation (Agent 10) | For IaC |
| Snyk CLI | Additional SCA | Optional |

Run `bash setup.sh` to install everything automatically.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where help is most wanted:
- New Semgrep rules for additional languages
- Additional Nuclei templates for DAST coverage
- New OPA policies for cloud providers
- Dashboard integrations (Grafana, Metabase, Kibana)
- Integrations with JIRA, GitHub Issues, PagerDuty

---

## Security

See [SECURITY.md](SECURITY.md) for the security policy and how to report vulnerabilities.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Legal

GRIMSEC is for authorized security testing only. Only run against systems you own or have explicit written permission to test. The exploit validation and adversary simulation agents include safeguards, but you are responsible for ensuring all usage is authorized and legal in your jurisdiction.
