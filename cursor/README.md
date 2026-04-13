# GRIMSEC for Cursor

12-agent DevSecOps security analysis suite for [Cursor](https://cursor.sh). Agents auto-activate based on trigger phrases — just describe what you want in the Cursor chat.

## Installation

1. Copy the `.cursor/` folder to your project root:
   ```bash
   cp -r .cursor/ /path/to/your/project/
   ```

2. Open your project in Cursor.

3. Start chatting in Cursor's AI chat panel.

That's it. Rules auto-activate based on keywords in your prompts.

## How Rules Work

Cursor reads `.cursor/rules/` files and automatically applies them when trigger phrases appear in the conversation. You do not need to manually load anything.

**Example triggers:**

| What you say | What activates |
|---|---|
| "analyze this repo for security issues" | `grimsec-repo-analyzer.mdc` |
| "audit the GitHub Actions workflows" | `grimsec-cicd-auditor.mdc` |
| "look up CVE-2024-1234" | `grimsec-vuln-enricher.mdc` |
| "map the attack surface of ./src" | `grimsec-code-understanding.mdc` |
| "scan the Terraform files for security issues" | `grimsec-iac-policy.mdc` |
| "investigate this package for supply chain compromise" | `grimsec-forensics.mdc` |
| "generate an executive security report" | `grimsec-executive-reporter.mdc` |
| "run a DAST scan against staging.example.com" | `grimsec-dast-scanner.mdc` |

## The 12 Agents

| # | Agent | Purpose |
|---|-------|---------|
| 1 | Repo Analyzer | End-to-end DevSecOps analysis: STRIDE threat model, SAST/SCA/secrets/IaC scanning, Real Risk Scores |
| 2 | CI/CD Auditor | GitHub Actions security: supply chain, expression injection, permissions, dangerous triggers |
| 3 | Vuln Enricher | CVE intelligence: CVSS, EPSS, CISA KEV, MITRE ATT&CK, fix availability |
| 4 | Doc Intel | Documentation analysis: builds security context profile to validate/adjust scanner findings |
| 5 | Threat Monitor | Continuous monitoring: cross-references CISA KEV + OSV against your dependency inventories |
| 6 | Executive Reporter | Board-ready reports: financial risk quantification, compliance mapping, MTTR benchmarking |
| 7 | DAST Scanner | Runtime testing: Nuclei + OWASP ZAP, OWASP Top 10 detection |
| 8 | Exploit Validator | Proves exploitability: 7-stage PoC generation and validation for RRS ≥ 7 findings |
| 9 | Code Understanding | Code analysis: attack surface mapping, data flow tracing, variant hunting, framework security |
| 10 | IaC Policy | Infrastructure compliance: Checkov + OPA, CIS/NIST/SOC2/HIPAA/PCI-DSS, SBOM generation |
| 11 | Forensics | Supply chain forensics: evidence collection, IOC extraction, timeline reconstruction |
| 12 | Adversary Sim | Red team simulation: controlled exploitation with MITRE ATT&CK mapping (requires authorization) |

## Output Directory

All analysis artifacts are written to `./grimsec-output/` relative to your project:

```
grimsec-output/
├── {repo-name}/              # Per-repo analysis (Agents 1-5, 7-10)
│   ├── inventory.json
│   ├── app-context.json
│   ├── scan-results/
│   ├── reachability-analysis.json
│   ├── remediation.json
│   └── assessment-report.md
├── threat-intel/             # Agent 5 output
├── executive/                # Agent 6 output
├── exploit-validation/       # Agent 8 output
├── code-understanding/       # Agent 9 output
├── iac-policy/               # Agent 10 output
├── forensics/                # Agent 11 output
└── adversary-simulation/     # Agent 12 output
```

## Example Workflows

### Full Security Assessment
```
1. "Analyze https://github.com/org/repo for security vulnerabilities"
2. "Enrich the high and critical CVEs from the scan"
3. "Validate the findings with RRS >= 7"
4. "Generate an executive security report"
```

### CI/CD Hardening
```
1. "Audit the GitHub Actions workflows in this repo"
2. "Show me the specific fixes for each finding"
```

### IaC Compliance Audit
```
"Scan the Terraform and Kubernetes files for security issues and map to CIS benchmarks"
```

### Supply Chain Investigation
```
"Investigate https://github.com/org/suspicious-package for signs of compromise"
```

## File Structure

```
cursor/
├── README.md                            # This file
└── .cursor/
    ├── index.mdc                        # Master agent index
    └── rules/
        ├── grimsec-repo-analyzer.mdc
        ├── grimsec-cicd-auditor.mdc
        ├── grimsec-vuln-enricher.mdc
        ├── grimsec-doc-intel.mdc
        ├── grimsec-threat-monitor.mdc
        ├── grimsec-executive-reporter.mdc
        ├── grimsec-dast-scanner.mdc
        ├── grimsec-exploit-validator.mdc
        ├── grimsec-code-understanding.mdc
        ├── grimsec-iac-policy.mdc
        ├── grimsec-forensics.mdc
        └── grimsec-adversary-sim.mdc
```

## Important Notes

- **Active scan authorization required.** Agents 7 (DAST) and 12 (Adversary Sim) run active tests. Always confirm authorization before running against any system.
- **Secrets in public repos.** Agent 1 will flag secrets found in public repos as compromised and recommend rotation, even if they appear to be test values.
- **Rate limits.** Agents 3 and 5 query public APIs (NVD, EPSS, CISA KEV). NVD allows 5 requests/30s without an API key.
