# GRIMSEC for Claude Code

12-agent DevSecOps security analysis suite for [Claude Code](https://claude.ai/code). Agents are invokable as slash commands or described naturally in the chat.

## Installation

1. Copy `CLAUDE.md` to your project root:
   ```bash
   cp CLAUDE.md /path/to/your/project/
   ```

2. Copy the `.claude/` folder to your project root:
   ```bash
   cp -r .claude/ /path/to/your/project/
   ```

3. Open your project in Claude Code.

Claude Code reads `CLAUDE.md` automatically when you start a session. Skills in `.claude/skills/` are referenced by `CLAUDE.md` and available as slash commands.

## Slash Commands

| Command | Agent | What It Does |
|---------|-------|-------------|
| `/repo-analyzer` | Repo Analyzer | Full 6-stage DevSecOps scan |
| `/cicd-auditor` | CI/CD Auditor | GitHub Actions security audit |
| `/vuln-enricher` | Vuln Enricher | Enrich CVEs with EPSS/CISA KEV/ATT&CK |
| `/doc-intel` | Doc Intel | Build security context from documentation |
| `/threat-monitor` | Threat Monitor | Check exposure against current threat feeds |
| `/executive-reporter` | Executive Reporter | Generate CISO/board-ready reports |
| `/dast-scanner` | DAST Scanner | Runtime testing with Nuclei + ZAP |
| `/exploit-validator` | Exploit Validator | Prove exploitability of high-risk findings |
| `/code-understanding` | Code Understanding | Map attack surface, trace data flows |
| `/iac-policy` | IaC Policy | Scan IaC with Checkov + OPA |
| `/forensics` | OSS Forensics | Investigate supply chain incidents |
| `/adversary-sim` | Adversary Sim | Controlled red team simulation |

## Natural Language Triggers

You don't need to use slash commands — just describe what you want:

```
"Analyze https://github.com/org/repo for security vulnerabilities"
"Audit the GitHub Actions workflows"
"Look up CVE-2024-1234 and check if it's actively exploited"
"Map the attack surface of ./src"
"Run a Checkov scan on the Terraform files"
"Investigate this npm package for supply chain compromise"
"Generate an executive security report"
```

## The 12 Agents

| # | Agent | Purpose |
|---|-------|---------|
| 1 | Repo Analyzer | End-to-end DevSecOps analysis: STRIDE threat model, SAST/SCA/secrets/IaC scanning, Real Risk Scores, remediation recommendations |
| 2 | CI/CD Auditor | GitHub Actions security: supply chain, expression injection, permissions, dangerous triggers (CVE-2025-30066) |
| 3 | Vuln Enricher | CVE intelligence: CVSS, EPSS exploit probability, CISA KEV, MITRE ATT&CK mapping, composite priority scoring |
| 4 | Doc Intel | Documentation analysis: builds security context profile to validate and adjust scanner findings |
| 5 | Threat Monitor | Continuous monitoring: cross-references CISA KEV + OSV against dependency inventories |
| 6 | Executive Reporter | Board-ready reports: financial risk quantification, compliance mapping (SOC2/ISO27001/NIST), MTTR benchmarking |
| 7 | DAST Scanner | Runtime testing: Nuclei + OWASP ZAP, OWASP Top 10 detection |
| 8 | Exploit Validator | Proves exploitability: 7-stage pipeline with PoC generation for RRS ≥ 7 findings |
| 9 | Code Understanding | Code analysis: attack surface mapping (`--map`), data flow tracing (`--trace`), variant hunting (`--hunt`), framework security (`--teach`) |
| 10 | IaC Policy | Infrastructure compliance: Checkov + OPA, CIS/NIST 800-53/SOC2/HIPAA/PCI-DSS, SBOM generation (Syft) |
| 11 | Forensics | Supply chain forensics: GitHub API + git history + package registry + Wayback Machine evidence collection |
| 12 | Adversary Sim | Red team simulation: controlled exploitation with MITRE ATT&CK mapping (requires signed authorization) |

## Example Workflows

### Full Security Assessment
```
1. /repo-analyzer https://github.com/org/repo
2. /vuln-enricher (enrich the high/critical CVEs from the scan)
3. /exploit-validator (validate findings with RRS >= 7)
4. /executive-reporter (generate board-ready report)
```

### CI/CD Hardening
```
/cicd-auditor
(review findings, apply suggested fixes)
```

### Supply Chain Investigation
```
/forensics https://github.com/org/suspicious-package
```

### IaC Compliance Check
```
/iac-policy (run Checkov + OPA, map to CIS benchmarks)
```

## File Structure

```
claude-code/
├── README.md                     # This file
├── CLAUDE.md                     # Project memory (copy to project root)
└── .claude/
    ├── skills/
    │   ├── repo-analyzer/SKILL.md
    │   ├── cicd-auditor/SKILL.md
    │   ├── vuln-enricher/SKILL.md
    │   ├── doc-intel/SKILL.md
    │   ├── threat-monitor/SKILL.md
    │   ├── executive-reporter/SKILL.md
    │   ├── dast-scanner/SKILL.md
    │   ├── exploit-validator/SKILL.md
    │   ├── code-understanding/SKILL.md
    │   ├── iac-policy/SKILL.md
    │   ├── forensics/SKILL.md
    │   └── adversary-sim/SKILL.md
    └── rules/
        ├── security-scanning.md    # Always-on security scanning rules
        └── devsecops-workflow.md   # Standard DevSecOps workflow conventions
```

## Important Notes

- **DAST and Adversary Sim require authorization.** Always confirm authorization before running active security tests against any system.
- **Secrets handling.** If secrets are found in code, they are treated as compromised and rotation is recommended.
- **NVD rate limits.** Vuln Enricher queries NVD at 5 requests/30s without an API key. Register for a free key at https://nvd.nist.gov/developers for higher limits.
- **Output directory.** All analysis artifacts go to `./grimsec-output/` in your project.
