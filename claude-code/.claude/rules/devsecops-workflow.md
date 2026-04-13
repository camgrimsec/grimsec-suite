# DevSecOps Workflow Rules

Standard workflow conventions for DevSecOps analysis with the GRIMSEC suite.

## Output Directory Convention

All analysis artifacts go to `./grimsec-output/` relative to the project root:

```
grimsec-output/
├── {repo-name}/             # Per-repo analysis
├── threat-intel/            # Threat monitoring reports
├── executive/               # Executive reports
├── exploit-validation/      # PoC files and validation reports
├── code-understanding/      # Attack surface maps, flow traces
├── iac-policy/              # Checkov, OPA, SBOM, compliance map
├── forensics/               # Evidence, IOCs, timeline, report
└── adversary-simulation/    # RoE, recon, exploitation log, report
```

## Standard Pipeline Order

For a complete security assessment, run agents in this order:

1. `/repo-analyzer` — builds `inventory.json`, `app-context.json`, `reachability-analysis.json`
2. `/cicd-auditor` — audits `.github/workflows/`
3. `/doc-intel` — builds `doc-profile.json` (enriches finding context)
4. `/vuln-enricher` — enriches CVEs from scan results with EPSS/KEV/ATT&CK
5. `/exploit-validator` — validates findings with RRS ≥ 7
6. `/iac-policy` — scans Terraform, K8s, Docker, GitHub Actions
7. `/dast-scanner` — runtime testing (if running application available)
8. `/executive-reporter` — consumes all outputs, produces board-ready report

## Agent Chaining

Agents produce structured JSON that downstream agents read:

```
inventory.json ──► threat-monitor (exposure detection)
app-context.json ──► exploit-validator (data flow context)
reachability-analysis.json ──► exploit-validator (findings to validate)
validation-report.json ──► adversary-sim (EXPLOITABLE findings)
all outputs ──► executive-reporter (aggregation)
```

## Security Posture Rating

After a full scan, rate the overall security posture:

| Rating | Criteria |
|--------|---------|
| CRITICAL | Any unmitigated Real Risk Score 9-10 findings |
| HIGH | Unmitigated RRS 7-8 findings OR exposed secrets |
| MEDIUM | Unmitigated RRS 5-6 findings OR significant IaC misconfigs |
| LOW | Only noise-level findings (RRS ≤ 4) |
| GOOD | Clean scan or all findings have mitigating controls |

## Authorization Requirements

Before running active security tests:
- **DAST (/dast-scanner)**: Confirm user has authorization for the target
- **Adversary Sim (/adversary-sim)**: Require signed Rules of Engagement
- **Exploit Validation (/exploit-validator)**: Confirm local/isolated analysis only

Never run active scans against production systems without explicit authorization.
