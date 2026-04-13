# Sample Output Structure

This directory shows what a GRIMSEC analysis output looks like after a full pipeline run.

**No actual scan data is stored here.** This is the schema reference only.

---

## Output Directory Layout

After running `python grimsec.py analyze https://github.com/org/repo`, the output is structured as:

```
grimsec-output/
└── example-repo/
    └── 2026-01-01T12-00-00/
        │
        ├── inventory.json                    ← Agent 01, Stage 1
        ├── app-context.json                  ← Agent 01, Stage 2 (STRIDE input)
        ├── stride-threats.json               ← Agent 01, Stage 2
        │
        ├── scan-results/                     ← Agent 01, Stage 3
        │   ├── trivy-sca.json                  Trivy SCA findings
        │   ├── trivy-container.json            Trivy container scan (if Docker)
        │   ├── trivy-iac.json                  Trivy IaC scan
        │   ├── trivy-secrets.json              Trivy secrets scan
        │   ├── semgrep-sast.json               Semgrep SAST findings
        │   ├── gitleaks-secrets.json           Gitleaks git history secrets
        │   ├── grype-sca.json                  Grype SCA findings
        │   └── snyk-sca.json                   Snyk findings (if installed)
        │
        ├── reachability-analysis.json        ← Agent 01, Stage 4
        ├── remediation-plan.json             ← Agent 01, Stage 5
        ├── findings.json                     ← Agent 01, Stage 6 (canonical)
        │
        ├── cicd-findings.json                ← Agent 02
        │
        ├── enriched-findings.json            ← Agent 03
        │   (same findings.json schema, augmented with:
        │    - cvss_vector, epss_score, in_cisa_kev, attack_technique)
        │
        ├── doc-context.json                  ← Agent 04
        │
        ├── threat-intel-report.json          ← Agent 05
        │
        ├── executive-summary/                ← Agent 06
        │   ├── executive-summary.json          Machine-readable report
        │   ├── executive-summary.md            Markdown version
        │   ├── board-deck.md                   2-page board presentation
        │   └── compliance-report.json          SOC2/ISO27001/NIST/OWASP mapping
        │
        ├── dast-results/                     ← Agent 07 (deep mode)
        │   ├── nuclei-results.json
        │   ├── httpx-output.json
        │   └── zap-report.json
        │
        ├── exploit-validation.json           ← Agent 08 (deep mode)
        │
        ├── attack-surface-map.json           ← Agent 09 (deep mode)
        ├── context-map.json                  ← Agent 09 (deep mode)
        │
        ├── iac-findings.json                 ← Agent 10 (deep mode)
        │   └── (also: checkov-output.json, opa-results.json)
        │
        ├── forensics-report.json             ← Agent 11 (deep mode)
        ├── evidence-package/                 ← Agent 11 (deep mode)
        │   ├── commit-log.json
        │   ├── ioc-list.json
        │   └── timeline.json
        │
        └── simulation-report.json            ← Agent 12 (deep mode)
```

---

## Key File Schemas

### `inventory.json`

```json
{
  "repo": "org/example-repo",
  "scan_timestamp": "2026-01-01T12:00:00Z",
  "languages": ["Python", "TypeScript"],
  "frameworks": ["FastAPI", "React"],
  "deployment": "docker-compose",
  "dependencies": [
    {
      "name": "example-package",
      "version": "1.0.0",
      "type": "pip",
      "direct": true
    }
  ],
  "entry_points": [
    {
      "path": "/api/users",
      "method": "POST",
      "input_type": "JSON body",
      "auth_required": true
    }
  ],
  "has_dockerfile": true,
  "has_k8s": false,
  "has_terraform": false,
  "has_github_actions": true,
  "secrets_in_env": ["DATABASE_URL", "API_KEY"]
}
```

### `findings.json` (canonical format)

```json
{
  "summary": {
    "total_raw_findings": 483,
    "after_dedup": 124,
    "after_reachability": 31,
    "critical_exploitable": 3,
    "noise_reduction_pct": 93.6
  },
  "findings": [
    {
      "finding_id": "GSEC-001",
      "type": "sca_cve",
      "cve_id": "CVE-XXXX-XXXXX",
      "package": "example-package",
      "installed_version": "1.0.0",
      "fixed_version": "1.0.1",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "real_risk_score": 8.7,
      "reachability": "REACHABLE",
      "epss_score": 0.72,
      "in_cisa_kev": true,
      "exploit_status": "EXPLOITABLE",
      "fix_available": true,
      "fix_pr_ready": true,
      "affected_file": "requirements.txt",
      "remediation": "Upgrade to 1.0.1: pip install example-package==1.0.1"
    }
  ]
}
```

### `executive-summary.json`

```json
{
  "repo": "org/example-repo",
  "scan_date": "2026-01-01",
  "risk_level": "HIGH",
  "risk_score": 7.8,
  "financial_exposure": {
    "low_estimate": 120000,
    "high_estimate": 850000,
    "currency": "USD"
  },
  "critical_findings": 3,
  "high_findings": 8,
  "medium_findings": 12,
  "noise_reduction": "93.6%",
  "compliance_gaps": {
    "soc2": ["CC6.1", "CC6.7"],
    "iso27001": ["A.12.6.1"],
    "nist_csf": ["ID.RA-1"]
  },
  "top_3_priorities": [
    "Upgrade example-package to 1.0.1 (CVE-XXXX-XXXXX, CISA KEV, EXPLOITABLE)",
    "Pin all GitHub Actions to commit SHAs (supply chain risk)",
    "Rotate potentially leaked credentials found in git history"
  ],
  "remediation_roadmap": [
    {
      "priority": 1,
      "action": "Dependency upgrade",
      "effort": "2 hours",
      "risk_reduction": "HIGH"
    }
  ]
}
```

---

## Reading Results

After a run, the fastest way to understand what matters:

```bash
# See the executive summary
cat grimsec-output/example-repo/2026-01-01T12-00-00/executive-summary/executive-summary.md

# See critical findings only
python3 -c "
import json
with open('grimsec-output/example-repo/2026-01-01T12-00-00/findings.json') as f:
    data = json.load(f)
critical = [f for f in data['findings'] if f['severity'] == 'CRITICAL']
for finding in critical:
    print(f\"{finding['finding_id']}: {finding.get('cve_id', finding['type'])} — {finding['real_risk_score']:.1f} Real Risk\")
"
```
