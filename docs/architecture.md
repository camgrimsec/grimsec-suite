# GRIMSEC — Architecture

This document describes how the 12 agents chain together, what data each produces, and how downstream agents consume it.

---

## Pipeline Overview

GRIMSEC operates as a sequential pipeline where each agent consumes the output of previous agents, progressively building a complete security picture.

```
INPUT
  │
  ▼  github.com/org/repo
┌─────────────────────────────────────────────────────────────────────────┐
│                         FOUNDATION LAYER                                │
│                                                                         │
│  Agent 01: Repo Analyzer ──────────────────────────────────────────── │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Stage 1: Inventory        → inventory.json                      │   │
│  │ Stage 2: STRIDE           → stride-threats.json                 │   │
│  │ Stage 3: Scan             → scan-results/ (trivy/semgrep/etc.)  │   │
│  │ Stage 4: Reachability     → reachability-analysis.json          │   │
│  │ Stage 5: Remediation      → draft PRs, fix recommendations      │   │
│  │ Stage 6: Report           → findings.json (canonical format)    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                │                                                        │
│                ▼                                                        │
│  Agent 02: CI/CD Auditor ──────────────────────────────────────────── │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  .github/workflows/*.yml (from repo clone)               │   │
│  │ Output: cicd-findings.json                                      │   │
│  │         Categories: unpinned_action, expression_injection,      │   │
│  │         overpermissive_permissions, dangerous_trigger,          │   │
│  │         secrets_exposure, self_hosted_runner                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ENRICHMENT LAYER                                │
│                                                                         │
│  Agent 03: Vulnerability Enricher                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  scan-results/*.json (CVE IDs from Agent 01)             │   │
│  │ Fetch:  NVD → CVSS v3.1 + vector                                │   │
│  │         EPSS → probability of exploitation (0-100%)             │   │
│  │         CISA KEV → is it actively exploited in the wild?        │   │
│  │         MITRE ATT&CK → technique mapping                        │   │
│  │ Output: enriched-findings.json                                  │   │
│  │         Each CVE tagged: Real Risk Score, priority              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Agent 04: Doc Intelligence                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  inventory.json (known tech stack) + scan-results/       │   │
│  │ Reads:  README, SECURITY.md, docs/, architecture docs           │   │
│  │         Dockerfiles, k8s manifests, config files                │   │
│  │ Output: doc-context.json                                        │   │
│  │         Validates/downgrades findings that are mitigated        │   │
│  │         by documented controls                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Agent 05: Threat Intel Monitor                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  inventory.json (package versions)                        │   │
│  │ Checks: NVD for new CVEs (last 48h)                             │   │
│  │         CISA KEV for newly added exploited vulnerabilities       │   │
│  │         GitHub Security Advisories                              │   │
│  │ Output: threat-intel-report.json                                │   │
│  │         Alert: new CVEs affecting your stack                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        REPORTING LAYER                                  │
│                                                                         │
│  Agent 06: Executive Reporter                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  findings.json + enriched-findings.json + cicd-findings  │   │
│  │         + doc-context.json + threat-intel-report.json           │   │
│  │ Output: executive-summary.json                                  │   │
│  │         • Risk quantification in $$ (ALE model)                 │   │
│  │         • SOC 2 / ISO 27001 / NIST CSF / OWASP SAMM mapping    │   │
│  │         • Prioritized remediation roadmap                       │   │
│  │         • Board-ready 2-page executive summary                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
  │
  ▼ (--deep mode only)
┌─────────────────────────────────────────────────────────────────────────┐
│                       VALIDATION LAYER                                  │
│                                                                         │
│  Agent 07: DAST Scanner                                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  Target URL (running application)                        │   │
│  │ Runs:   Nuclei (community + custom templates)                   │   │
│  │         httpx (service fingerprinting)                          │   │
│  │         OWASP ZAP (active scan, if configured)                  │   │
│  │ Output: dast-results/                                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Agent 08: Exploit Validator                                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  scan-results/ + dast-results/ + enriched-findings.json  │   │
│  │ Output: exploit-validation.json                                 │   │
│  │         Each finding: EXPLOITABLE / NOT_EXPLOITABLE / NEEDS_ACCESS │
│  │         PoC code (safe, non-destructive)                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Agent 09: Code Understanding                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  Repository source code + inventory.json                 │   │
│  │ Output: attack-surface-map.json                                 │   │
│  │         • All entry points (HTTP endpoints, CLI args, env vars) │   │
│  │         • Source-to-sink data flow traces                       │   │
│  │         • Dangerous sink inventory                              │   │
│  │         • Variant analysis results                              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Agent 10: IaC Policy                                                   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  Repository (Dockerfiles, k8s/, terraform/, workflows/)  │   │
│  │ Runs:   Checkov (SAST for IaC)                                  │   │
│  │         OPA with custom .rego policies                          │   │
│  │         Conftest for structured config                          │   │
│  │         Syft for SBOM                                           │   │
│  │ Output: iac-findings.json                                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Agent 11: OSS Forensics                                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  Package URL / GitHub repo                               │   │
│  │ Checks: Commit history anomalies                                │   │
│  │         Maintainer account signals                              │   │
│  │         Build script changes                                    │   │
│  │         IOC pattern matching                                    │   │
│  │ Output: forensics-report.json + evidence-package/              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Agent 12: Adversary Simulation  [AUTHORIZED USE ONLY]                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Input:  Target + exploit-validation.json + attack-surface-map   │   │
│  │ Output: simulation-report.json                                  │   │
│  │         • Kill chain documentation                              │   │
│  │         • ATT&CK technique mapping                              │   │
│  │         • Remediation recommendations                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Between Agents

### Key Artifact: `inventory.json`

Produced by Agent 01, consumed by Agents 03, 04, 05, 09, 10.

```json
{
  "repo": "org/repo",
  "languages": ["Python", "TypeScript"],
  "frameworks": ["FastAPI", "React"],
  "dependencies": [
    { "name": "fastapi", "version": "0.100.0", "type": "pip" }
  ],
  "entry_points": ["/api/users", "/api/auth"],
  "has_dockerfile": true,
  "has_k8s": false,
  "has_terraform": false,
  "has_github_actions": true
}
```

### Key Artifact: `findings.json` (canonical format)

Produced by Agent 01 Stage 6, enriched by Agents 03/04/08.

```json
{
  "finding_id": "GSEC-001",
  "type": "sca_cve",
  "cve_id": "CVE-XXXX-XXXXX",
  "severity": "CRITICAL",
  "real_risk_score": 9.1,
  "reachability": "REACHABLE",
  "epss_score": 0.72,
  "in_cisa_kev": true,
  "exploit_status": "EXPLOITABLE",
  "fix_available": true,
  "fix_pr_ready": true
}
```

---

## Real Risk Score Formula

Each finding gets a Real Risk Score (0-10) computed as:

```
Real Risk Score = (CVSS_Base × 0.3)
               + (EPSS_Score × 0.25)
               + (KEV_Bonus × 2.0)
               + (Reachability_Multiplier × 0.25)
               + (Context_Modifier × 0.2)

Where:
  KEV_Bonus             = 1 if in CISA KEV, else 0
  Reachability_Multiplier = 1.0 (REACHABLE) | 0.5 (UNKNOWN) | 0.1 (UNREACHABLE)
  Context_Modifier      = adjustment from Agent 04 doc intelligence
```

This scoring is what drives the 89-96% noise reduction — most scanner findings are UNREACHABLE or have a near-zero EPSS score.

---

## Modes

| Mode | Agents | Use Case |
|------|--------|----------|
| `--quick` | 1, 2, 3 | Fast initial triage (~10 minutes) |
| Standard | 1-6 | Full analysis with exec report (~30-60 min) |
| `--deep` | 1-12 | Complete assessment including active testing (~2-4 hrs) |

> **Note:** `--deep` mode runs active DAST (Agent 07) and adversary simulation (Agent 12). Only use against systems you own or have explicit written permission to test.
