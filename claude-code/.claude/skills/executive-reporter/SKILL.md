# Executive Reporting Agent

Transforms raw DevSecOps scan data into leadership-ready intelligence. Consumes output from other GRIMSEC agents and produces financial, operational, and compliance analysis for CISOs, CTOs, and board members.

Invoke with `/executive-reporter` or phrases like "generate executive report", "security ROI", "compliance mapping", "board briefing".

## When to Use

- Generate an executive security report or board briefing
- Quantify the financial impact of security findings
- Calculate ROI of the DevSecOps program
- Map findings to compliance frameworks (SOC 2, ISO 27001, NIST CSF, OWASP SAMM)
- Benchmark MTTR against industry standards
- Translate technical findings into business language

## Prerequisites

Reads output from other GRIMSEC agents:
- `./grimsec-output/{repo}/assessment-report.md` and `reachability-analysis.json` (from `/repo-analyzer`)
- `./grimsec-output/{repo}/audit-report.json` (from `/cicd-auditor`)
- `./grimsec-output/{repo}/enriched-cves.json` (from `/vuln-enricher`)
- `./grimsec-output/{repo}/doc-profile.json` (from `/doc-intel`)
- `./grimsec-output/threat-intel/{date}-report.json` (from `/threat-monitor`)

## Pipeline

```
Phase 1: Data Aggregation     — merge all agent outputs
Phase 2: Risk Quantification  — assign dollar values
Phase 3: Operational Metrics  — MTTR, velocity, coverage
Phase 4: Compliance Mapping   — SOC 2, ISO 27001, NIST, OWASP SAMM
Phase 5: Trend Analysis       — compare against baselines
Phase 6: Report Generation    — executive brief + dashboard JSON
Phase 7: Recommendations      — prioritized next steps
```

## Phase 2: Risk Quantification

**Shift-Left Savings:**
```
savings_per_critical = cost_fix_production - cost_fix_development
total_savings = criticals_caught_early × savings_per_critical
```

Industry benchmarks:
- Fix in requirements: $100 (1x) — IBM Systems Sciences Institute
- Fix in development: $1,000–$1,500 (10-15x) — NIST, Synopsys
- Fix in production: $10,000–$50,000 (100-640x) — IBM/Ponemon
- Average data breach cost: $4.88M (2024) — IBM Cost of a Data Breach Report

**Engineering Efficiency:**
```
triage_hours_saved = false_positives_eliminated × avg_minutes_per_triage / 60
annual_salary_equivalent = triage_hours_saved × 52 × hourly_rate
```

## Phase 3: Operational Metrics

**MTTR benchmarks:**
- Elite: < 1 day for critical findings
- Strong: 1-7 days for critical
- Average: 30-60 days
- Poor: 60+ days

**Noise Reduction Rate:**
```
noise_rate = (raw_findings - actionable_findings) / raw_findings × 100
```

## Phase 4: Compliance Mapping

**SOC 2 Type II:**
| Control | GRIMSEC Coverage |
|---------|----------------|
| CC6.1 — Logical Access | Auth bypass detection, RBAC analysis |
| CC7.1 — System Monitoring | Continuous scanning, threat intel monitoring |
| CC7.2 — Anomaly Detection | Reachability analysis, noise reduction |
| CC8.1 — Change Management | CI/CD audit, PR-based remediation |

**ISO 27001:2022:**
| Control | GRIMSEC Coverage |
|---------|----------------|
| A.8.8 — Technical Vulnerability Management | SCA scanning, CVE enrichment |
| A.8.9 — Configuration Management | IaC scanning, Terraform audit |
| A.8.25 — Secure Development Lifecycle | CI/CD audit, action pinning |
| A.8.28 — Secure Coding | SAST scanning, code path analysis |

**NIST CSF 2.0:**
| Function | GRIMSEC Coverage |
|----------|----------------|
| ID.RA — Risk Assessment | STRIDE threat modeling, reachability scoring |
| PR.DS — Data Security | Secrets scanning, encryption analysis |
| DE.CM — Continuous Monitoring | Scheduled scans, threat intel feeds |
| RS.MI — Mitigation | Automated PR generation, remediation roadmap |

## Phase 7: Recommendations Engine

**Priority 1 — Immediate (24h):** Unpatched CRITICAL findings with Real Risk ≥ 8, exposed secrets, production IaC misconfigurations.

**Priority 2 — This Sprint:** HIGH findings with available fixes, CI/CD expression injections, unpinned third-party actions.

**Priority 3 — Next Sprint:** Coverage gaps, compliance gaps, missing SECURITY.md.

**Priority 4 — Backlog:** MEDIUM findings with no exploit path, best practice improvements.

## Output Files

```
grimsec-output/executive/
├── aggregated.json          # Unified dataset from all agents
├── executive-report.json    # Structured report data
├── executive-brief.md       # Readable markdown report
├── dashboard-data.json      # Dashboard-ready JSON
└── recommendations.json     # Prioritized actions
```

## executive-brief.md Structure

1. Executive Summary (1 paragraph, 3 key numbers)
2. Risk Posture (before/after with percentages)
3. Financial Impact (shift-left savings, breach risk reduction)
4. Operational Excellence (MTTR, coverage, velocity)
5. Supply Chain Hardening (pin rates, injection fixes)
6. Compliance Status (framework alignment table)
7. Recommendations (prioritized next steps)

## Important Notes

- **Never fabricate numbers.** All financial estimates must cite benchmark sources (IBM, Ponemon, NIST, Synopsys).
- **Conservative estimates.** When uncertain, round down.
- **Plain language.** Define acronyms on first use.
- **Audit trail.** Reference specific CVEs, PR numbers, and scan dates.
