---
name: executive-reporting-agent
description: Generates executive-level security posture reports for CISOs, CTOs, and board members. Translates raw DevSecOps findings into business impact metrics including financial risk quantification, compliance alignment, MTTR benchmarking, supply chain exposure, and engineering velocity impact. Use when asked to create executive reports, board presentations, security ROI analysis, risk quantification, compliance mapping, or leadership briefings from security scan data. Chains with devsecops-repo-analyzer, cicd-pipeline-auditor, and vulnerability-context-enricher outputs.
metadata:
  author: grimsec-suite
  version: "1.0"
  suite: GRIMSEC
---

# Executive Reporting Agent

Transforms raw DevSecOps scan data into leadership-ready intelligence. This agent does not scan code — it consumes output from the other GRIMSEC agents and produces financial, operational, and compliance analysis that CISOs, CTOs, and board members actually care about.

## When to Use This Skill

Use when the user asks to:

- Generate an executive security report or board briefing
- Quantify the financial impact of security findings
- Calculate ROI of the DevSecOps program
- Map findings to compliance frameworks (SOC 2, ISO 27001, NIST CSF, OWASP SAMM)
- Benchmark MTTR against industry standards
- Assess supply chain risk exposure
- Measure engineering velocity impact of security tooling
- Create a security posture dashboard for leadership
- Translate technical findings into business language
- Prepare for a security audit or due diligence review

## Prerequisites

No scanning tools needed. This agent reads output files from other GRIMSEC agents:

- `devsecops-repo-analyzer` → `assessment-report.md`, `reachability-analysis.json`, `inventory.json`
- `cicd-pipeline-auditor` → `audit-report.json`, `audit-summary.md`
- `vulnerability-context-enricher` → `enriched-cves.json`
- `doc-intelligence-agent` → `doc-profile.json`
- `threat-intel-monitor` → `{date}-report.json`

The analysis script uses only Python standard library (no pip installs required).

## Pipeline Overview

```
Input: GRIMSEC agent outputs (JSON/MD from previous scans)
  │
  ├─► Phase 1: Data Aggregation — Merge all agent outputs into unified dataset
  ├─► Phase 2: Risk Quantification — Assign dollar values to risk categories
  ├─► Phase 3: Operational Metrics — Calculate MTTR, velocity, efficiency
  ├─► Phase 4: Compliance Mapping — Map findings to framework controls
  ├─► Phase 5: Trend Analysis — Compare against baselines and benchmarks
  └─► Phase 6: Report Generation — Executive brief, board deck data, dashboard JSON
  │
  ▼
Output: executive-report.json + executive-brief.md + dashboard-data.json
```

## Instructions

### Phase 1: Data Aggregation

Scan the workspace for all GRIMSEC agent outputs:

```bash
python3 /home/user/workspace/skills/executive-reporting-agent/scripts/aggregate-data.py \
  --input-dir /home/user/workspace/devsecops-analysis/ \
  --output /home/user/workspace/devsecops-analysis/executive/aggregated.json
```

If the script doesn't exist or you're running manually, gather data from:

1. **Per-repo scan results**: Look for `devsecops-analysis/{repo-name}/` directories
2. **Reachability analyses**: `reachability-analysis.json` in each repo dir
3. **CI/CD audits**: `audit-report.json` files
4. **Enriched CVEs**: `enriched-cves.json` files
5. **Doc profiles**: `doc-profile.json` files

Compile a unified dataset with:
- Total findings by severity (CRITICAL, HIGH, MEDIUM, LOW) per repo
- Actionable vs noise counts per repo
- CI/CD findings by category per repo
- IaC findings per repo
- Secrets scan results per repo
- Dependency inventories per repo

### Phase 2: Risk Quantification

Apply financial models to translate findings into dollar impact. Read `references/risk-quantification.md` for the full methodology.

**Core formulas:**

**Shift-Left Savings:**
```
savings_per_critical = cost_fix_production - cost_fix_development
total_savings = criticals_caught_early × savings_per_critical
```

Industry benchmarks (cite sources):
- Fix in requirements: $100 (1x) — IBM Systems Sciences Institute
- Fix in development: $1,000–$1,500 (10-15x) — NIST, Synopsys
- Fix in production: $10,000–$50,000 (100-640x) — IBM/Ponemon, Security Compass
- Average data breach cost: $4.88M (2024) — IBM Cost of a Data Breach Report

**Annualized Risk Reduction:**
```
breach_probability_reduction = actionable_criticals_fixed / total_criticals_identified
annualized_savings = avg_breach_cost × breach_probability_reduction
```

**Engineering Efficiency:**
```
triage_hours_saved = false_positives_eliminated × avg_minutes_per_triage / 60
weekly_savings = triage_hours_saved (assuming weekly scan cadence)
annual_salary_equivalent = weekly_savings × 52 × hourly_rate
```

### Phase 3: Operational Metrics

Calculate key performance indicators that leadership tracks:

**MTTR (Mean Time to Remediate):**
```
mttr = sum(time_from_detection_to_fix) / number_of_fixes
```
- Track per-repo and per-severity
- Compare against industry benchmarks: Read `references/industry-benchmarks.md`
  - Elite: < 1 day for critical
  - Strong: 1-7 days for critical
  - Average: 30-60 days
  - Poor: 60+ days

**Noise Reduction Rate:**
```
noise_rate = (raw_findings - actionable_findings) / raw_findings × 100
```

**Coverage Metrics:**
- Repos with active scanning / total repos
- Dependencies monitored / total dependencies
- CI/CD workflows audited / total workflows
- Percentage of findings with remediation PRs

**Supply Chain Metrics:**
- Action pin rate before/after
- Expression injection count before/after
- Dangerous trigger count before/after

### Phase 4: Compliance Mapping

Map findings and remediations to compliance framework controls. Read `references/compliance-mapping.md` for the full control-to-finding mapping.

**SOC 2 Type II:**
| Control | What GRIMSEC Covers |
|---------|-------------------|
| CC6.1 — Logical Access | Auth bypass detection (CASL CVE), RBAC analysis |
| CC7.1 — System Monitoring | Continuous scanning, threat intel monitoring |
| CC7.2 — Anomaly Detection | Reachability analysis, noise reduction |
| CC8.1 — Change Management | CI/CD audit, PR-based remediation |

**ISO 27001:2022:**
| Control | What GRIMSEC Covers |
|---------|-------------------|
| A.8.8 — Technical Vulnerability Management | SCA scanning, CVE enrichment, reachability |
| A.8.9 — Configuration Management | IaC scanning, Terraform audit |
| A.8.25 — Secure Development Lifecycle | CI/CD audit, action pinning, permissions |
| A.8.28 — Secure Coding | SAST scanning, code path analysis |

**NIST CSF 2.0:**
| Function | What GRIMSEC Covers |
|----------|-------------------|
| ID.RA — Risk Assessment | STRIDE threat modeling, reachability scoring |
| PR.DS — Data Security | Secrets scanning, encryption analysis |
| PR.PS — Platform Security | IaC scanning, container security |
| DE.CM — Continuous Monitoring | Scheduled scans, threat intel feeds |
| RS.MI — Mitigation | Automated PR generation, remediation roadmap |

**OWASP SAMM:**
| Practice | Level | What GRIMSEC Covers |
|----------|-------|-------------------|
| Threat Assessment | L2 | STRIDE threat modeling per repo |
| Security Testing | L2 | Multi-scanner pipeline (SCA+SAST+secrets+IaC) |
| Defect Management | L2 | Finding triage, noise reduction, PR tracking |
| Secure Build | L1-L2 | CI/CD audit, supply chain hardening |

For each framework, determine:
- **Aligned**: GRIMSEC actively addresses this control
- **Partial**: Some coverage but gaps exist
- **Gap**: Not currently addressed

### Phase 5: Trend Analysis

If historical data exists (previous scan runs), calculate:

- Finding count trend (is risk going up or down?)
- MTTR trend (are we getting faster?)
- Noise rate trend (is signal quality improving?)
- Coverage expansion (new repos, new scan types)
- Remediation velocity (PRs per week)

If no historical data, establish the current state as the baseline and note it.

### Phase 6: Report Generation

Produce three output files:

**1. executive-report.json** — Structured data for dashboards:
```json
{
  "generated_at": "ISO timestamp",
  "period": "date range",
  "summary": {
    "repos_analyzed": 3,
    "total_findings_raw": 442,
    "total_findings_actionable": 13,
    "noise_reduction_pct": 97.1,
    "prs_delivered": 7,
    "prs_merged": 1,
    "mttr_hours": 4.2,
    "mttr_industry_days": 60
  },
  "financial_impact": { ... },
  "risk_by_category": [ ... ],
  "mttr_by_repo": [ ... ],
  "supply_chain": { ... },
  "compliance": [ ... ],
  "engineering_velocity": { ... },
  "timeline": [ ... ],
  "recommendations": [ ... ]
}
```

**2. executive-brief.md** — Markdown report for sharing:
- Executive Summary (1 paragraph, 3 key numbers)
- Risk Posture (before/after with percentages)
- Financial Impact (shift-left savings, breach risk reduction)
- Operational Excellence (MTTR, coverage, velocity)
- Supply Chain Hardening (pin rates, injection fixes)
- Compliance Status (framework alignment table)
- Recommendations (prioritized next steps)

**3. dashboard-data.json** — Pre-computed data for the Mission Control Executive Brief page

### Phase 7: Recommendations Engine

Based on the analysis, generate prioritized recommendations:

**Priority 1 — Immediate (24h):**
- Any unpatched CRITICAL findings with Real Risk ≥ 8
- Exposed secrets (real, not test)
- Production IaC misconfigurations (HTTP-only, public APIs)

**Priority 2 — This Sprint:**
- HIGH findings with available fixes
- CI/CD expression injections
- Unpinned third-party actions on critical repos

**Priority 3 — Next Sprint:**
- Coverage gaps (repos without scanning)
- Compliance gaps (framework controls not addressed)
- Documentation gaps (missing SECURITY.md, audit logging)

**Priority 4 — Backlog:**
- MEDIUM findings with no exploit path
- Best practice improvements
- Process maturity investments

Each recommendation includes:
- What: Specific action
- Why: Business impact in plain language
- Effort: Estimated hours/days
- Impact: Risk reduction or compliance benefit

## Output Files

```
devsecops-analysis/executive/
├── aggregated.json          # Phase 1: Unified dataset
├── executive-report.json    # Phase 6: Structured report data
├── executive-brief.md       # Phase 6: Readable report
├── dashboard-data.json      # Phase 6: Dashboard-ready JSON
└── recommendations.json     # Phase 7: Prioritized actions
```

## Integration with GRIMSEC Suite

```
devsecops-repo-analyzer ──┐
cicd-pipeline-auditor ────┤
vuln-context-enricher ────┼──► executive-reporting-agent ──► Reports
doc-intelligence-agent ───┤                                  Dashboard
threat-intel-monitor ─────┘                                  Board Deck
```

This agent is the final stage of the GRIMSEC pipeline — it consumes all other agents' output and produces leadership-ready intelligence.

## Important Notes

- **Never fabricate numbers.** All financial estimates must be clearly labeled as estimates and cite their benchmark sources (IBM, Ponemon, NIST, Synopsys).
- **Conservative estimates.** When uncertain, round down. A CISO who discovers inflated numbers loses trust in the entire program.
- **Plain language.** No jargon without explanation. "MTTR" should be followed by "(time from finding a vulnerability to fixing it)" on first use.
- **Actionable recommendations.** Every section should end with "what to do next" — leadership hates reports that identify problems without solutions.
- **Audit trail.** Reference specific CVEs, PR numbers, and scan dates. Leadership needs to trust that the data is real and verifiable.
