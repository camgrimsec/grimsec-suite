# Real Risk Scoring Methodology

## Purpose

Raw CVSS scores tell you how dangerous a vulnerability *could* be in the worst case. The Real Risk Score tells you how dangerous it *actually is* in this specific application. This is the core value proposition of the analysis pipeline.

## Scoring Dimensions

The Real Risk Score (1-10) is calculated from four dimensions, each scored 1-10:

### 1. Reachability (Weight: 35%)
**Question:** Is the vulnerable code actually executed in this application?

| Score | Criteria |
|-------|----------|
| 10 | Vulnerable function is directly called from an external-facing endpoint |
| 8-9 | Vulnerable function is called indirectly (2-3 steps from external input) |
| 6-7 | Vulnerable code is in an imported module that IS used, but the specific vulnerable function's usage is unclear |
| 4-5 | Vulnerable code is in an imported module, but the specific function appears unused |
| 2-3 | Module is imported but the vulnerable code path requires explicit opt-in that isn't present |
| 1 | Vulnerable code is in a transitive dependency and is confirmed dead code |

**How to assess:**
- `grep -r` for imports of the vulnerable package/module
- Trace call chains from the import to the vulnerable function
- Check if the vulnerable function signature matches actual usage
- For dependency vulns: check if the exact vulnerable version range applies

### 2. Exploitability (Weight: 30%)
**Question:** How hard is it to actually exploit this in a real attack?

| Score | Criteria |
|-------|----------|
| 10 | Exploitable via simple HTTP request, no authentication, public PoC exists |
| 8-9 | Exploitable via authenticated request with standard user credentials |
| 6-7 | Requires specific conditions (certain content type, specific header, race condition) |
| 4-5 | Requires chaining with another vulnerability or specific server configuration |
| 2-3 | Requires local access, admin credentials, or highly unusual conditions |
| 1 | Theoretical only — requires conditions that don't exist in this deployment |

**How to assess:**
- Search for public exploit code / PoC for the CVE
- Check EPSS score (Exploit Prediction Scoring System) if available
- Check CISA KEV (Known Exploited Vulnerabilities) catalog
- Evaluate authentication requirements against the app's auth model
- Assess input validation between entry point and vulnerable code

### 3. Impact (Weight: 25%)
**Question:** What's the damage if this is exploited?

| Score | Criteria |
|-------|----------|
| 10 | Remote Code Execution (RCE) or full database compromise |
| 8-9 | Access to all user data (PII, credentials) or admin takeover |
| 6-7 | Access to limited sensitive data or ability to modify data |
| 4-5 | Information disclosure of non-sensitive data or limited DoS |
| 2-3 | Minor information leak or cosmetic defacement |
| 1 | No meaningful impact in this application context |

**How to assess:**
- What data is accessible from the vulnerable code path?
- Cross-reference with the high-value assets from the threat model
- What permissions does the vulnerable component run with?
- Is lateral movement possible from this component?

### 4. Exposure (Weight: 10%)
**Question:** How exposed is the vulnerable component?

| Score | Criteria |
|-------|----------|
| 10 | Internet-facing, no WAF, no rate limiting |
| 8-9 | Internet-facing with basic protections |
| 6-7 | Behind authentication but accessible to all users |
| 4-5 | Behind authentication and restricted to specific roles |
| 2-3 | Internal-only service, not directly accessible from outside |
| 1 | Development/test code only, not deployed |

## Calculating the Real Risk Score

```
Real Risk Score = (Reachability × 0.35) + (Exploitability × 0.30) + (Impact × 0.25) + (Exposure × 0.10)
```

Round to nearest integer (1-10).

## Action Thresholds

| Score | Classification | Action |
|-------|---------------|--------|
| 9-10 | Critical Risk | Immediate remediation required. Include in PR. |
| 7-8 | High Risk | Remediation recommended. Include in PR. |
| 5-6 | Medium Risk | Track for next update cycle. Include in report only. |
| 3-4 | Low Risk | Acknowledge in report. No action needed. |
| 1-2 | Noise | Exclude from report. Count for noise reduction metrics only. |

## Documentation Requirements

For each scored finding, document:

1. **Finding ID** — Sequential identifier (VULN-001, VULN-002, etc.)
2. **Source** — Which scanner produced this finding
3. **CVE/Rule ID** — CVE number or Semgrep rule ID
4. **Original Severity** — What the scanner reported
5. **Dimension Scores** — Individual scores for Reachability, Exploitability, Impact, Exposure
6. **Real Risk Score** — Calculated composite score
7. **Reachability Evidence** — Specific grep results, call chains, or code references that support the reachability assessment
8. **Context Summary** — 2-3 sentences explaining why this score was assigned, written for someone unfamiliar with the codebase
9. **Exploitation Scenario** — If reachable: step-by-step description of how an attacker would exploit this. If not reachable: "N/A — [reason]"
10. **Recommended Action** — Specific fix recommendation with urgency level

## Noise Reduction Metrics

After scoring all findings, calculate:

- **Total raw High+Critical findings** (from scanners)
- **Findings with Real Risk Score ≥ 7** (actually actionable)
- **Noise reduction rate**: `(1 - actionable / total_raw) × 100`

This is the headline metric for the lab and LinkedIn content:
> "We analyzed {repo}. The scanner found {total_raw} High/Critical vulnerabilities. After contextual analysis, only {actionable} required attention. {noise_pct}% was noise."
