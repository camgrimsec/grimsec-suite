# Security Assessment Report Template

Use this structure when generating the final assessment report in Stage 6.

---

## Report Structure

```markdown
# Security Assessment Report: {Repository Name}

**Repository:** {owner/repo}
**Branch:** {branch} @ {commit_hash}
**Assessment Date:** {YYYY-MM-DD}
**Scan Depth:** {quick | standard | deep}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Application Type** | {Web App / API / CLI / Library / Integration / Infrastructure} |
| **Primary Languages** | {Language 1, Language 2} |
| **Total Raw Findings** | {N} |
| **High/Critical (Raw)** | {N} |
| **Actionable (Real Risk ≥ 7)** | {N} |
| **Noise Reduction** | {X}% |
| **Overall Risk Posture** | {Critical / High / Moderate / Low / Minimal} |

### Key Takeaway

{2-3 sentences summarizing the most important finding. If the noise reduction is
significant, lead with that. Example: "Of 127 scanner findings flagged as Critical
or High, only 4 represent actual exploitable risk in this application's context.
The remaining 97% are unreachable code paths in transitive dependencies."}

---

## Application Profile

### Overview
{Paragraph from Stage 2 app context describing what the application does}

### Technology Stack
| Layer | Technologies |
|-------|-------------|
| Languages | {list} |
| Frameworks | {list} |
| Databases | {list} |
| Infrastructure | {list} |
| CI/CD | {list} |

### Architecture Summary
{Brief description of the application architecture — monolith, microservices,
serverless, etc. Include key components and how they interact.}

### External Attack Surface
{List the external-facing entry points identified in Stage 2:}
- {Entry point 1 — e.g., "REST API on /api/v1/* (authenticated)"}
- {Entry point 2 — e.g., "Webhook handler on /webhooks/* (unauthenticated)"}
- {Entry point 3}

---

## Threat Model Summary

{Top 5-8 threats identified via STRIDE analysis, mapped to actual findings where applicable:}

| ID | Category | Threat | Severity | Finding Match |
|----|----------|--------|----------|--------------|
| STRIDE-S-01 | Spoofing | {description} | High | VULN-003 |
| STRIDE-T-01 | Tampering | {description} | Medium | — |
| ... | ... | ... | ... | ... |

---

## Findings Overview

### By Scanner
| Scanner | Findings | Critical | High | Medium | Low |
|---------|----------|----------|------|--------|-----|
| Trivy SCA | {N} | {N} | {N} | {N} | {N} |
| Semgrep SAST | {N} | {N} | {N} | {N} | {N} |
| Gitleaks | {N} | — | — | — | — |
| Trivy IaC | {N} | {N} | {N} | {N} | {N} |

### By Real Risk Score (High + Critical raw findings only)
| Real Risk Score | Count | Classification |
|-----------------|-------|---------------|
| 9-10 | {N} | Critical Risk |
| 7-8 | {N} | High Risk |
| 5-6 | {N} | Medium Risk |
| 3-4 | {N} | Low Risk |
| 1-2 | {N} | Noise |

### Noise Analysis
> **Scanner reported {X} High/Critical findings.**
> **After reachability analysis, {Y} are actually actionable.**
> **Noise reduction: {Z}%**

{1-2 sentences explaining why the noise rate is what it is. Common reasons:
transitive dependency vulns where the vulnerable function isn't called,
SAST rules matching patterns that have proper sanitization, etc.}

---

## Critical & High Risk Findings (Real Risk Score ≥ 7)

{For each finding with Real Risk Score ≥ 7, include a detailed section:}

### VULN-{NNN}: {Brief Title}

| Field | Value |
|-------|-------|
| **Source** | {Scanner name} |
| **CVE / Rule** | {CVE-XXXX-XXXXX or semgrep-rule-id} |
| **Component** | {package@version or file:line} |
| **Original Severity** | {CRITICAL / HIGH} |
| **Real Risk Score** | {X}/10 |

**Reachability:** {Reachable / Partially Reachable / Unreachable}

**Dimension Scores:**
| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Reachability | {X}/10 | {Brief explanation} |
| Exploitability | {X}/10 | {Brief explanation} |
| Impact | {X}/10 | {Brief explanation} |
| Exposure | {X}/10 | {Brief explanation} |

**Context:**
{2-4 sentences explaining what this vulnerability is and why it matters
specifically for this application. Reference specific code paths, endpoints,
or data flows.}

**Exploitation Scenario:**
{Step-by-step: how would an attacker exploit this in this application?}
1. {Step 1}
2. {Step 2}
3. {Step 3}

**Evidence:**
{Code references, grep results, call chain analysis that supports the assessment}

**Recommended Fix:**
{Specific remediation steps}

**PR Status:** {Submitted: [PR #{number}]({url}) | Not submitted | N/A}

---

## Remediation Roadmap

Priority order based on Real Risk Score:

| Priority | Finding | Fix | Effort | Real Risk |
|----------|---------|-----|--------|-----------|
| 1 | VULN-{NNN} | {Brief fix description} | {Low/Med/High} | {X}/10 |
| 2 | VULN-{NNN} | {Brief fix description} | {Low/Med/High} | {X}/10 |
| ... | ... | ... | ... | ... |

### Quick Wins (< 1 hour)
{List fixes that are simple dependency upgrades or config changes}

### Medium Effort (1-4 hours)
{List fixes that require code changes}

### Significant Effort (> 4 hours)
{List fixes that require architectural changes}

---

## Appendix

### A. Methodology
This assessment was performed using an automated multi-stage pipeline:
1. Repository inventory and codebase analysis
2. Application context classification and STRIDE threat modeling
3. Multi-tool vulnerability scanning (Semgrep SAST, Trivy SCA, Gitleaks secrets, Trivy IaC)
4. Reachability analysis with contextual risk scoring
5. Remediation recommendation generation

Real Risk Scores are calculated using a weighted formula across four dimensions:
Reachability (35%), Exploitability (30%), Impact (25%), and Exposure (10%).

### B. Scanner Versions
| Tool | Version |
|------|---------|
| Semgrep | {version} |
| Trivy | {version} |
| Grype | {version} (if used) |
| Gitleaks | {version} |

### C. Full Finding List
{Table of ALL findings (not just High+Critical) with their Real Risk Scores,
for completeness. Keep it brief — ID, CVE, severity, Real Risk Score, one-line summary.}
```
