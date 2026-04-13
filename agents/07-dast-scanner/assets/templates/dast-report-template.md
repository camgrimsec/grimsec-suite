# DAST Security Report

<!-- GRIMSEC DevSecOps Suite — Agent 7: DAST Scanner -->
<!-- Replace all {{PLACEHOLDER}} values with actual scan data -->

**Target:**        {{TARGET_URL}}  
**Scan Date:**     {{SCAN_DATE}}  <!-- ISO 8601, e.g. 2026-04-04T16:00:00Z -->
**Scan Modes:**    {{SCAN_MODES}} <!-- e.g. "Nuclei (cves,misconfiguration,exposures) + ZAP Full Scan" -->
**Performed By:**  GRIMSEC DAST Agent 7 (Automated)  
**Report Version:** 1.0

---

## Executive Summary

{{EXECUTIVE_SUMMARY_PARAGRAPH}}
<!-- 2–4 sentences. Lead with overall risk posture, key findings count by severity, and immediate recommended action. -->
<!-- Example: "Dynamic testing of https://app.example.com identified 14 vulnerabilities including 1 critical (confirmed SQL injection in the /login endpoint), 3 high-severity issues (stored XSS, path traversal, SSRF), and 10 medium/low findings. Immediate remediation is recommended for the SQL injection before the next deployment. Full finding details and remediation guidance are provided below." -->

### Risk Scorecard

| Severity | Count | Requires Immediate Action |
|----------|-------|--------------------------|
| 🔴 CRITICAL | {{CRITICAL_COUNT}} | Yes — block deployment |
| 🟠 HIGH | {{HIGH_COUNT}} | Yes — fix within 7 days |
| 🟡 MEDIUM | {{MEDIUM_COUNT}} | Fix within 30 days |
| 🔵 LOW | {{LOW_COUNT}} | Fix within 90 days |
| ⚪ INFO | {{INFO_COUNT}} | Informational |
| **TOTAL** | **{{TOTAL_COUNT}}** | |

### Scan Coverage

| Tool | Templates/Mode | Findings | Duration |
|------|---------------|----------|----------|
| Nuclei | {{NUCLEI_CATEGORIES}} | {{NUCLEI_FINDING_COUNT}} | {{NUCLEI_DURATION}} |
| OWASP ZAP | {{ZAP_MODE}} | {{ZAP_FINDING_COUNT}} | {{ZAP_DURATION}} |
| Combined (deduped) | — | {{TOTAL_DEDUPED_COUNT}} | — |

---

## Target Reconnaissance

**Technology Stack Detected:**
<!-- Populate from Nuclei technologies scan and httpx output -->
- Server: {{SERVER_HEADER}}
- Framework: {{FRAMEWORK}}
- Language/Runtime: {{RUNTIME}}
- Database (inferred): {{DATABASE}}
- CDN/WAF: {{CDN_WAF}}
- Other: {{OTHER_TECH}}

**Discovered Endpoints:** {{ENDPOINT_COUNT}} (from ZAP spider)  
**API Spec Available:** {{YES_NO}}  
**Authentication Tested:** {{YES_NO}} {{AUTH_TYPE}}

---

## Finding Summary Table

> Sorted by severity (critical → info). Duplicate findings across tools merged.

| # | Finding | Severity | CWE | OWASP Category | Tool(s) | Affected Endpoint |
|---|---------|----------|-----|----------------|---------|------------------|
| 1 | {{FINDING_1_NAME}} | 🔴 CRITICAL | {{CWE}} | {{OWASP}} | {{TOOLS}} | {{ENDPOINT}} |
| 2 | {{FINDING_2_NAME}} | 🟠 HIGH | {{CWE}} | {{OWASP}} | {{TOOLS}} | {{ENDPOINT}} |
| 3 | {{FINDING_3_NAME}} | 🟠 HIGH | {{CWE}} | {{OWASP}} | {{TOOLS}} | {{ENDPOINT}} |
| 4 | {{FINDING_4_NAME}} | 🟡 MEDIUM | {{CWE}} | {{OWASP}} | {{TOOLS}} | {{ENDPOINT}} |
| 5 | {{FINDING_5_NAME}} | 🔵 LOW | {{CWE}} | {{OWASP}} | {{TOOLS}} | {{ENDPOINT}} |
<!-- Add rows as needed -->

---

## Detailed Findings

<!-- Repeat the section below for each finding. Start with CRITICAL, then HIGH, etc. -->

---

### Finding {{N}}: {{FINDING_NAME}}

**Severity:** {{SEVERITY}}  
**CWE:** [{{CWE_ID}}](https://cwe.mitre.org/data/definitions/{{CWE_NUM}}.html)  
**OWASP Category:** {{OWASP_CATEGORY}}  
**Detected By:** {{TOOL_LIST}} <!-- e.g. "Nuclei, ZAP" or "ZAP only" -->  
**Template / Plugin ID:** {{TEMPLATE_OR_PLUGIN_ID}}  

#### Affected Location

```
{{HTTP_METHOD}} {{AFFECTED_URL}}
Parameter: {{PARAM_NAME}}
```

#### Description

{{FINDING_DESCRIPTION}}
<!-- Clear explanation of what the vulnerability is and why it is dangerous. 2–5 sentences. -->

#### Evidence

```
{{RAW_REQUEST_OR_RESPONSE_SNIPPET}}
```
<!-- Paste the relevant HTTP request/response snippet, extracted result, or Nuclei curl command. -->

#### Impact

{{IMPACT_DESCRIPTION}}
<!-- What can an attacker achieve by exploiting this? Be specific to the target context. -->
<!-- Example: "An attacker can exfiltrate the full users table including password hashes and PII, bypassing all authentication." -->

#### Remediation

{{REMEDIATION_STEPS}}
<!-- Step-by-step fix. Include code examples where applicable. -->

**References:**
- {{REFERENCE_1}}
- {{REFERENCE_2}}

---

<!-- Repeat the finding block above for each finding. Then continue with the sections below. -->

---

## OWASP Top 10 Coverage

| OWASP Category | Findings |
|----------------|---------|
| A01:2021 – Broken Access Control | {{COUNT}} |
| A02:2021 – Cryptographic Failures | {{COUNT}} |
| A03:2021 – Injection | {{COUNT}} |
| A04:2021 – Insecure Design | {{COUNT}} |
| A05:2021 – Security Misconfiguration | {{COUNT}} |
| A06:2021 – Vulnerable and Outdated Components | {{COUNT}} |
| A07:2021 – Identification and Authentication Failures | {{COUNT}} |
| A08:2021 – Software and Data Integrity Failures | {{COUNT}} |
| A09:2021 – Security Logging and Monitoring Failures | {{COUNT}} |
| A10:2021 – Server-Side Request Forgery | {{COUNT}} |

---

## Remediation Priorities

### Immediate Action Required (CRITICAL)
<!-- List CRITICAL findings and the specific fix needed. -->
1. **{{CRITICAL_FINDING_1}}** — {{ONE_LINE_FIX}}
2. {{...}}

### High Priority (Complete within 7 days)
1. **{{HIGH_FINDING_1}}** — {{ONE_LINE_FIX}}
2. {{...}}

### Standard Remediation (Complete within 30 days)
1. **{{MEDIUM_FINDING_1}}** — {{ONE_LINE_FIX}}
2. {{...}}

### Maintenance Items (Complete within 90 days)
1. **{{LOW_FINDING_1}}** — {{ONE_LINE_FIX}}
2. {{...}}

---

## Remediation Verification

After fixes are applied, re-run targeted checks:

```bash
# Re-verify specific Nuclei template
nuclei -target {{TARGET_URL}} -id {{TEMPLATE_ID}} -severity critical,high

# Re-run ZAP baseline to verify header fixes
python scripts/run-zap.py --target {{TARGET_URL}} --mode baseline --output dast-results/zap-retest.json

# Re-run full suite
python scripts/run-nuclei.py --target {{TARGET_URL}} --output dast-results/nuclei-retest.json
python scripts/run-zap.py --target {{TARGET_URL}} --mode full --output dast-results/zap-retest.json
```

---

## Scan Metadata

| Field | Value |
|-------|-------|
| Scan Start | {{SCAN_START_ISO}} |
| Scan End | {{SCAN_END_ISO}} |
| Total Duration | {{TOTAL_DURATION}} |
| Nuclei Version | {{NUCLEI_VERSION}} |
| Nuclei Template Version | {{TEMPLATE_VERSION}} |
| ZAP Image | ghcr.io/zaproxy/zaproxy:stable |
| ZAP Version | {{ZAP_VERSION}} |
| Target IP | {{TARGET_IP}} |
| Scope | {{SCOPE_DESCRIPTION}} |
| Authorization | {{PENTEST_AUTH_REFERENCE}} |
| GRIMSEC Agent | 7 — dast-scanner |
| Predecessor Output | inventory.json from devsecops-repo-analyzer |
| Successor Consumers | vulnerability-context-enricher, executive-reporting-agent |

---

## Raw Output Files

| File | Description | Size |
|------|-------------|------|
| `dast-results/nuclei.json` | Nuclei structured findings | {{SIZE}} |
| `dast-results/zap.json` | ZAP structured findings | {{SIZE}} |
| `dast-results/httpx.json` | Target discovery metadata | {{SIZE}} |
| `dast-results/dast-report.md` | This report | {{SIZE}} |

---

*Report generated by GRIMSEC DAST Scanner — Agent 7 of the GRIMSEC DevSecOps Suite.*  
*For questions, contact the security team or open an issue in the GRIMSEC repository.*
