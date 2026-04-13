# IaC Security Report

**Repository:** `{{REPOSITORY_PATH}}`  
**Scan Date:** {{SCAN_TIMESTAMP}}  
**Agent:** GRIMSEC IaC Policy Agent v1.0  
**Scan Duration:** {{SCAN_DURATION_SECONDS}}s  

---

## Executive Summary

| Metric | Value |
|---|---|
| IaC Frameworks Detected | {{FRAMEWORKS_DETECTED}} |
| Checkov Checks Run | {{CHECKOV_TOTAL_CHECKS}} |
| Checkov Passed | {{CHECKOV_PASSED}} ({{CHECKOV_PASS_RATE}}%) |
| Checkov Failed | {{CHECKOV_FAILED}} |
| OPA Violations | {{OPA_VIOLATIONS}} |
| OPA Warnings | {{OPA_WARNINGS}} |
| SBOM Packages | {{SBOM_PACKAGE_COUNT}} |
| Critical Findings | **{{CRITICAL_FINDING_COUNT}}** |

### Risk Level: {{RISK_LEVEL}}

{{RISK_LEVEL_DESCRIPTION}}

---

## Compliance Coverage

| Framework | Controls Assessed | Pass | Fail | Pass Rate |
|---|---|---|---|---|
| CIS AWS Foundations | {{CIS_AWS_TOTAL}} | {{CIS_AWS_PASS}} | {{CIS_AWS_FAIL}} | {{CIS_AWS_RATE}}% |
| CIS Kubernetes | {{CIS_K8S_TOTAL}} | {{CIS_K8S_PASS}} | {{CIS_K8S_FAIL}} | {{CIS_K8S_RATE}}% |
| SOC 2 Type II | {{SOC2_TOTAL}} | {{SOC2_PASS}} | {{SOC2_FAIL}} | {{SOC2_RATE}}% |
| NIST 800-53 | {{NIST_TOTAL}} | {{NIST_PASS}} | {{NIST_FAIL}} | {{NIST_RATE}}% |
| HIPAA | {{HIPAA_TOTAL}} | {{HIPAA_PASS}} | {{HIPAA_FAIL}} | {{HIPAA_RATE}}% |
| PCI-DSS v4.0 | {{PCIDSS_TOTAL}} | {{PCIDSS_PASS}} | {{PCIDSS_FAIL}} | {{PCIDSS_RATE}}% |

---

## IaC Discovery Summary

| Framework | Files Found | Checks Run | Passed | Failed |
|---|---|---|---|---|
| Terraform | {{TF_FILES}} | {{TF_CHECKS}} | {{TF_PASSED}} | {{TF_FAILED}} |
| Kubernetes | {{K8S_FILES}} | {{K8S_CHECKS}} | {{K8S_PASSED}} | {{K8S_FAILED}} |
| Docker | {{DOCKER_FILES}} | {{DOCKER_CHECKS}} | {{DOCKER_PASSED}} | {{DOCKER_FAILED}} |
| CloudFormation | {{CFN_FILES}} | {{CFN_CHECKS}} | {{CFN_PASSED}} | {{CFN_FAILED}} |
| GitHub Actions | {{GHA_FILES}} | {{GHA_CHECKS}} | {{GHA_PASSED}} | {{GHA_FAILED}} |
| Ansible | {{ANSIBLE_FILES}} | {{ANSIBLE_CHECKS}} | {{ANSIBLE_PASSED}} | {{ANSIBLE_FAILED}} |
| ARM Templates | {{ARM_FILES}} | {{ARM_CHECKS}} | {{ARM_PASSED}} | {{ARM_FAILED}} |

---

## Critical Findings

> These findings require immediate remediation before deployment.

{{#each CRITICAL_FINDINGS}}
### {{INDEX}}. {{CHECK_ID}} — {{CHECK_NAME}}

- **Severity:** CRITICAL  
- **Framework:** {{FRAMEWORK}}  
- **Resource:** `{{RESOURCE}}`  
- **File:** `{{FILE_PATH}}` (line {{LINE_NUMBER}})  
- **Compliance Impact:** {{COMPLIANCE_CONTROLS}}  

**Description:** {{DESCRIPTION}}

**Remediation:**
```{{LANGUAGE}}
{{REMEDIATION_CODE}}
```

---
{{/each}}

## High Severity Findings

{{#each HIGH_FINDINGS}}
### {{INDEX}}. {{CHECK_ID}} — {{CHECK_NAME}}

- **Severity:** HIGH  
- **Framework:** {{FRAMEWORK}}  
- **Resource:** `{{RESOURCE}}`  
- **File:** `{{FILE_PATH}}` (line {{LINE_NUMBER}})  

**Remediation:** {{REMEDIATION_SUMMARY}}

---
{{/each}}

## OPA Custom Policy Violations

### Docker Security

| Rule | Violation | File |
|---|---|---|
{{#each OPA_DOCKER_VIOLATIONS}}
| {{RULE}} | {{MESSAGE}} | {{FILE}} |
{{/each}}

### Kubernetes Security

| Rule | Violation | File |
|---|---|---|
{{#each OPA_K8S_VIOLATIONS}}
| {{RULE}} | {{MESSAGE}} | {{FILE}} |
{{/each}}

### Terraform Security

| Rule | Violation | File |
|---|---|---|
{{#each OPA_TERRAFORM_VIOLATIONS}}
| {{RULE}} | {{MESSAGE}} | {{FILE}} |
{{/each}}

### GitHub Actions Security

| Rule | Violation | File |
|---|---|---|
{{#each OPA_GHA_VIOLATIONS}}
| {{RULE}} | {{MESSAGE}} | {{FILE}} |
{{/each}}

---

## SBOM Summary

**Scan method:** Syft filesystem scan  
**Output files:**
- `iac-policy/sbom/filesystem-sbom.spdx.json` (SPDX format)
- `iac-policy/sbom/filesystem-sbom.cdx.json` (CycloneDX format)

| Package Type | Count |
|---|---|
| Python (pip) | {{SBOM_PYTHON}} |
| Node.js (npm) | {{SBOM_NPM}} |
| Go modules | {{SBOM_GO}} |
| Java (jar/maven) | {{SBOM_JAVA}} |
| System (deb/rpm/apk) | {{SBOM_SYSTEM}} |
| **Total** | **{{SBOM_TOTAL}}** |

{{#if SBOM_CVE_COUNT}}
> **⚠ CVE Alert:** {{SBOM_CVE_COUNT}} packages with known vulnerabilities detected. Run Grype for full CVE details: `grype iac-policy/sbom/filesystem-sbom.spdx.json`
{{/if}}

---

## Compliance Detail: CIS AWS Foundations Benchmark

| Control | Title | Status | Failing Resources |
|---|---|---|---|
{{#each CIS_AWS_CONTROLS}}
| {{ID}} | {{TITLE}} | {{STATUS}} | {{FAILING_RESOURCES}} |
{{/each}}

---

## Remediation Priority Matrix

Findings are ranked by impact × likelihood:

| Priority | Check ID | Description | Effort | Impact |
|---|---|---|---|---|
{{#each REMEDIATION_MATRIX}}
| {{PRIORITY}} | {{CHECK_ID}} | {{DESCRIPTION}} | {{EFFORT}} | {{IMPACT}} |
{{/each}}

---

## Scan Configuration

| Parameter | Value |
|---|---|
| Checkov version | {{CHECKOV_VERSION}} |
| OPA version | {{OPA_VERSION}} |
| Syft version | {{SYFT_VERSION}} |
| Frameworks scanned | {{FRAMEWORKS_LIST}} |
| Custom policies | {{OPA_POLICIES_COUNT}} |
| Checks skipped | {{SKIPPED_CHECKS}} |
| Scan directory | `{{REPOSITORY_PATH}}` |
| Output directory | `iac-policy/` |

---

## Full Findings Appendix

The complete findings are available in machine-readable format:
- `iac-policy/checkov-results.json` — All Checkov check results
- `iac-policy/opa-results.json` — All OPA policy evaluation results
- `iac-policy/compliance-map.json` — Control-by-control compliance status

---

*Generated by GRIMSEC IaC Policy Agent (Agent 10) on {{SCAN_TIMESTAMP}}*  
*GRIMSEC DevSecOps Suite — https://github.com/grimsec/devsecops-suite*
