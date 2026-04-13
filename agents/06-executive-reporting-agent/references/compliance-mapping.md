# Compliance Framework Control Mapping

Maps GRIMSEC DevSecOps activities to specific compliance framework controls.

## SOC 2 Type II

| Control ID | Control Name | GRIMSEC Coverage | Evidence |
|-----------|-------------|-----------------|----------|
| CC6.1 | Logical and Physical Access Controls | Auth bypass detection (CASL CVE), RBAC analysis, API endpoint audit | Reachability analysis, doc-intelligence auth review |
| CC6.6 | Security for Externally Transmitted Data | TLS verification, ALB HTTPS checks, secrets-in-transit scan | IaC scan results, CI/CD audit (secrets exposure) |
| CC7.1 | System Monitoring | Continuous scanning pipeline, threat intel feed monitoring | Scan timestamps, cron job configs, threat-intel reports |
| CC7.2 | Anomaly Detection | Reachability analysis filters noise from signal, deviation from baseline | Noise reduction metrics, before/after comparison |
| CC7.3 | Evaluation of Identified Events | STRIDE threat modeling, Real Risk scoring, context enrichment | Threat model output, enriched CVE profiles |
| CC8.1 | Change Management | CI/CD audit (every workflow change scanned), PR-based remediation | Audit reports, PR history, self-audit pipeline |
| CC9.1 | Risk Mitigation | Prioritized remediation roadmap, automated fix PRs | Remediation JSON, merged PR tracking |

## ISO 27001:2022

| Control ID | Control Name | GRIMSEC Coverage | Notes |
|-----------|-------------|-----------------|-------|
| A.8.8 | Technical Vulnerability Management | Multi-scanner SCA (Trivy+Snyk+Grype), CVE enrichment, reachability analysis | Core strength — full pipeline |
| A.8.9 | Configuration Management | IaC scanning (Checkov, tfsec), Dockerfile audit, Terraform state review | Windmill IaC analysis |
| A.8.25 | Secure Development Lifecycle | CI/CD audit, action pinning, permissions hardening, PR-based fixes | Full CI/CD pipeline coverage |
| A.8.28 | Secure Coding | Semgrep SAST, code path analysis, input validation review | Standard/deep scan modes |
| A.5.23 | Information Security for Cloud Services | Cloud IaC review (AWS ALB, EKS, S3, security groups) | Windmill Terraform analysis |
| A.8.12 | Data Classification | Doc-intelligence identifies PII handling, secret categorization | Doc profile output |

## NIST CSF 2.0

| Function | Category | GRIMSEC Coverage |
|----------|---------|-----------------|
| IDENTIFY (ID) | ID.AM — Asset Management | Repo inventory, dependency enumeration, SBOM-like output |
| IDENTIFY (ID) | ID.RA — Risk Assessment | STRIDE threat modeling, Real Risk scoring, reachability analysis |
| PROTECT (PR) | PR.DS — Data Security | Secrets scanning (Gitleaks), encryption-at-rest verification |
| PROTECT (PR) | PR.PS — Platform Security | IaC scanning, container security, CI/CD hardening |
| DETECT (DE) | DE.CM — Continuous Monitoring | Scheduled scanning, threat intel feeds, CVE monitoring |
| DETECT (DE) | DE.AE — Adverse Event Analysis | Reachability analysis, noise reduction, false positive elimination |
| RESPOND (RS) | RS.MI — Mitigation | Automated PR generation, prioritized remediation roadmap |
| RESPOND (RS) | RS.AN — Analysis | CVE enrichment (EPSS, CISA KEV, ATT&CK mapping) |

## OWASP SAMM v2

| Practice | Level | GRIMSEC Activity | Gap? |
|----------|-------|-----------------|------|
| Threat Assessment | L2 | STRIDE threat model per repo, data flow mapping | No |
| Security Testing | L2 | Multi-scanner CI/CD pipeline (SCA+SAST+secrets+IaC) | No |
| Security Testing | L3 | Would need runtime DAST and fuzz testing | Yes — L3 gap |
| Defect Management | L2 | Finding triage with reachability, PR tracking, noise reduction | No |
| Secure Build | L2 | CI/CD audit, action pinning, permissions hardening | No |
| Secure Build | L3 | Would need reproducible builds, SBOM signing | Yes — L3 gap |
| Security Architecture | L1 | Doc-intelligence architecture review | Partial |
| Security Architecture | L2 | Would need formal threat modeling workshops | Yes — L2 gap |
