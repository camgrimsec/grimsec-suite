# GRIMSEC DevSecOps Agent Suite

12-agent DevSecOps security analysis platform compatible with Codex CLI, OpenAI Assistants, and any tool that reads AGENTS.md.

## Suite Overview

GRIMSEC provides end-to-end DevSecOps security coverage: static analysis, CI/CD auditing, CVE intelligence, documentation analysis, threat monitoring, DAST, exploit validation, code comprehension, IaC compliance, forensics, and adversary simulation.

All output artifacts go to `./grimsec-output/` relative to the project root.

---

## Agent 1: DevSecOps Repo Analyzer

**Trigger phrases:** "analyze this repo", "security scan", "vulnerability assessment", "threat model", "DevSecOps analysis", "audit codebase", "check for security issues"

**Description:** End-to-end 6-stage security analysis pipeline. Runs STRIDE threat modeling, multi-tool vulnerability scanning (SAST with Semgrep, SCA with Trivy/Grype/Snyk, secrets with Gitleaks, IaC with Trivy Config), reachability analysis that assigns Real Risk Scores (1-10), and remediation recommendations. Key differentiator: contextual reachability analysis that reduces scanner noise by 80-97%.

**Output:** `grimsec-output/{repo-name}/assessment-report.md`

**Dependencies:** Semgrep, Trivy, Grype, Gitleaks, Snyk CLI (optional)

**Instructions:** See `prompts/01-repo-analyzer.md`

---

## Agent 2: CI/CD Pipeline Auditor

**Trigger phrases:** "audit GitHub Actions", "CI/CD security", "workflow security", "pipeline security", "supply chain attack", "expression injection", "pull_request_target", "pinned actions", "workflow hardening"

**Description:** Structured 6-category security audit of GitHub Actions workflow files. Detects unpinned third-party actions (CVE-2025-30066 class), expression injection, dangerous triggers (pull_request_target PPE attacks), overly permissive permissions, secrets exposure, and self-hosted runner risks. Provides specific YAML remediation snippets.

**Output:** `grimsec-output/{repo-name}/audit-report.json` + `audit-summary.md`

**Dependencies:** PyYAML

**Instructions:** See `prompts/02-cicd-auditor.md`

---

## Agent 3: Vulnerability Context Enricher

**Trigger phrases:** "look up CVE", "enrich vulnerabilities", "CVE details", "EPSS score", "CISA KEV", "check if exploited in wild", "prioritize vulnerabilities", "ATT&CK mapping"

**Description:** Multi-source CVE intelligence aggregator. Queries NVD API 2.0, OSV.dev, EPSS (FIRST), and CISA KEV catalog. Produces composite priority scores (0-100), MITRE ATT&CK technique mappings via CWE, fix availability analysis, and plain-language summaries. Works standalone with individual CVEs or in batch mode.

**Output:** `grimsec-output/{context}/enriched-cves.json`

**Dependencies:** None (Python stdlib only, all public APIs)

**Instructions:** See `prompts/03-vuln-enricher.md`

---

## Agent 4: Documentation Intelligence Agent

**Trigger phrases:** "analyze documentation", "product context", "security architecture", "validate finding", "false positive check", "doc intelligence", "security controls"

**Description:** 8-phase documentation analysis to build a security context profile. Extracts authentication mechanisms, authorization model, sandboxing configurations, encryption settings, deployment security, and API surfaces. Produces vulnerability_context_adjustments that modify scanner risk scores based on documented controls.

**Output:** `grimsec-output/{repo-name}/doc-profile.json` + `doc-summary.md`

**Dependencies:** PyYAML

**Instructions:** See `prompts/04-doc-intel.md`

---

## Agent 5: Threat Intel Monitor

**Trigger phrases:** "new CVEs", "monitor vulnerabilities", "threat intel", "exposure check", "CISA KEV update", "new threats", "dependency exposure"

**Description:** Continuous threat intelligence monitoring. Downloads CISA KEV catalog, queries OSV.dev for all monitored dependencies, and cross-references against `inventory.json` files from analyzed repositories. Classifies exposure status (EXPOSED/POTENTIALLY_EXPOSED/NOT_AFFECTED) and generates prioritized exposure reports.

**Output:** `grimsec-output/threat-intel/{date}-report.json` + `{date}-summary.md`

**Dependencies:** None (Python stdlib only)

**Instructions:** See `prompts/05-threat-monitor.md`

---

## Agent 6: Executive Reporting Agent

**Trigger phrases:** "executive report", "board presentation", "security ROI", "risk quantification", "compliance mapping", "CISO report", "MTTR", "shift-left savings"

**Description:** Transforms raw DevSecOps scan data into leadership-ready intelligence. Produces financial risk quantification (shift-left savings, breach probability reduction), MTTR benchmarking, noise reduction metrics, compliance framework mapping (SOC 2, ISO 27001, NIST CSF, OWASP SAMM), and prioritized recommendations.

**Output:** `grimsec-output/executive/executive-brief.md` + `executive-report.json`

**Dependencies:** None (reads other agents' JSON output)

**Instructions:** See `prompts/06-executive-reporter.md`

---

## Agent 7: DAST Scanner

**Trigger phrases:** "DAST", "dynamic testing", "black-box scan", "ZAP scan", "Nuclei scan", "web application security", "runtime vulnerabilities", "web app pentest"

**Description:** Dynamic Application Security Testing using Nuclei (9,000+ templates) and OWASP ZAP. Phases: target discovery (httpx), Nuclei quick scan (CVEs/misconfigs/exposures), ZAP deep scan (spider/active/passive/API), finding correlation across tools with CWE/OWASP mapping, unified report.

**Authorization required:** Never run active scans without explicit user authorization.

**Output:** `dast-results/dast-report.md` + individual tool JSON files

**Dependencies:** Nuclei, OWASP ZAP (Docker), httpx

**Instructions:** See `prompts/07-dast-scanner.md`

---

## Agent 8: Exploit Validation Agent

**Trigger phrases:** "exploit validation", "PoC generation", "prove exploitability", "validate finding", "Real Risk Score", "security finding confirmation"

**Description:** 7-stage validation pipeline for findings with Real Risk Score ≥ 7. Stages: inventory, quick assessment (instant-confirm), attack surface mapping, exploit hypothesis, PoC generation, validation, report. Classifies findings as EXPLOITABLE/LIKELY_EXPLOITABLE/NEEDS_RUNTIME/RULED_OUT.

**Safety:** All generated PoC code is FOR SECURITY ASSESSMENT ONLY and must include the required safety header.

**Output:** `exploit-validation/validation-report.json` + `validation-summary.md` + PoC files

**Dependencies:** None

**Instructions:** See `prompts/08-exploit-validator.md`

---

## Agent 9: Code Understanding Agent

**Trigger phrases:** "map attack surface", "trace dataflow", "hunt variants", "explain framework security", "code comprehension", "entry points", "taint analysis"

**Description:** Adversarial code comprehension with four modes: `--map` (attack surface), `--trace` (data flow tracing from source to sink), `--hunt` (variant hunting for known vulnerability patterns), `--teach` (framework security model explanation). Integrates with `inventory.json` and `app-context.json`.

**Output:** `code-understanding/context-map.json`, `flow-traces/`, `variants.json`

**Dependencies:** None

**Instructions:** See `prompts/09-code-understanding.md`

---

## Agent 10: IaC Policy Agent

**Trigger phrases:** "scan IaC", "Checkov", "OPA policy", "CIS benchmark", "SOC2 IaC", "NIST infrastructure", "Dockerfile security", "Kubernetes security", "Terraform security review", "SBOM"

**Description:** Comprehensive IaC security scanning using Checkov (750+ policies) and OPA (custom Rego policies). Covers Terraform, CloudFormation, Kubernetes, Docker, Ansible, GitHub Actions. Generates SBOMs (SPDX + CycloneDX via Syft). Maps findings to CIS, NIST 800-53, SOC 2, HIPAA, PCI-DSS.

**Output:** `iac-policy/iac-report.md` + JSON results + SBOM files + compliance map

**Dependencies:** Checkov, OPA/conftest, Syft

**Instructions:** See `prompts/10-iac-policy.md`

---

## Agent 11: OSS Forensics Agent

**Trigger phrases:** "investigate this repo", "forensic analysis", "supply chain compromise", "was this package backdoored", "suspicious maintainer", "oss forensics", "supply chain incident"

**Description:** Evidence-backed forensic investigation of GitHub repositories. 5 phases: evidence collection (GitHub REST API, git history, GH Archive, Wayback Machine, package registries), IOC extraction (obfuscation/exfiltration/env-access/install-hook/behavioral IOCs), timeline reconstruction, hypothesis formation with confidence ratings, forensic report.

**Output:** `forensics/forensic-report.md` + evidence/ + IOCs + timeline + hypotheses

**Dependencies:** GITHUB_TOKEN env var (optional, for higher rate limits)

**Instructions:** See `prompts/11-forensics.md`

---

## Agent 12: Adversary Simulation Agent

**Trigger phrases:** "adversary simulation", "red team", "penetration testing", "attack simulation", "kill chain", "ATT&CK mapping", "post-exploitation", "pentest"

**Description:** Controlled adversary simulation converting EXPLOITABLE findings into evidence-backed attack narratives. 6 phases: rules of engagement (signed authorization required), reconnaissance (nmap, httpx, Nuclei), exploitation (human approval mandatory), post-exploitation impact assessment, MITRE ATT&CK mapping, executive simulation report.

**Authorization required:** Must have signed RoE and explicit human approval before Phase 3.

**Output:** `adversary-simulation/simulation-report.md` + RoE + exploitation log + ATT&CK mapping

**Dependencies:** nmap, httpx, Nuclei, Metasploit/SQLMap/Hydra (exploitation phase)

**Instructions:** See `prompts/12-adversary-sim.md`

---

## Standard Pipeline

```
Repo Analyzer (1) → produces inventory.json, app-context.json, reachability-analysis.json
  ├── CI/CD Auditor (2)      → covers GitHub Actions attack surface
  ├── Vuln Enricher (3)      → adds EPSS, CISA KEV, ATT&CK context to CVEs
  ├── Doc Intel (4)          → validates findings against documented controls
  ├── Threat Monitor (5)     → continuous exposure monitoring
  ├── DAST Scanner (7)       → runtime testing (if running app available)
  ├── Exploit Validator (8)  → proves exploitability of RRS ≥ 7 findings
  ├── Code Understanding (9) → deep code analysis, variant hunting
  ├── IaC Policy (10)        → infrastructure compliance scanning
  ├── Forensics (11)         → supply chain investigation (if triggered)
  └── Adversary Sim (12)     → red team simulation (if authorized)
          │
          ▼
Executive Reporter (6) → consumes all outputs → board-ready report
```

## Output Directory Structure

```
grimsec-output/
├── {repo-name}/
│   ├── source/
│   ├── inventory.json
│   ├── app-context.json
│   ├── scan-results/
│   ├── reachability-analysis.json
│   ├── doc-profile.json
│   ├── enriched-cves.json
│   ├── remediation.json
│   └── assessment-report.md
├── threat-intel/
├── executive/
├── exploit-validation/
├── code-understanding/
├── iac-policy/
├── forensics/
└── adversary-simulation/
```
