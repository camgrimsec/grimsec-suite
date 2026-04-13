# GRIMSEC — Agent Reference

Detailed reference for all 12 agents: what each does, what it needs, what it produces.

---

## Agent 01 — DevSecOps Repo Analyzer

**Skill file:** `agents/01-devsecops-repo-analyzer/SKILL.md`
**CLI command:** `python grimsec.py scan <repo-url>`

### What It Does

Runs a 6-stage security analysis pipeline against any GitHub repository.

| Stage | Name | Output |
|-------|------|--------|
| 1 | Inventory | `inventory.json` — languages, frameworks, dependencies, entry points |
| 2 | STRIDE Threat Model | `stride-threats.json` — enumerated threats per component |
| 3 | Multi-Scanner Run | `scan-results/` — Trivy + Semgrep + Gitleaks + Grype output |
| 4 | Reachability Analysis | `reachability-analysis.json` — which findings are actually reachable |
| 5 | Remediation | Draft PRs, pinned dependency updates, fix recommendations |
| 6 | Report | `findings.json` — deduplicated, scored, prioritized findings |

### Scan Depth Options

- `quick` — SCA + secrets only (~5 min)
- `standard` — all scanners, default Semgrep rules (~15 min)
- `deep` — all scanners + extended Semgrep rulesets (~30 min)

### Tools Used

- **Trivy** — SCA, container scanning, IaC misconfiguration, secrets
- **Semgrep** — SAST (custom + community rules)
- **Gitleaks** — git history secrets detection
- **Grype** — SCA from SBOM
- **Snyk** — optional additional SCA

### Real Risk Score

Each finding gets a Real Risk Score (0-10) based on CVSS + EPSS + KEV status + reachability + documentation context. This is what drives the 89-96% noise reduction.

---

## Agent 02 — CI/CD Pipeline Auditor

**Skill file:** `agents/02-cicd-pipeline-auditor/SKILL.md`
**CLI command:** `python grimsec.py audit <repo-url>`

### What It Does

Audits GitHub Actions workflow files for supply chain and pipeline security risks.

### Finding Categories

| Category | Examples |
|----------|---------|
| `unpinned_action` | `uses: actions/checkout@v3` instead of SHA pin |
| `expression_injection` | `run: echo "${{ github.event.issue.title }}"` |
| `overpermissive_permissions` | `permissions: write-all` |
| `dangerous_trigger` | `pull_request_target:` with code checkout |
| `secrets_exposure` | Secrets passed as CLI args, logged in `run:` steps |
| `self_hosted_runner` | Unverified self-hosted runner usage |

### Output

`cicd-findings.json` with each finding including:
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- Affected file and line number
- Code snippet showing the issue
- Fix recommendation with fixed code example

---

## Agent 03 — Vulnerability Context Enricher

**Skill file:** `agents/03-vulnerability-context-enricher/SKILL.md`
**CLI command:** `python grimsec.py enrich <cve-id>`

### What It Does

Takes a CVE ID and enriches it with real-world exploitability context.

### Data Sources

| Source | What It Provides |
|--------|-----------------|
| NVD | CVSS v3.1 base score + vector string |
| EPSS | Probability of exploitation in next 30 days (0-100%) |
| CISA KEV | Actively exploited in the wild? Yes/No |
| MITRE ATT&CK | Technique and tactic mapping |

### Output per CVE

```
CVE-XXXX-XXXXX
  CVSS:     9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
  EPSS:     72.3% (HIGH exploitation probability)
  KEV:      YES — added 2024-01-15
  ATT&CK:   T1190 (Exploit Public-Facing Application)
  Verdict:  PRIORITIZE — actively exploited, network-reachable, no auth required
```

---

## Agent 04 — Doc Intelligence Agent

**Skill file:** `agents/04-doc-intelligence-agent/SKILL.md`

### What It Does

Reads project documentation to build context that validates or downgrades scanner findings.

### What It Reads

- `README.md`, `docs/`, `SECURITY.md`, `CHANGELOG.md`
- Architecture diagrams and decision records
- Deployment docs (Dockerfiles, k8s manifests, Helm charts)
- Configuration files (`.env.example`, `config.yaml`, etc.)

### Why It Matters

A scanner may flag a CVE as CRITICAL, but the project's docs might show:
- The vulnerable code path is behind auth (downgrades exploitability)
- The component is only used in internal tooling (downgrades exposure)
- A mitigating control is documented (downgrades severity)

### Output

`doc-context.json` with:
- Technology stack confirmation
- Security controls identified in docs
- Finding validation/downgrade decisions with evidence

---

## Agent 05 — Threat Intel Monitor

**Skill file:** `agents/05-threat-intel-monitor/SKILL.md`
**CLI command:** `python grimsec.py monitor`

### What It Does

Continuously monitors threat intelligence feeds for new CVEs affecting your specific dependency stack.

### How It Works

1. Loads `inventory.json` from a previous Agent 01 run
2. Queries NVD for CVEs published in the last 48 hours
3. Cross-references with CISA KEV for active exploitation
4. Matches against your exact package versions
5. Produces prioritized alert report

### Configuration

Set `NVD_API_KEY` environment variable for higher NVD rate limits (recommended for production use). Free at: nvd.nist.gov/developers/request-an-api-key

### Output

`threat-intel-report.json` with:
- New CVEs affecting your stack (last 48h)
- EPSS scores for each
- KEV matches highlighted as CRITICAL ALERTS
- Recommended actions per finding

---

## Agent 06 — Executive Reporting Agent

**Skill file:** `agents/06-executive-reporting-agent/SKILL.md`
**CLI command:** `python grimsec.py report <analysis-dir>`

### What It Does

Translates technical security findings into business-language executive reports.

### Output Formats

1. **Executive Summary** (2 pages) — C-suite / board ready
2. **Technical Findings** — Detailed per-finding breakdown
3. **Compliance Report** — Mapped to SOC 2, ISO 27001, NIST CSF, OWASP SAMM
4. **Remediation Roadmap** — Prioritized by risk/effort with time estimates

### Risk Quantification

Uses the ALE (Annual Loss Expectancy) model:
- Estimated breach probability based on finding severity + exploitability
- Industry breach cost data by company size and sector
- Net risk expressed in dollar ranges

### Compliance Mapping

| Framework | Controls Mapped |
|-----------|----------------|
| SOC 2 | CC6, CC7, CC8, CC9 |
| ISO 27001 | A.12.6, A.14.2, A.16.1 |
| NIST CSF | ID.RA, PR.DS, DE.CM, RS.AN |
| OWASP SAMM | SR, TA, ST, IR |

---

## Agent 07 — DAST Scanner

**Skill file:** `agents/07-dast-scanner/SKILL.md`
**CLI command:** `python grimsec.py dast <target-url>`

> **Authorization required.** Only run against applications you own or have written permission to test.

### What It Does

Dynamic Application Security Testing against a running application.

### Tools Used

| Tool | Purpose |
|------|---------|
| Nuclei | Template-based vulnerability scanning (XSS, SQLi, misconfigs, CVEs) |
| httpx | Service fingerprinting, technology detection |
| OWASP ZAP | Active scan, spider, API fuzzing (optional) |

### Output

`dast-results/` containing:
- `nuclei-results.json` — template matches with severity
- `httpx-output.json` — service fingerprint
- `zap-report.json` — active scan findings (if ZAP used)
- `dast-summary.json` — deduplicated, prioritized findings

---

## Agent 08 — Exploit Validation Agent

**Skill file:** `agents/08-exploit-validation-agent/SKILL.md`
**CLI command:** `python grimsec.py validate <analysis-dir>`

> **Authorization required.** All PoC generation is for authorized security testing only.

### What It Does

Reviews each finding and generates proof-of-concept code demonstrating actual exploitability.

### Validation Verdicts

| Verdict | Meaning |
|---------|---------|
| `EXPLOITABLE` | PoC generated and confirmed, or trivially provable |
| `NOT_EXPLOITABLE` | Finding is present but not reachable or blocked by controls |
| `NEEDS_ACCESS` | Requires authenticated access or specific environment to confirm |
| `THEORETICAL` | Vulnerability class applies but specific conditions unclear |

### Safety Constraints

- PoCs use safe probe URLs and controlled environments
- No destructive actions (no data modification, no service disruption)
- AWS/cloud metadata endpoints documented but not executed in code
- All PoCs include authorization warnings

---

## Agent 09 — Code Understanding Agent

**Skill file:** `agents/09-code-understanding-agent/SKILL.md`
**CLI command:** `python grimsec.py understand <repo-path>`

### What It Does

Deep static code analysis to map the attack surface and trace data flows.

### Analysis Types

| Analysis | Output |
|----------|--------|
| Attack Surface Mapping | All entry points with input types and auth requirements |
| Source-to-Sink Tracing | Data flow from user input to dangerous operations |
| Dangerous Sink Inventory | All SQL queries, shell commands, file ops, HTTP calls |
| Variant Analysis | Finding N variants of a known vulnerability pattern |

### Output

`attack-surface-map.json` and `context-map.json` consumed by Agents 08 and 12.

---

## Agent 10 — IaC Policy Agent

**Skill file:** `agents/10-iac-policy-agent/SKILL.md`
**CLI command:** `python grimsec.py iac <repo-path>`

### What It Does

Static analysis of Infrastructure-as-Code files using multiple policy engines.

### Coverage

| IaC Type | Tools | Custom Policies |
|----------|-------|----------------|
| Dockerfile | Checkov, OPA | docker-security.rego |
| Kubernetes | Checkov, OPA | k8s-security.rego |
| Terraform | Checkov, OPA | terraform-security.rego |
| GitHub Actions | Checkov, OPA | github-actions.rego |

### Custom OPA Policies Included

- `deny_root_user` — Dockerfiles must not run as root
- `deny_privileged` — K8s pods must not use privileged mode
- `deny_open_sg` — Security groups must not allow unrestricted access on sensitive ports
- `deny_secrets_in_env` — ENV/ARG keys must not match secret name patterns
- `require_readonly_root` — K8s containers must use read-only root filesystem

---

## Agent 11 — OSS Forensics Agent

**Skill file:** `agents/11-oss-forensics-agent/SKILL.md`
**CLI command:** `python grimsec.py forensics <repo-url>`

### What It Does

Investigates an open-source package or repository for signs of supply chain compromise.

### Investigation Areas

| Area | What It Checks |
|------|---------------|
| Commit History | Unusual commits, deleted/modified files, timing anomalies |
| Maintainer Signals | Account takeovers, new contributors with large changes |
| Build Scripts | `setup.py`, `package.json` scripts, CI/CD changes |
| IOC Patterns | Network calls, obfuscated code, crypto miners, data exfiltration |
| Dependency Changes | Sudden new dependencies, version bumps without changelog |

### Output

- `forensics-report.json` — structured findings with timeline
- `evidence-package/` — collected evidence for further review
- `ioc-list.json` — indicators of compromise

---

## Agent 12 — Adversary Simulation Agent

**Skill file:** `agents/12-adversary-simulation-agent/SKILL.md`
**CLI command:** `python grimsec.py simulate <target>`

> **AUTHORIZED USE ONLY.** Requires written Rules of Engagement before proceeding. Only run against systems you own or have explicit written permission to test.

### What It Does

Executes controlled adversary simulation scenarios to validate security posture.

### Process

1. Define scope and Rules of Engagement
2. Map applicable ATT&CK techniques based on findings
3. Execute controlled exploitation scenarios (non-destructive)
4. Document kill chain with evidence
5. Produce remediation recommendations

### Output

- `simulation-report.json` — full simulation report
- `roe.pdf` — Rules of Engagement document
- ATT&CK technique coverage map

---

## Agent Chaining Reference

```
Agent 01 → inventory.json         → consumed by: 03, 04, 05, 09, 10
Agent 01 → findings.json          → consumed by: 06, 08
Agent 01 → scan-results/          → consumed by: 03, 08
Agent 02 → cicd-findings.json     → consumed by: 06
Agent 03 → enriched-findings.json → consumed by: 06, 08
Agent 04 → doc-context.json       → consumed by: 06
Agent 05 → threat-intel-report    → consumed by: 06
Agent 07 → dast-results/          → consumed by: 08
Agent 09 → attack-surface-map     → consumed by: 08, 12
Agent 10 → iac-findings.json      → consumed by: 06
Agent 11 → forensics-report       → consumed by: 06
Agent 08 → exploit-validation     → consumed by: 12
```
