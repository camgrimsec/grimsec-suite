# DevSecOps Repo Analyzer

A 6-stage AI-driven security analysis pipeline with contextual vulnerability analysis — instead of dumping hundreds of CVEs, this skill determines which vulnerabilities are actually reachable and exploitable in the specific application context.

Invoke with `/repo-analyzer` or describe the task naturally: "analyze this repo for security issues".

## When to Use

- Analyze a GitHub repository for security vulnerabilities
- Run a DevSecOps assessment on a codebase
- Threat model an application
- Audit an open-source project's security posture
- Check dependencies for known vulnerabilities with real-world context
- Assess actual risk (not just CVSS scores)
- Prepare a security PR for an open-source repo

## Prerequisites

Install required scanning tools:

```bash
# SAST
pip install semgrep

# SCA + IaC
# Linux: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
# macOS: brew install trivy

# Secondary SCA
# https://github.com/anchore/grype/releases

# Secrets detection
# macOS: brew install gitleaks

# Optional: Snyk SCA (requires account)
npm install -g snyk
snyk auth
```

## Pipeline Overview

```
Stage 1: Repo Scout ──► Stage 2: App Context ──► Stage 3: Vulnerability Scan
                                                          │
                                                          ▼
Stage 6: Report ◄── Stage 5: Remediation ◄── Stage 4: Reachability Analysis
```

Each stage produces artifacts in `./grimsec-output/{repo-name}/`.

## Input

User provides one of:
- A GitHub repository URL (e.g., `https://github.com/supabase/supabase`)
- An `owner/repo` shorthand
- A local path to an already-cloned repository

Optional: `--depth quick|standard|deep` (default: `standard`), `--branch`, `--pr-mode`

## Stage 1: Repo Scout & Ingestion

Clone and inventory the repository:

```bash
gh repo clone {owner/repo} ./grimsec-output/{repo-name}/source/ -- --depth=1
# Or:
git clone --depth=1 {repo-url} ./grimsec-output/{repo-name}/source/
```

Build inventory containing:
- Languages detected (file counts + LOC per language)
- Package managers and dependency files found
- Infrastructure files (Dockerfiles, IaC, CI/CD configs)
- Codebase metrics (total files, LOC, top directories)
- README summary extraction

**Output:** `./grimsec-output/{repo-name}/inventory.json`

## Stage 2: Application Context & Threat Model

Classify the application and build a STRIDE threat model.

**Application classification:**

| Type | Indicators |
|------|-----------|
| Web Application | Frontend frameworks, serves HTML, has routes/pages |
| API Service | REST/GraphQL endpoints, no frontend, returns JSON |
| CLI Tool | Argument parsers (argparse, cobra, clap), binary entry point |
| Library/SDK | Published as package, exports functions |
| Integration Platform | Connects services, webhook handlers, queue consumers |
| Infrastructure Tool | Manages servers/containers, IaC definitions |

**Map data flows:**
- Entry points: HTTP endpoints, CLI args, file uploads, webhooks, message queues, env vars
- Processing: validation, transformation, business logic, database queries
- Storage: databases, filesystems, caches, external services
- Exit points: API responses, emails, third-party calls, logs

**STRIDE threat model per trust boundary:**
- **S**poofing — Can identity be faked at entry points?
- **T**ampering — Can data be modified in transit or at rest?
- **R**epudiation — Can actions be performed without audit trails?
- **I**nformation Disclosure — Can sensitive data leak?
- **D**enial of Service — Can resources be exhausted through input?
- **E**levation of Privilege — Can a low-privilege user gain higher access?

**Output schema (`app-context.json`):**
```json
{
  "application_type": "web_app|api|cli|library|integration|infrastructure",
  "description": "One-paragraph summary",
  "tech_stack": {"languages": [], "frameworks": [], "databases": [], "infrastructure": []},
  "data_flows": [{"name": "", "entry_point": "", "input_type": "", "trust_boundary_crossing": true}],
  "stride_threats": [{"category": "Spoofing", "threat": "", "severity": "High"}],
  "high_value_assets": [{"asset": "", "sensitivity": "Critical", "location": ""}]
}
```

**Output:** `./grimsec-output/{repo-name}/app-context.json`

## Stage 3: Vulnerability Scanning

**Quick scan:** Trivy (SCA) + Gitleaks (secrets)
**Standard scan (default):** Quick + Semgrep (SAST, `p/default` + `p/security-audit`) + Trivy IaC + Snyk SCA
**Deep scan:** Standard + Semgrep extended rulesets (`p/owasp-top-ten`, `p/cwe-top-25`) + Grype

```bash
# SCA
trivy fs ./source/ --format json --output scan-results/trivy-sca.json

# Secrets
gitleaks detect --source ./source/ --report-format json --report-path scan-results/gitleaks.json

# SAST (standard)
semgrep --config p/default --config p/security-audit --json --output scan-results/semgrep.json ./source/

# IaC
trivy config ./source/ --format json --output scan-results/trivy-iac.json

# SCA (Snyk — requires auth)
cd ./source/ && snyk test --json > ../scan-results/snyk-sca.json

# Secondary SCA (deep)
grype dir:./source/ -o json > scan-results/grype.json
```

**Output:** `./grimsec-output/{repo-name}/scan-results/`

## Stage 4: Reachability & Context Analysis

For each High/Critical finding, determine if it's actually exploitable in this application's context.

**Real Risk Score (1-10):**

| Score | Meaning | Criteria |
|-------|---------|----------|
| 9-10 | Critical | Reachable from unauthenticated external input + high impact + no mitigating controls |
| 7-8 | High | Reachable but requires authentication or specific conditions |
| 5-6 | Medium | Theoretically reachable but significant barriers exist |
| 3-4 | Low | Vulnerable code exists but unreachable in practice |
| 1-2 | Noise | Dead code, test-only, or completely mitigated |

**Analysis for SCA findings:**
1. Identify the vulnerable function/method in the dependency
2. Search the application code: Is that specific function imported and called?
3. Trace call chain: Can it be reached from an external entry point?
4. Check input constraints: Is input validated before reaching vulnerable code?

**Analysis for SAST findings:**
1. Read the flagged code and surrounding ±50 lines
2. Trace the data flow: Where does the tainted input come from?
3. Check for sanitization/validation between input source and vulnerable sink

**Analysis for secrets:**
1. Check if it's a real credential or test/example value
2. Check if it should be gitignored
3. Assess: What access does this secret grant?

**Analysis for IaC findings:**
1. Determine if the misconfiguration applies to production or dev/test
2. Check for compensating controls elsewhere
3. Assess: What's the blast radius if exploited?

**Output:** `./grimsec-output/{repo-name}/reachability-analysis.json`

## Stage 5: Remediation Recommendations

For findings with Real Risk Score ≥ 7:

- **Dependency vulns:** Minimum fix version, breaking change check, specific file edits (package.json, requirements.txt, etc.)
- **Code vulns:** Specific code fix matching project style, before/after blocks
- **Secrets:** Rotation steps, .gitignore additions, git history cleanup (BFG Repo-Cleaner or `git filter-repo`)
- **IaC:** Corrected configuration, security rationale, CIS benchmark reference

**PR mode** (if user requests):
```bash
gh repo fork {owner/repo} --clone=false
git checkout -b security/fix-{cve-id}
# Apply fix
git commit -m "fix(security): remediate {CVE-ID} in {component}"
gh pr create --title "fix(security): remediate {CVE-ID}" --body "..."
```

**Output:** `./grimsec-output/{repo-name}/remediation.json`

## Stage 6: Assessment Report

Report sections:
1. **Executive Summary** — application type, scan date, key metrics, overall risk posture
2. **Application Profile** — what the app is, tech stack, architecture overview
3. **Threat Model Summary** — top STRIDE threats mapped to actual findings
4. **Findings Overview** — all findings sorted by Real Risk Score (descending)
5. **Critical & High Risk (Score ≥ 7)** — detailed analysis, exploitation scenarios, remediation
6. **Noise Analysis** — before/after comparison (raw scanner output vs. contextualized)
7. **Remediation Roadmap** — prioritized fixes with effort estimates
8. **Appendix** — full scanner outputs, methodology notes

**Output:** `./grimsec-output/{repo-name}/assessment-report.md`

## Output Structure

```
grimsec-output/{repo-name}/
├── source/                    # Cloned repository
├── inventory.json             # Stage 1
├── app-context.json           # Stage 2
├── scan-results/              # Stage 3
│   ├── trivy-sca.json
│   ├── gitleaks.json
│   ├── semgrep.json
│   ├── trivy-iac.json
│   ├── snyk-sca.json
│   └── summary.json
├── reachability-analysis.json # Stage 4
├── remediation.json           # Stage 5
└── assessment-report.md       # Stage 6
```

## Important Notes

- **Verify before claiming.** Never assume a function is or isn't called — search for evidence and cite file/line.
- **Err on caution with Real Risk Scores.** If uncertain, score higher and note the uncertainty.
- **Secrets in public repos are compromised.** Always recommend rotation.
- **Rate limiting.** When analyzing many repos in sequence, space out GitHub API calls.
