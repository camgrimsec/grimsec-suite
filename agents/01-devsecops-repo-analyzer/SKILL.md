---
name: devsecops-repo-analyzer
description: >-
  Performs end-to-end DevSecOps security analysis on any GitHub repository.
  Runs a 6-stage pipeline: repo ingestion and inventory, application context
  classification with STRIDE threat modeling, multi-tool vulnerability scanning
  (SAST, SCA via Trivy + Snyk + Grype, secrets, IaC), reachability and context
  analysis that assigns Real Risk Scores, remediation recommendations with
  optional GitHub PR generation, and a final structured assessment report. Use when the user asks
  to analyze a repo for security issues, run a DevSecOps assessment, threat
  model a codebase, check for vulnerabilities, or audit an open source project.
  Triggers include phrases like "analyze this repo", "security scan",
  "vulnerability assessment", "threat model this", "DevSecOps analysis",
  "audit this codebase", or "check this project for security issues".
metadata:
  author: cambamwham2
  version: '1.1'
---

# DevSecOps Repo Analyzer

A 6-stage AI-driven security analysis pipeline that goes far beyond raw scanner output. The key differentiator is **contextual vulnerability analysis** — instead of dumping hundreds of CVEs, this skill determines which vulnerabilities are actually reachable and exploitable in the specific application context.

## When to Use This Skill

Use when the user asks to:
- Analyze a GitHub repository for security vulnerabilities
- Run a DevSecOps assessment on a codebase
- Threat model an application
- Audit an open-source project's security posture
- Check dependencies for known vulnerabilities with real-world context
- Assess the actual risk of vulnerability findings (not just CVSS scores)
- Prepare a security PR for an open-source repo

## Prerequisites

Before starting, install required scanning tools:

```bash
bash /home/user/workspace/skills/devsecops-repo-analyzer/scripts/install-tools.sh
```

This installs Semgrep, Trivy, Grype, Gitleaks, Snyk CLI, and supporting utilities. The script is idempotent — safe to run multiple times.

**Snyk authentication:** Snyk requires an API token. Set the `SNYK_TOKEN` environment variable or run `snyk auth` before scanning. If not authenticated, Snyk scanning is skipped gracefully and other scanners still run. Get a free token at https://app.snyk.io/account.

## Pipeline Overview

```
Stage 1: Repo Scout ──► Stage 2: App Context ──► Stage 3: Vulnerability Scan
                                                          │
                                                          ▼
Stage 6: Report ◄── Stage 5: Remediation ◄── Stage 4: Reachability Analysis
```

Each stage produces artifacts saved to `/home/user/workspace/devsecops-analysis/{repo-name}/`. Stages are sequential — each depends on the output of the previous stage.

## Instructions

### Input

The user provides one of:
- A GitHub repository URL (e.g., `https://github.com/supabase/supabase`)
- An `owner/repo` shorthand (e.g., `supabase/supabase`)
- A local path to an already-cloned repository

Optional parameters the user may specify:
- **Branch or commit** (default: `main` or default branch HEAD)
- **Scan depth**: `quick` (SCA + secrets only), `standard` (all scanners), or `deep` (all scanners + extended Semgrep rulesets). Default: `standard`
- **Skip stages**: User may request only specific stages (e.g., "just threat model it" = stages 1-2 only)
- **PR mode**: Whether to generate remediation PRs (default: report only, no PRs)

### Stage 1: Repo Scout & Ingestion

**Goal:** Clone the repo and build a complete inventory of what's inside.

1. Clone the repository into `/home/user/workspace/devsecops-analysis/{repo-name}/source/`:
   ```bash
   # Use gh CLI if available (handles auth automatically)
   gh repo clone {owner/repo} /home/user/workspace/devsecops-analysis/{repo-name}/source/ -- --depth=1
   # Or fallback to git
   git clone --depth=1 {repo-url} /home/user/workspace/devsecops-analysis/{repo-name}/source/
   ```

2. Run the inventory script:
   ```bash
   python3 /home/user/workspace/skills/devsecops-repo-analyzer/scripts/repo-inventory.py \
     /home/user/workspace/devsecops-analysis/{repo-name}/source/ \
     --output /home/user/workspace/devsecops-analysis/{repo-name}/inventory.json
   ```

3. Review the inventory output. It will contain:
   - Languages detected (with file counts and LOC per language)
   - Package managers and dependency files found
   - Infrastructure files (Dockerfiles, IaC, CI/CD configs)
   - Codebase metrics (total files, total LOC, top directories by size)
   - README summary extraction

4. Save the inventory as `inventory.json` in the analysis directory.

**Output artifact:** `/home/user/workspace/devsecops-analysis/{repo-name}/inventory.json`

### Stage 2: Application Context & Threat Model

**Goal:** Understand what the application actually does, classify it, and build a STRIDE threat model.

Read `references/stride-model.md` for the full STRIDE framework reference.

1. Read the inventory JSON from Stage 1.
2. Read the repository's README, main entry points, and key configuration files to understand the application.
3. Classify the application by examining its structure:

   | Type | Indicators |
   |------|-----------|
   | Web Application | Has frontend frameworks (React, Vue, Angular), serves HTML, has routes/pages |
   | API Service | Has REST/GraphQL endpoints, no frontend, returns JSON |
   | CLI Tool | Has argument parsers (argparse, cobra, clap), binary entry point |
   | Library/SDK | Published as a package, has no standalone entry point, exports functions |
   | Integration Platform | Connects multiple services, has webhook handlers, queue consumers |
   | Infrastructure Tool | Manages servers/containers/networking, has IaC definitions |

4. Map the application's data flows:
   - **Entry points:** Where does external input enter? (HTTP endpoints, CLI args, file uploads, webhooks, message queues, environment variables)
   - **Processing:** What happens to the input? (Validation, transformation, business logic, database queries)
   - **Storage:** Where is data persisted? (Databases, filesystems, caches, external services)
   - **Exit points:** Where does data leave? (API responses, emails, third-party API calls, logs)

5. Identify trust boundaries:
   - External-facing vs. internal-only components
   - Authenticated vs. unauthenticated access
   - Admin vs. user privilege levels
   - Service-to-service communication

6. Build the STRIDE threat model by analyzing each data flow crossing a trust boundary:
   - **S**poofing: Can identity be faked at entry points?
   - **T**ampering: Can data be modified in transit or at rest?
   - **R**epudiation: Can actions be performed without audit trails?
   - **I**nformation Disclosure: Can sensitive data leak through error messages, logs, or side channels?
   - **D**enial of Service: Can resources be exhausted through input manipulation?
   - **E**levation of Privilege: Can a low-privilege user gain higher access?

7. Identify high-value assets:
   - User credential stores, PII databases
   - Payment processing flows
   - Admin interfaces and privileged operations
   - API keys, secrets, tokens in configuration
   - Third-party integrations with broad permissions

8. Save the application context document:

```json
{
  "application_type": "web_app | api | cli | library | integration | infrastructure",
  "description": "One-paragraph summary of what the application does",
  "tech_stack": {
    "languages": ["typescript", "python"],
    "frameworks": ["next.js", "fastapi"],
    "databases": ["postgresql", "redis"],
    "infrastructure": ["docker", "kubernetes"]
  },
  "data_flows": [
    {
      "name": "User Authentication",
      "entry_point": "POST /api/auth/login",
      "input_type": "JSON body (email, password)",
      "processing": "Validates credentials against user table, issues JWT",
      "storage": "PostgreSQL users table, Redis session cache",
      "exit_point": "JWT token in response body + Set-Cookie header",
      "trust_boundary_crossing": true,
      "authentication_required": false
    }
  ],
  "trust_boundaries": [
    {
      "name": "External → Application",
      "description": "All HTTP traffic from the internet hitting the API gateway"
    }
  ],
  "stride_threats": [
    {
      "category": "Spoofing",
      "threat": "Attacker submits forged JWT tokens to impersonate other users",
      "data_flow": "User Authentication",
      "severity": "High",
      "existing_controls": "JWT signature verification with RS256"
    }
  ],
  "high_value_assets": [
    {
      "asset": "User credentials database",
      "sensitivity": "Critical",
      "location": "PostgreSQL users table",
      "access_pattern": "Auth service only"
    }
  ]
}
```

**Output artifact:** `/home/user/workspace/devsecops-analysis/{repo-name}/app-context.json`

### Stage 3: Vulnerability Scanning

**Goal:** Run all scanning tools and collect raw findings.

Run the scanning script which orchestrates all tools:

```bash
python3 /home/user/workspace/skills/devsecops-repo-analyzer/scripts/run-scanners.py \
  /home/user/workspace/devsecops-analysis/{repo-name}/source/ \
  --output-dir /home/user/workspace/devsecops-analysis/{repo-name}/scan-results/ \
  --depth {quick|standard|deep}
```

The script runs the following based on scan depth:

**Quick scan:**
- Trivy (SCA — dependency vulnerabilities)
- Gitleaks (secrets detection)

**Standard scan (default):**
- Everything in Quick, plus:
- Semgrep (SAST — code pattern analysis with `p/default` + `p/security-audit` rulesets)
- Trivy IaC scanning (Dockerfile, Terraform, K8s misconfigs)
- Snyk SCA (proprietary vulnerability database, upgrade paths, exploit intelligence, license compliance)

**Deep scan:**
- Everything in Standard, plus:
- Semgrep with extended rulesets (`p/owasp-top-ten`, `p/cwe-top-25`, language-specific rules)
- Grype (secondary SCA for cross-validation)

After scanning completes, the script produces:
- `scan-results/trivy-sca.json` — dependency vulnerability findings
- `scan-results/gitleaks.json` — leaked secrets findings
- `scan-results/semgrep.json` — SAST findings (standard/deep only)
- `scan-results/trivy-iac.json` — infrastructure misconfigurations (standard/deep only)
- `scan-results/snyk-sca.json` — Snyk SCA findings with fix advice and exploit data (standard/deep, requires auth)
- `scan-results/grype.json` — secondary SCA findings (deep only)
- `scan-results/summary.json` — aggregated counts by severity

Review `scan-results/summary.json` for the high-level picture before proceeding.

**Output artifact:** `/home/user/workspace/devsecops-analysis/{repo-name}/scan-results/`

### Stage 4: Reachability & Context Analysis

**Goal:** For each High/Critical finding, determine if it's actually exploitable in this application's context. This is the stage that transforms noise into signal.

Read `references/real-risk-scoring.md` for the complete scoring methodology.

1. Load the scan results from Stage 3 and the app context from Stage 2.

2. Filter to High and Critical severity findings only (CVSS ≥ 7.0 or Semgrep severity high/error).

3. For each High/Critical finding, perform contextual analysis:

   **For dependency vulnerabilities (SCA findings from Trivy, Snyk, and Grype):**
   a. Identify the vulnerable function/method in the dependency
   b. Search the application code: Is that specific function imported and called?
   c. If called, trace the call chain: Can it be reached from an external entry point identified in the app context?
   d. Check input constraints: Does the application validate/sanitize input before it reaches the vulnerable code?
   e. Cross-reference Snyk data: Check `isUpgradable`, `isPatchable`, `exploit` status, and `fixedIn` versions from Snyk output to enrich remediation advice
   f. Assess: What would an attacker need to do to trigger this vulnerability? Be specific.

   **For code vulnerabilities (SAST findings):**
   a. Read the flagged code and surrounding context (±50 lines)
   b. Trace the data flow: Where does the tainted input come from?
   c. Check for sanitization/validation between the input source and the vulnerable sink
   d. Cross-reference with the threat model: Is this code path on an identified attack surface?
   e. Assess: What's the realistic impact if exploited?

   **For secrets findings:**
   a. Check if the secret is a real credential or a test/example value
   b. Check if it's in a file that should be gitignored
   c. Check if it's been rotated (look at git history for the file)
   d. Assess: What access does this secret grant?

   **For IaC findings:**
   a. Determine if the misconfiguration applies to production or dev/test
   b. Check if there are compensating controls elsewhere in the configuration
   c. Assess: What's the blast radius if exploited?

4. Assign a Real Risk Score (1-10) to each finding using the matrix in `references/real-risk-scoring.md`:

   | Score | Meaning | Criteria |
   |-------|---------|----------|
   | 9-10 | Critical | Reachable from unauthenticated external input + high impact + no mitigating controls |
   | 7-8 | High | Reachable but requires authentication or specific conditions |
   | 5-6 | Medium | Theoretically reachable but significant barriers exist |
   | 3-4 | Low | Vulnerable code exists but is unreachable in practice |
   | 1-2 | Noise | Dead code, test-only, or completely mitigated |

5. For each finding, write a contextual assessment:
   ```json
   {
     "finding_id": "VULN-001",
     "original_source": "trivy-sca",
     "cve_id": "CVE-2024-XXXXX",
     "original_severity": "CRITICAL",
     "affected_component": "lodash@4.17.20",
     "vulnerable_function": "lodash.template()",
     "real_risk_score": 2,
     "reachable": false,
     "context_summary": "lodash.template() is never called in this codebase. The application only imports lodash.get and lodash.merge. This CVE affects the template rendering function which is dead code in this dependency.",
     "exploitation_scenario": "N/A — vulnerable function is not reachable",
     "recommended_action": "Low priority — upgrade lodash to >=4.17.21 during next dependency update cycle",
     "evidence": {
       "search_performed": "grep -r 'template' --include='*.ts' --include='*.js' in source/",
       "calls_found": 0,
       "import_analysis": "Only lodash.get and lodash.merge are imported in 3 files"
     }
   }
   ```

6. Calculate noise reduction metrics:
   - Total raw findings (High + Critical)
   - Findings with Real Risk Score ≥ 7 (actually actionable)
   - Noise reduction percentage: `(1 - actionable/total) × 100`

7. Save the reachability analysis:

**Output artifact:** `/home/user/workspace/devsecops-analysis/{repo-name}/reachability-analysis.json`

### Stage 5: Remediation Recommendations

**Goal:** For findings with Real Risk Score ≥ 7, generate specific fix recommendations. Optionally create GitHub PRs.

1. Load the reachability analysis from Stage 4. Filter to findings with Real Risk Score ≥ 7.

2. For each actionable finding, generate a remediation recommendation:

   **For dependency vulnerabilities:**
   - Identify the minimum version that fixes the CVE
   - Check if upgrading introduces breaking changes (check changelogs, major version bumps)
   - If the vulnerable function is used, suggest code-level mitigations as interim fixes
   - Generate the specific file edit (package.json, requirements.txt, etc.)

   **For code vulnerabilities:**
   - Generate a specific code fix with explanation
   - Ensure the fix follows the project's existing code style
   - Include before/after code blocks

   **For secrets:**
   - Recommend rotation and the specific steps to rotate for that service
   - Suggest adding the file pattern to .gitignore
   - Recommend git history cleanup if needed (BFG Repo-Cleaner or git filter-repo)

   **For IaC findings:**
   - Generate the corrected configuration
   - Explain the security implication and reference the relevant benchmark (CIS, etc.)

3. **If PR mode is enabled** (user explicitly requested PRs):

   Read `references/pr-template.md` for the PR format.

   a. Fork the repository (or use existing fork):
      ```bash
      gh repo fork {owner/repo} --clone=false
      ```
   b. Create a branch:
      ```bash
      git checkout -b security/fix-{cve-id}
      ```
   c. Apply the fix
   d. Commit with a conventional commit message:
      ```
      fix(security): remediate {CVE-ID} in {component}
      ```
   e. Push and create the PR using the template from `references/pr-template.md`
   f. Record the PR URL

4. Save remediation recommendations:

**Output artifact:** `/home/user/workspace/devsecops-analysis/{repo-name}/remediation.json`

### Stage 6: Assessment Report

**Goal:** Compile all findings into a professional, readable security assessment report.

1. Load all artifacts from previous stages.

2. Generate the assessment report using the template structure in `assets/templates/report-template.md`.

3. The report must include these sections:
   - **Executive Summary**: Application type, scan date, key metrics (total findings, actionable findings, noise reduction percentage), overall risk posture
   - **Application Profile**: From Stage 2 — what the app is, tech stack, architecture overview
   - **Threat Model Summary**: Top threats identified via STRIDE, mapped to actual findings
   - **Findings Overview**: Table of all findings sorted by Real Risk Score (descending)
   - **Critical & High Risk Findings (Score ≥ 7)**: Detailed analysis for each, including exploitation scenario, evidence, and remediation
   - **Noise Analysis**: Before/after comparison showing raw scanner output vs. contextualized findings
   - **Remediation Roadmap**: Prioritized list of recommended fixes with effort estimates
   - **Appendix**: Full scanner outputs, methodology notes

4. Save the report as Markdown:

**Output artifact:** `/home/user/workspace/devsecops-analysis/{repo-name}/assessment-report.md`

5. Share the report with the user via `share_file`.

## Output Summary

After a complete run, the analysis directory contains:

```
devsecops-analysis/{repo-name}/
├── source/                      # Cloned repository
├── inventory.json               # Stage 1: Repo inventory
├── app-context.json             # Stage 2: Application context + threat model
├── scan-results/                # Stage 3: Raw scanner outputs
│   ├── trivy-sca.json
│   ├── gitleaks.json
│   ├── semgrep.json
│   ├── trivy-iac.json
│   ├── snyk-sca.json (standard/deep, requires SNYK_TOKEN)
│   ├── grype.json (deep only)
│   └── summary.json
├── reachability-analysis.json   # Stage 4: Contextualized findings
├── remediation.json             # Stage 5: Fix recommendations
└── assessment-report.md         # Stage 6: Final report
```

## Important Notes

- **Be respectful of open-source maintainers.** When analyzing public repos, position findings as collaborative contributions, not adversarial attacks. PRs should be professional, well-documented, and genuinely helpful.
- **Verify before claiming.** When assessing reachability, always check the actual code. Never assume a function is or isn't called — search for evidence and cite the specific files/lines.
- **Err on the side of caution with Real Risk Scores.** If you're uncertain whether a vulnerability is reachable, score it higher (not lower) and note the uncertainty.
- **Secrets found in public repos should be treated as compromised.** Always recommend rotation regardless of whether the secret appears to be a test value.
- **Rate limiting.** If analyzing many repos in sequence, space out GitHub API calls and scanning operations to avoid hitting rate limits.
