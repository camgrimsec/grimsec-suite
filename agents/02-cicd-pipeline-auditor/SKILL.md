---
name: cicd-pipeline-auditor
description: "Audits GitHub Actions CI/CD workflow files for supply chain and pipeline security risks. Use when asked to audit, analyze, scan, or review GitHub Actions workflows, .github/workflows/, CI/CD pipelines, pipeline security, or DevSecOps pipeline hardening. Detects unpinned third-party actions (supply chain attacks like tj-actions CVE-2025-30066), expression injection / script injection, overly permissive permissions, dangerous triggers (pull_request_target, workflow_run PPE), secrets exposure, and self-hosted runner risks. Part of the GRIMSEC DevSecOps agent suite."
license: MIT
metadata:
  author: cambamwham2
  version: '1.0'
  suite: GRIMSEC
  related_skills: devsecops-repo-analyzer, vulnerability-context-enricher
---

# CI/CD Pipeline Security Auditor

## When to Use This Skill

Use this skill when asked to:

- Audit or review GitHub Actions workflow files
- Scan `.github/workflows/` for security risks
- Detect supply chain attack vectors in CI/CD pipelines
- Find expression injection / script injection vulnerabilities
- Check for dangerous triggers like `pull_request_target`
- Assess pipeline permission hygiene
- Detect secrets exposure risks in workflows
- Harden CI/CD pipelines as part of a DevSecOps review
- Investigate whether a repo is vulnerable to Poisoned Pipeline Execution (PPE) attacks

## Overview

This skill runs a structured 6-category security audit against all GitHub Actions workflow files in a repository's `.github/workflows/` directory. It uses the bundled `scripts/audit-workflows.py` script to produce:

1. A structured JSON report (machine-readable, suitable for downstream tooling)
2. A human-readable Markdown summary

The audit covers the same risk categories exploited in real-world supply chain attacks, including the tj-actions/changed-files incident (CVE-2025-30066) and the Shai Hulud campaign.

For background on the attack techniques, load `references/github-actions-risks.md` before beginning.

## Instructions

### Step 1 – Locate Workflow Files

Identify the target repository path (or clone it first if given a URL):

```bash
# If working locally
find /path/to/repo/.github/workflows -name "*.yml" -o -name "*.yaml"

# If given a GitHub URL, clone first
git clone https://github.com/owner/repo /tmp/target-repo
```

If no `.github/workflows/` directory exists, report that no workflows were found and stop.

### Step 2 – Install Dependencies

```bash
pip install -q pyyaml
```

### Step 3 – Run the Audit Script

```bash
python3 /home/user/workspace/skills/cicd-pipeline-auditor/scripts/audit-workflows.py \
  /path/to/repo \
  --output /path/to/output/ \
  --repo owner/repo
```

The script will produce:
- `audit-report.json` — full structured findings
- `audit-summary.md` — readable markdown summary

Both files are written to the `--output` directory.

### Step 4 – Interpret Results

Read the JSON report and parse findings by severity:

| Severity | Meaning |
|----------|---------|
| CRITICAL | Immediate supply chain or code execution risk |
| HIGH | Exploitable with moderate attacker access |
| MEDIUM | Defense-in-depth gap, should be fixed |
| LOW | Best practice deviation |

Key fields in each finding:
- `id` — unique finding identifier (e.g., `CICD-001`)
- `category` — one of: `unpinned_action`, `expression_injection`, `overpermissive_permissions`, `dangerous_trigger`, `secrets_exposure`, `self_hosted_runner`
- `workflow_file` — relative path to the affected workflow
- `line` — line number of the finding (0 if not line-specific)
- `current` — the vulnerable snippet as written
- `recommended` — the remediated form
- `reference` — link to authoritative guidance

### Step 5 – Generate Findings Report

After the script runs, read and present the `audit-summary.md` to the user. Highlight:

1. **CRITICAL findings first** — these need immediate remediation
2. **Supply chain exposure** — unpinned third-party actions
3. **PPE risk** — dangerous trigger combinations
4. **Quick wins** — permissions and runner flags that are easy to fix

### Step 6 – Score and Prioritize

Use this prioritization order:
1. CRITICAL unpinned third-party actions (direct supply chain vector)
2. HIGH expression injection (direct code execution via PR title/body)
3. HIGH dangerous triggers with checkout (PPE attack surface)
4. HIGH secrets exposure
5. MEDIUM permissions hygiene
6. MEDIUM self-hosted runners
7. MEDIUM GitHub-owned unpinned actions

### Step 7 – Recommend Fixes

For each CRITICAL or HIGH finding, provide the specific remediated YAML snippet:

**Unpinned action fix:**
```yaml
# Before (vulnerable)
- uses: tj-actions/changed-files@v44

# After (pinned to immutable SHA)
- uses: tj-actions/changed-files@d6babd6899969df1a11d14c368283ea4436bca78 # v44
```

**Expression injection fix:**
```yaml
# Before (vulnerable)
- run: echo "${{ github.event.pull_request.title }}"

# After (safe via env var)
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```

**Permissions fix:**
```yaml
# Before (vulnerable - implicit write-all)
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest

# After (explicit least-privilege)
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
```

**Dangerous trigger fix:**
```yaml
# Before (vulnerable - pull_request_target with checkout of PR code)
on:
  pull_request_target:
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

# After (use pull_request instead, or isolate with no secrets access)
on:
  pull_request:
```

### Step 8 – Optional: Create a Fix PR

If the user wants automated fixes applied:

1. Check out the repository on a new branch: `git checkout -b fix/cicd-security-hardening`
2. Apply the recommended fixes to each workflow file
3. Commit with descriptive messages per file
4. Push and open a PR

Only apply fixes the user explicitly approves. Do NOT auto-apply fixes without confirmation.

## Check Category Reference

### Category 1: Unpinned Third-Party Actions (CICD-001 series)
- Detection: `uses:` value contains `@` followed by a non-SHA ref (tag, branch name)
- SHA pattern: exactly 40 hex characters
- GitHub-owned: prefix matches `actions/`, `github/` → MEDIUM
- Third-party: all others → CRITICAL
- Reference: CVE-2025-30066 (tj-actions/changed-files supply chain attack)

### Category 2: Expression Injection (CICD-002 series)
- Detection: `run:` block contains `${{` followed by any of:
  - `github.event.pull_request.title`
  - `github.event.pull_request.body`
  - `github.event.issue.title`
  - `github.event.comment.body`
  - `github.head_ref`
  - `github.event.inputs.*`
- Severity: HIGH
- Fix: Always pass via `env:` block, never interpolate directly

### Category 3: Overly Permissive Permissions (CICD-003 series)
- Detection:
  - `permissions: write-all` → MEDIUM
  - No `permissions:` key at workflow or job level → MEDIUM
  - `permissions: read-all` is safe (no finding)
  - Job-level `write` permissions for `contents`, `pull-requests`, `packages`, `id-token` → flag if unnecessary
- Severity: MEDIUM

### Category 4: Dangerous Triggers (CICD-004 series)
- `pull_request_target` with checkout of PR head → HIGH
- `pull_request_target` alone → MEDIUM
- `workflow_run` with checkout of triggering PR code → HIGH
- `workflow_run` alone → LOW
- Severity: HIGH or MEDIUM depending on combination

### Category 5: Secrets Exposure (CICD-005 series)
- Secrets as CLI args: `run:` contains `${{ secrets.` not inside an `env:` block → HIGH
- `ACTIONS_RUNNER_DEBUG: true` in env → MEDIUM
- Secrets in step names or echo commands → HIGH
- Severity: HIGH or MEDIUM

### Category 6: Self-Hosted Runners (CICD-006 series)
- `runs-on: self-hosted` or `runs-on: [self-hosted, ...]` → MEDIUM
- Combined with `pull_request_target` or untrusted code execution → escalate to HIGH
- Severity: MEDIUM (standalone), HIGH (with dangerous trigger)

## Output Format

The JSON report follows this schema:

```json
{
  "repo": "owner/repo",
  "scan_timestamp": "2026-03-23T22:51:00Z",
  "workflow_count": 5,
  "total_findings": 23,
  "by_severity": {"CRITICAL": 3, "HIGH": 8, "MEDIUM": 10, "LOW": 2},
  "findings": [...],
  "summary_stats": {
    "total_workflows": 5,
    "total_actions_used": 18,
    "pinned_actions": 3,
    "unpinned_actions": 15,
    "pin_rate": "16.7%",
    "dangerous_triggers": 1,
    "expression_injections": 2,
    "overpermissive_workflows": 3
  }
}
```

## Integration with GRIMSEC Suite

This skill fits into the GRIMSEC pipeline as follows:

```
devsecops-repo-analyzer     → Full repo vulnerability pipeline (deps, SCA, SAST)
cicd-pipeline-auditor       → CI/CD workflow security (this skill)
vulnerability-context-enricher → CVE intelligence enrichment for findings
```

Run this skill after `devsecops-repo-analyzer` to cover the CI/CD attack surface that SCA/SAST tools miss. Feed CRITICAL findings into `vulnerability-context-enricher` if CVE IDs are associated (e.g., CVE-2025-30066).

## References

- `references/github-actions-risks.md` — Detailed attack technique writeups and real-world examples
- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [CVE-2025-30066 — tj-actions/changed-files](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)
- [Poisoned Pipeline Execution (Cider Security)](https://www.cidersecurity.io/blog/research/ppe-poisoned-pipeline-execution/)
