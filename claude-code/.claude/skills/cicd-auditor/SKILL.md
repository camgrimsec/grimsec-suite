# CI/CD Pipeline Security Auditor

Structured 6-category security audit against all GitHub Actions workflow files. Covers the same risk categories exploited in real-world supply chain attacks, including tj-actions/changed-files (CVE-2025-30066).

Invoke with `/cicd-auditor` or phrases like "audit GitHub Actions workflows", "CI/CD security review".

## When to Use

- Audit or review GitHub Actions workflow files
- Scan `.github/workflows/` for security risks
- Detect supply chain attack vectors in CI/CD pipelines
- Find expression injection / script injection vulnerabilities
- Check for dangerous triggers like `pull_request_target`
- Investigate Poisoned Pipeline Execution (PPE) vulnerability

## Instructions

### Step 1 – Locate Workflow Files

```bash
find /path/to/repo/.github/workflows -name "*.yml" -o -name "*.yaml"
```

If no `.github/workflows/` directory exists, report no workflows found and stop.

### Step 2 – Install Dependencies

```bash
pip install pyyaml
```

### Step 3 – Audit Script

Run the audit against each workflow file, checking all 6 categories:

```python
import yaml, os, json

def audit_workflows(repo_path):
    findings = []
    workflows_dir = os.path.join(repo_path, '.github', 'workflows')
    for fname in os.listdir(workflows_dir):
        if fname.endswith(('.yml', '.yaml')):
            with open(os.path.join(workflows_dir, fname)) as f:
                wf = yaml.safe_load(f)
            findings.extend(check_workflow(fname, wf))
    return findings
```

### Step 4 – Severity Scale

| Severity | Meaning |
|----------|---------|
| CRITICAL | Immediate supply chain or code execution risk |
| HIGH | Exploitable with moderate attacker access |
| MEDIUM | Defense-in-depth gap, should be fixed |
| LOW | Best practice deviation |

### Step 5 – Prioritization Order

1. CRITICAL unpinned third-party actions
2. HIGH expression injection
3. HIGH dangerous triggers with checkout
4. HIGH secrets exposure
5. MEDIUM permissions hygiene
6. MEDIUM self-hosted runners
7. MEDIUM GitHub-owned unpinned actions

### Step 6 – Recommend Fixes

For each CRITICAL or HIGH finding, provide the specific remediated YAML snippet.

### Step 7 – Optional PR

If user wants fixes applied:
1. `git checkout -b fix/cicd-security-hardening`
2. Apply fixes
3. Commit and create PR

Only apply fixes the user explicitly approves.

## 6-Category Check Reference

### Category 1: Unpinned Third-Party Actions (CICD-001)

Detection: `uses:` value contains `@` followed by a non-SHA ref.
- SHA pattern: exactly 40 hex characters
- Third-party (not `actions/`, `github/`) → CRITICAL
- GitHub-owned → MEDIUM

```yaml
# VULNERABLE
- uses: tj-actions/changed-files@v44

# SAFE — SHA-pinned
- uses: tj-actions/changed-files@d6babd6899969df1a11d14c368283ea4436bca78 # v44
```

### Category 2: Expression Injection (CICD-002)

Detection: `run:` block contains `${{` with any of:
- `github.event.pull_request.title`
- `github.event.pull_request.body`
- `github.event.issue.title`
- `github.event.comment.body`
- `github.head_ref`
- `github.event.inputs.*`

```yaml
# VULNERABLE
- run: echo "${{ github.event.pull_request.title }}"

# SAFE
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```

### Category 3: Overly Permissive Permissions (CICD-003)

- `permissions: write-all` → MEDIUM
- No `permissions:` key at workflow or job level → MEDIUM

```yaml
# SAFE — least-privilege
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
```

### Category 4: Dangerous Triggers (CICD-004)

- `pull_request_target` with checkout of PR head → HIGH
- `pull_request_target` alone → MEDIUM
- `workflow_run` with checkout of triggering PR code → HIGH

```yaml
# VULNERABLE
on:
  pull_request_target:
# With checkout: ref: ${{ github.event.pull_request.head.sha }}

# SAFER
on:
  pull_request:
```

### Category 5: Secrets Exposure (CICD-005)

- Secrets as CLI args in `run:` not inside `env:` → HIGH
- `ACTIONS_RUNNER_DEBUG: true` in env → MEDIUM
- Secrets in step names or echo commands → HIGH

### Category 6: Self-Hosted Runners (CICD-006)

- `runs-on: self-hosted` → MEDIUM
- Combined with `pull_request_target` or untrusted code execution → HIGH

## Output Format

```json
{
  "repo": "owner/repo",
  "scan_timestamp": "2024-03-23T22:51:00Z",
  "workflow_count": 5,
  "total_findings": 23,
  "by_severity": {"CRITICAL": 3, "HIGH": 8, "MEDIUM": 10, "LOW": 2},
  "findings": [
    {
      "id": "CICD-001",
      "category": "unpinned_action",
      "workflow_file": ".github/workflows/ci.yml",
      "line": 12,
      "current": "uses: tj-actions/changed-files@v44",
      "recommended": "uses: tj-actions/changed-files@d6babd6899969df1a11d14c368283ea4436bca78 # v44",
      "reference": "https://github.com/advisories/GHSA-mrrh-fwg8-r2c3"
    }
  ]
}
```

## GRIMSEC Integration

Run after `/repo-analyzer` to cover the CI/CD attack surface that SCA/SAST tools miss. Feed CRITICAL findings into `/vuln-enricher` if CVE IDs are associated.

## References

- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [CVE-2025-30066 — tj-actions/changed-files](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)
- [Poisoned Pipeline Execution](https://www.cidersecurity.io/blog/research/ppe-poisoned-pipeline-execution/)
