#!/usr/bin/env python3
"""
audit-workflows.py — CI/CD Pipeline Security Auditor
Part of the GRIMSEC DevSecOps agent suite.

Usage:
    python3 audit-workflows.py /path/to/repo --output /path/to/output/ [--repo owner/repo]

Detects:
    1. Unpinned third-party actions (supply chain risk)
    2. Expression injection / script injection
    3. Overly permissive permissions
    4. Dangerous workflow triggers (pull_request_target, workflow_run PPE)
    5. Secrets exposure risks
    6. Self-hosted runner risks
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
TAG_PATTERN = re.compile(r"^(?:v\d[\w.\-]*|main|master|latest|develop|HEAD|[\w.\-]+)$")

GITHUB_OWNED_PREFIXES = ("actions/", "github/")

# Dangerous user-controlled context expressions
DANGEROUS_CONTEXTS = [
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.issue\.title",
    r"github\.event\.comment\.body",
    r"github\.head_ref",
    r"github\.event\.inputs\.[^\s}]+",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.discussion\.body",
    r"github\.event\.discussion\.title",
]

DANGEROUS_CONTEXT_PATTERN = re.compile(
    r"\$\{\{\s*(?:" + "|".join(DANGEROUS_CONTEXTS) + r")\s*\}\}",
    re.IGNORECASE,
)

WRITE_PERMISSIONS = {
    "contents": "write",
    "pull-requests": "write",
    "packages": "write",
    "id-token": "write",
    "issues": "write",
    "deployments": "write",
    "security-events": "write",
    "statuses": "write",
    "checks": "write",
}

SECRETS_IN_RUN_PATTERN = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------

class FindingCounter:
    def __init__(self):
        self._counts = {}

    def next_id(self, prefix: str) -> str:
        self._counts[prefix] = self._counts.get(prefix, 0) + 1
        return f"{prefix}-{self._counts[prefix]:03d}"


counter = FindingCounter()


def make_finding(
    prefix: str,
    category: str,
    severity: str,
    workflow_file: str,
    line: int,
    description: str,
    current: str,
    recommended: str,
    reference: str,
) -> dict:
    return {
        "id": counter.next_id(prefix),
        "category": category,
        "severity": severity,
        "workflow_file": workflow_file,
        "line": line,
        "description": description,
        "current": current,
        "recommended": recommended,
        "reference": reference,
    }


# ---------------------------------------------------------------------------
# YAML loader with line tracking
# ---------------------------------------------------------------------------

def load_workflow(path: Path):
    """Load a YAML workflow file. Returns (data, raw_lines, error_string)."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(raw)
        return data, raw.splitlines(), None
    except yaml.YAMLError as exc:
        return None, [], f"YAML parse error: {exc}"
    except Exception as exc:
        return None, [], f"Read error: {exc}"


def find_line(raw_lines: list, snippet: str) -> int:
    """Return 1-based line number of first occurrence of snippet, or 0."""
    for i, line in enumerate(raw_lines, start=1):
        if snippet in line:
            return i
    return 0


# ---------------------------------------------------------------------------
# Check 1: Unpinned Actions
# ---------------------------------------------------------------------------

def check_unpinned_actions(data: dict, raw_lines: list, rel_path: str) -> list:
    findings = []
    if not isinstance(data, dict):
        return findings

    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return findings

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            if not uses or "@" not in uses:
                continue

            action, ref = uses.rsplit("@", 1)
            ref = ref.strip()

            if SHA_PATTERN.match(ref):
                # Pinned — safe
                continue

            is_github_owned = any(action.startswith(p) for p in GITHUB_OWNED_PREFIXES)

            if is_github_owned:
                severity = "MEDIUM"
                description = (
                    f"GitHub-owned action '{uses}' referenced by mutable tag '{ref}'. "
                    "Should be pinned to a commit SHA for reproducibility."
                )
                reference = "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
            else:
                severity = "CRITICAL"
                description = (
                    f"Third-party action '{uses}' referenced by mutable tag '{ref}'. "
                    "A compromised tag can execute arbitrary code in your pipeline. "
                    "See CVE-2025-30066 (tj-actions/changed-files supply chain attack)."
                )
                reference = "https://github.com/advisories/GHSA-mrrh-fwg8-r2c3 — Pin to immutable commit SHA"

            line_no = find_line(raw_lines, uses)
            findings.append(make_finding(
                prefix="CICD-001",
                category="unpinned_action",
                severity=severity,
                workflow_file=rel_path,
                line=line_no,
                description=description,
                current=uses,
                recommended=f"{action}@<40-char-commit-sha> # {ref}",
                reference=reference,
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 2: Expression Injection
# ---------------------------------------------------------------------------

def check_expression_injection(data: dict, raw_lines: list, rel_path: str) -> list:
    findings = []
    if not isinstance(data, dict):
        return findings

    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return findings

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            run_block = step.get("run", "")
            if not run_block:
                continue

            matches = DANGEROUS_CONTEXT_PATTERN.findall(run_block)
            if not matches:
                continue

            # Find the first problematic expression for line lookup
            first_expr = re.search(r"\$\{\{[^}]+\}\}", run_block)
            expr_str = first_expr.group(0) if first_expr else "${{ <expression> }}"
            line_no = find_line(raw_lines, expr_str) or find_line(raw_lines, "run:")

            description = (
                f"User-controlled GitHub context expression interpolated directly into "
                f"a 'run:' step in job '{job_name}'. An attacker can craft a PR title, "
                f"body, or comment to inject arbitrary shell commands. "
                f"Expressions found: {', '.join(set(matches))}"
            )

            # Extract just the matched expression for current/recommended
            current_expr = matches[0] if matches else expr_str
            # Extract context var name
            ctx_match = re.search(r"\$\{\{\s*([^\s}]+)\s*\}\}", current_expr)
            ctx_var = ctx_match.group(1).strip() if ctx_match else "github.event.VALUE"
            env_var_name = re.sub(r"[^A-Z0-9]", "_", ctx_var.upper())

            findings.append(make_finding(
                prefix="CICD-002",
                category="expression_injection",
                severity="HIGH",
                workflow_file=rel_path,
                line=line_no,
                description=description,
                current=f"run: ... {current_expr} ...",
                recommended=(
                    f"env:\n  {env_var_name}: {current_expr}\n"
                    f"run: ... ${env_var_name} ..."
                ),
                reference=(
                    "https://docs.github.com/en/actions/security-guides/"
                    "security-hardening-for-github-actions#understanding-the-risk-of-script-injections"
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 3: Overly Permissive Permissions
# ---------------------------------------------------------------------------

def check_permissions(data: dict, raw_lines: list, rel_path: str) -> list:
    findings = []
    if not isinstance(data, dict):
        return findings

    wf_perms = data.get("permissions")

    # Case 1: explicit write-all
    if wf_perms == "write-all":
        line_no = find_line(raw_lines, "write-all")
        findings.append(make_finding(
            prefix="CICD-003",
            category="overpermissive_permissions",
            severity="MEDIUM",
            workflow_file=rel_path,
            line=line_no,
            description=(
                "Workflow uses 'permissions: write-all', granting write access to all "
                "GitHub API scopes. If the workflow is compromised, an attacker gains "
                "broad repository write access."
            ),
            current="permissions: write-all",
            recommended="permissions: read-all  # Grant write only where explicitly needed at job level",
            reference=(
                "https://docs.github.com/en/actions/security-guides/"
                "security-hardening-for-github-actions#using-permissions-for-the-github_token"
            ),
        ))
        return findings

    # Case 2: no permissions specified at all (defaults to write on many scopes)
    if wf_perms is None:
        # Check if there's a permissions key anywhere at job level
        jobs = data.get("jobs", {})
        has_any_permissions = False
        if isinstance(jobs, dict):
            for job in jobs.values():
                if isinstance(job, dict) and "permissions" in job:
                    has_any_permissions = True
                    break

        if not has_any_permissions:
            findings.append(make_finding(
                prefix="CICD-003",
                category="overpermissive_permissions",
                severity="MEDIUM",
                workflow_file=rel_path,
                line=0,
                description=(
                    "Workflow does not specify 'permissions:', defaulting to broad "
                    "write access on many scopes (repository-dependent). Explicitly "
                    "declare least-privilege permissions."
                ),
                current="(no permissions key)",
                recommended=(
                    "permissions:\n  contents: read\n"
                    "# Add specific write permissions only where needed"
                ),
                reference=(
                    "https://docs.github.com/en/actions/security-guides/"
                    "security-hardening-for-github-actions#using-permissions-for-the-github_token"
                ),
            ))
        return findings

    # Case 3: dict permissions — flag specific write grants
    if isinstance(wf_perms, dict):
        for scope, level in wf_perms.items():
            if level == "write" and scope in WRITE_PERMISSIONS:
                line_no = find_line(raw_lines, f"{scope}: write")
                findings.append(make_finding(
                    prefix="CICD-003",
                    category="overpermissive_permissions",
                    severity="MEDIUM",
                    workflow_file=rel_path,
                    line=line_no,
                    description=(
                        f"Workflow grants '{scope}: write' at the workflow level. "
                        f"Move write grants to specific jobs that require them."
                    ),
                    current=f"{scope}: write",
                    recommended=f"# Move to specific job level:\njobs:\n  my-job:\n    permissions:\n      {scope}: write",
                    reference=(
                        "https://docs.github.com/en/actions/security-guides/"
                        "security-hardening-for-github-actions#using-permissions-for-the-github_token"
                    ),
                ))

    return findings


# ---------------------------------------------------------------------------
# Check 4: Dangerous Triggers
# ---------------------------------------------------------------------------

def _workflow_checks_out_pr_code(data: dict) -> bool:
    """Heuristic: does this workflow checkout PR head SHA / head_ref?"""
    jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
    if not isinstance(jobs, dict):
        return False
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []):
            if not isinstance(step, dict):
                continue
            # Check for checkout with PR ref
            uses = step.get("uses", "")
            withs = step.get("with", {}) or {}
            if "checkout" in uses.lower():
                ref_val = str(withs.get("ref", ""))
                if any(x in ref_val for x in ["head.sha", "head_ref", "head_commit", "pull_request.head"]):
                    return True
            # Check run for git checkout of PR
            run = step.get("run", "")
            if run and any(x in run for x in ["head.sha", "head_ref", "pull_request.head"]):
                return True
    return False


def check_dangerous_triggers(data: dict, raw_lines: list, rel_path: str) -> list:
    findings = []
    if not isinstance(data, dict):
        return findings

    on_val = data.get("on", data.get(True, None))  # 'on' is parsed as True in some YAML parsers
    if on_val is None:
        return findings

    triggers = set()
    if isinstance(on_val, str):
        triggers.add(on_val)
    elif isinstance(on_val, list):
        triggers.update(on_val)
    elif isinstance(on_val, dict):
        triggers.update(on_val.keys())

    checkouts_pr = _workflow_checks_out_pr_code(data)

    if "pull_request_target" in triggers:
        if checkouts_pr:
            severity = "HIGH"
            description = (
                "Workflow uses 'pull_request_target' trigger AND checks out PR head code. "
                "This is a critical Poisoned Pipeline Execution (PPE) vector: the workflow "
                "runs with secrets access in the context of the base branch while executing "
                "attacker-controlled code from the fork PR."
            )
            recommended = (
                "Option 1: Use 'pull_request' trigger (no secrets access, safer for forks).\n"
                "Option 2: If secrets are needed, do NOT checkout untrusted PR code in the same job."
            )
        else:
            severity = "MEDIUM"
            description = (
                "Workflow uses 'pull_request_target' trigger. This trigger runs with base-branch "
                "secrets access, making it a potential PPE target if PR code is ever checked out. "
                "Audit carefully that no steps process untrusted fork content."
            )
            recommended = (
                "Use 'pull_request' unless secrets are explicitly needed for fork PRs. "
                "If you must use pull_request_target, never checkout the PR head ref in the same job."
            )

        line_no = find_line(raw_lines, "pull_request_target")
        findings.append(make_finding(
            prefix="CICD-004",
            category="dangerous_trigger",
            severity=severity,
            workflow_file=rel_path,
            line=line_no,
            description=description,
            current="on: pull_request_target",
            recommended=recommended,
            reference="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        ))

    if "workflow_run" in triggers:
        if checkouts_pr:
            severity = "HIGH"
            description = (
                "Workflow uses 'workflow_run' trigger AND checks out PR code from the triggering run. "
                "This can enable PPE if the triggering workflow processes untrusted fork input. "
                "The workflow_run trigger has access to secrets even for fork-triggered runs."
            )
        else:
            severity = "LOW"
            description = (
                "Workflow uses 'workflow_run' trigger. Verify that no steps in this workflow "
                "process artifacts or code from untrusted fork pull requests, as this trigger "
                "has secrets access."
            )

        line_no = find_line(raw_lines, "workflow_run")
        findings.append(make_finding(
            prefix="CICD-004",
            category="dangerous_trigger",
            severity=severity,
            workflow_file=rel_path,
            line=line_no,
            description=description,
            current="on: workflow_run",
            recommended=(
                "Ensure workflow_run jobs do not checkout or execute code from untrusted PRs. "
                "Use artifact download patterns, not git checkout."
            ),
            reference="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 5: Secrets Exposure
# ---------------------------------------------------------------------------

def check_secrets_exposure(data: dict, raw_lines: list, rel_path: str) -> list:
    findings = []
    if not isinstance(data, dict):
        return findings

    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return findings

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        # Check job-level env for ACTIONS_RUNNER_DEBUG
        job_env = job.get("env", {}) or {}
        if isinstance(job_env, dict) and job_env.get("ACTIONS_RUNNER_DEBUG") == "true":
            line_no = find_line(raw_lines, "ACTIONS_RUNNER_DEBUG")
            findings.append(make_finding(
                prefix="CICD-005",
                category="secrets_exposure",
                severity="MEDIUM",
                workflow_file=rel_path,
                line=line_no,
                description=(
                    f"Job '{job_name}' has ACTIONS_RUNNER_DEBUG enabled. "
                    "This causes all secret values to be printed in runner debug logs, "
                    "which are visible to anyone with read access to the repository."
                ),
                current="ACTIONS_RUNNER_DEBUG: true",
                recommended="Remove ACTIONS_RUNNER_DEBUG or restrict to non-production environments",
                reference="https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/enabling-debug-logging",
            ))

        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue

            # Check step-level env for ACTIONS_RUNNER_DEBUG
            step_env = step.get("env", {}) or {}
            if isinstance(step_env, dict) and step_env.get("ACTIONS_RUNNER_DEBUG") == "true":
                line_no = find_line(raw_lines, "ACTIONS_RUNNER_DEBUG")
                findings.append(make_finding(
                    prefix="CICD-005",
                    category="secrets_exposure",
                    severity="MEDIUM",
                    workflow_file=rel_path,
                    line=line_no,
                    description=(
                        "ACTIONS_RUNNER_DEBUG enabled at step level. "
                        "This prints all secret values in debug logs visible to repository readers."
                    ),
                    current="ACTIONS_RUNNER_DEBUG: true",
                    recommended="Remove ACTIONS_RUNNER_DEBUG from step env",
                    reference="https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/enabling-debug-logging",
                ))

            run_block = step.get("run", "")
            if not run_block:
                continue

            # Find secrets used directly in run: (not via env:)
            secret_refs = SECRETS_IN_RUN_PATTERN.findall(run_block)
            if not secret_refs:
                continue

            # Check if these secrets are defined in the step's env block (safe pattern)
            defined_in_env = set()
            if isinstance(step_env, dict):
                for env_key, env_val in step_env.items():
                    if isinstance(env_val, str) and "${{ secrets." in env_val:
                        defined_in_env.add(env_val.strip())

            # Only flag secrets that are directly in run: and NOT in env:
            exposed = [s for s in secret_refs if s not in defined_in_env]
            if not exposed:
                continue

            line_no = find_line(raw_lines, exposed[0]) or find_line(raw_lines, "run:")
            findings.append(make_finding(
                prefix="CICD-005",
                category="secrets_exposure",
                severity="HIGH",
                workflow_file=rel_path,
                line=line_no,
                description=(
                    f"Secret(s) interpolated directly into a 'run:' command as CLI arguments "
                    f"in job '{job_name}'. Secrets passed as command arguments are visible in "
                    f"process listings and may be captured in shell history or error output. "
                    f"Secrets found: {', '.join(set(exposed))}"
                ),
                current=f"run: command {exposed[0]}",
                recommended=(
                    f"env:\n  MY_SECRET: {exposed[0]}\n"
                    f"run: command $MY_SECRET"
                ),
                reference="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets",
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 6: Self-Hosted Runners
# ---------------------------------------------------------------------------

def check_self_hosted_runners(data: dict, raw_lines: list, rel_path: str) -> list:
    findings = []
    if not isinstance(data, dict):
        return findings

    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return findings

    # Check for dangerous triggers to escalate severity
    on_val = data.get("on", data.get(True, None))
    has_dangerous_trigger = False
    if on_val:
        triggers = set()
        if isinstance(on_val, str):
            triggers.add(on_val)
        elif isinstance(on_val, list):
            triggers.update(on_val)
        elif isinstance(on_val, dict):
            triggers.update(on_val.keys())
        has_dangerous_trigger = "pull_request_target" in triggers or "workflow_run" in triggers

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        runs_on = job.get("runs-on", "")
        is_self_hosted = False

        if isinstance(runs_on, str) and "self-hosted" in runs_on:
            is_self_hosted = True
        elif isinstance(runs_on, list) and "self-hosted" in runs_on:
            is_self_hosted = True

        if not is_self_hosted:
            continue

        line_no = find_line(raw_lines, "self-hosted")

        if has_dangerous_trigger:
            severity = "HIGH"
            description = (
                f"Job '{job_name}' uses a self-hosted runner AND the workflow has a dangerous "
                f"trigger (pull_request_target or workflow_run). A fork PR can execute "
                f"attacker code directly on your self-hosted runner, enabling network pivoting "
                f"into internal infrastructure."
            )
        else:
            severity = "MEDIUM"
            description = (
                f"Job '{job_name}' uses a self-hosted runner ('runs-on: self-hosted'). "
                "Self-hosted runners persist between runs and can be targeted to pivot into "
                "internal networks. If untrusted code (e.g., from fork PRs) runs on this "
                "runner, the internal network is at risk."
            )

        findings.append(make_finding(
            prefix="CICD-006",
            category="self_hosted_runner",
            severity=severity,
            workflow_file=rel_path,
            line=line_no,
            description=description,
            current=f"runs-on: {runs_on}",
            recommended=(
                "Use GitHub-hosted runners (ubuntu-latest, windows-latest, macos-latest) "
                "for workflows that process untrusted input. If self-hosted is required, "
                "use ephemeral runners and restrict to trusted branches only."
            ),
            reference="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners",
        ))

    return findings


# ---------------------------------------------------------------------------
# Summary stats helpers
# ---------------------------------------------------------------------------

def collect_action_stats(data: dict) -> dict:
    total = 0
    pinned = 0
    if not isinstance(data, dict):
        return {"total": total, "pinned": pinned}

    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return {"total": total, "pinned": pinned}

    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            if uses and "@" in uses:
                total += 1
                _, ref = uses.rsplit("@", 1)
                if SHA_PATTERN.match(ref.strip()):
                    pinned += 1

    return {"total": total, "pinned": pinned}


# ---------------------------------------------------------------------------
# Markdown report generator
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def generate_markdown(report: dict) -> str:
    lines = []
    lines.append(f"# CI/CD Pipeline Security Audit Report")
    lines.append(f"")
    lines.append(f"**Repository:** `{report['repo']}`")
    lines.append(f"**Scan Time:** {report['scan_timestamp']}")
    lines.append(f"**Workflows Scanned:** {report['workflow_count']}")
    lines.append(f"**Total Findings:** {report['total_findings']}")
    lines.append(f"")

    by_sev = report["by_severity"]
    lines.append("## Findings by Severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = by_sev.get(sev, 0)
        emoji = SEVERITY_EMOJI.get(sev, "")
        lines.append(f"| {emoji} {sev} | {count} |")
    lines.append("")

    stats = report.get("summary_stats", {})
    lines.append("## Pipeline Summary Stats")
    lines.append("")
    lines.append(f"- Total workflows: **{stats.get('total_workflows', 0)}**")
    lines.append(f"- Total actions used: **{stats.get('total_actions_used', 0)}**")
    lines.append(f"- Pinned actions: **{stats.get('pinned_actions', 0)}** ({stats.get('pin_rate', 'N/A')})")
    lines.append(f"- Unpinned actions: **{stats.get('unpinned_actions', 0)}**")
    lines.append(f"- Dangerous triggers: **{stats.get('dangerous_triggers', 0)}**")
    lines.append(f"- Expression injections: **{stats.get('expression_injections', 0)}**")
    lines.append(f"- Overpermissive workflows: **{stats.get('overpermissive_workflows', 0)}**")
    lines.append("")

    # Group findings by severity
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [f for f in report["findings"] if f["severity"] == sev]
        if not sev_findings:
            continue
        emoji = SEVERITY_EMOJI.get(sev, "")
        lines.append(f"## {emoji} {sev} Findings ({len(sev_findings)})")
        lines.append("")

        for f in sev_findings:
            lines.append(f"### [{f['id']}] {f['description'][:80]}...")
            lines.append("")
            lines.append(f"- **File:** `{f['workflow_file']}`" + (f" (line {f['line']})" if f["line"] else ""))
            lines.append(f"- **Category:** `{f['category']}`")
            lines.append("")
            lines.append(f"**Current (vulnerable):**")
            lines.append(f"```yaml")
            lines.append(f"{f['current']}")
            lines.append(f"```")
            lines.append("")
            lines.append(f"**Recommended:**")
            lines.append(f"```yaml")
            lines.append(f"{f['recommended']}")
            lines.append(f"```")
            lines.append("")
            lines.append(f"**Reference:** {f['reference']}")
            lines.append("")

    lines.append("---")
    lines.append("*Generated by cicd-pipeline-auditor (GRIMSEC DevSecOps Suite)*")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main audit runner
# ---------------------------------------------------------------------------

def audit_repo(repo_path: str, repo_name: str) -> dict:
    repo_dir = Path(repo_path)
    workflows_dir = repo_dir / ".github" / "workflows"

    if not workflows_dir.exists():
        print(f"[WARN] No .github/workflows/ directory found at {repo_path}")
        workflow_files = []
    else:
        workflow_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))

    all_findings = []
    total_actions = 0
    total_pinned = 0
    dangerous_trigger_count = 0
    expression_injection_count = 0
    overpermissive_count = 0

    for wf_path in sorted(workflow_files):
        rel_path = str(wf_path.relative_to(repo_dir))
        print(f"[INFO] Auditing {rel_path}")

        data, raw_lines, error = load_workflow(wf_path)
        if error:
            print(f"[WARN] Skipping {rel_path}: {error}")
            continue

        if not isinstance(data, dict):
            print(f"[WARN] Skipping {rel_path}: parsed data is not a dict (got {type(data).__name__})")
            continue

        # Run all checks
        findings_1 = check_unpinned_actions(data, raw_lines, rel_path)
        findings_2 = check_expression_injection(data, raw_lines, rel_path)
        findings_3 = check_permissions(data, raw_lines, rel_path)
        findings_4 = check_dangerous_triggers(data, raw_lines, rel_path)
        findings_5 = check_secrets_exposure(data, raw_lines, rel_path)
        findings_6 = check_self_hosted_runners(data, raw_lines, rel_path)

        all_findings.extend(findings_1 + findings_2 + findings_3 + findings_4 + findings_5 + findings_6)

        # Collect stats
        action_stats = collect_action_stats(data)
        total_actions += action_stats["total"]
        total_pinned += action_stats["pinned"]

        if findings_4:
            dangerous_trigger_count += len([f for f in findings_4 if f["severity"] in ("HIGH", "MEDIUM")])
        expression_injection_count += len(findings_2)
        if findings_3:
            overpermissive_count += 1

    # Build by_severity
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity", "LOW")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    unpinned_actions = total_actions - total_pinned
    pin_rate = (
        f"{(total_pinned / total_actions * 100):.1f}%"
        if total_actions > 0 else "N/A"
    )

    report = {
        "repo": repo_name,
        "scan_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workflow_count": len(workflow_files),
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "findings": all_findings,
        "summary_stats": {
            "total_workflows": len(workflow_files),
            "total_actions_used": total_actions,
            "pinned_actions": total_pinned,
            "unpinned_actions": unpinned_actions,
            "pin_rate": pin_rate,
            "dangerous_triggers": dangerous_trigger_count,
            "expression_injections": expression_injection_count,
            "overpermissive_workflows": overpermissive_count,
        },
    }

    return report


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CI/CD Pipeline Security Auditor — GitHub Actions workflow scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 audit-workflows.py /path/to/repo --repo owner/repo
  python3 audit-workflows.py /tmp/my-project --output /tmp/audit-results/ --repo myorg/myproject
        """,
    )
    parser.add_argument(
        "repo_path",
        help="Path to the local repository root (must contain .github/workflows/)",
    )
    parser.add_argument(
        "--output",
        default=".",
        help="Output directory for report files (default: current directory)",
    )
    parser.add_argument(
        "--repo",
        default="unknown/repo",
        help="Repository name in owner/repo format for the report header",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Only write JSON report, skip markdown",
    )
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Starting CI/CD Pipeline Security Audit")
    print(f"[INFO] Repo path: {args.repo_path}")
    print(f"[INFO] Output dir: {output_dir}")
    print()

    report = audit_repo(args.repo_path, args.repo)

    # Write JSON report
    json_path = output_dir / "audit-report.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[INFO] JSON report written to {json_path}")

    # Write Markdown summary
    if not args.json_only:
        md_path = output_dir / "audit-summary.md"
        md_path.write_text(generate_markdown(report), encoding="utf-8")
        print(f"[INFO] Markdown summary written to {md_path}")

    # Print summary to stdout
    print()
    print("=" * 60)
    print(f"  CI/CD PIPELINE SECURITY AUDIT COMPLETE")
    print("=" * 60)
    print(f"  Repository:     {report['repo']}")
    print(f"  Workflows:      {report['workflow_count']}")
    print(f"  Total findings: {report['total_findings']}")
    print()
    by_sev = report["by_severity"]
    print(f"  CRITICAL: {by_sev['CRITICAL']}")
    print(f"  HIGH:     {by_sev['HIGH']}")
    print(f"  MEDIUM:   {by_sev['MEDIUM']}")
    print(f"  LOW:      {by_sev['LOW']}")
    print("=" * 60)

    stats = report["summary_stats"]
    print(f"  Action pin rate:  {stats['pin_rate']} ({stats['pinned_actions']}/{stats['total_actions_used']})")
    print(f"  Dangerous triggers: {stats['dangerous_triggers']}")
    print(f"  Expression injections: {stats['expression_injections']}")
    print(f"  Overpermissive workflows: {stats['overpermissive_workflows']}")
    print("=" * 60)

    # Exit with non-zero if CRITICAL or HIGH findings
    if by_sev["CRITICAL"] > 0 or by_sev["HIGH"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
