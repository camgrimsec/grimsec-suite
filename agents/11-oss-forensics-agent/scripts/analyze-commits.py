#!/usr/bin/env python3
"""
analyze-commits.py — GRIMSEC OSS Forensics Agent (Agent 11)

Git history forensics: clone a repository bare and analyze commit history for
forensic indicators including force-pushes, author/committer mismatches, timezone
anomalies, obfuscated code additions, and suspicious file modifications.

Usage:
    python analyze-commits.py --repo owner/repo [--token GITHUB_TOKEN] [--output-dir forensics]

Output:
    forensics/git-analysis-{owner}-{repo}.json
    forensics/ioc-candidates.json  (preliminary IOCs from git analysis)
"""

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] {msg}", file=sys.stderr)


def run_git(repo_path: Path, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo_path)] + args,
        capture_output=True,
        text=True,
        check=check,
    )


def save_json(data: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log(f"Saved: {path} ({path.stat().st_size:,} bytes)")


# ---------------------------------------------------------------------------
# IOC Pattern Detection
# ---------------------------------------------------------------------------

# Obfuscation patterns
OBFUSCATION_PATTERNS = [
    (re.compile(r'eval\s*\(', re.MULTILINE), "eval() call", "code_obfuscation", "HIGH"),
    (re.compile(r'base64[_-]?decode\s*\(', re.I), "base64 decode", "code_obfuscation", "HIGH"),
    (re.compile(r'Buffer\.from\s*\([^)]+,\s*[\'"]base64[\'"]\)', re.I), "Buffer.from base64", "code_obfuscation", "HIGH"),
    (re.compile(r'atob\s*\(', re.I), "atob() base64 decode", "code_obfuscation", "MEDIUM"),
    (re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}'), "hex-encoded string (5+ bytes)", "code_obfuscation", "HIGH"),
    (re.compile(r'(?:exec|execSync|spawn|spawnSync)\s*\(', re.I), "process execution", "code_obfuscation", "MEDIUM"),
    (re.compile(r'__import__\s*\(\s*[\'"]os[\'"]\s*\)', re.I), "dynamic os import", "code_obfuscation", "HIGH"),
    (re.compile(r'compile\s*\([^,]+,\s*[\'"]exec[\'"]\)', re.I), "compile/exec", "code_obfuscation", "HIGH"),
    (re.compile(r'[A-Za-z0-9+/]{200,}={0,2}'), "long base64 blob (>200 chars)", "code_obfuscation", "MEDIUM"),
]

# Exfiltration patterns
EXFILTRATION_PATTERNS = [
    (re.compile(r'(?:fetch|axios|got|request|http\.get|https\.get)\s*\([\'"]https?://(?!(?:api\.github\.com|registry\.npmjs\.org|pypi\.org))[^\'"]+[\'"]', re.I),
     "outbound HTTP call to unknown domain", "exfiltration", "HIGH"),
    (re.compile(r'(?:webhook|discord\.com/api/webhooks|slack\.com/services)', re.I),
     "webhook POST", "exfiltration", "MEDIUM"),
    (re.compile(r'DNS|dns\.resolve|dgram', re.I),
     "DNS resolution (potential DNS exfil)", "exfiltration", "LOW"),
    (re.compile(r'(?:curl|wget)\s+[\'"]?https?://[^\s\'"]+', re.I),
     "curl/wget to remote URL", "exfiltration", "HIGH"),
]

# Environment variable access patterns
ENV_PATTERNS = [
    (re.compile(r'process\.env\.(?:NPM_TOKEN|GH_TOKEN|GITHUB_TOKEN|AWS_|CI|SECRET)', re.I),
     "CI secret env var access", "env_access", "CRITICAL"),
    (re.compile(r'os\.environ\.get\s*\(\s*[\'"](?:AWS|GITHUB|CI|SECRET|TOKEN|KEY)', re.I),
     "CI secret os.environ access", "env_access", "CRITICAL"),
    (re.compile(r'System\.getenv\s*\(\s*[\'"](?:AWS|GITHUB|CI|SECRET|TOKEN|KEY)', re.I),
     "CI secret System.getenv", "env_access", "CRITICAL"),
    (re.compile(r'(?:process\.env|os\.environ)', re.I),
     "environment variable access", "env_access", "LOW"),
    (re.compile(r'~\/\.ssh\/|\/root\/\.ssh\/|\$HOME\/\.ssh\/', re.I),
     "SSH key path access", "env_access", "HIGH"),
    (re.compile(r'~\/\.aws\/credentials|AWS_SHARED_CREDENTIALS', re.I),
     "AWS credentials file access", "env_access", "HIGH"),
    (re.compile(r'~\/\.npmrc|~\/\.netrc|~\/\.gitconfig', re.I),
     "credentials file access (.npmrc/.netrc/.gitconfig)", "env_access", "HIGH"),
]

# Install hook suspicious patterns
INSTALL_HOOK_PATTERNS = [
    (re.compile(r'"postinstall"\s*:\s*"[^"]*(?:curl|wget|fetch|node|python|bash|sh)', re.I),
     "postinstall script with network/exec command", "install_hook", "CRITICAL"),
    (re.compile(r'"preinstall"\s*:\s*"[^"]*(?:curl|wget|fetch|node|python|bash|sh)', re.I),
     "preinstall script with network/exec command", "install_hook", "CRITICAL"),
    (re.compile(r'cmdclass.*install\s*=', re.DOTALL),
     "setup.py custom install command class", "install_hook", "HIGH"),
    (re.compile(r'//go:generate.*(?:curl|wget|go run)', re.I),
     "go:generate with network fetch", "install_hook", "HIGH"),
]

# Suspicious file paths
SUSPICIOUS_FILES = [
    re.compile(r'\.github/workflows/.*\.ya?ml$', re.I),
    re.compile(r'package\.json$', re.I),
    re.compile(r'setup\.py$', re.I),
    re.compile(r'setup\.cfg$', re.I),
    re.compile(r'pyproject\.toml$', re.I),
    re.compile(r'CMakeLists\.txt$', re.I),
    re.compile(r'Makefile$', re.I),
    re.compile(r'\.npmrc$', re.I),
    re.compile(r'\.env$', re.I),
    re.compile(r'Gemfile$', re.I),
    re.compile(r'requirements.*\.txt$', re.I),
    re.compile(r'go\.mod$', re.I),
]

ALL_IOC_PATTERNS = OBFUSCATION_PATTERNS + EXFILTRATION_PATTERNS + ENV_PATTERNS + INSTALL_HOOK_PATTERNS


def scan_diff_for_iocs(diff: str, commit_sha: str, file_path: str) -> list[dict]:
    """Scan a git diff patch for IOC patterns. Only examines added lines (+)."""
    iocs = []
    added_lines = []
    line_num = 0

    for line in diff.split("\n"):
        if line.startswith("@@"):
            # Parse hunk header for line numbers: @@ -a,b +c,d @@
            m = re.search(r"\+(\d+)", line)
            if m:
                line_num = int(m.group(1)) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            line_num += 1
            added_lines.append((line_num, line[1:]))
        elif not line.startswith("-"):
            line_num += 1

    for lnum, content in added_lines:
        for pattern, description, category, severity in ALL_IOC_PATTERNS:
            if pattern.search(content):
                iocs.append({
                    "commit_sha": commit_sha,
                    "file_path": file_path,
                    "line_number": lnum,
                    "content_snippet": content[:200],
                    "pattern_description": description,
                    "category": category,
                    "severity": severity,
                })
    return iocs


# ---------------------------------------------------------------------------
# Git Clone and Analysis
# ---------------------------------------------------------------------------

def clone_repo(owner: str, repo: str, token: str | None, work_dir: Path) -> Path:
    """Clone repository bare into work_dir."""
    repo_path = work_dir / f"{owner}-{repo}.git"
    if repo_path.exists():
        log(f"Repo already cloned at {repo_path}")
        return repo_path

    if token:
        clone_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"
    else:
        clone_url = f"https://github.com/{owner}/{repo}.git"

    log(f"Cloning {owner}/{repo} (bare)...")
    result = subprocess.run(
        ["git", "clone", "--bare", "--quiet", clone_url, str(repo_path)],
        capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr}")
    log(f"Cloned to {repo_path}")
    return repo_path


def get_all_commits(repo_path: Path) -> list[dict]:
    """Get full commit log with author, committer, and message."""
    log("Extracting full commit history...")
    # Format: hash|author_name|author_email|author_date|committer_email|committer_date|subject
    fmt = "%H|%an|%ae|%aI|%ce|%cI|%s"
    result = run_git(repo_path, ["log", "--all", f"--format={fmt}"])
    commits = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split("|", 6)
        if len(parts) < 7:
            continue
        commits.append({
            "sha": parts[0],
            "author_name": parts[1],
            "author_email": parts[2],
            "author_date": parts[3],
            "committer_email": parts[4],
            "committer_date": parts[5],
            "subject": parts[6],
        })
    log(f"  Found {len(commits)} commits total")
    return commits


def detect_force_pushes(repo_path: Path) -> list[dict]:
    """Detect force pushes via reflog (non-fast-forward updates)."""
    log("Checking reflog for force pushes...")
    try:
        result = run_git(repo_path, ["reflog", "--all", "--format=%H %gD %gs"])
        force_pushes = []
        for line in result.stdout.strip().split("\n"):
            if "forced-update" in line or "force" in line.lower():
                force_pushes.append({"reflog_entry": line})
        log(f"  Force push indicators: {len(force_pushes)}")
        return force_pushes
    except Exception as e:
        log(f"  Warning: reflog analysis: {e}")
        return []


def detect_dangling_commits(repo_path: Path) -> list[str]:
    """Find dangling (orphaned) commits not reachable from any ref."""
    log("Checking for dangling commits...")
    try:
        result = run_git(repo_path, ["fsck", "--unreachable", "--no-progress"], check=False)
        dangling = []
        for line in result.stdout.split("\n"):
            if "unreachable commit" in line:
                sha = line.split()[-1]
                dangling.append(sha)
        log(f"  Dangling commits: {len(dangling)}")
        return dangling
    except Exception as e:
        log(f"  Warning: fsck: {e}")
        return []


def detect_author_committer_mismatches(commits: list[dict]) -> list[dict]:
    """Flag commits where author email != committer email."""
    mismatches = []
    for c in commits:
        if c.get("author_email") and c.get("committer_email"):
            if c["author_email"] != c["committer_email"]:
                # Exclude GitHub's noreply address (used for web UI commits)
                if "noreply.github.com" not in c["committer_email"]:
                    mismatches.append(c)
    log(f"  Author/committer mismatches: {len(mismatches)}")
    return mismatches


def detect_timezone_anomalies(commits: list[dict]) -> dict:
    """
    Analyze author commit timezone distribution.
    Flag commits with timezone offsets far from the author's historical norm.
    """
    log("Analyzing timezone patterns...")
    author_offsets: dict[str, list[int]] = defaultdict(list)

    for c in commits:
        date_str = c.get("author_date", "")
        if not date_str:
            continue
        # ISO 8601 offset: +05:30, -08:00, Z
        m = re.search(r'([+-])(\d{2}):(\d{2})$', date_str)
        if m:
            sign = 1 if m.group(1) == "+" else -1
            offset_min = sign * (int(m.group(2)) * 60 + int(m.group(3)))
            author_offsets[c["author_email"]].append(offset_min)

    anomalies = []
    profiles = {}
    for email, offsets in author_offsets.items():
        if len(offsets) < 3:
            continue
        avg = sum(offsets) / len(offsets)
        std = (sum((x - avg) ** 2 for x in offsets) / len(offsets)) ** 0.5
        profiles[email] = {"avg_offset_min": avg, "std_dev_min": std, "commit_count": len(offsets)}
        # Flag commits > 4 hours (240 min) from average
        threshold = max(std * 2, 240)
        for offset in offsets:
            if abs(offset - avg) > threshold:
                anomalies.append({
                    "author_email": email,
                    "anomalous_offset_min": offset,
                    "avg_offset_min": avg,
                    "deviation_min": abs(offset - avg),
                })

    log(f"  Timezone anomalies: {len(anomalies)} across {len(profiles)} authors")
    return {"profiles": profiles, "anomalies": anomalies}


def detect_suspicious_file_modifications(repo_path: Path, commits: list[dict],
                                          max_commits: int = 200) -> list[dict]:
    """Detect commits that modify security-sensitive files and scan diffs for IOCs."""
    log(f"Scanning diffs for IOCs (checking up to {max_commits} commits)...")
    suspicious = []
    all_iocs = []

    for commit in commits[:max_commits]:
        sha = commit["sha"]
        try:
            # Get files changed in this commit
            result = run_git(repo_path, ["show", "--name-status", "--format=", sha])
            files_changed = []
            for line in result.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    status, fpath = parts[0], parts[-1]
                    files_changed.append((status, fpath))

            # Check if any suspicious files were modified
            suspicious_files_in_commit = [
                (status, fpath) for status, fpath in files_changed
                if any(pat.search(fpath) for pat in SUSPICIOUS_FILES)
            ]

            if suspicious_files_in_commit:
                suspicious.append({
                    "commit_sha": sha,
                    "author_email": commit.get("author_email"),
                    "date": commit.get("author_date"),
                    "subject": commit.get("subject"),
                    "suspicious_files": [
                        {"status": s, "path": p} for s, p in suspicious_files_in_commit
                    ],
                })

            # Scan diff for IOC patterns on ALL added content
            diff_result = run_git(repo_path, ["show", "--unified=0", sha], check=False)
            if diff_result.stdout:
                current_file = ""
                current_diff = []
                for line in diff_result.stdout.split("\n"):
                    if line.startswith("+++ b/"):
                        if current_file and current_diff:
                            iocs = scan_diff_for_iocs("\n".join(current_diff), sha, current_file)
                            all_iocs.extend(iocs)
                        current_file = line[6:]
                        current_diff = []
                    else:
                        current_diff.append(line)
                if current_file and current_diff:
                    iocs = scan_diff_for_iocs("\n".join(current_diff), sha, current_file)
                    all_iocs.extend(iocs)

        except Exception as e:
            log(f"  Warning: analyzing commit {sha}: {e}")

    log(f"  Suspicious file modifications: {len(suspicious)}")
    log(f"  IOC pattern matches in diffs: {len(all_iocs)}")
    return suspicious, all_iocs


def analyze_workflow_files(repo_path: Path) -> list[dict]:
    """Extract and analyze all GitHub Actions workflow files."""
    log("Analyzing GitHub Actions workflows...")
    try:
        result = run_git(repo_path, ["ls-tree", "-r", "HEAD", "--name-only"], check=False)
        workflow_files = [
            f for f in result.stdout.split("\n")
            if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml"))
        ]
    except Exception:
        return []

    workflows = []
    concerns = []
    for wf_path in workflow_files:
        try:
            content_result = run_git(repo_path, ["show", f"HEAD:{wf_path}"])
            content = content_result.stdout

            wf_concerns = []
            # Dangerous patterns in workflows
            danger_patterns = [
                (r'curl\s+[^\s]+\s*\|\s*(?:bash|sh)', "curl pipe to shell"),
                (r'pull_request_target', "pull_request_target trigger (TOCTOU risk)"),
                (r'\$\{\{\s*github\.event\.pull_request', "PR-controlled input in expression"),
                (r'secrets\.\w+', "secret reference"),
                (r'env\.GITHUB_TOKEN\s*=', "GITHUB_TOKEN reassignment"),
                (r'actions/checkout@(?!v\d)', "unpinned actions/checkout"),
                (r'uses:\s+\S+@(?!sha|v\d|\d)', "action pinned to branch not SHA"),
                (r'run:\s+\$\(\s*\S+\s+\$\{\{', "command injection via expression"),
            ]
            for pat, desc in danger_patterns:
                if re.search(pat, content, re.I):
                    wf_concerns.append(desc)

            workflows.append({
                "path": wf_path,
                "content": content,
                "concerns": wf_concerns,
            })
            if wf_concerns:
                concerns.append({"path": wf_path, "concerns": wf_concerns})
        except Exception as e:
            log(f"  Warning: reading {wf_path}: {e}")

    log(f"  Workflows: {len(workflows)}, with concerns: {len(concerns)}")
    return workflows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="GRIMSEC OSS Forensics — Git history analyzer"
    )
    parser.add_argument("--repo", required=True, help="owner/repo format")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--output-dir", default="forensics")
    parser.add_argument("--max-commits", type=int, default=200,
                        help="Max commits to scan for IOC patterns (default: 200)")
    parser.add_argument("--keep-clone", action="store_true",
                        help="Keep the cloned repo after analysis")
    args = parser.parse_args()

    if "/" not in args.repo:
        print("ERROR: --repo must be in owner/repo format", file=sys.stderr)
        sys.exit(1)

    owner, repo = args.repo.split("/", 1)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    work_dir = Path(tempfile.mkdtemp(prefix="grimsec-forensics-"))
    log(f"Working directory: {work_dir}")

    try:
        # Clone
        repo_path = clone_repo(owner, repo, args.token, work_dir)

        # Get all commits
        commits = get_all_commits(repo_path)

        # Force push detection
        force_pushes = detect_force_pushes(repo_path)

        # Dangling commits
        dangling = detect_dangling_commits(repo_path)

        # Author/committer mismatches
        mismatches = detect_author_committer_mismatches(commits)

        # Timezone anomalies
        tz_analysis = detect_timezone_anomalies(commits)

        # Suspicious file modifications + IOC scanning
        suspicious_mods, diff_iocs = detect_suspicious_file_modifications(
            repo_path, commits, max_commits=args.max_commits
        )

        # Workflow analysis
        workflows = analyze_workflow_files(repo_path)

        # Aggregate results
        analysis = {
            "repo": f"{owner}/{repo}",
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_commits": len(commits),
            "force_pushes": force_pushes,
            "dangling_commits": dangling,
            "author_committer_mismatches": mismatches,
            "timezone_analysis": tz_analysis,
            "suspicious_file_modifications": suspicious_mods,
            "workflow_analysis": {
                "total_workflows": len(workflows),
                "workflows_with_concerns": [w for w in workflows if w.get("concerns")],
                "all_workflows": [{"path": w["path"], "concerns": w["concerns"]} for w in workflows],
            },
        }

        # IOC candidates from diff scanning
        ioc_candidates = {
            "repo": f"{owner}/{repo}",
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "commits_scanned": min(args.max_commits, len(commits)),
            "ioc_candidates": diff_iocs,
            "summary_by_category": dict(Counter(i["category"] for i in diff_iocs)),
            "summary_by_severity": dict(Counter(i["severity"] for i in diff_iocs)),
        }

        save_json(analysis, out_dir / f"git-analysis-{owner}-{repo}.json")
        save_json(ioc_candidates, out_dir / "ioc-candidates.json")

        log("Git analysis complete.")
        print(json.dumps({
            "commits_analyzed": len(commits),
            "force_pushes": len(force_pushes),
            "dangling_commits": len(dangling),
            "author_committer_mismatches": len(mismatches),
            "ioc_pattern_matches": len(diff_iocs),
            "suspicious_modifications": len(suspicious_mods),
            "outputs": [
                str(out_dir / f"git-analysis-{owner}-{repo}.json"),
                str(out_dir / "ioc-candidates.json"),
            ]
        }, indent=2))

    finally:
        if not args.keep_clone and work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)
            log(f"Cleaned up work dir: {work_dir}")


if __name__ == "__main__":
    main()
