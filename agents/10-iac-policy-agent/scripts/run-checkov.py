#!/usr/bin/env python3
"""
GRIMSEC IaC Policy Agent — Checkov Scanner Wrapper
====================================================
Runs Checkov against a repository directory, auto-selects frameworks based on
discovered IaC file types, and writes structured JSON output.

Usage:
    python run-checkov.py --directory <path> --output <output_file.json>
    python run-checkov.py --directory <path> --output <output_file.json> --frameworks terraform kubernetes
    python run-checkov.py --directory <path> --output <output_file.json> --compact
    python run-checkov.py --directory <path> --output <output_file.json> --check CKV_AWS_19,CKV_AWS_20
    python run-checkov.py --directory <path> --output <output_file.json> --skip-check CKV_AWS_123

Options:
    --directory / -d    Repository or directory path to scan (required)
    --output / -o       Output JSON file path (default: iac-policy/checkov-results.json)
    --frameworks        Space-separated list of frameworks to scan (auto-detected if omitted)
    --check             Comma-separated check IDs to run exclusively
    --skip-check        Comma-separated check IDs to skip
    --compact           Omit passing checks from output (failures only)
    --external-checks   Path to external custom checks directory
    --soft-fail         Exit 0 even if violations are found (for CI integration)
    --quiet             Suppress verbose output
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Framework detection: extension/filename patterns mapped to Checkov framework names
FRAMEWORK_DETECTORS = {
    "terraform": {
        "extensions": [".tf", ".tfvars"],
        "filenames": [],
        "checkov_name": "terraform",
    },
    "cloudformation": {
        "extensions": [".yaml", ".yml", ".json", ".template"],
        "filenames": ["template.yaml", "template.json"],
        "content_hints": ["AWSTemplateFormatVersion", "Resources:"],
        "checkov_name": "cloudformation",
    },
    "kubernetes": {
        "extensions": [".yaml", ".yml"],
        "filenames": [],
        "content_hints": ["apiVersion:", "kind: Deployment", "kind: Pod", "kind: Service",
                          "kind: Ingress", "kind: DaemonSet", "kind: StatefulSet"],
        "checkov_name": "kubernetes",
    },
    "dockerfile": {
        "extensions": [],
        "filenames": ["Dockerfile", "dockerfile"],
        "glob_patterns": ["Dockerfile*"],
        "checkov_name": "dockerfile",
    },
    "docker_compose": {
        "extensions": [".yml", ".yaml"],
        "filenames": ["docker-compose.yml", "docker-compose.yaml"],
        "checkov_name": "docker_compose",
    },
    "ansible": {
        "extensions": [".yml", ".yaml"],
        "filenames": [],
        "content_hints": ["- hosts:", "- name:", "ansible_"],
        "checkov_name": "ansible",
    },
    "arm": {
        "extensions": [".json"],
        "filenames": ["azuredeploy.json"],
        "content_hints": ['"$schema": "https://schema.management.azure.com/'],
        "checkov_name": "arm",
    },
    "github_actions": {
        "extensions": [".yml", ".yaml"],
        "filenames": [],
        "path_hints": [".github/workflows/"],
        "checkov_name": "github_actions",
    },
    "helm": {
        "extensions": [".yaml", ".yml"],
        "filenames": ["Chart.yaml", "values.yaml"],
        "checkov_name": "helm",
    },
}


def detect_frameworks(directory: str) -> list[str]:
    """Walk directory tree and detect IaC frameworks present."""
    detected = set()
    repo_path = Path(directory)

    for file_path in repo_path.rglob("*"):
        if not file_path.is_file():
            continue

        # Skip common non-IaC directories
        skip_dirs = {".git", "node_modules", "__pycache__", ".terraform", "vendor", ".venv"}
        if any(part in skip_dirs for part in file_path.parts):
            continue

        fname = file_path.name
        ext = file_path.suffix.lower()
        path_str = str(file_path)

        # GitHub Actions (path-based detection)
        if ".github/workflows/" in path_str and ext in (".yml", ".yaml"):
            detected.add("github_actions")
            continue

        # Dockerfile detection
        if fname.startswith("Dockerfile") or fname == "dockerfile":
            detected.add("dockerfile")
            continue

        # docker-compose detection
        if fname.startswith("docker-compose") and ext in (".yml", ".yaml"):
            detected.add("docker_compose")
            continue

        # Terraform detection
        if ext in (".tf", ".tfvars"):
            detected.add("terraform")
            continue

        # ARM template detection (check filename first)
        if fname in ("azuredeploy.json",):
            detected.add("arm")
            continue

        # Helm Chart.yaml detection
        if fname == "Chart.yaml":
            detected.add("helm")
            continue

        # For YAML/JSON files, do content-based detection (read first 512 bytes)
        if ext in (".yml", ".yaml", ".json") and file_path.stat().st_size < 5_000_000:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")[:512]
                if "AWSTemplateFormatVersion" in content or "Resources:\n" in content:
                    detected.add("cloudformation")
                elif "apiVersion:" in content and ("kind:" in content):
                    detected.add("kubernetes")
                elif "- hosts:" in content or "ansible_" in content:
                    detected.add("ansible")
                elif '"$schema": "https://schema.management.azure.com/' in content:
                    detected.add("arm")
            except (OSError, UnicodeDecodeError):
                pass

    return sorted(detected)


def run_checkov(
    directory: str,
    frameworks: list[str],
    output_path: str,
    check_ids: Optional[str] = None,
    skip_check_ids: Optional[str] = None,
    compact: bool = False,
    external_checks: Optional[str] = None,
    soft_fail: bool = False,
    quiet: bool = False,
) -> dict:
    """Run Checkov and return parsed results."""

    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build Checkov command
    cmd = [
        sys.executable, "-m", "checkov.main",
        "--directory", directory,
        "--output", "json",
        "--output-file-path", str(output_dir),
    ]

    # Try 'checkov' binary first, fall back to python -m
    try:
        result = subprocess.run(["checkov", "--version"], capture_output=True, timeout=10)
        if result.returncode == 0:
            cmd[0] = "checkov"
            cmd[1] = "-d"
            # Rebuild for binary usage
            cmd = ["checkov", "-d", directory, "--output", "json",
                   "--output-file-path", str(output_dir)]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Add frameworks
    if frameworks:
        cmd += ["--framework"] + frameworks

    # Add optional filters
    if check_ids:
        cmd += ["--check", check_ids]
    if skip_check_ids:
        cmd += ["--skip-check", skip_check_ids]
    if compact:
        cmd += ["--compact"]
    if external_checks:
        cmd += ["--external-checks-dir", external_checks]
    if soft_fail:
        cmd += ["--soft-fail"]
    if quiet:
        cmd += ["--quiet"]

    if not quiet:
        print(f"[checkov] Running: {' '.join(cmd)}")
        print(f"[checkov] Frameworks: {', '.join(frameworks) if frameworks else 'auto'}")

    # Run Checkov
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
        )
    except subprocess.TimeoutExpired:
        return {"error": "Checkov scan timed out after 10 minutes", "results": []}
    except FileNotFoundError:
        return {
            "error": "Checkov not found. Run: bash scripts/install-iac-tools.sh",
            "results": [],
        }

    # Checkov writes JSON to the output directory as 'results_json.json' or per-framework files
    # Find and consolidate output files
    json_files = list(output_dir.glob("results_json.json")) + \
                 list(output_dir.glob("results_*.json"))

    consolidated = {
        "metadata": {
            "directory": directory,
            "frameworks": frameworks,
            "checkov_exit_code": proc.returncode,
        },
        "summary": {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "parsing_error": 0,
        },
        "results": [],
        "failed_checks": [],
        "passed_checks": [],
    }

    # Parse JSON output from stdout if files not found
    raw_output = proc.stdout.strip()
    if not json_files and raw_output:
        try:
            parsed = json.loads(raw_output)
            if isinstance(parsed, list):
                all_results = parsed
            else:
                all_results = [parsed]

            for result in all_results:
                if "results" in result:
                    _merge_results(consolidated, result)
                elif "summary" in result:
                    _merge_results(consolidated, result)
        except json.JSONDecodeError:
            consolidated["raw_stdout"] = raw_output[:2000]
            consolidated["stderr"] = proc.stderr[:2000]
    else:
        for jf in json_files:
            try:
                data = json.loads(jf.read_text())
                if isinstance(data, list):
                    for item in data:
                        _merge_results(consolidated, item)
                else:
                    _merge_results(consolidated, data)
            except (json.JSONDecodeError, OSError) as e:
                consolidated.setdefault("parse_errors", []).append(
                    {"file": str(jf), "error": str(e)}
                )

    # Write consolidated output
    output_file = Path(output_path)
    output_file.write_text(json.dumps(consolidated, indent=2))

    if not quiet:
        s = consolidated["summary"]
        print(f"\n[checkov] Scan complete:")
        print(f"  Passed:  {s['passed']}")
        print(f"  Failed:  {s['failed']}")
        print(f"  Skipped: {s['skipped']}")
        print(f"  Errors:  {s['parsing_error']}")
        print(f"  Output:  {output_path}")

    return consolidated


def _merge_results(consolidated: dict, result: dict) -> None:
    """Merge a single Checkov result block into the consolidated output."""
    if not isinstance(result, dict):
        return

    summary = result.get("summary", {})
    if summary:
        consolidated["summary"]["passed"] += summary.get("passed", 0)
        consolidated["summary"]["failed"] += summary.get("failed", 0)
        consolidated["summary"]["skipped"] += summary.get("skipped", 0)
        consolidated["summary"]["parsing_error"] += summary.get("parsing_error", 0)

    results_block = result.get("results", {})
    if isinstance(results_block, dict):
        consolidated["failed_checks"].extend(results_block.get("failed_checks", []))
        consolidated["passed_checks"].extend(results_block.get("passed_checks", []))
    elif isinstance(results_block, list):
        consolidated["results"].extend(results_block)


def print_critical_findings(consolidated: dict) -> None:
    """Print CRITICAL findings that need immediate attention."""
    CRITICAL_CHECK_IDS = {
        "CKV_AWS_19", "CKV_AWS_20", "CKV_AWS_70", "CKV_AWS_9",
        "CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_17", "CKV_AZURE_28",
        "CKV_GCP_26", "CKV_K8S_30", "CKV_DOCKER_2",
    }

    critical = [
        check for check in consolidated.get("failed_checks", [])
        if check.get("check_id") in CRITICAL_CHECK_IDS
    ]

    if critical:
        print(f"\n[checkov] CRITICAL FINDINGS ({len(critical)}):")
        for c in critical:
            print(f"  [{c.get('check_id')}] {c.get('check_name', 'Unknown')}")
            print(f"    Resource: {c.get('resource', 'unknown')}")
            print(f"    File: {c.get('file_path', 'unknown')}:{c.get('file_line_range', '')}")
            if c.get("guideline"):
                print(f"    Guideline: {c['guideline']}")
            print()


def main():
    parser = argparse.ArgumentParser(
        description="GRIMSEC IaC Policy Agent — Checkov Scanner Wrapper"
    )
    parser.add_argument("-d", "--directory", required=True,
                        help="Repository directory to scan")
    parser.add_argument("-o", "--output", default="iac-policy/checkov-results.json",
                        help="Output JSON file path")
    parser.add_argument("--frameworks", nargs="+", default=None,
                        help="Frameworks to scan (auto-detected if omitted)")
    parser.add_argument("--check", default=None,
                        help="Comma-separated check IDs to run exclusively")
    parser.add_argument("--skip-check", default=None,
                        help="Comma-separated check IDs to skip")
    parser.add_argument("--compact", action="store_true",
                        help="Output only failures")
    parser.add_argument("--external-checks", default=None,
                        help="Path to external custom checks directory")
    parser.add_argument("--soft-fail", action="store_true",
                        help="Exit 0 even if violations found")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress verbose output")
    parser.add_argument("--detect-only", action="store_true",
                        help="Only detect frameworks, do not run scan")

    args = parser.parse_args()

    if not os.path.exists(args.directory):
        print(f"Error: Directory not found: {args.directory}", file=sys.stderr)
        sys.exit(1)

    # Detect frameworks
    if args.frameworks:
        frameworks = args.frameworks
        if not args.quiet:
            print(f"[checkov] Using specified frameworks: {', '.join(frameworks)}")
    else:
        if not args.quiet:
            print(f"[checkov] Auto-detecting IaC frameworks in: {args.directory}")
        frameworks = detect_frameworks(args.directory)
        if not frameworks:
            print(f"[checkov] No IaC files detected in: {args.directory}")
            sys.exit(0)
        if not args.quiet:
            print(f"[checkov] Detected frameworks: {', '.join(frameworks)}")

    if args.detect_only:
        print(json.dumps({"frameworks": frameworks}, indent=2))
        sys.exit(0)

    # Run scan
    results = run_checkov(
        directory=args.directory,
        frameworks=frameworks,
        output_path=args.output,
        check_ids=args.check,
        skip_check_ids=getattr(args, "skip_check"),
        compact=args.compact,
        external_checks=args.external_checks,
        soft_fail=args.soft_fail,
        quiet=args.quiet,
    )

    if not args.quiet:
        print_critical_findings(results)

    # Exit code: 0 if no failures, 1 if failures found (unless --soft-fail)
    if not args.soft_fail and results["summary"]["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
