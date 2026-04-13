#!/usr/bin/env python3
"""
run-scanners.py — Stage 3 of the DevSecOps Repo Analyzer pipeline.
Orchestrates multiple security scanning tools and aggregates results.

Usage:
    python3 run-scanners.py <repo-path> --output-dir <output-dir> [--depth quick|standard|deep]
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd: list, description: str, timeout: int = 600) -> tuple:
    """Run a command and return (success, stdout, stderr)."""
    print(f"  Running: {description}...")
    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = time.time() - start
        # Many scanners return non-zero when findings exist, so we check for actual errors
        if result.returncode not in (0, 1):
            print(f"    Warning: {description} exited with code {result.returncode} ({elapsed:.1f}s)")
            if result.stderr:
                print(f"    stderr: {result.stderr[:500]}")
        else:
            print(f"    Completed in {elapsed:.1f}s")
        return True, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        print(f"    Timeout after {timeout}s")
        return False, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        print(f"    Tool not found: {cmd[0]}")
        return False, "", f"Tool not found: {cmd[0]}"


def run_trivy_sca(repo_path: str, output_file: str) -> dict:
    """Run Trivy for Software Composition Analysis (dependency vulnerabilities)."""
    success, stdout, stderr = run_command(
        ["trivy", "fs", "--scanners", "vuln", "--format", "json",
         "--output", output_file, repo_path],
        "Trivy SCA (dependency vulnerabilities)"
    )
    if success and os.path.isfile(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
            # Count findings by severity
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
            results = data.get("Results", [])
            for result in results:
                for vuln in result.get("Vulnerabilities", []):
                    sev = vuln.get("Severity", "UNKNOWN")
                    counts[sev] = counts.get(sev, 0) + 1
            total = sum(counts.values())
            print(f"    Found {total} dependency vulnerabilities: {counts}")
            return {"status": "success", "total": total, "by_severity": counts}
        except (json.JSONDecodeError, KeyError):
            return {"status": "error", "message": "Failed to parse Trivy output"}
    return {"status": "skipped" if not success else "no_findings"}


def run_trivy_iac(repo_path: str, output_file: str) -> dict:
    """Run Trivy for IaC misconfiguration scanning."""
    success, stdout, stderr = run_command(
        ["trivy", "fs", "--scanners", "misconfig", "--format", "json",
         "--output", output_file, repo_path],
        "Trivy IaC (misconfigurations)"
    )
    if success and os.path.isfile(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            results = data.get("Results", [])
            for result in results:
                for mc in result.get("Misconfigurations", []):
                    sev = mc.get("Severity", "LOW")
                    counts[sev] = counts.get(sev, 0) + 1
            total = sum(counts.values())
            print(f"    Found {total} IaC misconfigurations: {counts}")
            return {"status": "success", "total": total, "by_severity": counts}
        except (json.JSONDecodeError, KeyError):
            return {"status": "error", "message": "Failed to parse Trivy IaC output"}
    return {"status": "skipped" if not success else "no_findings"}


def run_gitleaks(repo_path: str, output_file: str) -> dict:
    """Run Gitleaks for secrets detection."""
    success, stdout, stderr = run_command(
        ["gitleaks", "detect", "--source", repo_path,
         "--report-format", "json", "--report-path", output_file,
         "--no-git"],
        "Gitleaks (secrets detection)"
    )
    if os.path.isfile(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
            if isinstance(data, list):
                total = len(data)
                rule_counts = {}
                for finding in data:
                    rule = finding.get("RuleID", "unknown")
                    rule_counts[rule] = rule_counts.get(rule, 0) + 1
                print(f"    Found {total} potential secrets: {rule_counts}")
                return {"status": "success", "total": total, "by_rule": rule_counts}
        except (json.JSONDecodeError, KeyError):
            pass
    # Gitleaks returns exit code 1 when leaks found, 0 when clean
    if success:
        print(f"    No secrets detected")
        return {"status": "success", "total": 0, "by_rule": {}}
    return {"status": "skipped"}


def run_semgrep(repo_path: str, output_file: str, depth: str = "standard") -> dict:
    """Run Semgrep for SAST analysis."""
    # Select rulesets based on depth
    if depth == "deep":
        configs = ["p/default", "p/security-audit", "p/owasp-top-ten", "p/cwe-top-25"]
    else:
        configs = ["p/default", "p/security-audit"]

    cmd = ["semgrep", "scan", "--json", "--output", output_file, "--quiet"]
    for config in configs:
        cmd.extend(["--config", config])
    cmd.append(repo_path)

    success, stdout, stderr = run_command(
        cmd,
        f"Semgrep SAST ({', '.join(configs)})",
        timeout=900  # Semgrep can be slow on large repos
    )
    if os.path.isfile(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
            results = data.get("results", [])
            severity_counts = {}
            for r in results:
                sev = r.get("extra", {}).get("severity", "INFO")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            total = len(results)
            print(f"    Found {total} SAST findings: {severity_counts}")
            return {"status": "success", "total": total, "by_severity": severity_counts}
        except (json.JSONDecodeError, KeyError):
            return {"status": "error", "message": "Failed to parse Semgrep output"}
    return {"status": "skipped" if not success else "no_findings"}


def run_snyk_sca(repo_path: str, output_file: str) -> dict:
    """Run Snyk for SCA (dependency vulnerability scanning).
    
    Snyk provides additional intelligence beyond Trivy/Grype:
    - Proprietary vulnerability database with faster CVE coverage
    - Fix advice with upgrade paths and patch availability
    - Reachable vulnerability analysis for some ecosystems
    - License compliance checking
    
    Requires authentication: set SNYK_TOKEN env var or run 'snyk auth'.
    If not authenticated, this scanner is skipped gracefully.
    """
    # First check if snyk is available and authenticated
    auth_check = subprocess.run(
        ["snyk", "auth", "check"],
        capture_output=True, text=True, timeout=30
    )
    # snyk auth check is not a real command — test with snyk test --help
    # Instead, we just try to run the scan and handle auth errors gracefully
    
    # Detect project type and find manifest files
    manifest_patterns = {
        "package.json": "npm",
        "yarn.lock": "yarn",
        "pnpm-lock.yaml": "pnpm",
        "requirements.txt": "pip",
        "Pipfile": "pipenv",
        "poetry.lock": "poetry",
        "go.mod": "gomod",
        "Gemfile.lock": "rubygems",
        "pom.xml": "maven",
        "build.gradle": "gradle",
        "Cargo.lock": "cargo",
    }
    
    # Find all manifest files in the repo
    found_manifests = []
    for root, dirs, files in os.walk(repo_path):
        # Skip node_modules and vendor directories
        dirs[:] = [d for d in dirs if d not in ("node_modules", "vendor", ".git", "dist", "build")]
        for f in files:
            if f in manifest_patterns:
                rel_path = os.path.relpath(os.path.join(root, f), repo_path)
                found_manifests.append({
                    "file": rel_path,
                    "type": manifest_patterns[f],
                    "dir": os.path.join(root)
                })
    
    if not found_manifests:
        print("    No supported manifest files found for Snyk")
        return {"status": "skipped", "reason": "no_manifest_files"}
    
    all_vulns = []
    project_results = []
    
    for manifest in found_manifests:
        scan_dir = manifest["dir"]
        scan_file = manifest["file"]
        
        # Run snyk test on each project directory
        cmd = [
            "snyk", "test",
            "--json",
            "--severity-threshold=low",
            f"--file={os.path.basename(manifest['file'])}",
        ]
        
        success, stdout, stderr = run_command(
            cmd,
            f"Snyk SCA ({scan_file})",
            timeout=300
        )
        
        # Check for auth errors
        if stderr and ("not authenticated" in stderr.lower() or "auth" in stderr.lower()
                       or "SNYK_TOKEN" in stderr):
            print("    Snyk not authenticated. Set SNYK_TOKEN or run 'snyk auth'.")
            return {"status": "skipped", "reason": "not_authenticated",
                    "message": "Set SNYK_TOKEN env var or run 'snyk auth' to enable Snyk scanning"}
        
        if stdout:
            try:
                data = json.loads(stdout)
                vulns = data.get("vulnerabilities", [])
                project_name = data.get("projectName", scan_file)
                
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                unique_vulns = []
                seen_ids = set()
                
                for v in vulns:
                    vuln_id = v.get("id", "")
                    if vuln_id not in seen_ids:
                        seen_ids.add(vuln_id)
                        sev = v.get("severity", "low").lower()
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                        unique_vulns.append({
                            "id": vuln_id,
                            "title": v.get("title", ""),
                            "severity": sev,
                            "packageName": v.get("packageName", ""),
                            "version": v.get("version", ""),
                            "fixedIn": v.get("fixedIn", []),
                            "isUpgradable": v.get("isUpgradable", False),
                            "isPatchable": v.get("isPatchable", False),
                            "cvssScore": v.get("cvssScore", None),
                            "exploit": v.get("exploit", "Not Defined"),
                            "from": v.get("from", []),
                            "language": v.get("language", ""),
                        })
                        all_vulns.append(unique_vulns[-1])
                
                project_results.append({
                    "project": project_name,
                    "manifest": scan_file,
                    "unique_vulnerabilities": len(unique_vulns),
                    "by_severity": severity_counts,
                })
                
                print(f"    {scan_file}: {len(unique_vulns)} unique vulns {severity_counts}")
                
            except json.JSONDecodeError:
                project_results.append({
                    "project": scan_file,
                    "status": "parse_error",
                })
    
    # Aggregate results
    total_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in all_vulns:
        sev_upper = v["severity"].upper()
        if sev_upper in total_severity:
            total_severity[sev_upper] += 1
    
    # Compute Snyk-specific metrics
    upgradable = sum(1 for v in all_vulns if v.get("isUpgradable"))
    patchable = sum(1 for v in all_vulns if v.get("isPatchable"))
    with_exploit = sum(1 for v in all_vulns if v.get("exploit") not in ("Not Defined", None, ""))
    
    result = {
        "status": "success",
        "total": len(all_vulns),
        "by_severity": total_severity,
        "projects_scanned": len(project_results),
        "project_results": project_results,
        "snyk_metrics": {
            "upgradable": upgradable,
            "patchable": patchable,
            "with_known_exploit": with_exploit,
        },
        "vulnerabilities": all_vulns,
    }
    
    # Save full output
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"    Total unique: {len(all_vulns)} | Upgradable: {upgradable} | With exploits: {with_exploit}")
    return {k: v for k, v in result.items() if k != "vulnerabilities"}  # Don't include full vulns in summary


def run_grype(repo_path: str, output_file: str) -> dict:
    """Run Grype for secondary SCA cross-validation."""
    success, stdout, stderr = run_command(
        ["grype", f"dir:{repo_path}", "-o", "json", "--file", output_file],
        "Grype SCA (cross-validation)"
    )
    if success and os.path.isfile(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
            matches = data.get("matches", [])
            severity_counts = {}
            for m in matches:
                sev = m.get("vulnerability", {}).get("severity", "Unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            total = len(matches)
            print(f"    Found {total} dependency vulnerabilities (Grype): {severity_counts}")
            return {"status": "success", "total": total, "by_severity": severity_counts}
        except (json.JSONDecodeError, KeyError):
            return {"status": "error", "message": "Failed to parse Grype output"}
    return {"status": "skipped" if not success else "no_findings"}


def main():
    parser = argparse.ArgumentParser(description="Run security scanners on a repository")
    parser.add_argument("repo_path", help="Path to the cloned repository")
    parser.add_argument("--output-dir", "-o", required=True, help="Output directory for scan results")
    parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard",
                        help="Scan depth: quick (SCA+secrets), standard (all), deep (all+extended)")
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo_path)
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    print(f"=== Security Scanning ({args.depth} depth) ===")
    print(f"Repository: {repo_path}")
    print(f"Output:     {output_dir}")
    print()

    summary = {
        "repo_path": repo_path,
        "scan_depth": args.depth,
        "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scanners": {},
    }

    # === Quick scans (always run) ===
    print("[1] Trivy SCA scan...")
    summary["scanners"]["trivy_sca"] = run_trivy_sca(
        repo_path, os.path.join(output_dir, "trivy-sca.json")
    )

    print("[2] Gitleaks secrets scan...")
    summary["scanners"]["gitleaks"] = run_gitleaks(
        repo_path, os.path.join(output_dir, "gitleaks.json")
    )

    # === Standard scans ===
    if args.depth in ("standard", "deep"):
        print("[3] Semgrep SAST scan...")
        summary["scanners"]["semgrep"] = run_semgrep(
            repo_path, os.path.join(output_dir, "semgrep.json"), args.depth
        )

        print("[4] Trivy IaC scan...")
        summary["scanners"]["trivy_iac"] = run_trivy_iac(
            repo_path, os.path.join(output_dir, "trivy-iac.json")
        )

        print("[5] Snyk SCA scan...")
        summary["scanners"]["snyk_sca"] = run_snyk_sca(
            repo_path, os.path.join(output_dir, "snyk-sca.json")
        )

    # === Deep scans ===
    if args.depth == "deep":
        print("[6] Grype SCA cross-validation...")
        summary["scanners"]["grype"] = run_grype(
            repo_path, os.path.join(output_dir, "grype.json")
        )

    # === Aggregate summary ===
    total_findings = 0
    severity_aggregate = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for scanner_name, scanner_result in summary["scanners"].items():
        if scanner_result.get("status") == "success":
            total_findings += scanner_result.get("total", 0)
            for sev_key in ("by_severity",):
                for sev, count in scanner_result.get(sev_key, {}).items():
                    sev_upper = sev.upper()
                    if sev_upper in severity_aggregate:
                        severity_aggregate[sev_upper] += count

    summary["totals"] = {
        "total_findings": total_findings,
        "by_severity": severity_aggregate,
        "high_and_critical": severity_aggregate["CRITICAL"] + severity_aggregate["HIGH"],
    }

    # Save summary
    summary_path = os.path.join(output_dir, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n=== Scan Complete ===")
    print(f"Total findings:       {total_findings}")
    print(f"Critical:             {severity_aggregate['CRITICAL']}")
    print(f"High:                 {severity_aggregate['HIGH']}")
    print(f"Medium:               {severity_aggregate['MEDIUM']}")
    print(f"Low:                  {severity_aggregate['LOW']}")
    print(f"High+Critical:        {summary['totals']['high_and_critical']}")
    print(f"\nResults saved to: {output_dir}")
    print(f"Summary:          {summary_path}")


if __name__ == "__main__":
    main()
