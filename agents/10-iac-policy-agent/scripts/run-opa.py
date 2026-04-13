#!/usr/bin/env python3
"""
GRIMSEC IaC Policy Agent — OPA Policy Evaluator
================================================
Evaluates custom Rego policies against IaC files using Open Policy Agent.
Supports Docker, Kubernetes, Terraform, and GitHub Actions policies.

Usage:
    python run-opa.py --policy <rego_file> --input <input_json> --output <output.json>
    python run-opa.py --all-policies --repo-dir <path> --output iac-policy/opa-results.json
    python run-opa.py --policy assets/policies/k8s-security.rego --input manifests.json

Options:
    --policy / -p       Path to a single .rego policy file
    --input / -i        Input JSON data file to evaluate against
    --output / -o       Output JSON file (default: iac-policy/opa-results.json)
    --all-policies      Run all policies in assets/policies/ directory
    --repo-dir          Repository directory (used with --all-policies to find IaC files)
    --policies-dir      Directory containing .rego policy files (default: assets/policies/)
    --query             OPA query to evaluate (default: data.<package>.violations)
    --format            Output format: json or table (default: json)
    --quiet             Suppress verbose output
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import yaml
from pathlib import Path
from typing import Any, Optional

POLICIES_DIR = Path(__file__).parent.parent / "assets" / "policies"
DEFAULT_OUTPUT = "iac-policy/opa-results.json"

# Policy metadata: maps policy filename to the IaC type it handles
POLICY_META = {
    "docker-security.rego": {
        "domain": "docker",
        "file_patterns": ["Dockerfile*", "docker-compose*.yml", "docker-compose*.yaml"],
        "input_type": "dockerfile",
        "package": "docker.security",
        "queries": ["violations", "warnings"],
    },
    "k8s-security.rego": {
        "domain": "kubernetes",
        "file_patterns": ["*.yaml", "*.yml"],
        "content_hints": ["apiVersion:", "kind:"],
        "input_type": "kubernetes",
        "package": "k8s.security",
        "queries": ["violations", "warnings"],
    },
    "terraform-security.rego": {
        "domain": "terraform",
        "file_patterns": ["*.tf"],
        "input_type": "terraform",
        "package": "terraform.security",
        "queries": ["violations", "warnings"],
    },
    "github-actions.rego": {
        "domain": "github_actions",
        "file_patterns": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
        "input_type": "github_actions",
        "package": "github.actions.security",
        "queries": ["violations", "warnings"],
    },
}


def check_opa_available() -> bool:
    """Check if OPA binary is available."""
    try:
        result = subprocess.run(
            ["opa", "version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_opa_eval(
    policy_file: str,
    input_data: Any,
    query: str,
    quiet: bool = False,
) -> dict:
    """Run OPA eval with a policy file and input data."""

    # Write input data to a temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as tmp_input:
        json.dump(input_data, tmp_input, indent=2)
        tmp_input_path = tmp_input.name

    try:
        cmd = [
            "opa", "eval",
            "--format", "json",
            "--data", policy_file,
            "--input", tmp_input_path,
            query,
        ]

        if not quiet:
            print(f"  [opa] Evaluating: {query} against {Path(policy_file).name}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode not in (0, 1):  # OPA returns 1 for undefined results
            return {
                "error": result.stderr.strip(),
                "returncode": result.returncode,
                "results": [],
            }

        try:
            output = json.loads(result.stdout)
            # Extract the actual result values from OPA's eval output
            results = []
            for binding in output.get("result", []):
                for expr in binding.get("expressions", []):
                    value = expr.get("value")
                    if value is not None:
                        if isinstance(value, list):
                            results.extend(value)
                        elif isinstance(value, dict):
                            results.append(value)
                        elif isinstance(value, bool) and not value:
                            pass  # empty/false result
            return {"results": results, "raw": output}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON from OPA", "stdout": result.stdout[:500]}

    finally:
        os.unlink(tmp_input_path)


def parse_dockerfile(dockerfile_path: str) -> dict:
    """Parse a Dockerfile into a structured dict for OPA evaluation."""
    instructions = []
    try:
        with open(dockerfile_path, encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if parts:
                    instructions.append({
                        "line": line_num,
                        "instruction": parts[0].upper(),
                        "value": parts[1] if len(parts) > 1 else "",
                        "raw": line,
                    })
    except OSError as e:
        return {"error": str(e), "instructions": []}

    return {
        "file": dockerfile_path,
        "instructions": instructions,
        "has_user": any(i["instruction"] == "USER" for i in instructions),
        "has_healthcheck": any(i["instruction"] == "HEALTHCHECK" for i in instructions),
        "has_multistage": sum(1 for i in instructions if i["instruction"] == "FROM") > 1,
        "from_instructions": [i for i in instructions if i["instruction"] == "FROM"],
        "env_instructions": [i for i in instructions if i["instruction"] in ("ENV", "ARG")],
    }


def parse_kubernetes_manifest(manifest_path: str) -> list[dict]:
    """Parse a Kubernetes YAML manifest into a list of resource dicts."""
    resources = []
    try:
        with open(manifest_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # Handle multi-document YAML
        try:
            docs = list(yaml.safe_load_all(content))
            for doc in docs:
                if doc and isinstance(doc, dict) and "kind" in doc:
                    resources.append(doc)
        except yaml.YAMLError:
            pass
    except OSError:
        pass
    return resources


def parse_github_actions(workflow_path: str) -> dict:
    """Parse a GitHub Actions workflow YAML into a dict for OPA."""
    try:
        with open(workflow_path, encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            data["_file"] = workflow_path
            return data
    except (OSError, yaml.YAMLError) as e:
        return {"_file": workflow_path, "_error": str(e)}
    return {}


def find_iac_files(repo_dir: str, domain: str) -> list[str]:
    """Find IaC files of a given domain type in the repo."""
    repo = Path(repo_dir)
    files = []

    if domain == "docker":
        files.extend(str(p) for p in repo.rglob("Dockerfile*") if p.is_file())
        files.extend(str(p) for p in repo.rglob("docker-compose*.yml") if p.is_file())
        files.extend(str(p) for p in repo.rglob("docker-compose*.yaml") if p.is_file())

    elif domain == "kubernetes":
        skip_dirs = {".git", "node_modules", ".terraform"}
        for p in repo.rglob("*.yaml"):
            if any(part in skip_dirs for part in p.parts):
                continue
            if ".github/workflows" in str(p):
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")[:256]
                if "apiVersion:" in content and "kind:" in content:
                    files.append(str(p))
            except OSError:
                pass

    elif domain == "terraform":
        files.extend(str(p) for p in repo.rglob("*.tf") if p.is_file())

    elif domain == "github_actions":
        workflows_dir = repo / ".github" / "workflows"
        if workflows_dir.exists():
            files.extend(str(p) for p in workflows_dir.glob("*.yml"))
            files.extend(str(p) for p in workflows_dir.glob("*.yaml"))

    return files


def evaluate_policy(
    policy_file: str,
    domain: str,
    repo_dir: str,
    quiet: bool = False,
) -> dict:
    """Evaluate an OPA policy against all relevant files in a repo."""
    meta = POLICY_META.get(Path(policy_file).name, {})
    package = meta.get("package", "policy")
    queries_to_run = meta.get("queries", ["violations"])

    files = find_iac_files(repo_dir, domain)
    if not files:
        return {
            "domain": domain,
            "policy": policy_file,
            "message": f"No {domain} files found in {repo_dir}",
            "violations": [],
            "warnings": [],
        }

    if not quiet:
        print(f"\n[opa] Evaluating {domain} policy: {Path(policy_file).name}")
        print(f"      Files found: {len(files)}")

    all_violations = []
    all_warnings = []

    for file_path in files:
        if not quiet:
            print(f"  -> {file_path}")

        # Parse file into appropriate input format
        if domain == "docker":
            input_data = parse_dockerfile(file_path)
        elif domain == "kubernetes":
            resources = parse_kubernetes_manifest(file_path)
            if not resources:
                continue
            input_data = {"resources": resources, "file": file_path}
        elif domain == "terraform":
            # For Terraform, pass raw file content as input
            try:
                content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                input_data = {"file": file_path, "content": content}
            except OSError:
                continue
        elif domain == "github_actions":
            input_data = parse_github_actions(file_path)
        else:
            continue

        # Run each query
        for query_name in queries_to_run:
            query = f"data.{package}.{query_name}"
            result = run_opa_eval(policy_file, input_data, query, quiet=quiet)

            findings = result.get("results", [])
            for finding in findings:
                enriched = {
                    "file": file_path,
                    "query": query_name,
                    "finding": finding,
                }
                if query_name == "violations":
                    all_violations.append(enriched)
                else:
                    all_warnings.append(enriched)

    return {
        "domain": domain,
        "policy": str(policy_file),
        "files_scanned": len(files),
        "violations": all_violations,
        "warnings": all_warnings,
        "violation_count": len(all_violations),
        "warning_count": len(all_warnings),
    }


def run_all_policies(
    repo_dir: str,
    policies_dir: str,
    output_path: str,
    quiet: bool = False,
) -> dict:
    """Run all policies in the policies directory against a repository."""
    if not check_opa_available():
        print("Error: OPA not found. Run: bash scripts/install-iac-tools.sh", file=sys.stderr)
        sys.exit(1)

    policies_path = Path(policies_dir)
    policy_files = list(policies_path.glob("*.rego"))

    if not policy_files:
        print(f"No .rego files found in: {policies_dir}", file=sys.stderr)
        sys.exit(1)

    if not quiet:
        print(f"[opa] Running {len(policy_files)} policies against: {repo_dir}")

    all_results = {}

    for policy_file in sorted(policy_files):
        policy_name = policy_file.name
        meta = POLICY_META.get(policy_name, {})
        domain = meta.get("domain", policy_name.replace("-security.rego", "").replace(".rego", ""))

        result = evaluate_policy(
            policy_file=str(policy_file),
            domain=domain,
            repo_dir=repo_dir,
            quiet=quiet,
        )
        all_results[domain] = result

    # Write output
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(all_results, indent=2))

    # Print summary
    if not quiet:
        print("\n[opa] Policy Evaluation Summary:")
        total_v = 0
        total_w = 0
        for domain, result in all_results.items():
            v = result.get("violation_count", 0)
            w = result.get("warning_count", 0)
            total_v += v
            total_w += w
            status = "PASS" if v == 0 else "FAIL"
            print(f"  [{status}] {domain}: {v} violations, {w} warnings "
                  f"({result.get('files_scanned', 0)} files)")
        print(f"\n  Total: {total_v} violations, {total_w} warnings")
        print(f"  Output: {output_path}")

    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="GRIMSEC IaC Policy Agent — OPA Policy Evaluator"
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-p", "--policy", help="Single .rego policy file to evaluate")
    mode.add_argument("--all-policies", action="store_true",
                      help="Run all policies in --policies-dir")

    parser.add_argument("-i", "--input", help="Input JSON data file (single policy mode)")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help="Output JSON file")
    parser.add_argument("--repo-dir", help="Repository directory (used with --all-policies)")
    parser.add_argument("--policies-dir", default=str(POLICIES_DIR),
                        help="Directory containing .rego policy files")
    parser.add_argument("--query", default=None,
                        help="OPA query (default: auto-detect from policy name)")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose output")

    args = parser.parse_args()

    if not check_opa_available():
        print("Error: OPA binary not found.", file=sys.stderr)
        print("Install it with: bash scripts/install-iac-tools.sh", file=sys.stderr)
        sys.exit(1)

    if args.all_policies:
        if not args.repo_dir:
            print("Error: --repo-dir is required with --all-policies", file=sys.stderr)
            sys.exit(1)
        run_all_policies(
            repo_dir=args.repo_dir,
            policies_dir=args.policies_dir,
            output_path=args.output,
            quiet=args.quiet,
        )

    elif args.policy:
        if not args.input:
            print("Error: --input is required with --policy", file=sys.stderr)
            sys.exit(1)

        # Load input data
        try:
            with open(args.input) as f:
                input_data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Error loading input file: {e}", file=sys.stderr)
            sys.exit(1)

        # Determine query
        policy_name = Path(args.policy).name
        meta = POLICY_META.get(policy_name, {})
        package = meta.get("package", "policy")
        query = args.query or f"data.{package}.violations"

        result = run_opa_eval(args.policy, input_data, query, quiet=args.quiet)

        output_file = Path(args.output)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(result, indent=2))

        if not args.quiet:
            print(f"[opa] Results written to: {args.output}")
            violations = result.get("results", [])
            print(f"[opa] Findings: {len(violations)}")


if __name__ == "__main__":
    main()
