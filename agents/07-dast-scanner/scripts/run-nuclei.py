#!/usr/bin/env python3
"""
run-nuclei.py — GRIMSEC DAST Scanner (Agent 7)
Nuclei scanner wrapper with structured JSON output.

Usage:
    python run-nuclei.py --target https://example.com \
        --categories cves,misconfiguration,exposures \
        --severity critical,high,medium \
        --output dast-results/nuclei.json

Template categories:
    cves, misconfiguration, exposures, technologies,
    default-logins, network, headless, token-spray
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── CWE / OWASP lookup tables ─────────────────────────────────────────────────

OWASP_MAP: dict[str, str] = {
    "sqli":                  "A03:2021 – Injection",
    "sql-injection":         "A03:2021 – Injection",
    "xss":                   "A03:2021 – Injection",
    "cross-site-scripting":  "A03:2021 – Injection",
    "rce":                   "A03:2021 – Injection",
    "command-injection":     "A03:2021 – Injection",
    "ssrf":                  "A10:2021 – Server-Side Request Forgery",
    "idor":                  "A01:2021 – Broken Access Control",
    "path-traversal":        "A01:2021 – Broken Access Control",
    "lfi":                   "A01:2021 – Broken Access Control",
    "rfi":                   "A01:2021 – Broken Access Control",
    "auth-bypass":           "A07:2021 – Identification and Authentication Failures",
    "default-login":         "A07:2021 – Identification and Authentication Failures",
    "default-password":      "A07:2021 – Identification and Authentication Failures",
    "misconfig":             "A05:2021 – Security Misconfiguration",
    "misconfiguration":      "A05:2021 – Security Misconfiguration",
    "exposure":              "A05:2021 – Security Misconfiguration",
    "info-disclosure":       "A05:2021 – Security Misconfiguration",
    "cve":                   "A06:2021 – Vulnerable and Outdated Components",
    "cors":                  "A05:2021 – Security Misconfiguration",
    "csrf":                  "A01:2021 – Broken Access Control",
    "xxe":                   "A03:2021 – Injection",
    "ssti":                  "A03:2021 – Injection",
    "open-redirect":         "A01:2021 – Broken Access Control",
}

CWE_MAP: dict[str, str] = {
    "sqli":                  "CWE-89",
    "sql-injection":         "CWE-89",
    "xss":                   "CWE-79",
    "cross-site-scripting":  "CWE-79",
    "rce":                   "CWE-78",
    "command-injection":     "CWE-78",
    "ssrf":                  "CWE-918",
    "idor":                  "CWE-284",
    "path-traversal":        "CWE-22",
    "lfi":                   "CWE-22",
    "rfi":                   "CWE-98",
    "auth-bypass":           "CWE-287",
    "default-login":         "CWE-1392",
    "default-password":      "CWE-1392",
    "misconfig":             "CWE-16",
    "misconfiguration":      "CWE-16",
    "exposure":              "CWE-200",
    "info-disclosure":       "CWE-200",
    "cors":                  "CWE-942",
    "csrf":                  "CWE-352",
    "xxe":                   "CWE-611",
    "ssti":                  "CWE-1336",
    "open-redirect":         "CWE-601",
    "cve":                   "CWE-1035",
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
    "unknown":  0,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", file=sys.stderr)


def lookup_owasp(tags: list[str]) -> str:
    for tag in tags:
        tag_lower = tag.lower()
        for key, val in OWASP_MAP.items():
            if key in tag_lower:
                return val
    return "Uncategorized"


def lookup_cwe(tags: list[str], name: str) -> str:
    search_tokens = [t.lower() for t in tags] + [name.lower()]
    for token in search_tokens:
        for key, val in CWE_MAP.items():
            if key in token:
                return val
    return "CWE-Unknown"


def parse_nuclei_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw Nuclei JSONL line into a normalised finding dict."""
    info_block = raw.get("info", {})
    tags = info_block.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    severity = (info_block.get("severity") or raw.get("severity") or "unknown").lower()
    name = info_block.get("name") or raw.get("templateID") or "Unknown"
    template_id = raw.get("templateID") or raw.get("template-id") or ""

    matched_at = raw.get("matched-at") or raw.get("host") or ""
    extracted = raw.get("extracted-results") or []
    curl_command = raw.get("curl-command") or ""
    matcher_name = raw.get("matcher-name") or ""

    classification = info_block.get("classification") or {}
    cwe_ids = classification.get("cwe-id") or []
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]

    cwe_primary = cwe_ids[0] if cwe_ids else lookup_cwe(tags, name)
    owasp_category = lookup_owasp(tags)

    return {
        "id": template_id,
        "name": name,
        "severity": severity,
        "severity_rank": SEVERITY_RANK.get(severity, 0),
        "cwe_id": cwe_primary,
        "owasp_category": owasp_category,
        "matched_at": matched_at,
        "tags": tags,
        "description": info_block.get("description") or "",
        "reference": info_block.get("reference") or [],
        "remediation": info_block.get("remediation") or "",
        "matcher_name": matcher_name,
        "extracted_results": extracted,
        "curl_command": curl_command,
        "tool": "nuclei",
        "raw": raw,
    }


# ── Scanner ───────────────────────────────────────────────────────────────────

def build_nuclei_command(
    target: str,
    categories: list[str],
    severity: list[str],
    rate_limit: int,
    timeout: int,
    raw_output: str,
    extra_args: list[str],
    offline: bool,
) -> list[str]:
    cmd = [
        "nuclei",
        "-target", target,
        "-jsonl",
        "-output", raw_output,
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout),
        "-no-color",
        "-silent",
    ]

    if categories:
        # Map friendly category names to Nuclei template directory paths
        CATEGORY_DIRS = {
            "cves":           "cves",
            "misconfiguration": "misconfiguration",
            "misconfig":      "misconfiguration",
            "exposures":      "exposures",
            "exposure":       "exposures",
            "technologies":   "technologies",
            "tech":           "technologies",
            "default-logins": "default-logins",
            "network":        "network",
            "headless":       "headless",
            "token-spray":    "token-spray",
        }
        template_dirs = []
        for cat in categories:
            mapped = CATEGORY_DIRS.get(cat.lower(), cat)
            template_dirs.append(f"-t")
            template_dirs.append(mapped)
        cmd.extend(template_dirs)

    if severity:
        cmd.extend(["-severity", ",".join(severity)])

    if offline:
        cmd.append("-offline")

    cmd.extend(extra_args)
    return cmd


def run_nuclei(
    target: str,
    categories: list[str],
    severity: list[str],
    output_path: str,
    rate_limit: int = 100,
    timeout: int = 300,
    extra_args: list[str] | None = None,
    offline: bool = False,
) -> dict[str, Any]:
    """
    Run Nuclei against the target and return structured results.

    Returns:
        dict with keys: scan_meta, findings, summary
    """
    extra_args = extra_args or []
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    start_time = datetime.now(timezone.utc)
    log(f"Starting Nuclei scan: {target}")
    log(f"  Categories : {categories or 'all'}")
    log(f"  Severity   : {severity or 'all'}")
    log(f"  Rate limit : {rate_limit} req/s")
    log(f"  Timeout    : {timeout}s")

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as tmp:
        raw_output = tmp.name

    try:
        cmd = build_nuclei_command(
            target=target,
            categories=categories,
            severity=severity,
            rate_limit=rate_limit,
            timeout=timeout,
            raw_output=raw_output,
            extra_args=extra_args,
            offline=offline,
        )

        log(f"Running: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 60,
        )

        if result.returncode not in (0, 1):
            # Nuclei exits 1 if findings are present; other codes are errors
            log(f"Nuclei exited with code {result.returncode}", "WARN")
            if result.stderr:
                log(result.stderr[:500], "WARN")

        # ── Parse raw JSONL output ─────────────────────────────────────────
        findings: list[dict[str, Any]] = []
        if Path(raw_output).exists():
            with open(raw_output) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw_finding = json.loads(line)
                        findings.append(parse_nuclei_finding(raw_finding))
                    except json.JSONDecodeError as e:
                        log(f"Failed to parse line: {e}", "WARN")

        end_time = datetime.now(timezone.utc)
        duration_s = (end_time - start_time).total_seconds()

        # ── Summary ───────────────────────────────────────────────────────
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        findings.sort(key=lambda x: x["severity_rank"], reverse=True)

        structured = {
            "scan_meta": {
                "tool": "nuclei",
                "target": target,
                "categories": categories,
                "severity_filter": severity,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": round(duration_s, 1),
                "rate_limit": rate_limit,
                "nuclei_exit_code": result.returncode,
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "critical_count": severity_counts.get("critical", 0),
                "high_count":     severity_counts.get("high", 0),
                "medium_count":   severity_counts.get("medium", 0),
                "low_count":      severity_counts.get("low", 0),
                "info_count":     severity_counts.get("info", 0),
            },
            "findings": findings,
        }

        # Write output
        with open(output_path, "w") as out:
            json.dump(structured, out, indent=2, default=str)

        log(f"Nuclei scan complete. {len(findings)} finding(s) in {duration_s:.1f}s")
        log(f"Results saved to: {output_path}")
        for sev, count in sorted(severity_counts.items(), key=lambda x: SEVERITY_RANK.get(x[0], 0), reverse=True):
            log(f"  {sev.upper():10s}: {count}")

        return structured

    finally:
        # Clean up temp file
        try:
            os.unlink(raw_output)
        except OSError:
            pass


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GRIMSEC DAST Agent 7 — Nuclei Scanner Wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--target", "-t", required=True,
        help="Target URL (e.g. https://example.com)"
    )
    parser.add_argument(
        "--categories", "-c", default="cves,misconfiguration,exposures,technologies,default-logins",
        help="Comma-separated template categories (default: cves,misconfiguration,exposures,technologies,default-logins)"
    )
    parser.add_argument(
        "--severity", "-s", default="critical,high,medium",
        help="Comma-separated severity filter (default: critical,high,medium)"
    )
    parser.add_argument(
        "--output", "-o", default="dast-results/nuclei.json",
        help="Output JSON path (default: dast-results/nuclei.json)"
    )
    parser.add_argument(
        "--rate-limit", type=int, default=100,
        help="Maximum requests per second (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=int, default=300,
        help="Per-request timeout in seconds (default: 300)"
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Run in offline mode (no template updates)"
    )
    parser.add_argument(
        "--extra", nargs=argparse.REMAINDER, default=[],
        help="Additional raw arguments passed directly to nuclei"
    )

    args = parser.parse_args()

    categories = [c.strip() for c in args.categories.split(",") if c.strip()]
    severity   = [s.strip() for s in args.severity.split(",") if s.strip()]

    results = run_nuclei(
        target=args.target,
        categories=categories,
        severity=severity,
        output_path=args.output,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        extra_args=args.extra,
        offline=args.offline,
    )

    # Print summary to stdout for pipeline consumption
    print(json.dumps(results["summary"], indent=2))

    # Exit with non-zero if critical/high findings found
    if results["summary"]["critical_count"] > 0:
        sys.exit(2)
    if results["summary"]["high_count"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
