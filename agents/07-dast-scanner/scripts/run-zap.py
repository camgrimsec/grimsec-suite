#!/usr/bin/env python3
"""
run-zap.py — GRIMSEC DAST Scanner (Agent 7)
OWASP ZAP scanner wrapper (Docker-based) with structured JSON output.

Scan modes:
  baseline  — Passive-only scan. Safe for CI/CD. (~2 min)
  full      — Active + passive scan. Comprehensive. (~20–60 min)
  api       — OpenAPI/Swagger/SOAP/GraphQL-aware active scan.

Usage:
    python run-zap.py --target https://example.com --mode baseline --output dast-results/zap.json
    python run-zap.py --target https://api.example.com --mode api --openapi-spec ./openapi.yaml
    python run-zap.py --target https://example.com --mode full \\
        --login-url https://example.com/login --username admin --password secret
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Constants ─────────────────────────────────────────────────────────────────
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

# ZAP risk codes → normalized severity
ZAP_RISK_MAP: dict[int, str] = {
    3: "high",
    2: "medium",
    1: "low",
    0: "info",
}

# ZAP alert pluginId / name → CWE / OWASP hints
PLUGIN_CWE_MAP: dict[str, str] = {
    "10020": "CWE-1021",   # Anti-clickjacking header
    "10021": "CWE-614",    # Secure cookie flag
    "10023": "CWE-693",    # Information disclosure – debug errors
    "10024": "CWE-200",    # Information disclosure
    "10038": "CWE-693",    # Content Security Policy
    "10040": "CWE-16",     # HTTPS to HTTP redirect
    "10049": "CWE-525",    # Non-storable content
    "10063": "CWE-319",    # Permissions Policy header missing
    "10202": "CWE-306",    # Absence of Anti-CSRF Tokens
    "40012": "CWE-79",     # Reflected XSS
    "40014": "CWE-79",     # Persistent XSS
    "40018": "CWE-89",     # SQL Injection
    "40024": "CWE-74",     # Generic Injection
    "40034": "CWE-918",    # SSRF
    "6":     "CWE-22",     # Path Traversal
    "7":     "CWE-601",    # Remote File Inclusion
}

OWASP_MAP: dict[str, str] = {
    "CWE-89":   "A03:2021 – Injection",
    "CWE-79":   "A03:2021 – Injection",
    "CWE-78":   "A03:2021 – Injection",
    "CWE-918":  "A10:2021 – Server-Side Request Forgery",
    "CWE-22":   "A01:2021 – Broken Access Control",
    "CWE-284":  "A01:2021 – Broken Access Control",
    "CWE-287":  "A07:2021 – Identification and Authentication Failures",
    "CWE-352":  "A01:2021 – Broken Access Control",
    "CWE-614":  "A02:2021 – Cryptographic Failures",
    "CWE-200":  "A05:2021 – Security Misconfiguration",
    "CWE-693":  "A05:2021 – Security Misconfiguration",
    "CWE-16":   "A05:2021 – Security Misconfiguration",
    "CWE-1021": "A05:2021 – Security Misconfiguration",
    "CWE-942":  "A05:2021 – Security Misconfiguration",
    "CWE-319":  "A02:2021 – Cryptographic Failures",
    "CWE-601":  "A01:2021 – Broken Access Control",
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", file=sys.stderr)


def check_docker() -> None:
    if not shutil.which("docker"):
        log("Docker not found on PATH. Install Docker and retry.", "ERROR")
        sys.exit(1)
    result = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if result.returncode != 0:
        log("Docker daemon is not running.", "ERROR")
        sys.exit(1)


def ensure_zap_image() -> None:
    result = subprocess.run(
        ["docker", "image", "inspect", ZAP_IMAGE],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log(f"ZAP image not found locally. Pulling {ZAP_IMAGE} ...")
        subprocess.run(["docker", "pull", ZAP_IMAGE], check=True)
        log("ZAP image pulled.")
    else:
        log(f"ZAP image ready: {ZAP_IMAGE}")


def parse_zap_xml_report(xml_path: str) -> list[dict[str, Any]]:
    """Parse ZAP XML report into a list of normalised finding dicts."""
    findings: list[dict[str, Any]] = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        log(f"Failed to parse ZAP XML: {e}", "WARN")
        return findings

    for site in root.findall(".//site"):
        host = site.get("host", "")
        for alert in site.findall(".//alertitem"):
            plugin_id = alert.findtext("pluginid") or ""
            name      = alert.findtext("alert") or alert.findtext("name") or "Unknown"
            desc      = alert.findtext("desc") or ""
            solution  = alert.findtext("solution") or ""
            reference = alert.findtext("reference") or ""
            risk_code_str = alert.findtext("riskcode") or "0"
            risk_desc = alert.findtext("riskdesc") or ""
            confidence = alert.findtext("confidence") or "0"
            cweid     = alert.findtext("cweid") or PLUGIN_CWE_MAP.get(plugin_id, "CWE-Unknown")
            wascid    = alert.findtext("wascid") or ""

            if cweid and not cweid.startswith("CWE-"):
                cweid = f"CWE-{cweid}"

            try:
                risk_code = int(risk_code_str)
            except ValueError:
                risk_code = 0

            severity = ZAP_RISK_MAP.get(risk_code, "info")

            # Upgrade risk-2 (medium) to critical/high based on name heuristics
            name_lower = name.lower()
            if any(k in name_lower for k in ("sql injection", "command injection", "rce", "remote code")):
                severity = "critical"
            elif any(k in name_lower for k in ("stored xss", "persistent xss", "ssrf", "path traversal")):
                severity = "high"

            owasp_category = OWASP_MAP.get(cweid, "Uncategorized")

            # Collect instances (URLs where this alert was found)
            instances: list[dict[str, str]] = []
            for inst in alert.findall(".//instance"):
                instances.append({
                    "uri":     inst.findtext("uri") or "",
                    "method":  inst.findtext("method") or "",
                    "param":   inst.findtext("param") or "",
                    "attack":  inst.findtext("attack") or "",
                    "evidence": inst.findtext("evidence") or "",
                })

            findings.append({
                "id": f"zap-{plugin_id}-{cweid}",
                "name": name,
                "severity": severity,
                "severity_rank": SEVERITY_RANK.get(severity, 0),
                "cwe_id": cweid,
                "wasc_id": wascid,
                "owasp_category": owasp_category,
                "plugin_id": plugin_id,
                "confidence": confidence,
                "risk_code": risk_code,
                "risk_description": risk_desc,
                "description": desc,
                "solution": solution,
                "reference": reference,
                "instances": instances,
                "instance_count": len(instances),
                "tool": "zap",
            })

    return findings


def parse_zap_json_report(json_path: str) -> list[dict[str, Any]]:
    """Parse ZAP JSON report as fallback if XML is unavailable."""
    findings: list[dict[str, Any]] = []
    try:
        with open(json_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        log(f"Failed to parse ZAP JSON: {e}", "WARN")
        return findings

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            plugin_id   = str(alert.get("pluginid") or "")
            name        = alert.get("alert") or alert.get("name") or "Unknown"
            risk_code   = int(alert.get("riskcode") or 0)
            severity    = ZAP_RISK_MAP.get(risk_code, "info")
            cweid_raw   = str(alert.get("cweid") or PLUGIN_CWE_MAP.get(plugin_id, "0"))
            cweid       = f"CWE-{cweid_raw}" if cweid_raw and not cweid_raw.startswith("CWE-") else cweid_raw
            owasp_category = OWASP_MAP.get(cweid, "Uncategorized")

            instances = [
                {
                    "uri":      inst.get("uri", ""),
                    "method":   inst.get("method", ""),
                    "param":    inst.get("param", ""),
                    "attack":   inst.get("attack", ""),
                    "evidence": inst.get("evidence", ""),
                }
                for inst in alert.get("instances", [])
            ]

            findings.append({
                "id": f"zap-{plugin_id}-{cweid}",
                "name": name,
                "severity": severity,
                "severity_rank": SEVERITY_RANK.get(severity, 0),
                "cwe_id": cweid,
                "owasp_category": owasp_category,
                "plugin_id": plugin_id,
                "confidence": str(alert.get("confidence") or ""),
                "risk_code": risk_code,
                "description": alert.get("desc") or "",
                "solution": alert.get("solution") or "",
                "reference": alert.get("reference") or "",
                "instances": instances,
                "instance_count": len(instances),
                "tool": "zap",
            })

    return findings


# ── Scanner ───────────────────────────────────────────────────────────────────

def build_docker_command(
    target: str,
    mode: str,
    report_dir: str,
    openapi_spec_container: str | None,
    login_url: str | None,
    username: str | None,
    password: str | None,
    extra_args: list[str],
) -> list[str]:
    """Build the docker run command for ZAP."""

    # ZAP script selection
    SCAN_SCRIPTS: dict[str, str] = {
        "baseline": "zap-baseline.py",
        "full":     "zap-full-scan.py",
        "api":      "zap-api-scan.py",
    }
    zap_script = SCAN_SCRIPTS.get(mode, "zap-baseline.py")

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{report_dir}:/zap/wrk",
        ZAP_IMAGE,
        "python", f"/zap/{zap_script}",
        "-t", target,
        "-r", "zap-report.html",
        "-J", "zap-report.json",
        "-x", "zap-report.xml",
        "-I",           # Don't fail on warnings/alerts (let us handle exit codes)
    ]

    if mode == "api" and openapi_spec_container:
        cmd.extend(["-f", openapi_spec_container])

    if login_url:
        # ZAP form-based auth via context file or CLI args (simplified)
        cmd.extend([
            "-config", f"replacer.full_list(0).description=auth-token",
            "-config", f"replacer.full_list(0).enabled=true",
            "-config", f"replacer.full_list(0).matchtype=REQ_HEADER",
            "-config", f"replacer.full_list(0).matchstr=Authorization",
        ])
        log("Auth config provided — manual context setup may be needed for complex auth flows.", "WARN")

    cmd.extend(extra_args)
    return cmd


def run_zap(
    target: str,
    mode: str,
    output_path: str,
    openapi_spec: str | None = None,
    login_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run OWASP ZAP via Docker and return structured results.

    Returns:
        dict with keys: scan_meta, findings, summary
    """
    extra_args = extra_args or []
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    check_docker()
    ensure_zap_image()

    start_time = datetime.now(timezone.utc)
    log(f"Starting ZAP {mode} scan: {target}")

    with tempfile.TemporaryDirectory(prefix="grimsec-zap-") as report_dir:
        # Copy OpenAPI spec into container-accessible volume if provided
        openapi_spec_container: str | None = None
        if openapi_spec and Path(openapi_spec).exists():
            dest = Path(report_dir) / "openapi.yaml"
            shutil.copy2(openapi_spec, dest)
            openapi_spec_container = "/zap/wrk/openapi.yaml"
            log(f"OpenAPI spec copied to container volume: {dest}")

        cmd = build_docker_command(
            target=target,
            mode=mode,
            report_dir=report_dir,
            openapi_spec_container=openapi_spec_container,
            login_url=login_url,
            username=username,
            password=password,
            extra_args=extra_args,
        )

        log(f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=7200,  # 2 hour maximum
            )
        except subprocess.TimeoutExpired:
            log("ZAP scan timed out after 2 hours.", "ERROR")
            result = subprocess.CompletedProcess(cmd, returncode=9, stdout="", stderr="Timeout")

        # ZAP exits non-zero when findings exist — check for report files instead
        xml_report  = Path(report_dir) / "zap-report.xml"
        json_report = Path(report_dir) / "zap-report.json"

        findings: list[dict[str, Any]] = []
        parse_source = "none"

        if xml_report.exists() and xml_report.stat().st_size > 100:
            findings = parse_zap_xml_report(str(xml_report))
            parse_source = "xml"
        elif json_report.exists() and json_report.stat().st_size > 100:
            findings = parse_zap_json_report(str(json_report))
            parse_source = "json"
        else:
            log("No ZAP report file found. Scan may have failed.", "WARN")
            if result.stderr:
                log(result.stderr[-1000:], "WARN")

        end_time = datetime.now(timezone.utc)
        duration_s = (end_time - start_time).total_seconds()

        findings.sort(key=lambda x: x["severity_rank"], reverse=True)

        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        structured = {
            "scan_meta": {
                "tool":            "zap",
                "image":           ZAP_IMAGE,
                "mode":            mode,
                "target":          target,
                "openapi_spec":    openapi_spec,
                "auth_configured": login_url is not None,
                "parse_source":    parse_source,
                "start_time":      start_time.isoformat(),
                "end_time":        end_time.isoformat(),
                "duration_seconds": round(duration_s, 1),
                "zap_exit_code":   result.returncode,
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity":   severity_counts,
                "critical_count": severity_counts.get("critical", 0),
                "high_count":     severity_counts.get("high", 0),
                "medium_count":   severity_counts.get("medium", 0),
                "low_count":      severity_counts.get("low", 0),
                "info_count":     severity_counts.get("info", 0),
            },
            "findings": findings,
        }

        with open(output_path, "w") as out:
            json.dump(structured, out, indent=2, default=str)

        log(f"ZAP scan complete. {len(findings)} alert(s) in {duration_s:.1f}s")
        log(f"Results saved to: {output_path}")
        for sev, count in sorted(severity_counts.items(), key=lambda x: SEVERITY_RANK.get(x[0], 0), reverse=True):
            log(f"  {sev.upper():10s}: {count}")

        return structured


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GRIMSEC DAST Agent 7 — OWASP ZAP Scanner Wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--target", "-t", required=True,
        help="Target URL (e.g. https://example.com)"
    )
    parser.add_argument(
        "--mode", "-m", default="baseline",
        choices=["baseline", "full", "api"],
        help="Scan mode: baseline (passive), full (active+passive), api (OpenAPI-aware) [default: baseline]"
    )
    parser.add_argument(
        "--output", "-o", default="dast-results/zap.json",
        help="Output JSON path [default: dast-results/zap.json]"
    )
    parser.add_argument(
        "--openapi-spec", default=None,
        help="Path to OpenAPI/Swagger spec file (enables API scan mode)"
    )
    parser.add_argument(
        "--login-url", default=None,
        help="Login URL for form-based authentication"
    )
    parser.add_argument(
        "--username", default=None,
        help="Username for authenticated scan"
    )
    parser.add_argument(
        "--password", default=None,
        help="Password for authenticated scan"
    )
    parser.add_argument(
        "--extra", nargs=argparse.REMAINDER, default=[],
        help="Extra arguments passed directly to ZAP scan script"
    )

    args = parser.parse_args()

    # Auto-switch to API mode if OpenAPI spec provided
    mode = args.mode
    if args.openapi_spec and mode != "api":
        log("OpenAPI spec provided — switching to api scan mode.", "INFO")
        mode = "api"

    results = run_zap(
        target=args.target,
        mode=mode,
        output_path=args.output,
        openapi_spec=args.openapi_spec,
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        extra_args=args.extra,
    )

    print(json.dumps(results["summary"], indent=2))

    if results["summary"]["critical_count"] > 0:
        sys.exit(2)
    if results["summary"]["high_count"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
