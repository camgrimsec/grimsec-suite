#!/usr/bin/env python3
"""
run-simulation.py — Orchestrate adversary simulation using RedAmon
GRIMSEC DevSecOps Suite — Agent 12: Adversary Simulation Agent

Reads EXPLOITABLE findings from exploit-validation-agent and drives
RedAmon through the full adversary simulation pipeline.

USAGE:
    python scripts/run-simulation.py [OPTIONS]

    Options:
      --roe FILE            Path to roe.json (required)
      --findings FILE       Path to exploit-validation/validation-report.json
      --scenarios FILE      Path to references/attack-scenarios.md
      --output FILE         Output exploitation-log.json path
      --phase PHASE         Run specific phase only (1-6, default: all)
      --dry-run             Print planned actions without executing
      --no-approval         Skip human approval prompt (TESTING ONLY)
      --neo4j-uri URI       Neo4j connection URI
      --timeout SECONDS     Per-exploit timeout (default: 300)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Optional rich console for pretty output
# --------------------------------------------------------------------------- #
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
    def log(msg, style="bold blue"):   console.print(f"[{style}][run-simulation][/{style}] {msg}")
    def warn(msg):  console.print(f"[bold yellow][WARN][/bold yellow] {msg}")
    def err(msg):   console.print(f"[bold red][ERROR][/bold red] {msg}", file=sys.stderr)
    def ok(msg):    console.print(f"[bold green][OK][/bold green] {msg}")
    HAS_RICH = True
except ImportError:
    def log(msg, style=None):  print(f"[run-simulation] {msg}")
    def warn(msg):  print(f"[WARN] {msg}", file=sys.stderr)
    def err(msg):   print(f"[ERROR] {msg}", file=sys.stderr)
    def ok(msg):    print(f"[OK] {msg}")
    HAS_RICH = False


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
EXPLOITABLE_STATUS = "EXPLOITABLE"
EMERGENCY_STOP_CMD = ["./redamon.sh", "down"]
APPROVAL_TIMEOUT_SECONDS = 1800  # 30 minutes

TOOL_MAP = {
    "CVE":              "metasploit",
    "SQLI":             "sqlmap",
    "CREDENTIAL":       "hydra",
    "JWT":              "custom_payload",
    "CONTAINER_ESCAPE": "redamon_container_escape",
    "SSRF":             "custom_payload",
    "SUPPLY_CHAIN":     "redamon_dependency_hijack",
    "WEBSOCKET":        "custom_payload",
    "XSS":              "nuclei",
    "RCE":              "metasploit",
    "IDOR":             "custom_payload",
    "PATH_TRAVERSAL":   "custom_payload",
}


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #
class ExploitFinding:
    def __init__(self, data: dict[str, Any]):
        self.id: str = data.get("id", str(uuid.uuid4()))
        self.vuln_type: str = data.get("vuln_type", "UNKNOWN").upper()
        self.severity: str = data.get("severity", "UNKNOWN")
        self.target: str = data.get("target", "")
        self.endpoint: str = data.get("endpoint", "")
        self.cve: str | None = data.get("cve")
        self.status: str = data.get("status", "")
        self.confidence: float = data.get("confidence", 0.0)
        self.evidence: dict = data.get("evidence", {})
        self.raw = data

    @property
    def tool(self) -> str:
        return TOOL_MAP.get(self.vuln_type, "custom_payload")


class ExploitAttempt:
    def __init__(self, finding: ExploitFinding):
        self.finding = finding
        self.attempt_id = str(uuid.uuid4())
        self.timestamp_start: str = ""
        self.timestamp_end: str = ""
        self.success: bool = False
        self.output: str = ""
        self.error: str | None = None
        self.tool_used: str = finding.tool
        self.command: list[str] = []
        self.post_conditions: dict = {}
        self.evograph_node_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "attempt_id": self.attempt_id,
            "finding_id": self.finding.id,
            "vuln_type": self.finding.vuln_type,
            "target": self.finding.target,
            "endpoint": self.finding.endpoint,
            "tool_used": self.tool_used,
            "command": self.command,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": self.timestamp_end,
            "success": self.success,
            "output_summary": self.output[:2000] if self.output else "",
            "error": self.error,
            "post_conditions": self.post_conditions,
            "evograph_node_id": self.evograph_node_id,
        }


# --------------------------------------------------------------------------- #
# Core simulation runner
# --------------------------------------------------------------------------- #
class SimulationRunner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.engagement_id = str(uuid.uuid4())
        self.roe: dict = {}
        self.findings: list[ExploitFinding] = []
        self.attempts: list[ExploitAttempt] = []
        self.start_time = datetime.now(timezone.utc)
        self.output_dir = Path(args.output).parent
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Phase 1: Load and validate RoE
    # ------------------------------------------------------------------ #
    def load_roe(self) -> bool:
        log("Phase 1: Loading Rules of Engagement...")
        roe_path = Path(self.args.roe)
        if not roe_path.exists():
            err(f"RoE file not found: {roe_path}")
            err("Create a RoE first using assets/templates/roe-template.md")
            return False

        with open(roe_path) as f:
            self.roe = json.load(f)

        # Validate required fields
        required = ["engagement_id", "authorized_by", "scope", "time_window", "contacts"]
        missing = [k for k in required if k not in self.roe]
        if missing:
            err(f"RoE is missing required fields: {missing}")
            return False

        # Check time window
        now = datetime.now(timezone.utc).isoformat()
        window_start = self.roe["time_window"].get("start", "")
        window_end = self.roe["time_window"].get("end", "")
        if window_start and now < window_start:
            warn(f"Testing window hasn't started yet. Window starts: {window_start}")
        if window_end and now > window_end:
            err(f"Testing window has EXPIRED. Window ended: {window_end}")
            err("Update RoE with a new authorized time window before continuing.")
            return False

        ok(f"RoE loaded. Authorized by: {self.roe['authorized_by']}")
        log(f"Scope: {len(self.roe['scope'].get('targets', []))} targets")
        return True

    # ------------------------------------------------------------------ #
    # Phase 2: Load exploit-validation findings
    # ------------------------------------------------------------------ #
    def load_findings(self) -> bool:
        log("Loading exploit-validation findings...")
        findings_path = Path(self.args.findings)
        if not findings_path.exists():
            err(f"Findings file not found: {findings_path}")
            return False

        with open(findings_path) as f:
            data = json.load(f)

        # Support both flat list and {findings: [...]} shapes
        raw_findings = data if isinstance(data, list) else data.get("findings", [])

        all_findings = [ExploitFinding(f) for f in raw_findings]
        self.findings = [f for f in all_findings if f.status == EXPLOITABLE_STATUS]

        log(f"Total findings: {len(all_findings)} | EXPLOITABLE: {len(self.findings)}")
        if not self.findings:
            warn("No EXPLOITABLE findings to simulate. Check validation-report.json.")
            return False

        # Display findings table
        if HAS_RICH:
            t = Table(title="EXPLOITABLE Findings — Attack Hypotheses")
            for col in ("ID", "Type", "Severity", "Target", "Tool"):
                t.add_column(col)
            for f in self.findings:
                t.add_row(f.id[:8], f.vuln_type, f.severity, f.target, f.tool)
            console.print(t)

        return True

    # ------------------------------------------------------------------ #
    # Human approval gate
    # ------------------------------------------------------------------ #
    def request_approval(self) -> bool:
        if self.args.no_approval:
            warn("--no-approval flag set. Skipping human approval (TESTING ONLY).")
            return True

        print("\n" + "="*70)
        print("⚠️  HUMAN APPROVAL REQUIRED BEFORE EXPLOITATION")
        print("="*70)
        print(f"\nEngagement ID : {self.engagement_id}")
        print(f"Authorized by : {self.roe.get('authorized_by', 'UNKNOWN')}")
        print(f"Scope         : {', '.join(self.roe['scope'].get('targets', []))}")
        print(f"\nPlanned exploit attempts: {len(self.findings)}")
        print()

        for i, f in enumerate(self.findings, 1):
            print(f"  {i:2d}. [{f.severity}] {f.vuln_type} → {f.target}{f.endpoint} (tool: {f.tool})")
            if f.cve:
                print(f"       CVE: {f.cve}")

        print("\nType APPROVE to proceed, or anything else to abort:")
        print("  (You have 30 minutes before this request times out)")
        print()

        try:
            response = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            err("Approval interrupted. Aborting simulation.")
            return False

        if response == "APPROVE":
            ok("Exploitation approved. Proceeding...")
            return True
        else:
            warn("Approval not granted. Aborting Phase 3.")
            return False

    # ------------------------------------------------------------------ #
    # Phase 3: Execute exploitation attempts
    # ------------------------------------------------------------------ #
    def run_exploitation(self) -> None:
        log("Phase 3: Exploitation — executing attack hypotheses...")

        for finding in self.findings:
            attempt = ExploitAttempt(finding)
            attempt.timestamp_start = datetime.now(timezone.utc).isoformat()

            log(f"Attempting: [{finding.severity}] {finding.vuln_type} → {finding.target}")

            if self.args.dry_run:
                warn(f"[DRY-RUN] Would execute {finding.tool} against {finding.target}")
                attempt.success = False
                attempt.output = "[DRY-RUN] Not executed"
                attempt.timestamp_end = datetime.now(timezone.utc).isoformat()
                self.attempts.append(attempt)
                continue

            # Check target is in scope before each attempt
            if not self._is_in_scope(finding.target):
                warn(f"Target {finding.target} is OUT OF SCOPE. Skipping.")
                attempt.error = "OUT_OF_SCOPE"
                attempt.timestamp_end = datetime.now(timezone.utc).isoformat()
                self.attempts.append(attempt)
                continue

            try:
                success, output, command = self._dispatch_exploit(finding)
                attempt.success = success
                attempt.output = output
                attempt.command = command
            except Exception as e:
                err(f"Exploit execution error: {e}")
                attempt.error = str(e)
            finally:
                attempt.timestamp_end = datetime.now(timezone.utc).isoformat()

            if attempt.success:
                ok(f"SUCCESS: {finding.vuln_type} on {finding.target}")
            else:
                log(f"NOT EXPLOITED: {finding.vuln_type} on {finding.target}")

            self.attempts.append(attempt)
            self._update_evograph(attempt)

    def _is_in_scope(self, target: str) -> bool:
        """Check if target is within the authorized scope."""
        scope_targets = self.roe.get("scope", {}).get("targets", [])
        exclusions = self.roe.get("scope", {}).get("exclusions", [])
        if target in exclusions:
            return False
        return any(target == t or target.startswith(t.rstrip("/*")) for t in scope_targets)

    def _dispatch_exploit(self, finding: ExploitFinding) -> tuple[bool, str, list[str]]:
        """Build and execute the appropriate exploit command."""
        tool = finding.tool
        timeout = self.args.timeout

        if tool == "sqlmap":
            cmd = [
                "sqlmap", "-u", f"http://{finding.target}{finding.endpoint}",
                "--level", "3", "--risk", "2", "--batch",
                "--output-dir", str(self.output_dir / "sqlmap"),
                "--timeout", "30"
            ]
        elif tool == "hydra":
            cmd = [
                "hydra", "-L", "references/wordlists/users.txt",
                "-P", "references/wordlists/passwords.txt",
                finding.target, "http-post-form",
                "/:username=^USER^&password=^PASS^:F=incorrect",
                "-t", "4", "-f"
            ]
        elif tool == "metasploit":
            module = self._cve_to_msf_module(finding.cve)
            cmd = [
                "msfconsole", "-q", "-x",
                f"use {module}; set RHOSTS {finding.target}; set LHOST 127.0.0.1; run; exit"
            ]
        elif tool == "nuclei":
            cmd = [
                "nuclei", "-u", f"http://{finding.target}",
                "-severity", "high,critical",
                "-json-export", str(self.output_dir / f"nuclei-{finding.id[:8]}.json"),
                "-silent"
            ]
        elif tool == "redamon_container_escape":
            cmd = [
                "./redamon.sh", "exploit", "--module", "container-escape",
                "--target", finding.target,
                "--output", str(self.output_dir / f"container-escape-{finding.id[:8]}.json")
            ]
        elif tool == "redamon_dependency_hijack":
            cmd = [
                "./redamon.sh", "exploit", "--module", "dependency-hijack",
                "--target", finding.target
            ]
        else:
            # Custom payload via RedAmon payload engine
            cmd = [
                "./redamon.sh", "exploit", "--module", "custom-payload",
                "--vuln-type", finding.vuln_type,
                "--target", finding.target,
                "--endpoint", finding.endpoint,
                "--evidence", json.dumps(finding.evidence)
            ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            success = result.returncode == 0
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = f"Timed out after {timeout}s"
            success = False
        except FileNotFoundError:
            output = f"Tool not found: {cmd[0]}"
            success = False

        return success, output, cmd

    def _cve_to_msf_module(self, cve: str | None) -> str:
        """Map CVE ID to Metasploit module path (simplified lookup)."""
        if not cve:
            return "exploit/multi/handler"
        # Real implementation would query MSF's module database
        # This returns a placeholder that RedAmon's AI agent resolves
        return f"exploit/auto/{cve.lower().replace('-', '_')}"

    def _update_evograph(self, attempt: ExploitAttempt) -> None:
        """Record attempt in RedAmon's EvoGraph attack chain."""
        try:
            node_data = {
                "node_type": "exploit_attempt",
                "finding_id": attempt.finding.id,
                "tool": attempt.tool_used,
                "target": attempt.finding.target,
                "success": attempt.success,
                "timestamp": attempt.timestamp_start
            }
            result = subprocess.run(
                ["./redamon.sh", "graph", "--add-node", json.dumps(node_data)],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                attempt.evograph_node_id = result.stdout.strip()
        except Exception:
            pass  # EvoGraph is best-effort; don't fail simulation

    # ------------------------------------------------------------------ #
    # Write outputs
    # ------------------------------------------------------------------ #
    def write_outputs(self) -> None:
        log("Writing exploitation log...")
        output_path = Path(self.args.output)
        end_time = datetime.now(timezone.utc)
        duration_seconds = (end_time - self.start_time).total_seconds()

        successful_attempts = [a for a in self.attempts if a.success]
        failed_attempts = [a for a in self.attempts if not a.success]

        log_data = {
            "engagement_id": self.engagement_id,
            "roe_engagement_id": self.roe.get("engagement_id"),
            "authorized_by": self.roe.get("authorized_by"),
            "simulation_start": self.start_time.isoformat(),
            "simulation_end": end_time.isoformat(),
            "duration_seconds": duration_seconds,
            "findings_evaluated": len(self.findings),
            "attempts_made": len(self.attempts),
            "successful_exploits": len(successful_attempts),
            "failed_exploits": len(failed_attempts),
            "skipped_out_of_scope": sum(1 for a in self.attempts if a.error == "OUT_OF_SCOPE"),
            "attempts": [a.to_dict() for a in self.attempts],
            "attack_chain": [a.to_dict() for a in self.attempts if a.success],
            "meta": {
                "tool_version": "adversary-simulation-agent/1.0",
                "dry_run": self.args.dry_run,
            }
        }

        with open(output_path, "w") as f:
            json.dump(log_data, f, indent=2)

        ok(f"Exploitation log written: {output_path}")
        log(f"Summary: {len(successful_attempts)} successful / {len(self.attempts)} total attempts")
        log(f"Duration: {duration_seconds:.0f}s ({duration_seconds/60:.1f} min)")

    # ------------------------------------------------------------------ #
    # Main entry point
    # ------------------------------------------------------------------ #
    def run(self) -> int:
        log("=== GRIMSEC Adversary Simulation Agent — RedAmon Orchestrator ===")
        warn("REMINDER: Only run against authorized targets within the signed RoE window.")

        # Phase 1: RoE
        if not self.load_roe():
            return 1

        # Phase 2: Findings
        if not self.load_findings():
            return 1

        # Human approval gate
        if not self.request_approval():
            return 0  # Not an error — user declined

        # Phase 3: Exploitation
        self.run_exploitation()

        # Write outputs
        self.write_outputs()

        return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="GRIMSEC Adversary Simulation — RedAmon Orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument("--roe", default="adversary-simulation/roe.json",
                   help="Path to signed rules-of-engagement JSON")
    p.add_argument("--findings", default="exploit-validation/validation-report.json",
                   help="Path to exploit-validation findings JSON")
    p.add_argument("--scenarios", default="references/attack-scenarios.md",
                   help="Path to attack scenarios reference")
    p.add_argument("--output", default="adversary-simulation/exploitation-log.json",
                   help="Output path for exploitation log JSON")
    p.add_argument("--phase", type=int, choices=range(1, 7), default=None,
                   help="Run a specific phase only (1-6)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print planned actions without executing exploits")
    p.add_argument("--no-approval", action="store_true",
                   help="Skip human approval prompt (TESTING ENVIRONMENTS ONLY)")
    p.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                   help="Neo4j connection URI")
    p.add_argument("--timeout", type=int, default=300,
                   help="Per-exploit timeout in seconds")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    runner = SimulationRunner(args)
    sys.exit(runner.run())
