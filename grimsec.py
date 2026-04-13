#!/usr/bin/env python3
"""
GRIMSEC — AI-Powered DevSecOps Agent Suite

12 autonomous security agents that analyze, audit, validate, and remediate
vulnerabilities in any GitHub repository. Context-aware. Noise-reduced. PR-ready.

Usage:
  grimsec analyze <repo-url>              Full 12-agent pipeline
  grimsec analyze <repo-url> --quick      Agents 1-3 only (fast scan)
  grimsec analyze <repo-url> --deep       All agents + DAST + adversary sim
  grimsec scan <repo-url>                 Just vulnerability scanning (Agent 1, stages 1-3)
  grimsec audit <repo-url>                Just CI/CD audit (Agent 2)
  grimsec enrich <cve-id>                 Enrich a single CVE (Agent 3)
  grimsec monitor                         Run threat intel check (Agent 5)
  grimsec report <analysis-dir>           Generate executive report (Agent 6)
  grimsec dast <target-url>               Run DAST scan (Agent 7)
  grimsec validate <analysis-dir>         Validate findings with PoCs (Agent 8)
  grimsec understand <repo-path>          Map attack surface (Agent 9)
  grimsec iac <repo-path>                 IaC policy scan (Agent 10)
  grimsec forensics <repo-url>            Supply chain forensics (Agent 11)
  grimsec simulate <target>               Adversary simulation (Agent 12)
  grimsec dashboard                       Launch local dashboard
  grimsec status                          Show agent/tool status
  grimsec install                         Install all tools
"""

import argparse
import datetime
import os
import shutil
import subprocess
import sys

# ─── ANSI Colors ───────────────────────────────────────────────────────────────
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
BLUE   = "\033[0;34m"
MAGENTA= "\033[0;35m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def supports_color() -> bool:
    """Return True if the terminal supports ANSI color codes."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def c(color: str, text: str) -> str:
    """Wrap text in a color code (no-op if terminal doesn't support color)."""
    if supports_color():
        return f"{color}{text}{RESET}"
    return text


BANNER = r"""
  ██████╗ ██████╗ ██╗███╗   ███╗███████╗███████╗ ██████╗
 ██╔════╝ ██╔══██╗██║████╗ ████║██╔════╝██╔════╝██╔════╝
 ██║  ███╗██████╔╝██║██╔████╔██║███████╗█████╗  ██║
 ██║   ██║██╔══██╗██║██║╚██╔╝██║╚════██║██╔══╝  ██║
 ╚██████╔╝██║  ██║██║██║ ╚═╝ ██║███████║███████╗╚██████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝
"""

TAGLINE = "AI-Powered DevSecOps Agent Suite  •  12 Agents  •  89-96% Noise Reduction"


def print_banner():
    print(c(CYAN, BANNER))
    print(c(BOLD, f"  {TAGLINE}"))
    print()


# ─── Tool Checks ───────────────────────────────────────────────────────────────
TOOLS = {
    # (display_name, binary, agent)
    "trivy":    ("Trivy (SCA/container)",    "trivy",    "Agent 1"),
    "semgrep":  ("Semgrep (SAST)",           "semgrep",  "Agent 1"),
    "gitleaks": ("Gitleaks (secrets)",       "gitleaks", "Agent 1"),
    "grype":    ("Grype (SCA)",              "grype",    "Agent 1"),
    "snyk":     ("Snyk CLI (optional)",      "snyk",     "Agent 1"),
    "nuclei":   ("Nuclei (DAST)",            "nuclei",   "Agent 7"),
    "httpx":    ("httpx (HTTP probe)",       "httpx",    "Agent 7"),
    "checkov":  ("Checkov (IaC)",            "checkov",  "Agent 10"),
    "opa":      ("OPA (policy engine)",      "opa",      "Agent 10"),
    "conftest": ("Conftest (policy tests)",  "conftest", "Agent 10"),
    "syft":     ("Syft (SBOM)",              "syft",     "Agent 10"),
}

AGENT_SKILLS = {
    "analyze":    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    "scan":       [1],
    "audit":      [2],
    "enrich":     [3],
    "doc":        [4],
    "monitor":    [5],
    "report":     [6],
    "dast":       [7],
    "validate":   [8],
    "understand": [9],
    "iac":        [10],
    "forensics":  [11],
    "simulate":   [12],
}

AGENT_NAMES = {
    1:  ("01-devsecops-repo-analyzer",    "DevSecOps Repo Analyzer",        "devsecops-repo-analyzer"),
    2:  ("02-cicd-pipeline-auditor",      "CI/CD Pipeline Auditor",          "cicd-pipeline-auditor"),
    3:  ("03-vulnerability-context-enricher", "Vulnerability Context Enricher", "vulnerability-context-enricher"),
    4:  ("04-doc-intelligence-agent",     "Doc Intelligence Agent",          "doc-intelligence-agent"),
    5:  ("05-threat-intel-monitor",       "Threat Intel Monitor",            "threat-intel-monitor"),
    6:  ("06-executive-reporting-agent",  "Executive Reporting Agent",       "executive-reporting-agent"),
    7:  ("07-dast-scanner",               "DAST Scanner",                    "dast-scanner"),
    8:  ("08-exploit-validation-agent",   "Exploit Validation Agent",        "exploit-validation-agent"),
    9:  ("09-code-understanding-agent",   "Code Understanding Agent",        "code-understanding-agent"),
    10: ("10-iac-policy-agent",           "IaC Policy Agent",                "iac-policy-agent"),
    11: ("11-oss-forensics-agent",        "OSS Forensics Agent",             "oss-forensics-agent"),
    12: ("12-adversary-simulation-agent", "Adversary Simulation Agent",      "adversary-simulation-agent"),
}


def check_tools() -> dict:
    """Return dict of tool → (installed: bool, version_hint: str)."""
    results = {}
    for key, (display, binary, _agent) in TOOLS.items():
        path = shutil.which(binary)
        if path:
            try:
                out = subprocess.run(
                    [binary, "--version"],
                    capture_output=True, text=True, timeout=5
                )
                ver = (out.stdout or out.stderr).strip().splitlines()[0][:60]
            except Exception:
                ver = "installed"
            results[key] = (True, ver)
        else:
            results[key] = (False, "not found")
    return results


def make_output_dir(repo_or_target: str) -> str:
    """Create grimsec-output/<name>/<timestamp>/ and return the path."""
    name = repo_or_target.rstrip("/").split("/")[-1].replace(".git", "") or "target"
    ts   = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    path = os.path.join("grimsec-output", name, ts)
    os.makedirs(path, exist_ok=True)
    return path


def print_skill_instructions(agent_nums: list):
    """Print Perplexity Computer skill loading instructions."""
    print()
    print(c(BOLD, "─── Perplexity Computer Skills ──────────────────────────────"))
    print(c(DIM, "  Load the following skill(s) in Perplexity Computer:"))
    print()
    for n in agent_nums:
        _dir, display, skill_id = AGENT_NAMES[n]
        print(f"  {c(CYAN, f'Agent {n:02d}')}: {display}")
        print(f"           {c(DIM, f'perplexity.ai → Computer → Skills → Load: {skill_id}')}")
    print()
    print(c(DIM, "  Then trigger with natural language, e.g.:"))
    print(c(DIM, '  "analyze this repo for security issues"'))
    print()


# ─── Subcommand Handlers ───────────────────────────────────────────────────────

def cmd_analyze(args):
    print_banner()
    repo = args.repo_url
    if args.quick:
        mode = "quick"
        agents = [1, 2, 3]
        print(c(YELLOW, f"  [QUICK MODE] Running Agents 1-3 on: {repo}"))
    elif args.deep:
        mode = "deep"
        agents = list(range(1, 13))
        print(c(YELLOW, f"  [DEEP MODE] Running all 12 agents on: {repo}"))
    else:
        mode = "standard"
        agents = list(range(1, 13))
        print(c(GREEN, f"  [FULL PIPELINE] Running 12 agents on: {repo}"))

    out_dir = make_output_dir(repo)
    print(c(DIM, f"  Output directory: {out_dir}"))
    print()

    print(c(BOLD, "─── Pipeline Stages ─────────────────────────────────────────"))
    stage_map = {
        1:  "Repository inventory + STRIDE threat model + multi-scanner run",
        2:  "CI/CD workflow audit (supply chain, PPE, injection)",
        3:  "CVE enrichment (NVD + EPSS + CISA KEV + ATT&CK)",
        4:  "Documentation intelligence (validate/downgrade findings)",
        5:  "Threat intel monitoring against dependency inventory",
        6:  "Executive report generation (risk $$, compliance, board deck)",
        7:  "DAST scan (Nuclei + ZAP against running application)",
        8:  "Exploit validation with PoC generation",
        9:  "Attack surface mapping + source-to-sink tracing",
        10: "IaC policy scan (Docker, K8s, Terraform, GH Actions)",
        11: "OSS supply chain forensics (IOC detection, timeline)",
        12: "Adversary simulation (ATT&CK-mapped controlled exploitation)",
    }
    for n in agents:
        _dir, display, _skill = AGENT_NAMES[n]
        print(f"  {c(CYAN, f'[{n:02d}]')} {display}")
        print(f"       {c(DIM, stage_map[n])}")
    print()

    print_skill_instructions(agents)

    print(c(BOLD, "─── How To Run ──────────────────────────────────────────────"))
    print(f"  1. Load each skill in Perplexity Computer (see above)")
    print(f"  2. Provide the repo URL: {c(CYAN, repo)}")
    print(f"  3. Output will be structured at: {c(CYAN, out_dir)}")
    print(f"  4. Run {c(CYAN, 'python grimsec.py report ' + out_dir)} when done")
    print()
    if mode == "deep":
        print(c(YELLOW, "  ⚠  DEEP MODE includes active DAST and adversary simulation."))
        print(c(YELLOW, "     Only run against targets you own or have explicit permission to test."))
        print()


def cmd_scan(args):
    print_banner()
    repo = args.repo_url
    out_dir = make_output_dir(repo)
    print(c(GREEN, f"  [SCAN] Running vulnerability scan on: {repo}"))
    print(c(DIM,   f"  Output: {out_dir}"))
    print()
    print(c(BOLD, "  This runs Agent 1 (stages 1-3 only):"))
    print(c(DIM,  "    Stage 1: Repository inventory"))
    print(c(DIM,  "    Stage 2: STRIDE threat model"))
    print(c(DIM,  "    Stage 3: Multi-scanner run (Trivy + Semgrep + Gitleaks + Grype)"))
    print()
    print_skill_instructions([1])


def cmd_audit(args):
    print_banner()
    repo = args.repo_url
    out_dir = make_output_dir(repo)
    print(c(GREEN, f"  [AUDIT] Running CI/CD audit on: {repo}"))
    print(c(DIM,   f"  Output: {out_dir}"))
    print()
    print(c(BOLD, "  Agent 2 checks for:"))
    print(c(DIM,  "    • Unpinned third-party actions (supply chain risk)"))
    print(c(DIM,  "    • Expression injection / script injection"))
    print(c(DIM,  "    • Overpermissive workflow permissions"))
    print(c(DIM,  "    • Dangerous triggers (pull_request_target, workflow_run PPE)"))
    print(c(DIM,  "    • Secrets exposure in workflow steps"))
    print(c(DIM,  "    • Self-hosted runner risks"))
    print()
    print_skill_instructions([2])


def cmd_enrich(args):
    print_banner()
    cve = args.cve_id.upper()
    print(c(GREEN, f"  [ENRICH] Enriching: {cve}"))
    print()
    print(c(BOLD, "  Agent 3 will fetch:"))
    print(c(DIM,  f"    • NVD record for {cve} (CVSS v3.1 + vector)"))
    print(c(DIM,  "    • EPSS score (probability of exploitation in 30 days)"))
    print(c(DIM,  "    • CISA KEV status (is it actively exploited?)"))
    print(c(DIM,  "    • MITRE ATT&CK technique mapping"))
    print(c(DIM,  "    • Reachability verdict (REACHABLE / UNREACHABLE / UNKNOWN)"))
    print(c(DIM,  "    • Remediation priority with PR-ready fix"))
    print()
    print_skill_instructions([3])
    print(c(DIM, f"  Trigger: \"enrich {cve}\""))


def cmd_monitor(args):
    print_banner()
    print(c(GREEN, "  [MONITOR] Running threat intel monitor"))
    print()
    print(c(BOLD, "  Agent 5 will:"))
    print(c(DIM,  "    • Load your dependency inventory (inventory.json)"))
    print(c(DIM,  "    • Check NVD for CVEs published in the last 48 hours"))
    print(c(DIM,  "    • Cross-reference with CISA KEV for active exploitation"))
    print(c(DIM,  "    • Score and rank emerging threats"))
    print(c(DIM,  "    • Generate alert report with actionable remediation steps"))
    print()
    print_skill_instructions([5])
    print(c(DIM, "  Trigger: \"run threat intel check\""))
    print(c(DIM, "  Tip: set NVD_API_KEY env variable for higher rate limits"))


def cmd_report(args):
    print_banner()
    analysis_dir = args.analysis_dir
    print(c(GREEN, f"  [REPORT] Generating executive report from: {analysis_dir}"))
    print()
    print(c(BOLD, "  Agent 6 will produce:"))
    print(c(DIM,  "    • Executive summary (2-page board-ready version)"))
    print(c(DIM,  "    • Risk quantification in $ impact estimates"))
    print(c(DIM,  "    • Compliance mapping (SOC 2, ISO 27001, NIST CSF, OWASP SAMM)"))
    print(c(DIM,  "    • Prioritized finding table (Critical → Low)"))
    print(c(DIM,  "    • Remediation roadmap with effort estimates"))
    print(c(DIM,  "    • Trend comparison if prior scans exist"))
    print()
    print_skill_instructions([6])
    print(c(DIM, f"  Trigger: \"generate executive report from {analysis_dir}\""))


def cmd_dast(args):
    print_banner()
    target = args.target_url
    out_dir = make_output_dir(target)
    print(c(GREEN, f"  [DAST] Running DAST scan against: {target}"))
    print(c(DIM,   f"  Output: {out_dir}"))
    print()
    print(c(BOLD, "  Agent 7 will run:"))
    print(c(DIM,  "    • Nuclei with community + custom templates"))
    print(c(DIM,  "    • OWASP ZAP active scan (if configured)"))
    print(c(DIM,  "    • httpx service fingerprinting"))
    print(c(DIM,  "    • API endpoint fuzzing"))
    print()
    print(c(YELLOW, "  ⚠  Only run against targets you own or have explicit permission to test."))
    print()
    print_skill_instructions([7])
    print(c(DIM, f"  Trigger: \"run DAST scan against {target}\""))


def cmd_validate(args):
    print_banner()
    analysis_dir = args.analysis_dir
    print(c(GREEN, f"  [VALIDATE] Validating findings in: {analysis_dir}"))
    print()
    print(c(BOLD, "  Agent 8 will:"))
    print(c(DIM,  "    • Review each finding from scan-results/"))
    print(c(DIM,  "    • Generate PoC code proving exploitability"))
    print(c(DIM,  "    • Assign verdict: EXPLOITABLE / NOT_EXPLOITABLE / NEEDS_ACCESS"))
    print(c(DIM,  "    • Update risk scores based on confirmed exploitability"))
    print(c(DIM,  "    • Produce validation report with evidence"))
    print()
    print(c(YELLOW, "  ⚠  All PoC generation is for authorized security testing only."))
    print()
    print_skill_instructions([8])


def cmd_understand(args):
    print_banner()
    repo_path = args.repo_path
    out_dir = make_output_dir(repo_path)
    print(c(GREEN, f"  [UNDERSTAND] Mapping attack surface of: {repo_path}"))
    print(c(DIM,   f"  Output: {out_dir}"))
    print()
    print(c(BOLD, "  Agent 9 will produce:"))
    print(c(DIM,  "    • Attack surface map (all entry points)"))
    print(c(DIM,  "    • Source-to-sink data flow traces"))
    print(c(DIM,  "    • Dangerous sink inventory"))
    print(c(DIM,  "    • Variant analysis (finding N variants of a known pattern)"))
    print(c(DIM,  "    • context-map.json for downstream agent consumption"))
    print()
    print_skill_instructions([9])


def cmd_iac(args):
    print_banner()
    repo_path = args.repo_path
    out_dir = make_output_dir(repo_path)
    print(c(GREEN, f"  [IAC] Running IaC policy scan on: {repo_path}"))
    print(c(DIM,   f"  Output: {out_dir}"))
    print()
    print(c(BOLD, "  Agent 10 covers:"))
    print(c(DIM,  "    • Dockerfile: user, capabilities, secrets in ARG/ENV"))
    print(c(DIM,  "    • Kubernetes: privileged pods, host namespaces, RBAC"))
    print(c(DIM,  "    • Terraform: open security groups, unencrypted resources"))
    print(c(DIM,  "    • GitHub Actions: unpinned actions, excessive permissions"))
    print(c(DIM,  "    • OPA custom policies via .rego files"))
    print()
    print_skill_instructions([10])


def cmd_forensics(args):
    print_banner()
    repo = args.repo_url
    out_dir = make_output_dir(repo)
    print(c(GREEN, f"  [FORENSICS] Running OSS forensics on: {repo}"))
    print(c(DIM,   f"  Output: {out_dir}"))
    print()
    print(c(BOLD, "  Agent 11 will investigate:"))
    print(c(DIM,  "    • Commit history for suspicious changes"))
    print(c(DIM,  "    • Maintainer account anomalies"))
    print(c(DIM,  "    • Build script modifications"))
    print(c(DIM,  "    • IOC patterns (exfiltration, backdoors, typosquatting)"))
    print(c(DIM,  "    • Supply chain attack timeline reconstruction"))
    print(c(DIM,  "    • Forensic evidence package"))
    print()
    print_skill_instructions([11])


def cmd_simulate(args):
    print_banner()
    target = args.target
    out_dir = make_output_dir(target)
    print(c(GREEN, f"  [SIMULATE] Running adversary simulation against: {target}"))
    print(c(DIM,   f"  Output: {out_dir}"))
    print()
    print(c(BOLD, "  Agent 12 will:"))
    print(c(DIM,  "    • Map applicable ATT&CK techniques"))
    print(c(DIM,  "    • Execute controlled exploitation scenarios"))
    print(c(DIM,  "    • Document kill chain with evidence"))
    print(c(DIM,  "    • Produce remediation recommendations"))
    print()
    print(c(RED, "  ⛔ AUTHORIZED USE ONLY."))
    print(c(RED, "     Only run against systems you own or have written permission to test."))
    print(c(RED, "     A Rules of Engagement document is required before proceeding."))
    print()
    print_skill_instructions([12])


def cmd_dashboard(_args):
    print_banner()
    print(c(GREEN, "  [DASHBOARD] Dashboard setup instructions:"))
    print()
    print(c(DIM, "  See dashboard/README.md for full setup instructions."))
    print()
    print(c(BOLD, "  Quick start:"))
    print(c(DIM,  "    1. Point your dashboard tool at grimsec-output/"))
    print(c(DIM,  "    2. Load findings.json / executive-summary.json"))
    print(c(DIM,  "    3. Any JSON-capable dashboard (Grafana, Metabase, etc.) works"))
    print()


def cmd_status(_args):
    print_banner()
    print(c(BOLD, "─── Tool Status ─────────────────────────────────────────────"))
    tool_status = check_tools()
    all_ok = True
    for key, (display, _binary, agent) in TOOLS.items():
        installed, version = tool_status[key]
        if installed:
            mark = c(GREEN, "✓")
            ver_str = c(DIM, f"({version})")
        else:
            mark = c(RED, "✗")
            ver_str = c(RED, "(not installed — run: python grimsec.py install)")
            all_ok = False
        print(f"  {mark}  {display:<35} {c(DIM, agent)}  {ver_str}")
    print()
    if all_ok:
        print(c(GREEN, "  All tools installed. Ready to run."))
    else:
        print(c(YELLOW, "  Some tools are missing. Run: python grimsec.py install"))
    print()

    print(c(BOLD, "─── Agent Skills ────────────────────────────────────────────"))
    agents_dir = os.path.join(os.path.dirname(__file__), "agents")
    for n, (agent_dir, display, skill_id) in AGENT_NAMES.items():
        skill_path = os.path.join(agents_dir, agent_dir, "SKILL.md")
        if os.path.exists(skill_path):
            mark = c(GREEN, "✓")
            note = c(DIM, f"agents/{agent_dir}/SKILL.md")
        else:
            mark = c(RED, "✗")
            note = c(RED, "SKILL.md not found")
        print(f"  {mark}  Agent {n:02d}: {display:<40} {note}")
    print()


def cmd_install(_args):
    print_banner()
    print(c(GREEN, "  [INSTALL] Installing GRIMSEC tools..."))
    print()
    install_script = os.path.join(os.path.dirname(__file__), "scripts", "install-tools.sh")
    if not os.path.exists(install_script):
        print(c(RED, f"  Install script not found: {install_script}"))
        sys.exit(1)
    print(c(DIM, f"  Running: bash {install_script}"))
    print()
    result = subprocess.run(["bash", install_script])
    if result.returncode == 0:
        print()
        print(c(GREEN, "  Installation complete. Run: python grimsec.py status"))
    else:
        print(c(RED, "  Installation encountered errors. Check output above."))
        sys.exit(result.returncode)


# ─── Argument Parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grimsec",
        description="GRIMSEC — AI-Powered DevSecOps Agent Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # analyze
    p = sub.add_parser("analyze", help="Run full 12-agent pipeline on a repository")
    p.add_argument("repo_url", metavar="<repo-url>", help="GitHub repository URL")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="Run agents 1-3 only (fast scan)")
    mode.add_argument("--deep",  action="store_true", help="All agents + DAST + adversary sim")
    p.set_defaults(func=cmd_analyze)

    # scan
    p = sub.add_parser("scan", help="Vulnerability scanning only (Agent 1, stages 1-3)")
    p.add_argument("repo_url", metavar="<repo-url>", help="GitHub repository URL")
    p.set_defaults(func=cmd_scan)

    # audit
    p = sub.add_parser("audit", help="CI/CD pipeline audit (Agent 2)")
    p.add_argument("repo_url", metavar="<repo-url>", help="GitHub repository URL")
    p.set_defaults(func=cmd_audit)

    # enrich
    p = sub.add_parser("enrich", help="Enrich a single CVE (Agent 3)")
    p.add_argument("cve_id", metavar="<cve-id>", help="CVE identifier (e.g. CVE-2024-1234)")
    p.set_defaults(func=cmd_enrich)

    # monitor
    p = sub.add_parser("monitor", help="Run threat intel check (Agent 5)")
    p.set_defaults(func=cmd_monitor)

    # report
    p = sub.add_parser("report", help="Generate executive report (Agent 6)")
    p.add_argument("analysis_dir", metavar="<analysis-dir>", help="Path to analysis output directory")
    p.set_defaults(func=cmd_report)

    # dast
    p = sub.add_parser("dast", help="DAST scan against a running application (Agent 7)")
    p.add_argument("target_url", metavar="<target-url>", help="Target URL (must be authorized)")
    p.set_defaults(func=cmd_dast)

    # validate
    p = sub.add_parser("validate", help="Validate findings with PoCs (Agent 8)")
    p.add_argument("analysis_dir", metavar="<analysis-dir>", help="Path to analysis output directory")
    p.set_defaults(func=cmd_validate)

    # understand
    p = sub.add_parser("understand", help="Map attack surface (Agent 9)")
    p.add_argument("repo_path", metavar="<repo-path>", help="Local repository path or GitHub URL")
    p.set_defaults(func=cmd_understand)

    # iac
    p = sub.add_parser("iac", help="IaC policy scan (Agent 10)")
    p.add_argument("repo_path", metavar="<repo-path>", help="Local repository path or GitHub URL")
    p.set_defaults(func=cmd_iac)

    # forensics
    p = sub.add_parser("forensics", help="OSS supply chain forensics (Agent 11)")
    p.add_argument("repo_url", metavar="<repo-url>", help="GitHub repository URL")
    p.set_defaults(func=cmd_forensics)

    # simulate
    p = sub.add_parser("simulate", help="Adversary simulation — AUTHORIZED USE ONLY (Agent 12)")
    p.add_argument("target", metavar="<target>", help="Target system (authorized targets only)")
    p.set_defaults(func=cmd_simulate)

    # dashboard
    p = sub.add_parser("dashboard", help="Show dashboard setup instructions")
    p.set_defaults(func=cmd_dashboard)

    # status
    p = sub.add_parser("status", help="Show agent and tool status")
    p.set_defaults(func=cmd_status)

    # install
    p = sub.add_parser("install", help="Install all scanning tools")
    p.set_defaults(func=cmd_install)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
