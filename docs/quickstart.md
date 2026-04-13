# GRIMSEC — 5-Minute Quick Start

This guide gets you from zero to your first security analysis in 5 minutes.

---

## Prerequisites

- Python 3.8+
- Git
- macOS or Linux (Windows via WSL2)

---

## Step 1: Clone and Install (2 min)

```bash
git clone https://github.com/yourusername/grimsec-suite.git
cd grimsec-suite
bash setup.sh
```

`setup.sh` installs Python dependencies and all scanning tools (Trivy, Semgrep, Gitleaks, Grype, and optionally Nuclei, Checkov, OPA).

Verify everything is ready:

```bash
python grimsec.py status
```

You should see green checkmarks next to the core tools (Trivy, Semgrep, Gitleaks, Grype).

---

## Step 2: Run Your First Scan (1 min)

```bash
python grimsec.py analyze https://github.com/org/repo --quick
```

The `--quick` flag runs Agents 1-3, which takes 5-10 minutes depending on repo size. This is the best starting point.

Output:

```
  GRIMSEC — AI-Powered DevSecOps Agent Suite

  [QUICK MODE] Running Agents 1-3 on: https://github.com/org/repo
  Output directory: grimsec-output/repo/2026-01-01T12-00-00

  Pipeline Stages:
  [01] DevSecOps Repo Analyzer
       Repository inventory + STRIDE threat model + multi-scanner run
  [02] CI/CD Pipeline Auditor
       CI/CD workflow audit (supply chain, PPE, injection)
  [03] Vulnerability Context Enricher
       CVE enrichment (NVD + EPSS + CISA KEV + ATT&CK)

  Perplexity Computer Skills:
    Agent 01: DevSecOps Repo Analyzer
              perplexity.ai → Computer → Skills → Load: devsecops-repo-analyzer
    ...
```

---

## Step 3: Load the Skill in Perplexity Computer (1 min)

GRIMSEC agents are Perplexity Computer skills. The CLI prints exactly which skills to load.

For `--quick` mode, load Agent 01 first:

1. Go to [perplexity.ai](https://perplexity.ai) → Computer → Skills
2. Click **Import Skill**
3. Select `agents/01-devsecops-repo-analyzer/SKILL.md`
4. The skill loads automatically

Then trigger it:

```
analyze this repo for security issues: https://github.com/org/repo
```

The agent runs all 6 stages and produces structured JSON output.

---

## Step 4: Review Results (1 min)

After Agent 01 completes, check the output:

```bash
ls grimsec-output/repo/2026-01-01T12-00-00/
```

Key files:
- `inventory.json` — what's in the repo (languages, frameworks, packages)
- `scan-results/` — raw scanner output
- `reachability-analysis.json` — which findings are actually reachable
- `findings.json` — deduplicated, prioritized, enriched findings

The findings file shows only what matters:

```json
{
  "summary": {
    "total_raw_findings": 483,
    "after_dedup": 124,
    "after_reachability": 31,
    "after_enrichment": 12,
    "critical_exploitable": 3
  }
}
```

483 raw findings → 3 that actually need immediate action.

---

## Step 5: Generate Executive Report

```bash
python grimsec.py report grimsec-output/repo/2026-01-01T12-00-00
```

Load the `executive-reporting-agent` skill and trigger:

```
generate executive report from the analysis at grimsec-output/repo/2026-01-01T12-00-00
```

This produces a board-ready report with risk in dollar terms and compliance mapping.

---

## Common Next Steps

### Audit CI/CD separately

```bash
python grimsec.py audit https://github.com/org/repo
```

Checks for unpinned actions (like the tj-actions CVE-2025-30066 pattern), expression injection, and overpermissive workflow permissions.

### Enrich a specific CVE

```bash
python grimsec.py enrich CVE-2024-1234
```

Fetches CVSS, EPSS score, CISA KEV status, and ATT&CK mapping for a single CVE.

### Run full pipeline

```bash
python grimsec.py analyze https://github.com/org/repo
```

Runs all 6 foundation agents (no DAST, no adversary sim). Takes 30-60 minutes.

### Full deep assessment

```bash
python grimsec.py analyze https://github.com/org/repo --deep
```

Runs all 12 agents including active DAST and adversary simulation.

**Only run `--deep` against systems you own or have explicit written permission to test.**

---

## Troubleshooting

**Tool not found errors:**
```bash
python grimsec.py install
```

**Rate limiting from NVD API (Agent 03, 05):**
Set an NVD API key (free, takes 5 minutes to get):
```bash
export NVD_API_KEY=your-key-here
```

**Large repo timeout:**
Use `--quick` mode or scan a specific subdirectory:
```bash
python grimsec.py scan https://github.com/org/repo
```

**Permission denied on scripts:**
```bash
chmod +x setup.sh scripts/*.sh
```

---

## Getting Help

- Read [docs/agent-reference.md](agent-reference.md) for detailed agent documentation
- Read [docs/architecture.md](architecture.md) for how agents chain together
- Open an issue on GitHub
- Read individual agent `SKILL.md` files for agent-specific help
