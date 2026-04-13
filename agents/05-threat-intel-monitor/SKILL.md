---
name: threat-intel-monitor
description: Continuous threat intelligence monitoring agent for DevSecOps. Monitors CISA KEV (Known Exploited Vulnerabilities), OSV.dev, NVD, and GitHub Advisory Database for newly disclosed CVEs, then cross-references them against dependency inventories from previously analyzed repositories to detect exposure. Use when asked to check for new threats, monitor CVEs, run a threat intel scan, detect new vulnerabilities affecting monitored repos, or schedule recurring vulnerability monitoring. Part of the GRIMSEC DevSecOps agent suite. Integrates with devsecops-repo-analyzer inventory outputs.
license: MIT
metadata:
  author: cambamwham2
  version: '1.0'
  suite: GRIMSEC
  integrates_with: devsecops-repo-analyzer, vulnerability-context-enricher, cicd-pipeline-auditor
---

# Threat Intel Monitor

## When to Use This Skill

Use this skill when the user asks to:

- Check for new high-severity CVEs or newly disclosed vulnerabilities
- Monitor threat intelligence feeds (CISA KEV, OSV, NVD)
- Determine if previously analyzed repos are exposed to new threats
- Set up scheduled/recurring CVE monitoring (daily, weekly)
- Run a one-time exposure check against current dependency inventories
- Get a threat intel briefing or exposure report

This skill is part of the **GRIMSEC DevSecOps agent suite** and works downstream of:
- **devsecops-repo-analyzer** — produces `inventory.json` files per repo
- **vulnerability-context-enricher** — enriches individual CVEs with EPSS, CVSS, KEV status
- **cicd-pipeline-auditor** — audits CI/CD pipeline security

---

## Skill Overview

The threat-intel-monitor performs a **three-phase pipeline**:

```
Phase 1: Threat Ingestion
  └─ CISA KEV feed → filter by date
  └─ OSV.dev batch API → query all monitored deps
  └─ NVD API v2 → enrich critical findings

Phase 2: Exposure Cross-Reference
  └─ Load all inventory.json files from monitored repos
  └─ Match CVE-affected packages against installed versions
  └─ Classify exposure: EXPOSED / POTENTIALLY_EXPOSED / NOT_AFFECTED

Phase 3: Report Generation
  └─ JSON threat intel report
  └─ Markdown executive summary
  └─ (Optional) dashboard update or notification
```

---

## Instructions

### One-Time Threat Check

Run the check-threats.py script:

```bash
cd /home/user/workspace
python threat-intel-monitor/scripts/check-threats.py \
  --lookback 7d \
  --inventory-dir devsecops-analysis/ \
  --output-dir devsecops-analysis/threat-intel/
```

**Lookback options:**
- `1d` — last 24 hours (for daily scheduled runs)
- `7d` — last 7 days (default, good for weekly monitoring)
- `30d` — last 30 days (initial baseline scan)

The script will:
1. Download and cache the CISA KEV JSON feed locally
2. Load all `inventory.json` files from `--inventory-dir`
3. Query OSV.dev batch API for all discovered dependencies
4. Optionally enrich with NVD data for CRITICAL findings
5. Write the JSON report and markdown summary to `--output-dir`

**Output files:**
- `{date}-report.json` — structured JSON with full threat data
- `{date}-summary.md` — human-readable markdown summary

---

### Setting Up Scheduled/Recurring Monitoring

Use Perplexity Computer's `schedule_cron` capability to run this automatically:

**Daily monitoring (runs at 6:00 AM UTC every day):**
```
Schedule: 0 6 * * *
Command: python /home/user/workspace/threat-intel-monitor/scripts/check-threats.py --lookback 1d --inventory-dir /home/user/workspace/devsecops-analysis/ --output-dir /home/user/workspace/devsecops-analysis/threat-intel/
```

**Weekly monitoring (runs every Monday at 7:00 AM UTC):**
```
Schedule: 0 7 * * 1
Command: python /home/user/workspace/threat-intel-monitor/scripts/check-threats.py --lookback 7d --inventory-dir /home/user/workspace/devsecops-analysis/ --output-dir /home/user/workspace/devsecops-analysis/threat-intel/
```

To set up via agent: Ask the agent to schedule the cron job, providing the command above. The agent will use the `schedule_cron` tool from the Computer platform.

---

### Interpreting Results

#### Exposure Status Values

| Status | Meaning | Action Required |
|--------|---------|-----------------|
| `EXPOSED` | Installed version is within the affected range | **Immediate** — patch or mitigate |
| `POTENTIALLY_EXPOSED` | Version range could not be precisely determined | **Urgent** — manual verification needed |
| `NOT_AFFECTED` | Installed version is outside affected range | No action needed |

#### Threat Priority

Threats are classified by combining CVE severity and exploit status:

| Priority | Criteria |
|----------|---------|
| **P0 — CRITICAL** | CISA KEV + CRITICAL CVSS + ransomware use |
| **P1 — HIGH** | CISA KEV + any severity, or CRITICAL CVSS without KEV |
| **P2 — MEDIUM** | HIGH CVSS, not in KEV |
| **P3 — LOW** | Medium/Low CVSS |

Always treat CISA KEV entries as highest priority — these are actively exploited in the wild.

#### Summary Fields

```json
{
  "total_new_threats": 15,           // Total CVEs from all sources in lookback window
  "threats_affecting_monitored_repos": 2,  // CVEs that match at least one monitored dep
  "repos_with_exposure": 1,          // Distinct repos with at least one EXPOSED status
  "critical_exposures": 1,           // EXPOSED findings with CRITICAL severity
  "high_exposures": 1                // EXPOSED findings with HIGH severity
}
```

---

### Adding New Repos to Monitoring

The monitor automatically picks up any repo that has been analyzed with `devsecops-repo-analyzer`. To add a new repo:

1. Run `devsecops-repo-analyzer` on the repo:
   ```
   Analyze repo: https://github.com/org/new-repo
   ```
   This produces `/home/user/workspace/devsecops-analysis/new-repo/inventory.json`

2. The next threat intel scan will automatically include it — no additional configuration needed.

**Manual inventory:** If you want to add a repo without running the full analyzer, create a minimal `inventory.json`:

```json
{
  "repo": "my-repo",
  "analyzed_at": "2026-03-24T00:00:00Z",
  "dependencies": {
    "npm": [
      {"name": "express", "version": "4.18.2", "ecosystem": "npm"},
      {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}
    ],
    "pip": [
      {"name": "django", "version": "4.2.0", "ecosystem": "PyPI"}
    ]
  }
}
```

---

## Script Reference

### check-threats.py Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--lookback` | `7d` | Time window: `1d`, `7d`, or `30d` |
| `--inventory-dir` | `devsecops-analysis/` | Root dir containing per-repo subdirs with `inventory.json` |
| `--output-dir` | `devsecops-analysis/threat-intel/` | Where to write reports |
| `--nvd-api-key` | None | Optional NVD API key (increases rate limit to 50 req/30s) |
| `--no-nvd` | False | Skip NVD enrichment entirely (faster) |
| `--cache-dir` | `/tmp/threat-intel-cache/` | Local cache for CISA KEV and other feeds |
| `--severity` | `HIGH,CRITICAL` | Minimum severity filter (comma-separated) |
| `--verbose` | False | Enable verbose logging |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NVD API key (alternative to `--nvd-api-key`) |
| `GITHUB_TOKEN` | GitHub PAT for GitHub Advisory Database queries |
| `THREAT_INTEL_CACHE_DIR` | Override default cache directory |

---

## References

For detailed documentation on each intel source, see:
- `references/threat-intel-sources.md` — Source documentation, rate limits, field definitions, and interpretation guidance

---

## Ecosystem Support

The following package ecosystems are supported for OSV.dev cross-referencing:

| Ecosystem | Inventory Key | Lock File |
|-----------|--------------|-----------|
| npm / yarn | `npm` | package-lock.json, yarn.lock |
| PyPI | `pip` | requirements.txt, Pipfile.lock |
| Go | `go` | go.sum |
| Maven | `maven` | pom.xml |
| Cargo | `cargo` | Cargo.lock |
| RubyGems | `rubygems` | Gemfile.lock |
| NuGet | `nuget` | packages.lock.json |

---

## Integration with Other GRIMSEC Skills

```
devsecops-repo-analyzer
  └─ Produces: inventory.json (dependency list per repo)
        │
        ▼
threat-intel-monitor  ◄── (this skill)
  └─ Reads: inventory.json files
  └─ Queries: CISA KEV, OSV, NVD, GitHub Advisories
  └─ Produces: {date}-report.json, {date}-summary.md
        │
        ▼
vulnerability-context-enricher
  └─ Reads: threat-intel report
  └─ Enriches: EPSS scores, CVSS vectors, patch availability
  └─ Produces: enriched CVE profiles
```

Run `devsecops-repo-analyzer` first to build inventories, then `threat-intel-monitor` to check exposure against current threat feeds.
