# Threat Intel Monitor

Monitors CISA KEV, OSV.dev, and NVD for newly disclosed CVEs and cross-references them against dependency inventories from analyzed repositories to detect exposure.

Invoke with `/threat-monitor` or phrases like "check for new CVEs", "monitor threat feeds", "exposure check".

## When to Use

- Check for new high-severity CVEs or newly disclosed vulnerabilities
- Determine if previously analyzed repos are exposed to new threats
- Set up scheduled/recurring CVE monitoring
- Get a threat intel briefing or exposure report

## Three-Phase Pipeline

```
Phase 1: Threat Ingestion
  └─ CISA KEV feed → filter by date
  └─ OSV.dev batch API → query all monitored deps
  └─ NVD API v2 → enrich critical findings

Phase 2: Exposure Cross-Reference
  └─ Load all inventory.json files
  └─ Match CVE-affected packages against installed versions
  └─ Classify: EXPOSED / POTENTIALLY_EXPOSED / NOT_AFFECTED

Phase 3: Report Generation
  └─ JSON threat intel report
  └─ Markdown executive summary
```

## Phase 1: Threat Ingestion

```bash
# Run the check script (lookback options: 1d, 7d, 30d)
python scripts/check-threats.py \
  --lookback 7d \
  --inventory-dir ./grimsec-output/ \
  --output-dir ./grimsec-output/threat-intel/
```

The script:
1. Downloads and caches the CISA KEV JSON feed locally
2. Loads all `inventory.json` files from `--inventory-dir`
3. Queries OSV.dev batch API for all discovered dependencies
4. Optionally enriches with NVD data for CRITICAL findings
5. Writes JSON report and markdown summary to `--output-dir`

**Manual CISA KEV download:**
```python
import urllib.request, json
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
with urllib.request.urlopen(kev_url) as r:
    kev_data = json.loads(r.read())
```

**Manual OSV.dev query:**
```python
def query_osv(package_name, ecosystem, version=None):
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    url = "https://api.osv.dev/v1/query"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())
```

## Exposure Status Values

| Status | Meaning | Action |
|--------|---------|--------|
| `EXPOSED` | Installed version within affected range | **Immediate** — patch or mitigate |
| `POTENTIALLY_EXPOSED` | Version range could not be precisely determined | **Urgent** — manual verification |
| `NOT_AFFECTED` | Installed version outside affected range | No action needed |

## Threat Priority

| Priority | Criteria |
|----------|---------|
| P0 — CRITICAL | CISA KEV + CRITICAL CVSS + ransomware use |
| P1 — HIGH | CISA KEV + any severity, or CRITICAL CVSS without KEV |
| P2 — MEDIUM | HIGH CVSS, not in KEV |
| P3 — LOW | Medium/Low CVSS |

Always treat CISA KEV entries as highest priority.

## Script Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--lookback` | `7d` | Time window: `1d`, `7d`, or `30d` |
| `--inventory-dir` | `grimsec-output/` | Root dir with per-repo `inventory.json` files |
| `--output-dir` | `grimsec-output/threat-intel/` | Where to write reports |
| `--nvd-api-key` | None | Optional NVD API key (increases rate limit) |
| `--severity` | `HIGH,CRITICAL` | Minimum severity filter |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NVD API key (alternative to `--nvd-api-key`) |
| `GITHUB_TOKEN` | GitHub PAT for GitHub Advisory Database |

## Adding Repos to Monitoring

Run `/repo-analyzer` on the repo — it produces `./grimsec-output/{repo-name}/inventory.json`. The monitor automatically picks it up on the next run.

**Manual minimal inventory:**
```json
{
  "repo": "my-repo",
  "analyzed_at": "2024-01-01T00:00:00Z",
  "dependencies": {
    "npm": [{"name": "express", "version": "4.18.2", "ecosystem": "npm"}],
    "pip": [{"name": "django", "version": "4.2.0", "ecosystem": "PyPI"}]
  }
}
```

## Scheduled Monitoring

```bash
# Daily at 6 AM UTC
0 6 * * * python check-threats.py --lookback 1d --inventory-dir ./grimsec-output/ --output-dir ./grimsec-output/threat-intel/

# Weekly on Monday at 7 AM UTC
0 7 * * 1 python check-threats.py --lookback 7d --inventory-dir ./grimsec-output/ --output-dir ./grimsec-output/threat-intel/
```

## Supported Ecosystems

npm/yarn, PyPI, Go, Maven, Cargo, RubyGems, NuGet

## Output Files

```
grimsec-output/threat-intel/
├── {date}-report.json     # Structured JSON with full threat data
└── {date}-summary.md      # Human-readable markdown summary
```
