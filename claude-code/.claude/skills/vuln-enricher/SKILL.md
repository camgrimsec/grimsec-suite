# Vulnerability Context Enricher

Multi-source vulnerability intelligence aggregator. Transforms raw CVE identifiers into actionable security intelligence with CVSS decomposition, EPSS exploit prediction, CISA KEV status, MITRE ATT&CK mapping, and plain-language summaries.

Invoke with `/vuln-enricher` or phrases like "look up CVE-2024-1234", "enrich these vulnerabilities".

## When to Use

- Look up details on a specific CVE or set of CVEs
- Enrich vulnerability scan results with external intelligence
- Check whether a CVE is actively exploited (CISA KEV)
- Get the EPSS exploit prediction score
- Map CVEs to MITRE ATT&CK techniques
- Prioritize a list of vulnerabilities for remediation
- Generate plain-language summaries for non-security audiences

## Data Sources

All sources require no API keys and are publicly available:

| Source | URL | Data |
|--------|-----|------|
| NVD API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}` | CVSS scores, CWE, references |
| OSV.dev | `https://api.osv.dev/v1/query` | Affected versions, fix versions |
| EPSS (FIRST) | `https://api.first.org/data/v1/epss?cve={cve}` | 30-day exploitation probability |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Active exploitation confirmation |

**NVD rate limit:** 5 requests per 30 seconds without an API key. Use 6.5-second delays between requests. Register at https://nvd.nist.gov/developers/request-an-api-key for 50 req/30s.

## Input Modes

**Mode 1 — Individual CVE IDs:**
```
"Look up CVE-2024-1774"
"Enrich CVE-2024-1774 and CVE-2024-25223"
```

**Mode 2 — CVE list file:**
```
"Enrich the CVEs in ./cves.txt"
```

**Mode 3 — Trivy scan output:**
```
"Enrich all High and Critical findings from grimsec-output/{repo}/scan-results/trivy-sca.json"
```

## Enrichment Script

```python
import urllib.request, json, time

def enrich_cve(cve_id, package=None, ecosystem=None):
    result = {"cve_id": cve_id}
    
    # 1. NVD
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    with urllib.request.urlopen(nvd_url) as r:
        nvd_data = json.loads(r.read())
    result["nvd"] = nvd_data
    time.sleep(6.5)  # Rate limiting
    
    # 2. EPSS
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    with urllib.request.urlopen(epss_url) as r:
        epss_data = json.loads(r.read())
    result["epss"] = epss_data["data"][0] if epss_data.get("data") else {}
    
    # 3. CISA KEV (cached download)
    # kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    result["cisa_kev"] = {"in_kev": check_kev_cache(cve_id)}
    
    # 4. OSV.dev
    osv_payload = {"aliases": [cve_id]}
    if package and ecosystem:
        osv_payload = {"package": {"name": package, "ecosystem": ecosystem}}
    osv_req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(osv_payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(osv_req) as r:
        result["osv"] = json.loads(r.read())
    
    return result
```

## Composite Priority Scoring

| Factor | Max Points | Source |
|--------|-----------|--------|
| CVSS base score | 40 | NVD |
| EPSS score | 30 | FIRST |
| CISA KEV status | 20 | CISA |
| Fix availability | 10 | OSV |

**Priority thresholds:**

| Score | Priority | SLA |
|-------|----------|-----|
| ≥ 80 | P0 — Critical | Remediate immediately |
| 60–79 | P1 — High | Remediate within 7 days |
| 40–59 | P2 — Medium | Remediate within 30 days |
| 20–39 | P3 — Low | Next maintenance cycle |
| < 20 | P4 — Informational | Monitor only |

## MITRE ATT&CK CWE Mapping

| CWE | ATT&CK Technique |
|-----|-----------------|
| CWE-89 (SQLi) | T1190 — Exploit Public-Facing Application |
| CWE-79 (XSS) | T1059.007 — JavaScript |
| CWE-22 (Path Traversal) | T1083 — File and Directory Discovery |
| CWE-78 (OS Command Injection) | T1059 — Command and Scripting Interpreter |
| CWE-502 (Deserialization) | T1190 |
| CWE-918 (SSRF) | T1090 — Proxy |
| CWE-287 (Improper Auth) | T1078 — Valid Accounts |
| CWE-798 (Hardcoded Credentials) | T1078.001 — Default Accounts |

## Output Schema

```json
{
  "schema_version": "1.0",
  "enriched_at": "2024-03-23T00:00:00Z",
  "findings": [
    {
      "cve_id": "CVE-2024-1774",
      "nvd": {
        "cvss": {"score": 9.8, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "weaknesses": [{"cwe_id": "CWE-1321"}]
      },
      "epss": {"epss_score": 0.0234, "epss_percentile": 0.89, "interpretation": "2.34% probability in next 30 days"},
      "cisa_kev": {"in_kev": false},
      "fix": {"fix_available": true, "fixed_versions": [{"package": "pkg", "ecosystem": "npm", "fixed_in": "6.7.5"}]},
      "priority": {"composite_score": 72.5, "label": "P1 — HIGH: Remediate within 7 days"},
      "plain_language_summary": "..."
    }
  ],
  "summary": {"total_enriched": 10, "in_cisa_kev": 0, "fix_available": 8}
}
```

## Chaining with Repo Analyzer

When enriching CVEs from a previous `/repo-analyzer` run:
1. Load `./grimsec-output/{repo}/reachability-analysis.json`
2. Match findings by CVE ID to enriched data
3. **CISA KEV overrides local reachability** — if in KEV, treat as high priority regardless of local analysis
4. **EPSS validates Real Risk Scores** — high EPSS with low local reachability means the vuln is dangerous elsewhere
5. Save merged analysis to `./grimsec-output/{repo}/enriched-reachability.json`

## Output Files

```
grimsec-output/{context}/
├── enriched-cves.json          # Full enrichment data
├── enrichment-report.md        # Formatted report (if requested)
└── enriched-reachability.json  # Merged with repo analyzer output
```

## Important Notes

- **CISA KEV is the strongest signal.** KEV inclusion means real attackers are using it right now.
- **EPSS scores change daily.** A low EPSS today can spike when a PoC is published.
- **OSV covers open-source only.** Use NVD as fallback for proprietary software vulnerabilities.
- **Large batches:** For 50+ CVEs, expect 5-6 minutes of enrichment time due to NVD rate limits.
