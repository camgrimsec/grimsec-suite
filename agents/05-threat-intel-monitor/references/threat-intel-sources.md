# Threat Intelligence Sources — Reference Guide

This document covers each threat intelligence source used by the `threat-intel-monitor` skill: its purpose, API details, rate limits, field definitions, and how to interpret its data.

---

## 1. CISA KEV — Known Exploited Vulnerabilities Catalog

### Overview
The CISA KEV (Known Exploited Vulnerabilities) catalog is maintained by the Cybersecurity and Infrastructure Security Agency (CISA) of the U.S. Department of Homeland Security. It lists CVEs that have been **confirmed as actively exploited in the wild**.

Being on the KEV list is a strong signal of real-world attacker activity — treat these with the highest urgency regardless of CVSS score.

### Access
- **URL:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **Method:** HTTP GET (no authentication required)
- **Format:** JSON (~2–5 MB)
- **Update Frequency:** CISA updates the catalog on working days, typically adding 1–10 entries per update

### Rate Limits
- No API key required
- No documented rate limit, but the file should be **cached locally** after download
- Recommended cache lifetime: **12 hours** (the default in check-threats.py)
- Do NOT download on every script run — cache to `/tmp/threat-intel-cache/cisa_kev.json`

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `cveID` | string | CVE identifier (e.g., `CVE-2021-44228`) |
| `vendorProject` | string | Affected vendor or project (e.g., `Apache`) |
| `product` | string | Affected product name (e.g., `Log4j2`) |
| `vulnerabilityName` | string | Short human-readable name |
| `shortDescription` | string | Brief description of the vulnerability |
| `dateAdded` | string | Date added to KEV catalog (`YYYY-MM-DD`) |
| `dueDate` | string | Federal agency remediation deadline (`YYYY-MM-DD`) |
| `knownRansomwareCampaignUse` | string | `"Known"` or `"Unknown"` — whether used in ransomware |
| `requiredAction` | string | CISA-recommended remediation action |

### How to Interpret

- **`dateAdded`** is the primary field for filtering recent entries — always filter by this.
- **`knownRansomwareCampaignUse = "Known"`** elevates urgency significantly; these CVEs are weaponized in ransomware operations.
- **`dueDate`** applies to U.S. federal agencies (BOD 22-01) but is a useful proxy for urgency for any organization.
- CVSS scores are NOT included in the KEV feed — use NVD for CVSS enrichment.

### Strengths & Limitations

| Strengths | Limitations |
|-----------|-------------|
| Confirmed real-world exploitation | No CVSS scores in feed |
| High-quality, government-maintained | No package-level matching (product-level only) |
| Ransomware flag is actionable | Updated on workdays only (may lag 1–2 days) |
| No API key or rate limits | Doesn't cover all high-severity CVEs |

---

## 2. OSV.dev — Open Source Vulnerabilities

### Overview
OSV.dev is an open, distributed vulnerability database for open-source software maintained by Google. It aggregates vulnerability data from multiple sources (GitHub Advisory Database, PyPA, RustSec, Go Vulnerability DB, etc.) and provides **package-level matching** — the ability to check if a specific version of a specific package is affected.

This is the primary source for the **"is my dependency version actually affected?"** question.

### Access

#### Single Vulnerability Lookup
```
GET https://api.osv.dev/v1/vulns/{id}
```

#### Batch Package Query (used by check-threats.py)
```
POST https://api.osv.dev/v1/querybatch
Content-Type: application/json

{
  "queries": [
    {
      "version": "1.2.3",
      "package": {"name": "lodash", "ecosystem": "npm"}
    },
    {
      "version": "2.28.0",
      "package": {"name": "requests", "ecosystem": "PyPI"}
    }
  ]
}
```

The batch endpoint accepts up to **1000 queries per request**.

### Rate Limits
- No API key required
- No documented rate limit
- Batch endpoint handles up to 1000 package queries per request — use it
- Add a 0.5s delay between batch chunks for good citizenship

### Supported Ecosystems

| OSV Ecosystem Name | Package Manager | Examples |
|-------------------|----------------|---------|
| `npm` | npm / yarn | `lodash`, `express` |
| `PyPI` | pip / pipenv / poetry | `requests`, `django` |
| `Go` | go modules | `github.com/gin-gonic/gin` |
| `Maven` | Maven / Gradle | `org.apache.commons:commons-lang3` |
| `crates.io` | Cargo (Rust) | `serde`, `tokio` |
| `RubyGems` | Bundler | `rails`, `devise` |
| `NuGet` | .NET | `Newtonsoft.Json` |
| `Hex` | Elixir / Erlang | `phoenix` |
| `Packagist` | Composer (PHP) | `symfony/http-kernel` |

### Key Response Fields

```json
{
  "id": "GHSA-xxxx-xxxx-xxxx",
  "aliases": ["CVE-2023-XXXXX"],
  "published": "2023-01-15T00:00:00Z",
  "modified": "2023-06-01T00:00:00Z",
  "summary": "Short description",
  "affected": [
    {
      "package": {"name": "package-name", "ecosystem": "npm"},
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {"introduced": "0"},
            {"fixed": "1.2.4"}
          ]
        }
      ],
      "versions": ["1.0.0", "1.1.0", "1.2.0", "1.2.3"]
    }
  ]
}
```

### How to Interpret

- **`aliases`** — Check for `CVE-*` aliases to get the canonical CVE ID
- **`ranges[].events`** — Version range definition:
  - `{"introduced": "0"}` means "from the beginning"
  - `{"fixed": "X.Y.Z"}` means "fixed in version X.Y.Z (exclusive)"
  - Multiple ranges can cover multiple affected branches
- **`versions`** — Exact list of affected versions (useful for non-semver packages)
- If a package version is returned in the batch query results, it is **definitively affected** — OSV already matched the version

### Strengths & Limitations

| Strengths | Limitations |
|-----------|-------------|
| Precise package+version matching | Aggregated data, may have duplicates |
| Multi-ecosystem support | Some older CVEs may be missing |
| No authentication required | Non-SemVer packages harder to match |
| Batch API is very efficient | |

---

## 3. NVD API v2 — NIST National Vulnerability Database

### Overview
The National Vulnerability Database (NVD) is the U.S. government's repository of standards-based vulnerability management data. It provides **CVSS scores, CWE classifications, CPE configurations**, and detailed technical descriptions for CVEs.

In this skill, NVD is used primarily for **enrichment** — after CISA KEV and OSV identify relevant CVEs, NVD provides the detailed CVSS scoring and technical context.

### Access

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
    ?pubStartDate=2026-03-17T00:00:00.000
    &pubEndDate=2026-03-24T00:00:00.000
    &cvssV3Severity=CRITICAL
    &resultsPerPage=100
    &startIndex=0
```

**Getting an API Key:** Register at https://nvd.nist.gov/developers/request-an-api-key (free)

Pass the key as an HTTP header:
```
apiKey: YOUR_KEY_HERE
```
Or set `NVD_API_KEY` environment variable.

### Rate Limits

| Without API Key | With API Key |
|----------------|-------------|
| 5 requests / 30 seconds | 50 requests / 30 seconds |
| ~1 request / 6 seconds | ~1 request / 0.6 seconds |

**Always implement a sleep between requests.** NVD will return HTTP 403 if you exceed the rate limit. check-threats.py implements this automatically (6s without key, 0.7s with key).

### Key Query Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `pubStartDate` | CVE publication start date | `2026-03-17T00:00:00.000` |
| `pubEndDate` | CVE publication end date | `2026-03-24T00:00:00.000` |
| `cvssV3Severity` | Filter by CVSS v3 severity | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `keywordSearch` | Free-text search | `log4j` |
| `cveId` | Lookup specific CVE | `CVE-2021-44228` |
| `resultsPerPage` | Results per page (max 2000) | `100` |
| `startIndex` | Pagination offset | `0`, `100`, `200` |

### Key Response Fields

```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-XXXXX",
        "published": "2026-03-20T15:30:00.000",
        "lastModified": "2026-03-22T12:00:00.000",
        "descriptions": [{"lang": "en", "value": "..."}],
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
              }
            }
          ]
        },
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        "configurations": [...]
      }
    }
  ]
}
```

### CVSS Score Interpretation

| Score Range | Severity | Typical Action |
|-------------|----------|---------------|
| 9.0 – 10.0 | CRITICAL | Emergency patch within 24–72h |
| 7.0 – 8.9 | HIGH | Patch within 7–14 days |
| 4.0 – 6.9 | MEDIUM | Patch in next release cycle |
| 0.1 – 3.9 | LOW | Patch at convenience |

### CVSS Vector Components (Quick Reference)

| Component | Key Values | Meaning |
|-----------|-----------|---------|
| `AV:N` | Network | Exploitable remotely |
| `AC:L` | Low Complexity | Easy to exploit |
| `PR:N` | No Privileges | No account needed |
| `UI:N` | No User Interaction | Fully automated exploit |
| `C:H/I:H/A:H` | High CIA Impact | Full compromise possible |

A vector of `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` is the "worst case" — network-exploitable, no auth, no user interaction, full system compromise.

### Strengths & Limitations

| Strengths | Limitations |
|-----------|-------------|
| Authoritative CVSS scores | Strict rate limiting |
| CWE and CPE mappings | CPE matching is complex |
| Covers all CVEs (not just OSS) | Publication delay (CVEs can take weeks to score) |
| Free API with key | No package-level version matching |

---

## 4. GitHub Advisory Database

### Overview
The GitHub Advisory Database aggregates vulnerability data for packages hosted on GitHub, with a focus on ecosystem package advisories (npm, PyPI, Maven, etc.). It cross-references CVEs with GHSA IDs and provides ecosystem-specific context.

### Access
```
GET https://api.github.com/advisories
    ?type=reviewed
    &severity=critical
    &per_page=100
```

**Authentication:** Set `GITHUB_TOKEN` environment variable for higher rate limits.
```
Authorization: Bearer ghp_xxxx
X-GitHub-Api-Version: 2022-11-28
```

### Rate Limits

| Without Token | With Token |
|--------------|------------|
| 60 req/hour | 5,000 req/hour |

### Key Fields

| Field | Description |
|-------|-------------|
| `ghsa_id` | GitHub Security Advisory ID (e.g., `GHSA-xxxx-xxxx-xxxx`) |
| `cve_id` | Associated CVE ID (may be null for GHSA-only) |
| `severity` | `critical`, `high`, `medium`, `low` |
| `summary` | Short description |
| `description` | Full description (Markdown) |
| `published_at` | Publication datetime |
| `vulnerabilities[].package` | `{name, ecosystem}` of affected package |
| `vulnerabilities[].vulnerable_version_range` | Version range expression |
| `vulnerabilities[].patched_versions` | Fixed version |

### Strengths & Limitations

| Strengths | Limitations |
|-----------|-------------|
| Strong npm/pip ecosystem coverage | Requires GitHub token for practical use |
| Good patch version data | Some advisories lack CVE IDs |
| Ecosystem-specific context | Overlap with OSV (OSV aggregates GitHub too) |

---

## Source Priority and Trust Hierarchy

When multiple sources report the same CVE, use this priority order:

```
1. CISA KEV         — Highest priority (confirmed active exploitation)
2. NVD              — Authoritative CVSS scoring
3. OSV.dev          — Most accurate for version-level matching
4. GitHub Advisory  — Best for ecosystem-specific context
```

If NVD and OSV disagree on affected versions, trust OSV for package-level decisions (it's more granular). Trust NVD for CVSS scores.

---

## Caching Strategy

| Source | Cache Key | Recommended TTL |
|--------|-----------|----------------|
| CISA KEV | `cisa_kev.json` | 12 hours |
| NVD responses | `nvd_{date}_{severity}.json` | 1 hour |
| OSV vuln details | `osv_{vuln_id}.json` | 24 hours |
| GitHub Advisories | `github_advisories_{date}.json` | 6 hours |

Store cache files in `--cache-dir` (default: `/tmp/threat-intel-cache/`).

---

## Data Freshness Expectations

| Source | Update Frequency | Typical Lag |
|--------|-----------------|-------------|
| CISA KEV | Workdays | 1–2 days after exploitation confirmed |
| NVD | Continuous | 1–14 days after CVE assignment |
| OSV.dev | Near real-time | Hours to 1 day |
| GitHub Advisory | Continuous | Hours to 1 day |

For daily monitoring (`--lookback 1d`), expect some CVEs to appear in OSV/GitHub before they appear in NVD.

---

## Troubleshooting

### "CISA KEV returns 0 results for lookback window"
- The feed only includes CVEs actually exploited in the wild — most lookback windows may have 0–5 new entries. This is normal.

### "NVD returns HTTP 403"
- Rate limit exceeded. Add an API key (`--nvd-api-key`) or increase the delay between requests. The script auto-handles this, but network conditions can cause burst failures.

### "OSV returns no vulnerabilities for my packages"
- Check that `ecosystem` values in your inventory.json match OSV's naming (see Ecosystem Map in SKILL.md).
- For Go modules, the package name must be the full module path (e.g., `github.com/gin-gonic/gin`).

### "GitHub Advisory returns 401"
- No GitHub token set. Set `GITHUB_TOKEN` environment variable or the script will use unauthenticated requests (60 req/hour limit).

### "Script finishes but no exposures found"
- Verify that `inventory.json` files exist in the `--inventory-dir` path.
- Check that dependency entries have both `name` and `version` populated.
- Try `--lookback 30d` for a wider window.
- Run with `--verbose` for detailed per-package logging.
