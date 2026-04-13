# Nuclei Template Selection Guide

## Overview

Nuclei uses YAML-defined templates organized into categories. Each category targets a different class of vulnerability or information. Selecting the right categories for the target technology stack keeps scans fast and reduces false positives.

## Template Categories

### `cves` — Known CVE Exploits
Checks for publicly disclosed CVEs with confirmed PoC exploits.

**Use when:** The target is a known product or framework (WordPress, Apache, Spring, etc.)  
**Time:** Medium (depends on tech stack match rate)  
**Noise:** Low — high-confidence, well-tested templates  
**Example finds:** CVE-2021-44228 (Log4Shell), CVE-2022-22965 (Spring4Shell), CVE-2023-23752 (Joomla info disclosure)

```bash
nuclei -t cves -target https://example.com -severity critical,high
```

Sub-categories under `cves/`:
- `cves/2024/` — Current year CVEs
- `cves/2023/`
- `cves/2022/`
- ... (each year has its own subdirectory back to 2013)

**Template selection tip:** If `httpx` detects a specific technology (e.g., WordPress), add `-tags wordpress,cms` to focus only on relevant CVE templates.

---

### `misconfiguration` — Server/App Misconfiguration
Detects insecure default configurations, exposed admin panels, and dangerous settings.

**Use when:** Any target — always include this category  
**Time:** Fast  
**Noise:** Low  
**Example finds:**
- Exposed `.git/` directory
- Directory listing enabled
- phpinfo() page accessible
- Spring Boot Actuator endpoints open
- GraphQL introspection enabled in production
- Jenkins dashboard unauthenticated
- Kibana/Grafana/Prometheus metrics public
- CORS misconfiguration (`Access-Control-Allow-Origin: *` on credentialed endpoints)

```bash
nuclei -t misconfiguration -target https://example.com
```

---

### `exposures` — Sensitive File and Endpoint Exposure
Looks for files and endpoints that should not be publicly accessible.

**Use when:** Any target — include for comprehensive scanning  
**Time:** Fast  
**Noise:** Very low  
**Example finds:**
- `.env` files (credentials in plaintext)
- `backup.zip`, `db.sql` database dumps
- `wp-config.php.bak` backup configuration
- `docker-compose.yml` exposed on web root
- `id_rsa` private keys
- `.DS_Store` metadata files (reveals directory structure)
- `/debug` or `/console` endpoints
- Swagger UI at `/swagger-ui.html` or `/api-docs`
- AWS credential files (`credentials`, `config`)

```bash
nuclei -t exposures -target https://example.com
```

---

### `technologies` — Technology Detection
Fingerprints the application stack for targeted follow-up scanning.

**Use when:** First scan phase — run this before selecting CVE templates  
**Time:** Very fast  
**Noise:** None (informational only)  
**Detects:**
- Web frameworks (Django, Rails, Laravel, Spring, Express)
- CMS platforms (WordPress, Drupal, Joomla, Ghost)
- CDN/WAF presence (Cloudflare, Akamai, ModSecurity)
- Database panels (phpMyAdmin, pgAdmin, Adminer)
- Cloud metadata endpoints
- JavaScript libraries and versions

**Workflow:**
1. Run technologies scan first to build a tech inventory
2. Use detected tech to add `-tags <tech>` filters to CVE scans

```bash
nuclei -t technologies -target https://example.com -json -o tech-detect.json
```

---

### `default-logins` — Default Credential Testing
Tests common vendor-default username/password combinations on admin interfaces.

**Use when:** Admin panels, IoT interfaces, network devices, databases discovered via exposures scan  
**Time:** Fast  
**Noise:** Low (only fires when actual login panels are found)  
**Example finds:**
- `admin:admin` on router management pages
- `elastic:` (empty password) on Elasticsearch
- `root:root` on Tomcat Manager
- `admin:password` on Grafana fresh install

```bash
nuclei -t default-logins -target https://example.com
```

---

### `network` — Network-Level Checks
Probes open ports and network services beyond HTTP.

**Use when:** Target has exposed non-HTTP services (databases, message queues, caches)  
**Time:** Medium  
**Noise:** Low  
**Example finds:**
- Redis without authentication (`AUTH` not required)
- MongoDB open to public (`--noauth`)
- Memcached exposed
- Kubernetes API server unauthenticated

```bash
nuclei -t network -target 192.168.1.1
```

---

### `headless` — Browser-Based Checks
Uses a headless browser for JavaScript-rendered vulnerability detection.

**Use when:** Single-page applications (React, Angular, Vue) where server-side templates don't render the full DOM  
**Time:** Slow (requires Chromium)  
**Noise:** Low  
**Requires:** `nuclei` built with headless support + Chromium installed  
**Example finds:**
- DOM-based XSS in SPA routes
- Client-side open redirect via `location.hash`
- Postmessage-based vulnerabilities

```bash
nuclei -t headless -target https://example.com -headless
```

---

### `token-spray` — Token/Secret Validation
Validates suspected API keys and tokens found during exposure scans.

**Use when:** Exposed config files or source code contain candidate secrets  
**Time:** Fast  
**Noise:** Very low  
**Example finds:**
- Valid AWS access key
- Active Slack webhook
- Live GitHub personal access token
- SendGrid API key with send permissions

```bash
nuclei -t token-spray -target https://example.com
```

---

## Template Selection Matrix by Target Type

| Target Type | Recommended Categories |
|-------------|----------------------|
| Generic web app | `cves,misconfiguration,exposures,technologies,default-logins` |
| WordPress site | `cves,misconfiguration,exposures,technologies` + `-tags wordpress` |
| REST API (no UI) | `cves,misconfiguration,exposures` + `-tags api` |
| GraphQL API | `misconfiguration,exposures` + `-tags graphql` |
| Spring Boot app | `cves,misconfiguration,exposures` + `-tags spring` |
| Django/Flask app | `cves,misconfiguration,exposures` + `-tags python` |
| Internal admin panel | `default-logins,misconfiguration,exposures` |
| SPA (React/Vue/Angular) | `technologies,exposures,headless` |
| Infrastructure/network | `network,misconfiguration,default-logins` |
| CI/CD systems | `misconfiguration,exposures,default-logins` |

---

## Severity Filter Recommendations

| Scan Context | Severity Filter |
|-------------|----------------|
| CI/CD gate (fast, block only crits) | `critical` |
| Pre-release security review | `critical,high` |
| Full security assessment | `critical,high,medium` |
| Comprehensive audit | `critical,high,medium,low` |
| Bug bounty / maximum coverage | `critical,high,medium,low,info` |

---

## Rate Limiting Guidelines

| Environment | Recommended `--rate-limit` |
|-------------|--------------------------|
| Production (shared hosting) | 10–25 req/s |
| Staging/pre-prod | 50–100 req/s |
| Dedicated test environment | 150–300 req/s |
| Local Docker container | 300+ req/s |

---

## Adding Custom Tags

Nuclei supports `-tags` for filtering templates by technology or vulnerability class:

```bash
# Focus only on WordPress CVEs
nuclei -t cves -tags wordpress -target https://blog.example.com

# Scan for XSS and SSRF only
nuclei -t exposures,misconfiguration -tags xss,ssrf -target https://example.com

# Exclude noisy informational tech templates
nuclei -t technologies -exclude-tags tech -target https://example.com
```

---

## Template Update Commands

```bash
# Update all templates to latest
nuclei -update-templates

# Update only specific categories
nuclei -update-templates -t cves

# Check current template version
nuclei -version

# List all available templates
nuclei -list -t cves | head -20

# Use custom template directory
nuclei -t /path/to/custom-templates -target https://example.com
```

---

## Output Format Reference

Nuclei supports multiple output formats. The GRIMSEC pipeline uses `-jsonl` (one JSON object per line):

```bash
# JSON Lines (used by run-nuclei.py)
nuclei -target https://example.com -jsonl -output findings.jsonl

# Markdown report
nuclei -target https://example.com -markdown-export ./report/

# SARIF (for GitHub Code Scanning integration)
nuclei -target https://example.com -sarif-export findings.sarif
```

---

## False Positive Management

1. **Verify before escalating:** For critical/high findings, confirm with `curl` or browser before including in executive reports.
2. **Template exclusion:** If a specific template is known noisy, use `-exclude-id <template-id>`.
3. **Confidence threshold:** Nuclei templates include a `confidence` field — prefer templates marked `confirmed` over `speculative`.
4. **Cross-check with ZAP:** Any Nuclei finding also detected by ZAP gets double-weighted in the correlation phase.
