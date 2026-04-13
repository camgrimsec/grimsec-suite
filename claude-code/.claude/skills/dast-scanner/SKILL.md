# DAST Scanner

Dynamic Application Security Testing using Nuclei and OWASP ZAP. Detects OWASP Top 10 vulnerabilities at runtime that static analysis misses.

Invoke with `/dast-scanner` or phrases like "DAST scan", "dynamic testing", "ZAP scan", "Nuclei scan".

## ⚠️ Authorization Required

Never run active scans against production systems without explicit authorization.

## When to Use

- Test a running web application for vulnerabilities
- Dynamic (black-box) security testing
- Detecting OWASP Top 10 vulnerabilities at runtime
- Combined Nuclei + ZAP scan with unified report

## Setup

```bash
# Nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# OWASP ZAP (via Docker — no install required)
docker pull ghcr.io/zaproxy/zaproxy:stable

# httpx for target discovery
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Phase 1 — Target Discovery

```bash
httpx -u <TARGET_URL> -tech-detect -status-code -title -json -o dast-results/httpx.json
```

## Phase 2 — Nuclei Quick Scan

```bash
nuclei -u <TARGET_URL> \
  -t cves,misconfiguration,exposures,technologies,default-logins \
  -severity critical,high,medium \
  -json-export dast-results/nuclei.json \
  -rate-limit 100
```

For fragile targets: `--rate-limit 25`

## Phase 3 — ZAP Scan

**Scan modes:**
- `baseline` — passive scan only, CI/CD safe (~2 min)
- `full` — active + passive (~20-60 min), requires authorization
- `api` — OpenAPI/GraphQL-aware scan

```bash
# Baseline (safe for any environment)
docker run -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t <TARGET_URL> -J dast-results/zap-baseline.json

# Full active scan (requires explicit authorization)
docker run -t ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t <TARGET_URL> -J dast-results/zap-full.json

# API scan with OpenAPI spec
docker run -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t <TARGET_URL> -f openapi -J dast-results/zap-api.json
```

## Phase 4 — Finding Correlation

1. Load `dast-results/nuclei.json` and `dast-results/zap.json`
2. Deduplicate by matching: same host + port + path + vulnerability class (CWE)
3. For each deduplicated finding assign:
   - `cwe_id` (CWE-89 for SQLi, CWE-79 for XSS, etc.)
   - `owasp_category` (A01:2021, A03:2021, etc.)
   - `unified_severity` (use the higher rating)
   - `source_tools` list

## Severity Mapping

| Severity | Finding Types |
|----------|--------------|
| CRITICAL | RCE, confirmed SQL injection, authentication bypass |
| HIGH | Stored XSS, SSRF, path traversal, IDOR |
| MEDIUM | Missing CSP/HSTS, CORS misconfiguration, information disclosure |
| LOW | Cookie flags missing, clickjacking, version disclosure |

## Phase 5 — Report

Generate `dast-results/dast-report.md` with:
- Executive summary (counts by severity, top 3 critical findings)
- Finding table sorted by severity
- Per-finding details: endpoint, method, evidence, CWE, OWASP category, remediation
- Recommended immediate actions

## Output Files

| File | Description |
|------|-------------|
| `dast-results/nuclei.json` | Nuclei findings |
| `dast-results/zap.json` | ZAP findings |
| `dast-results/dast-report.md` | Unified DAST report |
| `dast-results/httpx.json` | Target discovery metadata |

## Inputs

| Input | Required |
|-------|----------|
| `TARGET_URL` | Yes |
| `inventory.json` from `/repo-analyzer` | No (auto-discovers) |
| OpenAPI/Swagger spec | No (enables API scan mode) |
| Auth credentials | No (enables authenticated scan) |
