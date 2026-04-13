---
name: dast-scanner
description: Dynamic Application Security Testing (DAST) skill for the GRIMSEC DevSecOps agent suite (Agent 7). Performs runtime vulnerability detection on running web applications using Nuclei and OWASP ZAP. Use when performing DAST, dynamic testing, black-box scanning, web application security testing, ZAP scanning, Nuclei scanning, OWASP testing, or runtime vulnerability detection against a live target URL or Docker-hosted application.
metadata:
  author: GRIMSEC
  version: '1.0'
  suite: GRIMSEC DevSecOps Agent Suite
  agent-number: '7'
  predecessor: devsecops-repo-analyzer
  successors: vulnerability-context-enricher, executive-reporting-agent
---

# DAST Scanner

## When to Use This Skill

Use this skill when:

- The user provides a target URL or Docker Compose file to security-test
- The pipeline requires dynamic (black-box) testing of a running application
- You need to detect OWASP Top 10 vulnerabilities at runtime
- Chaining after `devsecops-repo-analyzer` has deployed the target app
- The user requests Nuclei scans, ZAP scans, or combined DAST reports
- You need to correlate findings across multiple tools and map them to CWE/OWASP categories

## GRIMSEC Suite Position

```
devsecops-repo-analyzer (Agent 6)
        │
        ▼ inventory.json + docker-compose.yaml
  dast-scanner (Agent 7)  ◄──── YOU ARE HERE
        │
        ├──► vulnerability-context-enricher (CVE findings)
        └──► executive-reporting-agent (full dast-report.md)
```

## Pipeline Overview

```
Input: Target URL or Docker Compose file
  │
  ├─► Phase 1: Target Discovery
  │     - Detect running services, ports, endpoints
  │     - Probe with httpx for live hosts and tech fingerprinting
  │     - Parse inventory.json from devsecops-repo-analyzer (if available)
  │
  ├─► Phase 2: Nuclei Quick Scan
  │     ├── CVE templates          (known CVEs with PoC)
  │     ├── Misconfiguration       (exposed panels, default creds, open redirects)
  │     ├── Exposure templates     (sensitive files, debug endpoints, backups)
  │     └── Technology detection  (stack identification for targeted follow-up)
  │
  ├─► Phase 3: ZAP Deep Scan
  │     ├── Spider/crawl           (discover all application pages/endpoints)
  │     ├── Active scan            (XSS, SQLi, CSRF, path traversal, etc.)
  │     ├── Passive scan           (missing headers, cookie flags, CSP, CORS)
  │     └── API scan mode         (if OpenAPI/Swagger spec available)
  │
  ├─► Phase 4: Finding Correlation
  │     - Deduplicate findings across Nuclei + ZAP
  │     - Map each finding to CWE identifier
  │     - Map each finding to OWASP Top 10 category
  │     - Assign unified severity score
  │
  └─► Phase 5: Report Generation
        - dast-results/nuclei.json       (raw Nuclei findings)
        - dast-results/zap.json          (raw ZAP findings)
        - dast-results/dast-report.md    (unified markdown report)
```

## Severity Mapping

| Severity | Finding Types |
|----------|--------------|
| CRITICAL | Remote code execution (RCE), confirmed SQL injection, authentication bypass |
| HIGH | Stored XSS, SSRF, path traversal, IDOR, reflected XSS with DOM sink |
| MEDIUM | Missing CSP/HSTS headers, CORS misconfiguration, information disclosure |
| LOW | Cookie without Secure/HttpOnly flags, clickjacking potential, version disclosure |

## Instructions

### Phase 1 — Environment Setup

1. Check whether the bundled install script has been run:
   ```bash
   which nuclei && nuclei -version
   docker image inspect ghcr.io/zaproxy/zaproxy:stable >/dev/null 2>&1
   ```
2. If either tool is missing, execute `scripts/install-dast-tools.sh`.
3. Create the output directory: `mkdir -p dast-results`
4. If `inventory.json` from `devsecops-repo-analyzer` is available, read it to determine target ports/services. Otherwise, derive from the provided URL or Docker Compose file.

### Phase 2 — Target Discovery

5. Use `httpx` to probe the target and confirm liveness:
   ```bash
   httpx -u <TARGET_URL> -tech-detect -status-code -title -json -o dast-results/httpx.json
   ```
6. Extract endpoints and noted technologies for template selection.

### Phase 3 — Nuclei Quick Scan

7. Read `references/nuclei-templates.md` to select the appropriate template categories for the detected tech stack.
8. Execute `scripts/run-nuclei.py` with appropriate arguments:
   ```bash
   python scripts/run-nuclei.py \
     --target <TARGET_URL> \
     --categories cves,misconfiguration,exposures,technologies,default-logins \
     --severity critical,high,medium \
     --output dast-results/nuclei.json \
     --rate-limit 100 \
     --timeout 300
   ```
9. Review the parsed findings for any CRITICAL/HIGH items that warrant immediate escalation.

### Phase 4 — ZAP Deep Scan

10. Read `references/zap-scan-modes.md` to choose the appropriate ZAP scan mode:
    - `baseline` — fast passive scan (CI/CD safe, ~2 min)
    - `full` — active + passive scan (comprehensive, ~20–60 min)
    - `api` — OpenAPI/SOAP/GraphQL-aware scan
11. Execute `scripts/run-zap.py` with appropriate arguments:
    ```bash
    python scripts/run-zap.py \
      --target <TARGET_URL> \
      --mode full \
      --output dast-results/zap.json
    ```
12. If an OpenAPI spec is available, add `--openapi-spec path/to/openapi.yaml` and use `--mode api`.
13. If authentication is required, provide `--login-url`, `--username`, and `--password`.

### Phase 5 — Finding Correlation

14. Load both `dast-results/nuclei.json` and `dast-results/zap.json`.
15. Deduplicate findings by matching on:
    - Same host + port + path
    - Same vulnerability class (CWE or OWASP category)
16. For each deduplicated finding, assign:
    - `cwe_id` (e.g., CWE-89 for SQLi)
    - `owasp_category` (e.g., A03:2021 – Injection)
    - `unified_severity` (use the higher of the two tool ratings)
    - `source_tools` list (`["nuclei"]`, `["zap"]`, or `["nuclei","zap"]`)

### Phase 6 — Report Generation

17. Use `assets/templates/dast-report-template.md` as the structure for the final report.
18. Populate all sections: executive summary, finding table, per-finding details, remediation recommendations.
19. Write final report to `dast-results/dast-report.md`.
20. Summarize findings to the user: total count by severity, top 3 most critical findings, and recommended immediate actions.

## Inputs

| Input | Source | Required |
|-------|--------|----------|
| `TARGET_URL` | User or Docker Compose | Yes |
| `inventory.json` | devsecops-repo-analyzer output | No (auto-discover if missing) |
| `docker-compose.yaml` | Project repo | No (use if target not running) |
| OpenAPI spec | Project repo | No (enables API scan mode) |
| Auth credentials | User | No (enables authenticated scan) |

## Outputs

| File | Description |
|------|-------------|
| `dast-results/nuclei.json` | Raw + parsed Nuclei findings |
| `dast-results/zap.json` | Raw + parsed ZAP findings |
| `dast-results/dast-report.md` | Unified DAST report (markdown) |
| `dast-results/httpx.json` | Target discovery metadata |

## Bundled Resources

| File | Purpose | When to Read |
|------|---------|--------------|
| `scripts/install-dast-tools.sh` | Installs Nuclei, ZAP, httpx | Before first scan run |
| `scripts/run-nuclei.py` | Nuclei scanner wrapper | Phase 3 |
| `scripts/run-zap.py` | ZAP scanner wrapper | Phase 4 |
| `references/nuclei-templates.md` | Template selection guide | Before choosing Nuclei categories |
| `references/zap-scan-modes.md` | ZAP scan mode reference | Before choosing ZAP mode |
| `assets/templates/dast-report-template.md` | Report structure template | Phase 6 |

## Important Notes

- **Never run active scans against production systems without explicit authorization.** Always confirm scope with the user before executing full or API scan modes.
- ZAP active scans are loud and will appear in access logs. Warn users operating in shared or monitored environments.
- Nuclei template updates pull from the internet. Ensure outbound connectivity or use `--offline-mode` in air-gapped environments.
- If the target is only accessible via Docker internal networking, use `--network host` or pass the Docker Compose file to `run-zap.py` for automatic network attachment.
- Rate-limit Nuclei scans against fragile or production-adjacent targets using `--rate-limit 25` or lower.
