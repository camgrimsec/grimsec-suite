# Forensic Investigation Report

<!-- Fill in all bracketed placeholders. Remove all HTML comment instructions before final delivery. -->

**Classification:** CONFIDENTIAL — GRIMSEC OSS Forensics  
**Report ID:** `GRIMSEC-OSS-FORENSICS-{YYYYMMDD}-{NNN}`  
**Report Date:** {ISO date}  
**Investigator:** GRIMSEC OSS Forensics Agent (Agent 11)  
**Investigation Requested By:** {name / team}

---

## 1. Executive Summary

<!-- 3–5 sentences maximum. Written for a non-technical executive. Answer:
     What happened? When? To whom? What is the impact? What should be done now? -->

{Repository `owner/repo`} {was / may have been} compromised {between DATE1 and DATE2}. {Brief description of what happened in plain language}. The {number} affected versions are {list versions}. {Impact statement: who was affected, what data/secrets were at risk}. Immediate action is recommended: {one-sentence remediation}.

**Severity:** {CRITICAL / HIGH / MEDIUM / LOW}  
**Confidence:** {HIGH / MEDIUM / LOW} — {one sentence explaining confidence level}  
**Status:** {CONFIRMED / PROBABLE / SUSPECTED / UNCONFIRMED}

---

## 2. Repository Profile

| Field | Value |
|-------|-------|
| Repository | `{owner/repo}` |
| URL | https://github.com/{owner}/{repo} |
| Stars | {N} |
| Forks | {N} |
| Weekly Downloads (npm/PyPI) | {N} |
| Ecosystem | {npm / PyPI / Go / Maven / Other} |
| Known Dependents | {N packages / organizations} |
| Default Branch | `{main / master}` |
| License | {license} |
| Ecosystem Role | {brief description, e.g., "Widely used GitHub Action for detecting file changes in CI/CD"} |

---

## 3. Investigation Scope

**Date Range:** {start date} – {end date}  
**Evidence Sources Examined:**

| Source | Status | Notes |
|--------|--------|-------|
| GitHub REST API v3 | {Examined / Unavailable} | {Notes, e.g., "Rate-limited — 60 req/hr"} |
| Git history (local clone) | {Examined / Unavailable} | |
| GH Archive (BigQuery/HTTP) | {Examined / Unavailable} | Covered {date range} |
| Wayback Machine | {Examined / Unavailable} | {N} snapshots found |
| npm registry | {Examined / Not applicable} | |
| PyPI registry | {Examined / Not applicable} | |

**Limitations:**
<!-- List any gaps: deleted content not archived, rate limits hit, private repos not accessible, etc. -->
- {Limitation 1}
- {Limitation 2}

---

## 4. Timeline of Events

<!-- Chronological table of all significant events. Use UTC timestamps.
     Classification codes: NORMAL | SUSPICIOUS | MALICIOUS | RESPONSE | UNKNOWN -->

| Timestamp (UTC) | Classification | Actor | Event | Evidence |
|----------------|---------------|-------|-------|---------|
| {YYYY-MM-DD HH:MM} | NORMAL | `{actor}` | {Description} | [Link]({url}) |
| {YYYY-MM-DD HH:MM} | SUSPICIOUS | `{actor}` | {Description} | [Link]({url}) |
| {YYYY-MM-DD HH:MM} | **MALICIOUS** | `{actor}` | {Description} | [Link]({url}) |
| {YYYY-MM-DD HH:MM} | RESPONSE | `{actor}` | {Description} | [Link]({url}) |

<!-- Add rows as needed. Bold MALICIOUS rows for visibility. -->

**Pivot Point:** {ISO timestamp} — {Description of the initial compromise event}  
**Attack Duration:** {N hours / days}

---

## 5. Indicators of Compromise

<!-- Every IOC must cite a specific evidence source. -->

| IOC ID | Category | Severity | Description | Evidence Source | First Seen |
|--------|----------|----------|-------------|----------------|-----------|
| IOC-001 | `code_obfuscation` | CRITICAL | {Description} | [Commit {sha8}]({commit_url}) | {date} |
| IOC-002 | `exfiltration` | HIGH | {Description} | [GH Archive event]({url}) | {date} |
| IOC-003 | `behavioral` | HIGH | {Description} | [GitHub API]({url}) | {date} |
| IOC-004 | `env_access` | CRITICAL | {Description} | [File: {path}]({url}) | {date} |
| IOC-005 | `install_hook` | CRITICAL | {Description} | [package.json]({url}) | {date} |

<!-- Category options: code_obfuscation | exfiltration | env_access | install_hook | behavioral -->

---

## 6. Hypotheses

### Hypothesis H-001: {Title}

**Confidence:** {HIGH / MEDIUM / LOW}  
**Status:** {SUPPORTED / CONTRADICTED / UNRESOLVED}

**Supporting Evidence:**

| # | Evidence | Source | URL |
|---|---------|--------|-----|
| 1 | {Description} | {Source} | {URL} |
| 2 | {Description} | {Source} | {URL} |

**Contradicting Evidence:**

| # | Evidence | Source | URL |
|---|---------|--------|-----|
| 1 | {Description or "None"} | {Source} | {URL} |

**Assessment:** {One to two paragraphs. State what the evidence indicates, note any gaps, and give an honest confidence statement. Do not overstate certainty.}

---

### Hypothesis H-002: {Title}

**Confidence:** {HIGH / MEDIUM / LOW}

**Supporting Evidence:**

| # | Evidence | Source | URL |
|---|---------|--------|-----|
| 1 | {Description} | {Source} | {URL} |

**Contradicting Evidence:** None identified.

**Assessment:** {Assessment paragraph.}

<!-- Add additional hypotheses as needed. -->

---

## 7. Affected Versions

<!-- For each version: mark Safe, Malicious, or Unverified. Include the specific evidence. -->

| Version | Status | Published | Notes |
|---------|--------|-----------|-------|
| {v1.2.3} | ✅ Safe | {date} | Last known clean version |
| {v1.2.4} | ❌ Malicious | {date} | Contains {IOC-001, IOC-002} |
| {v1.2.5} | ❌ Malicious | {date} | Malicious version still in registry |
| {v1.2.6} | ✅ Safe | {date} | Patched — malicious code removed |
| {v2.0.0} | ⚠️ Unverified | {date} | Not examined — treat as suspect |

**Safe Upgrade Path:** Upgrade from {version} to {version}. Pin to commit SHA `{sha}` for GitHub Actions.

---

## 8. Impact Assessment

### Directly Affected Users

{Description of who was affected — organizations, users, downstream dependents.}

### Exposed Data / Secrets

<!-- List what types of secrets or data may have been exfiltrated. -->

| Secret Type | Risk | Evidence |
|-------------|------|---------|
| `GITHUB_TOKEN` | CI repository access | IOC-004 — env exfiltration |
| `AWS_*` credentials | Cloud infrastructure | IOC-004 — env exfiltration |
| `NPM_TOKEN` | npm publish access | IOC-004 — env exfiltration |

### Blast Radius

- **Direct exposure:** {N} repositories that consumed affected versions
- **Potential secondary exposure:** {N} downstream packages that depend on this package
- **Estimated CI runs affected:** {N} (based on weekly download counts × attack window in days / 7)

---

## 9. Remediation

### Immediate Actions (Do Today)

1. **Upgrade** to safe version `{version}` or uninstall the package.
2. **Rotate all CI secrets** that were accessible during the attack window ({date1} – {date2}):
   - GitHub Personal Access Tokens
   - npm publish tokens
   - AWS/GCP/Azure credentials
   - Docker registry credentials
3. **Audit CI logs** from {date1} to {date2} for outbound connections to:
   - `{ioc_domain_1}`
   - `{ioc_domain_2}`
4. **Check for lateral movement** — review which systems/repos the rotated tokens had access to.
5. **Revoke deploy keys** added to your repos from {date1} – {date2} if origin is unknown.

### Safe Versions

- **Avoid:** {list of malicious/suspect versions}
- **Use:** {recommended safe version}
- **Pin method (GitHub Actions):** `uses: {owner}/{repo}@{safe_commit_sha}  # {version} - verified safe`

### Longer-Term Mitigations

- Pin all GitHub Actions to immutable commit SHAs, not tags
- Enable Dependabot or Renovate for dependency update PRs
- Implement SLSA Level 2+ for your own releases (provenance attestation)
- Use Socket.dev or Snyk for real-time supply chain monitoring
- Require GPG-signed commits for releases
- Enable branch protection: require PR reviews, dismiss stale reviews

---

## 10. Evidence Inventory

| File | Source | Retrieved | Description |
|------|--------|-----------|-------------|
| `forensics/evidence/github-api-{owner}-{repo}.json` | GitHub REST API | {date} | Repo metadata, commits, releases, webhooks, deploy keys |
| `forensics/evidence/commits-detail-{owner}-{repo}.json` | GitHub REST API | {date} | Per-commit patch data (top {N} commits) |
| `forensics/evidence/gh-archive-events.json` | GH Archive | {date} | {N} events from {date range} |
| `forensics/evidence/wayback-snapshots.json` | Wayback Machine CDX | {date} | {N} snapshots across {N} URLs |
| `forensics/evidence/registry-npm-{pkg}-history.json` | npm registry | {date} | Full version history and maintainer records |
| `forensics/iocs.json` | This investigation | {date} | {N} IOCs identified |
| `forensics/timeline.json` | This investigation | {date} | {N} events in chronological timeline |
| `forensics/hypotheses.json` | This investigation | {date} | {N} hypotheses with confidence ratings |

---

## 11. Limitations and Caveats

<!-- Be honest about what could not be determined. Overstating certainty damages credibility. -->

- **Deleted content:** {Any GitHub content that was deleted before collection and not recovered from Wayback/GH Archive}
- **Private context:** {Any private org data, audit logs, or maintainer communications not accessible}
- **Rate limits:** {If GitHub API rate limits constrained evidence collection}
- **Analysis gaps:** {Commits not analyzed, time ranges not covered}
- **Attribution uncertainty:** {If actor attribution is not conclusively established}
- **Dynamic analysis:** {If malicious code was not executed to confirm payload behavior}

---

## Appendix A: Raw IOC Data

See: `forensics/iocs.json`

## Appendix B: Full Timeline Data

See: `forensics/timeline.json`

## Appendix C: Hypothesis Evidence Detail

See: `forensics/hypotheses.json`

---

*Report generated by GRIMSEC OSS Forensics Agent (Agent 11)*  
*GRIMSEC DevSecOps Suite — https://github.com/grimsec*  
*Feeds into: executive-reporting-agent, threat-intel-monitor*
