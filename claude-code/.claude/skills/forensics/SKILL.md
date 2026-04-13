# OSS Forensics Agent

Evidence-backed forensic investigation of open-source GitHub repositories.

Invoke with `/forensics` or phrases like "investigate this repo", "forensic analysis", "supply chain compromise", "was this package backdoored".

## Investigator Rules

1. Evidence first, conclusions second
2. Cite sources — every claim must include the source
3. Preserve evidence — save raw API responses
4. Note absence — if expected evidence is missing, document that gap
5. Timestamp everything in UTC
6. Never modify the repo — clone bare (`--bare`), never push
7. Confidence honesty — LOW confidence is better than unfounded HIGH

## Pipeline

```
Phase 1: Evidence Collection
Phase 2: IOC Extraction
Phase 3: Timeline Reconstruction
Phase 4: Hypothesis Formation & Verification
Phase 5: Forensic Report
```

## Phase 1: Evidence Collection

Set `GITHUB_TOKEN` for authenticated API requests.

**GitHub REST API:**
```bash
# Repo metadata
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/{owner}/{repo}

# Recent commits
curl -H "Authorization: Bearer $GITHUB_TOKEN" "https://api.github.com/repos/{owner}/{repo}/commits?per_page=100"

# Collaborators
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/{owner}/{repo}/collaborators

# Deploy keys
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/{owner}/{repo}/keys

# Branch protection
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/{owner}/{repo}/branches/{branch}/protection
```

**Git History:**
```bash
git clone --bare https://github.com/{owner}/{repo}.git repo.git
cd repo.git
git log --all --format="%H %ae %an %ai %s"
git log --all --diff-filter=A --name-only  # Files added
git log --all --format="%H %ae %ce" | awk '$2 != $3'  # Email mismatch
git fsck --unreachable  # Orphaned commits
```

**Package Registry:**
```bash
curl https://registry.npmjs.org/{package}  # npm history
curl https://pypi.org/pypi/{package}/json  # PyPI history
```

**Wayback Machine:**
```bash
curl "https://web.archive.org/cdx/search/cdx?url={github_url}&output=json&fl=timestamp,statuscode,original&limit=200"
```

Save all raw evidence to `forensics/evidence/`.

## Phase 2: IOC Extraction

**Code Obfuscation IOCs:**
- `base64_decode`, `atob()`, `Buffer.from(x,'base64')`, `eval(Buffer.from(...))` in source
- Hex-encoded strings (`\x68\x74...`)
- `exec()`, `subprocess.run()` in non-test code

**Exfiltration IOCs:**
- HTTP calls to domains not in project documentation or previous commits
- `process.env` or `os.environ` values sent in request headers/body/URL
- POST to webhook URLs not in project's legitimate use
- Outbound connections in `postinstall`, `preinstall`, `prepare` scripts

**Environment Access IOCs:**
- `process.env.NPM_TOKEN`, `process.env.AWS_*`, `process.env.GH_TOKEN`
- Reading `~/.ssh/`, `~/.aws/credentials`, `~/.npmrc`

**Behavioral IOCs:**
- New collaborator added < 7 days before a suspicious commit
- Force push to default branch
- Release tag created without an associated merged PR
- CI workflow modified to `curl | bash` remote scripts

**Save:** `forensics/iocs.json`

## Phase 3: Timeline Reconstruction

Mark events as: `NORMAL`, `SUSPICIOUS`, `MALICIOUS`, `RESPONSE`, `UNKNOWN`

Identify the **pivot point**: earliest event departing from normal behavior.

**Save:** `forensics/timeline.json`

## Phase 4: Hypothesis Formation

| Hypothesis | Key Evidence |
|------------|-------------|
| Compromised maintainer account | New SSH key, login from new location |
| New malicious maintainer | `MemberEvent` close to suspicious commit |
| Build system compromise | CI/CD workflow modification, build artifact hash mismatch |
| Malicious PR merged | PR from external contributor with no review |
| Insider threat | Known maintainer with documented grievance |

Confidence: HIGH (multiple independent sources) / MEDIUM (some evidence, gaps exist) / LOW (circumstantial)

**Save:** `forensics/hypotheses.json`

## Phase 5: Forensic Report

Sections:
1. Executive Summary (what, when, who, severity)
2. Repository Profile
3. Investigation Scope
4. Timeline (chronological table with labels)
5. Indicators of Compromise
6. Hypotheses (with confidence, supporting/contradicting evidence)
7. Affected Versions (Safe / Malicious / Unverified)
8. Impact Assessment
9. Remediation (versions to avoid, safe upgrade path, rotate secrets)
10. Evidence Inventory
11. Limitations & Caveats

**Save:** `forensics/forensic-report.md`

## Output Structure

```
forensics/
├── evidence/
│   ├── github-api-{owner}-{repo}.json
│   ├── commits-{sha-range}.json
│   ├── wayback-snapshots.json
│   └── registry-{pkg}-history.json
├── iocs.json
├── timeline.json
├── hypotheses.json
└── forensic-report.md
```
