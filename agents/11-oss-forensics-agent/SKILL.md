---
name: oss-forensics-agent
description: >
  GRIMSEC Agent 11: Evidence-backed forensic investigation of open-source GitHub repositories.
  Use when investigating supply chain incidents, suspicious commits, compromised maintainer accounts,
  backdoor injections, or any open-source security incident. Triggered by phrases like
  "investigate this repo", "forensic analysis of", "check for supply chain compromise",
  "was this package backdoored", "analyze suspicious maintainer activity", "oss forensics",
  or after cicd-pipeline-auditor flags suspicious patterns. Inspired by Raptor's /oss-forensics command.
license: MIT
metadata:
  author: GRIMSEC
  version: '1.0'
  suite: GRIMSEC DevSecOps
  agent-number: '11'
  suite-position: Runs after cicd-pipeline-auditor; feeds executive-reporting-agent and threat-intel-monitor
---

# OSS Forensics Agent

**GRIMSEC Agent 11** — Evidence-backed forensic investigation of open-source GitHub repositories.

## When to Use This Skill

Load this skill when asked to:

- Investigate a GitHub repository for supply chain compromise
- Analyze suspicious commit history or maintainer behavior
- Determine if a package was backdoored
- Reconstruct the timeline of a security incident
- Assess whether a dependency in `inventory.json` is compromised
- Follow up on findings from `cicd-pipeline-auditor` (reads `audit-report.json`)
- Produce a forensic report for executive escalation

Trigger phrases: "investigate this repo", "was this package compromised", "forensic analysis", "supply chain incident", "suspicious maintainer", "backdoor injection", "oss forensics".

---

## Reference Files

Load these references when relevant:

| File | When to Load |
|------|--------------|
| `references/evidence-sources.md` | Phase 1 — which APIs/tools to use and how |
| `references/ioc-patterns.md` | Phase 2 — what patterns constitute an IOC |
| `references/supply-chain-attacks.md` | Phase 2–4 — compare against known attack patterns |

---

## Inputs

| Input | Source | Required |
|-------|--------|----------|
| GitHub repo URL | User prompt | Yes |
| Investigation prompt | User prompt | Yes (e.g., "investigate suspicious maintainer activity") |
| `audit-report.json` | cicd-pipeline-auditor output | No (enriches Phase 1) |
| `inventory.json` | Dependency inventory | No (scopes Phase 1 to known deps) |

---

## Pipeline

```
Input: GitHub repo URL + investigation prompt
  │
  ├─► Phase 1: Evidence Collection
  ├─► Phase 2: IOC Extraction
  ├─► Phase 3: Timeline Reconstruction
  ├─► Phase 4: Hypothesis Formation & Verification
  └─► Phase 5: Forensic Report
```

---

## Phase 1: Evidence Collection

**Goal:** Gather all available evidence from every available source before forming conclusions.

**Script:** `scripts/collect-evidence.py`  
**Read:** `references/evidence-sources.md` for API endpoints and query patterns.

### 1a. GitHub REST API v3 + GraphQL v4

Collect the following via GitHub API. Authenticate with `GITHUB_TOKEN` env var when available.

```
GET /repos/{owner}/{repo}                          # repo metadata, visibility, fork status
GET /repos/{owner}/{repo}/commits?per_page=100     # recent commit history
GET /repos/{owner}/{repo}/commits/{sha}            # individual commit detail with patch
GET /repos/{owner}/{repo}/pulls?state=all          # all pull requests
GET /repos/{owner}/{repo}/issues?state=all         # issues (may contain incident disclosures)
GET /repos/{owner}/{repo}/releases                 # all releases + assets
GET /repos/{owner}/{repo}/contributors             # contributor list + commit counts
GET /repos/{owner}/{repo}/collaborators            # current collaborators + permissions
GET /repos/{owner}/{repo}/teams                    # teams with access
GET /repos/{owner}/{repo}/hooks                    # webhook configurations
GET /repos/{owner}/{repo}/keys                     # deploy keys
GET /repos/{owner}/{repo}/branches                 # branch list + protection status
GET /repos/{owner}/{repo}/branches/{branch}/protection  # branch protection rules
GET /repos/{owner}/{repo}/actions/workflows        # CI/CD workflow files
GET /repos/{owner}/{repo}/actions/runs?per_page=50 # recent workflow runs
GET /orgs/{org}/audit-log                          # org audit log (requires org owner token)
```

For GraphQL v4, query contributor history and permission change events not available in REST.

### 1b. Git History (Local Clone)

Use `scripts/analyze-commits.py` to perform local clone analysis:

```bash
git clone --bare https://github.com/{owner}/{repo}.git repo.git
cd repo.git
git log --all --oneline --format="%H %ae %an %ai %s"   # full history all branches
git log --all --diff-filter=A --name-only               # files added per commit
git log --all --diff-filter=D --name-only               # files deleted per commit
git reflog --all                                        # reflog for force-push detection
git fsck --unreachable                                  # dangling/orphaned commits
git log --format="%H %ae %ce" | awk '$2 != $3'         # author/committer email mismatch
git log --all --format="%H" | xargs -I{} git cat-file -p {} | grep -i "base64\|eval\|exec"
```

Flag commits where:
- Author email ≠ committer email (rebase / force-push indicators)
- Commit timestamp falls outside maintainer's historical timezone window
- Commit modifies `.github/workflows/`, `package.json#scripts`, `setup.py`, `CMakeLists.txt`
- Merge commits that bypass PR (no associated PR number in message)

### 1c. GH Archive (Historical Event Data)

GH Archive records immutable GitHub event data. Use for events before the repo's git history begins or for deleted events.

```
BigQuery: SELECT * FROM `githubarchive.day.20250101`
          WHERE repo.name = '{owner}/{repo}'
          AND type IN ('PushEvent','PullRequestEvent','MemberEvent',
                       'TeamAddEvent','ReleaseEvent','DeleteEvent',
                       'PublicEvent','ForkEvent','WatchEvent')
          ORDER BY created_at ASC
```

Also query the GH Archive HTTP API for specific dates:
```
https://data.gharchive.org/YYYY-MM-DD-{H}.json.gz
```

Key event types for forensics:
- `MemberEvent` (action: added/removed) — maintainer permission changes
- `TeamAddEvent` — team membership changes
- `DeleteEvent` — branch/tag deletions
- `PushEvent` with `forced: true` — force pushes

### 1d. Wayback Machine

Recover deleted content (READMEs, docs, release notes, package.json versions):

```
CDX API: https://web.archive.org/cdx/search/cdx?url={github_url}&output=json&fl=timestamp,statuscode,original&limit=200
Fetch:   https://web.archive.org/web/{timestamp}/{original_url}
```

Targets for Wayback recovery:
- `https://github.com/{owner}/{repo}/blob/main/package.json` — historical dependency versions
- `https://github.com/{owner}/{repo}/blob/main/.github/workflows/*.yml` — deleted workflow files
- `https://www.npmjs.com/package/{pkg}` — historical package page (before unpublish)
- `https://pypi.org/project/{pkg}/` — historical PyPI pages

### 1e. Package Registry APIs

```
npm:   https://registry.npmjs.org/{package}             # full publish history + dist-tags
       https://registry.npmjs.org/{package}/{version}   # specific version metadata
PyPI:  https://pypi.org/pypi/{package}/json             # release history + file hashes
       https://pypi.org/pypi/{package}/{version}/json
Go:    https://proxy.golang.org/{module}/@v/list        # available versions
       https://sum.golang.org/lookup/{module}@{version} # hash verification
```

Check for:
- Versions published in quick succession (< 1 hour apart)
- Versions with new maintainer in `_npmUser` or `maintainers` array
- Dist-tags moved to a different version than expected
- Checksum mismatches vs known-good versions

### 1f. Output

Save all raw evidence to `forensics/evidence/`:
```
forensics/evidence/
├── github-api-{owner}-{repo}.json
├── commits-{sha-range}.json
├── gh-archive-events.json
├── wayback-snapshots.json
└── registry-{pkg}-history.json
```

---

## Phase 2: IOC Extraction

**Goal:** Identify Indicators of Compromise from collected evidence.

**Read:** `references/ioc-patterns.md` for full pattern library.

### IOC Categories

**Code Obfuscation IOCs:**
- `base64_decode`, `atob()`, `Buffer.from(x,'base64')`, `eval(Buffer.from(...))` in source
- Hex-encoded strings: `\x68\x74\x74\x70` patterns
- Long one-line minified additions to previously readable files
- `exec()`, `__import__('os').system()`, `subprocess.run()` in non-test code
- Encoded payloads in string literals > 200 chars

**Exfiltration IOCs:**
- HTTP calls to domains not present in project documentation or previous commits
- DNS exfiltration: constructing domains with environment variable content
- `process.env` or `os.environ` values sent in request headers/body/URL
- POST to webhook URLs (Discord, Slack, custom) not in project's legitimate use
- Outbound connections in `postinstall`, `preinstall`, `prepare` scripts

**Environment Access IOCs:**
- `process.env.NPM_TOKEN`, `process.env.AWS_*`, `process.env.GH_TOKEN`
- `os.environ['CI']`, `os.environ['GITHUB_TOKEN']`, `os.environ['SECRET_*']`
- Reading `~/.ssh/`, `~/.aws/credentials`, `~/.npmrc`, `~/.gitconfig`
- Accessing `/proc/` filesystem

**Install Hook IOCs:**
- `package.json` `scripts.postinstall` / `scripts.preinstall` with network calls
- `setup.py` `cmdclass` or `install_requires` with dynamic network fetch
- `go generate` directives fetching remote content
- `CMakeLists.txt` `ExternalProject_Add` pointing to suspicious hosts

**Behavioral IOCs:**
- New collaborator added < 7 days before a suspicious commit
- Force push to default branch (from git reflog or GH Archive `PushEvent.forced`)
- Release tag created without an associated merged PR
- Branch protection disabled (GH Archive `MemberEvent` or audit log)
- Commit author timezone shift > 4 hours from historical average
- Author/committer email mismatch on commits to default branch
- CI workflow modified to `curl | bash` remote scripts
- Workflow exfiltrating `secrets.*` to external services
- Workflow checkouts of unreviewed PRs with `pull_request_target`

### IOC Output Format

Save `forensics/iocs.json`:
```json
{
  "repo": "owner/repo",
  "investigation_date": "ISO-8601",
  "iocs": [
    {
      "id": "IOC-001",
      "category": "code_obfuscation | exfiltration | env_access | install_hook | behavioral",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "description": "Human-readable description",
      "evidence": {
        "source": "github_api | git_log | gh_archive | wayback | registry",
        "commit_sha": "...",
        "file_path": "...",
        "line_numbers": [42, 43],
        "raw_snippet": "...",
        "url": "https://..."
      },
      "first_seen": "ISO-8601",
      "last_seen": "ISO-8601"
    }
  ]
}
```

---

## Phase 3: Timeline Reconstruction

**Goal:** Build a chronological, correlated event timeline to identify the initial compromise point and attack progression.

**Script:** `scripts/generate-timeline.py`

### Event Sources to Correlate

1. **Git commits** — timestamp, author, files changed
2. **GitHub API events** — collaborator additions, permission changes, branch protection changes
3. **GH Archive events** — `MemberEvent`, `PushEvent`, `ReleaseEvent`, `DeleteEvent`
4. **Package registry** — publish timestamps, maintainer changes
5. **Wayback snapshots** — when content changed or disappeared
6. **Issue/PR timeline** — vulnerability disclosures, incident reports

### Timeline Construction Rules

- Use UTC timestamps throughout
- Prefer Git commit timestamps but validate against GH Archive (committed-at vs pushed-at)
- Flag any event where the git commit time ≠ push time by > 24 hours (possible backdating)
- Identify the **pivot point**: the earliest event that represents a departure from normal behavior
- Mark events as: `NORMAL`, `SUSPICIOUS`, `MALICIOUS`, `RESPONSE`, `UNKNOWN`

### Output

Save `forensics/timeline.json`:
```json
{
  "repo": "owner/repo",
  "timeline": [
    {
      "timestamp": "ISO-8601",
      "event_type": "commit | pr | release | collaborator_change | branch_protection | force_push | registry_publish | wayback_change",
      "classification": "NORMAL | SUSPICIOUS | MALICIOUS | RESPONSE | UNKNOWN",
      "actor": "github_username or email",
      "summary": "One-line description",
      "ioc_refs": ["IOC-001"],
      "evidence_url": "https://...",
      "raw": {}
    }
  ],
  "pivot_point": "ISO-8601 timestamp of initial compromise",
  "attack_duration_hours": 0
}
```

---

## Phase 4: Hypothesis Formation & Verification

**Goal:** Form evidence-backed hypotheses about what happened, evaluate each against all evidence, and assign confidence levels. Never assert without evidence.

### Hypothesis Types

Consider these hypotheses based on the evidence:

| Hypothesis | Key Evidence To Look For |
|------------|--------------------------|
| Compromised maintainer account | Account login from new location/IP, new SSH key added, password reset before incident |
| New malicious maintainer added | `MemberEvent` close to suspicious commit, new contributor with no prior history |
| Build system compromise | CI/CD workflow modification, build artifact hash mismatch, Codecov-style injector |
| Dependency confusion / typosquatting | Package name similar to internal package, unexpected registry source |
| Malicious PR merged | PR from external contributor with no review, bypass of branch protection |
| Insider threat / maintainer sabotage | Known maintainer with documented grievance (issues/social media), `colors.js`-style |
| Automated bot compromise | Bot token stolen, workflow `GITHUB_TOKEN` abused |

### For Each Hypothesis

Structure each hypothesis entry:

```json
{
  "id": "H-001",
  "title": "Compromised maintainer account used to inject backdoor",
  "confidence": "HIGH | MEDIUM | LOW",
  "supporting_evidence": [
    {
      "description": "New SSH deploy key added 2 days before malicious commit",
      "source": "GitHub API /repos/{owner}/{repo}/keys",
      "url": "https://..."
    }
  ],
  "contradicting_evidence": [
    {
      "description": "Commit author GPG key matches maintainer's known signing key",
      "source": "git log --show-signature",
      "url": null
    }
  ],
  "verdict": "One-paragraph assessment"
}
```

**Confidence Rules:**
- `HIGH`: Multiple independent evidence sources corroborate; no significant contradictions
- `MEDIUM`: Some evidence supports; contradictions or evidence gaps exist
- `LOW`: Plausible but evidence is circumstantial or single-source

### Verify Claims

Before finalizing:
1. Re-fetch any URL cited in evidence to confirm it still exists or note if removed
2. Cross-check commit SHAs between GitHub API and GH Archive
3. Verify package checksums against registry hashes
4. Note any evidence that has been deleted/altered (itself an IOC)

**Save:** `forensics/hypotheses.json`

---

## Phase 5: Forensic Report

**Goal:** Produce a complete, evidence-backed forensic report.

**Template:** `assets/templates/forensic-report-template.md`

### Report Sections

1. **Executive Summary** — 3–5 sentences: what happened, when, who was affected, severity
2. **Repository Profile** — owner, stars, dependents, ecosystem role
3. **Investigation Scope** — date range, sources examined, limitations
4. **Timeline** — chronological table of key events with classification labels
5. **Indicators of Compromise** — table with IOC ID, category, severity, description, evidence link
6. **Hypotheses** — each with confidence, supporting/contradicting evidence, verdict
7. **Affected Versions** — table of versions: Safe / Malicious / Unverified
8. **Impact Assessment** — who was affected, what data/secrets at risk
9. **Remediation**
   - Versions to avoid
   - Safe upgrade path
   - Immediate actions (rotate secrets, audit logs, check for lateral movement)
10. **Evidence Inventory** — table of all evidence files with sources and retrieval dates
11. **Limitations & Caveats** — what could not be verified, evidence that was deleted

**Save:** `forensics/forensic-report.md`

---

## Output Structure

```
forensics/
├── evidence/
│   ├── github-api-{owner}-{repo}.json
│   ├── commits-{sha-range}.json
│   ├── gh-archive-events.json
│   ├── wayback-snapshots.json
│   └── registry-{pkg}-history.json
├── iocs.json
├── timeline.json
├── hypotheses.json
└── forensic-report.md
```

---

## GRIMSEC Integration

| Direction | Agent | Data |
|-----------|-------|------|
| Reads from | `cicd-pipeline-auditor` | `audit-report.json` — CI/CD findings that may indicate supply chain compromise |
| Reads from | *(dependency scanner)* | `inventory.json` — dependency list to check for known-compromised packages |
| Writes to | `executive-reporting-agent` | `forensics/forensic-report.md` — for incident report generation |
| Writes to | `threat-intel-monitor` | `forensics/iocs.json` — new IOCs to add to monitoring watchlist |

**Trigger conditions:**
- Manual invocation with repo URL
- After `cicd-pipeline-auditor` flags suspicious workflow modifications
- After `threat-intel-monitor` identifies a dependency in `inventory.json` matching a known-compromised package

---

## Investigator Rules

1. **Evidence first, conclusions second.** Never assert a hypothesis without citing evidence.
2. **Cite sources.** Every claim must include the source (API endpoint, commit SHA, Wayback URL, GH Archive timestamp).
3. **Preserve evidence.** Save raw API responses before summarizing. Deleted content is itself evidence.
4. **Note absence.** If expected evidence is missing (e.g., no PR for a release), document that gap.
5. **Timestamp everything.** All events in UTC. Flag any timezone inconsistencies.
6. **Never modify the repo.** This is read-only investigation. Clone bare (`--bare`), never push.
7. **Confidence honesty.** LOW confidence is better than unfounded HIGH confidence.
