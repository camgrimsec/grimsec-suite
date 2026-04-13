# Evidence Sources Reference

This reference covers every data source used in Phase 1 (Evidence Collection) of the OSS Forensics pipeline.
Load this file during Phase 1 to identify which endpoints to query and how to use them.

---

## 1. GitHub REST API v3

**Base URL:** `https://api.github.com`  
**Auth:** `Authorization: Bearer {GITHUB_TOKEN}`  
**Docs:** https://docs.github.com/en/rest

### Authentication Setup

```bash
export GITHUB_TOKEN="ghp_..."  # or fine-grained PAT
# Required scopes: repo (read), read:org (for org audit log)
```

### Forensic Endpoints

| Endpoint | Forensic Value |
|----------|----------------|
| `GET /repos/{owner}/{repo}` | Visibility, fork status, default branch, topics, archived state |
| `GET /repos/{owner}/{repo}/commits?per_page=100` | Paginated commit history |
| `GET /repos/{owner}/{repo}/commits/{sha}` | Per-commit patch, files changed, verification status |
| `GET /repos/{owner}/{repo}/pulls?state=all&per_page=100` | All PRs, merged_by, head SHA |
| `GET /repos/{owner}/{repo}/issues?state=all&per_page=100` | Issue timeline, security reports |
| `GET /repos/{owner}/{repo}/releases` | All releases, assets, tag names, published_at |
| `GET /repos/{owner}/{repo}/contributors?per_page=100&anon=1` | Contributor list and commit counts |
| `GET /repos/{owner}/{repo}/collaborators?per_page=100` | Current collaborators + permission levels |
| `GET /repos/{owner}/{repo}/teams` | Teams with repo access |
| `GET /repos/{owner}/{repo}/hooks` | Configured webhooks (URL, events, active status) |
| `GET /repos/{owner}/{repo}/keys` | Deploy keys (read/write, added date) |
| `GET /repos/{owner}/{repo}/branches?per_page=100` | All branches + protection status |
| `GET /repos/{owner}/{repo}/branches/{branch}/protection` | Branch protection rules (required reviews, dismissal, signed commits) |
| `GET /repos/{owner}/{repo}/actions/workflows` | All CI/CD workflow files |
| `GET /repos/{owner}/{repo}/actions/runs?per_page=50` | Recent workflow run history |
| `GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs` | Job details and logs for a run |
| `GET /orgs/{org}/audit-log?per_page=100` | Org audit log (requires org owner token) |
| `GET /repos/{owner}/{repo}/git/refs?per_page=100` | All git refs (branches, tags) |
| `GET /repos/{owner}/{repo}/git/tags` | Annotated tags with tagger info |
| `GET /repos/{owner}/{repo}/contents/{path}` | File content at HEAD |
| `GET /repos/{owner}/{repo}/contents/{path}?ref={sha}` | File content at specific commit |

### Pagination

GitHub paginates at 100 items max. Follow `Link` header:
```
Link: <https://api.github.com/repos/.../commits?page=2>; rel="next"
```

### Rate Limits

- Unauthenticated: 60 req/hour
- Authenticated (PAT): 5,000 req/hour
- Check: `GET /rate_limit`

### Key Forensic Patterns

**Find commits from unknown authors:**
```bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/owner/repo/commits?per_page=100" | \
  jq '.[] | {sha: .sha, author: .commit.author.email, verified: .commit.verification.verified}'
```

**Find deploy keys (backdoor persistence mechanism):**
```bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/owner/repo/keys" | \
  jq '.[] | {id: .id, title: .title, read_only: .read_only, added: .created_at}'
```

**Get webhook configs (exfiltration endpoints):**
```bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/owner/repo/hooks" | \
  jq '.[] | {id: .id, url: .config.url, events: .events, active: .active}'
```

---

## 2. GitHub GraphQL API v4

**Endpoint:** `https://api.github.com/graphql`  
**Auth:** Same token as REST

### Useful for Forensics

GraphQL v4 provides access to data not available in REST v3, including timeline events on issues/PRs and audit log data.

**Get PR review history:**
```graphql
query {
  repository(owner: "owner", name: "repo") {
    pullRequest(number: 123) {
      author { login }
      mergedAt
      mergedBy { login }
      reviews(first: 20) {
        nodes { author { login } state submittedAt }
      }
      timeline(first: 20) {
        nodes {
          ... on MergedEvent { createdAt actor { login } }
          ... on ReviewDismissedEvent { createdAt actor { login } }
        }
      }
    }
  }
}
```

**Get repository member events (org context):**
```graphql
query {
  organization(login: "org") {
    auditLog(first: 100, query: "action:member.add repo:owner/repo") {
      nodes {
        ... on OrgAddMemberAuditEntry {
          createdAt
          actor { login }
          user { login }
          permission
        }
      }
    }
  }
}
```

---

## 3. GH Archive (GitHub Archive)

**Website:** https://www.gharchive.org  
**Purpose:** Immutable archive of public GitHub event data. Use when repo history has been rewritten or deleted events need recovering.

### HTTP Download (No Auth Required)

```
https://data.gharchive.org/YYYY-MM-DD-{H}.json.gz
```
- Files are hourly, hour 0–23 (UTC)
- Each file is a newline-delimited JSON of GitHub event objects
- Example: `https://data.gharchive.org/2025-03-14-12.json.gz`

```bash
# Download and filter for a specific repo
curl -s https://data.gharchive.org/2025-03-14-12.json.gz | \
  gunzip | \
  jq -c 'select(.repo.name == "owner/repo")'
```

### BigQuery (Google Cloud)

Dataset: `githubarchive.day.*` (daily shards), `githubarchive.month.*` (monthly)

**Query template for forensic investigation:**
```sql
SELECT
  created_at,
  type,
  actor.login AS actor,
  payload
FROM `githubarchive.day.*`
WHERE _TABLE_SUFFIX BETWEEN '20250101' AND '20250315'
  AND repo.name = 'owner/repo'
  AND type IN (
    'PushEvent',
    'PullRequestEvent',
    'MemberEvent',
    'TeamAddEvent',
    'ReleaseEvent',
    'DeleteEvent',
    'CreateEvent',
    'IssuesEvent',
    'PublicEvent'
  )
ORDER BY created_at ASC
```

### Key Event Types for Forensics

| Event Type | Fields to Inspect | Forensic Relevance |
|------------|-------------------|-------------------|
| `PushEvent` | `payload.forced`, `payload.commits`, `payload.before`, `payload.after` | Force pushes, rewritten history |
| `MemberEvent` | `payload.action` (added/removed), `payload.member.login` | Maintainer changes |
| `TeamAddEvent` | `payload.user.login`, `payload.team.name` | Team permission grants |
| `ReleaseEvent` | `payload.action`, `payload.release.tag_name` | Release creation/deletion |
| `DeleteEvent` | `payload.ref_type`, `payload.ref` | Branch/tag deletion |
| `PublicEvent` | (no payload) | Repo made public (if previously private) |
| `CreateEvent` | `payload.ref_type`, `payload.ref` | New branch/tag creation |
| `IssuesEvent` | `payload.issue.title`, `payload.action` | Security issue reports |

**Find force pushes:**
```sql
SELECT created_at, actor.login, payload.before, payload.after
FROM `githubarchive.day.*`
WHERE _TABLE_SUFFIX >= '20250101'
  AND repo.name = 'owner/repo'
  AND type = 'PushEvent'
  AND payload.forced = true
```

**Find maintainer additions:**
```sql
SELECT created_at, actor.login, payload.member.login AS new_member
FROM `githubarchive.day.*`
WHERE _TABLE_SUFFIX >= '20250101'
  AND repo.name = 'owner/repo'
  AND type = 'MemberEvent'
  AND payload.action = 'added'
```

---

## 4. Wayback Machine (Internet Archive)

**CDX API:** `https://web.archive.org/cdx/search/cdx`  
**Fetch URL:** `https://web.archive.org/web/{timestamp}/{original_url}`  
**Docs:** https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md

### CDX API Query

```bash
# List all snapshots of a file
curl "https://web.archive.org/cdx/search/cdx?url=https://github.com/owner/repo/blob/main/package.json&output=json&fl=timestamp,statuscode,original&limit=200&collapse=timestamp:8"
```

**Parameters:**
- `url`: target URL (supports `*` wildcard)
- `output`: `json` or `text`
- `fl`: fields: `timestamp,statuscode,original,mimetype,digest,length`
- `limit`: max results (default 100000)
- `collapse=timestamp:8`: deduplicate by day (8-digit date prefix)
- `from=20240101&to=20250101`: date range filter
- `filter=statuscode:200`: only successful snapshots
- `matchType=prefix`: match all URLs under a prefix

### Fetch a Specific Snapshot

```bash
# Fetch the package.json as it existed on March 14, 2025
curl "https://web.archive.org/web/20250314000000/https://github.com/owner/repo/blob/main/package.json"
```

Use `20250314000000` as timestamp — Wayback finds the nearest snapshot at or before that date.

### Forensic Use Cases

| Target URL | What to Recover |
|------------|----------------|
| `github.com/{owner}/{repo}` | Historical README, repo description, topics |
| `github.com/{owner}/{repo}/blob/{branch}/package.json` | Previous postinstall scripts, dependency versions |
| `github.com/{owner}/{repo}/blob/{branch}/.github/workflows/{name}.yml` | Deleted or modified workflow files |
| `github.com/{owner}/{repo}/releases/tag/{version}` | Release notes before editing |
| `npmjs.com/package/{pkg}` | npm page before package unpublish |
| `pypi.org/project/{pkg}/{version}/` | PyPI page history |
| `raw.githubusercontent.com/{owner}/{repo}/{sha}/{file}` | Raw file content at specific SHAs |

### Wildcard Snapshot Discovery

```bash
# Find all archived paths under a repo
curl "https://web.archive.org/cdx/search/cdx?url=https://github.com/owner/repo/*&output=json&fl=timestamp,original&matchType=prefix&collapse=original&limit=500"
```

---

## 5. git Log Forensics

All git commands should run on a **bare clone** (`git clone --bare`) for forensic integrity.

### Essential Commands

```bash
# Full history across all branches
git log --all --oneline --format="%H %ae %an %aI %s"

# Files added in each commit (detect new malicious files)
git log --all --diff-filter=A --name-only --format="%H %aI %ae"

# Files deleted (cover-up evidence)
git log --all --diff-filter=D --name-only --format="%H %aI %ae"

# Only commits that modified CI/CD
git log --all --follow -- .github/workflows/

# Author vs committer email mismatch (rebase/forge indicators)
git log --all --format="%H %ae %ce %aI" | awk -F' ' '$2 != $3 {print}'

# Reflog — detect force pushes (non-bare only)
git reflog --all --format="%H %gd %gs"

# Find unreachable (dangling) commits
git fsck --unreachable --no-progress | grep "unreachable commit"

# Inspect a dangling commit
git cat-file -p {dangling_sha}

# Show full diff for a specific commit
git show --unified=5 {sha}

# Check GPG/SSH signing status
git log --show-signature --format="%H %G? %GS %ae" | head -50
# G? values: G=good, B=bad, U=untrusted, N=no sig, E=error

# Find merge commits that bypassed PR (no "Merge pull request" message)
git log --all --merges --format="%H %aI %ae %s" | grep -v "Merge pull request"

# Find commits with obfuscated content patterns
git log --all --format="%H" | xargs -I{} git show {} | grep -E "eval\(|base64_decode|atob\("
```

### Commit Timestamp Verification

GitHub timestamps can be falsified in the commit object but the push timestamp in GH Archive is immutable. To verify:

1. Get commit `authored_date` from `git log`
2. Get `pushed_at` from GH Archive `PushEvent.created_at` for the same SHA
3. If `authored_date` is > 24h before `pushed_at`, the commit may have been backdated

### Branch Protection Bypass Detection

```bash
# Commits directly on default branch without a PR merge commit
git log --first-parent main --format="%H %s" | grep -v "^.*Merge pull request"

# Commits authored outside normal business hours (UTC)
git log --all --format="%H %aI %ae %s" | awk -F'T' '{split($2,t,":"); if (t[1]+0 < 6 || t[1]+0 > 22) print}'
```

---

## 6. npm Registry API

**Base URL:** `https://registry.npmjs.org`  
**No auth required for public packages**

### Endpoints

```bash
# Full package metadata (all versions)
GET https://registry.npmjs.org/{package}

# Specific version metadata
GET https://registry.npmjs.org/{package}/{version}

# Version publish times
jq '.time' <<< "$(curl -s https://registry.npmjs.org/{package})"

# Maintainer history per version
jq '.versions | to_entries[] | {version: .key, maintainers: .value.maintainers, user: .value._npmUser}' \
  <<< "$(curl -s https://registry.npmjs.org/{package})"

# postinstall scripts per version
jq '.versions | to_entries[] | {version: .key, scripts: .value.scripts}' \
  <<< "$(curl -s https://registry.npmjs.org/{package})"
```

### Forensic Checks

| Check | Command |
|-------|---------|
| Version publish velocity | `jq '.time | to_entries[] | .value' <<< $PKG_JSON \| sort` |
| New maintainer appearance | Compare `maintainers` array across versions |
| postinstall changes | `jq '.versions."{v}".scripts' <<< $PKG_JSON` |
| Dist-tag manipulation | `jq '."dist-tags"' <<< $PKG_JSON` |
| Integrity hash | `jq '.versions."{v}".dist.integrity' <<< $PKG_JSON` |

---

## 7. PyPI API

**Base URL:** `https://pypi.org/pypi`

```bash
# All release info
GET https://pypi.org/pypi/{package}/json

# Specific version
GET https://pypi.org/pypi/{package}/{version}/json

# Extract upload times and hashes
jq '.releases | to_entries[] | {version: .key, upload_time: .value[0].upload_time, sha256: .value[0].digests.sha256}' \
  <<< "$(curl -s https://pypi.org/pypi/{package}/json)"

# Check for new maintainers (via warehouse API)
GET https://pypi.org/pypi/{package}/json | jq '.info.author, .info.maintainer'
```

### Forensic Checks

- New upload to old version slot (version shadowing)
- `setup.py` with network requests in `install_requires` or `cmdclass`
- Upload time out of band with git release tags
- MD5/SHA256 mismatch vs known-good versions

---

## 8. Go Module Proxy

**Base URL:** `https://proxy.golang.org`

```bash
# List available versions
GET https://proxy.golang.org/{module}/@v/list

# Fetch specific version info
GET https://proxy.golang.org/{module}/@v/{version}.info

# Checksum verification (via sum database)
GET https://sum.golang.org/lookup/{module}@{version}
# Returns: hash of module tree, signed by Google's transparency log
```

The Go checksum database (`sum.golang.org`) is an append-only, cryptographically verifiable log. If the hash for a version has changed since first publication, that is definitive evidence of tampering.

---

## Source Priority and Trust Hierarchy

When evidence sources conflict, use this trust ordering:

1. **Git object hashes** — cryptographically immutable once pushed
2. **GH Archive** — immutable external record, cannot be modified by repo owner
3. **Go checksum database** — cryptographically signed, append-only
4. **GitHub API** — authoritative but repo owner can modify (delete releases, edit PR descriptions)
5. **npm/PyPI registry** — authoritative for package state but admins can unpublish
6. **Wayback Machine** — best-effort archiving, may have gaps
7. **GitHub web UI** — same as API, can be edited

**Note:** If GitHub API data conflicts with GH Archive data, prefer GH Archive. Repo owners can delete events, edit descriptions, and force-push, but cannot alter historical GH Archive records.
