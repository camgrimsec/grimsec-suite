---
name: adversary-simulation-agent
description: >
  GRIMSEC Agent 12 — Adversary Simulation. Orchestrates controlled adversary simulation using
  RedAmon (autonomous pentest framework) to convert static vulnerability findings into
  evidence-backed attack narratives. Use when asked to run adversary simulation, penetration
  testing, red team exercises, exploit proven vulnerabilities, simulate attack chains, produce
  kill-chain reports, map ATT&CK techniques, generate executive attack narratives, or perform
  post-exploitation impact assessment. Reads EXPLOITABLE findings from exploit-validation-agent
  and produces simulation-report.md for executive-reporting-agent.
metadata:
  author: GRIMSEC
  version: '1.0'
  agent-number: '12'
  suite: GRIMSEC DevSecOps
  predecessor: exploit-validation-agent
  successor: executive-reporting-agent
---

# Adversary Simulation Agent (Agent 12)

## ⚠️ CRITICAL SAFETY CONSTRAINTS — READ FIRST

> These constraints are non-negotiable. Violating them causes legal liability and real-world harm.

- **NEVER** run against production systems without **explicit written authorization** (signed RoE document)
- **NEVER** exfiltrate real user data — demonstrate *capability* of access only, capture metadata/proof
- **NEVER** perform denial-of-service attacks of any kind (volumetric, application-layer, or resource exhaustion)
- **NEVER** modify production data, configurations, databases, or infrastructure
- **ALL** exploitation must occur in isolated test environments or explicitly authorized lab setups
- **Human approval required** before any Phase 3 (Exploitation) begins — present the exploitation plan and wait for explicit `APPROVE` confirmation
- **ALL** actions logged with full timestamped audit trail in `exploitation-log.json`
- **Emergency stop**: run `./redamon.sh down` to immediately terminate all RedAmon activity
- **Scope creep**: if recon discovers out-of-scope assets, log them and halt — do not continue without updated RoE

---

## When to Use This Skill

Load this skill when the user asks to:

- Run a full adversary simulation or red team exercise
- Convert exploit-validation findings into proven attack narratives
- Map discovered vulnerabilities to MITRE ATT&CK techniques
- Produce an executive-ready simulation report with kill-chain evidence
- Assess post-exploitation impact (lateral movement, privilege escalation, data access)
- Generate rules of engagement for an upcoming pentest
- Run RedAmon against an authorized target environment

---

## Pipeline Overview

```
Input: exploit-validation/validation-report.json (EXPLOITABLE findings)
       + target environment details + signed RoE
  │
  ├─► Phase 1: Rules of Engagement
  ├─► Phase 2: Reconnaissance
  ├─► Phase 3: Exploitation          ← HUMAN APPROVAL REQUIRED
  ├─► Phase 4: Post-Exploitation
  ├─► Phase 5: MITRE ATT&CK Mapping
  └─► Phase 6: Report Generation
```

---

## Input Files

Read these files from the GRIMSEC pipeline workspace before starting:

| File | Source Agent | Purpose |
|------|-------------|---------|
| `exploit-validation/validation-report.json` | exploit-validation-agent | EXPLOITABLE findings as attack hypotheses |
| `code-understanding/context-map.json` | devsecops-repo-analyzer | Attack surface topology |
| `app-context.json` | devsecops-repo-analyzer | Data flows and trust boundaries |
| `doc-profile.json` | devsecops-repo-analyzer | Security controls to test against |

Filter `validation-report.json` to entries where `status == "EXPLOITABLE"` — these become the seed attack hypotheses.

---

## Phase 1: Rules of Engagement

**Goal**: Define the authorized scope before any active testing begins.

### Steps

1. Load `references/rules-of-engagement.md` for templates and legal guidance
2. Load `assets/templates/roe-template.md` and populate with target details
3. Collect required inputs from the user:
   - Target IP ranges, domains, or CIDR blocks
   - In-scope services and ports
   - Out-of-scope exclusions (list every production system explicitly)
   - Testing time window (start/end datetime with timezone)
   - Notification contacts (security team lead, system owner, emergency contact)
   - Authorization signatory name and title
4. Generate `adversary-simulation/roe.json`:

```json
{
  "engagement_id": "<uuid>",
  "authorized_by": "<name, title>",
  "authorization_date": "<ISO8601>",
  "scope": {
    "targets": ["10.0.0.0/24", "staging.example.com"],
    "in_scope_ports": [80, 443, 8080, 5432],
    "in_scope_services": ["web", "api", "db-readonly-replica"],
    "out_of_scope": ["production databases", "user PII", "payment systems"],
    "exclusions": ["10.0.0.1 (core router)", "prod-db-01"]
  },
  "time_window": {
    "start": "<ISO8601>",
    "end": "<ISO8601>",
    "timezone": "UTC"
  },
  "contacts": {
    "security_lead": "<email>",
    "system_owner": "<email>",
    "emergency_stop": "<phone>"
  },
  "constraints": {
    "no_dos": true,
    "no_data_exfil": true,
    "no_production_writes": true,
    "human_approval_required": true
  }
}
```

5. **STOP**: Present `roe.json` to the user for review. Do NOT proceed to Phase 2 until the user confirms the RoE is accurate and authorization is documented.

---

## Phase 2: Reconnaissance

**Goal**: Build a complete attack surface map using RedAmon's recon pipeline.

### Steps

1. Run `scripts/setup-redamon.sh` if RedAmon is not already installed/configured
2. Load `references/redamon-integration.md` for API usage details
3. Execute the RedAmon recon pipeline:

```bash
# Subdomain discovery + DNS enumeration
./redamon.sh recon --target <domain> --mode subdomain-enum --output recon/subdomains.json

# Port scanning + service detection
./redamon.sh recon --target <cidr> --mode portscan --ports top-1000 --output recon/ports.json

# HTTP probing + technology fingerprinting
./redamon.sh recon --target recon/subdomains.json --mode http-probe --wappalyzer --output recon/tech-stack.json

# JavaScript recon (100 regex patterns, endpoint extraction)
./redamon.sh recon --target recon/http-hosts.json --mode js-recon --patterns 100 --output recon/endpoints.json

# Nuclei vulnerability scan (9,000+ templates)
./redamon.sh scan --target recon/http-hosts.json --templates all --severity medium,high,critical --output recon/nuclei-results.json
```

4. Store all results in Neo4j attack surface graph:

```bash
./redamon.sh graph --import recon/ --neo4j-uri $NEO4J_URI --neo4j-user $NEO4J_USER --neo4j-pass $NEO4J_PASS
```

5. Cross-reference Nuclei findings against `validation-report.json` EXPLOITABLE items — flag matches as high-priority attack hypotheses
6. Output `adversary-simulation/recon-results.json`:

```json
{
  "subdomains_discovered": 0,
  "open_ports": [],
  "services_detected": [],
  "tech_stack": {},
  "js_endpoints_found": 0,
  "nuclei_findings": [],
  "high_priority_targets": [],
  "neo4j_graph_populated": true
}
```

---

## Phase 3: Exploitation

**Goal**: Execute controlled attacks against authorized targets using EXPLOITABLE findings as hypotheses.

### ⚠️ Pre-Exploitation Checklist (MANDATORY)

Before executing ANY exploit:
- [ ] `roe.json` is signed and on file
- [ ] Current time is within authorized window
- [ ] Target confirmed to be in-scope
- [ ] User has explicitly typed `APPROVE` in response to the exploitation plan

### Steps

1. For each `EXPLOITABLE` finding from Phase 1, construct an attack hypothesis:
   - CVE or vulnerability class
   - Target service/endpoint
   - Proposed tool and technique
   - Expected impact
   - Risk level (stop-if-fail threshold)

2. **Present exploitation plan to user** — list all planned exploit attempts. Wait for `APPROVE`.

3. Load `references/attack-scenarios.md` for pre-built playbooks matching each vulnerability type

4. Execute via `scripts/run-simulation.py`:

```bash
python scripts/run-simulation.py \
  --roe adversary-simulation/roe.json \
  --findings exploit-validation/validation-report.json \
  --scenarios references/attack-scenarios.md \
  --output adversary-simulation/exploitation-log.json
```

5. RedAmon AI agent selects tools per finding type:
   - **CVE exploitation** → Metasploit (`msfconsole -x "use <module>; set RHOSTS <target>; run"`)
   - **Credential attacks** → Hydra (`hydra -L users.txt -P wordlist.txt <target> <service>`)
   - **SQL injection** → SQLMap (`sqlmap -u <url> --level 3 --risk 2 --batch`)
   - **Application-specific** → Custom payloads via RedAmon payload engine
   - **Container escape** → RedAmon container-escape module
   - **Supply chain** → RedAmon dependency-hijack scanner

6. Record every step in RedAmon EvoGraph (evolutionary attack chain) — each node is an action, each edge is a state transition

7. For dangerous operations (container escape, privilege escalation), pause and request explicit human approval before proceeding

8. Output `adversary-simulation/exploitation-log.json` with full timestamped steps and evidence

---

## Phase 4: Post-Exploitation

**Goal**: Assess real-world impact of successful exploitation.

### Assessment Dimensions

**Lateral Movement**
```bash
./redamon.sh post-exploit --mode lateral-movement \
  --compromised-host <host> --network-map recon/ports.json \
  --output post-exploit/lateral-movement.json
```
- Can the compromised service reach internal databases?
- Can it reach other microservices not exposed externally?
- What internal APIs are accessible?

**Privilege Escalation**
```bash
./redamon.sh post-exploit --mode privesc \
  --compromised-host <host> --output post-exploit/privesc.json
```
- Can the process escalate to root/admin?
- Can a container escape to the host?
- Are there writable sudoers/cron/suid binaries?

**Data Access Assessment**
- What sensitive data is reachable from the compromised context?
- Enumerate accessible S3 buckets, databases, secrets managers
- Record *metadata* of accessible data (table names, bucket names, secret ARNs) — **DO NOT read actual user data**

**Persistence Capability**
- Could an attacker drop a backdoor? (test only, do not install)
- Are there cron slots, webhook endpoints, or config injection points?

Output `adversary-simulation/post-exploitation-findings.json`:

```json
{
  "lateral_movement": {
    "possible": true,
    "reachable_hosts": [],
    "reachable_services": []
  },
  "privilege_escalation": {
    "possible": true,
    "method": "",
    "level_achieved": ""
  },
  "data_access": {
    "sensitive_data_reachable": true,
    "data_assets": [],
    "note": "Metadata only — no actual data read"
  },
  "persistence": {
    "possible": true,
    "methods": []
  }
}
```

---

## Phase 5: MITRE ATT&CK Mapping

**Goal**: Classify every simulation action against the MITRE ATT&CK framework.

### Steps

1. Load `references/mitre-attack-mapping.md` for the full technique reference
2. Parse `exploitation-log.json` and `post-exploitation-findings.json`
3. For each action, assign:
   - ATT&CK Tactic (e.g., `Initial Access`)
   - ATT&CK Technique ID (e.g., `T1190`)
   - Sub-technique if applicable (e.g., `T1190.001`)
   - Evidence pointer (log line, screenshot reference)

4. Build attack tree showing the full chain:
   ```
   Initial Access (T1190)
     └── Execution (T1059)
           └── Persistence (T1078)
                 └── Privilege Escalation (T1611)
                       └── Collection (T1005)
                             └── Exfiltration (T1048)
   ```

5. Identify ATT&CK coverage gaps — which phases from the full matrix were NOT tested?

6. Run `scripts/parse-results.py` to generate the mapping:

```bash
python scripts/parse-results.py \
  --exploitation-log adversary-simulation/exploitation-log.json \
  --post-exploit adversary-simulation/post-exploitation-findings.json \
  --mitre-ref references/mitre-attack-mapping.md \
  --output adversary-simulation/attack-mapping.json
```

7. Output `adversary-simulation/attack-mapping.json`:

```json
{
  "attack_chain": [],
  "techniques_used": [],
  "tactics_covered": [],
  "coverage_gaps": [],
  "heat_map_data": {}
}
```

---

## Phase 6: Report Generation

**Goal**: Produce executive-ready adversary simulation report with kill-chain evidence.

### Steps

1. Load `assets/templates/simulation-report-template.md`
2. Populate with all phase outputs
3. Generate `adversary-simulation/simulation-report.md` with:
   - **Attack Narrative**: Plain-English story of "an attacker who found your public repo could..."
   - **Kill Chain**: Step-by-step with evidence references
   - **Impact Matrix**: What was accessed, what could be damaged, blast radius
   - **MITRE ATT&CK Heat Map**: Which techniques fired
   - **Static vs. Actual comparison**: Predicted risk score vs. proven exploitation result
   - **Remediation Priority**: Fix the first link in the chain = break the whole chain
   - **Time-to-Compromise metric**: How long did the full simulation take?

4. Generate `adversary-simulation/dashboard-data.json` for GRIMSEC dashboard:

```json
{
  "engagement_id": "<uuid>",
  "time_to_compromise_minutes": 0,
  "phases_completed": [],
  "attack_chain_length": 0,
  "techniques_fired": [],
  "impact_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "remediation_items": [],
  "att_ck_heat_map": {}
}
```

5. Summary for executive-reporting-agent — proven attack narratives supersede static findings

---

## Output Files

| File | Description |
|------|-------------|
| `adversary-simulation/roe.json` | Signed rules of engagement |
| `adversary-simulation/recon-results.json` | Attack surface map |
| `adversary-simulation/exploitation-log.json` | Full exploitation audit trail |
| `adversary-simulation/post-exploitation-findings.json` | Impact assessment |
| `adversary-simulation/attack-mapping.json` | MITRE ATT&CK mapping |
| `adversary-simulation/simulation-report.md` | Executive narrative report |
| `adversary-simulation/dashboard-data.json` | Dashboard feed data |

---

## Reference Files

Load these references at the indicated phase:

| Reference | Load At |
|-----------|---------|
| `references/rules-of-engagement.md` | Phase 1 |
| `references/redamon-integration.md` | Phase 2 |
| `references/attack-scenarios.md` | Phase 3 |
| `references/mitre-attack-mapping.md` | Phase 5 |

---

## Error Handling

- **Out-of-scope target detected**: STOP immediately, log the target, update RoE before continuing
- **Exploitation produces unexpected system impact**: invoke emergency stop (`./redamon.sh down`), notify contacts in `roe.json`
- **RedAmon Neo4j connection failure**: retry with `--neo4j-retry 3`; if persistent, continue without graph and note in report
- **EXPLOITABLE finding not reproducible**: mark as `UNCONFIRMED` in exploitation log, do not escalate to post-exploitation
- **Human approval not received within 30 minutes**: timeout and halt Phase 3; log `AWAITING_APPROVAL`
