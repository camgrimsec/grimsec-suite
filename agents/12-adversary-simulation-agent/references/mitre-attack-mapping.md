# MITRE ATT&CK Mapping Reference

**GRIMSEC Agent 12 — Adversary Simulation Agent**

This reference maps RedAmon simulation actions to MITRE ATT&CK Enterprise techniques. Load this reference at Phase 5 (ATT&CK Mapping) of the simulation pipeline.

ATT&CK Enterprise v15 — Framework: https://attack.mitre.org/

---

## Quick Mapping Table — GRIMSEC Vulnerability Types

| GRIMSEC Vuln Type | Tactic | Technique ID | Technique Name |
|-------------------|--------|-------------|----------------|
| CVE (web app) | Initial Access | T1190 | Exploit Public-Facing Application |
| CVE (network) | Lateral Movement | T1210 | Exploitation of Remote Services |
| SQLI | Initial Access | T1190 | Exploit Public-Facing Application |
| RCE | Execution | T1059 | Command and Scripting Interpreter |
| JWT / Session | Credential Access | T1539 | Steal Web Session Cookie |
| CREDENTIAL | Credential Access | T1552 | Unsecured Credentials |
| CONTAINER_ESCAPE | Privilege Escalation | T1611 | Escape to Host |
| SUPPLY_CHAIN | Initial Access | T1195 | Supply Chain Compromise |
| SSRF | Lateral Movement | T1210 | Exploitation of Remote Services |
| WEBSOCKET | Credential Access | T1539 | Steal Web Session Cookie |
| IDOR / PATH_TRAVERSAL | Collection | T1005 | Data from Local System |
| CI/CD Injection | Initial Access | T1195 | Supply Chain Compromise |
| Lateral Movement | Lateral Movement | T1021 | Remote Services |
| Persistence | Persistence | T1078 | Valid Accounts |
| Data Access | Collection | T1213 | Data from Information Repositories |
| Exfiltration | Exfiltration | T1048 | Exfiltration Over Alternative Protocol |
| Privilege Escalation | Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Account Creation | Persistence | T1136 | Create Account |

---

## Tactic 1: Initial Access

**Definition**: Techniques to gain an initial foothold in a target environment.

### T1190 — Exploit Public-Facing Application
- **GRIMSEC triggers**: CVE findings, SQL injection, RCE via web application
- **RedAmon tools**: Metasploit (web exploits), SQLMap, custom payloads, Nuclei
- **Sub-techniques**:
  - T1190 — Base technique (general web app exploitation)
- **Detection opportunities**: WAF alerts, application error logs, anomalous HTTP responses
- **Common GRIMSEC evidence**: Metasploit session output, SQLMap extraction confirmation, Nuclei template match

```json
{
  "technique_id": "T1190",
  "technique_name": "Exploit Public-Facing Application",
  "tactic": "Initial Access",
  "mitre_url": "https://attack.mitre.org/techniques/T1190/",
  "grimsec_scenarios": ["scenario-2", "scenario-6"],
  "redamon_modules": ["metasploit", "sqlmap", "nuclei", "custom-payload"]
}
```

### T1195 — Supply Chain Compromise
- **GRIMSEC triggers**: Supply chain findings, CI/CD injection, compromised dependencies
- **RedAmon tools**: dependency-hijack module, CI/CD analysis module
- **Sub-techniques**:
  - T1195.001 — Compromise Software Dependencies and Development Tools
  - T1195.002 — Compromise Software Supply Chain
- **GRIMSEC evidence**: Malicious package install hooks, CI/CD workflow YAML analysis

```json
{
  "technique_id": "T1195",
  "technique_name": "Supply Chain Compromise",
  "tactic": "Initial Access",
  "mitre_url": "https://attack.mitre.org/techniques/T1195/",
  "grimsec_scenarios": ["scenario-3", "scenario-5"],
  "redamon_modules": ["dependency-hijack", "cicd-analysis"]
}
```

---

## Tactic 2: Execution

**Definition**: Techniques to run adversary-controlled code on a local or remote system.

### T1059 — Command and Scripting Interpreter
- **GRIMSEC triggers**: RCE, SQLMap OS command, container escape resulting in shell
- **Sub-techniques**:
  - T1059.004 — Unix Shell
  - T1059.006 — Python
  - T1059.007 — JavaScript
- **GRIMSEC evidence**: Shell command output captured in exploitation log

```json
{
  "technique_id": "T1059",
  "technique_name": "Command and Scripting Interpreter",
  "tactic": "Execution",
  "mitre_url": "https://attack.mitre.org/techniques/T1059/",
  "grimsec_scenarios": ["scenario-2", "scenario-4"],
  "redamon_modules": ["sqlmap", "metasploit", "container-escape"]
}
```

### T1203 — Exploitation for Client Execution
- **GRIMSEC triggers**: XSS, CSWSH, client-side template injection
- **RedAmon tools**: Nuclei (XSS templates), custom payload (CSWSH)
- **GRIMSEC evidence**: XSS proof-of-concept execution, CSWSH page triggering

```json
{
  "technique_id": "T1203",
  "technique_name": "Exploitation for Client Execution",
  "tactic": "Execution",
  "mitre_url": "https://attack.mitre.org/techniques/T1203/",
  "grimsec_scenarios": ["scenario-7"],
  "redamon_modules": ["nuclei", "custom-payload"]
}
```

---

## Tactic 3: Persistence

**Definition**: Techniques to maintain access despite restarts, changed credentials, or other interruptions.

### T1078 — Valid Accounts
- **GRIMSEC triggers**: Successfully stolen credentials reused for ongoing access
- **Sub-techniques**:
  - T1078.001 — Default Accounts
  - T1078.003 — Local Accounts
  - T1078.004 — Cloud Accounts
- **GRIMSEC evidence**: Successful login with harvested credentials in exploitation log

```json
{
  "technique_id": "T1078",
  "technique_name": "Valid Accounts",
  "tactic": "Persistence",
  "mitre_url": "https://attack.mitre.org/techniques/T1078/",
  "grimsec_scenarios": ["scenario-1", "scenario-3"],
  "redamon_modules": ["hydra", "custom-payload"]
}
```

### T1136 — Create Account
- **GRIMSEC triggers**: Demonstrated ability to create persistence via account creation
- **Sub-techniques**:
  - T1136.001 — Local Account
  - T1136.003 — Cloud Account
- **GRIMSEC note**: Test capability only — do NOT create actual accounts in test environment

```json
{
  "technique_id": "T1136",
  "technique_name": "Create Account",
  "tactic": "Persistence",
  "mitre_url": "https://attack.mitre.org/techniques/T1136/",
  "grimsec_scenarios": ["scenario-4"],
  "redamon_modules": ["container-escape", "custom-payload"]
}
```

---

## Tactic 4: Privilege Escalation

**Definition**: Techniques to gain higher-level permissions on a system or network.

### T1068 — Exploitation for Privilege Escalation
- **GRIMSEC triggers**: CVE exploitation leading to elevated privileges, Linux kernel exploits
- **GRIMSEC evidence**: `whoami` output showing root/admin after exploitation

```json
{
  "technique_id": "T1068",
  "technique_name": "Exploitation for Privilege Escalation",
  "tactic": "Privilege Escalation",
  "mitre_url": "https://attack.mitre.org/techniques/T1068/",
  "grimsec_scenarios": ["scenario-2", "scenario-4"],
  "redamon_modules": ["metasploit", "container-escape"]
}
```

### T1611 — Escape to Host
- **GRIMSEC triggers**: Container escape via Docker socket, privileged flag, CAP_SYS_ADMIN
- **GRIMSEC evidence**: Host filesystem access from within container context

```json
{
  "technique_id": "T1611",
  "technique_name": "Escape to Host",
  "tactic": "Privilege Escalation",
  "mitre_url": "https://attack.mitre.org/techniques/T1611/",
  "grimsec_scenarios": ["scenario-4"],
  "redamon_modules": ["container-escape"]
}
```

---

## Tactic 5: Credential Access

**Definition**: Techniques to steal account names, credentials, and other authentication material.

### T1552 — Unsecured Credentials
- **GRIMSEC triggers**: Hardcoded secrets in code/env files, plaintext credentials in config
- **Sub-techniques**:
  - T1552.001 — Credentials In Files
  - T1552.004 — Private Keys
  - T1552.007 — Container API
- **GRIMSEC evidence**: Secrets found by JS recon engine or static analysis

```json
{
  "technique_id": "T1552",
  "technique_name": "Unsecured Credentials",
  "tactic": "Credential Access",
  "mitre_url": "https://attack.mitre.org/techniques/T1552/",
  "grimsec_scenarios": ["scenario-1", "scenario-6"],
  "redamon_modules": ["js-recon", "custom-payload"]
}
```

### T1539 — Steal Web Session Cookie
- **GRIMSEC triggers**: JWT forgery, XSS-based cookie theft, WebSocket session hijacking
- **GRIMSEC evidence**: Forged/stolen session token used to access authenticated endpoints

```json
{
  "technique_id": "T1539",
  "technique_name": "Steal Web Session Cookie",
  "tactic": "Credential Access",
  "mitre_url": "https://attack.mitre.org/techniques/T1539/",
  "grimsec_scenarios": ["scenario-1", "scenario-7"],
  "redamon_modules": ["custom-payload"]
}
```

---

## Tactic 6: Lateral Movement

**Definition**: Techniques to move through the environment to reach high-value targets.

### T1021 — Remote Services
- **GRIMSEC triggers**: SSH, RDP, or API access to internal services post-compromise
- **Sub-techniques**:
  - T1021.001 — Remote Desktop Protocol
  - T1021.002 — SMB/Windows Admin Shares
  - T1021.004 — SSH
  - T1021.007 — Cloud Services
- **GRIMSEC evidence**: Successful connection to internal services from compromised host

```json
{
  "technique_id": "T1021",
  "technique_name": "Remote Services",
  "tactic": "Lateral Movement",
  "mitre_url": "https://attack.mitre.org/techniques/T1021/",
  "grimsec_scenarios": ["scenario-4"],
  "redamon_modules": ["post-exploit"]
}
```

### T1210 — Exploitation of Remote Services
- **GRIMSEC triggers**: SSRF reaching internal services, exploiting internal APIs post-SSRF
- **GRIMSEC evidence**: Internal service response captured via SSRF chain

```json
{
  "technique_id": "T1210",
  "technique_name": "Exploitation of Remote Services",
  "tactic": "Lateral Movement",
  "mitre_url": "https://attack.mitre.org/techniques/T1210/",
  "grimsec_scenarios": ["scenario-6"],
  "redamon_modules": ["custom-payload"]
}
```

---

## Tactic 7: Collection

**Definition**: Techniques to gather data of interest from the target environment.

### T1005 — Data from Local System
- **GRIMSEC triggers**: File system access post-compromise, path traversal exploitation
- **GRIMSEC note**: Capture metadata (file names, directory listing) only — do NOT read file contents containing real user data

```json
{
  "technique_id": "T1005",
  "technique_name": "Data from Local System",
  "tactic": "Collection",
  "mitre_url": "https://attack.mitre.org/techniques/T1005/",
  "grimsec_scenarios": ["scenario-2", "scenario-4"],
  "redamon_modules": ["post-exploit", "sqlmap"]
}
```

### T1213 — Data from Information Repositories
- **GRIMSEC triggers**: Database enumeration, S3 bucket access, internal wiki access
- **Sub-techniques**:
  - T1213.002 — Sharepoint
  - T1213.003 — Code Repositories
- **GRIMSEC evidence**: Database schema extraction, bucket listing (not file contents)

```json
{
  "technique_id": "T1213",
  "technique_name": "Data from Information Repositories",
  "tactic": "Collection",
  "mitre_url": "https://attack.mitre.org/techniques/T1213/",
  "grimsec_scenarios": ["scenario-1", "scenario-7"],
  "redamon_modules": ["sqlmap", "custom-payload", "post-exploit"]
}
```

---

## Tactic 8: Exfiltration

**Definition**: Techniques to steal data from the target network.

### T1048 — Exfiltration Over Alternative Protocol
- **GRIMSEC triggers**: Data exfiltration via DNS, ICMP, or non-standard protocols
- **Sub-techniques**:
  - T1048.001 — Exfiltration Over Symmetric Encrypted Non-C2 Protocol
  - T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol
- **GRIMSEC note**: Demonstrate the *capability* of exfiltration only — use a controlled GRIMSEC-lab endpoint. Never send real user data.

```json
{
  "technique_id": "T1048",
  "technique_name": "Exfiltration Over Alternative Protocol",
  "tactic": "Exfiltration",
  "mitre_url": "https://attack.mitre.org/techniques/T1048/",
  "grimsec_scenarios": ["scenario-3"],
  "redamon_modules": ["custom-payload"]
}
```

---

## ATT&CK Coverage Gap Analysis

### Full Tactic Inventory

| Tactic | ID | Tested in GRIMSEC Scenarios | Notes |
|--------|----|-----------------------------|-------|
| Reconnaissance | TA0043 | Phase 2 (automated) | Nuclei + RedAmon recon |
| Resource Development | TA0042 | ❌ Not tested | Requires separate infrastructure |
| Initial Access | TA0001 | ✅ Scenarios 1-6 | Core GRIMSEC coverage |
| Execution | TA0002 | ✅ Scenarios 2, 4, 7 | Via RCE and exploitation |
| Persistence | TA0003 | Partial — Scenarios 1, 3 | Capability demo only |
| Privilege Escalation | TA0004 | ✅ Scenarios 2, 4 | Container escape + SQLi |
| Defense Evasion | TA0005 | ❌ Not tested | Out of scope for default simulation |
| Credential Access | TA0006 | ✅ Scenarios 1, 6, 7 | JWT, hardcoded, SSRF |
| Discovery | TA0007 | ✅ Phase 2 | Automated recon covers this |
| Lateral Movement | TA0008 | ✅ Scenarios 4, 6 | Post-exploit assessment |
| Collection | TA0009 | ✅ Scenarios 1, 2, 7 | Metadata-only |
| Command and Control | TA0011 | Partial | Not a primary GRIMSEC focus |
| Exfiltration | TA0010 | Partial — Scenario 3 | Capability demo to lab endpoint |
| Impact | TA0040 | ❌ Prohibited | DoS/destruction prohibited by RoE |

### Common Gaps to Report

When `parse-results.py` identifies untested tactics, include in the simulation report:

> "The following ATT&CK tactics were not tested in this engagement and represent unknown risk: [list]. A follow-up engagement focused on [specific tactic] is recommended to provide complete coverage."

---

## Building the ATT&CK Heat Map

The `parse-results.py` script generates heat map data in this format:

```json
{
  "heat_map_data": {
    "Initial Access": [
      {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "fired": true, "count": 3}
    ],
    "Credential Access": [
      {"technique_id": "T1552", "technique_name": "Unsecured Credentials", "fired": true, "count": 1},
      {"technique_id": "T1539", "technique_name": "Steal Web Session Cookie", "fired": true, "count": 1}
    ],
    "Lateral Movement": [],
    ...
  }
}
```

This data feeds directly into the GRIMSEC dashboard ATT&CK heat map visualization and into the `simulation-report.md` executive report section.

### ATT&CK Navigator Layer

To generate an ATT&CK Navigator compatible layer from `attack-mapping.json`:

```bash
./redamon.sh report \
  --mode navigator-layer \
  --input adversary-simulation/attack-mapping.json \
  --output adversary-simulation/navigator-layer.json
```

The Navigator layer can be imported at https://mitre-attack.github.io/attack-navigator/ to produce a visual heat map for executive presentations.
