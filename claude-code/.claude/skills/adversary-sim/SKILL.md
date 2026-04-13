# Adversary Simulation Agent

Orchestrates controlled adversary simulation, converting static vulnerability findings into evidence-backed attack narratives with MITRE ATT&CK mapping.

Invoke with `/adversary-sim` or phrases like "run adversary simulation", "red team", "attack simulation", "kill chain".

## ⚠️ CRITICAL SAFETY CONSTRAINTS

- **NEVER** run against production systems without explicit written authorization (signed RoE)
- **NEVER** exfiltrate real user data
- **NEVER** perform denial-of-service attacks
- **NEVER** modify production data, configurations, databases, or infrastructure
- **Human approval required** before Phase 3 (Exploitation) — present plan and wait for explicit `APPROVE`
- **Emergency stop**: immediately terminate all simulation activity if unexpected impact occurs
- **Scope creep**: if recon discovers out-of-scope assets, log and halt

## When to Use

- Run a full adversary simulation or red team exercise
- Convert exploit-validation findings into proven attack narratives
- Map vulnerabilities to MITRE ATT&CK
- Produce executive-ready simulation report with kill-chain evidence
- Assess post-exploitation impact (lateral movement, privilege escalation, data access)

## Input Files

| File | Source |
|------|--------|
| `exploit-validation/validation-report.json` | `/exploit-validator` — filter to `status == "EXPLOITABLE"` |
| `code-understanding/context-map.json` | `/code-understanding` |
| `app-context.json` | `/repo-analyzer` |
| `doc-profile.json` | `/doc-intel` |

## Pipeline

```
Phase 1: Rules of Engagement    ← STOP: get user confirmation
Phase 2: Reconnaissance         ← Passive/active recon
Phase 3: Exploitation           ← STOP: get explicit APPROVE
Phase 4: Post-Exploitation      ← Impact assessment
Phase 5: MITRE ATT&CK Mapping
Phase 6: Report Generation
```

## Phase 1: Rules of Engagement

Generate and present `adversary-simulation/roe.json` before any testing:

```json
{
  "engagement_id": "<uuid>",
  "authorized_by": "<name, title>",
  "scope": {
    "targets": ["10.0.0.0/24", "staging.example.com"],
    "out_of_scope": ["production databases", "user PII", "payment systems"]
  },
  "time_window": {"start": "<ISO8601>", "end": "<ISO8601>", "timezone": "UTC"},
  "constraints": {"no_dos": true, "no_data_exfil": true, "no_production_writes": true}
}
```

STOP and present to user. Do NOT proceed until user confirms.

## Phase 2: Reconnaissance

```bash
nmap -sV -p 1-1000 <target> -oJ recon/ports.json
httpx -l recon/hosts.txt -tech-detect -json -o recon/http-hosts.json
nuclei -l recon/http-hosts.txt -t cves,misconfiguration,exposures -severity medium,high,critical -json-export recon/nuclei-results.json
```

## Phase 3: Exploitation (HUMAN APPROVAL REQUIRED)

**Pre-exploitation checklist:**
- [ ] `roe.json` signed and on file
- [ ] Current time within authorized window
- [ ] Target confirmed in-scope
- [ ] User has explicitly typed `APPROVE`

**Tool selection:**
| Vulnerability Class | Tool |
|----|----|
| CVE exploitation | Metasploit |
| Credential attacks | Hydra |
| SQL injection | SQLMap |
| SSRF | Manual request crafting |

## Phase 4: Post-Exploitation

**Lateral movement:** Can compromised service reach internal databases? Other microservices?

**Privilege escalation:** Can process escalate to root/admin? Container escape?

**Data access:** Enumerate accessible S3 buckets, databases, secret ARNs. **Record metadata only — do NOT read actual user data.**

**Persistence:** Could attacker drop a backdoor? (test capability only, do not install)

## Phase 5: MITRE ATT&CK Mapping

For each action, assign Tactic + Technique ID + Sub-technique + evidence pointer.

Build attack tree:
```
Initial Access (T1190) → Execution (T1059) → Persistence (T1078)
  → Privilege Escalation (T1611) → Collection (T1005) → Exfiltration (T1048)
```

## Phase 6: Report

`adversary-simulation/simulation-report.md` contains:
- Attack Narrative (plain English)
- Kill Chain (step-by-step with evidence)
- Impact Matrix (accessed, damaged, blast radius)
- MITRE ATT&CK Heat Map
- Static vs. Actual comparison (predicted risk vs. proven exploitation)
- Remediation Priority (fix the first link = break the whole chain)
- Time-to-Compromise metric

## Output Files

```
adversary-simulation/
├── roe.json
├── recon-results.json
├── exploitation-log.json
├── post-exploitation-findings.json
├── attack-mapping.json
└── simulation-report.md
```
