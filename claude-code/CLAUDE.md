# GRIMSEC DevSecOps Agent Suite

12-agent security analysis platform for DevSecOps workflows. All agents are invokable as slash commands or by describing the task in natural language.

## Quick Command Reference

| Command | Agent | What It Does |
|---------|-------|-------------|
| `/repo-analyzer` | Repo Analyzer | Full 6-stage DevSecOps scan: threat model + SAST/SCA/secrets/IaC + Real Risk Scores |
| `/cicd-auditor` | CI/CD Auditor | GitHub Actions security: supply chain, expression injection, dangerous triggers |
| `/vuln-enricher` | Vuln Enricher | Enrich CVEs with EPSS, CISA KEV, MITRE ATT&CK, fix availability |
| `/doc-intel` | Doc Intel | Build security context profile from repo documentation |
| `/threat-monitor` | Threat Monitor | Check dependency exposure against CISA KEV + OSV threat feeds |
| `/executive-reporter` | Executive Reporter | Generate board/CISO-ready reports with financial risk quantification |
| `/dast-scanner` | DAST Scanner | Runtime testing with Nuclei + OWASP ZAP |
| `/exploit-validator` | Exploit Validator | Prove exploitability of RRS ≥ 7 findings with PoC generation |
| `/code-understanding` | Code Understanding | Map attack surface, trace data flows, hunt variants |
| `/iac-policy` | IaC Policy | Scan IaC files with Checkov + OPA, map to CIS/NIST/SOC2 |
| `/forensics` | OSS Forensics | Investigate supply chain incidents, suspicious commits, backdoors |
| `/adversary-sim` | Adversary Sim | Controlled red team simulation with MITRE ATT&CK mapping |

## Output Convention

All analysis artifacts → `./grimsec-output/` relative to project root.

```
grimsec-output/
├── {repo-name}/             # Per-repo: inventory.json, app-context.json, scan-results/, assessment-report.md
├── threat-intel/            # Threat monitor reports
├── executive/               # Executive reports
├── exploit-validation/      # PoC files and validation reports
├── code-understanding/      # Attack surface maps, flow traces, variant lists
├── iac-policy/              # Checkov results, OPA violations, SBOM, compliance map
├── forensics/               # Evidence, IOCs, timeline, hypotheses, forensic report
└── adversary-simulation/    # RoE, recon, exploitation log, ATT&CK mapping, simulation report
```

## Standard Pipeline

```
/repo-analyzer → /vuln-enricher → /exploit-validator → /executive-reporter
      ↓               ↓
/cicd-auditor   /threat-monitor
      ↓
/doc-intel
```

## Agent Details

Read `.claude/skills/<agent-name>/SKILL.md` for complete pipeline documentation.

- `.claude/skills/repo-analyzer/SKILL.md` — 6-stage scan pipeline, STRIDE threat model, Real Risk Scoring
- `.claude/skills/cicd-auditor/SKILL.md` — 6-category workflow audit, supply chain checks, fix YAML snippets
- `.claude/skills/vuln-enricher/SKILL.md` — NVD/OSV/EPSS/CISA KEV APIs, composite priority scoring
- `.claude/skills/doc-intel/SKILL.md` — 8-phase documentation analysis, security control extraction
- `.claude/skills/threat-monitor/SKILL.md` — threat feed queries, exposure classification, scheduling
- `.claude/skills/executive-reporter/SKILL.md` — financial models, compliance mapping, MTTR benchmarks
- `.claude/skills/dast-scanner/SKILL.md` — Nuclei + ZAP setup, scan modes, finding correlation
- `.claude/skills/exploit-validator/SKILL.md` — 7-stage validation pipeline, PoC generation, safety rules
- `.claude/skills/code-understanding/SKILL.md` — --map/--trace/--hunt/--teach modes
- `.claude/skills/iac-policy/SKILL.md` — Checkov setup, OPA Rego policies, SBOM generation
- `.claude/skills/forensics/SKILL.md` — GitHub API evidence, IOC patterns, timeline construction
- `.claude/skills/adversary-sim/SKILL.md` — RoE template, RedAmon integration, ATT&CK mapping

## Key Rules

- Active scans (DAST, adversary-sim) require explicit user authorization before running
- Secrets found in repos should be treated as compromised and rotation recommended
- NVD API: rate-limited to 5 req/30s without API key — space requests at 6.5s intervals
- All PoC code must include safety header and be labeled FOR SECURITY ASSESSMENT ONLY
- Never assert a vulnerability finding without evidence from actual code or documentation
