# GRIMSEC Generic Format

12-agent DevSecOps security analysis suite — standalone prompts and system prompts for any AI coding tool.

## Choose Your Tool

| Tool | What to use |
|---|---|
| **Codex CLI** / OpenAI tools | Copy `AGENTS.md` to your project root |
| **GitHub Copilot Chat** | Copy `.github/copilot-instructions.md` to your project |
| **Windsurf, Aider, Continue, Cline** | Copy the individual prompt from `prompts/` for the agent you want |
| **ChatGPT, Claude.ai, Gemini (chat)** | Paste a prompt from `prompts/` or the full suite from `system-prompts/` |
| **Any AI tool — all 12 agents** | Paste `system-prompts/full-suite.md` as your system prompt |

## File Reference

### AGENTS.md
Full agent reference following OpenAI's `AGENTS.md` convention. Compatible with Codex CLI and any tool that reads AGENTS.md. Contains all 12 agents with trigger phrases, descriptions, and references to individual prompt files.

### .github/copilot-instructions.md
Concise version for GitHub Copilot Chat. Under 300 lines to fit within Copilot's context window. Contains all 12 agents in compressed form with key technical details.

### prompts/ — Individual Standalone Prompts

Each file is a complete, self-contained prompt you can paste into any AI tool. No tool-specific references. Works with ChatGPT, Claude, Gemini, Mistral, or any LLM.

| File | Agent | Activate When User Wants To... |
|------|-------|-------------------------------|
| `01-repo-analyzer.md` | Repo Analyzer | Analyze a repo for vulnerabilities, run DevSecOps assessment |
| `02-cicd-auditor.md` | CI/CD Auditor | Audit GitHub Actions, find supply chain risks |
| `03-vuln-enricher.md` | Vuln Enricher | Look up CVE details, get EPSS/KEV/ATT&CK data |
| `04-doc-intel.md` | Doc Intel | Analyze repo documentation, validate scanner findings |
| `05-threat-monitor.md` | Threat Monitor | Monitor for new CVEs, check dependency exposure |
| `06-executive-reporter.md` | Executive Reporter | Generate board/CISO reports, quantify security ROI |
| `07-dast-scanner.md` | DAST Scanner | Dynamic testing with Nuclei + ZAP |
| `08-exploit-validator.md` | Exploit Validator | Prove exploitability, generate safe PoC code |
| `09-code-understanding.md` | Code Understanding | Map attack surfaces, trace data flows, hunt variants |
| `10-iac-policy.md` | IaC Policy | Scan Terraform/K8s/Docker, check CIS compliance |
| `11-forensics.md` | OSS Forensics | Investigate supply chain incidents, analyze suspicious repos |
| `12-adversary-sim.md` | Adversary Sim | Run controlled red team simulation (requires authorization) |

### system-prompts/full-suite.md

Complete system prompt with all 12 agents. Paste as a system prompt to give any AI tool the full GRIMSEC capability.

Ideal for:
- Setting up a persistent security-focused AI chat session
- Configuring a custom GPT or AI assistant
- Using with Windsurf, Aider, or Continue via system prompt config

## Usage Examples

### ChatGPT / Claude.ai / Gemini

1. Open a new chat
2. Paste the contents of `system-prompts/full-suite.md` as a system prompt or first message
3. Then say: "Analyze https://github.com/org/repo for security vulnerabilities"

Or for a single agent:
1. Paste `prompts/01-repo-analyzer.md` as the system prompt
2. Provide the repo URL

### Codex CLI

1. Copy `AGENTS.md` to your project root
2. Codex CLI reads it automatically
3. Ask: `codex "analyze this repo for security issues"`

### GitHub Copilot Chat

1. Copy `.github/copilot-instructions.md` to your project
2. Copilot Chat reads it automatically when opened in your project
3. Ask: `@workspace analyze the GitHub Actions workflows for security issues`

### Windsurf / Aider / Continue

1. Configure the tool to use `system-prompts/full-suite.md` as the system prompt
2. Start chatting normally

For Aider:
```bash
aider --system-prompt system-prompts/full-suite.md
```

For Continue, add to `config.json`:
```json
{
  "systemMessage": "... contents of full-suite.md ..."
}
```

## What the Agents Do

| # | Agent | Key Capability |
|---|-------|---------------|
| 1 | Repo Analyzer | 6-stage pipeline: STRIDE threat model + SAST/SCA/secrets/IaC + Real Risk Scores (filters 80-97% scanner noise) |
| 2 | CI/CD Auditor | 6-category GitHub Actions audit: supply chain, expression injection, permissions, dangerous triggers |
| 3 | Vuln Enricher | CVE intelligence: CVSS + EPSS + CISA KEV + ATT&CK + composite priority scoring |
| 4 | Doc Intel | Documentation analysis: builds security context to validate/adjust scanner findings |
| 5 | Threat Monitor | Continuous exposure monitoring against CISA KEV + OSV feeds |
| 6 | Executive Reporter | Business impact: financial risk quantification, compliance mapping, MTTR benchmarks |
| 7 | DAST Scanner | Runtime testing: Nuclei + ZAP, OWASP Top 10 detection |
| 8 | Exploit Validator | 7-stage PoC generation + exploitability classification |
| 9 | Code Understanding | Attack surface mapping, data flow tracing, variant hunting |
| 10 | IaC Policy | Checkov + OPA: CIS/NIST/SOC2/HIPAA/PCI-DSS compliance + SBOM |
| 11 | OSS Forensics | Supply chain investigation: GitHub API + git history + registry + Wayback Machine |
| 12 | Adversary Sim | Controlled red team: RoE + recon + exploitation + ATT&CK mapping |

## Important Notes

- **Active scan authorization required.** Agents 7 (DAST) and 12 (Adversary Sim) run active security tests. Always confirm authorization before pointing at any system.
- **All PoC code is for security assessment only.** Agent 8 generates proof-of-concept code — it should only be used against systems you have permission to test.
- **NVD rate limits.** Agent 3 queries NVD at 5 requests/30 seconds without an API key. Register for a free key at https://nvd.nist.gov/developers for higher limits.
- **All output goes to `./grimsec-output/`** relative to your project root.
