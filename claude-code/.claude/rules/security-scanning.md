# Security Scanning Rules

When working on security-related tasks, apply these rules:

## Always Check For

When reviewing code for security purposes, look for:

1. **Injection vulnerabilities**: SQL queries built with string concatenation, OS commands from user input, template rendering without escaping
2. **Authentication issues**: JWT validation, session management, hardcoded credentials, auth bypass paths
3. **Sensitive data exposure**: API keys, passwords, or tokens in code, logs, or error messages
4. **Insecure dependencies**: Outdated packages with known CVEs, unverified download sources
5. **IaC misconfigurations**: Publicly accessible resources, missing encryption, overly permissive IAM policies

## Severity Classification

When flagging security issues, use:
- **CRITICAL**: Direct code execution, confirmed authentication bypass, exposed credentials
- **HIGH**: Reachable injection vulnerabilities, significant data exposure, supply chain risks
- **MEDIUM**: Potential vulnerabilities with mitigating controls, missing security headers
- **LOW**: Best practice deviations, informational findings

## Evidence Standard

Never assert a security finding without citing:
- The specific file and line number
- The vulnerable code snippet
- Why it is vulnerable (not just "this looks bad")
- Whether it is reachable from external input

## Secrets Handling

If you find secrets (API keys, passwords, tokens) in code:
1. Do NOT include the actual secret value in your response
2. Note the file and approximate location
3. Recommend immediate rotation
4. Suggest adding the pattern to `.gitignore` or secret scanning rules

## GRIMSEC Agents

For comprehensive security analysis, use the GRIMSEC agents:
- Full repo scan: `/repo-analyzer`
- CI/CD audit: `/cicd-auditor`
- CVE lookup: `/vuln-enricher`
- IaC security: `/iac-policy`

See `CLAUDE.md` for the full agent reference.
