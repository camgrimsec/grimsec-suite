# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes |

GRIMSEC follows a rolling release model. Security fixes are applied to the latest version on the main branch.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a security vulnerability in GRIMSEC:

1. Open a [GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/creating-a-repository-security-advisory) in this repository (private by default)
2. Or email the maintainers directly via the contact information in the repository's GitHub profile

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

### What to Expect

- **Acknowledgement:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix timeline:** depends on severity — Critical issues are prioritized
- **Credit:** reporters are credited in the security advisory (unless they prefer anonymity)

---

## Scope

### In Scope

- Vulnerabilities in `grimsec.py` CLI
- Vulnerabilities in `scripts/` shell scripts
- Vulnerabilities in agent `scripts/` files
- Security issues with how GRIMSEC handles user-provided input (repo URLs, CVE IDs, etc.)
- Issues that could allow GRIMSEC to be weaponized beyond its intended authorized-use scope

### Out of Scope

- Vulnerabilities in upstream tools (Trivy, Semgrep, Nuclei, etc.) — report to those projects
- Findings from scanning GRIMSEC itself with security tools (unless they reveal real issues)
- Social engineering attacks

---

## Ethical Use Policy

GRIMSEC is a security testing tool built for authorized use only.

**Users are responsible for:**
- Only running GRIMSEC against systems they own or have explicit written permission to test
- Complying with all applicable laws and regulations in their jurisdiction
- Not using GRIMSEC to facilitate unauthorized access, data exfiltration, or system damage

The exploit validation (Agent 08) and adversary simulation (Agent 12) capabilities include built-in safeguards. Contributing code that weakens or removes these safeguards will not be accepted.

**If you discover that GRIMSEC is being used maliciously**, please report it via the vulnerability reporting process above.

---

## Security Design Principles

GRIMSEC itself is designed with these security principles:

1. **No credential storage** — GRIMSEC never stores API keys or credentials. All keys are passed as environment variables.
2. **No network calls without explicit user action** — the CLI only fetches data when a command is explicitly run.
3. **Output isolation** — all output is written to a local `grimsec-output/` directory, never uploaded anywhere.
4. **No hardcoded targets** — no internal hostnames, IP addresses, or repository names in any distributed file.
5. **Authorized-use safeguards** — agents 08 and 12 include explicit authorization warnings and safe-execution constraints.
