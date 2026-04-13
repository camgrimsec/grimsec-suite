# STRIDE Threat Modeling Reference

## Overview

STRIDE is a threat classification framework developed at Microsoft. Use it to systematically identify threats at each trust boundary in an application.

## Categories

### S — Spoofing Identity
**Question:** Can an attacker pretend to be another user or system?

Indicators to check:
- Authentication mechanisms (JWT, OAuth, session cookies, API keys)
- Input validation on user identity claims
- Certificate/token verification
- Default credentials in configuration

Common threats:
- Forged JWT tokens with manipulated claims
- Session hijacking via XSS or CSRF
- API key reuse across environments
- Credential stuffing against authentication endpoints

### T — Tampering with Data
**Question:** Can an attacker modify data they shouldn't?

Indicators to check:
- Input validation at all entry points
- Database access controls and parameterized queries
- File upload validation (type, size, content)
- Message integrity verification (HMAC, signatures)
- Mass assignment / object injection vulnerabilities

Common threats:
- SQL injection through unvalidated input
- File upload path traversal
- Direct object reference manipulation (IDOR)
- Insecure deserialization

### R — Repudiation
**Question:** Can an attacker deny performing an action?

Indicators to check:
- Audit logging implementation
- Log integrity protection
- Transaction logging for sensitive operations
- Non-repudiation mechanisms for critical actions

Common threats:
- Missing audit trails for admin actions
- Log injection / log tampering
- Unsigned transactions

### I — Information Disclosure
**Question:** Can sensitive data leak to unauthorized parties?

Indicators to check:
- Error handling (stack traces, debug info in responses)
- API response filtering (excessive data in responses)
- Logging of sensitive data (passwords, tokens, PII)
- Database query exposure through GraphQL introspection
- Directory listing enabled
- Source map files exposed in production

Common threats:
- Verbose error messages exposing internal paths/queries
- API endpoints returning more data than needed
- Secrets in environment files committed to git
- PII in application logs

### D — Denial of Service
**Question:** Can an attacker exhaust resources or crash the service?

Indicators to check:
- Rate limiting on endpoints
- Input size validation (request body, file uploads)
- Resource limits (memory, CPU, connections)
- Regex patterns (ReDoS)
- Recursive/nested query depth limits (GraphQL)
- Queue/job processing limits

Common threats:
- Unbounded file uploads consuming disk
- Complex GraphQL queries causing N+1 database hits
- ReDoS via crafted regex input
- Missing rate limits on authentication endpoints

### E — Elevation of Privilege
**Question:** Can a user gain higher access than intended?

Indicators to check:
- Role-based access control (RBAC) implementation
- Authorization checks on every privileged endpoint
- Object-level authorization (can user A access user B's data?)
- Function-level authorization (can a regular user access admin APIs?)
- Path traversal in file access

Common threats:
- Missing authorization middleware on admin endpoints
- IDOR allowing access to other users' resources
- Privilege escalation through role manipulation
- Path traversal to access restricted files

## Application Process

For each data flow that crosses a trust boundary:

1. **Identify the trust boundary** (e.g., external → API, API → database, service → service)
2. **Walk through each STRIDE category** — ask the corresponding question
3. **Document existing controls** — what mitigations are already in place?
4. **Assess severity** — considering impact and exploitability
5. **Note gaps** — where controls are missing or insufficient

## Severity Assessment

| Severity | Criteria |
|----------|----------|
| Critical | Directly exploitable, no authentication required, high impact (data breach, RCE) |
| High     | Exploitable with low-privilege access, significant impact |
| Medium   | Requires specific conditions or chained vulnerabilities |
| Low      | Theoretical risk with significant barriers to exploitation |

## Output Format

For each identified threat:

```
Threat ID:        STRIDE-{category_letter}-{number}
Category:         {Spoofing|Tampering|Repudiation|InfoDisclosure|DoS|ElevationOfPriv}
Data Flow:        {Which data flow is affected}
Trust Boundary:   {Which boundary is crossed}
Threat:           {Description of the specific threat}
Severity:         {Critical|High|Medium|Low}
Existing Controls: {What mitigations exist}
Gaps:             {What's missing}
Recommendation:   {What should be done}
```
