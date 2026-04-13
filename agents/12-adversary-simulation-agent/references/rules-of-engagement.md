# Rules of Engagement Reference

**GRIMSEC Agent 12 — Adversary Simulation Agent**

This reference covers all aspects of defining, documenting, and enforcing Rules of Engagement (RoE) for authorized adversary simulations. Load this reference at Phase 1 of the simulation pipeline.

---

## What is a Rules of Engagement Document?

A Rules of Engagement document is the **legal and operational contract** between the testing team and the system owner. It defines:

- What systems may be tested (scope)
- What actions are permitted (allowed techniques)
- What is strictly prohibited (exclusions and constraints)
- Who authorized the testing (legal chain of authority)
- What happens if something goes wrong (emergency procedures)

**No simulation should begin without a signed, documented RoE.**

---

## Authorized Security Testing Agreement Template

The following sections must appear in a signed authorization agreement before any active testing begins:

### Required Sections

**1. Parties and Authorization**
```
This Authorized Security Testing Agreement is entered into between:
  - Testing Entity: [GRIMSEC / your organization]
  - System Owner: [company name]
  - Authorized Signatory: [name, title]
  - Date: [ISO8601]
  - Engagement ID: [UUID]
```

**2. Scope Statement**
```
Authorized testing targets:
  - IP ranges: [CIDR notation, e.g., 10.0.1.0/24]
  - Domains: [e.g., staging.example.com, api-test.example.com]
  - Specific services: [e.g., API gateway, authentication service]
  - Ports: [e.g., 80, 443, 8080]

Authorized testing types:
  ☐ Network scanning and service enumeration
  ☐ Web application vulnerability scanning
  ☐ Exploitation of identified vulnerabilities
  ☐ Credential testing (brute force)
  ☐ Post-exploitation assessment (lateral movement, privesc)
  ☐ Social engineering — ONLY if explicitly checked
```

**3. Exclusions**
```
The following are EXPLICITLY OUT OF SCOPE:
  - Production databases containing live user data
  - Payment processing systems
  - Systems with IP addresses: [list]
  - Domains: [list]
  - All systems not explicitly listed in scope

The following actions are PROHIBITED:
  ☑ Denial of service attacks of any type
  ☑ Destruction or modification of production data
  ☑ Exfiltration of actual user data (demonstrate access capability only)
  ☑ Social engineering of employees (unless explicitly authorized above)
  ☑ Physical security testing
  ☑ Testing outside the authorized time window
```

**4. Time Window**
```
Authorized testing window:
  Start: [ISO8601 datetime with timezone]
  End:   [ISO8601 datetime with timezone]
  
After-hours contact for urgent issues: [phone]
Extension process: Written email to [contact] at least 24h in advance
```

**5. Signatures**
```
System Owner Authorized Signatory: _________________ Date: _________
Testing Team Lead:                 _________________ Date: _________
Legal Review:                      _________________ Date: _________
```

---

## Scope Definition Patterns

### IP Range Patterns

```
# Single host
10.0.0.1

# Subnet
10.0.1.0/24        # 256 addresses
192.168.100.0/28   # 16 addresses

# Range (non-CIDR)
10.0.0.1 - 10.0.0.50

# Named environment
staging-cluster: 10.0.1.0/24
test-api: 10.0.2.5
```

### Domain Patterns

```
# Exact domain (and all ports)
staging.example.com

# Wildcard subdomain (all subs of staging)
*.staging.example.com

# Specific path
api.example.com/v2/*

# Explicit out-of-scope exceptions within a wildcard
INCLUDE: *.staging.example.com
EXCLUDE: payments.staging.example.com  # still out of scope
```

### Service-Level Scoping

```yaml
in_scope_services:
  - name: "Authentication API"
    host: auth.staging.example.com
    ports: [443]
    endpoints: ["/v1/login", "/v1/register", "/v1/token"]
  
  - name: "Admin Dashboard"
    host: admin.staging.example.com
    ports: [443]
    endpoints: ["/*"]

out_of_scope_services:
  - name: "Production database"
    host: prod-db-01.internal
    reason: "Live user data — no testing permitted"
  
  - name: "Payment processor"
    host: payments.example.com
    reason: "PCI-DSS compliance — requires separate engagement"
```

---

## Exclusions Checklist

Before finalizing scope, verify each item:

### Production Data
- [ ] All production databases are explicitly excluded by hostname and IP
- [ ] Production read replicas are excluded (they still contain real data)
- [ ] Backup storage (S3 buckets with backup/ prefix, etc.) is excluded
- [ ] Log aggregation systems are excluded

### User Data
- [ ] Endpoints that return PII (names, emails, SSNs) are excluded from data extraction
- [ ] "Demonstrate access capability only" — capture metadata, not rows
- [ ] OAuth tokens and session tokens belonging to real users are excluded
- [ ] GDPR/CCPA-protected data stores are excluded

### Availability Impact
- [ ] No rate-limiting of production endpoints (use test/staging only)
- [ ] No volumetric attacks even against in-scope targets
- [ ] No resource exhaustion (memory/CPU) attacks
- [ ] No connection flooding
- [ ] Database queries must use LIMIT clauses (never unbounded queries)

### Third-Party Systems
- [ ] Cloud provider infrastructure (AWS, GCP, Azure shared infrastructure) is excluded
- [ ] CDN providers are excluded unless explicitly authorized by the CDN vendor
- [ ] SaaS integrations (Stripe, Salesforce, etc.) are excluded
- [ ] DNS providers are excluded

### Social Engineering
- [ ] Phishing employees is excluded unless explicitly authorized
- [ ] Vishing (phone-based) attacks are excluded
- [ ] Physical access attempts are excluded

---

## Emergency Stop Procedures

### Trigger Conditions

Stop ALL testing activity immediately if:

1. **Unintended production system access** — any sign that out-of-scope systems are being touched
2. **Real user data becomes visible** — PII, payment data, health records in any output
3. **Service degradation** — any monitored service shows elevated error rates or latency
4. **Security team alert** — the client's security team raises an incident
5. **Scope breach** — exploitation chain reaches systems not in the RoE
6. **Tool behavior anomaly** — a tool behaves unexpectedly or exceeds intended scope

### Emergency Stop Steps

```bash
# Step 1: Immediate RedAmon shutdown
./redamon.sh down

# Step 2: Kill all sub-process tools
pkill -f sqlmap
pkill -f hydra
pkill -f nuclei
pkill -f msfconsole

# Step 3: Notify emergency contact
# Call: [phone from roe.json contacts.emergency_stop]
# Email: [security_lead from roe.json contacts.security_lead]
# Message template:
#   "Adversary simulation Engagement ID [ID] has been stopped as of [TIME].
#   Reason: [REASON]. All testing activity has ceased. 
#   Preliminary findings indicate [BRIEF SUMMARY].
#   Full incident log: adversary-simulation/exploitation-log.json"

# Step 4: Preserve all evidence
cp -r adversary-simulation/ adversary-simulation-backup-$(date +%Y%m%d-%H%M%S)/
tar czf evidence-$(date +%Y%m%d-%H%M%S).tar.gz adversary-simulation/

# Step 5: Document the stop event
cat >> adversary-simulation/exploitation-log.json << EOF
EMERGENCY STOP EVENT: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Reason: [FILL IN]
Last action: [FILL IN]
EOF
```

### What NOT to Do During Emergency Stop
- Do NOT delete evidence or logs
- Do NOT attempt to "undo" changes — document and report
- Do NOT continue testing in a different area "while things cool down"
- Do NOT wait to notify — immediate notification is required

---

## Evidence Preservation Requirements

### What Must Be Preserved

All of the following must be retained for 90 days minimum:

| Evidence Type | Location | Format |
|---------------|----------|--------|
| RoE document | `adversary-simulation/roe.json` | JSON |
| Exploitation log | `adversary-simulation/exploitation-log.json` | JSON (timestamped) |
| Nuclei scan results | `recon/nuclei-results.json` | JSON |
| Tool output logs | `adversary-simulation/tool-logs/` | Raw text |
| Neo4j graph export | `adversary-simulation/graph-export.graphml` | GraphML |
| Screenshots/PoC | `adversary-simulation/evidence/` | PNG/JPEG |
| Communication log | `adversary-simulation/communications.md` | Markdown |

### Evidence Chain of Custody

For each piece of evidence:
1. Record when it was captured (ISO8601 timestamp)
2. Record who captured it (team member name)
3. Record the system it was captured from
4. Generate SHA-256 hash: `sha256sum <file> >> adversary-simulation/evidence-hashes.txt`
5. Do NOT modify evidence after capture — create new files for analysis

---

## Communication Plan

### Pre-Engagement
- [ ] RoE distributed to all stakeholders 48h before start
- [ ] Security team lead briefed on start time and expected actions
- [ ] IT operations notified (to prevent false-positive incident response)
- [ ] Change management ticket opened (if required by client process)

### During Engagement
- [ ] Daily status email to security_lead at end of each testing day
- [ ] Immediate notification for any unexpected findings
- [ ] Immediate stop and notification for any out-of-scope touches

### Post-Engagement
- [ ] Findings briefing within 24h of simulation completion
- [ ] Draft report delivered within 5 business days
- [ ] Final report delivered within 10 business days
- [ ] Remediation walkthrough session scheduled

### Communication Templates

**Daily Status Email**:
```
Subject: [GRIMSEC] Adversary Simulation Day N Status — Engagement [ID]

Today's activity:
- Phase completed: [Phase N]
- Targets tested: [list]
- Critical findings: [count and brief description]
- No safety constraints were triggered.

Next session: [date/time]
Questions: [testing team contact]
```

**Critical Finding Notification**:
```
Subject: [GRIMSEC] CRITICAL FINDING — Engagement [ID] — Immediate Attention Required

Finding: [1-line description]
Severity: CRITICAL
Target: [target]
Impact: [brief impact description]

We have paused testing pending your acknowledgment. 
Please confirm receipt within 2 hours.
```

---

## Legal Considerations

### Computer Fraud and Abuse Act (CFAA) — United States

The CFAA (18 U.S.C. § 1030) criminalizes unauthorized access to computer systems. To ensure testing is authorized:

1. **Written authorization is mandatory** — verbal agreement is not sufficient
2. The authorization must come from the **system owner or their authorized representative** (not just IT staff)
3. Authorization must explicitly cover the **type of activities** performed (scanning vs. exploitation vs. data access are distinct)
4. Third-party systems in the scope require **separate authorization** from those third parties
5. Cloud provider accounts: authorization from the account holder does not grant permission to test the provider's shared infrastructure

### UK Computer Misuse Act / EU Cybercrime Convention

Similar provisions apply in international contexts. Obtain local legal review for cross-border engagements.

### Documentation Minimum Requirements

The following must be documented before any testing begins:

- [ ] Signed authorization letter on company letterhead
- [ ] Explicit list of authorized test targets (not just "our systems")
- [ ] Statement of authorized test methods
- [ ] Authorized tester identities (name, organization)
- [ ] Testing time window
- [ ] Emergency contact and stop procedure acknowledgment
- [ ] Signatory's authority to authorize testing (e.g., CTO, CISO, system owner)

### Safe Harbor Language

Include in the authorization document:

> "[System Owner] grants [Testing Entity] authorization to perform security testing activities as defined in this document. This authorization constitutes permission as required under applicable computer crime laws including 18 U.S.C. § 1030 (CFAA). [Testing Entity] shall not be held liable for security vulnerabilities discovered during the authorized testing period, provided testing activities conform to the scope and constraints defined herein."

---

## roe.json Schema Reference

```json
{
  "engagement_id": "UUID",
  "authorized_by": "Full Name, Title, Organization",
  "authorization_date": "ISO8601",
  "authorization_document_ref": "filepath or URL to signed document",
  
  "scope": {
    "targets": ["IP", "CIDR", "domain"],
    "in_scope_ports": [80, 443],
    "in_scope_services": ["service description"],
    "in_scope_endpoints": ["/path/*"],
    "out_of_scope": ["description of excluded systems"],
    "exclusions": ["specific hostname or IP + reason"]
  },
  
  "authorized_techniques": [
    "reconnaissance",
    "vulnerability_scanning",
    "exploitation",
    "post_exploitation"
  ],
  
  "time_window": {
    "start": "ISO8601",
    "end": "ISO8601",
    "timezone": "UTC"
  },
  
  "contacts": {
    "security_lead": "email",
    "system_owner": "email",
    "emergency_stop": "phone",
    "testing_team_lead": "email"
  },
  
  "constraints": {
    "no_dos": true,
    "no_data_exfil": true,
    "no_production_writes": true,
    "human_approval_required": true,
    "max_request_rate": 50,
    "stop_on_real_data": true
  },
  
  "legal": {
    "jurisdiction": "US",
    "authorization_act": "CFAA 18 U.S.C. § 1030",
    "signed_document_hash": "SHA256"
  }
}
```
