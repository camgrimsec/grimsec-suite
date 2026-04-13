# Rules of Engagement — Authorization Template

**GRIMSEC DevSecOps Suite — Agent 12: Adversary Simulation Agent**

---

<!-- 
INSTRUCTIONS FOR AGENT:
1. Populate all {{PLACEHOLDER}} fields with actual engagement details
2. Have the system owner and testing team lead sign before proceeding
3. Save the populated document as both:
   - A PDF/signed document for legal records
   - adversary-simulation/roe.json (structured version) for the simulation pipeline
4. Do NOT proceed past Phase 1 until this document is signed
-->

---

# Authorized Security Testing Agreement

**Engagement ID**: {{ENGAGEMENT_ID}}  
**Document Version**: 1.0  
**Date Issued**: {{ISSUE_DATE}}  

---

## Parties

**Testing Organization**:  
Name: {{TESTING_ORG_NAME}}  
Address: {{TESTING_ORG_ADDRESS}}  
Lead Tester: {{LEAD_TESTER_NAME}}, {{LEAD_TESTER_TITLE}}  
Contact: {{LEAD_TESTER_EMAIL}} | {{LEAD_TESTER_PHONE}}  

**System Owner / Client**:  
Company: {{CLIENT_COMPANY_NAME}}  
Address: {{CLIENT_ADDRESS}}  
Authorized Signatory: {{CLIENT_SIGNATORY_NAME}}, {{CLIENT_SIGNATORY_TITLE}}  
Contact: {{CLIENT_SIGNATORY_EMAIL}} | {{CLIENT_SIGNATORY_PHONE}}  

---

## Authorization Statement

{{CLIENT_COMPANY_NAME}} ("System Owner") hereby authorizes {{TESTING_ORG_NAME}} ("Testing Entity") to perform authorized security testing on the systems and services described in this document. This authorization constitutes permission as required under applicable computer crime laws, including but not limited to 18 U.S.C. § 1030 (Computer Fraud and Abuse Act).

Testing Entity shall conduct all activities in accordance with this agreement and shall not exceed the scope defined herein.

---

## Authorized Testing Window

**Start**: {{TESTING_WINDOW_START}} ({{TIMEZONE}})  
**End**: {{TESTING_WINDOW_END}} ({{TIMEZONE}})  

Extension procedure: Submit written request to {{CLIENT_SIGNATORY_EMAIL}} at least 24 hours before expiration. Extensions require written approval.

---

## Scope — Authorized Targets

### In-Scope IP Ranges and Hosts

```
{{IN_SCOPE_IP_RANGES}}
```

*Example format:*
```
# Staging cluster
10.0.1.0/24

# Test API server
192.168.100.5

# Staging domain and all subdomains
staging.example.com
*.staging.example.com
```

### In-Scope Services

| Service Name | Host | Ports | Notes |
|-------------|------|-------|-------|
| {{SERVICE_1_NAME}} | {{SERVICE_1_HOST}} | {{SERVICE_1_PORTS}} | {{SERVICE_1_NOTES}} |
| {{SERVICE_2_NAME}} | {{SERVICE_2_HOST}} | {{SERVICE_2_PORTS}} | {{SERVICE_2_NOTES}} |

### In-Scope Endpoints (if restricted)

```
{{IN_SCOPE_ENDPOINTS}}
```

Leave blank to authorize all endpoints on in-scope hosts.

---

## Scope — Exclusions (OUT OF SCOPE)

### Explicitly Excluded Systems

The following systems are **explicitly excluded** from testing. Contact must be halted immediately if any testing activity reaches these systems.

| System | Identifier | Reason |
|--------|-----------|--------|
| {{EXCLUDED_SYSTEM_1}} | {{EXCLUDED_ID_1}} | {{EXCLUDED_REASON_1}} |
| {{EXCLUDED_SYSTEM_2}} | {{EXCLUDED_ID_2}} | {{EXCLUDED_REASON_2}} |
| {{EXCLUDED_SYSTEM_3}} | {{EXCLUDED_ID_3}} | {{EXCLUDED_REASON_3}} |

*Examples:*
| Production database | prod-db-01.internal (10.0.0.10) | Live user data — PII/GDPR |
| Payment processor | payments.example.com | PCI-DSS scope — separate engagement required |
| Core network infrastructure | 10.0.0.1 | Critical availability risk |

### Prohibited Actions

The following actions are **strictly prohibited** regardless of scope:

- [ ] **Denial of service** — any attack that degrades availability, including accidental resource exhaustion
- [ ] **Data exfiltration** — reading, copying, or transmitting actual user data; demonstrate *capability* only
- [ ] **Production data modification** — writing to, updating, or deleting any production data or configuration
- [ ] **Social engineering** — phishing, vishing, or physical access attempts against employees
- [ ] **Third-party systems** — cloud provider infrastructure, SaaS platforms, CDN providers
- [ ] **Persistence installation** — leaving backdoors, scheduled tasks, or modified configurations after the engagement
- [ ] **Testing outside the authorized window** — no exceptions without signed written extension

---

## Authorized Testing Techniques

Place a checkmark next to each authorized technique:

- [ ] **Passive reconnaissance** — DNS lookup, WHOIS, search engine queries
- [ ] **Active reconnaissance** — port scanning, service enumeration, subdomain enumeration
- [ ] **Vulnerability scanning** — automated scanning with Nuclei, manual verification
- [ ] **Web application exploitation** — exploiting identified vulnerabilities in web applications
- [ ] **Credential testing** — testing found/guessed credentials against in-scope services
- [ ] **Exploitation** — executing exploits against confirmed vulnerabilities in in-scope systems
- [ ] **Post-exploitation** — lateral movement, privilege escalation assessment (read-only)
- [ ] **Social engineering** — ONLY if checked by authorized signatory (default: NOT authorized)

---

## Emergency Stop Procedure

If ANY of the following conditions occur, **immediately cease all testing activity** and invoke the emergency stop procedure:

1. Any contact with out-of-scope systems is detected
2. Real user data (PII, payment data, health records) becomes visible
3. Any monitored service shows elevated error rates or customer impact
4. The client's security team raises an incident
5. Any tool behaves unexpectedly or produces unintended effects

### Emergency Stop Steps

1. Run: `./redamon.sh down` (terminates all RedAmon activity)
2. Kill all sub-process tools: `pkill -f sqlmap; pkill -f hydra; pkill -f nuclei`
3. **Immediately call**: {{EMERGENCY_STOP_PHONE}}
4. Send email to: {{SECURITY_LEAD_EMAIL}} with subject: `[GRIMSEC STOP] Engagement {{ENGAGEMENT_ID}}`
5. Preserve all logs: `tar czf evidence-$(date +%Y%m%d-%H%M%S).tar.gz adversary-simulation/`
6. Do NOT delete evidence. Do NOT continue testing.

---

## Notification Contacts

| Role | Name | Email | Phone |
|------|------|-------|-------|
| Security Lead | {{SECURITY_LEAD_NAME}} | {{SECURITY_LEAD_EMAIL}} | {{SECURITY_LEAD_PHONE}} |
| System Owner | {{SYSTEM_OWNER_NAME}} | {{SYSTEM_OWNER_EMAIL}} | {{SYSTEM_OWNER_PHONE}} |
| Emergency Stop | {{EMERGENCY_CONTACT_NAME}} | — | {{EMERGENCY_STOP_PHONE}} |
| Testing Team Lead | {{LEAD_TESTER_NAME}} | {{LEAD_TESTER_EMAIL}} | {{LEAD_TESTER_PHONE}} |

### Communication Schedule

- **Start of engagement**: Email to Security Lead confirming start
- **Daily status**: Email to Security Lead by 6:00 PM {{TIMEZONE}} each testing day
- **Critical finding**: Immediate email and phone call to Security Lead
- **Engagement completion**: Email to all contacts with summary within 24 hours
- **Draft report**: Delivered within 5 business days
- **Final report**: Delivered within 10 business days

---

## Evidence Preservation

All testing activity must be logged with:
- Full timestamps (ISO8601 with timezone)
- Source system identification
- Tester identity
- Commands executed and outputs received

Evidence must be retained for a minimum of **90 days** from engagement end.

Evidence files will be stored at:
```
adversary-simulation/
├── roe.json                     (this document in structured form)
├── exploitation-log.json        (full audit trail)
├── evidence/                    (screenshots, PoC files)
└── evidence-hashes.txt          (SHA-256 hashes for chain of custody)
```

---

## Legal and Liability

### Applicable Law

This authorization is provided under the following legal framework:

- **United States**: Computer Fraud and Abuse Act (18 U.S.C. § 1030)
- **European Union**: Directive on Attacks Against Information Systems (2013/40/EU)
- **United Kingdom**: Computer Misuse Act 1990

### Liability Limitation

Testing Entity shall not be held liable for security vulnerabilities discovered during the authorized testing period, provided testing activities conform to the scope and constraints defined in this document.

System Owner acknowledges that security testing may reveal vulnerabilities that pose risk to the system. System Owner takes responsibility for remediation.

### Indemnification

System Owner agrees to indemnify and hold harmless Testing Entity from any claims arising from vulnerabilities exploited during the authorized engagement, provided testing remained within the defined scope.

---

## Safe Harbor Statement

> {{CLIENT_COMPANY_NAME}} grants {{TESTING_ORG_NAME}} and its authorized testers permission to perform the security testing activities described in this Authorized Security Testing Agreement. This permission constitutes authorization as required under 18 U.S.C. § 1030 (CFAA) and equivalent laws in applicable jurisdictions. {{TESTING_ORG_NAME}} testers are authorized to perform the activities checked in the "Authorized Testing Techniques" section above, limited to the systems listed in the "In-Scope" section, during the specified testing window.

---

## Signatures

By signing below, each party acknowledges that they have read, understood, and agree to the terms of this Authorized Security Testing Agreement.

**System Owner / Authorized Signatory**:

Signature: ________________________________  
Name: {{CLIENT_SIGNATORY_NAME}}  
Title: {{CLIENT_SIGNATORY_TITLE}}  
Organization: {{CLIENT_COMPANY_NAME}}  
Date: ________________________________  

**Testing Team Lead**:

Signature: ________________________________  
Name: {{LEAD_TESTER_NAME}}  
Title: {{LEAD_TESTER_TITLE}}  
Organization: {{TESTING_ORG_NAME}}  
Date: ________________________________  

**Legal Review (if required)**:

Signature: ________________________________  
Name: ________________________________  
Title: ________________________________  
Date: ________________________________  

---

## roe.json — Structured Export

*After completion, convert this document to the structured JSON format below for use by the simulation pipeline.*

```json
{
  "engagement_id": "{{ENGAGEMENT_ID}}",
  "authorized_by": "{{CLIENT_SIGNATORY_NAME}}, {{CLIENT_SIGNATORY_TITLE}}, {{CLIENT_COMPANY_NAME}}",
  "authorization_date": "{{ISSUE_DATE}}",
  "authorization_document_ref": "adversary-simulation/roe-signed.pdf",

  "scope": {
    "targets": ["{{IN_SCOPE_IP_OR_DOMAIN_1}}", "{{IN_SCOPE_IP_OR_DOMAIN_2}}"],
    "in_scope_ports": [80, 443],
    "in_scope_services": ["{{SERVICE_1_NAME}}", "{{SERVICE_2_NAME}}"],
    "in_scope_endpoints": [],
    "out_of_scope": ["{{EXCLUDED_SYSTEM_1}} ({{EXCLUDED_REASON_1}})"],
    "exclusions": ["{{EXCLUDED_ID_1}}", "{{EXCLUDED_ID_2}}"]
  },

  "authorized_techniques": [
    "reconnaissance",
    "vulnerability_scanning",
    "exploitation",
    "post_exploitation"
  ],

  "time_window": {
    "start": "{{TESTING_WINDOW_START}}",
    "end": "{{TESTING_WINDOW_END}}",
    "timezone": "{{TIMEZONE}}"
  },

  "contacts": {
    "security_lead": "{{SECURITY_LEAD_EMAIL}}",
    "system_owner": "{{SYSTEM_OWNER_EMAIL}}",
    "emergency_stop": "{{EMERGENCY_STOP_PHONE}}",
    "testing_team_lead": "{{LEAD_TESTER_EMAIL}}"
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
    "signed_document_hash": "{{SHA256_OF_SIGNED_PDF}}"
  }
}
```

---

*GRIMSEC Adversary Simulation Agent (Agent 12) — Rules of Engagement Template v1.0*
