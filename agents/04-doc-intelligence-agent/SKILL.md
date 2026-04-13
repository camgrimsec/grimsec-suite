---
name: doc-intelligence-agent
description: Performs deep documentation analysis on software repositories to build a comprehensive product context profile used to validate and enrich security vulnerability findings. Use when analyzing repositories for security assessments, when security scanner findings need context about the application's actual runtime environment, when evaluating whether scanner-reported vulnerabilities are mitigated by existing security controls, or when preparing security PRs that reference deployment architecture, authentication model, sandboxing, encryption, and audit logging. Covers documentation analysis, product context extraction, security architecture mapping, deployment security, API surface analysis, and vulnerability context adjustment.
metadata:
  author: cambamwham2
  version: '1.0'
---

# Documentation Intelligence Agent

## When to Use This Skill

Load this skill when you need to:

- Build a **product context profile** from a repository's documentation before writing security findings
- Validate whether scanner-flagged vulnerabilities are mitigated by the application's own security controls
- Produce **vulnerability_context_adjustments** that adjust raw scanner risk scores based on documented architecture
- Understand a repo's authentication model, sandboxing, network isolation, encryption, and authorization before making claims about risk
- Prepare security PRs that will be accepted by maintainers (because they acknowledge existing mitigations)

**Core principle**: A scanner finding is a hypothesis. Documentation is the evidence that confirms, upgrades, or downgrades it. Never treat a scanner finding as ground truth until you have read the application's own security documentation.

---

## Prerequisites

```bash
pip install pyyaml
```

The automated script (`scripts/analyze-docs.py`) uses only Python stdlib + pyyaml.

---

## 8-Phase Documentation Intelligence Sweep

Work through all 8 phases in order. Phases 1–6 can be automated with `scripts/analyze-docs.py`. Phases 7–8 require agent judgment.

---

### Phase 1: Repository Surface Scan

Inventory every documentation source before reading any of them. Use the script or manually check:

| File/Path | Purpose |
|---|---|
| `README.md` | Product overview, quick start, deployment notes |
| `SECURITY.md` | Vulnerability disclosure policy, security model |
| `/docs/` directory | Deep documentation tree |
| `CONTRIBUTING.md` | Dev setup, architecture overview |
| `CHANGELOG.md` | Recent security fixes, version cadence |
| `.env.example` / `.env.sample` | Configuration surface area, secret names |
| `LICENSE` | Open-source model — affects threat model |
| `Dockerfile` / `docker-compose.yml` | Container security baseline |
| `helm/` / `charts/` | Kubernetes deployment security |
| `terraform/` / `infra/` | Infrastructure security |
| `openapi.yaml` / `swagger.json` | API surface definition |

**Flag as a finding** if any of these are missing:
- No `SECURITY.md` → "No vulnerability disclosure policy"
- No `.env.example` → "Secret surface area undocumented"
- No deployment docs → "Security deployment guidance absent"

Record the complete inventory before proceeding.

---

### Phase 2: Product Identity

Extract from README.md and top-level docs:

1. **Product description** — one paragraph, in the product's own words
2. **Target audience** — developers, enterprises, consumers, platform engineers, etc.
3. **Deployment models** — SaaS, self-hosted Docker, self-hosted Kubernetes, CLI tool, library
4. **Pricing model** — free/open-source, open-core, enterprise tiers
5. **Maturity indicators** — GitHub stars, contributor count, release cadence, last commit date

This context determines the threat model. A self-hosted tool for platform engineers has a very different threat model than a SaaS product for consumers.

---

### Phase 3: Architecture & Runtime

Extract from code, Dockerfiles, docker-compose, and docs:

1. **Tech stack** — languages, frameworks (backend + frontend), major libraries
2. **Runtime environment** — Docker, Kubernetes, bare metal, serverless, Lambda
3. **Service architecture** — monolith, microservices, workers, serverless functions
4. **Database layer** — type (relational/NoSQL), ORM, connection pooling
5. **Caching layer** — Redis, Memcached, in-memory cache
6. **Queue/worker system** — BullMQ, Celery, SQS, Kafka, etc.
7. **External dependencies** — cloud providers, third-party APIs, CDNs

Architecture determines attack surface. A monolith with a single database is fundamentally different from a microservices mesh with message queues.

---

### Phase 4: Security Architecture (Critical Phase)

This is the most important phase. Read carefully — missing a security control leads to false-positive findings.

#### 4.1 Authentication
- Mechanism: JWT, OAuth2, SAML, LDAP, API keys, machine tokens, magic links
- Token storage: cookies (httpOnly/Secure flags?), localStorage, server-side sessions
- Token expiry and refresh logic
- Multi-factor authentication support
- Machine-to-machine authentication

#### 4.2 Authorization
- Model: RBAC, ABAC, custom, CASL, Casbin, Open Policy Agent
- Scope of enforcement: per-resource, per-workspace, per-organization
- Admin/superuser privilege escalation paths

#### 4.3 Encryption
- At-rest: database-level, application-level, field-level, disk encryption
- In-transit: TLS enforced vs. recommended vs. absent
- Key management: application-managed, KMS (AWS/GCP/Azure), HashiCorp Vault
- Secret rotation policy

#### 4.4 Sandboxing & Isolation
Look specifically for:
- **NSJAIL**: filesystem isolation, network isolation, resource limits, PID namespace
- **seccomp profiles**: syscall filtering
- **AppArmor/SELinux**: MAC policies
- **Container isolation**: non-root USER, read-only filesystem, dropped capabilities
- **VM isolation**: separate VMs for untrusted code execution
- **Agent workers**: workers without direct DB access

Document what's **available**, what's **enabled by default**, and what requires opt-in.

#### 4.5 Network Controls
- VPC / network segmentation
- Security groups and their default rules (especially egress)
- Kubernetes NetworkPolicy
- Service mesh (Istio, Linkerd) for mTLS
- WAF, DDoS protection, IP allowlisting

#### 4.6 Secret Management
- How secrets are passed: env vars, Vault, KMS, Kubernetes secrets
- Whether secrets appear in logs (check logging config)
- Whether secrets are committed (check .gitignore, .env.example)

#### 4.7 Audit Logging
- What events are logged (auth, admin actions, data access)
- Where logs go (file, database, SIEM, cloud logging)
- Tamper protection (append-only, signed logs)
- Retention policy

#### 4.8 Input Validation & Output Encoding
- Validation library or framework (Zod, Joi, Pydantic, class-validator, etc.)
- Where validation occurs (edge, controller, service layer)
- File upload validation and sandboxing
- SQL injection prevention (parameterized queries, ORM usage)

#### 4.9 Security Policy & Certifications
- `SECURITY.md` contents: disclosure email, PGP key, supported versions, SLA
- Any certifications: SOC2, ISO27001, HIPAA, PCI DSS
- Bug bounty program

---

### Phase 5: Deployment & Operations Security

Analyze Dockerfiles, docker-compose, Helm charts, Terraform:

#### Dockerfiles
```
Check for:
- USER directive (non-root required)
- Base image (pinned digest vs. floating tag)
- COPY --chown vs. root-owned files
- Exposed ports (is 443 used? port 80 exposed unnecessarily?)
- Multi-stage builds (reduces attack surface)
- Secrets in ENV or ARG (security anti-pattern)
```

#### Docker Compose
```
Check for:
- Environment variable names with SECRET/KEY/PASSWORD (are they externalized?)
- Volume mounts (is sensitive host path mounted?)
- Network definitions (are services isolated on internal networks?)
- privileged: true (red flag)
- cap_add: (especially SYS_ADMIN, NET_ADMIN)
- read_only: true (security positive)
- security_opt entries (apparmor, seccomp)
```

#### Helm / Kubernetes
```
Check for:
- securityContext.runAsNonRoot
- securityContext.readOnlyRootFilesystem
- securityContext.allowPrivilegeEscalation: false
- capabilities.drop: [ALL]
- podDisruptionBudget
- NetworkPolicy resources
- Resource limits (prevents DoS)
```

#### Terraform
```
Check for:
- aws_security_group egress rules (0.0.0.0/0 → flag for review)
- aws_security_group ingress (0.0.0.0/0 on ports other than 80/443 → CRITICAL)
- aws_s3_bucket public access blocks
- aws_rds_instance publicly_accessible
- aws_lb listeners (HTTP-only listener = finding)
- encryption_at_rest and storage_encrypted settings
- KMS key references
```

---

### Phase 6: API Surface Analysis

Scan route definition files and OpenAPI specs:

1. **Public endpoints** (no auth required) — enumerate them explicitly
2. **Authenticated endpoints** — confirm auth middleware is applied
3. **Admin endpoints** — extra-privilege paths, confirm they're protected
4. **File upload endpoints** — flag for upload validation analysis
5. **Webhook receivers** — check HMAC signature validation
6. **API versioning** — are old API versions still active?
7. **Rate limiting** — per-endpoint, per-user, global?
8. **GraphQL** — introspection enabled? depth limits? field limits?

Common route file patterns to scan:
- Express/Fastify: `router.get(`, `app.post(`, `fastify.route(`
- Flask/FastAPI: `@app.route(`, `@router.get(`
- Rails: `routes.rb`
- Go: `mux.HandleFunc(`, `r.GET(`
- Rust (Actix): `.route(`, `.service(`

---

### Phase 7: External Documentation Fetch

Many projects have external documentation sites beyond the repo. Identify and fetch:

1. **Find the docs site URL** in README.md (look for patterns like `docs.example.com`, `example.com/docs`)
2. **Identify security-critical pages** to fetch:
   - Self-hosting guide
   - Security hardening guide
   - Authentication configuration
   - Network/firewall requirements
   - Upgrade/migration guide (for known CVEs)
3. **Use `fetch_url`** on each relevant page and incorporate findings into the profile

Key sections to look for in external docs:
- "Security" or "Security Hardening" — often contains controls not in the repo
- "Self-hosting" — contains deployment security requirements
- "API Reference" — full endpoint inventory
- "Architecture" — may reveal security design decisions absent from README

Document which external URLs were fetched and what security-relevant information was found.

---

### Phase 8: Security Context Profile Generation

After completing Phases 1–7, compile all findings into a structured JSON profile. This is the output that feeds into vulnerability reachability analysis.

**Output file**: `doc-profile.json`
**Summary file**: `doc-summary.md`

#### Profile Schema

```json
{
  "product_context": {
    "name": "<product name>",
    "description": "<one-paragraph summary from product's own words>",
    "deployment_models": ["<model1>", "<model2>"],
    "target_audience": ["<audience1>"],
    "maturity": {
      "stars": 0,
      "contributors": 0,
      "last_release": "<YYYY-MM-DD>",
      "release_cadence": "<weekly|monthly|irregular>"
    },
    "docs_completeness": "<complete|partial|minimal>",
    "missing_docs": ["<list of missing expected documentation>"]
  },
  "architecture": {
    "languages": ["<lang1>"],
    "frameworks": {"backend": "<framework>", "frontend": "<framework>"},
    "databases": ["<db1>"],
    "caching": ["<cache1>"],
    "queue_system": "<system or null>",
    "runtime": ["<env1>"],
    "service_model": "<monolith|microservices|serverless|hybrid>",
    "external_services": ["<service1>"]
  },
  "security_controls": {
    "authentication": ["<mechanism1>"],
    "authorization": "<model description>",
    "sandboxing": {
      "<technology>": {
        "available": true,
        "default": false,
        "capabilities": ["<cap1>"],
        "notes": "<important details>"
      }
    },
    "encryption": {
      "at_rest": "<description or null>",
      "in_transit": "<description>",
      "key_management": "<description or null>"
    },
    "audit_logging": "<true|false|partial>",
    "rate_limiting": "<description or null>",
    "input_validation": "<library/approach or null>",
    "security_policy": "<SECURITY.md exists|missing>",
    "certifications": ["<cert1>"],
    "known_security_features": ["<feature1>"]
  },
  "deployment_security": {
    "recommended_method": "<method>",
    "tls_configuration": "<description>",
    "container_user": "<description>",
    "isolation_defaults": {},
    "environment_secrets": ["<VAR_NAME1>"],
    "known_gaps": ["<gap1>"]
  },
  "api_surface": {
    "public_endpoints": ["<endpoint1>"],
    "admin_endpoints": ["<endpoint1>"],
    "file_upload": true,
    "webhooks": false,
    "graphql": false,
    "api_versioning": "<strategy or null>",
    "rate_limiting": "<description or null>"
  },
  "external_docs": {
    "docs_site": "<URL or null>",
    "fetched_pages": [
      {"url": "<URL>", "key_findings": "<summary>"}
    ],
    "unfetched_recommended": ["<URL1>"]
  },
  "vulnerability_context_adjustments": [
    {
      "finding_category": "<scanner_category>",
      "adjustment": "<DOWNGRADE|UPGRADE|CONFIRMED|NEEDS_MORE_INFO>",
      "from_risk": 0.0,
      "to_risk": 0.0,
      "reason": "<specific explanation citing evidence>",
      "evidence": "<file path, line number, URL, or quote>"
    }
  ]
}
```

#### Adjustment Decision Logic

For each scanner finding, apply this logic:

```
IF the application has a documented security control that directly mitigates the finding:
  → DOWNGRADE the risk score
  → Document the control as evidence
  → Note whether it's enabled by default or requires configuration

IF the finding is confirmed by the application's own documentation acknowledging the gap:
  → CONFIRMED — do not downgrade
  → Quote the documentation as evidence

IF the application has a security control but it's disabled by default:
  → Partial DOWNGRADE (e.g., 7.0 → 5.5, not 7.0 → 2.0)
  → Note the default behavior

IF documentation is missing for the relevant component:
  → NEEDS_MORE_INFO — flag what documentation is absent
  → Do not assume mitigation exists

IF the finding affects a deployment template/example that users copy:
  → CONFIRMED even if production deployments might differ
  → Users copy the example — it IS the risk
```

#### Markdown Summary

The `doc-summary.md` file should contain:

1. **Product Overview** — name, description, deployment models
2. **Security Architecture Summary** — key controls found
3. **Documentation Completeness** — what's present vs. missing
4. **Key Findings for Vulnerability Context** — each adjustment with rationale
5. **External Docs Fetched** — URLs and key findings
6. **Recommended Next Steps** — what else to investigate

---

## Running the Automated Analysis

```bash
# Install dependency
pip install pyyaml

# Run the analysis script
python scripts/analyze-docs.py --repo-path /path/to/repo --output /path/to/output

# Outputs:
#   /path/to/output/doc-profile.json
#   /path/to/output/doc-summary.md
```

The script handles Phases 1–6 automatically. After running it, the agent should:
1. Review `doc-profile.json` for completeness
2. Perform Phase 7 (fetch external docs manually with `fetch_url`)
3. Refine `vulnerability_context_adjustments` with agent judgment

---

## Quality Checks

Before finalizing the profile, verify:

- [ ] Every vulnerability adjustment has a specific evidence reference (not just "docs say so")
- [ ] Missing documentation is explicitly flagged, not silently ignored
- [ ] Default vs. opt-in security controls are clearly distinguished
- [ ] Deployment example security differs from "production best practice" security — both are noted
- [ ] External docs site has been checked if one exists
- [ ] The `doc-summary.md` can stand alone as a human-readable security brief

---

## Reference Files

- `references/security-doc-checklist.md` — Complete checklist of what to look for in each phase, common patterns by framework, red flags, and green flags
- `scripts/analyze-docs.py` — Automated script for Phases 1–6
