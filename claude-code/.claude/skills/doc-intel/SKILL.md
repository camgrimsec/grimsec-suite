# Documentation Intelligence Agent

Deep documentation analysis to build a security context profile for validating vulnerability findings. Core principle: a scanner finding is a hypothesis — documentation is the evidence that confirms, upgrades, or downgrades it.

Invoke with `/doc-intel` or phrases like "analyze documentation", "build security context profile", "validate this finding against the docs".

## When to Use

- Build a product context profile before writing security findings
- Validate whether scanner-flagged vulnerabilities are mitigated by application's own controls
- Adjust raw scanner risk scores based on documented architecture
- Prepare security PRs that acknowledge existing mitigations (more likely to be accepted)

## 8-Phase Documentation Intelligence Sweep

Phases 1–6 can be automated with `scripts/analyze-docs.py`. Phases 7–8 require judgment.

### Phase 1: Repository Surface Scan

Inventory every documentation source:

| File/Path | Purpose |
|---|---|
| `README.md` | Product overview, deployment notes |
| `SECURITY.md` | Vulnerability disclosure policy, security model |
| `/docs/` | Deep documentation tree |
| `CONTRIBUTING.md` | Dev setup, architecture overview |
| `CHANGELOG.md` | Recent security fixes, version cadence |
| `.env.example` | Configuration surface, secret names |
| `Dockerfile` / `docker-compose.yml` | Container security baseline |
| `helm/` / `charts/` | Kubernetes deployment security |
| `terraform/` / `infra/` | Infrastructure security |
| `openapi.yaml` / `swagger.json` | API surface definition |

**Flag as finding if missing:**
- No `SECURITY.md` → "No vulnerability disclosure policy"
- No `.env.example` → "Secret surface area undocumented"
- No deployment docs → "Security deployment guidance absent"

### Phase 2: Product Identity

Extract: product description (in the product's own words), target audience, deployment models (SaaS/self-hosted/CLI/library), pricing model, maturity indicators.

### Phase 3: Architecture & Runtime

Extract: tech stack, runtime environment, service architecture (monolith/microservices/serverless), database layer, caching layer, queue/worker system, external dependencies.

### Phase 4: Security Architecture (Critical Phase)

**4.1 Authentication:** Mechanism (JWT, OAuth2, SAML, LDAP, API keys), token storage (httpOnly/Secure flags?), expiry/refresh, MFA, M2M auth.

**4.2 Authorization:** Model (RBAC, ABAC, CASL, Casbin, OPA), scope of enforcement.

**4.3 Encryption:** At-rest (DB-level, app-level, field-level), in-transit (TLS enforced vs. optional), key management (KMS, Vault).

**4.4 Sandboxing & Isolation:** NSJAIL, seccomp profiles, AppArmor/SELinux, container isolation (non-root USER, read-only filesystem, dropped capabilities). Document what's available, what's enabled by default, and what requires opt-in.

**4.5 Network Controls:** VPC/segmentation, security groups, K8s NetworkPolicy, WAF, IP allowlisting.

**4.6 Audit Logging:** Events logged, log destination, tamper protection, retention.

**4.7 Input Validation:** Validation library (Zod, Joi, Pydantic), where validation occurs, SQL injection prevention.

**4.8 Security Policy:** `SECURITY.md` contents, certifications (SOC2, ISO27001), bug bounty.

### Phase 5: Deployment Security

**Dockerfile:** USER directive (non-root), base image pinning, multi-stage builds, secrets in ENV/ARG (anti-pattern).

**Docker Compose:** `privileged: true` (red flag), `cap_add: SYS_ADMIN`, service network isolation.

**Kubernetes / Helm:** `securityContext.runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, NetworkPolicy, resource limits.

**Terraform:** `0.0.0.0/0` in security groups (non-80/443) → CRITICAL, public S3 buckets, `publicly_accessible` RDS, HTTP-only load balancers.

### Phase 6: API Surface Analysis

1. **Public endpoints** — paths requiring no auth (enumerate explicitly)
2. **Authenticated endpoints** — confirm auth middleware applied
3. **Admin endpoints** — extra-privilege paths
4. **File upload endpoints** — upload validation
5. **Webhook receivers** — HMAC signature validation
6. **GraphQL** — introspection enabled? depth limits?

### Phase 7: External Documentation Fetch

Find the docs site URL in README, then fetch:
- Self-hosting guide
- Security hardening guide
- Authentication configuration
- Network/firewall requirements

Use bash/curl to fetch external pages and incorporate findings into the profile.

### Phase 8: Security Context Profile Generation

**Output schema (`doc-profile.json`):**
```json
{
  "product_context": {"name": "", "deployment_models": [], "target_audience": []},
  "architecture": {"languages": [], "frameworks": {}, "databases": []},
  "security_controls": {
    "authentication": [], "authorization": "",
    "sandboxing": {"nsjail": {"available": true, "default": false, "capabilities": []}},
    "encryption": {"at_rest": "", "in_transit": ""},
    "audit_logging": "true|false|partial",
    "input_validation": ""
  },
  "deployment_security": {"recommended_method": "", "known_gaps": []},
  "api_surface": {"public_endpoints": [], "admin_endpoints": [], "file_upload": false},
  "vulnerability_context_adjustments": [
    {
      "finding_category": "",
      "adjustment": "DOWNGRADE|UPGRADE|CONFIRMED|NEEDS_MORE_INFO",
      "from_risk": 7.0, "to_risk": 3.0,
      "reason": "Application uses nsjail sandboxing that prevents filesystem access",
      "evidence": "docs/security.md line 42"
    }
  ]
}
```

**Adjustment logic:**
- Documented control directly mitigates finding → DOWNGRADE (cite evidence)
- App's own docs acknowledge the gap → CONFIRMED (do not downgrade)
- Control exists but disabled by default → Partial DOWNGRADE (e.g., 7.0 → 5.5)
- Documentation missing → NEEDS_MORE_INFO

## Automated Analysis

```bash
pip install pyyaml
python scripts/analyze-docs.py --repo-path /path/to/repo --output /path/to/output
# Outputs: doc-profile.json, doc-summary.md
```

Script handles Phases 1–6 automatically. Then manually perform Phase 7 (fetch external docs) and refine `vulnerability_context_adjustments` with judgment.

## Quality Checks

- [ ] Every vulnerability adjustment has a specific evidence reference (file:line or URL)
- [ ] Missing documentation explicitly flagged, not silently ignored
- [ ] Default vs. opt-in security controls clearly distinguished
- [ ] External docs site has been checked if one exists
- [ ] `doc-summary.md` can stand alone as human-readable security brief
