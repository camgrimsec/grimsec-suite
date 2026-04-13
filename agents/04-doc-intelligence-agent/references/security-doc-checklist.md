# Security Documentation Checklist

Reference guide for the doc-intelligence-agent. Use during each phase to ensure comprehensive coverage.

---

## Phase 1: Files to Search For

### Essential Documentation
```
README.md / readme.md / Readme.md
SECURITY.md / .github/SECURITY.md
CONTRIBUTING.md / .github/CONTRIBUTING.md
CHANGELOG.md / CHANGES.md / HISTORY.md / RELEASES.md
LICENSE / LICENSE.md / LICENSE.txt
CODE_OF_CONDUCT.md
.env.example / .env.sample / .env.template / example.env
```

### Infrastructure & Deployment
```
Dockerfile
Dockerfile.* (Dockerfile.dev, Dockerfile.prod, Dockerfile.worker)
docker-compose.yml / docker-compose.yaml
docker-compose.*.yml (docker-compose.dev.yml, docker-compose.prod.yml)
helm/ (Chart.yaml, values.yaml, values-prod.yaml)
terraform/ (*.tf, *.tfvars, terraform.tfvars)
kubernetes/ (deployment.yaml, service.yaml, ingress.yaml, network-policy.yaml)
.github/workflows/*.yml (CI/CD security practices)
Makefile (build and deploy commands)
scripts/deploy.sh (deployment process)
```

### API Surface
```
openapi.yaml / openapi.json / swagger.yaml / swagger.json
api-docs/ (directory)
routes/ (Express, Fastify routes)
controllers/ (MVC controllers)
src/api/ (API definitions)
src/routes/ (route definitions)
```

### Security-Specific
```
SECURITY.md
THREAT_MODEL.md / threat-model.md
docs/security/ (security documentation directory)
docs/self-hosting/ (self-hosting security requirements)
docs/deployment/ (deployment security guides)
certs/ (certificate files — presence is a finding if committed)
.secrets (never should exist — flag if present)
.npmrc / .yarnrc (registry auth tokens — flag if present)
```

---

## Phase 2: Product Identity Patterns

### Deployment Model Signals

| Pattern | Deployment Model |
|---|---|
| `docker-compose`, `docker run`, `self-host` | Self-hosted Docker |
| `helm install`, `kubectl apply`, `k8s`, `kubernetes` | Self-hosted Kubernetes |
| `.com`, `cloud version`, `managed service` | SaaS / Cloud |
| `npm install`, `pip install`, `cargo install`, `brew install` | CLI tool or library |
| `serverless`, `lambda`, `cloud function` | Serverless |
| `on-premise`, `on-prem`, `air-gapped` | On-premises |

### Target Audience Signals
```
"developers", "engineers" → developers
"enterprises", "teams", "organizations" → enterprise
"platform engineers", "DevOps", "SREs" → platform/ops
"data engineers", "data scientists" → data teams
"security teams", "SOC", "infosec" → security professionals
```

---

## Phase 3: Framework & Stack Detection

### Backend Frameworks by Language

**Rust**
- `actix-web`, `actix_web` → Actix-web
- `axum`, `tokio` → Axum
- `rocket` → Rocket
- `warp` → Warp

**TypeScript / JavaScript**
- `express` → Express.js
- `fastify` → Fastify
- `@nestjs/core` → NestJS
- `hapi` → Hapi.js
- `koa` → Koa.js
- `@hono/` → Hono

**Python**
- `from flask import`, `Flask(__name__)` → Flask
- `from fastapi import`, `FastAPI()` → FastAPI
- `django.urls`, `INSTALLED_APPS` → Django
- `tornado.web`, `RequestHandler` → Tornado

**Go**
- `github.com/gin-gonic/gin` → Gin
- `github.com/labstack/echo` → Echo
- `net/http` + `gorilla/mux` → Gorilla Mux
- `github.com/go-chi/chi` → Chi
- `github.com/gofiber/fiber` → Fiber

**Ruby**
- `Rails.application`, `config/routes.rb` → Ruby on Rails
- `require 'sinatra'` → Sinatra

**PHP**
- `use Illuminate\` → Laravel
- `use Symfony\` → Symfony

**Java / Kotlin**
- `@SpringBootApplication` → Spring Boot
- `@Controller`, `@RestController` → Spring MVC
- `Quarkus` → Quarkus
- `Micronaut` → Micronaut

### ORM / Database Patterns

| Pattern | Technology |
|---|---|
| `sqlalchemy`, `declarative_base` | SQLAlchemy (Python) |
| `typeorm`, `@Entity()` | TypeORM (TypeScript) |
| `prisma.`, `@prisma/client` | Prisma (TypeScript) |
| `Sequelize`, `sequelize.define` | Sequelize (Node.js) |
| `ActiveRecord`, `belongs_to` | ActiveRecord (Rails) |
| `diesel::`, `#[derive(Queryable)]` | Diesel (Rust) |
| `sqlx::`, `query!` macro | sqlx (Rust) |
| `gorm.DB`, `gorm.Model` | GORM (Go) |
| `knex.`, `knex.raw` | Knex.js (Node.js) |
| `drizzle`, `pgTable` | Drizzle ORM (TypeScript) |

---

## Phase 4: Security Architecture Patterns

### Authentication Patterns by Framework

**JWT Patterns**
```
jsonwebtoken.sign / jwt.verify (Node.js)
python-jose, PyJWT: jwt.encode / jwt.decode
golang-jwt: jwt.ParseWithClaims
jsonwebtoken, jose (Rust)
Authorization: Bearer <token>
```

**OAuth2 / OIDC Patterns**
```
passport.js with passport-oauth2 / passport-openidconnect
auth0, okta, keycloak integrations
openid-client, node-openid-client
authlib (Python)
goauth2, golang.org/x/oauth2
OAUTH_CLIENT_ID in .env.example
```

**Session-Based Auth**
```
express-session
connect-pg-simple (PostgreSQL sessions)
flask-session, flask-login
django.contrib.sessions
SESSION_SECRET in .env
```

**API Key Auth**
```
x-api-key header
Authorization: ApiKey
API_KEY in .env.example
req.headers['x-api-key']
```

### Authorization Libraries

| Library | Language | Pattern |
|---|---|---|
| CASL | JavaScript/TypeScript | `ability.can('read', 'Post')` |
| Casbin | Multi-language | `enforcer.Enforce(sub, obj, act)` |
| Open Policy Agent | Multi-language | `rego` policy files |
| Pundit | Ruby | `authorize @resource` |
| CanCan/CanCanCan | Ruby | `can :read, Article` |
| django-guardian | Python | `assign_perm('view_task', user)` |
| spring-security | Java | `@PreAuthorize("hasRole('ADMIN')")` |
| bouncer | PHP | `Gate::allows('update-post', $post)` |

### Sandboxing Indicators

**NSJAIL** (strongest signal — purpose-built sandboxing)
```
nsjail binary in Dockerfile
nsjail.cfg, nsjail.proto
--config /etc/nsjail.cfg
nsjail --network_none (network isolation)
nsjail --rlimit_* (resource limits)
```

**Container Security**
```
USER <non-root> in Dockerfile → POSITIVE
--user flag in docker run → POSITIVE
securityContext.runAsNonRoot: true → POSITIVE
securityContext.readOnlyRootFilesystem: true → STRONG POSITIVE
capabilities.drop: [ALL] → STRONG POSITIVE
allowPrivilegeEscalation: false → POSITIVE
```

**Linux Namespaces**
```
unshare --pid, --net, --mount (shell commands)
pid_namespace, net_namespace (documentation)
clone(CLONE_NEWPID|CLONE_NEWNET) (C code)
```

**seccomp**
```
security_opt: seccomp:/path/to/profile.json (docker-compose)
securityContext.seccompProfile (Kubernetes)
libseccomp (dependency)
```

---

## Phase 5: Deployment Security Indicators

### Dockerfile Red Flags
```
FROM ... (no digest pinning: @sha256:...)  ← supply chain risk
USER root (explicit root)                  ← privilege risk
ENV SECRET_KEY=hardcoded_value             ← secret exposure
COPY . . (copies .git, secrets)            ← data exposure
RUN curl ... | bash                        ← supply chain
ADD https://... (remote file add)          ← supply chain
```

### Dockerfile Green Flags
```
FROM ... @sha256:abc123...                 ← pinned digest
USER nonroot / USER 1000                   ← non-root user
COPY --chown=app:app                       ← proper ownership
RUN apt-get install && rm -rf /var/lib/apt/lists/*  ← clean layers
HEALTHCHECK CMD ...                        ← operational maturity
Multi-stage build (AS builder / AS runner)  ← minimal attack surface
```

### Docker Compose Red Flags
```
privileged: true                           ← full host access (CRITICAL)
cap_add: [SYS_ADMIN]                       ← dangerous capability
cap_add: [NET_ADMIN]                       ← network manipulation
volume: /:/host                            ← full host filesystem mount
volume: /var/run/docker.sock              ← Docker socket (container escape)
network_mode: host                         ← no network isolation
secrets hardcoded in environment           ← secret exposure
```

### Docker Compose Green Flags
```
read_only: true                            ← read-only filesystem
cap_drop: [ALL]                            ← drop all capabilities
security_opt: no-new-privileges:true       ← prevent privilege escalation
security_opt: seccomp:/path/profile.json   ← syscall filtering
tmpfs: /tmp                                ← in-memory temp
networks: internal: (no external access)   ← network isolation
user: "1000:1000"                          ← explicit non-root
```

### Terraform Security Indicators

**Critical Red Flags**
```hcl
# Open ingress on non-web ports
ingress {
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

# HTTP-only load balancer
resource "aws_lb_listener" "http" {
  protocol = "HTTP"   # no HTTPS redirect
}

# Publicly accessible database
resource "aws_db_instance" "main" {
  publicly_accessible = true
}

# S3 public access
block_public_acls       = false
block_public_policy     = false
```

**Security Positive Patterns**
```hcl
# Encrypted storage
storage_encrypted = true
kms_key_id        = aws_kms_key.main.arn

# HTTPS only
protocol         = "HTTPS"
ssl_policy       = "ELBSecurityPolicy-TLS13-1-2-2021-06"

# Non-public database
publicly_accessible = false

# VPC with private subnets
subnet_ids = [aws_subnet.private.*.id]

# WAF association
aws_wafv2_web_acl_association
```

---

## Phase 6: API Surface Patterns

### Route Authentication Middleware Patterns

**Express / Node.js**
```javascript
router.use(authenticate)          // blanket auth
router.get('/admin', isAdmin, ...) // per-route auth
app.use('/api', authMiddleware)   // path-level auth
passport.authenticate('jwt')      // Passport.js
```

**FastAPI / Python**
```python
Depends(get_current_user)         // FastAPI dependency injection
@login_required                   // Flask-Login decorator
@permission_required('admin')     // Django permissions
security = [{"bearerAuth": []}]   // OpenAPI security scheme
```

**Rails**
```ruby
before_action :authenticate_user!  // Devise
before_action :require_admin       // custom
```

**Go**
```go
r.Use(AuthMiddleware)              // Gorilla/Chi middleware
group.Use(JWTMiddleware())         // Gin groups
```

### Public Endpoint Red Flags
```
/api/health (OK — health checks should be public)
/api/metrics (MAYBE — if Prometheus metrics expose sensitive data)
/admin (CRITICAL if no auth middleware)
/api/users (HIGH if returns PII without auth)
/api/v1/execute (CRITICAL if executes code without auth)
/debug (HIGH — debug endpoints should never be public)
/api/config (HIGH — configuration exposure)
```

### File Upload Risk Signals
```
multer, formidable, busboy (Node.js)
FileField, ImageField (Django)
werkzeug.FileStorage (Flask)
multipart/form-data in OpenAPI spec
Content-Type: multipart/form-data in route handler
```

### Webhook Security Patterns
```
hmacSha256(secret, body)           // HMAC signature validation (POSITIVE)
crypto.timingSafeEqual             // Timing-safe comparison (POSITIVE)
X-Hub-Signature-256 header check   // GitHub-style webhook auth (POSITIVE)
No signature validation            // RED FLAG — replay attacks possible
```

---

## Security Posture Scoring Reference

### Green Flags (Reduce Risk Scores)

Each green flag can justify a 0.5–1.5 point risk reduction:

| Green Flag | Max Reduction | Applies To |
|---|---|---|
| NSJAIL with network isolation ON by default | -2.0 | Network egress findings |
| Non-root container user documented AND enforced | -1.5 | Container privilege findings |
| HTTPS enforced at load balancer | -1.5 | HTTP exposure findings |
| seccomp profile in place | -1.0 | Privilege escalation findings |
| Encrypted storage with KMS | -1.0 | Data exposure findings |
| WAF in production | -1.0 | Injection / XSS findings |
| Field-level encryption for PII | -1.5 | Data breach findings |
| Network policy isolating services | -1.0 | Lateral movement findings |
| Auth middleware on all authenticated routes | -1.0 | Auth bypass findings |
| Input validation library (Zod, Pydantic, etc.) | -0.5 | Injection findings |
| Prepared statements / parameterized queries | -1.0 | SQL injection findings |
| CSRF protection | -1.0 | CSRF findings |

### Red Flags (Increase Risk Scores or Confirm Findings)

| Red Flag | Action |
|---|---|
| No SECURITY.md | Add finding: missing disclosure policy (3.0) |
| Secrets in Dockerfiles | CONFIRM severity of secret exposure finding |
| privileged: true in docker-compose | UPGRADE to CRITICAL |
| No USER directive in Dockerfile | CONFIRM container privilege finding |
| HTTP-only load balancer in Terraform | CONFIRM plaintext transport finding |
| Docs explicitly acknowledge gap | CONFIRM — "README says X is not implemented" |
| NSJAIL available but disabled by default | Partial DOWNGRADE only |
| Security features behind enterprise tier | Note as mitigation gap for non-enterprise deployments |

### Adjustment Rules

```
DOWNGRADE conditions:
  - Security control exists AND is enabled by default
  - Risk reduction: 1.0–2.5 points depending on control strength
  - Always cite the specific evidence (file path + line or URL)

PARTIAL DOWNGRADE conditions:
  - Security control exists BUT requires opt-in configuration
  - Risk reduction: 0.5–1.5 points
  - Note the default behavior explicitly

CONFIRMED conditions:
  - Documentation acknowledges the gap exists
  - Example code or templates don't implement the control
  - Risk stays the same or increases slightly (user copies the example)

UPGRADE conditions:
  - Documentation is missing (can't confirm controls exist)
  - Finding is in a deployment template users copy verbatim
  - Security gap is documented as a known issue

NEEDS_MORE_INFO conditions:
  - Security architecture documentation is absent for this component
  - External documentation wasn't fetched yet
  - Feature may exist in enterprise tier only — unclear
```

---

## Missing Documentation Findings Reference

When expected security documentation is absent, these are findings in themselves:

| Missing Document | Severity | Finding |
|---|---|---|
| No SECURITY.md | MEDIUM | No vulnerability disclosure policy — security posture unclear |
| No .env.example | LOW | Secret surface area undocumented — unclear what credentials are required |
| No deployment security guide | MEDIUM | No documented security hardening guidance for operators |
| No authentication docs | HIGH | Auth model undocumented — can't verify security controls |
| No API reference | LOW | Can't enumerate full API surface for attack surface analysis |
| No CHANGELOG | LOW | Can't verify whether known CVEs have been patched |
| No architecture diagram | LOW | Runtime security model unclear |
| No backup/DR docs | LOW | Operational security posture unclear |

---

## Common Security Architecture Anti-Patterns

These patterns in documentation or code suggest systemic security weaknesses:

1. **"Security is handled at the reverse proxy level"** — without specifying which proxy or how
2. **"HTTPS in production"** — no enforcement or documentation of how
3. **"Contact us for security issues"** — no email, no PGP key, no SLA
4. **"Environment variables for all secrets"** — without `.env.example` or secret rotation docs
5. **Security features listed only in enterprise tier** — self-hosted users have reduced security posture
6. **NSJAIL or sandboxing mentioned but "disabled by default for performance"** — creates false sense of security
7. **"Coming soon"** for security features in roadmap — current version lacks them

---

## External Documentation Priority List

When fetching external docs (Phase 7), prioritize these page types in order:

1. `/docs/security` or `/docs/security-hardening` — most valuable
2. `/docs/self-hosting` or `/docs/deployment` — deployment security requirements
3. `/docs/authentication` or `/docs/auth` — auth model details
4. `/docs/api` or `/docs/api-reference` — complete API surface
5. `/docs/architecture` — runtime security design
6. `/docs/configuration` — all configuration options including security ones
7. `/docs/changelog` or `/blog/security-updates` — recent security fixes
8. `/docs/enterprise` — enterprise security features that may not be in base install
