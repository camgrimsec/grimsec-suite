#!/usr/bin/env python3
"""
analyze-docs.py — Documentation Intelligence Agent (Phases 1-6)

Performs automated documentation analysis on a repository to build a
security context profile used for vulnerability validation.

Usage:
    python analyze-docs.py --repo-path /path/to/repo --output /path/to/output

Output:
    doc-profile.json   — Structured product context profile
    doc-summary.md     — Human-readable security brief

Dependencies:
    pip install pyyaml
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml is required. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_file(path: Path) -> str | None:
    """Read a text file, returning None if it cannot be read."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def find_files(root: Path, patterns: list[str]) -> list[Path]:
    """Return all files matching any of the given glob patterns under root."""
    results = []
    for pattern in patterns:
        results.extend(root.rglob(pattern))
    return [p for p in results if p.is_file()]


def extract_section(text: str, heading: str, next_headings: list[str] | None = None) -> str:
    """Extract a markdown section by heading (case-insensitive)."""
    lines = text.splitlines()
    capture = False
    collected = []
    heading_lower = heading.lower()
    stop_patterns = next_headings or []

    for line in lines:
        stripped = line.strip()
        if not capture:
            if re.match(r"^#{1,3}\s+" + re.escape(heading_lower), stripped.lower()):
                capture = True
                collected.append(line)
        else:
            if stripped.startswith("#"):
                if stop_patterns:
                    if any(p.lower() in stripped.lower() for p in stop_patterns):
                        break
                else:
                    # Stop at any same-or-higher level heading
                    current_level = len(stripped) - len(stripped.lstrip("#"))
                    start_level = len(collected[0]) - len(collected[0].lstrip("#"))
                    if current_level <= start_level:
                        break
            collected.append(line)
    return "\n".join(collected).strip()


def grep_lines(text: str, pattern: str, flags: int = re.IGNORECASE) -> list[tuple[int, str]]:
    """Return (line_number, line) tuples matching pattern."""
    results = []
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(pattern, line, flags):
            results.append((i, line.rstrip()))
    return results


# ---------------------------------------------------------------------------
# Phase 1: Repository Surface Scan
# ---------------------------------------------------------------------------

def phase1_surface_scan(repo: Path) -> dict[str, Any]:
    """Inventory all documentation sources."""
    print("[Phase 1] Repository Surface Scan...")

    inventory = {}
    missing = []

    candidates = {
        "README.md": ["README.md", "readme.md", "Readme.md"],
        "SECURITY.md": ["SECURITY.md", "security.md", ".github/SECURITY.md"],
        "CONTRIBUTING.md": ["CONTRIBUTING.md", "contributing.md", ".github/CONTRIBUTING.md"],
        "CHANGELOG.md": ["CHANGELOG.md", "CHANGES.md", "HISTORY.md", "changelog.md"],
        ".env.example": [".env.example", ".env.sample", ".env.template", "example.env"],
        "LICENSE": ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"],
    }

    for key, names in candidates.items():
        found = None
        for name in names:
            candidate = repo / name
            if candidate.exists():
                found = str(candidate.relative_to(repo))
                break
        inventory[key] = found
        if found is None:
            missing.append(key)

    # /docs directory
    docs_dir = repo / "docs"
    if docs_dir.exists() and docs_dir.is_dir():
        md_files = list(docs_dir.rglob("*.md")) + list(docs_dir.rglob("*.mdx"))
        inventory["docs_directory"] = {
            "path": "docs/",
            "file_count": len(md_files),
            "files": [str(p.relative_to(repo)) for p in sorted(md_files)[:50]],
        }
    else:
        inventory["docs_directory"] = None
        missing.append("docs/")

    # Infrastructure files
    infra = {
        "dockerfiles": [str(p.relative_to(repo)) for p in find_files(repo, ["Dockerfile", "Dockerfile.*"])],
        "docker_compose": [str(p.relative_to(repo)) for p in find_files(repo, ["docker-compose*.yml", "docker-compose*.yaml"])],
        "helm_charts": [str(p.relative_to(repo)) for p in find_files(repo, ["values.yaml", "Chart.yaml"])],
        "terraform": [str(p.relative_to(repo)) for p in find_files(repo, ["*.tf"])[:20]],
        "kubernetes": [str(p.relative_to(repo)) for p in find_files(repo, ["*.yaml", "*.yml"])
                       if any(kw in p.name for kw in ["deployment", "service", "ingress", "network-policy"])],
        "openapi": [str(p.relative_to(repo)) for p in find_files(repo, ["openapi.yaml", "openapi.json", "swagger.yaml", "swagger.json"])],
        "env_files": [str(p.relative_to(repo)) for p in find_files(repo, [".env*"])[:10]],
    }
    inventory["infrastructure"] = infra

    return {"inventory": inventory, "missing": missing}


# ---------------------------------------------------------------------------
# Phase 2: Product Identity
# ---------------------------------------------------------------------------

def phase2_product_identity(repo: Path, inventory: dict) -> dict[str, Any]:
    """Extract product identity from README and top-level docs."""
    print("[Phase 2] Product Identity...")

    readme_path = inventory.get("README.md")
    content = ""
    if readme_path:
        content = read_file(repo / readme_path) or ""

    # Extract first substantial paragraph as description
    description = ""
    paragraphs = [p.strip() for p in re.split(r"\n\n+", content) if len(p.strip()) > 80]
    # Skip badge lines and headings
    for para in paragraphs:
        if not para.startswith("#") and not re.match(r"^\[!\[", para):
            description = para[:500]
            break

    # Detect deployment models
    deployment_models = []
    dm_patterns = {
        "self-hosted-docker": r"docker[- ]compose|self.host|docker run",
        "self-hosted-kubernetes": r"kubernetes|helm chart|kubectl|k8s",
        "cloud": r"cloud[- ]hosted|managed[- ]service|saas|\.com|cloud version",
        "cli": r"\bcli\b|command.line.tool|npm install|pip install",
        "library": r"\blibrary\b|\bpackage\b|npm install|pip install.*as a library",
        "serverless": r"serverless|lambda|cloud.function|faas",
    }
    content_lower = content.lower()
    for model, pattern in dm_patterns.items():
        if re.search(pattern, content_lower):
            deployment_models.append(model)

    # Target audience
    audience = []
    audience_patterns = {
        "developers": r"\bdevelopers?\b|\bengineers?\b|\bdev\b",
        "enterprises": r"\benterprise\b|\bcorporate\b|\bbusiness\b",
        "devops": r"\bdevops\b|\bplatform.engineer\b|\bsre\b|\bops\b",
        "data-engineers": r"\bdata.engineer\b|\bdata.scientist\b|\bdata.analyst\b",
        "consumers": r"\busers?\b|\bconsumers?\b|\bteams?\b",
        "security": r"\bsecurity.team\b|\bsoc\b|\binfosec\b",
    }
    for aud, pattern in audience_patterns.items():
        if re.search(pattern, content_lower):
            audience.append(aud)

    # GitHub stars (look for badge patterns)
    stars = None
    star_match = re.search(r"(\d[\d,]+)\s*stars?|stars?[:\s]+(\d[\d,]+)", content, re.IGNORECASE)
    if star_match:
        raw = (star_match.group(1) or star_match.group(2)).replace(",", "")
        try:
            stars = int(raw)
        except ValueError:
            pass

    # Docs site URL
    docs_site = None
    for pattern in [r"https?://docs\.\S+", r"https?://\S+/docs", r"Documentation[:\s]+\(?(https?://\S+)\)?"]:
        m = re.search(pattern, content)
        if m:
            url = m.group(0) if "docs" in m.group(0) else m.group(1)
            url = url.rstrip(").,")
            docs_site = url
            break

    # Pricing model
    pricing = "unknown"
    if re.search(r"open.source|apache.2|mit license|agpl|gpl", content_lower):
        pricing = "open-source"
    if re.search(r"open.core|enterprise.license|enterprise.tier", content_lower):
        pricing = "open-core"
    if re.search(r"pricing|subscribe|per.seat|per.month", content_lower):
        pricing = "commercial"

    return {
        "description": description,
        "deployment_models": deployment_models or ["unknown"],
        "target_audience": audience or ["unknown"],
        "pricing_model": pricing,
        "stars": stars,
        "docs_site": docs_site,
    }


# ---------------------------------------------------------------------------
# Phase 3: Architecture & Runtime
# ---------------------------------------------------------------------------

def phase3_architecture(repo: Path, inventory: dict) -> dict[str, Any]:
    """Detect tech stack, runtime environment, and service architecture."""
    print("[Phase 3] Architecture & Runtime...")

    all_text = ""
    for key in ["README.md", "CONTRIBUTING.md"]:
        path = inventory.get(key)
        if path:
            all_text += (read_file(repo / path) or "") + "\n"

    # Languages (file extensions heuristic)
    lang_counts: dict[str, int] = {}
    ext_to_lang = {
        ".py": "Python", ".rs": "Rust", ".ts": "TypeScript", ".tsx": "TypeScript",
        ".js": "JavaScript", ".jsx": "JavaScript", ".go": "Go", ".java": "Java",
        ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".cpp": "C++", ".c": "C",
        ".ex": "Elixir", ".exs": "Elixir", ".hs": "Haskell", ".scala": "Scala",
        ".kt": "Kotlin", ".swift": "Swift",
    }
    skip_dirs = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
    for path in repo.rglob("*"):
        if path.is_file() and not any(d in path.parts for d in skip_dirs):
            lang = ext_to_lang.get(path.suffix)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + 1

    languages = sorted(lang_counts, key=lambda x: -lang_counts[x])[:8]

    # Frameworks
    frameworks: dict[str, str] = {}
    framework_patterns = {
        "backend": {
            "Actix-web (Rust)": r"actix.web|actix_web",
            "Axum (Rust)": r"\baxum\b",
            "Express (Node)": r"express\b",
            "Fastify (Node)": r"fastify\b",
            "NestJS": r"nestjs|@nestjs",
            "Django": r"django",
            "Flask": r"\bflask\b",
            "FastAPI": r"fastapi",
            "Rails": r"ruby.on.rails|rails\b",
            "Spring Boot": r"spring.boot|springboot",
            "Gin (Go)": r"\bgin\b.*golang|golang.*\bgin\b",
            "Echo (Go)": r"\becho\b.*golang",
        },
        "frontend": {
            "React": r"\breact\b",
            "Svelte/SvelteKit": r"\bsvelte\b",
            "Vue": r"\bvue\.?js\b",
            "Next.js": r"next\.js|nextjs",
            "Angular": r"\bangular\b",
            "Nuxt": r"\bnuxt\b",
        },
    }
    text_lower = all_text.lower()
    for category, patterns in framework_patterns.items():
        for fw, pattern in patterns.items():
            if re.search(pattern, text_lower):
                frameworks[category] = fw
                break

    # Databases
    db_patterns = {
        "PostgreSQL": r"postgres|postgresql",
        "MySQL": r"\bmysql\b",
        "SQLite": r"\bsqlite\b",
        "MongoDB": r"\bmongodb\b|\bmongoose\b",
        "Redis": r"\bredis\b",
        "Elasticsearch": r"elasticsearch",
        "CockroachDB": r"cockroachdb|cockroach",
        "Cassandra": r"cassandra",
        "DynamoDB": r"dynamodb",
        "ClickHouse": r"clickhouse",
    }
    databases = [db for db, pat in db_patterns.items() if re.search(pat, text_lower)]

    # Caching
    cache_patterns = {"Redis": r"\bredis\b", "Memcached": r"memcached", "In-memory": r"in.memory.cache|lru.cache"}
    caching = [c for c, pat in cache_patterns.items() if re.search(pat, text_lower)]

    # Queue systems
    queue_patterns = {
        "BullMQ": r"bullmq|bull\b", "Celery": r"\bcelery\b", "SQS": r"\bsqs\b",
        "Kafka": r"\bkafka\b", "RabbitMQ": r"rabbitmq", "NATS": r"\bnats\b",
        "Sidekiq": r"\bsidekiq\b", "Temporal": r"\btemporal\b",
    }
    queue_system = next((q for q, pat in queue_patterns.items() if re.search(pat, text_lower)), None)

    # Runtime environment
    runtime = []
    if inventory.get("dockerfiles"):
        runtime.append("Docker")
    if inventory.get("helm_charts"):
        runtime.append("Kubernetes")
    if inventory.get("terraform"):
        runtime.append("Cloud (Terraform)")
    if re.search(r"bare.metal|systemd|apt.get|yum install", text_lower):
        runtime.append("bare-metal")
    if re.search(r"serverless|lambda|cloud.function", text_lower):
        runtime.append("serverless")
    if not runtime:
        runtime.append("unknown")

    # Service model
    service_model = "unknown"
    if re.search(r"microservices|micro.services|service.mesh", text_lower):
        service_model = "microservices"
    elif re.search(r"monolith|single.service|all.in.one", text_lower):
        service_model = "monolith"
    elif re.search(r"worker|job.queue|background.process", text_lower):
        service_model = "monolith with worker processes"
    elif re.search(r"serverless|function.as.a.service", text_lower):
        service_model = "serverless"

    return {
        "languages": languages,
        "frameworks": frameworks,
        "databases": databases,
        "caching": caching,
        "queue_system": queue_system,
        "runtime": runtime,
        "service_model": service_model,
    }


# ---------------------------------------------------------------------------
# Phase 4: Security Architecture
# ---------------------------------------------------------------------------

def phase4_security(repo: Path, inventory: dict) -> dict[str, Any]:
    """Extract authentication, authorization, sandboxing, encryption, and policy."""
    print("[Phase 4] Security Architecture...")

    # Aggregate all relevant text
    search_paths = []
    for key in ["README.md", "SECURITY.md", "CONTRIBUTING.md"]:
        p = inventory.get(key)
        if p:
            search_paths.append(repo / p)
    if inventory.get("docs_directory"):
        search_paths += list((repo / "docs").rglob("*.md"))[:30]

    all_text = "\n".join(read_file(p) or "" for p in search_paths)
    text_lower = all_text.lower()

    # Authentication
    auth_patterns = {
        "JWT": r"\bjwt\b|json.web.token",
        "OAuth2": r"oauth2?|openid.connect|oidc",
        "SAML": r"\bsaml\b",
        "LDAP": r"\bldap\b",
        "API keys": r"api.key|apikey|x-api-key",
        "Machine tokens": r"machine.token|service.account|bot.token",
        "Magic links": r"magic.link|passwordless",
        "TOTP/MFA": r"\btotp\b|\bmfa\b|\b2fa\b|two.factor",
        "Basic Auth": r"basic.auth|http.basic",
    }
    authentication = [name for name, pat in auth_patterns.items() if re.search(pat, text_lower)]

    # Authorization
    authz_patterns = {
        "RBAC": r"\brbac\b|role.based.access",
        "ABAC": r"\babac\b|attribute.based.access",
        "CASL": r"\bcasl\b",
        "Casbin": r"\bcasbin\b",
        "OPA": r"\bopa\b|open.policy.agent",
        "Workspace-level": r"workspace.*permission|workspace.*role",
        "Organization-level": r"org.*permission|organization.*role",
    }
    authz_found = [name for name, pat in authz_patterns.items() if re.search(pat, text_lower)]
    authorization = " + ".join(authz_found) if authz_found else "unknown"

    # Sandboxing
    sandbox: dict[str, Any] = {}
    sandbox_patterns = {
        "nsjail": r"\bnsjail\b",
        "seccomp": r"\bseccomp\b",
        "apparmor": r"\bapparmor\b|app.armor",
        "selinux": r"\bselinux\b",
        "gvisor": r"\bgvisor\b",
        "firecracker": r"\bfirecracker\b",
        "kata_containers": r"kata.container",
        "pid_namespace": r"pid.namespace|pid_namespace",
        "network_namespace": r"network.namespace|net_namespace|netns",
        "agent_workers": r"agent.worker|worker.*no.*db|worker.*without.*database",
    }
    for tech, pattern in sandbox_patterns.items():
        matches = grep_lines(all_text, pattern)
        if matches:
            default_match = any(re.search(r"default|enabled.by.default|on.by.default", m[1], re.IGNORECASE) for m in matches)
            optional_match = any(re.search(r"optional|disabled.by.default|must.enable|can.enable", m[1], re.IGNORECASE) for m in matches)
            sandbox[tech] = {
                "available": True,
                "default": default_match and not optional_match,
                "evidence_lines": [m[1][:120] for m in matches[:3]],
            }

    # Encryption
    encryption: dict[str, str | None] = {}
    if re.search(r"encrypt.*at.rest|at.rest.*encrypt|disk.encrypt|storage.encrypt", text_lower):
        encryption["at_rest"] = "mentioned"
    else:
        encryption["at_rest"] = None
    if re.search(r"\btls\b|\bssl\b|\bhttps\b", text_lower):
        encryption["in_transit"] = "TLS/HTTPS mentioned"
    else:
        encryption["in_transit"] = None
    kms_match = re.search(r"\bkms\b|key.management|hashicorp.vault|\bvault\b", text_lower)
    encryption["key_management"] = "mentioned" if kms_match else None

    # Audit logging
    audit_logging = bool(re.search(r"audit.log|audit.trail|event.log|access.log.*audit", text_lower))

    # Rate limiting
    rl_patterns = {"present": r"rate.limit|throttl|ratelimit"}
    rate_limiting = "mentioned" if re.search(rl_patterns["present"], text_lower) else None

    # Input validation
    val_patterns = {
        "Zod": r"\bzod\b", "Joi": r"\bjoi\b", "Pydantic": r"\bpydantic\b",
        "class-validator": r"class.validator", "Yup": r"\byup\b",
        "jsonschema": r"jsonschema|json.schema", "OpenAPI validation": r"openapi.validation",
    }
    input_validation = next((name for name, pat in val_patterns.items() if re.search(pat, text_lower)), None)

    # Security policy
    security_policy_path = inventory.get("SECURITY.md")
    security_policy = "SECURITY.md exists" if security_policy_path else "MISSING — no vulnerability disclosure policy"

    if security_policy_path:
        sec_content = read_file(repo / security_policy_path) or ""
        has_email = bool(re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", sec_content))
        has_pgp = bool(re.search(r"pgp|gpg|-----begin pgp", sec_content.lower()))
        security_policy = f"SECURITY.md exists (email: {has_email}, PGP: {has_pgp})"

    # Certifications
    cert_patterns = {
        "SOC2": r"\bsoc.?2\b", "ISO27001": r"iso.?27001", "HIPAA": r"\bhipaa\b",
        "PCI DSS": r"pci.dss|pci.compliance", "GDPR": r"\bgdpr\b",
    }
    certifications = [name for name, pat in cert_patterns.items() if re.search(pat, text_lower)]

    # Known security features
    feature_patterns = {
        "WAF": r"\bwaf\b|web.application.firewall",
        "CSP": r"content.security.policy|\bcsp\b",
        "CORS": r"\bcors\b|cross.origin",
        "Helmet.js": r"\bhelmet\b",
        "CSRF protection": r"\bcsrf\b|cross.site.request.forgery",
        "SSRF protection": r"\bssrf\b",
        "SQL injection prevention": r"parameterized.quer|prepared.statement|sqlalchemy|typeorm|prisma",
        "Secrets scanning": r"gitleaks|trufflehog|detect.secrets|secret.scanning",
    }
    known_features = [name for name, pat in feature_patterns.items() if re.search(pat, text_lower)]

    return {
        "authentication": authentication or ["unknown"],
        "authorization": authorization,
        "sandboxing": sandbox,
        "encryption": encryption,
        "audit_logging": audit_logging,
        "rate_limiting": rate_limiting,
        "input_validation": input_validation,
        "security_policy": security_policy,
        "certifications": certifications,
        "known_security_features": known_features,
    }


# ---------------------------------------------------------------------------
# Phase 5: Deployment & Operations Security
# ---------------------------------------------------------------------------

def phase5_deployment(repo: Path, inventory: dict) -> dict[str, Any]:
    """Analyze Dockerfiles, docker-compose, Helm, and Terraform for security posture."""
    print("[Phase 5] Deployment & Operations Security...")

    result: dict[str, Any] = {
        "container_security": {},
        "compose_security": {},
        "helm_security": {},
        "terraform_findings": [],
        "environment_secrets": [],
        "known_gaps": [],
        "recommended_method": "unknown",
        "tls_configuration": None,
    }

    # --- Dockerfiles ---
    for df_rel in (inventory.get("infrastructure") or {}).get("dockerfiles", []):
        df_path = repo / df_rel
        content = read_file(df_path)
        if not content:
            continue
        cs = result["container_security"].setdefault(df_rel, {})

        user_directives = grep_lines(content, r"^USER\s+")
        cs["USER_directive"] = user_directives[0][1] if user_directives else "MISSING — runs as root by default"
        if not user_directives:
            result["known_gaps"].append(f"{df_rel}: No USER directive — container runs as root")

        from_matches = grep_lines(content, r"^FROM\s+")
        cs["base_images"] = [m[1] for m in from_matches]

        # Pinned digest check
        unpinned = [m[1] for m in from_matches if "@sha256:" not in m[1] and "scratch" not in m[1].lower()]
        if unpinned:
            cs["unpinned_base_images"] = unpinned

        expose_matches = grep_lines(content, r"^EXPOSE\s+")
        cs["exposed_ports"] = [m[1] for m in expose_matches]

        secret_in_env = grep_lines(content, r"^ENV\s+.*(SECRET|PASSWORD|KEY|TOKEN)\s*=", re.IGNORECASE)
        if secret_in_env:
            cs["secrets_in_env"] = [m[1] for m in secret_in_env]
            result["known_gaps"].append(f"{df_rel}: Secrets baked into ENV directives")

        cs["multi_stage"] = bool(re.search(r"^FROM.*AS\s+\w+", content, re.MULTILINE | re.IGNORECASE))

    # --- Docker Compose ---
    env_secret_pattern = re.compile(
        r"(DATABASE_URL|DB_PASS|DB_PASSWORD|SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|PRIVATE|API_KEY|OAUTH)",
        re.IGNORECASE,
    )

    for dc_rel in (inventory.get("infrastructure") or {}).get("docker_compose", []):
        dc_path = repo / dc_rel
        content = read_file(dc_path)
        if not content:
            continue
        try:
            data = yaml.safe_load(content) or {}
        except yaml.YAMLError:
            result["compose_security"][dc_rel] = {"error": "YAML parse failed"}
            continue

        cs = result["compose_security"].setdefault(dc_rel, {})
        services = data.get("services") or {}

        has_privileged = False
        cap_adds = []
        read_only_services = []
        env_vars_found = []
        security_opts = []

        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            if svc.get("privileged"):
                has_privileged = True
                result["known_gaps"].append(f"{dc_rel}/{svc_name}: privileged: true — full host access")
            caps = svc.get("cap_add", [])
            if caps:
                cap_adds.extend([f"{svc_name}: {c}" for c in caps])
            if svc.get("read_only"):
                read_only_services.append(svc_name)
            svc_env = svc.get("environment") or {}
            if isinstance(svc_env, list):
                for e in svc_env:
                    if isinstance(e, str) and env_secret_pattern.search(e):
                        env_vars_found.append(e.split("=")[0])
            elif isinstance(svc_env, dict):
                for k in svc_env:
                    if env_secret_pattern.search(k):
                        env_vars_found.append(k)
            sopts = svc.get("security_opt", [])
            security_opts.extend(sopts)

        cs["privileged_service"] = has_privileged
        cs["cap_add"] = cap_adds
        cs["read_only_services"] = read_only_services
        cs["security_opts"] = security_opts
        result["environment_secrets"] = list(set(result["environment_secrets"] + env_vars_found))

        # Networks
        networks = data.get("networks") or {}
        cs["custom_networks"] = list(networks.keys())

        # Recommended method heuristic
        if "caddy" in content.lower() or "traefik" in content.lower():
            result["recommended_method"] = "Docker Compose with reverse proxy"
            result["tls_configuration"] = "Reverse proxy handles TLS (Caddy/Traefik auto-TLS)"
        elif "nginx" in content.lower():
            result["recommended_method"] = "Docker Compose with NGINX"
            result["tls_configuration"] = "NGINX reverse proxy — TLS config not confirmed"
        else:
            result["recommended_method"] = "Docker Compose (direct)"

        if cap_adds and any("SYS_ADMIN" in c or "NET_ADMIN" in c for c in cap_adds):
            result["known_gaps"].append(f"{dc_rel}: Dangerous capabilities added: {cap_adds}")

    # --- Helm ---
    for helm_rel in (inventory.get("infrastructure") or {}).get("helm_charts", []):
        if "values.yaml" not in helm_rel:
            continue
        helm_path = repo / helm_rel
        content = read_file(helm_path)
        if not content:
            continue
        try:
            data = yaml.safe_load(content) or {}
        except yaml.YAMLError:
            continue

        hc = result["helm_security"].setdefault(helm_rel, {})
        sc = data.get("securityContext") or data.get("podSecurityContext") or {}
        hc["runAsNonRoot"] = sc.get("runAsNonRoot", "not set")
        hc["readOnlyRootFilesystem"] = sc.get("readOnlyRootFilesystem", "not set")
        hc["allowPrivilegeEscalation"] = sc.get("allowPrivilegeEscalation", "not set")

        if sc.get("runAsNonRoot") is False:
            result["known_gaps"].append(f"{helm_rel}: runAsNonRoot=false in Helm values")

        resource_limits = data.get("resources") or {}
        hc["resource_limits_set"] = bool(resource_limits.get("limits"))
        if not resource_limits.get("limits"):
            result["known_gaps"].append(f"{helm_rel}: No resource limits — DoS risk")

    # --- Terraform ---
    tf_findings = []
    for tf_rel in (inventory.get("infrastructure") or {}).get("terraform", []):
        tf_path = repo / tf_rel
        content = read_file(tf_path)
        if not content:
            continue

        # Unrestricted egress
        if re.search(r'egress.*?cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', content, re.DOTALL):
            tf_findings.append({
                "file": tf_rel,
                "finding": "unrestricted_egress",
                "severity": "HIGH",
                "detail": "Security group allows all outbound traffic (0.0.0.0/0)",
            })

        # Open ingress
        open_ingress = re.findall(
            r'ingress\s*\{[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\][^}]*\}', content, re.DOTALL
        )
        for match in open_ingress:
            port_match = re.search(r"from_port\s*=\s*(\d+)", match)
            port = port_match.group(1) if port_match else "unknown"
            if port not in ("80", "443"):
                tf_findings.append({
                    "file": tf_rel,
                    "finding": "open_ingress",
                    "severity": "CRITICAL",
                    "detail": f"Open ingress from 0.0.0.0/0 on port {port}",
                })

        # HTTP-only load balancer
        if re.search(r'protocol\s*=\s*"HTTP"', content) and re.search(r"aws_alb_listener|aws_lb_listener", content):
            tf_findings.append({
                "file": tf_rel,
                "finding": "alb_http_only",
                "severity": "HIGH",
                "detail": "ALB listener configured with HTTP only, no HTTPS redirect",
            })

        # Public RDS
        if re.search(r"publicly_accessible\s*=\s*true", content):
            tf_findings.append({
                "file": tf_rel,
                "finding": "rds_publicly_accessible",
                "severity": "CRITICAL",
                "detail": "RDS instance is publicly accessible",
            })

        # S3 public access
        if re.search(r"block_public_acls\s*=\s*false|block_public_policy\s*=\s*false", content):
            tf_findings.append({
                "file": tf_rel,
                "finding": "s3_public_access",
                "severity": "HIGH",
                "detail": "S3 bucket has public access blocks disabled",
            })

        # Unencrypted storage
        if re.search(r"aws_rds_instance|aws_db_instance", content) and not re.search(r"storage_encrypted\s*=\s*true", content):
            tf_findings.append({
                "file": tf_rel,
                "finding": "rds_unencrypted",
                "severity": "MEDIUM",
                "detail": "RDS instance does not explicitly enable storage_encrypted = true",
            })

    result["terraform_findings"] = tf_findings

    # Deduplicate known_gaps
    result["known_gaps"] = list(dict.fromkeys(result["known_gaps"]))

    return result


# ---------------------------------------------------------------------------
# Phase 6: API Surface
# ---------------------------------------------------------------------------

def phase6_api_surface(repo: Path, inventory: dict) -> dict[str, Any]:
    """Detect public vs. authenticated endpoints, file uploads, webhooks."""
    print("[Phase 6] API Surface...")

    api: dict[str, Any] = {
        "public_endpoints": [],
        "admin_endpoints": [],
        "file_upload": False,
        "webhooks": False,
        "graphql": False,
        "api_versioning": None,
        "rate_limiting": None,
        "route_files_scanned": [],
    }

    # OpenAPI / Swagger
    for spec_rel in (inventory.get("infrastructure") or {}).get("openapi", []):
        spec_path = repo / spec_rel
        content = read_file(spec_path)
        if not content:
            continue
        try:
            spec = yaml.safe_load(content) if spec_rel.endswith((".yaml", ".yml")) else json.loads(content)
        except Exception:
            continue

        paths = spec.get("paths") or {}
        for endpoint, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if not isinstance(details, dict):
                    continue
                security = details.get("security")
                tags = details.get("tags", [])
                is_public = security == [] or security is None
                is_admin = any("admin" in t.lower() for t in tags) or "/admin" in endpoint
                if is_public:
                    api["public_endpoints"].append(f"{method.upper()} {endpoint}")
                if is_admin:
                    api["admin_endpoints"].append(f"{method.upper()} {endpoint}")

        # Check versioning
        if "/v1/" in str(paths.keys()) or "/v2/" in str(paths.keys()):
            api["api_versioning"] = "URL path versioning detected"

    # Scan route files
    route_patterns = [
        ("*.routes.ts", r'(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', "Express/Fastify"),
        ("*.routes.js", r'(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', "Express/Fastify"),
        ("routes.py", r'@.*route\s*\(\s*["\']([^"\']+)["\']', "Flask"),
        ("router.py", r'@.*\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', "FastAPI"),
        ("routes.rb", r'(get|post|put|delete|patch)\s+["\']([^"\']+)["\']', "Rails"),
    ]

    skip_dirs = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build", "test", "tests", "spec"}
    scanned = 0

    for pattern, regex, framework in route_patterns:
        for route_file in repo.rglob(pattern):
            if any(d in route_file.parts for d in skip_dirs):
                continue
            if scanned >= 20:
                break
            content = read_file(route_file)
            if not content:
                continue
            api["route_files_scanned"].append(str(route_file.relative_to(repo)))
            scanned += 1

            for match in re.finditer(regex, content, re.IGNORECASE):
                endpoint = match.group(2) if len(match.groups()) >= 2 else match.group(1)
                if "admin" in endpoint.lower():
                    api["admin_endpoints"].append(endpoint)
                if "upload" in endpoint.lower() or "file" in endpoint.lower():
                    api["file_upload"] = True
                if "webhook" in endpoint.lower():
                    api["webhooks"] = True

    # Scan all source files for auth middleware patterns
    auth_middleware_found = False
    graphql_found = False
    rate_limit_found = False

    source_exts = {".ts", ".js", ".py", ".go", ".rs", ".rb", ".php"}
    for path in repo.rglob("*"):
        if path.suffix not in source_exts:
            continue
        if any(d in path.parts for d in skip_dirs):
            continue
        content = read_file(path)
        if not content:
            continue
        content_lower = content.lower()
        if re.search(r"graphql|apollo.server|graphene|strawberry", content_lower):
            graphql_found = True
        if re.search(r"rate.limit|ratelimit|throttl", content_lower):
            rate_limit_found = True
        if re.search(r"requireauth|isauthentic|jwt.verify|decode.token|@login_required|authmiddleware", content_lower):
            auth_middleware_found = True

    api["graphql"] = graphql_found
    api["rate_limiting"] = "detected in codebase" if rate_limit_found else None
    api["auth_middleware_detected"] = auth_middleware_found

    # Deduplicate
    api["public_endpoints"] = list(dict.fromkeys(api["public_endpoints"]))[:20]
    api["admin_endpoints"] = list(dict.fromkeys(api["admin_endpoints"]))[:20]

    return api


# ---------------------------------------------------------------------------
# Phase 8: Profile Compilation
# ---------------------------------------------------------------------------

def compile_profile(repo: Path, phases: dict[str, Any]) -> dict[str, Any]:
    """Compile all phase results into the final JSON profile."""
    p1 = phases.get("phase1", {})
    p2 = phases.get("phase2", {})
    p3 = phases.get("phase3", {})
    p4 = phases.get("phase4", {})
    p5 = phases.get("phase5", {})
    p6 = phases.get("phase6", {})

    # Docs completeness
    inventory = p1.get("inventory", {})
    missing = p1.get("missing", [])
    if len(missing) == 0:
        completeness = "complete"
    elif len(missing) <= 2:
        completeness = "partial"
    else:
        completeness = "minimal"

    repo_name = repo.name.replace("-", " ").replace("_", " ").title()

    # Build vulnerability_context_adjustments from terraform findings
    adjustments = []
    for tf in (p5.get("terraform_findings") or []):
        finding = tf["finding"]
        sev = tf["severity"]
        from_risk = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0}.get(sev, 5.0)

        # Check for mitigating factors
        sandboxing = p4.get("sandboxing") or {}
        adjustment_type = "CONFIRMED"
        to_risk = from_risk
        reason = tf["detail"]

        if finding == "unrestricted_egress" and (sandboxing.get("nsjail") or sandboxing.get("network_namespace")):
            adjustment_type = "DOWNGRADE"
            to_risk = round(from_risk - 1.5, 1)
            reason = (
                f"{tf['detail']}. However, sandboxing controls detected "
                f"({', '.join(k for k in sandboxing)}). "
                "Verify whether sandbox network isolation is enabled by default."
            )

        adjustments.append({
            "finding_category": finding,
            "adjustment": adjustment_type,
            "from_risk": from_risk,
            "to_risk": to_risk,
            "reason": reason,
            "evidence": tf["file"],
        })

    # Flag missing documentation as findings
    for missing_doc in missing:
        if missing_doc == "SECURITY.md":
            adjustments.append({
                "finding_category": "missing_security_policy",
                "adjustment": "UPGRADE",
                "from_risk": 0.0,
                "to_risk": 3.0,
                "reason": "No SECURITY.md found. Absence of vulnerability disclosure policy is a maturity gap.",
                "evidence": "Repository root — file not present",
            })

    profile = {
        "product_context": {
            "name": repo_name,
            "description": p2.get("description", "Description not extracted — README may be missing or non-standard"),
            "deployment_models": p2.get("deployment_models", ["unknown"]),
            "target_audience": p2.get("target_audience", ["unknown"]),
            "pricing_model": p2.get("pricing_model", "unknown"),
            "maturity": {
                "stars": p2.get("stars"),
                "docs_site": p2.get("docs_site"),
            },
            "docs_completeness": completeness,
            "missing_docs": missing,
        },
        "architecture": {
            "languages": p3.get("languages", []),
            "frameworks": p3.get("frameworks", {}),
            "databases": p3.get("databases", []),
            "caching": p3.get("caching", []),
            "queue_system": p3.get("queue_system"),
            "runtime": p3.get("runtime", []),
            "service_model": p3.get("service_model", "unknown"),
        },
        "security_controls": {
            "authentication": p4.get("authentication", ["unknown"]),
            "authorization": p4.get("authorization", "unknown"),
            "sandboxing": p4.get("sandboxing", {}),
            "encryption": p4.get("encryption", {}),
            "audit_logging": p4.get("audit_logging", False),
            "rate_limiting": p4.get("rate_limiting"),
            "input_validation": p4.get("input_validation"),
            "security_policy": p4.get("security_policy", "MISSING"),
            "certifications": p4.get("certifications", []),
            "known_security_features": p4.get("known_security_features", []),
        },
        "deployment_security": {
            "recommended_method": p5.get("recommended_method", "unknown"),
            "tls_configuration": p5.get("tls_configuration"),
            "container_security": p5.get("container_security", {}),
            "helm_security": p5.get("helm_security", {}),
            "terraform_findings": p5.get("terraform_findings", []),
            "environment_secrets": p5.get("environment_secrets", []),
            "known_gaps": p5.get("known_gaps", []),
        },
        "api_surface": {
            "public_endpoints": p6.get("public_endpoints", []),
            "admin_endpoints": p6.get("admin_endpoints", []),
            "file_upload": p6.get("file_upload", False),
            "webhooks": p6.get("webhooks", False),
            "graphql": p6.get("graphql", False),
            "api_versioning": p6.get("api_versioning"),
            "rate_limiting": p6.get("rate_limiting"),
            "auth_middleware_detected": p6.get("auth_middleware_detected", False),
        },
        "external_docs": {
            "docs_site": p2.get("docs_site"),
            "note": "Phase 7 (external docs fetch) requires manual agent invocation of fetch_url",
            "fetched_pages": [],
            "unfetched_recommended": [],
        },
        "vulnerability_context_adjustments": adjustments,
    }

    return profile


# ---------------------------------------------------------------------------
# Markdown Summary
# ---------------------------------------------------------------------------

def generate_summary(profile: dict[str, Any]) -> str:
    """Generate a human-readable markdown summary from the profile."""
    pc = profile["product_context"]
    arch = profile["architecture"]
    sec = profile["security_controls"]
    dep = profile["deployment_security"]
    api = profile["api_surface"]
    adjustments = profile["vulnerability_context_adjustments"]

    lines = [
        f"# Documentation Intelligence Report: {pc['name']}",
        "",
        "## Product Overview",
        "",
        f"**Description**: {pc['description']}",
        "",
        f"**Deployment Models**: {', '.join(pc['deployment_models'])}",
        f"**Target Audience**: {', '.join(pc['target_audience'])}",
        f"**Pricing**: {pc['pricing_model']}",
        f"**Documentation Completeness**: {pc['docs_completeness']}",
    ]

    if pc["missing_docs"]:
        lines += ["", "**Missing Documentation**:"]
        for m in pc["missing_docs"]:
            lines.append(f"- {m}")

    lines += [
        "",
        "## Architecture",
        "",
        f"**Languages**: {', '.join(arch['languages']) or 'unknown'}",
        f"**Backend Framework**: {arch['frameworks'].get('backend', 'unknown')}",
        f"**Frontend Framework**: {arch['frameworks'].get('frontend', 'unknown')}",
        f"**Databases**: {', '.join(arch['databases']) or 'none detected'}",
        f"**Runtime**: {', '.join(arch['runtime'])}",
        f"**Service Model**: {arch['service_model']}",
        "",
        "## Security Architecture Summary",
        "",
        f"**Authentication**: {', '.join(sec['authentication'])}",
        f"**Authorization**: {sec['authorization']}",
        f"**Audit Logging**: {'Yes' if sec['audit_logging'] else 'Not confirmed'}",
        f"**Rate Limiting**: {sec['rate_limiting'] or 'Not confirmed'}",
        f"**Input Validation**: {sec['input_validation'] or 'Not confirmed'}",
        f"**Security Policy**: {sec['security_policy']}",
        f"**Certifications**: {', '.join(sec['certifications']) or 'None mentioned'}",
    ]

    if sec["sandboxing"]:
        lines += ["", "**Sandboxing/Isolation Detected**:"]
        for tech, info in sec["sandboxing"].items():
            default_str = "default" if info.get("default") else "opt-in"
            lines.append(f"- **{tech}**: available ({default_str})")

    if sec["known_security_features"]:
        lines += ["", f"**Known Security Features**: {', '.join(sec['known_security_features'])}"]

    lines += [
        "",
        "## Deployment Security",
        "",
        f"**Recommended Method**: {dep['recommended_method']}",
        f"**TLS Configuration**: {dep['tls_configuration'] or 'Not documented'}",
    ]

    if dep["environment_secrets"]:
        lines += [f"**Secret Environment Variables**: {', '.join(dep['environment_secrets'][:10])}"]

    if dep["known_gaps"]:
        lines += ["", "**Known Security Gaps**:"]
        for gap in dep["known_gaps"]:
            lines.append(f"- {gap}")

    lines += [
        "",
        "## API Surface",
        "",
        f"**File Upload Endpoints**: {'Yes' if api['file_upload'] else 'Not detected'}",
        f"**Webhook Receivers**: {'Yes' if api['webhooks'] else 'Not detected'}",
        f"**GraphQL**: {'Yes' if api['graphql'] else 'No'}",
        f"**Auth Middleware**: {'Detected' if api['auth_middleware_detected'] else 'Not confirmed'}",
        f"**API Versioning**: {api['api_versioning'] or 'Not detected'}",
    ]

    if api["admin_endpoints"]:
        lines += ["", "**Admin Endpoints Detected**:"]
        for ep in api["admin_endpoints"][:10]:
            lines.append(f"- `{ep}`")

    lines += ["", "## Vulnerability Context Adjustments", ""]

    if not adjustments:
        lines.append("No automated adjustments generated. Review terraform_findings and known_gaps manually.")
    else:
        for adj in adjustments:
            icon = {"DOWNGRADE": "↓", "UPGRADE": "↑", "CONFIRMED": "✓", "NEEDS_MORE_INFO": "?"}.get(
                adj["adjustment"], "?"
            )
            lines += [
                f"### {icon} {adj['finding_category']} — {adj['adjustment']}",
                "",
                f"**Risk**: {adj['from_risk']} → {adj['to_risk']}",
                f"**Reason**: {adj['reason']}",
                f"**Evidence**: `{adj['evidence']}`",
                "",
            ]

    docs_site = profile["external_docs"].get("docs_site")
    lines += [
        "## Phase 7: External Documentation (Manual Step Required)",
        "",
        f"**Docs Site**: {docs_site or 'Not detected in README'}",
        "",
        "Use `fetch_url` on the following page types if available:",
        "- Security hardening guide",
        "- Self-hosting documentation",
        "- Authentication configuration",
        "- API reference",
        "- Network/firewall requirements",
        "",
        "---",
        "",
        "_Generated by doc-intelligence-agent scripts/analyze-docs.py_",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Documentation Intelligence Agent — Phases 1-6 automated analysis"
    )
    parser.add_argument("--repo-path", required=True, help="Path to the repository root")
    parser.add_argument("--output", required=True, help="Output directory for doc-profile.json and doc-summary.md")
    args = parser.parse_args()

    repo = Path(args.repo_path).resolve()
    output = Path(args.output).resolve()

    if not repo.exists():
        print(f"ERROR: Repository path does not exist: {repo}", file=sys.stderr)
        sys.exit(1)

    output.mkdir(parents=True, exist_ok=True)
    print(f"Analyzing repository: {repo}")
    print(f"Output directory:     {output}")
    print()

    # Run all phases
    p1 = phase1_surface_scan(repo)
    inventory = p1["inventory"]

    p2 = phase2_product_identity(repo, inventory)
    p3 = phase3_architecture(repo, inventory)
    p4 = phase4_security(repo, inventory)
    p5 = phase5_deployment(repo, inventory)
    p6 = phase6_api_surface(repo, inventory)

    phases = {"phase1": p1, "phase2": p2, "phase3": p3, "phase4": p4, "phase5": p5, "phase6": p6}

    print()
    print("[Phase 8] Compiling Security Context Profile...")
    profile = compile_profile(repo, phases)

    # Write outputs
    profile_path = output / "doc-profile.json"
    summary_path = output / "doc-summary.md"

    with open(profile_path, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2, default=str)

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(generate_summary(profile))

    print(f"  Written: {profile_path}")
    print(f"  Written: {summary_path}")
    print()
    print("Done. Next steps:")
    print("  1. Review doc-profile.json for completeness")
    print("  2. Run Phase 7 manually: use fetch_url on docs site pages listed in profile")
    print("  3. Refine vulnerability_context_adjustments with agent judgment")

    if p1.get("missing"):
        print()
        print(f"WARNING: Missing documentation: {', '.join(p1['missing'])}")
        print("  Missing security docs are themselves findings — document in your assessment.")


if __name__ == "__main__":
    main()
