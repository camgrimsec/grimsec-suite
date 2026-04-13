---
name: code-understanding-agent
description: >
  GRIMSEC Agent 9 — adversarial code comprehension for the DevSecOps suite.
  Use when asked to map attack surfaces, trace data flows from source to sink,
  hunt for vulnerability variants, or explain the security model of a framework.
  Trigger phrases: understand code, map attack surface, trace dataflow, hunt
  variants, explain framework security, /understand, code comprehension, entry
  points, dangerous sinks, taint analysis, reachability analysis.
license: MIT
metadata:
  author: GRIMSEC
  version: '1.0'
  suite-position: '9'
  inspired-by: Raptor /understand command
  reads: inventory.json, app-context.json
  writes: code-understanding/context-map.json, code-understanding/flow-traces/, code-understanding/variants.json
  feeds-into: devsecops-repo-analyzer Stage 4, exploit-validation-agent, executive-reporting-agent
---

# Code Understanding Agent

## When to Use This Skill

Load this skill when asked to:

- Map the attack surface of a codebase (entry points, trust boundaries, sinks)
- Trace a specific data flow from user input to a dangerous operation
- Hunt for variants of a known vulnerability pattern across a codebase
- Explain the security model or common pitfalls of a framework or library
- Integrate with the GRIMSEC suite (reads `inventory.json` / `app-context.json`)
- Perform any command prefixed with `--map`, `--trace`, `--hunt`, or `--teach`

## GRIMSEC Integration

| Source | File | Used By |
|--------|------|---------|
| devsecops-repo-analyzer Stage 1 | `inventory.json` | context for --map |
| devsecops-repo-analyzer Stage 2 | `app-context.json` | enriched analysis |
| **This agent outputs** | `code-understanding/context-map.json` | Stage 4 reachability |
| **This agent outputs** | `code-understanding/flow-traces/*.json` | exploit-validation-agent |
| **This agent outputs** | `code-understanding/variants.json` | executive-reporting-agent |

When `inventory.json` or `app-context.json` is present in the workspace, load them before running any mode to enrich analysis.

## Reference Files

Load the relevant reference file before each mode:

- `references/entry-points.md` — common entry points by framework (Go, TypeScript/Node, Python, Rust, Java)
- `references/dangerous-sinks.md` — dangerous sinks by language/category
- `references/variant-patterns.md` — structural and semantic patterns for variant hunting
- `assets/templates/context-map-template.json` — output schema for --map mode

## Analysis Modes

---

### Mode 1: `--map` (Attack Surface Mapping)

**Trigger:** User asks to map the attack surface, enumerate entry points, or understand where the application receives external input.

**Load:** `references/entry-points.md`, `references/dangerous-sinks.md`, `assets/templates/context-map-template.json`

**Steps:**

1. **Enumerate all entry points** — read the codebase and identify every location where external, attacker-controlled data enters the application:
   - HTTP route handlers (REST, GraphQL, WebSocket, SSE)
   - CLI argument parsers
   - File upload handlers and multipart form processors
   - Webhook receivers
   - Message queue consumers (Kafka, RabbitMQ, SQS, NATS, Redis Streams)
   - Environment variable readers at startup
   - gRPC service implementations
   - Cron/scheduled job triggers that read external data
   - IPC sockets and named pipes

2. **Identify trust boundaries** — for each entry point, classify:
   - `external→app`: unauthenticated internet traffic
   - `app→db`: application to data store
   - `service→service`: internal microservice calls
   - `authenticated` vs `unauthenticated` paths
   - `admin` vs `user` privilege levels
   - Third-party integrations (OAuth callbacks, webhook senders)

3. **Catalog dangerous sinks** — scan for all locations where data is consumed in a dangerous way. Use `references/dangerous-sinks.md` for the full catalog. Prioritize:
   - Raw SQL query construction
   - OS command / shell execution
   - File path construction from user input
   - Template rendering without autoescaping
   - Deserialization of untrusted data
   - Cryptographic operations with user-controlled parameters
   - Outbound network calls whose URL is user-influenced (SSRF)

4. **Map unchecked flows** — for each entry point, determine if a path exists to a dangerous sink without adequate validation. Mark flows as:
   - `UNCHECKED`: no validation found between entry point and sink
   - `PARTIAL`: some validation present but potentially bypassable
   - `SANITIZED`: validation appears sufficient (document what mechanism)

5. **Output** — write `code-understanding/context-map.json` following the schema in `assets/templates/context-map-template.json`. Also produce a human-readable summary table showing: Entry Point → Trust Boundary → Sink → Status.

**Script helper:** `scripts/map-attack-surface.py` — run to enumerate entry points and sinks programmatically when the codebase is available on disk.

---

### Mode 2: `--trace` (Data Flow Tracing)

**Trigger:** User asks to trace a specific data flow, follow user input through the code, perform taint analysis, or answer "does attacker-controlled data reach X?"

**Load:** `references/dangerous-sinks.md`

**Steps:**

1. **Select the entry point** — identify the specific function/route to trace (e.g., `POST /api/query`, `handleUpload()`, CLI flag `--config`).

2. **Trace hop-by-hop** — follow the data through every function call, transformation, and branch. At each hop record:
   - Function name and file:line reference
   - Variable name(s) carrying the tainted value
   - Whether the attacker fully controls, partially controls, or cannot control the value at this point
   - Any validation, sanitization, or encoding applied
   - Whether the sanitization is sufficient or bypassable

3. **Identify taint propagation** — determine if attacker-controlled data survives transformations:
   - String concatenation, interpolation, format strings: taint propagates
   - Parameterized queries, allowlist checks, type coercion to integer: taint blocked
   - Base64 encode/decode, URL encode/decode: taint propagates (encoding ≠ sanitization)
   - JSON.stringify of a primitive: may break taint depending on context

4. **Document branch conditions** — record every `if`/`switch`/`match` that affects whether tainted data reaches a sink. State precisely what conditions must hold for the taint to reach the sink (i.e., the exploit preconditions).

5. **Classify the flow:**
   - `EXPLOITABLE`: tainted data reaches sink without sufficient sanitization
   - `CONDITIONAL`: reaches sink only under specific conditions (document them)
   - `BLOCKED`: sanitization is sufficient — document why
   - `UNCLEAR`: insufficient information to determine — document what's missing

6. **Output** — write `code-understanding/flow-traces/flow-trace-{id}.json` with the full hop sequence, and produce an inline summary:  
   `Entry → hop1 → hop2 → ... → Sink [STATUS]`

**Script helper:** `scripts/trace-dataflow.py` — assists with AST-based tracing when the codebase is on disk.

---

### Mode 3: `--hunt` (Variant Hunting)

**Trigger:** User asks to find variants of a vulnerability, look for similar bugs, check if a CVE pattern appears elsewhere in the codebase, or perform root-cause analysis.

**Load:** `references/variant-patterns.md`

**Steps:**

1. **Characterize the seed vulnerability** — extract the essential pattern:
   - Vulnerability class (SQLi, SSRF, path traversal, command injection, etc.)
   - The specific coding construct that enables it (e.g., string concatenation in SQL, `os.Open` on user-supplied path)
   - Any bypass techniques or edge cases already known

2. **Structural search** — find all code locations that literally match the pattern:
   - Same function calls, same variable flow, same sink type
   - Use grep-style matching augmented by AST awareness where possible
   - Record every match with file:line and a code snippet

3. **Semantic search** — find functionally equivalent code that doesn't match the literal pattern:
   - Different function names, different languages, different frameworks — same vulnerability class
   - Aliases and wrappers (custom database helpers that internally do raw queries)
   - Indirect sinks (data stored in DB, then read and executed elsewhere)
   - Use `references/variant-patterns.md` for known semantic equivalents per vulnerability class

4. **Root cause analysis** — identify the underlying coding pattern shared by all variants:
   - Missing abstraction (devs bypassed the ORM for "performance")
   - Trust assumption mismatch (treating internal service input as safe)
   - Incomplete allowlist (one path sanitized, sister paths missed)
   - Document the root cause in one clear sentence

5. **Risk-rank each variant:**
   - `CRITICAL`: direct exploitability, no auth required
   - `HIGH`: exploitable with authentication or minor conditions
   - `MEDIUM`: exploitable but constrained
   - `LOW`: pattern present but likely mitigated by other controls

6. **Output** — write `code-understanding/variants.json` with the full variant list, and produce an inline table: File:Line | Snippet | Class | Risk.

---

### Mode 4: `--teach` (Framework Explanation)

**Trigger:** User asks to explain how a framework or library works from a security perspective, what pitfalls exist, or how to use it safely.

**Steps:**

1. **Identify the framework/library** — name, version (if specified), and language ecosystem.

2. **Explain the security model:**
   - What security guarantees does the framework make by default?
   - What must the developer do explicitly to be secure?
   - Where does the framework's security model break down?

3. **Common pitfalls** — document the top 5–10 ways developers misuse this framework and introduce vulnerabilities. For each:
   - Name the pitfall
   - Show a vulnerable code example
   - Show the secure alternative

4. **Framework-specific vulnerabilities** — list CVEs or well-known vulnerability classes associated with this framework, with brief explanations of root cause.

5. **Safe usage patterns** — provide concise, copy-paste-ready guidance for the most dangerous operations: parameterized queries, safe file handling, input validation, authentication middleware, etc.

6. **Output** — inline explanation (no JSON output). Organize as: Security Model → Common Pitfalls → Known Vulns → Safe Patterns.

---

## Output File Conventions

| Mode | Output Path | Format |
|------|-------------|--------|
| `--map` | `code-understanding/context-map.json` | JSON (schema: context-map-template.json) |
| `--trace` | `code-understanding/flow-traces/flow-trace-{id}.json` | JSON |
| `--hunt` | `code-understanding/variants.json` | JSON |
| `--teach` | inline only | Markdown |

All JSON outputs must be machine-readable by downstream GRIMSEC agents. Follow the schema in `assets/templates/context-map-template.json` for `--map` output, and mirror the structure for `--trace` and `--hunt`.

## Invocation Examples

```
--map ./src/                          # map the full attack surface of ./src
--trace "POST /api/query"             # trace a specific route
--hunt "SQL injection via fmt.Sprintf" # hunt for variants of a known pattern
--teach "ClickHouse Go client"        # explain security model of a library
```

## Quality Standards

- Always cite file:line for every finding
- Do not speculate — if you cannot determine a flow with certainty, classify it `UNCLEAR` and document what's missing
- For `--map` and `--trace`, prefer reading actual code over making assumptions
- For `--hunt`, cast a wide net first (structural), then narrow semantically
- For `--teach`, ground explanations in real CVEs and documented pitfalls where possible
