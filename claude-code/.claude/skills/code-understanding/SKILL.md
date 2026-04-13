# Code Understanding Agent

Adversarial code comprehension. Four analysis modes targeting different aspects of security-relevant code analysis.

Invoke with `/code-understanding` or `--map`, `--trace`, `--hunt`, `--teach` flags.

## When to Use

- `--map`: Map the attack surface of a codebase (entry points, trust boundaries, sinks)
- `--trace`: Trace a specific data flow from user input to a dangerous operation
- `--hunt`: Hunt for variants of a known vulnerability pattern across a codebase
- `--teach`: Explain the security model or common pitfalls of a framework or library

## Mode 1: `--map` (Attack Surface Mapping)

**Enumerate entry points:**
- HTTP route handlers (REST, GraphQL, WebSocket, SSE)
- CLI argument parsers
- File upload handlers
- Webhook receivers
- Message queue consumers (Kafka, RabbitMQ, SQS, NATS)
- Environment variable readers at startup
- gRPC service implementations

**Classify trust boundaries:**
- `external→app`: unauthenticated internet traffic
- `authenticated` vs `unauthenticated`
- `admin` vs `user` privilege levels

**Catalog dangerous sinks:**
- Raw SQL query construction
- OS command / shell execution
- File path construction from user input
- Template rendering without autoescaping
- Deserialization of untrusted data
- Outbound network calls with user-influenced URL (SSRF)

**Flow status:**
- `UNCHECKED`: no validation between entry point and sink
- `PARTIAL`: some validation present but potentially bypassable
- `SANITIZED`: validation appears sufficient

**Output:** `./code-understanding/context-map.json` + summary table: Entry Point → Trust Boundary → Sink → Status

## Mode 2: `--trace` (Data Flow Tracing)

Trace a specific data flow hop-by-hop. At each hop record:
- Function name and `file:line`
- Variable name(s) carrying the tainted value
- Whether attacker fully controls / partially controls / cannot control the value
- Any validation, sanitization, or encoding applied

**Taint propagation rules:**
- String concatenation, interpolation → **taint propagates**
- Parameterized queries, allowlist checks, integer coercion → **taint blocked**
- Base64 encode/decode, URL encode/decode → **taint propagates** (encoding ≠ sanitization)

**Flow classification:**
- `EXPLOITABLE`: tainted data reaches sink without sufficient sanitization
- `CONDITIONAL`: reaches sink only under specific conditions
- `BLOCKED`: sanitization is sufficient
- `UNCLEAR`: insufficient information

**Output:** `./code-understanding/flow-traces/flow-trace-{id}.json`

## Mode 3: `--hunt` (Variant Hunting)

1. **Characterize the seed vulnerability** (class, coding construct, bypass techniques)
2. **Structural search** — literal pattern matches (same function calls, same sink type)
3. **Semantic search** — functionally equivalent code (aliases, wrappers, indirect sinks)
4. **Root cause analysis** — underlying pattern shared by all variants
5. **Risk-rank each variant:** CRITICAL/HIGH/MEDIUM/LOW

**Output:** `./code-understanding/variants.json` + inline table

## Mode 4: `--teach` (Framework Security Explanation)

1. Explain the security model (default guarantees, developer responsibilities, where it breaks down)
2. Common pitfalls — top 5-10 misuses with vulnerable + secure code examples
3. Framework-specific CVEs with root cause explanations
4. Safe usage patterns (copy-paste-ready guidance)

**Output:** Inline markdown explanation

## Output File Conventions

| Mode | Output |
|------|--------|
| `--map` | `code-understanding/context-map.json` |
| `--trace` | `code-understanding/flow-traces/flow-trace-{id}.json` |
| `--hunt` | `code-understanding/variants.json` |
| `--teach` | inline markdown only |

## Quality Standards

- Always cite `file:line` for every finding
- If you cannot determine a flow with certainty, classify it `UNCLEAR` and document what's missing
- For `--hunt`, cast a wide net first (structural), then narrow semantically
