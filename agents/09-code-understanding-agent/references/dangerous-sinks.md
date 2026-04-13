# Dangerous Sinks Reference

Dangerous operations that consume attacker-controlled data. Load this file when running `--map` or `--trace` mode.

For each sink: the vulnerability class, detection patterns, why it's dangerous, and what constitutes a real control.

---

## SQL — Raw Query Construction

**Vulnerability class:** SQL Injection

### Detection patterns

| Language | Pattern | Example |
|----------|---------|---------|
| Go | `db.Query(fmt.Sprintf(...))` | `db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))` |
| Go | `db.Exec(fmt.Sprintf(...))` | `db.Exec(fmt.Sprintf("DELETE FROM sessions WHERE token = '%s'", tok))` |
| Go | `db.QueryContext` with string concat | `db.QueryContext(ctx, "SELECT " + col + " FROM t")` |
| Python | `cursor.execute(f"...")` | `cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")` |
| Python | `cursor.execute("..." % var)` | `cursor.execute("INSERT INTO t VALUES ('%s')" % val)` |
| TypeScript | Template literal in query | `` pool.query(`SELECT * FROM users WHERE id = ${req.query.id}`) `` |
| Java | `Statement.execute(concat)` | `stmt.execute("SELECT * FROM t WHERE col = '" + userInput + "'")` |
| Rust | `sqlx::query` with format! | `sqlx::query(&format!("SELECT * FROM t WHERE id = {}", id))` |

### Why it's dangerous

Attacker-controlled SQL syntax can read arbitrary data, bypass authentication, modify or delete data, and (in some configurations) execute OS commands via `xp_cmdshell` or UDF.

### Real controls

- **Parameterized queries / prepared statements** — `db.Query("SELECT * FROM t WHERE id = ?", userID)` (Go), `cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,))` (Python), `$1`/`$2` placeholders (PostgreSQL)
- **ORM with query builder** — SQLAlchemy, GORM, Hibernate — safe by default, unsafe with `.Raw()` / `Exec()` + string concat
- **Allowlisted column/table names** — when dynamic identifiers are needed, validate against an explicit allowlist

### False positives to rule out

- Query string is a compile-time constant with no user input
- "User input" is the result of a type coercion to integer (e.g., `strconv.Atoi`) and the query uses that integer directly

---

## Command Execution

**Vulnerability class:** OS Command Injection

### Detection patterns

| Language | Function | Risk level |
|----------|----------|------------|
| Go | `exec.Command(name, args...)` | HIGH — args separate, shell not invoked |
| Go | `exec.Command("sh", "-c", userInput)` | CRITICAL — shell invoked with user input |
| Python | `subprocess.run(shell=True, ...)` | CRITICAL — shell invoked |
| Python | `os.system(cmd)` | CRITICAL |
| Python | `os.popen(cmd)` | CRITICAL |
| Node | `child_process.exec(cmd)` | CRITICAL — shell invoked |
| Node | `child_process.execSync(cmd)` | CRITICAL |
| Node | `child_process.spawn(cmd, args)` | HIGH — no shell by default |
| Rust | `Command::new("sh").arg("-c").arg(input)` | CRITICAL |
| Java | `Runtime.getRuntime().exec(new String[]{"sh", "-c", input})` | CRITICAL |
| Java | `ProcessBuilder(List.of("sh", "-c", input))` | CRITICAL |

### Why it's dangerous

Full OS command execution as the process's user. Can read secrets, exfiltrate data, pivot to other systems, establish persistence.

### Real controls

- **Avoid shell=True / sh -c** — pass args as a list to avoid shell interpretation
- **Allowlist command names** — never pass user input as the command name
- **Never interpolate user data into shell strings** — use separate args array
- **Use libraries instead of shell** — e.g., Python's `zipfile` module instead of `unzip` subprocess

---

## File System — Path from User Input

**Vulnerability class:** Path Traversal, Arbitrary File Read/Write

### Detection patterns

| Language | Pattern | Risk |
|----------|---------|------|
| Go | `os.Open(userInput)` | CRITICAL |
| Go | `ioutil.ReadFile(path)` where path includes user data | CRITICAL |
| Go | `filepath.Join(base, userInput)` without validation | HIGH |
| Python | `open(user_path)` | CRITICAL |
| Python | `pathlib.Path(base) / user_input` | HIGH |
| Node | `fs.readFile(path.join(base, userInput))` | HIGH |
| Node | `fs.createReadStream(userInput)` | CRITICAL |
| Rust | `File::open(user_path)` | CRITICAL |
| Java | `new FileInputStream(userInput)` | CRITICAL |

### Why it's dangerous

`../` sequences in user input let attackers read or write arbitrary files. Reading `/etc/passwd`, `/proc/self/environ`, AWS credentials at `~/.aws/credentials`, or overwriting critical files.

### Real controls

- **Resolve and prefix-check:** `realpath(filepath.Join(base, userInput))` then verify it starts with `base/`
- **Allowlist filenames** — never accept arbitrary paths; accept only known file identifiers
- **Separate user-facing IDs from file paths** — store files with UUIDs, map UUID→filename in DB

### File upload destinations

- **Never use `filename` from multipart header** as the disk filename
- Store with a generated UUID; record original filename in DB only
- Validate MIME type by reading magic bytes (not Content-Type header)
- Store outside webroot; serve via controller, not directly

---

## Template Rendering

**Vulnerability class:** Cross-Site Scripting (XSS), Server-Side Template Injection (SSTI)

### Detection patterns

| Language/Framework | Dangerous pattern | Safe alternative |
|-------------------|-------------------|-----------------|
| JavaScript / React | `element.innerHTML = userInput` | `element.textContent = userInput` |
| React | `dangerouslySetInnerHTML={{__html: userInput}}` | Avoid; use sanitize-html if needed |
| Go html/template | `template.HTML(userInput)` | Let template engine escape automatically |
| Go text/template | Any user input in text/template (no autoescaping) | Use html/template instead |
| Python Jinja2 | `{{ var \| safe }}` | Remove `\| safe`; ensure autoescaping enabled |
| Python Jinja2 | `Template(userInput).render()` | Never render user-supplied template strings |
| JavaScript Handlebars | `{{{ userInput }}}` (triple braces) | `{{ userInput }}` (double braces) |
| Thymeleaf (Java) | `th:utext="${userInput}"` | `th:text="${userInput}"` |
| EJS / Pug | `<%- userInput %>` | `<%= userInput %>` |

### SSTI — Server-Side Template Injection

When user input is used as the template string itself (not just a variable inside a safe template), attackers can execute arbitrary code. Languages at highest risk: Jinja2, Twig, Smarty, Freemarker, Velocity.

**Detection:** `Template(userInput).render()`, `env.from_string(userInput)`, `template.Execute(w, userInput)` where the template itself is user-controlled.

### Real controls

- Enable autoescaping by default (Jinja2: `autoescape=True`, Go: use `html/template`)
- Never render user-supplied template strings
- Use `textContent` instead of `innerHTML` in JavaScript
- Apply a well-maintained HTML sanitizer (DOMPurify) only when rich HTML is genuinely required

---

## Deserialization

**Vulnerability class:** Insecure Deserialization — arbitrary code execution, object injection

### Detection patterns

| Language | Dangerous function | Notes |
|----------|--------------------|-------|
| Python | `pickle.loads(data)` | Arbitrary code execution |
| Python | `pickle.load(file)` | Same |
| Python | `yaml.load(data)` (no Loader) | Use `yaml.safe_load` instead |
| Python | `yaml.load(data, Loader=yaml.Loader)` | Still dangerous |
| Node | `node-serialize` `unserialize()` | RCE via `_$$ND_FUNC$$_` |
| Java | `ObjectInputStream.readObject()` | Classic Java deserialization gadget chains |
| Java | `XStream.fromXML(input)` | Arbitrary class instantiation |
| PHP | `unserialize($input)` | Object injection |
| Ruby | `Marshal.load(data)` | RCE |

### Why it's dangerous

Deserialization of untrusted data can lead to:
- **Arbitrary code execution** (pickle, Java ObjectInputStream, node-serialize)
- **Object injection** — manipulate application state via crafted objects
- **DoS** — deeply nested structures, billion-laughs-style payloads

### Real controls

- **Prefer data formats over object serialization**: JSON, Protobuf, MessagePack — these don't carry type information
- **Python YAML:** always use `yaml.safe_load()` — only deserializes basic Python primitives
- **Java:** use serialization filters (`ObjectInputFilter`), avoid Java serialization entirely in new code
- **Sign serialized data** before sending to clients; verify signature before deserializing

---

## Cryptographic Operations

**Vulnerability class:** Weak crypto, predictable randomness, key exposure

### Weak algorithms

| Algorithm | Risk | Notes |
|-----------|------|-------|
| MD5 | HIGH | Collision attacks; not suitable for security purposes |
| SHA-1 | HIGH | Collision attacks; deprecated for signing |
| DES / 3DES | HIGH | Weak key sizes; deprecated |
| RC4 | HIGH | Statistical biases; deprecated in TLS |
| ECB mode | HIGH | Doesn't hide plaintext patterns; use GCM or CBC+HMAC |
| RSA with PKCS#1 v1.5 padding | HIGH | Padding oracle attacks; use OAEP |

**Detection:** Search for `md5`, `sha1`, `sha-1`, `des`, `rc4`, `ECB` in crypto initialization code.

### Hardcoded keys and secrets

```python
# Dangerous
SECRET_KEY = "hardcoded_secret_abc123"
JWT_SECRET = "my-jwt-secret"
AES_KEY = b"\x00" * 16  # all-zeros key

# Safe
SECRET_KEY = os.environ["SECRET_KEY"]
```

**Detection pattern:** `(?i)(secret|key|password|token|api_key)\s*[:=]\s*["'][a-zA-Z0-9+/=_-]{8,}["']`

### Predictable randomness

| Language | Insecure | Secure |
|----------|----------|--------|
| JavaScript | `Math.random()` | `crypto.randomBytes()` / `crypto.getRandomValues()` |
| Python | `random.random()`, `random.randint()` | `secrets.token_bytes()`, `os.urandom()` |
| Go | `math/rand` (seeded) | `crypto/rand` |
| Java | `new Random()` | `SecureRandom` |

**Use cases where predictable randomness is critical:** session tokens, CSRF tokens, password reset tokens, API keys, OTP codes.

### JWT-specific

```python
# CRITICAL — no signature verification
jwt.decode(token, options={"verify_signature": False})

# CRITICAL — accepts "none" algorithm
jwt.decode(token, algorithms=["none", "HS256"])

# CRITICAL — using public key to verify HMAC (algorithm confusion attack)
jwt.decode(token, public_key, algorithms=["HS256"])
```

---

## Network — SSRF

**Vulnerability class:** Server-Side Request Forgery

### Detection patterns

```go
// Go — URL from user input
url := fmt.Sprintf("https://%s/api", userHost)  // CRITICAL
http.Get(url)

resp, _ := http.Get(req.FormValue("url"))        // CRITICAL
```

```python
# Python
requests.get(request.args.get("url"))            # CRITICAL
target = f"http://{user_host}/internal"
requests.post(target, json=payload)              # CRITICAL
```

```typescript
// Node
fetch(req.query.url)                             // CRITICAL
axios.get(`http://${req.body.host}/api`)         // CRITICAL
```

### Why it's dangerous

SSRF allows attackers to:
- Access internal services (metadata APIs, admin endpoints, databases)
- Reach `169.254.169.254` (AWS/GCP/Azure metadata) to steal IAM credentials
- Port scan internal networks
- Exfiltrate data via DNS (blind SSRF)

### Real controls

- **Allowlist of permitted outbound domains** — validate against explicit list
- **Block private IP ranges** — RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), loopback (`127.0.0.0/8`)
- **Resolve hostname and check IP** — prevent DNS rebinding
- **Never forward raw URLs from user input** to backend services

---

## Authentication Sinks

**Vulnerability class:** Authentication bypass, session fixation, privilege escalation

### JWT without verification

```python
# Dangerous — no signature check
jwt.decode(token, options={"verify_signature": False})

# Dangerous — accepts none algorithm
decoded = jwt.decode(token, "", algorithms=["none"])
```

### Session fixation

```python
# Dangerous — session ID from user input
session_id = request.args.get('session_id')
session[session_id] = user_data   # attacker-controlled session ID
```

### Insecure direct object reference (IDOR) sinks

```go
// User ID comes from request parameter — no ownership check
userID := c.Param("user_id")
db.Query("SELECT * FROM users WHERE id = ?", userID)
```

### Password comparison

```python
# Dangerous — timing side-channel
if stored_password == submitted_password: ...

# Safe
import hmac
if hmac.compare_digest(stored_password, submitted_password): ...
```

### Missing authentication middleware

Look for routes that should require authentication but are registered outside the auth middleware group:
```go
// Dangerous — /admin route outside auth group
r.GET("/admin/users", adminHandler)  // no auth middleware

// Should be
adminGroup := r.Group("/admin", authMiddleware)
adminGroup.GET("/users", adminHandler)
```
