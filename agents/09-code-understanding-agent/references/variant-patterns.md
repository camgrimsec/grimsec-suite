# Vulnerability Variant Hunting Patterns

Structural and semantic patterns for `--hunt` mode. For each vulnerability class: the seed pattern, structural variants (syntactically similar), semantic variants (functionally equivalent but different surface), and root-cause signatures.

---

## SQL Injection

### Seed pattern
String concatenation or interpolation into a SQL query that is directly executed.

### Structural variants (same mechanism, different syntax)

```go
// fmt.Sprintf into query
db.Query(fmt.Sprintf("SELECT * FROM %s WHERE id = '%s'", table, id))
db.Exec(fmt.Sprintf("UPDATE users SET role='%s' WHERE id=%d", role, uid))

// + concatenation
query := "SELECT * FROM users WHERE name = '" + name + "'"
db.QueryRow(query)

// Builder without parameterization
var q strings.Builder
q.WriteString("SELECT * FROM t WHERE col IN (")
for _, v := range vals { q.WriteString(v + ",") }
```

```python
# f-string
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# % formatting
cursor.execute("SELECT * FROM t WHERE id = %d" % user_id)   # safe for int
cursor.execute("SELECT * FROM t WHERE name = '%s'" % name)  # unsafe for string

# .format()
cursor.execute("SELECT * FROM t WHERE token = '{}'".format(token))
```

```typescript
// template literal
pool.query(`SELECT * FROM users WHERE id = ${userId}`)
knex.raw(`SELECT * FROM t WHERE name = '${name}'`)
```

```java
stmt.execute("SELECT * FROM t WHERE id = '" + userId + "'");
String q = "SELECT * FROM " + tableName + " WHERE col = ?";  // table name still injectable
```

### Semantic variants (functionally equivalent, different surface)

- **ORM `.Raw()` method:** `db.Raw("SELECT * FROM t WHERE id = " + id).Scan(&result)` — bypasses ORM parameterization
- **Stored procedure with exec:** `EXEC sp_executeSQL N'SELECT * FROM t WHERE id = ' + @id` — server-side concatenation
- **Dynamic `ORDER BY` / `GROUP BY`:** `db.Query("SELECT * FROM t ORDER BY " + userColumn)` — identifiers cannot be parameterized; need allowlist
- **Dynamic table name:** `db.Query("SELECT * FROM " + tableName)` — same issue
- **Second-order SQLi:** user input stored in DB, then later retrieved and used in a query without re-sanitization
- **JSON operator injection (PostgreSQL):** `WHERE data->>'key' = '` + val + `'` — injectable even with `->>`
- **Search helpers that build WHERE clauses from user-supplied field→value maps**

### Root cause signatures

1. Developer constructs query string using string operations (concat, format, template) rather than parameterized placeholders
2. Developer needs dynamic identifiers (table/column names) which cannot be parameterized — missing allowlist
3. Data retrieved from DB is trusted as safe for second-order insertion

### Hunt checklist

- [ ] All calls to `db.Query`, `db.Exec`, `db.QueryRow`, `cursor.execute`, `pool.query`, `stmt.execute`
- [ ] All `.Raw()` / `.Exec()` methods on ORM objects
- [ ] All `fmt.Sprintf` / f-strings / template literals containing SQL keywords
- [ ] Dynamic `ORDER BY`, `GROUP BY`, `LIMIT` clauses
- [ ] Search/filter functions that build `WHERE` clauses from maps or arrays

---

## Command Injection

### Seed pattern
User-controlled data passed to a function that invokes an OS shell or executes a command with shell interpretation.

### Structural variants

```go
exec.Command("sh", "-c", "git clone " + repoURL)           // shell=True equivalent
exec.Command("sh", "-c", fmt.Sprintf("convert %s", input)) // same
cmd := userInput; exec.Command(cmd)                         // command name from user
```

```python
os.system(f"ffmpeg -i {filename} output.mp4")              # shell=True
subprocess.run(f"convert {user_file} output.png", shell=True)
subprocess.Popen(cmd_string, shell=True)
```

```typescript
exec(`git log --oneline ${branch}`)                        // shell interpolation
execSync("ffmpeg -i " + req.body.input)
```

### Semantic variants

- **Indirect via config file:** user controls a config file that is read by a command (e.g., `.npmrc`, `.gitconfig`)
- **Argument injection without shell:** `exec.Command("git", "clone", userURL)` — no shell, but `--upload-pack` argument injection possible
- **Filename injection:** safe shell invocation but filename contains shell metacharacters (`; rm -rf /`, `$(id)`)
- **Environment variable injection:** user controls env var that a script reads (`$PATH` manipulation, `$LD_PRELOAD`)
- **Shebang abuse:** user uploads a file with a crafted shebang, system executes it
- **Template-based command building:** Jinja2/Mustache template used to build a command string

### Root cause signatures

1. `shell=True` (Python) or `sh -c` (all languages) + any user input in command string
2. Program name or path derived from user input
3. Insufficient escaping of shell metacharacters: `;`, `|`, `&`, `$()`, `` ` ``, `\n`

### Hunt checklist

- [ ] All `shell=True` subprocess calls
- [ ] All `exec("sh", "-c", ...)` or `exec("bash", "-c", ...)` patterns
- [ ] All `os.system()`, `os.popen()` calls
- [ ] All `child_process.exec()` / `execSync()` in Node (uses shell by default)
- [ ] File/directory names passed to commands without shell-quoting

---

## Path Traversal

### Seed pattern
User-supplied string used to construct a file path, read/written without resolving and checking the resolved path.

### Structural variants

```go
filePath := filepath.Join(uploadDir, req.FormValue("filename"))
data, _ := os.ReadFile(filePath)  // traversal possible if filename = "../../../etc/passwd"

// URL param as path
os.Open(r.URL.Query().Get("path"))
```

```python
filename = request.form['filename']
with open(os.path.join(UPLOAD_DIR, filename)) as f: ...

# Zip slip — extracting archive with crafted paths
for entry in zipfile.ZipFile(upload).namelist():
    target = os.path.join(EXTRACT_DIR, entry)
    # entry = "../../etc/cron.d/backdoor"
```

```typescript
const filePath = path.join(STATIC_DIR, req.params.file)
fs.readFile(filePath, ...)  // must verify filePath starts with STATIC_DIR after resolution
```

### Semantic variants

- **Zip Slip:** archive extraction where entry paths contain `../` — common in Go, Python, Java archive libraries
- **Symlink traversal:** archive contains a symlink pointing outside extraction directory
- **URL-encoded traversal:** `..%2F..%2F` — check if the app decodes before path resolution
- **Double encoding:** `..%252F` → `..%2F` → `../` — if app decodes twice
- **Null byte injection:** `filename.php\x00.jpg` — truncates at null byte in some C-based functions
- **Windows UNC / drive paths:** `\\server\share`, `C:\Windows\...` — relevant in mixed OS environments

### Root cause signatures

1. `filepath.Join` / `path.join` / `os.path.join` used but resolved path not compared to base directory
2. User-supplied filenames used directly as filesystem paths
3. Archive extraction without path validation

### Hunt checklist

- [ ] All `os.Open`, `os.ReadFile`, `os.WriteFile` with non-constant path
- [ ] All `path.join` / `filepath.Join` where any component originates from user input
- [ ] All archive extraction code (zip, tar, jar)
- [ ] Static file serving middleware configured with a user-controllable root

---

## SSRF

### Seed pattern
Outbound HTTP request made to a URL partially or fully controlled by user input.

### Structural variants

```go
url := "https://" + req.FormValue("host") + "/api/resource"
resp, _ := http.Get(url)

// Webhook registration + delivery
// User registers URL, server later POSTs to it
```

```python
target = request.json()['callback_url']
requests.post(target, json=payload)

# URL from database — second-order SSRF
webhook_url = db.query("SELECT url FROM webhooks WHERE id = ?", wh_id)
requests.post(webhook_url, ...)
```

### Semantic variants

- **Second-order SSRF:** URL stored in DB (during registration), server later uses it for an outbound request
- **Redirect-based SSRF:** server fetches a user-supplied URL, the URL redirects to an internal address
- **DNS rebinding:** URL resolves to external IP during allowlist check, then resolves to internal IP during actual request — check IP after resolution, not hostname
- **Protocol abuse:** `file://`, `gopher://`, `dict://`, `ftp://` — if the HTTP client supports non-HTTP schemes
- **URL parsing inconsistencies:** `http://evil.com@internal.service/` — some parsers treat `evil.com` as the userinfo, not the host
- **PDF/image generators:** tools like wkhtmltopdf, Puppeteer, ImageMagick that render user-supplied URLs or documents containing URLs
- **XML with external entities (XXE):** XML parser fetches external entity URL from user-supplied XML

### Root cause signatures

1. User controls all or part of the outbound URL (host, path, scheme)
2. Validation is DNS-based only (bypassable via DNS rebinding)
3. No allowlist of permitted outbound destinations

### Hunt checklist

- [ ] All `http.Get(url)` / `requests.get(url)` / `fetch(url)` where URL is not a compile-time constant
- [ ] Webhook registration and delivery flows
- [ ] PDF/screenshot/image generation endpoints
- [ ] XML parsers — check for `FEATURE_SECURE_PROCESSING`, `DISALLOW_DOCTYPE_DECL`
- [ ] URL shortener / preview / proxy features

---

## Insecure Deserialization

### Seed pattern
Untrusted bytes deserialized using a format that supports arbitrary type/code instantiation.

### Structural variants

```python
data = pickle.loads(base64.b64decode(cookie_value))       # cookie-based
obj = pickle.load(open(user_supplied_filename, 'rb'))      # file-based
config = yaml.load(config_string)                          # YAML without SafeLoader
```

```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();                             // classic Java deserialization

XStream xstream = new XStream();
Object obj = xstream.fromXML(request.getBody());           // XStream RCE
```

```typescript
const obj = unserialize(req.body.data)                     // node-serialize RCE
```

### Semantic variants

- **Indirect deserialization:** user uploads a file that is later deserialized (e.g., `.pkl` model file, Java `.ser` file)
- **Cached deserialization:** attacker-controlled data cached in Redis/Memcached, later deserialized by application
- **Template engine evaluation:** `eval()`, `Function()` constructor in JavaScript with user input
- **YAML as config:** application accepts YAML config from users — `yaml.load` with full Loader = RCE
- **Class.forName + newInstance:** dynamic class loading in Java based on user-supplied class name
- **PHP `unserialize`** with magic methods (`__wakeup`, `__destruct`, `__toString`)

### Root cause signatures

1. Format used (pickle, Java serialization, PHP serialization) inherently carries type and code information
2. Input source (network, file upload, cookie, cache) is attacker-influenced
3. No signature or integrity check on serialized blob before deserialization

### Hunt checklist

- [ ] All `pickle.loads` / `pickle.load` calls
- [ ] All `yaml.load` (check Loader argument)
- [ ] All `ObjectInputStream.readObject()` in Java
- [ ] All `unserialize()` in PHP and `unserialize()` in node-serialize
- [ ] Dynamic class loading: `Class.forName`, `importlib.import_module` + `getattr` with user input
- [ ] `eval()` / `exec()` / `Function()` with user-influenced strings

---

## XSS (Cross-Site Scripting)

### Seed pattern
User-controlled string inserted into HTML output without encoding/escaping.

### Structural variants

```typescript
// DOM-based
document.getElementById('output').innerHTML = location.hash.substring(1)
element.innerHTML = req.query.q

// React
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Server-side (Go)
fmt.Fprintf(w, "<p>Hello, %s</p>", r.FormValue("name"))  // text/template, not html/template
```

### Semantic variants

- **Attribute injection:** `<input value="` + userVal + `">` — attacker closes attribute, injects event handler
- **href/src injection:** `<a href="` + url + `">` — `javascript:` URL
- **JSON in HTML:** server renders `var data = ` + json + `;` — attacker can close script tag
- **CSP bypass:** `unsafe-inline`, `unsafe-eval`, or overly broad source allowlists
- **Markdown/rich text editors:** user-controlled Markdown rendered to HTML without sanitization
- **SVG upload:** SVG files contain `<script>` elements; serving SVG with wrong Content-Type causes XSS
- **postMessage handler:** `window.addEventListener('message', e => { eval(e.data) })` — any origin

### Root cause signatures

1. User data inserted into HTML context without HTML entity encoding
2. Template engine autoescaping disabled or bypassed (`| safe`, `{{{ }}}`, `th:utext`)
3. User data inserted into JavaScript context (even if HTML-escaped, `<script>var x = "` + input + `"`)

### Hunt checklist

- [ ] All `innerHTML =` assignments
- [ ] All `dangerouslySetInnerHTML` usages
- [ ] All `template.HTML()` casts in Go
- [ ] All `| safe` / `{% autoescape false %}` / `{{{ }}}` in templates
- [ ] All server-side string concatenation into HTML responses
- [ ] All `postMessage` handlers without origin check
- [ ] SVG upload endpoints — check Content-Type and Content-Disposition response headers

---

## Authentication and Authorization

### Seed pattern
Access control decision made incorrectly — wrong data trusted, check missing, or check bypassable.

### Structural variants

```go
// IDOR — no ownership check
userID := c.Param("user_id")                              // user-supplied
db.Query("SELECT * FROM users WHERE id = ?", userID)      // no check: is this the caller's own ID?

// Missing auth middleware
router.GET("/admin/report", adminHandler)                  // no auth middleware applied
```

```python
# JWT none algorithm
decoded = jwt.decode(token, options={"verify_signature": False})

# Insecure comparison
if user_token == expected_token: ...                        # timing side-channel
```

### Semantic variants

- **Mass assignment:** model bound from `request.body` without field allowlist — attacker sets `is_admin: true`
- **Privilege escalation via parameter:** `?role=admin` changes user's role in session
- **Horizontal privilege escalation:** user A can access user B's resources by changing a resource ID
- **JWT algorithm confusion:** RS256 signed token, server accepts HS256 — attacker signs with public key
- **Cookie security flags:** `HttpOnly`, `Secure`, `SameSite` missing — enables CSRF or session hijack
- **Path-based auth bypass:** middleware protects `/api/admin` but not `/api/admin/` (trailing slash)
- **GraphQL auth at schema vs. resolver level:** schema-level auth bypassable via aliasing

### Root cause signatures

1. Authorization check compares user-supplied data against itself (circular reference)
2. Auth middleware applied to some but not all routes in a group
3. Trust placed in client-supplied data (JWT payload without verification, cookie value, request header)

### Hunt checklist

- [ ] All routes — verify each has appropriate auth middleware
- [ ] All resource-by-ID lookups — verify ownership check after fetch
- [ ] All JWT decode calls — verify signature verification is not disabled
- [ ] All model binding — verify field allowlisting (no mass assignment)
- [ ] All session/cookie creation — verify `HttpOnly`, `Secure`, `SameSite` attributes
- [ ] GraphQL resolvers — verify auth checks at resolver level, not just schema level
