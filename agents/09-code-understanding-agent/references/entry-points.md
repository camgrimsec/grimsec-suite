# Entry Points Reference

Common entry points by framework and language. Load this file when running `--map` mode.

---

## Go

### net/http (standard library)

```go
http.HandleFunc("/path", handlerFunc)
http.Handle("/path", handlerObject)

// ServeMux
mux := http.NewServeMux()
mux.HandleFunc("/path", handlerFunc)
```

**What to look for:** Any `HandlerFunc` or `ServeHTTP` method implementation. The `r *http.Request` parameter carries attacker-controlled data: `r.URL.Query()`, `r.Body`, `r.Form`, `r.PostForm`, `r.MultipartForm`, `r.Header`, `r.URL.Path`, `r.URL.RawQuery`.

---

### Gin

```go
r := gin.Default()
r.GET("/path", handler)
r.POST("/path", handler)
r.Group("/api").GET("/resource", handler)
r.Any("/path", handler)
```

**Attacker-controlled inputs in gin context:**
- `c.Param("id")` — URL path parameter
- `c.Query("q")` — query string
- `c.PostForm("field")` — POST form field
- `c.ShouldBindJSON(&req)` / `c.BindJSON(&req)` — JSON body
- `c.GetHeader("X-Custom")` — request header
- `c.GetRawData()` — raw body bytes
- `c.FormFile("file")` — file upload

---

### Echo

```go
e := echo.New()
e.GET("/path", handler)
e.POST("/path", handler)
g := e.Group("/api")
g.GET("/resource", handler)
```

**Attacker-controlled inputs:**
- `c.Param("id")`, `c.QueryParam("q")`, `c.FormValue("field")`
- `c.Bind(&req)` — binds JSON/form/query to struct
- `c.Request().Body` — raw request body
- `c.Request().Header.Get("key")`

---

### Fiber (fasthttp-based)

```go
app := fiber.New()
app.Get("/path", handler)
app.Post("/path", handler)
```

**Attacker-controlled inputs:**
- `c.Params("id")`, `c.Query("q")`, `c.FormValue("field")`
- `c.BodyParser(&req)` — parses body into struct
- `c.Body()` — raw body bytes
- `c.Get("Header-Name")` — request header
- `c.FormFile("file")` — file upload

---

### Chi

```go
r := chi.NewRouter()
r.Get("/path", handler)
r.Post("/path", handler)
r.Route("/api", func(r chi.Router) { r.Get("/resource", handler) })
```

**Attacker-controlled inputs:** Standard `r *http.Request` — same as net/http. Chi uses `chi.URLParam(r, "id")` for path params.

---

### gRPC (Go)

```go
pb.RegisterMyServiceServer(grpcServer, &myServer{})
```

**Attacker-controlled inputs:** Every field in the protobuf request message is attacker-controlled if the caller is external. Service methods receive `(ctx context.Context, req *pb.RequestType)` — treat all `req.*` fields as tainted.

---

### GraphQL (gqlgen, graph-gophers)

```go
// gqlgen — resolvers
func (r *queryResolver) MyField(ctx context.Context, input model.MyInput) (*model.Result, error)
```

**Attacker-controlled inputs:** Every field in `input` struct. Resolver arguments. Custom scalars that accept strings.

---

### WebSocket (gorilla/websocket)

```go
conn.ReadMessage()        // returns messageType, []byte, error
conn.ReadJSON(&v)         // unmarshals into struct
```

**Attacker-controlled inputs:** Every byte/field returned from `ReadMessage` / `ReadJSON`.

---

### Message Queue Consumers

#### Kafka (sarama, confluent-kafka-go, segmentio/kafka-go)
```go
for msg := range consumer.Messages()  { /* msg.Value is tainted */ }
reader.ReadMessage(ctx)                // returns kafka.Message
```

#### NATS
```go
nc.Subscribe("subject", func(m *nats.Msg) { /* m.Data is tainted */ })
```

#### Redis Streams (go-redis)
```go
result, _ := rdb.XRead(ctx, &redis.XReadArgs{...})
// result[i].Messages[j].Values map — values are tainted
```

#### RabbitMQ (amqp091-go)
```go
deliveries, _ := ch.Consume(...)
for d := range deliveries { /* d.Body is tainted */ }
```

---

### CLI (cobra, flag)

```go
// cobra
var myFlag string
cmd.Flags().StringVar(&myFlag, "flag", "", "usage")
// flag stdlib
myFlag := flag.String("flag", "", "usage")
```

**Attacker-controlled inputs:** All flag values when tool is invoked by untrusted users. Environment variables via `os.Getenv()`.

---

### Environment Variables / Config at Startup

```go
os.Getenv("DATABASE_URL")
os.Getenv("SECRET_KEY")
```

These are operator-controlled at deploy time, but can be attacker-controlled in injection scenarios (config injection, CI/CD compromise). Always note when secrets are read this way.

---

## TypeScript / Node.js

### Express

```js
app.get('/path', (req, res) => { /* req.query, req.params, req.body, req.headers */ })
app.post('/path', (req, res) => { /* req.body */ })
router.use('/prefix', routerHandler)
```

**Attacker-controlled inputs:**
- `req.params` — URL path params
- `req.query` — query string (always strings or arrays)
- `req.body` — parsed request body (via body-parser)
- `req.headers['x-custom']` — request headers
- `req.files` / `req.file` — file uploads (multer)
- `req.cookies` — cookies

---

### Fastify

```js
fastify.get('/path', { schema }, async (request, reply) => {
  request.params  // path params
  request.query   // query string
  request.body    // parsed body
  request.headers // headers
})
```

Fastify's schema validation is a security control — note when schemas are missing or use `anyOf: [{}]` (effectively no validation).

---

### NestJS

```typescript
@Controller('resource')
export class MyController {
  @Get(':id')
  findOne(@Param('id') id: string, @Query('filter') filter: string) {}

  @Post()
  create(@Body() dto: CreateDto) {}
}
```

**Attacker-controlled inputs:** `@Param()`, `@Query()`, `@Body()`, `@Headers()`. Validation pipe (`class-validator`) is a security control — note when it's missing.

---

### Next.js API Routes

```typescript
// pages/api/resource.ts
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  req.query   // query string + path params
  req.body    // parsed body
  req.headers
}

// App Router (Next.js 13+)
export async function GET(request: Request) {
  const url = new URL(request.url)
  url.searchParams.get('q')  // query string
}
```

---

### GraphQL (Apollo Server, type-graphql)

```typescript
@Resolver()
class MyResolver {
  @Query(() => [User])
  async users(@Arg('filter') filter: string): Promise<User[]> { /* filter is tainted */ }

  @Mutation(() => User)
  async createUser(@Arg('input') input: CreateUserInput): Promise<User> { /* input fields are tainted */ }
}
```

**Special risk:** GraphQL introspection exposes the full schema. Batched queries, alias abuse, and deep recursion are DoS vectors. Inline fragments can bypass field-level auth checks.

---

### WebSocket (ws, socket.io)

```js
wss.on('connection', (ws) => {
  ws.on('message', (data) => { /* data is tainted */ })
})

io.on('connection', (socket) => {
  socket.on('event', (payload) => { /* payload is tainted */ })
})
```

---

### Message Queue Consumers (Node)

```js
// bull / bullmq
queue.process(async (job) => { /* job.data is tainted */ })

// AWS SQS (aws-sdk)
sqs.receiveMessage(params, (err, data) => { /* data.Messages[i].Body is tainted */ })

// Kafka (kafkajs)
await consumer.run({ eachMessage: async ({ message }) => { /* message.value is tainted */ } })
```

---

## Python

### Flask

```python
@app.route('/path', methods=['GET', 'POST'])
def handler():
    request.args.get('q')         # query string
    request.form.get('field')     # POST form data
    request.get_json()            # JSON body
    request.headers.get('X-Key')  # headers
    request.files['upload']       # file uploads
    request.cookies.get('session')# cookies
```

---

### FastAPI

```python
@app.get('/resource/{item_id}')
async def read_item(
    item_id: int,          # path param — type conversion is a partial control
    q: Optional[str] = None,  # query param — always validate with Annotated validators
    body: MyModel = Body(...), # Pydantic model — fields are tainted, validation is a control
    x_header: str = Header(None),
):
```

**Note:** Pydantic validation is a partial control — custom validators can be bypassed if they use `model_validator` incorrectly. `item_id: int` coerces to int (blocks string injection) but confirm with tests.

---

### Django

```python
# urls.py
path('resource/<int:pk>/', views.detail, name='detail')
re_path(r'^resource/(?P<slug>[-\w]+)/$', views.detail)

# views.py
def my_view(request):
    request.GET.get('q')      # query string
    request.POST.get('field') # POST data
    request.body              # raw body bytes
    request.META.get('HTTP_X_CUSTOM')  # headers
    request.FILES['file']     # file uploads
```

**Security controls to look for:** `django.db.models` ORM (parameterized by default), `{% autoescape %}` in templates (on by default), CSRF middleware.

---

### Message Queue / Async Workers (Python)

```python
# Celery
@app.task
def my_task(arg1, arg2): ...  # args come from task queue — treat as tainted

# aio-pika (RabbitMQ)
async def on_message(message: aio_pika.IncomingMessage):
    body = message.body  # tainted

# aiokafka
async for msg in consumer:
    msg.value  # tainted bytes
```

---

## Rust

### Actix-web

```rust
#[get("/resource/{id}")]
async fn get_resource(
    path: web::Path<String>,  // path param — tainted
    query: web::Query<MyQuery>, // query string — tainted
    body: web::Json<MyBody>,    // JSON body — tainted
    req: HttpRequest,           // headers via req.headers()
) -> impl Responder { ... }
```

---

### Axum

```rust
async fn handler(
    Path(id): Path<String>,
    Query(params): Query<MyParams>,
    Json(body): Json<MyBody>,
    headers: HeaderMap,
) -> impl IntoResponse { ... }
```

**Note:** Axum's type-safe extractors validate format but not semantics. A `Path<String>` accepts any string, including path traversal sequences.

---

### Rocket

```rust
#[get("/resource/<id>")]
fn get_resource(id: String) -> String { ... }

#[post("/resource", data = "<form>")]
fn create_resource(form: Form<MyForm>) -> String { ... }
```

---

## Java / Spring Boot

```java
@RestController
@RequestMapping("/api")
public class MyController {

    @GetMapping("/resource/{id}")
    public ResponseEntity<?> getResource(
        @PathVariable String id,
        @RequestParam String filter,
        @RequestHeader("X-Custom") String header
    ) { ... }

    @PostMapping("/resource")
    public ResponseEntity<?> createResource(
        @RequestBody MyRequest body
    ) { ... }
}
```

**Attacker-controlled inputs:** `@PathVariable`, `@RequestParam`, `@RequestBody`, `@RequestHeader`, `@CookieValue`.

**Security controls to look for:** Spring Security filter chain, `@Valid` + Bean Validation (`@NotNull`, `@Size`, `@Pattern`), JPA repositories (parameterized by default), Thymeleaf with `th:text` (escaped by default vs `th:utext` which is not).

---

## Cross-Language Patterns

### Cron / Scheduled Jobs

Cron jobs may read from files, databases, or external APIs — any external data source feeds into the job and should be treated as tainted if it originates from user-influenced data.

```go
// Go (robfig/cron)
c.AddFunc("@hourly", func() { processExternalData() })

// Python (APScheduler)
scheduler.add_job(process_data, 'interval', hours=1)

// Java (Spring)
@Scheduled(cron = "0 * * * * *")
public void scheduledTask() { ... }
```

### File Upload Endpoints

Regardless of framework, file upload handlers are high-risk entry points:
- Validate MIME type server-side (not just Content-Type header — it's attacker-controlled)
- Validate file extension against an allowlist
- Never use the original filename directly in file system operations
- Store uploads outside the webroot

### GraphQL Resolvers (General)

Every argument to every query, mutation, and subscription resolver is attacker-controlled. GraphQL-specific risks:
- Batched queries / query complexity attacks
- Introspection disclosure
- Authorization checks at resolver level (not schema level) can be bypassed via aliases
- N+1 injection via deeply nested queries
