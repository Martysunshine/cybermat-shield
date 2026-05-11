Continue from the existing scanner project. The previous setup created the basic package structure, rule system, secret engine, and report model. Now deepen the architecture so this becomes a real local-first application security scanner, not just a collection of regex checks.

Product framing:
This is a serious local-first Application Security Scanner for modern web applications, APIs, and AI-assisted software. It should support production-grade projects while remaining safe, non-destructive, and privacy-first.

Main goal of this phase:
Implement the internal scanner architecture that allows accurate static analysis, route intelligence, client/server boundary detection, evidence quality, false-positive reduction, and future runtime/auth scanning.

Do not build aggressive exploitation.
Do not add cloud upload.
Do not expose raw secrets.
Do not scan external targets without explicit user-provided scope.

Implement the following architecture.

1. Scanner pipeline

Create a proper scan pipeline:

- loadConfig()
- buildFileInventory()
- detectStack()
- classifyFiles()
- parseImportantFiles()
- discoverRoutes()
- buildImportGraph()
- runEngines()
- normalizeFindings()
- redactFindings()
- deduplicateFindings()
- scoreReport()
- writeReports()

Create a main orchestrator:

runScan(targetPath: string, options: ScanOptions): Promise<ScanReport>

The scan flow should be clear, testable, and modular.

2. Core data types

Create or refine these types:

type ScanContext = {
  targetPath: string;
  config: ScannerConfig;
  files: ScannedFile[];
  stack: DetectedStack;
  fileClassifications: FileClassification[];
  routeMap: RouteInfo[];
  importGraph: ImportGraph;
  parsedFiles: ParsedFile[];
  packageInfo?: PackageInfo;
  startedAt: string;
};

type ScannedFile = {
  path: string;
  relativePath: string;
  extension: string;
  sizeBytes: number;
  content?: string;
  sha256: string;
  ignored: boolean;
  reasonIgnored?: string;
};

type FileClassification = {
  file: string;
  kind: "client" | "server" | "shared" | "config" | "public" | "test" | "unknown";
  confidence: "high" | "medium" | "low";
  reasons: string[];
};

type DetectedStack = {
  languages: string[];
  frameworks: string[];
  packageManagers: string[];
  authProviders: string[];
  databases: string[];
  deploymentTargets: string[];
  aiProviders: string[];
};

type RouteInfo = {
  route: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "ANY";
  file: string;
  framework: "nextjs" | "express" | "react-router" | "unknown";
  isApi: boolean;
  isPage: boolean;
  requiresAuth?: boolean;
  hasRoleCheck?: boolean;
  acceptsUserInput?: boolean;
  riskTags: string[];
};

type ImportGraph = {
  nodes: string[];
  edges: Array<{ from: string; to: string; importType: "static" | "dynamic" | "unknown" }>;
};

type ParsedFile = {
  file: string;
  astAvailable: boolean;
  imports: string[];
  exports: string[];
  functions: string[];
  dangerousCalls: DangerousCall[];
  userInputSources: UserInputSource[];
};

type DangerousCall = {
  name: string;
  file: string;
  line: number;
  column?: number;
  sinkType: "xss" | "sql" | "command" | "ssrf" | "redirect" | "filesystem" | "crypto" | "ai-output" | "unknown";
  argumentPreview?: string;
};

type UserInputSource = {
  name: string;
  file: string;
  line: number;
  sourceType: "request-body" | "request-query" | "request-params" | "url-search-params" | "browser-location" | "storage" | "cookie" | "post-message" | "file-upload" | "ai-output" | "webhook" | "unknown";
};

3. File inventory

Implement buildFileInventory():

- recursively scan files
- skip ignored directories:
  node_modules
  .next
  dist
  build
  .git
  coverage
  .turbo
  .vercel
  .cache
- skip huge files by default
- hash files with sha256
- read text files only
- detect binary files
- support ignore file:
  .appsecignore

The file inventory should be used by every engine. Engines should not manually crawl the file system independently.

4. Stack detection

Implement detectStack() based on package.json and config files.

Detect at least:

Frameworks:
- Next.js
- React
- Vite
- Express
- Fastify placeholder
- NestJS placeholder

Auth:
- Clerk
- NextAuth/Auth.js
- Supabase Auth
- Firebase Auth
- Better Auth placeholder

Databases:
- Prisma
- Drizzle
- Supabase
- Firebase
- MongoDB
- PostgreSQL
- Redis

Deployment:
- Vercel
- Netlify
- Docker
- GitHub Actions

AI providers:
- OpenAI
- Anthropic
- Google/Gemini
- Mistral
- Groq
- HuggingFace
- Replicate
- Together

Package managers:
- npm
- pnpm
- yarn
- bun

5. File classification

Implement classifyFiles().

Classify files as:

client:
- contains "use client"
- uses window/document/localStorage/sessionStorage
- is under components, src/components, public
- Vite frontend files
- React components with JSX/TSX and browser APIs

server:
- app/api/**/route.ts
- pages/api/**
- server/**
- lib/server/**
- middleware.ts
- contains "use server"
- imports fs, child_process, crypto server usage
- uses process.env without NEXT_PUBLIC/VITE prefix

config:
- next.config.*
- vite.config.*
- vercel.json
- netlify.toml
- Dockerfile
- docker-compose.yml
- package.json
- tsconfig.json
- eslint config
- GitHub Actions workflows

public:
- public/**
- static assets

shared:
- lib/**
- utils/**
- shared/**
- code imported by both client and server if import graph can detect it

Add reasons and confidence for every classification.

6. Import graph

Implement buildImportGraph() for JS/TS files.

Use TypeScript parser or ts-morph.

Track:
- static imports
- dynamic imports
- relative file imports
- server file importing client-like module
- client file importing server-only module
- client import chain reaching secret/env/server module

Add rules later that can flag:
- server-only module imported into client path
- secret-bearing module imported into client code
- use of process.env.SECRET in a client import chain

7. AST analysis foundation

Add AST utilities for TypeScript/JavaScript.

The scanner should detect dangerous calls structurally, not only by regex.

Detect sinks:

XSS/browser sinks:
- dangerouslySetInnerHTML
- innerHTML assignment
- outerHTML assignment
- insertAdjacentHTML
- document.write

Code execution:
- eval()
- new Function()
- setTimeout(string)
- setInterval(string)

Command execution:
- child_process.exec
- execSync
- spawn with shell true

SQL/database:
- Prisma.$queryRawUnsafe
- raw SQL template/string concatenation
- db.execute with interpolated strings
- sequelize.query with concatenated input

SSRF:
- fetch(variableUrl) in server code
- axios.get(variableUrl) in server code
- got(variableUrl)
- request(variableUrl)

Redirect:
- redirect(userInput)
- res.redirect(userInput)
- NextResponse.redirect(userInput)

Filesystem:
- fs.readFile user-controlled path
- fs.writeFile user-controlled path
- path.join with request input

AI output:
- variables named aiResponse, llmOutput, completion, modelOutput, generatedHtml, assistantMessage flowing to HTML sinks or tool calls

Also detect user input sources:

Next.js:
- request.json()
- request.formData()
- searchParams
- params
- cookies()
- headers()

Express:
- req.body
- req.query
- req.params
- req.headers
- req.cookies

Browser:
- location.search
- location.hash
- URLSearchParams
- localStorage.getItem
- sessionStorage.getItem
- document.cookie
- message event.data

Webhook:
- raw request body in webhook routes

8. Basic source/sink correlation

Implement a simple local function-level source/sink analyzer.

Do not attempt perfect full-program taint analysis yet.

For each parsed file:
- collect variable assignments from known sources
- collect calls to dangerous sinks
- if same variable or obvious alias appears in sink argument, create higher-confidence finding
- if sink exists but no source is linked, create lower-confidence finding
- if sanitizer appears before sink, reduce severity/confidence

Known sanitizers/validators:
- DOMPurify.sanitize
- sanitizeHtml
- validator.escape
- zod parse/safeParse
- Joi validate
- yup validate
- escapeHtml
- parameterized query APIs
- URL allowlist helper names like isAllowedUrl, validateRedirectUrl

Known auth/guard functions:
- auth()
- currentUser()
- getServerSession()
- requireAuth()
- requireAdmin()
- checkRole()
- isOwner()
- supabase.auth.getUser()
- clerkClient
- verifyToken()

9. Route discovery

Implement discoverRoutes().

Next.js:
- app/api/**/route.ts => API route
- pages/api/** => API route
- app/**/page.tsx => page route
- pages/** => page route
- middleware.ts => global middleware

Express:
- app.get/post/put/patch/delete
- router.get/post/put/patch/delete
- router.use

For each route:
- identify method
- identify file
- mark isApi/isPage
- detect whether auth guard appears
- detect whether role/admin check appears
- detect whether request body/query/params are used
- add risk tags:
  admin-route
  api-route
  state-changing-method
  missing-auth
  accepts-user-id
  accepts-url
  accepts-file
  webhook
  payment
  ai-tool
  debug-route

10. Framework-specific rule improvements

Add or improve rules for:

Next.js:
- API route missing auth on protected-looking route
- admin route missing role check
- server secret used in client component
- missing middleware where route structure suggests protected area
- unsafe NextResponse.redirect
- public source maps config

Supabase:
- service role key in client path = critical
- service role key anywhere in repo = high/critical depending context
- supabase.from(...).select/update/delete without obvious user ownership filter in server route = suspicious
- missing RLS migration/policy files if Supabase is detected = medium/high
- storage bucket public config if visible = flag

Firebase:
- Firebase apiKey in frontend = info
- Firebase private key = critical
- firebase rules file with allow read, write: if true = critical
- broad allow read/write without auth = high/critical

Clerk:
- frontend publishable key = info
- CLERK_SECRET_KEY in client = critical
- API route with no auth() or currentUser() where protected-looking route = high
- admin route with no role/org check = high

Stripe:
- STRIPE_SECRET_KEY in client = critical
- webhook route missing stripe.webhooks.constructEvent = high
- endpoint creating checkout/session from client-provided price/amount without allowlist = high
- payment success route trusting query params = medium/high

AI:
- LLM output rendered as HTML = high
- LLM output passed to SQL, shell, fetch, email, delete, payment, or code execution function = critical/high
- AI tool call handlers without allowlist or approval = high
- RAG documents mixed into system/developer instructions = medium/high

11. Finding normalization and deduplication

Create normalizeFindings().

Every finding must have:
- ruleId
- stable id
- title
- severity
- confidence
- OWASP mapping
- optional CWE
- category
- file/line/route when available
- evidence with redaction
- impact
- recommendation
- fixExample when possible
- tags

Create generateFingerprint(finding).

Fingerprint should be stable across scans:
- ruleId
- file
- route
- line bucket
- redacted evidence
- category

Deduplicate:
- same rule + same file + same evidence
- prefer higher confidence
- merge tags if needed

12. Confidence scoring

Add confidence rules.

High confidence:
- known secret pattern with strong token format
- private key found
- source and sink linked in same function
- route missing auth and route is admin/protected-looking
- webhook route missing signature verification

Medium confidence:
- dangerous sink found with variable input but source not proven
- missing security header
- suspicious broad CORS
- token-like value found by entropy

Low confidence:
- keyword-only match
- generic suspicious pattern
- public key that may be expected

13. Report improvements

Update report to show:

- scan summary
- detected stack
- files scanned
- files ignored
- routes discovered
- findings by severity
- findings by OWASP 2025 category
- findings by engine
- top risky files
- top risky routes
- top 5 recommended fixes
- evidence redacted
- confidence displayed
- false-positive guidance

14. Tests

Add unit tests for:

- file classification
- stack detection
- route discovery for Next.js
- route discovery for Express
- import graph basic imports
- AST dangerous sink detection
- source/sink correlation
- finding fingerprint stability
- deduplication
- confidence scoring
- redaction safety

15. Example vulnerable app

Enhance examples/vulnerable-app with controlled examples:

- exposed fake secret
- fake private key fixture
- dangerouslySetInnerHTML
- innerHTML assignment
- queryRawUnsafe
- API route missing auth
- admin route missing role check
- webhook missing signature check
- Stripe fake secret in client file
- Firebase permissive rules
- Supabase service role fake key in client file
- LLM output rendered as HTML
- fetch(req.body.url) SSRF candidate
- redirect from query parameter

Use fake test secrets only. Clearly mark them as fake.

16. Documentation

Create docs/internal-architecture.md explaining:

- scanner pipeline
- engines
- rule lifecycle
- source/sink model
- file classification
- route discovery
- finding evidence model
- redaction model
- false-positive management
- safety model
- future runtime/auth scanner integration

Keep this phase focused on internal scanner architecture and static analysis quality.
