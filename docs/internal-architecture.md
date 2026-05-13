# CyberMat Shield — Internal Architecture

## Scanner Pipeline

Every `cybermat scan <path>` invocation runs through the following sequential pipeline inside `packages/core/src/scanner.ts`:

```
loadConfig()
  → buildFileInventory()       # packages/analyzers/src/file-inventory.ts
  → detectStack()              # packages/analyzers/src/stack-detector.ts
  → classifyFiles()            # packages/analyzers/src/file-classifier.ts
  → discoverRoutes()           # packages/analyzers/src/route-discovery.ts
  → buildImportGraph()         # packages/analyzers/src/import-graph.ts
  → analyzeAst()               # packages/analyzers/src/ast-analyzer.ts
  → correlateSources()         # packages/analyzers/src/source-sink.ts
  → runRules()                 # packages/rules/src/**
  → deduplicateFindings()
  → applyIgnoreRules()         # .cybermatignore support
  → scoreReport()
  → writeReports()             # JSON + HTML
```

Each step is a pure function that takes its inputs and returns structured data. No step crawls the filesystem independently — all file access goes through `buildFileInventory()`.

---

## Analyzers (`packages/analyzers/`)

Analyzers are **fact extractors** — they read files and produce structured data that rules and engines consume.

| Analyzer | Input | Output | Status |
|---|---|---|---|
| `file-inventory` | rootPath, config | `ScannedFile[]` + ignored count | ✅ Full |
| `stack-detector` | files, package.json | `DetectedStack` | ✅ Full |
| `file-classifier` | files | `FileClassification[]` | ✅ Full |
| `route-discovery` | files, framework | `RouteInfo[]` | ✅ Full |
| `import-graph` | files | `ImportGraph` | ✅ Regex-based |
| `ast-analyzer` | files | sinks + sources | ✅ Regex-based |
| `source-sink` | sources, sinks | `SourceSinkCorrelation[]` | ✅ Function-level |
| `dependency-analyzer` | files, package.json | `DependencyAnalysisResult` | ✅ Basic |
| `config-analyzer` | files | `ConfigAnalysisResult` | ✅ Basic |

### File Inventory

Recursively scans the target directory. Hard-coded ignore directories:
`node_modules`, `.next`, `dist`, `build`, `.git`, `coverage`, `.turbo`, `.vercel`, `.cache`, `.cybermat`

Skips:
- Binary files (files containing null bytes `\0`)
- Files larger than `maxFileSizeBytes` (default: 1 MB)
- Extensions not in the allowlist (text extensions only)
- Paths matching `.cybermatignore`

Each file gets a SHA-256 hash of its content for fingerprinting.

### Stack Detector

Reads `package.json` (dependencies + devDependencies + peerDependencies) and file paths. Detects:
- **Frameworks**: Next.js, React, Vite, Express, Fastify, NestJS, SvelteKit, Nuxt, Astro
- **Auth**: Clerk, NextAuth/Auth.js, Supabase Auth, Firebase Auth, Better Auth
- **Databases**: Prisma, Drizzle, Supabase, Firebase, MongoDB, PostgreSQL, Redis
- **Deployment**: Vercel, Netlify, Docker, GitHub Actions
- **AI providers**: OpenAI, Anthropic, Google AI, Groq, Mistral, Replicate, Together AI, Vercel AI SDK
- **Package managers**: pnpm, yarn, bun, npm (by lockfile presence)

### File Classifier

Assigns each file one of: `client | server | shared | config | public | test | unknown`.

Classification priority (highest wins):
1. Known config filename (`next.config.js`, `tsconfig.json`, etc.) → `config`
2. In `public/`, `static/`, `assets/` → `public`
3. Test file pattern (`.test.`, `.spec.`, `__tests__/`) → `test`
4. `"use client"` directive → `client` (high confidence)
5. `"use server"` directive → `server` (high confidence)
6. Server path pattern (`app/api/`, `pages/api/`, `middleware.ts`) → `server`
7. Client path pattern (`components/`, `pages/` non-api, `page.tsx`) → `client`
8. Uses server-only Node.js APIs (`fs`, `child_process`, `process.env` non-public) → `server`
9. Uses browser APIs (`window`, `document`, `localStorage`) → `client`
10. Shared utility path (`lib/`, `utils/`, `hooks/`, `types/`) → `shared`
11. Default → `unknown`

### Route Discovery

Discovers HTTP routes without running the application.

**Next.js app router**: Finds `app/**/route.ts` files. Extracts exported HTTP methods (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`). Converts file path to URL: `app/api/users/[id]/route.ts` → `/api/users/[id]`.

**Next.js pages router**: Finds `pages/api/**/*.ts` files. Converts path to URL: `pages/api/users.ts` → `/api/users`.

**Express**: Scans for `app.get/post/put/patch/delete(route, ...)` and `router.get/post/...` patterns.

Each route is annotated with:
- `requiresAuth`: whether auth guard patterns are present
- `hasRoleCheck`: whether role check patterns are present
- `acceptsUserInput`: whether request body/query/params are used
- `riskTags`: array of `admin-route`, `api-route`, `webhook`, `payment`, `ai-tool`, `missing-auth`, `accepts-url`, `accepts-user-id`, etc.

### Import Graph

Parses static imports, dynamic imports, and `require()` calls using regex on source files. Produces:
- `edges`: `{from, to, importType}` for every import relationship
- `serverClientLeaks`: client files importing server-only modules (`fs`, `server-only`, `next/headers`, etc.)
- `clientServerLeaks`: server files importing client-only modules (`client-only`, `react-dom/client`)

### AST Analysis (Regex-Based)

Detects dangerous sinks and user-controlled sources by scanning each line of TypeScript/JavaScript files.

**Sink types detected:**

| Sink type | Examples |
|---|---|
| `xss` | `dangerouslySetInnerHTML`, `.innerHTML=`, `eval()`, `new Function()`, `document.write` |
| `sql` | `$queryRawUnsafe`, `$executeRawUnsafe`, SQL string concatenation |
| `command` | `exec()`, `execSync()`, `spawn({shell:true})`, `child_process.exec` |
| `ssrf` | `fetch(variable)`, `axios.get(variable)`, `got(variable)` |
| `redirect` | `redirect(userInput)`, `res.redirect(userInput)`, `NextResponse.redirect(variable)` |
| `filesystem` | `fs.readFile(userInput)`, `fs.writeFile(userInput)`, `path.join(userInput)` |
| `ai-output` | LLM variable names flowing to `innerHTML`, `dangerouslySetInnerHTML` |

**Source types detected:**

| Source type | Examples |
|---|---|
| `request-body` | `req.body`, `request.json()`, `request.formData()` |
| `request-query` | `req.query`, `searchParams.get()` |
| `request-params` | `req.params`, `params.*` |
| `cookie` | `req.cookies`, `document.cookie`, `cookies().get()` |
| `storage` | `localStorage.getItem()`, `sessionStorage.getItem()` |
| `browser-location` | `location.search`, `location.hash` |
| `post-message` | `event.data` (message event) |

### Source/Sink Correlation

For each file where both sources and sinks are found:
1. Collect variable names assigned from source expressions (`const body = req.body`, `const { id } = req.params`)
2. For each sink within 50 lines of a source, check if a source variable appears in the sink call
3. Check for sanitizer presence in the window between source and sink
4. Assign confidence: `high` (variable linked, no sanitizer) / `medium` (same file, no sanitizer) / `low` (sanitizer present)

---

## Rules (`packages/rules/`)

Rules are **evaluators** — they receive the fully-populated `RuleContext` and return `Finding[]`. Rules must not crawl the filesystem independently.

| Rule pack | Detects |
|---|---|
| `secrets` | 66 secret detectors (cloud, auth, database, payment, AI, monitoring) |
| `injection` | XSS sinks, SQL injection, eval, command injection, Prisma raw |
| `auth` | Missing auth guards, admin routes, Clerk/Supabase/Stripe checks, webhook signature |
| `config` | CORS wildcard, missing security headers, Firebase permissive rules, Supabase missing RLS |
| `crypto` | Token in localStorage, insecure cookie flags |
| `supply-chain` | Lifecycle scripts, wildcard versions, missing lockfile |
| `ai-security` | LLM output to HTML/exec, tool call without approval, prompt injection, RAG injection |
| `runtime` | Placeholder (Phase 6) |
| `authz` | Placeholder (Phase 7) |

### Rule Lifecycle

```
RuleContext (files, stack, routes, classifications, importGraph, parsedFiles)
  → Rule.run(context) → Finding[]
  → scanner: tagFindingLayer(finding, rule.layer)
  → deduplicateFindings() — by stable fingerprint (SHA1 of ruleId+file+line+evidence)
  → applyIgnoreRules() — .cybermatignore by file path, rule ID, fingerprint
  → filteredFindings[]
```

---

## Finding Evidence Model

Every `Finding` has a structured `evidence` field:

```typescript
interface FindingEvidence {
  snippet?: string;          // raw code line (may contain secret)
  redactedSnippet?: string;  // redacted version shown in output
  match?: string;            // raw matched value (never logged)
  redactedMatch?: string;    // redacted match (first4****last4)
  reason: string;            // human-readable explanation
}
```

**Redaction model**: The `secrets-engine` computes `redactedMatch` using `sk_l****1234` format (first 4 chars + `****` + last 4 chars, or full mask for short secrets). Raw values are **never** stored, logged, or written to disk.

---

## Redaction Model

The `redactSecret(value)` utility in `packages/engines/secrets-engine/` applies the following:
- Length < 8: `****` (full mask)
- Length 8–15: first 2 + `****` + last 2
- Length 16+: first 4 + `****` + last 4

All report writers (`generateHtml`, `writeReports`) only use `evidence.redactedSnippet` and `evidence.redactedMatch` — never raw values.

---

## Finding Fingerprints

Stable fingerprints are generated via SHA-1 from: `ruleId + file + Math.floor(line/5)*5 + redactedEvidence`. The `line bucket` (floored to nearest 5) ensures small refactors don't invalidate fingerprints. This enables:
- Deduplication across rules
- `.cybermatignore` by fingerprint
- Baseline diffing (Phase 8)

---

## File Classification in Rules

Rules that need to distinguish client vs. server context use `context.fileClassifications`:

```typescript
const clientFiles = (context.fileClassifications ?? [])
  .filter(fc => fc.kind === 'client')
  .map(fc => fc.file);
```

Example: `auth.supabase-service-role-in-client` only fires when the service role key is found in a **client-classified** file.

---

## False-Positive Management

Several mechanisms reduce false positives:

1. **Confidence levels**: `high` (strong signal), `medium` (pattern match + context), `low` (keyword-only). CLI and report display confidence on each finding.

2. **Skip lists**: Rules like `injection.child-process-exec` skip known safe paths (`node_modules`, `dist`).

3. **Context checks**: `config.exposed-env-file` skips files containing `# FAKE` or `# TEST`.

4. **Source/sink correlation**: Sinks found without linked sources get lower confidence than those with proven data flow.

5. **Sanitizer detection**: Known sanitizers (DOMPurify, Zod, parameterized queries) reduce confidence when found between source and sink.

6. **`.cybermatignore`**: Users can ignore by file path glob, rule ID, or finding fingerprint.

---

## Safety Model

### Code Scanner
- Reads files only — zero network calls, zero browser activity
- Secrets in reports are always redacted (`sk_l****1234`)
- Raw secret values are **never** stored anywhere

### Runtime Scanner (Phase 6 — planned)
- Same-origin scope only by default
- Only safe HTTP methods (GET/HEAD/OPTIONS)
- No destructive payloads
- `safeMode: true` by default

### Auth/Authz Scanner (Phase 7 — planned)
- Hard requirement: explicit user-configured auth profiles
- No random ID generation / brute forcing
- 75 request limit per session
- 150ms minimum delay between requests

---

## Future Runtime/Auth Scanner Integration

The architecture is already wired for future layers. The `ScannerEngine` contract is layer-agnostic:

```typescript
type ScannerEngine = {
  id: string;
  name: string;
  layer: 'code' | 'runtime' | 'authz' | 'dependency' | 'external';
  run: (context: ScanContext) => Promise<Finding[]>;
};
```

Phase 6 will add `packages/engines/src/runtime-engine/` which receives `context.targetUrl` and runs Playwright. Phase 7 will add `packages/engines/src/authz-engine/` which receives `context.authProfiles`.

All findings from all layers share the same `Finding` type. The `ScanReport.findingsByLayer` field provides pre-grouped views.
