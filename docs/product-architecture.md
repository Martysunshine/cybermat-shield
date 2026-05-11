# CyberMat Shield — Product Architecture

## Overview

CyberMat Shield is a **local-first Application Security Scanner** that combines Semgrep-like static checks, Gitleaks-like secret scanning, npm-audit-like dependency analysis, and safe DAST-style runtime testing — all running on your machine with no code upload.

The product is **three scanners in one**, built in strict order so each layer can mature independently:

```
Layer 1 — Code Scanner      (Phases 1–5) ✅ active
Layer 2 — Runtime Scanner   (Phase 6)    🔲 planned
Layer 3 — Auth/Authz Scanner(Phase 7)    🔲 planned
```

---

## The Three Scanner Layers

### Layer 1 — Code Scanner

**Think:** Semgrep + Gitleaks + npm audit + framework-specific AppSec checks.

**Runs against:** source files on disk. No network, no browser.

**Responsibilities:**
- File inventory (recursive scan, binary skip, size limits, .appsecignore)
- Stack detection (frameworks, auth providers, databases, AI providers)
- File classification (client / server / shared / config / public / test)
- Secret scanning (66 detectors with context-aware severity)
- Dependency risk analysis (lifecycle scripts, wildcard versions, missing lockfile)
- Configuration misconfiguration (CORS, missing headers, exposed .env files)
- Static code analysis (XSS sinks, SQL injection, eval, command injection)
- Route discovery (Next.js app router, pages router, Express)
- Import graph analysis (client/server boundary violations)
- AST source/sink correlation (function-level taint tracking)
- AI-specific risks (LLM output to HTML sink, tool-call without approval)
- Finding normalization, deduplication, fingerprinting
- Evidence redaction (secrets never appear in reports)
- Report generation (JSON, HTML, SARIF)

**What it does NOT do:**
- Start a browser or make HTTP requests
- Test authentication or access control
- Exploit findings

### Layer 2 — Runtime Scanner

**Think:** A safe mini-DAST scanner for local/staging apps.

**Runs against:** a user-provided `localhost` or staging URL via Playwright.

**Responsibilities:**
- Scope enforcement (same-origin only, configurable path exclusions)
- Crawl pages and collect responses, headers, cookies, forms, scripts, API calls
- Header analysis (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Cookie analysis (HttpOnly, Secure, SameSite flags, JWT-like values)
- CORS testing (reflected origin, wildcard + credentials, null origin)
- Open redirect testing (known redirect params with safe target URL)
- Reflected input detection (harmless marker injection in GET params)
- Exposed file probing (20 well-known paths: .env, .git/config, swagger.json, etc.)
- Source map exposure detection

**What it does NOT do:**
- Scan external hosts (without explicit opt-in)
- Use destructive payloads or POST/PUT/DELETE
- Attempt authentication bypass
- Duplicate logic from the Code Scanner

### Layer 3 — Auth / Access-Control Scanner

**Think:** Controlled access-control testing for apps you own or have permission to test.

**Runs against:** a URL + user-configured auth profiles (anonymous, userA, userB, admin).

**Responsibilities:**
- Anonymous access testing (protected routes return 200 without credentials)
- Vertical privilege testing (low-privileged user accessing admin routes)
- Horizontal IDOR/BOLA testing (userA accessing userB's resources)
- Tenant boundary testing (cross-org resource access)
- Sensitive response comparison (compare response bodies across profiles)
- Static/runtime correlation (link runtime findings to static evidence)
- Auth scan reporting (profiles used, routes tested, resource pairs, correlations)

**What it does NOT do:**
- Run without explicit auth profiles (hard requirement)
- Use DELETE/PUT/POST/PATCH by default
- Brute-force IDs (no random ID generation)
- Test external hosts without explicit scope

**Safety limits:**
- Max 75 requests per session
- 150ms minimum delay between requests
- Halts on excessive 5xx responses
- All sensitive values redacted from findings

---

## Development Order

The layers must be built in strict order. Later layers depend on earlier layers being stable.

| Phase | Layer | Status |
|---|---|---|
| 1 — MVP Foundation | Code Scanner basics | ✅ Done |
| 2 — Architecture Hardening | Code Scanner (66 secret detectors) | ✅ Done |
| 3 — Three-Layer Architecture | Type contracts, ScanPlanner, Analyzers | ✅ Done |
| 4 — Deep Static Analysis | Full Code Scanner pipeline | 🔲 Planned |
| 5 — Rule Pack System | OWASP/CWE metadata, RuleRegistry | 🔲 Planned |
| 6 — Runtime Scanner | Playwright crawler, probes | 🔲 Planned |
| 7 — Auth Scanner | IDOR/BOLA, vertical privilege | 🔲 Planned |
| 8 — Productionization | SARIF, CI/CD, npm publish | 🔲 Planned |

**Do not implement runtime crawling before the Code Scanner architecture is clean.**
**Do not implement auth testing before runtime scanning and route discovery are stable.**

---

## Package Architecture

```
packages/
  shared/          Core types — Finding, Rule, ScanReport, ScannerEngine, etc.
  analyzers/       Fact extractors — read files, produce structured data for rules
    file-inventory/   Recursive file scan, binary detection, .appsecignore
    stack-detector/   Framework, auth, DB, AI provider detection
    file-classifier/  Client/server/shared classification (Phase 4)
    route-discovery/  Next.js + Express route discovery (Phase 4)
    import-graph/     Static import analysis, boundary violations (Phase 4)
    ast-analyzer/     Dangerous sinks, user-input sources (Phase 4)
    source-sink/      Function-level taint correlation (Phase 4)
    dependency-analyzer/ Lockfile + audit integration (Phase 4)
    config-analyzer/  Framework config misconfigurations (Phase 4)
  engines/         Orchestrators — coordinate analyzers, produce Finding[]
    code-scanner/     Orchestrates all code-layer engines
    runtime-scanner/  Orchestrates Playwright + HTTP probes (Phase 6)
    authz-scanner/    Orchestrates auth profile tests (Phase 7)
    secrets-engine/   66 secret detectors with context-aware severity
    static-code-engine/  AST-based sink/source detection (Phase 4)
    dependency-engine/   Dependency risk analysis (Phase 4)
    config-engine/    Config misconfiguration detection (Phase 4)
    ai-security-engine/  LLM output + tool-call risks (Phase 4)
    runtime-engine/   Playwright crawler + HTTP probes (Phase 6)
    authz-engine/     Auth profile test runner (Phase 7)
  rules/           Rule packs — evaluate facts, produce tagged Finding[]
    secrets/          Delegates to secrets-engine
    injection/        XSS, SQL injection, command injection (static patterns)
    auth/             Missing auth guards, IDOR via request body
    config/           CORS, missing headers, exposed .env
    crypto/           Insecure token storage, cookie flags
    supply-chain/     Lifecycle scripts, wildcard deps, missing lockfile
    ai-security/      LLM output rendering, tool-call approval
    runtime/          Runtime findings (Phase 6 — empty placeholder)
    authz/            Authz findings (Phase 7 — empty placeholder)
  core/            Scanner orchestrator — runs the full scan pipeline
  cli/             Commander.js CLI (appsec scan <path>)
  dashboard/       React + Vite web dashboard (Phase 8)
examples/
  vulnerable-next-app/   Intentionally vulnerable test target
docs/
  product-architecture.md   This file
  roadmap.md                Stage roadmap
```

### Architectural Principles

| Concern | Responsible package | Not responsible |
|---|---|---|
| Reading files | analyzers/ | rules/, engines/ |
| Extracting facts | analyzers/ | rules/, reporters |
| Evaluating facts | rules/ | analyzers/, reporters |
| Orchestrating | engines/ | rules/, reporters |
| Displaying findings | reporters / cli | engines/, rules/ |
| Network/browser | runtime-engine/ | code-scanner engines |
| Auth testing | authz-engine/ | code-scanner engines |

**Rules must not crawl the filesystem directly.**
**Reporters must not perform scanning logic.**
**Runtime scanner must not duplicate static scanner logic.**
**Authz scanner must never brute-force.**

---

## Shared Data Contracts

All scanner layers share the same core types (defined in `packages/shared/src/types.ts`).

### Finding

Every finding from every layer uses the same `Finding` type:

```typescript
interface Finding {
  id: string;           // stable fingerprint (SHA1)
  ruleId: string;       // e.g. 'secrets.openai-api-key'
  layer: ScannerLayer;  // 'code' | 'runtime' | 'authz'
  title: string;
  severity: Severity;   // 'critical' | 'high' | 'medium' | 'low' | 'info'
  confidence: Confidence;
  owasp: string[];
  cwe?: string[];
  evidence: FindingEvidence;  // all secrets are redacted here
  // ...
}
```

### ScannerEngine

Any scanner engine — TypeScript-native or an adapter for an external tool — implements `ScannerEngine`:

```typescript
type ScannerEngine = {
  id: string;
  name: string;
  layer: 'code' | 'runtime' | 'authz' | 'dependency' | 'external';
  supportedLanguages?: string[];
  supportedFrameworks?: string[];
  run: (context: ScanContext) => Promise<Finding[]>;
};
```

### ExternalToolAdapter

Future integrations (Semgrep, Gitleaks, Trivy, OSV) use the adapter contract:

```typescript
type ExternalToolAdapter = {
  id: string;
  command: string;
  isAvailable: () => Promise<boolean>;
  run: (context: ScanContext) => Promise<ExternalToolResult>;
  normalize: (result: ExternalToolResult) => Finding[];
};
```

Every adapter must normalize its output into `Finding[]`. The language the adapter is written in doesn't matter.

### ScanReport

Reports are split by layer for clean filtering:

```typescript
interface ScanReport {
  metadata: ScanMetadata;
  findings: Finding[];
  findingsByLayer: Record<ScannerLayer, Finding[]>;
  // ...
}
```

---

## Safety Model

### Code Scanner
- Reads files only — no network calls, no browser
- Secrets in reports are always redacted (`sk_l****1234`)
- Raw secret values are never stored anywhere

### Runtime Scanner
- Same-origin scope only by default
- Only safe HTTP methods (GET/HEAD/OPTIONS)
- No destructive payloads
- No external hosts without explicit opt-in
- `safeMode: true` by default — must explicitly disable

### Auth/Authz Scanner
- Hard requirement: explicit user-configured auth profiles
- No random ID generation / brute forcing
- 75 request limit per session
- 150ms minimum delay between requests
- All sensitive response values are redacted in findings

---

## Future Extensions

The architecture is designed to plug in additional tools and surfaces without changing core contracts:

| Extension | Integration point |
|---|---|
| VS Code extension | Consumes `ScanReport` JSON from `.appsec/report.json` |
| Browser extension | Runs `runtime-scanner` engine headlessly |
| GitHub Action | `appsec scan .` + SARIF upload to GitHub code scanning |
| Cloud dashboard | Receives `ScanReport` via secure upload (opt-in) |
| Semgrep adapter | `ExternalToolAdapter` + `normalize()` → `Finding[]` |
| Gitleaks adapter | `ExternalToolAdapter` + `normalize()` → `Finding[]` |
| Trivy adapter | `ExternalToolAdapter` for container / IaC scanning |
| Python engine | Separate process, same `ScannerEngine` contract via stdio |
| Go/Rust engine | High-performance repo scanning, same contract via stdio |
