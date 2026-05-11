Continue from the current local-first Application Security Scanner project.

Before adding more features, refactor and document the architecture around one important product principle:

This scanner is three products in one, built in strict order:

1. Code Scanner
2. Runtime Scanner
3. Auth / Access-Control Scanner

Do not try to fully build all three at once. The codebase must be structured so each layer can mature independently without creating messy coupling.

Product framing:
This is a serious local-first Application Security Scanner for modern web applications, APIs, and AI-assisted software. It is not branded as a “vibe-coded app scanner,” although it should be especially useful for AI-generated and AI-assisted codebases.

The scanner should feel like a professional security tool that combines:
- Semgrep-like static checks
- Gitleaks-like secret scanning
- npm-audit-like dependency checks
- framework-specific security checks
- safe DAST-style runtime checks later
- controlled authenticated access-control testing later

The architecture must make this separation very clear.

1. Define the three scanner layers

Layer 1: Code Scanner

Purpose:
Scan source code, configuration, dependencies, secrets, framework usage, and AI-specific risky patterns.

This is the first strong MVP.

It includes:
- file inventory
- stack detection
- file classification
- secret scanning
- dependency scanning
- config scanning
- static code scanning
- AST analysis
- route discovery
- import graph
- source/sink correlation
- OWASP mapping
- finding normalization
- evidence redaction
- report generation

Think of this layer as:

Semgrep + Gitleaks + npm audit + framework-specific AppSec checks.

Layer 2: Runtime Scanner

Purpose:
Safely scan a running localhost/staging app through HTTP and browser automation.

This comes second.

It includes:
- Playwright crawler
- HTTP probe engine
- header checks
- cookie checks
- CORS checks
- open redirect checks
- exposed file checks
- reflected input checks with harmless markers
- source map exposure
- debug/admin route exposure
- runtime evidence collection

Think of this layer as:

a safe mini-DAST scanner for local/staging apps.

Layer 3: Auth / Access-Control Scanner

Purpose:
Safely test authorization boundaries using user-provided test accounts and explicit scope.

This is the red-team value layer and comes third.

It includes:
- anonymous access testing
- userA/userB comparison
- admin route testing
- IDOR/BOLA checks
- tenant boundary checks
- sensitive response comparison
- static/runtime correlation
- controlled resource pair testing

Think of this layer as:

controlled access-control testing for apps the user owns or has permission to test.

2. Enforce development order

The implementation order must be:

Phase 1:
Code Scanner only.

Phase 2:
Runtime Scanner.

Phase 3:
Auth / Access-Control Scanner.

Phase 4:
Productionization, CI, SARIF, dashboard polish.

Do not implement runtime crawling before the Code Scanner architecture is clean.
Do not implement auth testing before runtime scanning and route discovery are stable.
Do not implement cloud features before the local-first scanner works.

3. Refactor package architecture around this model

Use this structure or adapt the existing structure cleanly:

packages/
  cli/
  core/
  engines/
    code-scanner/
    runtime-scanner/
    authz-scanner/
  rules/
    secrets/
    static-code/
    dependencies/
    config/
    framework-nextjs/
    framework-react/
    framework-node-express/
    framework-supabase/
    framework-firebase/
    framework-clerk/
    framework-stripe/
    ai-security/
    runtime/
    authz/
  analyzers/
    file-inventory/
    stack-detector/
    file-classifier/
    route-discovery/
    import-graph/
    ast-analyzer/
    source-sink/
    dependency-analyzer/
    config-analyzer/
  reports/
  shared/
  dashboard/

The important principle:
Engines orchestrate.
Analyzers extract facts.
Rules evaluate facts.
Reporters display findings.

Do not let rules crawl the filesystem directly.
Do not let reporters perform scanning logic.
Do not let runtime scanner duplicate static scanner logic.
Do not let authz scanner perform unsafe brute forcing.

4. Define responsibilities clearly

Code Scanner responsibilities:

- read project files
- classify files as client/server/shared/config/public/test
- detect stack
- parse package.json and lockfiles
- detect routes
- build import graph
- parse AST
- find sources, sinks, guards, sanitizers
- detect secrets
- detect dependency risks
- detect misconfigurations
- detect AI-specific static risks
- produce normalized findings

Runtime Scanner responsibilities:

- accept a user-provided base URL
- enforce scope
- crawl same-origin pages
- collect responses, headers, cookies, forms, links, scripts, API calls
- safely probe headers, CORS, redirects, exposed files, reflection
- never use destructive payloads
- never scan external hosts unless explicitly allowed
- produce runtime findings

Auth / Access-Control Scanner responsibilities:

- only run with explicit auth profiles
- load anonymous/userA/userB/admin profiles
- compare access across profiles
- test configured resource pairs
- detect anonymous access to protected routes
- detect low-privileged user access to admin/internal routes
- detect horizontal IDOR/BOLA issues
- detect tenant boundary issues
- avoid brute forcing
- avoid destructive methods
- produce authz findings

5. Define shared scanner contracts

Create shared contracts that all scanner layers use.

Types:

type ScannerLayer = "code" | "runtime" | "authz";

type ScanMode = {
  layer: ScannerLayer;
  enabled: boolean;
  requiresTargetUrl: boolean;
  requiresAuthProfiles: boolean;
  safeByDefault: boolean;
};

type ScanPlan = {
  targetPath?: string;
  targetUrl?: string;
  layers: ScanMode[];
  config: ScannerConfig;
};

type ScanReport = {
  metadata: ScanMetadata;
  summary: ScanSummary;
  detectedStack?: DetectedStack;
  files?: ScannedFile[];
  routes?: RouteInfo[];
  findings: Finding[];
  findingsByLayer: Record<ScannerLayer, Finding[]>;
  riskScore: number;
};

Every finding must include:

scannerLayer: "code" | "runtime" | "authz";

This makes reporting and dashboard filtering clean.

6. Build a scan planner

Create a ScanPlanner.

Purpose:
Decide what scanner layers should run based on command and config.

Examples:

appsec scan .
Runs:
- code scanner only

appsec scan-runtime http://localhost:3000
Runs:
- runtime scanner
- optionally uses previous code scan context if available

appsec scan-auth http://localhost:3000
Runs:
- authz scanner
- requires auth profiles
- can reuse route map from code scanner and runtime scanner if available

appsec full-scan .
Runs:
- code scanner
- runtime scanner only if runtime.baseUrl exists
- authz scanner only if authProfiles exist

7. Add architecture documentation

Create docs/product-architecture.md.

It must explain:

- why the product is split into three scanner layers
- what each layer does
- what each layer does not do
- development order
- safety boundaries
- shared data contracts
- how future VS Code extension, browser extension, GitHub Action, and cloud dashboard plug into the same engine

8. Add architectural acceptance criteria

The project should not be considered architecturally clean unless:

- code scanner can run without runtime scanner
- runtime scanner can run without authz scanner
- authz scanner refuses to run without explicit auth profiles
- findings are tagged by scannerLayer
- reports can filter by scannerLayer
- rules do not directly crawl the filesystem
- analyzers produce reusable facts
- engines orchestrate analyzers/rules
- report generation is separate from scanning
- all sensitive evidence is redacted
- safe mode is default for runtime/authz scans

9. Add current roadmap file

Create docs/roadmap.md with this staged roadmap:

Stage 1: Code Scanner MVP
- secrets
- static code risks
- dependency risks
- config risks
- framework-specific checks
- AI-specific static risks
- HTML/JSON report

Stage 2: Runtime Scanner
- local/staging URL scanner
- headers/cookies/CORS
- exposed files
- open redirects
- reflected marker detection
- safe crawling

Stage 3: Auth / Access-Control Scanner
- anonymous access testing
- userA/userB testing
- admin route testing
- IDOR/BOLA checks
- tenant boundary checks

Stage 4: Production Developer Tooling
- dashboard polish
- baseline diffing
- SARIF
- GitHub Actions
- npm package
- documentation

Stage 5: Future Extensions
- VS Code extension
- browser extension
- signed rule updates
- optional cloud dashboard
- deeper language support
- OpenAPI/GraphQL scanning
- container/IaC scanning

10. Do not overbuild yet

For this prompt, focus on:
- architecture separation
- documentation
- shared types
- scan planner
- engine boundaries
- report layer awareness

Do not implement full runtime scanner yet.
Do not implement full authz scanner yet.
Do not implement cloud dashboard.
Do not implement browser extension.
Do not add aggressive exploitation.

This prompt is mainly to orient the architecture so future prompts can build the scanner cleanly.


Language and implementation strategy:

Use a TypeScript-first architecture for the initial implementation because the first supported targets are modern JavaScript/TypeScript web applications: Next.js, React, Vite, Node.js, Express, Supabase, Firebase, Clerk, Stripe, and AI-assisted web apps.

However, do not design the product as TypeScript-only forever.

The scanner must be architected as a platform with stable engine contracts, rule contracts, finding contracts, and external tool adapters.

The TypeScript core should handle:
- CLI
- scanner orchestration
- configuration
- file inventory
- JS/TS AST analysis
- Next.js/React/Node rules
- secret scanning MVP
- dependency scanning for npm ecosystem
- runtime scanning with Playwright
- auth/access-control scanning
- report generation
- dashboard

The architecture must allow future engines or adapters written in other languages.

Future supported additions may include:
- Python engine for Django/FastAPI/Flask scanning
- Go or Rust engine for high-performance repository scanning
- Semgrep adapter
- Gitleaks adapter
- Trivy adapter
- OSV scanner adapter
- container/IaC scanner adapters
- OpenAPI/GraphQL scanner adapters

Define a generic ScannerEngine contract:

type ScannerEngine = {
  id: string;
  name: string;
  layer: "code" | "runtime" | "authz" | "dependency" | "external";
  supportedLanguages?: string[];
  supportedFrameworks?: string[];
  run: (context: ScanContext) => Promise<Finding[]>;
};

Define an ExternalToolAdapter contract:

type ExternalToolAdapter = {
  id: string;
  name: string;
  command: string;
  isAvailable: () => Promise<boolean>;
  run: (context: ScanContext) => Promise<ExternalToolResult>;
  normalize: (result: ExternalToolResult) => Finding[];
};

The core rule is:
Every scanner engine, regardless of implementation language or external tool, must output normalized Finding objects.

Do not hardwire the architecture so only TypeScript-native rules can exist.
Do not let TypeScript become a limitation.
TypeScript is the first implementation language, not the permanent boundary of the product.
