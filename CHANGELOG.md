# Changelog

All notable changes to CyberMat Shield are documented here.

## [0.1.0] — 2025-05-12

### Added

**Phase 1 — MVP Foundation**
- `appsec scan <path>` CLI command with terminal output, JSON and HTML reports
- 33 initial security rules across 6 categories
- Risk score 0–100
- Intentionally vulnerable Next.js example app

**Phase 2 — Architecture Hardening + Secret Engine**
- 66+ secret detectors (cloud keys, tokens, connection strings, private keys)
- Context-aware severity (frontend vs backend file paths, NEXT_PUBLIC_ prefix)
- Secret redaction — only first/last 4 chars visible in reports
- `.appsecignore` file support — suppress by path, rule ID, or fingerprint
- Stable finding fingerprints for deduplication

**Phase 3 — Three-Layer Architecture**
- Three scanner layers: code / runtime / authz
- `ScanPlanner` — decides which layers run based on command
- `packages/analyzers` — dedicated analysis package
- `docs/product-architecture.md`, `docs/roadmap.md`

**Phase 4 — Deep Static Analysis**
- Full scan pipeline: inventory → stack detection → classification → AST → source/sink → routes → normalize → score
- Import graph analysis (ts-morph)
- AST-level dangerous sink detection (XSS, SQL, command exec, SSRF, redirect, filesystem, AI output)
- Source/sink correlation with sanitizer and auth guard recognition
- Next.js App Router + Pages Router + Express route discovery
- 15 controlled vulnerability fixtures in the example app
- `docs/internal-architecture.md`

**Phase 5 — Rule Pack System + OWASP Mapping**
- 95 rules across 9 packs with full metadata (OWASP Top 10:2025, CWE, ASVS, WSTG)
- `RuleRegistry` — enable/disable rules, severity overrides, config-driven
- `appsec rules list/show/docs` commands
- OWASP Top 10:2025 coverage mapping
- Auto-generated `docs/rules.md` (95 rules)

**Phase 6 — Safe Runtime Scanner**
- `appsec scan-runtime <url>` — Playwright-based safe HTTP/browser scanner
- Scope enforcement — same-origin only, no destructive paths
- `HeaderAnalyzer`, `CookieAnalyzer`, `CorsAnalyzer`, `ReflectionAnalyzer`, `RedirectAnalyzer`, `ExposedFileAnalyzer`
- 48 unit tests

**Phase 7 — Auth/Access-Control Scanner**
- `appsec scan-auth <url>` — IDOR, vertical privilege, anonymous access, tenant boundary testing
- `appsec auth init` + `appsec auth test-config`
- Playwright storageState profiles + cookie/header profiles
- `SensitiveResponseAnalyzer` — recursive JSON field detection
- `ResponseComparator` — pass/suspicious/fail verdicts
- `scripts/setup-auth-profiles.ts` — automated session setup for test accounts
- Auth system + IDOR-vulnerable routes in example app
- 38 unit tests
- `docs/auth-access-control-scanning.md`

**Phase 8 — Productionization**
- SARIF 2.1.0 output — compatible with GitHub code scanning
- Markdown report format
- Baseline diffing — `appsec baseline create/compare`, `--baseline` and `--ci` flags
- `appsec init` — initialize project config, `.appsecignore`, and `.gitignore` entries
- `appsec doctor` — environment check (Node, pnpm, Playwright, rule registry, config)
- `appsec config validate` — validate `appsec.config.json`
- `appsec report` — generate SARIF/Markdown from saved JSON report
- Stable exit codes: 0 clean, 1 findings, 2 error, 3 config error, 4 missing dep, 5 new baseline findings
- GitHub Actions workflow with SARIF upload and PR comments
- `docs/ci.md`, `docs/configuration.md`, `docs/safety-model.md`
- `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`
