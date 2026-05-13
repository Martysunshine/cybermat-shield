# Changelog

All notable changes to CyberMat Shield are documented here.

## [0.2.0] — 2026-05-12

### Added

**Multi-language Coverage Expansion**
- File inventory expanded from ~20 JS/TS extensions to 60+ extensions across 7 language groups: web, backend, config, infrastructure, database, script, and documentation
- `SCANNABLE_FILENAMES` — 50+ exact-filename matches for extension-less files (`Dockerfile`, `Makefile`, `Jenkinsfile`, `go.mod`, `Cargo.toml`, `requirements.txt`, `firestore.rules`, `nginx.conf`, CI/CD configs, and more)
- `language`, `fileKind`, and `ecosystem` fields on every `ScannedFile` — populated at inventory time, available to all engines
- `language-classifier.ts` — pure lookup-table classifier: `detectLanguage`, `detectFileKind`, `detectEcosystem`
- CI/CD path detection for GitHub Actions (`.github/workflows/`), CircleCI, GitLab CI, Azure Pipelines, and Bitbucket Pipelines
- Env file wildcard: any basename starting with `.env` (`.env.local`, `.env.staging`, `.env.example`, etc.)
- Binary-file safety: null-byte detection + non-printable ratio heuristic (>30% of first 512 bytes)
- Symlink safety: symlinked directories are detected via `lstat` and not followed
- `skipped` and `skippedByReason` counts on `FileInventoryResult` (`binary`, `too_large`, `ignored_file`, `symlink_skipped`, `read_error`)
- Explicit `JS_TS_EXTENSIONS` guard in `ast-analyzer.ts` — non-JS/TS files can never enter the JS parser
- `multilang-engine` — 27 dangerous pattern detectors across Docker (6), Shell (5), Terraform (3), Kubernetes (5), Python (4), PHP (3), and CI/CD (2)
- `scanFilesForPatterns` wired into the code scanner — pattern findings appear alongside secret findings in all reports
- 166 new tests in `@cybermat/analyzers` (language-classifier: 57, file-inventory: 109)
- 29 new tests in `@cybermat/engines` for multi-language pattern detection

**Secrets Engine Hardening**
- Shannon entropy scoring for secret candidates — filters low-entropy false positives (dictionary words, template placeholders)
- Post-detection validators per detector family — format-aware validation for AWS keys, JWT tokens, connection strings, RSA headers
- Stable content-based finding fingerprints (SHA-256 of `ruleId:normalizedPath:normalizedEvidence`) — resistant to line-number drift on refactors
- `fingerprint.ts` module in `@cybermat/core` — `makeFindingId`, `normalizeEvidence`

### Changed
- `@cybermat/analyzers`: `TS_EXTENSIONS` renamed to `JS_TS_EXTENSIONS` (explicit safety invariant)
- `FileInventoryResult`: `ignored` field retained; `skipped` and `skippedByReason` added alongside it

---

## [0.1.0] — 2025-05-12

### Added

**Phase 1 — MVP Foundation**
- `cybermat scan <path>` CLI command with terminal output, JSON and HTML reports
- 33 initial security rules across 6 categories
- Risk score 0–100
- Intentionally vulnerable Next.js example app

**Phase 2 — Architecture Hardening + Secret Engine**
- 66+ secret detectors (cloud keys, tokens, connection strings, private keys)
- Context-aware severity (frontend vs backend file paths, NEXT_PUBLIC_ prefix)
- Secret redaction — only first/last 4 chars visible in reports
- `.cybermatignore` file support — suppress by path, rule ID, or fingerprint
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
- `cybermat rules list/show/docs` commands
- OWASP Top 10:2025 coverage mapping
- Auto-generated `docs/rules.md` (95 rules)

**Phase 6 — Safe Runtime Scanner**
- `cybermat scan-runtime <url>` — Playwright-based safe HTTP/browser scanner
- Scope enforcement — same-origin only, no destructive paths
- `HeaderAnalyzer`, `CookieAnalyzer`, `CorsAnalyzer`, `ReflectionAnalyzer`, `RedirectAnalyzer`, `ExposedFileAnalyzer`
- 48 unit tests

**Phase 7 — Auth/Access-Control Scanner**
- `cybermat scan-auth <url>` — IDOR, vertical privilege, anonymous access, tenant boundary testing
- `cybermat auth init` + `cybermat auth test-config`
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
- Baseline diffing — `cybermat baseline create/compare`, `--baseline` and `--ci` flags
- `cybermat init` — initialize project config, `.cybermatignore`, and `.gitignore` entries
- `cybermat doctor` — environment check (Node, pnpm, Playwright, rule registry, config)
- `cybermat config validate` — validate `cybermat.config.json`
- `cybermat report` — generate SARIF/Markdown from saved JSON report
- Stable exit codes: 0 clean, 1 findings, 2 error, 3 config error, 4 missing dep, 5 new baseline findings
- GitHub Actions workflow with SARIF upload and PR comments
- `docs/ci.md`, `docs/configuration.md`, `docs/safety-model.md`
- `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`
