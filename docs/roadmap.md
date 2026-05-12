# CyberMat Shield — Roadmap

## Stage 1 — Code Scanner MVP ✅ Done

Static analysis of source files. No browser, no network.

- [x] Secret scanning (66+ detectors — cloud, auth, databases, payments, AI, monitoring)
- [x] Shannon entropy scoring + per-family validators (filter low-entropy false positives)
- [x] Stable content-based finding fingerprints (SHA-256, drift-resistant)
- [x] Context-aware severity (frontend vs backend, env file vs source code)
- [x] Secret redaction in all outputs (raw values never stored)
- [x] Static code risks (XSS sinks, SQL injection, eval, command injection)
- [x] Dependency risks (lifecycle scripts, wildcard versions, missing lockfile)
- [x] Config misconfigurations (CORS, missing security headers, exposed .env)
- [x] Cryptography risks (tokens in localStorage, insecure cookie flags)
- [x] AI-specific risks (LLM output to HTML sink, tool-call without approval)
- [x] Auth risks (missing Next.js middleware, admin routes without auth guards)
- [x] File classification (client / server / shared)
- [x] Route discovery (Next.js app router, pages router, Express)
- [x] Import graph analysis (client/server boundary violations)
- [x] AST source/sink correlation
- [x] Full OWASP/CWE/ASVS/WSTG metadata on every rule
- [x] Rule registry + `appsec rules list/show/docs` CLI
- [x] .appsecignore support (ignore by file path, rule ID, fingerprint)
- [x] HTML + JSON reports with redacted evidence
- [x] Risk score 0–100 with OWASP Top 10:2025 coverage
- [x] Multi-language file support (60+ extensions: Python, Go, Java, PHP, Ruby, Rust, Docker, Terraform, K8s, CI/CD, and more)
- [x] Language/fileKind/ecosystem metadata on every scanned file
- [x] 27 multi-language dangerous pattern detectors (Docker, Shell, Terraform, K8s, Python, PHP, CI/CD)
- [x] Language coverage summary in CLI output and report

---

## Stage 2 — Runtime Scanner ✅ Done (v0.1.0)

Safe DAST-style scanning of a running app via Playwright.

**Requires:** `npx playwright install chromium`

- [x] `appsec scan-runtime <url>` CLI command
- [x] Playwright crawler with same-origin scope enforcement
- [x] HTTP security header analysis (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- [x] Cookie flag analysis (HttpOnly, Secure, SameSite, JWT-like values)
- [x] CORS testing (reflected origin, wildcard + credentials, null origin)
- [x] Open redirect testing (next, redirect, returnUrl, callbackUrl params)
- [x] Reflected input detection (harmless marker injection in GET params)
- [x] Exposed file probing (.env, .git/config, package.json, swagger.json, etc.)
- [x] Source map exposure detection
- [x] Runtime findings section in HTML/JSON report
- [x] 48 unit tests

---

## Stage 3 — Auth / Access-Control Scanner ✅ Done (v0.1.0)

Controlled access-control testing using user-provided auth profiles.

**Requires:** User creates test accounts and exports Playwright `storageState`.

- [x] `appsec auth init` — create auth config template
- [x] `appsec auth test-config` — validate auth profiles and connectivity
- [x] `appsec scan-auth <url>` CLI command
- [x] Anonymous access testing (protected routes return 200 without credentials)
- [x] Vertical privilege testing (low-privileged user accessing admin routes)
- [x] Horizontal IDOR/BOLA testing (userA accessing userB's resources)
- [x] Tenant boundary testing (cross-org resource access)
- [x] Sensitive response comparison across profiles (22 sensitive field names)
- [x] Static/runtime correlation (link findings to source code evidence)
- [x] Auth scan report section (profiles used, routes tested, resource pairs)
- [x] Safety limits: 75 max requests, 150ms delay, halt on 5xx
- [x] 38 unit tests

---

## Stage 4 — Production Developer Tooling ✅ Done (v0.1.0)

Making the scanner production-ready for CI/CD and team use.

- [x] SARIF 2.1.0 output (compatible with GitHub code scanning)
- [x] Markdown report format
- [x] Baseline diffing (`.appsec/baseline.json` — new/existing/fixed per finding)
- [x] `appsec baseline create` / `appsec baseline compare`
- [x] `appsec init` — initialize project config, .appsecignore, .gitignore entries
- [x] `appsec doctor` — checks Node, pnpm, Playwright, config validity
- [x] `appsec config validate` — validate appsec.config.json
- [x] `appsec report` — generate SARIF/Markdown from saved JSON report
- [x] GitHub Actions workflow with SARIF upload and PR comments
- [x] Stable exit codes: 0 clean, 1 findings, 2 error, 3 config error, 4 missing dep, 5 new baseline findings
- [x] CHANGELOG.md, LICENSE, CONTRIBUTING.md, SECURITY.md
- [x] Full documentation (architecture, config, rules, runtime, CI, safety model, auth)

---

## Stage 5 — Future Extensions 🔲 Planned

Extensions beyond the core CLI tool.

- [ ] **npm publish** — public `npx appsec-shield` install (no auth required)
- [ ] VS Code extension (inline findings, quick-fix suggestions)
- [ ] Browser extension (runtime scanning from the browser)
- [ ] Signed rule pack updates (verified community rule packs)
- [ ] Optional cloud dashboard (opt-in, no code upload by default)
- [ ] Deeper Python/Go/Ruby/PHP AST analysis (currently pattern + secret scanning)
- [ ] Semgrep adapter (ExternalToolAdapter)
- [ ] Gitleaks adapter (ExternalToolAdapter)
- [ ] Trivy adapter (container / IaC scanning)
- [ ] OSV Scanner adapter (supply chain vulnerability database)
- [ ] OpenAPI / GraphQL schema scanning
- [ ] Multi-repo scanning (monorepo support)
