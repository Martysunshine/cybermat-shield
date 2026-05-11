# CyberMat Shield — Roadmap

## Stage 1 — Code Scanner MVP ✅ Done

Static analysis of source files. No browser, no network.

- [x] Secret scanning (66 detectors — cloud, auth, databases, payments, AI, monitoring)
- [x] Context-aware severity (frontend vs backend, env file vs source code)
- [x] Secret redaction in all outputs (raw values never stored)
- [x] Static code risks (XSS sinks, SQL injection, eval, command injection)
- [x] Dependency risks (lifecycle scripts, wildcard versions, missing lockfile)
- [x] Config misconfigurations (CORS, missing security headers, exposed .env)
- [x] Cryptography risks (tokens in localStorage, insecure cookie flags)
- [x] AI-specific risks (LLM output to HTML sink, tool-call without approval)
- [x] Auth risks (missing Next.js middleware, admin routes without auth guards)
- [x] .appsecignore support (ignore by file path, rule ID, fingerprint)
- [x] HTML + JSON reports with redacted evidence
- [x] Risk score 0–100 with OWASP Top 10:2025 coverage
- [ ] File classification (client / server / shared) — Phase 4
- [ ] Route discovery (Next.js app router, pages router, Express) — Phase 4
- [ ] Import graph analysis (client/server boundary violations) — Phase 4
- [ ] AST source/sink correlation — Phase 4
- [ ] Full OWASP/CWE metadata on every rule — Phase 5
- [ ] Rule registry + `appsec rules list` CLI — Phase 5

---

## Stage 2 — Runtime Scanner 🔲 Planned (Phase 6)

Safe DAST-style scanning of a running app via Playwright.

**Requires:** `npx playwright install chromium`

- [ ] `appsec scan-runtime <url>` CLI command
- [ ] Playwright crawler with same-origin scope enforcement
- [ ] HTTP security header analysis (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- [ ] Cookie flag analysis (HttpOnly, Secure, SameSite, JWT-like values)
- [ ] CORS testing (reflected origin, wildcard + credentials, null origin)
- [ ] Open redirect testing (next, redirect, returnUrl, callbackUrl params)
- [ ] Reflected input detection (harmless marker injection in GET params)
- [ ] Exposed file probing (.env, .git/config, package.json, swagger.json, etc.)
- [ ] Source map exposure detection
- [ ] Debug/admin route exposure
- [ ] Runtime findings section in HTML/JSON report

---

## Stage 3 — Auth / Access-Control Scanner 🔲 Planned (Phase 7)

Controlled access-control testing using user-provided auth profiles.

**Requires:** User creates test accounts and exports Playwright `storageState`.

- [ ] `appsec auth init` — create auth config template
- [ ] `appsec scan-auth <url>` CLI command
- [ ] Anonymous access testing (protected routes return 200 without credentials)
- [ ] Vertical privilege testing (low-privileged user accessing admin routes)
- [ ] Horizontal IDOR/BOLA testing (userA accessing userB's resources)
- [ ] Tenant boundary testing (cross-org resource access)
- [ ] Sensitive response comparison across profiles
- [ ] Static/runtime correlation (link findings to source code evidence)
- [ ] Auth scan report section (profiles used, routes tested, resource pairs)
- [ ] Safety limits: 75 max requests, 150ms delay, halt on 5xx

---

## Stage 4 — Production Developer Tooling 🔲 Planned (Phase 8)

Making the scanner production-ready for CI/CD and team use.

- [ ] SARIF output (compatible with GitHub code scanning)
- [ ] Markdown report format
- [ ] Baseline diffing (`.appsec/baseline.json` — new/existing/fixed per finding)
- [ ] `appsec baseline create` / `appsec baseline compare`
- [ ] GitHub Actions workflow (`.github/workflows/appsec-scan.yml`)
- [ ] `appsec doctor` — checks Node version, Playwright, config validity
- [ ] Dashboard polish (React + Vite): score, filter by severity/OWASP/layer, search
- [ ] `appsec init` — interactive project setup
- [ ] npm package (`appsec` CLI installable globally)
- [ ] `appsec.config.json` schema validation with Zod
- [ ] CHANGELOG.md, LICENSE, CONTRIBUTING.md, SECURITY.md
- [ ] Full documentation set (architecture, config, secrets, runtime, CI, safety model)

---

## Stage 5 — Future Extensions 🔲 Future

Extensions beyond the core CLI tool.

- [ ] VS Code extension (inline findings, quick-fix suggestions)
- [ ] Browser extension (runtime scanning from the browser)
- [ ] Signed rule pack updates (verified community rule packs)
- [ ] Optional cloud dashboard (opt-in, no code upload by default)
- [ ] Python engine (Django / FastAPI / Flask scanning)
- [ ] Go/Rust engine (high-performance repository scanning)
- [ ] Semgrep adapter (ExternalToolAdapter)
- [ ] Gitleaks adapter (ExternalToolAdapter)
- [ ] Trivy adapter (container / IaC scanning)
- [ ] OSV Scanner adapter (supply chain vulnerability database)
- [ ] OpenAPI / GraphQL schema scanning
- [ ] Deeper language support (Python, Go, Ruby, PHP)
- [ ] Multi-repo scanning (monorepo support)
